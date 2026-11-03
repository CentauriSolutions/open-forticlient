//! One-time FortiClient profile PSK migration. The live host does not use this
//! function during a tunnel start. It returns only an in-memory secret buffer.
#![allow(dead_code)]
mod fctcrypt;
mod profile;

use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

#[repr(C)]
pub struct WireBuffer { pub data: *mut u8, pub count: usize }

#[repr(C)]
pub struct ImportWire {
    pub gateway: WireBuffer,
    pub psk: WireBuffer,
    pub saml_port: u32,
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes { unsafe { ptr::write_volatile(byte, 0) }; }
    compiler_fence(Ordering::SeqCst);
}

fn migrate(name: &str, expected_gateway: &str) -> Result<Box<[u8]>, ()> {
    let mut loaded = profile::Profile::load(name).map_err(|_| ())?;
    let mut psk = std::mem::take(&mut loaded.psk);
    let valid = loaded.server == expected_gateway && loaded.psk_is_plaintext &&
        (1..=1024).contains(&psk.len()) && !psk.contains('\0') &&
        !psk.starts_with("Enc ") && psk != loaded.user;
    if !valid { wipe(unsafe { psk.as_bytes_mut() }); return Err(()); }
    let wire = psk.as_bytes().to_vec().into_boxed_slice();
    wipe(unsafe { psk.as_bytes_mut() });
    Ok(wire)
}

type ImportedProfile = (Box<[u8]>, Box<[u8]>, u32);

fn import(name: &str) -> Result<ImportedProfile, ()> {
    let mut loaded = profile::Profile::load(name).map_err(|_| ())?;
    let mut psk = std::mem::take(&mut loaded.psk);
    let gateway = loaded.server.as_bytes();
    let valid_gateway = (1..=253).contains(&gateway.len()) &&
        gateway.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-') &&
        !gateway.starts_with(b".") && !gateway.ends_with(b".") &&
        !gateway.windows(2).any(|part| part == b"..");
    let valid = valid_gateway && (1..=65535).contains(&loaded.saml_port) &&
        loaded.psk_is_plaintext && (1..=1024).contains(&psk.len()) &&
        !psk.contains('\0') && !psk.starts_with("Enc ") && psk != loaded.user;
    if !valid { wipe(unsafe { psk.as_bytes_mut() }); return Err(()); }
    let result = (gateway.to_vec().into_boxed_slice(),
                  psk.as_bytes().to_vec().into_boxed_slice(), loaded.saml_port);
    wipe(unsafe { psk.as_bytes_mut() });
    Ok(result)
}

/// Explicit one-time import. Tunnel starts never call the FortiClient loader.
/// The gateway and SAML port are nonsecret; the PSK is returned in a wipeable
/// buffer and must be moved into the OFTC Keychain by the caller.
#[no_mangle]
pub unsafe extern "C" fn oftc_import_profile(
    name: *const u8, name_len: usize, output: *mut ImportWire,
) -> i32 {
    std::panic::catch_unwind(|| {
        let Some(output) = (unsafe { output.as_mut() }) else { return 1; };
        *output = ImportWire {
            gateway: WireBuffer { data: ptr::null_mut(), count: 0 },
            psk: WireBuffer { data: ptr::null_mut(), count: 0 },
            saml_port: 0,
        };
        if name.is_null() || name_len == 0 || name_len > 128 { return 1; }
        let Some(name) = std::str::from_utf8(unsafe {
            std::slice::from_raw_parts(name, name_len) }).ok() else { return 1; };
        if name.contains('\0') { return 1; }
        let Ok((gateway, psk, port)) = import(name) else { return 2; };
        output.gateway.count = gateway.len();
        output.gateway.data = Box::into_raw(gateway) as *mut u8;
        output.psk.count = psk.len();
        output.psk.data = Box::into_raw(psk) as *mut u8;
        output.saml_port = port;
        0
    }).unwrap_or(2)
}

#[no_mangle]
pub unsafe extern "C" fn oftc_import_free(output: *mut ImportWire) {
    let Some(output) = (unsafe { output.as_mut() }) else { return; };
    if !output.gateway.data.is_null() && (1..=253).contains(&output.gateway.count) {
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(
            output.gateway.data, output.gateway.count)) });
    }
    if !output.psk.data.is_null() && (1..=1024).contains(&output.psk.count) {
        let mut owned = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(
            output.psk.data, output.psk.count)) };
        wipe(&mut owned);
    }
    output.gateway = WireBuffer { data: ptr::null_mut(), count: 0 };
    output.psk = WireBuffer { data: ptr::null_mut(), count: 0 };
    output.saml_port = 0;
}

/// Profile and gateway names are nonsecret. Returns a bounded PSK only when
/// profile::load resolved a plaintext key for precisely the expected gateway.
#[no_mangle]
pub unsafe extern "C" fn oftc_migrate_profile_psk(
    name: *const u8, name_len: usize, gateway: *const u8, gateway_len: usize,
    output: *mut WireBuffer,
) -> i32 {
    std::panic::catch_unwind(|| {
        let Some(output) = (unsafe { output.as_mut() }) else { return 1; };
        *output = WireBuffer { data: ptr::null_mut(), count: 0 };
        if name.is_null() || gateway.is_null() || name_len == 0 || name_len > 128 ||
            gateway_len == 0 || gateway_len > 253 { return 1; }
        let Some(name) = std::str::from_utf8(unsafe {
            std::slice::from_raw_parts(name, name_len) }).ok() else { return 1; };
        let Some(gateway) = std::str::from_utf8(unsafe {
            std::slice::from_raw_parts(gateway, gateway_len) }).ok() else { return 1; };
        if name.contains('\0') || gateway.contains('\0') { return 1; }
        let Ok(wire) = migrate(name, gateway) else { return 2; };
        output.count = wire.len();
        output.data = Box::into_raw(wire) as *mut u8;
        0
    }).unwrap_or(2)
}

#[no_mangle]
pub unsafe extern "C" fn oftc_migrate_free(data: *mut u8, count: usize) {
    if data.is_null() || count == 0 || count > 1024 { return; }
    let mut owned = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(data, count)) };
    wipe(&mut owned);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_input_without_reading_profile() {
        let mut out = WireBuffer { data: ptr::null_mut(), count: 0 };
        assert_eq!(unsafe { oftc_migrate_profile_psk(
            ptr::null(), 0, ptr::null(), 0, &mut out) }, 1);
        assert!(out.data.is_null());
        let mut imported = ImportWire {
            gateway: WireBuffer { data: ptr::null_mut(), count: 0 },
            psk: WireBuffer { data: ptr::null_mut(), count: 0 },
            saml_port: 0,
        };
        assert_eq!(unsafe { oftc_import_profile(ptr::null(), 0, &mut imported) }, 1);
        assert!(imported.gateway.data.is_null() && imported.psk.data.is_null());
    }
}
