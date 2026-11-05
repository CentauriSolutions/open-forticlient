//! One-time FortiClient profile migration: the gateway, SAML port and PSK of an
//! installed FortiClient profile, for the explicit `import-profile` and
//! `migrate-psk` verbs. Tunnel starts never call it. Secrets come back only in
//! zeroizing buffers.
//!
//! [`import_profile`] and [`migrate_psk`] are the direct-call API (`oftc-hostlib`
//! composes them into the host verbs). `oftc_migrate_profile_psk` is the C entry
//! the Swift setup window still calls; `oftc-hostlib` re-exports it.
mod fctcrypt;
mod profile;

use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

use zeroize::Zeroizing;

#[repr(C)]
pub struct WireBuffer { pub data: *mut u8, pub count: usize }

fn wipe(bytes: &mut [u8]) {
    for byte in bytes { unsafe { ptr::write_volatile(byte, 0) }; }
    compiler_fence(Ordering::SeqCst);
}

/// The nonsecret settings and the PSK of one FortiClient profile.
pub struct Imported {
    pub gateway: String,
    pub saml_port: u32,
    pub psk: Zeroizing<Vec<u8>>,
}

fn usable_psk(loaded: &profile::Profile, psk: &str) -> bool {
    loaded.psk_is_plaintext && (1..=1024).contains(&psk.len()) && !psk.contains('\0') &&
        !psk.starts_with("Enc ") && psk != loaded.user
}

/// The PSK of FortiClient profile `name` (`None` when it cannot be read), only when it is a plaintext key for
/// exactly `expected_gateway`.
pub fn migrate_psk(name: &str, expected_gateway: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut loaded = profile::Profile::load(name).ok()?;
    let psk = Zeroizing::new(std::mem::take(&mut loaded.psk));
    if loaded.server != expected_gateway || !usable_psk(&loaded, &psk) { return None; }
    Some(Zeroizing::new(psk.as_bytes().to_vec()))
}

/// The gateway, SAML port and PSK of FortiClient profile `name`, when the gateway
/// is a valid host name and the PSK a plaintext key.
pub fn import_profile(name: &str) -> Option<Imported> {
    let mut loaded = profile::Profile::load(name).ok()?;
    let psk = Zeroizing::new(std::mem::take(&mut loaded.psk));
    let gateway = loaded.server.as_bytes();
    let valid_gateway = (1..=253).contains(&gateway.len()) &&
        gateway.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-') &&
        !gateway.starts_with(b".") && !gateway.ends_with(b".") &&
        !gateway.windows(2).any(|part| part == b"..");
    if !valid_gateway || !(1..=65535).contains(&loaded.saml_port) || !usable_psk(&loaded, &psk) {
        return None;
    }
    Some(Imported {
        gateway: loaded.server,
        saml_port: loaded.saml_port,
        psk: Zeroizing::new(psk.as_bytes().to_vec()),
    })
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
        let Some(psk) = migrate_psk(name, gateway) else { return 2; };
        let wire = psk.to_vec().into_boxed_slice();
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
    }
}
