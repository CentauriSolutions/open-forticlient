//! In-memory host SAML -> provider bootstrap library. No executable entry.
#![allow(dead_code)]

mod log;
mod uid;
mod tls;
mod saml;

use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

const MAGIC: &[u8; 4] = b"HBR1";
const MAX_WIRE: usize = 4096;

#[repr(C)]
pub struct WireBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl Default for WireBuffer {
    fn default() -> Self { Self { ptr: ptr::null_mut(), len: 0 } }
}

struct SecretString(String);
impl Drop for SecretString {
    fn drop(&mut self) { wipe(unsafe { self.0.as_mut_vec() }); }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes { unsafe { ptr::write_volatile(byte, 0) }; }
    compiler_fence(Ordering::SeqCst);
}

struct Input {
    gateway: String,
    uid: String,
    psk: SecretString,
    token: SecretString,
}

fn valid_gateway(value: &str) -> bool {
    if value.parse::<std::net::Ipv4Addr>().is_ok() { return true; }
    !value.is_empty() && value.len() <= 253 &&
        value.split('.').all(|label| !label.is_empty() && label.len() <= 63 &&
            label.as_bytes().first().unwrap().is_ascii_alphanumeric() &&
            label.as_bytes().last().unwrap().is_ascii_alphanumeric() &&
            label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

fn encode(input: Input) -> Result<Box<[u8]>, ()> {
    let parts = [input.gateway.as_bytes(), input.uid.as_bytes(),
                 input.psk.0.as_bytes(), input.token.0.as_bytes()];
    if !valid_gateway(&input.gateway) || input.uid.is_empty() || input.uid.len() > 128 ||
        !input.uid.bytes().all(|b| b.is_ascii_alphanumeric()) ||
        parts[2..].iter().any(|p| p.is_empty() || p.len() > 1024) ||
        parts[2].contains(&0) || parts[3].contains(&0) {
        return Err(());
    }
    let total = 12 + parts.iter().map(|p| p.len()).sum::<usize>();
    if total > MAX_WIRE { return Err(()); }
    let mut wire = vec![0u8; total].into_boxed_slice();
    wire[..4].copy_from_slice(MAGIC);
    let mut offset = 12;
    for (index, part) in parts.iter().enumerate() {
        wire[4 + index * 2..6 + index * 2].copy_from_slice(&(part.len() as u16).to_be_bytes());
        wire[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    Ok(wire)
}

fn leak_for_swift(wire: Box<[u8]>, output: &mut WireBuffer) {
    let len = wire.len();
    let raw = Box::into_raw(wire);
    output.ptr = raw as *mut u8;
    output.len = len;
}

#[derive(Debug, PartialEq, Eq)]
enum AcquireFailure { BeforeBrowser, Other }

fn classify_saml_error(error: &(dyn std::error::Error + 'static)) -> AcquireFailure {
    if matches!(error.downcast_ref::<saml::SamlError>(),
                Some(saml::SamlError::Unreachable(_))) {
        AcquireFailure::BeforeBrowser
    } else {
        AcquireFailure::Other
    }
}

fn acquire(gateway: String, psk: String, saml_port: u32, insecure: bool)
    -> Result<Box<[u8]>, AcquireFailure> {
    let psk = SecretString(psk);
    if psk.0.is_empty() || !valid_gateway(&gateway) {
        return Err(AcquireFailure::Other);
    }
    let cfg = saml::SamlConfig { server: gateway.clone(),
        saml_port, insecure, timeout: Duration::from_secs(300) };
    let mut creds = saml::obtain(&cfg).map_err(|error| classify_saml_error(error.as_ref()))?;
    let uid = std::mem::take(&mut creds.uid);
    let token = SecretString(std::mem::take(&mut creds.tokenid));
    encode(Input { gateway, uid, psk, token })
        .map_err(|_| AcquireFailure::Other)
}

/// The caller supplies profile values already held in memory. This never reads
/// FortiClient's profile, an environment variable, or a Keychain item.
/// Invoking this entry performs the browser SSO flow; offline tests never do.
/// Status 3 means the gateway could not be reached before the browser opened;
/// it consumed no SAML token and can be retried with a bound. Other failures
/// stay generic to avoid retrying after an uncertain SSO callback.
#[no_mangle]
pub unsafe extern "C" fn oftc_host_acquire(
    gateway: *const u8, gateway_len: usize, psk: *const u8, psk_len: usize,
    saml_port: u32, insecure: u8, output: *mut WireBuffer,
) -> i32 {
    if output.is_null() { return 1; }
    *output = WireBuffer::default();
    if gateway.is_null() || psk.is_null() || gateway_len == 0 || gateway_len > 253 ||
        psk_len == 0 || psk_len > 1024 || saml_port == 0 || saml_port > 65535 || insecure > 1 {
        return 1;
    }
    let gateway = match std::str::from_utf8(std::slice::from_raw_parts(gateway, gateway_len)) {
        Ok(v) if valid_gateway(v) => v.to_owned(), _ => return 1,
    };
    let psk = match std::str::from_utf8(std::slice::from_raw_parts(psk, psk_len)) {
        Ok(v) if !v.contains('\0') => v.to_owned(), _ => return 1,
    };
    let result = std::panic::catch_unwind(|| acquire(gateway, psk, saml_port, insecure != 0));
    match result {
        Ok(Ok(wire)) => { leak_for_swift(wire, &mut *output); 0 },
        Ok(Err(AcquireFailure::BeforeBrowser)) => 3,
        _ => 2,
    }
}

/// The Swift host calls this immediately after copying into Data. The exact
/// allocation length is required so even spare capacity cannot retain bytes.
#[no_mangle]
pub unsafe extern "C" fn oftc_host_free_wire(data: *mut u8, len: usize) {
    if data.is_null() || len == 0 || len > MAX_WIRE { return; }
    let slice = ptr::slice_from_raw_parts_mut(data, len);
    let mut owned = Box::from_raw(slice);
    wipe(&mut owned);
    drop(owned);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_wire_is_versioned_and_bounded() {
        let wire = encode(Input { gateway: "integration.invalid".into(),
            uid: "UID123".into(), psk: SecretString("PSK".into()),
            token: SecretString("TOKEN".into()) }).unwrap();
        assert_eq!(&wire[..4], MAGIC);
        assert_eq!(wire.len(), 12 + 19 + 6 + 3 + 5);
        assert_eq!(&wire[4..12], &[0, 19, 0, 6, 0, 3, 0, 5]);
    }

    #[test]
    fn rejects_invalid_and_oversize_without_emitting_bytes() {
        let invalid = Input { gateway: "https://bad/".into(), uid: "UID".into(),
            psk: SecretString("PSK".into()), token: SecretString("TOKEN".into()) };
        assert!(encode(invalid).is_err());
        let huge = Input { gateway: "integration.invalid".into(), uid: "UID".into(),
            psk: SecretString("P".repeat(1025)), token: SecretString("TOKEN".into()) };
        assert!(encode(huge).is_err());
    }

    #[test]
    fn rejects_live_call_before_browser_if_input_invalid() {
        let mut out = WireBuffer::default();
        let status = unsafe { oftc_host_acquire(ptr::null(), 0, ptr::null(), 0, 0, 0, &mut out) };
        assert_ne!(status, 0);
        assert!(out.ptr.is_null());
    }

    #[test]
    fn explicit_wipe_clears_owned_bytes() {
        let mut secret = b"SYNTHETIC-TOKEN".to_vec();
        wipe(&mut secret);
        assert!(secret.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn only_pre_browser_unreachable_is_retryable() {
        let unreachable = saml::SamlError::Unreachable("offline".into());
        assert_eq!(classify_saml_error(&unreachable), AcquireFailure::BeforeBrowser);
        assert_eq!(classify_saml_error(&saml::SamlError::Timeout), AcquireFailure::Other);
    }
}
