//! In-memory host SAML -> provider bootstrap library. No executable entry.
//!
//! Two front doors over one implementation: [`acquire`] for Rust callers, and
//! the `oftc_host_*` C exports the Swift host still uses until it is removed.

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

pub use saml::TunnelProfile;

/// The `HBR1` record [`acquire`] returns. It carries the PSK and the single-use
/// SAML token, so it is wiped when dropped and never printed.
pub struct Wire(Box<[u8]>);

impl Wire {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }

    /// Hand the allocation to a caller that now owns wiping it.
    fn into_boxed(mut self) -> Box<[u8]> { std::mem::take(&mut self.0) }
}

impl Drop for Wire {
    fn drop(&mut self) { wipe(&mut self.0); }
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Wire(..)") }
}

/// Why [`acquire`] failed, as far as a caller may act on it.
#[derive(Debug, PartialEq, Eq)]
pub enum AcquireFailure {
    /// The gateway could not be reached before the browser opened. No SAML
    /// token was consumed, so a bounded retry is safe.
    BeforeBrowser,
    /// Anything else, including invalid input. Never retried automatically:
    /// an uncertain SSO callback may already have used the token.
    Other,
}

fn classify_saml_error(error: &(dyn std::error::Error + 'static)) -> AcquireFailure {
    if matches!(error.downcast_ref::<saml::SamlError>(),
                Some(saml::SamlError::Unreachable(_))) {
        AcquireFailure::BeforeBrowser
    } else {
        AcquireFailure::Other
    }
}

/// Run the browser SAML sign-in for `gateway` and return the `HBR1` record the
/// provider's start envelope carries. This blocks for the whole sign-in (up to
/// five minutes), so read the clock for the envelope only after it returns.
/// `profile` names the tunnel on the browser's callback page; the caller
/// supplies it, nothing is read from the environment, a Keychain item or
/// FortiClient's profile.
pub fn acquire(gateway: String, psk: String, saml_port: u32, insecure: bool,
               profile: TunnelProfile) -> Result<Wire, AcquireFailure> {
    let psk = SecretString(psk);
    if psk.0.is_empty() || !valid_gateway(&gateway) {
        return Err(AcquireFailure::Other);
    }
    let cfg = saml::SamlConfig { server: gateway.clone(),
        saml_port, insecure, timeout: Duration::from_secs(300), profile };
    let mut creds = saml::obtain(&cfg).map_err(|error| classify_saml_error(error.as_ref()))?;
    let uid = std::mem::take(&mut creds.uid);
    let token = SecretString(std::mem::take(&mut creds.tokenid));
    encode(Input { gateway, uid, psk, token })
        .map(Wire)
        .map_err(|_| AcquireFailure::Other)
}

/// The Swift supervisor names the tunnel for the callback page through these
/// two variables; the C entry turns them into the parameter [`acquire`] takes.
fn profile_from_env() -> TunnelProfile {
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    TunnelProfile { name: var("OFTC_PROFILE_NAME"), gateway: var("OFTC_PROFILE_GATEWAY") }
}

/// The caller supplies profile values already held in memory. This never reads
/// FortiClient's profile or a Keychain item; the only environment it reads is
/// the non-secret tunnel name for the callback page (`profile_from_env`).
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
    let result = std::panic::catch_unwind(|| {
        acquire(gateway, psk, saml_port, insecure != 0, profile_from_env())
    });
    match result {
        Ok(Ok(wire)) => { leak_for_swift(wire.into_boxed(), &mut *output); 0 },
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
    fn acquire_rejects_invalid_input_before_any_network_or_browser() {
        // Port 0 on loopback: if a guard were removed the call would fall through
        // to a refused connection (BeforeBrowser), not a live network or browser.
        for (gateway, psk) in [("https://bad/", "PSK"), ("127.0.0.1", "")] {
            let result = acquire(gateway.into(), psk.into(), 0, false, TunnelProfile::default());
            assert_eq!(result.unwrap_err(), AcquireFailure::Other, "{gateway:?}");
        }
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
