//! The SAML sign-in and the clock, as seams.

use std::fs::File;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oftc_host_bootstrap::{AcquireFailure, TunnelProfile};
use zeroize::Zeroizing;

/// The browser sign-in: blocks until the user finishes, then returns the `HBR1`
/// record the start envelope carries. `cancelled` is polled while it waits for the
/// browser; once it says true the sign-in is abandoned with `Other`.
pub trait Acquirer {
    fn acquire(
        &self,
        gateway: &str,
        psk: &[u8],
        saml_port: u32,
        insecure: bool,
        profile: TunnelProfile,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, AcquireFailure>;
}

/// [`oftc_host_bootstrap::acquire`]: opens the system browser.
pub struct SamlAcquirer;

impl Acquirer for SamlAcquirer {
    fn acquire(
        &self,
        gateway: &str,
        psk: &[u8],
        saml_port: u32,
        insecure: bool,
        profile: TunnelProfile,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Zeroizing<Vec<u8>>, AcquireFailure> {
        // A Keychain item can hold any bytes; the sign-in takes text.
        let psk = String::from_utf8(psk.to_vec()).map_err(|_| AcquireFailure::Other)?;
        let wire = oftc_host_bootstrap::acquire(
            gateway.to_owned(),
            psk,
            saml_port,
            insecure,
            profile,
            cancelled,
        )?;
        Ok(Zeroizing::new(wire.as_bytes().to_vec()))
    }
}

/// Wall-clock time and waiting, so polling loops and envelope expiry are testable.
pub trait Clock {
    fn unix_secs(&self) -> u64;
    /// A monotonic reading that keeps counting while the Mac sleeps, for deadlines
    /// and the recovery window (`Instant` does not count sleep on macOS).
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock {
    start: Duration,
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock {
            start: crate::os::monotonic(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn now(&self) -> Duration {
        crate::os::monotonic().saturating_sub(self.start)
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// 16 random bytes for a start's single-use session id; the provider rejects
/// the all-zero id, so that (a 2^-128 event) is drawn again. A machine with no
/// `/dev/urandom` cannot start a tunnel safely, so that panics, which the host
/// entry reports as an internal error.
pub fn random_session_id() -> [u8; 16] {
    let mut urandom = File::open("/dev/urandom").expect("/dev/urandom");
    let mut id = [0u8; 16];
    while id == [0; 16] {
        urandom.read_exact(&mut id).expect("/dev/urandom");
    }
    id
}
