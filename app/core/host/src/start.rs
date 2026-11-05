//! What a start asks for: the outer transport flags, and the start options built
//! from a sign-in or a preflight.
//!
//! The wire bytes are the provider crate's encoders; this module decides only
//! *when* the clock is read (after the browser sign-in, never before) and where
//! the session id comes from.

use std::net::Ipv4Addr;
use std::time::Duration;

use oftc_apple::manager::{StartKind, StartOptions};
use oftc_engine::transport::{ConnectOptions, OuterFamily, Wire};
use oftc_host_bootstrap::{AcquireFailure, TunnelProfile};
use oftc_provider::envelope::{encode_envelope, preflight_wire, ConnectMode};
use zeroize::Zeroizing;

use crate::acquire::{Acquirer, Clock};

/// How long a start envelope stays valid. The provider accepts at most 120 s.
const ENVELOPE_LIFETIME: Duration = Duration::from_secs(60);

/// `--tcp`, `--ipv6-outer <CLAT-IPv4>` and `--insecure-saml`, each at most once.
/// `None` for anything else, including a mode the provider would reject (an
/// unusable CLAT address, which `ConnectMode::encode` refuses).
pub fn parse_start_flags(flags: &[String]) -> Option<(ConnectMode, bool)> {
    let (mut tcp, mut insecure, mut idi) = (false, false, None);
    let mut rest = flags.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--tcp" if !tcp => tcp = true,
            "--insecure-saml" if !insecure => insecure = true,
            "--ipv6-outer" if idi.is_none() => idi = Some(parse_octets(rest.next()?)?),
            _ => return None,
        }
    }
    let mode = ConnectMode(ConnectOptions {
        wire: if tcp { Wire::Tcp4443 } else { Wire::Udp4500 },
        family: if idi.is_some() {
            OuterFamily::Ipv6
        } else {
            OuterFamily::Ipv4
        },
        idi_v4: idi,
        tcp_fallback: !tcp,
    });
    mode.encode().ok()?;
    Some((mode, insecure))
}

/// Four decimal parts of one to three digits each, as the Swift parser read them
/// (so `010` is 10; `std`'s `Ipv4Addr` parser refuses leading zeros).
fn parse_octets(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    let [a, b, c, d] = parts[..] else { return None };
    let octet = |part: &str| {
        (!part.is_empty() && part.len() <= 3 && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<u8>().ok())
            .flatten()
    };
    Some(Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?))
}

fn envelope_options(
    kind: StartKind,
    wire: &[u8],
    mode: Option<Vec<u8>>,
    now: u64,
    session_id: [u8; 16],
) -> Option<StartOptions> {
    let envelope =
        encode_envelope(now + ENVELOPE_LIFETIME.as_secs(), session_id, wire, now).ok()?;
    Some(StartOptions {
        kind,
        envelope: Zeroizing::new(envelope.as_bytes().to_vec()),
        mode,
    })
}

/// Sign in, then wrap the result for `startVPNTunnel`. The sign-in can take
/// minutes, so the clock is read only after it returns: an envelope stamped
/// before the browser opened would already be stale. Any failure is the one
/// "SAML bootstrap failed" the verb reports; the PSK and token never leave the
/// wiped buffers.
#[allow(clippy::too_many_arguments)]
pub fn live_options(
    acquirer: &dyn Acquirer,
    clock: &dyn Clock,
    session_id: &dyn Fn() -> [u8; 16],
    gateway: &str,
    psk: &[u8],
    saml_port: u32,
    insecure: bool,
    profile: TunnelProfile,
    mode: ConnectMode,
    cancelled: &dyn Fn() -> bool,
) -> Result<StartOptions, AcquireFailure> {
    let wire = acquirer.acquire(gateway, psk, saml_port, insecure, profile, cancelled)?;
    let now = clock.unix_secs();
    let mode = mode.encode().map_err(|_| AcquireFailure::Other)?;
    envelope_options(
        StartKind::Live,
        &wire,
        Some(mode.to_vec()),
        now,
        session_id(),
    )
    .ok_or(AcquireFailure::Other)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PreflightError {
    /// The gateway, UID or PSK is not something the provider would accept.
    Input,
    /// The envelope could not be made.
    Envelope,
}

pub fn preflight_options(
    clock: &dyn Clock,
    session_id: &dyn Fn() -> [u8; 16],
    gateway: &str,
    uid: &str,
    psk: &[u8],
) -> Result<StartOptions, PreflightError> {
    let wire = preflight_wire(gateway, uid, psk).map_err(|_| PreflightError::Input)?;
    envelope_options(
        StartKind::Preflight,
        wire.as_bytes(),
        None,
        clock.unix_secs(),
        session_id(),
    )
    .ok_or(PreflightError::Envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    fn mode(args: &[&str]) -> Option<(ConnectOptions, bool)> {
        parse_start_flags(&flags(args)).map(|(mode, insecure)| (mode.0, insecure))
    }

    #[test]
    fn start_flags_table() {
        let (udp, _) = mode(&[]).unwrap();
        assert_eq!(
            (udp.wire, udp.family, udp.tcp_fallback),
            (Wire::Udp4500, OuterFamily::Ipv4, true)
        );
        let (tcp, insecure) = mode(&["--tcp", "--insecure-saml"]).unwrap();
        assert_eq!(
            (tcp.wire, tcp.tcp_fallback, insecure),
            (Wire::Tcp4443, false, true)
        );
        let (v6, _) = mode(&["--ipv6-outer", "192.0.0.2"]).unwrap();
        assert_eq!(
            (v6.family, v6.idi_v4, v6.tcp_fallback),
            (OuterFamily::Ipv6, Some(Ipv4Addr::new(192, 0, 0, 2)), true)
        );
        // Octets are read digit by digit, so a leading zero is decimal.
        assert_eq!(
            mode(&["--ipv6-outer", "010.0.0.2"]).unwrap().0.idi_v4,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        for bad in [
            &["--tcp", "--tcp"][..],
            &["--insecure-saml", "--insecure-saml"],
            &["--ipv6-outer"],
            &["--ipv6-outer", "192.0.0.2", "--ipv6-outer", "192.0.0.3"],
            &["--ipv6-outer", "1.2.3"],
            &["--ipv6-outer", "256.0.0.1"],
            &["--ipv6-outer", "1.2.3.+4"],
            &["--ipv6-outer", "1.2.3.0004"],
            // Addresses the provider refuses as a CLAT address.
            &["--ipv6-outer", "0.0.0.0"],
            &["--ipv6-outer", "127.0.0.1"],
            &["--ipv6-outer", "224.0.0.1"],
            &["--udp"],
        ] {
            assert!(mode(bad).is_none(), "{bad:?}");
        }
    }
}
