//! The start envelope: what `startTunnel(options:)` carries and how it is
//! accepted. Ports `BootstrapInput.swift` and the wire half of `Bootstrap.swift`.
//!
//! The inner `HBR1` record is produced by `host-bootstrap`; the outer envelope
//! adds an expiry and a single-use session id. Secrets are wiped when dropped
//! (best effort, in safe code) and never printed.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use oftc_engine::transport::{ConnectOptions, OuterFamily, Wire};

pub const LIVE_KEY: &str = "oftc.ephemeral-bootstrap.v1";
pub const PREFLIGHT_KEY: &str = "oftc.ephemeral-preflight.v1";
pub const MODE_KEY: &str = "oftc.outer-mode.v1";

const ENVELOPE_MAGIC: [u8; 5] = [0x4f, 0x46, 0x54, 0x43, 0x01];
const ENVELOPE_HEADER: usize = 5 + 8 + 16 + 2;
const MAX_SECRET: usize = 4096;
const MAX_LIFETIME_SECONDS: u64 = 120;
const HBR1_MAGIC: [u8; 4] = *b"HBR1";
/// The replay set is bounded so a flood of starts cannot grow it.
const MAX_REMEMBERED_STARTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Invalid,
    Expired,
}

/// Bytes that are wiped on drop. Debug output never shows them.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Move the bytes out without copying, so no unwiped duplicate is left.
    pub fn into_string(mut self) -> Result<String, EnvelopeError> {
        String::from_utf8(std::mem::take(&mut self.0)).map_err(|_| EnvelopeError::Invalid)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
        // Keep the stores above from being optimised out as dead.
        std::hint::black_box(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The decoded `HBR1` record. `token` is empty for a preflight.
#[derive(Debug)]
pub struct BootstrapInput {
    pub gateway: String,
    pub uid: String,
    pub psk: Secret,
    pub token: Secret,
}

/// The outer transport the host chose; the default is UDP 4500 over IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectMode(pub ConnectOptions);

impl ConnectMode {
    pub const UDP_DEFAULT: ConnectMode = ConnectMode(ConnectOptions {
        wire: Wire::Udp4500,
        family: OuterFamily::Ipv4,
        idi_v4: None,
        tcp_fallback: true,
    });

    /// `[1, transport, family, tcp_fallback, idi_v4 x4]`.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let [1, transport, family, fallback, idi @ ..] = bytes else {
            return Err(EnvelopeError::Invalid);
        };
        let idi: [u8; 4] = idi.try_into().map_err(|_| EnvelopeError::Invalid)?;
        let wire = match transport {
            1 => Wire::Udp4500,
            2 => Wire::Tcp4443,
            _ => return Err(EnvelopeError::Invalid),
        };
        let family = match family {
            4 => OuterFamily::Ipv4,
            6 => OuterFamily::Ipv6,
            _ => return Err(EnvelopeError::Invalid),
        };
        if *fallback > 1 || (wire == Wire::Tcp4443 && *fallback != 0) {
            return Err(EnvelopeError::Invalid);
        }
        let idi_v4 = match family {
            OuterFamily::Ipv4 if idi == [0; 4] => None,
            OuterFamily::Ipv6 if idi != [0; 4] && idi[0] != 127 && idi[0] < 224 => {
                Some(Ipv4Addr::from(idi))
            }
            _ => return Err(EnvelopeError::Invalid),
        };
        let options = ConnectOptions { wire, family, idi_v4, tcp_fallback: *fallback != 0 };
        options.validate().map_err(|_| EnvelopeError::Invalid)?;
        Ok(Self(options))
    }
}

/// One option value as the backend received it. A value that is present but
/// not binary data is rejected, so the backend must not drop it.
#[derive(Debug, Clone)]
pub enum OptionValue {
    Data(Vec<u8>),
    NotData,
}

/// The `startTunnel` options this provider reads.
#[derive(Debug, Clone, Default)]
pub struct StartOptions {
    pub live: Option<OptionValue>,
    pub preflight: Option<OptionValue>,
    pub mode: Option<OptionValue>,
}

#[derive(Debug)]
pub enum StartMode {
    Live(BootstrapInput, ConnectMode),
    Preflight(BootstrapInput),
}

fn be16(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) << 8 | usize::from(bytes[1])
}

/// Decode the outer envelope into `(session id, expiry, secret)`.
fn decode_envelope(data: &[u8], now: u64) -> Result<([u8; 16], u64, Secret), EnvelopeError> {
    if data.len() < ENVELOPE_HEADER + 1
        || data.len() > ENVELOPE_HEADER + MAX_SECRET
        || data[..5] != ENVELOPE_MAGIC
    {
        return Err(EnvelopeError::Invalid);
    }
    let expires_at = u64::from_be_bytes(data[5..13].try_into().expect("8 bytes"));
    let size = be16(&data[29..31]);
    if !(1..=MAX_SECRET).contains(&size) || data.len() != ENVELOPE_HEADER + size {
        return Err(EnvelopeError::Invalid);
    }
    if expires_at <= now || expires_at - now > MAX_LIFETIME_SECONDS {
        return Err(EnvelopeError::Expired);
    }
    let id: [u8; 16] = data[13..29].try_into().expect("16 bytes");
    Ok((id, expires_at, Secret(data[ENVELOPE_HEADER..].to_vec())))
}

impl BootstrapInput {
    /// Decode an `HBR1` record: magic, four big-endian lengths (gateway, uid,
    /// psk, token), then the fields. A preflight carries no token.
    pub fn decode(wire: &[u8], token_required: bool) -> Result<Self, EnvelopeError> {
        if wire.len() < 12 || wire.len() > 4096 || wire[..4] != HBR1_MAGIC {
            return Err(EnvelopeError::Invalid);
        }
        let lengths: Vec<usize> = (4..12).step_by(2).map(|at| be16(&wire[at..])).collect();
        let token_ok = if token_required {
            (1..=1024).contains(&lengths[3])
        } else {
            lengths[3] == 0
        };
        if !(1..=253).contains(&lengths[0])
            || lengths[1] != 32
            || !(1..=1024).contains(&lengths[2])
            || !token_ok
            || 12 + lengths.iter().sum::<usize>() != wire.len()
        {
            return Err(EnvelopeError::Invalid);
        }
        let mut rest = &wire[12..];
        let mut take = |length: usize| {
            let (field, tail) = rest.split_at(length);
            rest = tail;
            field
        };
        let gateway = take(lengths[0]);
        let uid = take(lengths[1]);
        let psk = take(lengths[2]);
        let token = take(lengths[3]);
        if !uid.iter().all(u8::is_ascii_hexdigit) || psk.contains(&0) || token.contains(&0) {
            return Err(EnvelopeError::Invalid);
        }
        let text = |bytes: &[u8]| {
            std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| EnvelopeError::Invalid)
        };
        // An invalid UTF-8 secret is rejected up front, not at connect.
        std::str::from_utf8(psk).map_err(|_| EnvelopeError::Invalid)?;
        std::str::from_utf8(token).map_err(|_| EnvelopeError::Invalid)?;
        Ok(Self {
            gateway: text(gateway)?,
            uid: text(uid)?,
            psk: Secret(psk.to_vec()),
            token: Secret(token.to_vec()),
        })
    }
}

/// Remembers the session ids already used, so one envelope starts one tunnel.
#[derive(Default)]
pub struct StartEnvelopes {
    used: HashMap<[u8; 16], u64>,
}

impl StartEnvelopes {
    /// Validate and consume the start options at unix time `now`. Every
    /// rejection leaves the replay set unchanged.
    pub fn consume(&mut self, options: &StartOptions, now: u64) -> Result<StartMode, EnvelopeError> {
        let preflight = options.preflight.is_some();
        if options.live.is_some() == preflight {
            return Err(EnvelopeError::Invalid);
        }
        let Some(OptionValue::Data(data)) =
            (if preflight { &options.preflight } else { &options.live })
        else {
            return Err(EnvelopeError::Invalid);
        };
        let (id, expires_at, secret) = decode_envelope(data, now)?;
        if id == [0; 16] {
            return Err(EnvelopeError::Invalid);
        }
        let input = BootstrapInput::decode(secret.as_bytes(), !preflight)?;
        if preflight && options.mode.is_some() {
            return Err(EnvelopeError::Invalid);
        }
        let mode = match &options.mode {
            Some(OptionValue::Data(bytes)) => ConnectMode::decode(bytes)?,
            Some(OptionValue::NotData) => return Err(EnvelopeError::Invalid),
            None => ConnectMode::UDP_DEFAULT,
        };
        self.used.retain(|_, expiry| *expiry > now);
        if self.used.len() >= MAX_REMEMBERED_STARTS || self.used.contains_key(&id) {
            return Err(EnvelopeError::Invalid);
        }
        self.used.insert(id, expires_at);
        Ok(if preflight { StartMode::Preflight(input) } else { StartMode::Live(input, mode) })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const UID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Build an `HBR1` record the way `host-bootstrap` does.
    pub fn hbr1(gateway: &str, uid: &str, psk: &[u8], token: &[u8]) -> Vec<u8> {
        let fields = [gateway.as_bytes(), uid.as_bytes(), psk, token];
        let mut wire = HBR1_MAGIC.to_vec();
        for field in fields {
            wire.extend_from_slice(&(field.len() as u16).to_be_bytes());
        }
        for field in fields {
            wire.extend_from_slice(field);
        }
        wire
    }

    pub fn envelope(expires_at: u64, id: [u8; 16], secret: &[u8]) -> Vec<u8> {
        let mut data = ENVELOPE_MAGIC.to_vec();
        data.extend_from_slice(&expires_at.to_be_bytes());
        data.extend_from_slice(&id);
        data.extend_from_slice(&(secret.len() as u16).to_be_bytes());
        data.extend_from_slice(secret);
        data
    }

    pub fn id() -> [u8; 16] {
        std::array::from_fn(|i| i as u8 + 1)
    }

    pub fn live(now: u64, id: [u8; 16]) -> StartOptions {
        let secret = hbr1("integration.invalid", UID, b"synthetic", b"synthetic-token");
        StartOptions {
            live: Some(OptionValue::Data(envelope(now + 60, id, &secret))),
            ..StartOptions::default()
        }
    }

    fn preflight(now: u64, id: [u8; 16]) -> StartOptions {
        let secret = hbr1("integration.invalid", UID, b"synthetic", b"");
        StartOptions {
            preflight: Some(OptionValue::Data(envelope(now + 60, id, &secret))),
            ..StartOptions::default()
        }
    }

    fn data(bytes: &[u8]) -> Option<OptionValue> {
        Some(OptionValue::Data(bytes.to_vec()))
    }

    #[test]
    fn preflight_has_no_token_and_a_replay_is_rejected() {
        let mut starts = StartEnvelopes::default();
        let options = preflight(1000, id());
        let Ok(StartMode::Preflight(input)) = starts.consume(&options, 1000) else {
            panic!("wrong mode");
        };
        assert!(input.token.is_empty());
        assert_eq!(input.uid, UID);
        assert_eq!(starts.consume(&options, 1000).unwrap_err(), EnvelopeError::Invalid);
    }

    #[test]
    fn an_id_is_reusable_once_its_entry_has_expired() {
        let mut starts = StartEnvelopes::default();
        starts.consume(&preflight(1000, id()), 1000).unwrap();
        assert!(matches!(
            starts.consume(&preflight(1100, id()), 1100),
            Ok(StartMode::Preflight(_))
        ));
    }

    #[test]
    fn live_and_preflight_together_are_ambiguous() {
        let mut both = live(1000, id());
        both.preflight = preflight(1000, [9; 16]).preflight;
        let mut starts = StartEnvelopes::default();
        assert_eq!(starts.consume(&both, 1000).unwrap_err(), EnvelopeError::Invalid);
        assert_eq!(
            starts.consume(&StartOptions::default(), 1000).unwrap_err(),
            EnvelopeError::Invalid
        );
    }

    #[test]
    fn a_rejected_start_does_not_burn_its_id() {
        let mut starts = StartEnvelopes::default();
        let mut bad_mode = live(1000, id());
        bad_mode.mode = Some(OptionValue::NotData);
        assert!(starts.consume(&bad_mode, 1000).is_err());
        assert!(starts.consume(&live(1000, id()), 1000).is_ok());
    }

    #[test]
    fn a_preflight_with_a_mode_is_rejected() {
        let mut options = preflight(1000, id());
        options.mode = data(&[1, 1, 4, 1, 0, 0, 0, 0]);
        assert!(StartEnvelopes::default().consume(&options, 1000).is_err());
    }

    #[test]
    fn a_zero_session_id_and_non_data_options_are_rejected() {
        let mut starts = StartEnvelopes::default();
        assert!(starts.consume(&live(1000, [0; 16]), 1000).is_err());
        let not_data = StartOptions { live: Some(OptionValue::NotData), ..Default::default() };
        assert!(starts.consume(&not_data, 1000).is_err());
    }

    #[test]
    fn the_replay_set_is_bounded() {
        let mut starts = StartEnvelopes::default();
        for n in 1..=MAX_REMEMBERED_STARTS as u8 {
            starts.consume(&live(1000, [n; 16]), 1000).unwrap();
        }
        assert!(starts.consume(&live(1000, [200; 16]), 1000).is_err());
    }

    #[test]
    fn an_envelope_delayed_by_saml_is_valid_when_built_after_it_and_expires() {
        // A browser flow that began at t=1000 and finished at t=1500 gets an
        // envelope built then; no SAML runs here.
        let secret = hbr1("integration.invalid", UID, b"synthetic", b"synthetic-token");
        let late = envelope(1500 + 60, id(), &secret);
        assert!(decode_envelope(&late, 1500 + 30).is_ok());
        assert_eq!(decode_envelope(&late, 1500 + 60).unwrap_err(), EnvelopeError::Expired);
    }

    #[test]
    fn envelope_lifetime_and_framing_are_enforced() {
        let secret = hbr1("integration.invalid", UID, b"p", b"t");
        assert_eq!(
            decode_envelope(&envelope(1000 + 121, id(), &secret), 1000).unwrap_err(),
            EnvelopeError::Expired
        );
        let mut truncated = envelope(1060, id(), &secret);
        truncated.pop();
        assert_eq!(decode_envelope(&truncated, 1000).unwrap_err(), EnvelopeError::Invalid);
        let mut wrong_magic = envelope(1060, id(), &secret);
        wrong_magic[4] = 2;
        assert_eq!(decode_envelope(&wrong_magic, 1000).unwrap_err(), EnvelopeError::Invalid);
        assert_eq!(decode_envelope(&[], 1000).unwrap_err(), EnvelopeError::Invalid);
    }

    #[test]
    fn hbr1_decodes_a_live_record_and_rejects_malformed_ones() {
        let raw = hbr1("integration.invalid", UID, b"synthetic", b"synthetic-token");
        let live = BootstrapInput::decode(&raw, true).unwrap();
        assert_eq!(live.token.as_bytes(), b"synthetic-token");
        assert_eq!(live.gateway, "integration.invalid");
        assert!(BootstrapInput::decode(&raw[..raw.len() - 1], true).is_err());
        // A live record needs a token and a preflight record must not have one.
        assert!(BootstrapInput::decode(&hbr1("g", UID, b"p", b""), true).is_err());
        assert!(BootstrapInput::decode(&raw, false).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", "short", b"p", b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", &UID.replace('A', "G"), b"p", b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", UID, b"p\0q", b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", UID, &[0xff], b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("", UID, b"p", b"t"), true).is_err());
        let mut bad_magic = raw.clone();
        bad_magic[0] = b'X';
        assert!(BootstrapInput::decode(&bad_magic, true).is_err());
        let mut padded = raw;
        padded.push(0);
        assert!(BootstrapInput::decode(&padded, true).is_err());
    }

    #[test]
    fn a_tcp6_mode_is_carried_to_the_live_start() {
        let mut options = live(1500, id());
        options.mode = data(&[1, 2, 6, 0, 192, 0, 0, 2]);
        let Ok(StartMode::Live(_, ConnectMode(selected))) =
            StartEnvelopes::default().consume(&options, 1530)
        else {
            panic!("live transport mode lost");
        };
        assert_eq!(selected.wire, Wire::Tcp4443);
        assert_eq!(selected.family, OuterFamily::Ipv6);
        assert_eq!(selected.idi_v4, Some(Ipv4Addr::new(192, 0, 0, 2)));
        assert!(!selected.tcp_fallback);
    }

    #[test]
    fn the_default_mode_is_udp_over_ipv4() {
        let Ok(StartMode::Live(_, mode)) = StartEnvelopes::default().consume(&live(1000, id()), 1000)
        else {
            panic!("expected a live start");
        };
        assert_eq!(mode, ConnectMode::UDP_DEFAULT);
    }

    #[test]
    fn connect_mode_rejects_every_inconsistent_encoding() {
        // TCP never takes a second fallback.
        assert!(ConnectMode::decode(&[1, 2, 6, 1, 192, 0, 0, 2]).is_err());
        assert!(ConnectMode::decode(&[1, 2, 4, 1, 0, 0, 0, 0]).is_err());
        for bad in [
            &[2, 1, 4, 1, 0, 0, 0, 0][..], // version
            &[1, 3, 4, 1, 0, 0, 0, 0],     // transport
            &[1, 1, 5, 1, 0, 0, 0, 0],     // family
            &[1, 1, 4, 2, 0, 0, 0, 0],     // fallback
            &[1, 1, 4, 1, 192, 0, 0, 2],   // IPv4 outer must not carry an IDi
            &[1, 1, 6, 1, 0, 0, 0, 0],     // IPv6 outer needs one
            &[1, 1, 6, 1, 127, 0, 0, 1],   // loopback
            &[1, 1, 6, 1, 224, 0, 0, 1],   // multicast
            &[1, 1, 4, 1, 0, 0, 0],        // short
            &[1, 1, 4, 1, 0, 0, 0, 0, 0],  // long
        ] {
            assert!(ConnectMode::decode(bad).is_err(), "{bad:?}");
        }
        assert!(ConnectMode::decode(&[1, 1, 6, 1, 192, 0, 0, 2]).is_ok());
    }

    #[test]
    fn secrets_are_not_printed_and_move_out_without_a_copy() {
        let secret = Secret(b"SYNTHETIC".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret(..)");
        assert_eq!(secret.into_string().unwrap(), "SYNTHETIC");
    }
}
