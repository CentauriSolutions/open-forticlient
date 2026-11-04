//! The start envelope: what `startTunnel(options:)` carries and how it is
//! accepted. Ports `BootstrapInput.swift` and the wire half of `Bootstrap.swift`.
//!
//! The inner `HBR1` record is produced by `host-bootstrap`; the outer envelope
//! adds an expiry and a single-use session id. Secrets are wiped when dropped
//! (best effort, in safe code) and never printed.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, PoisonError};

use oftc_engine::transport::{ConnectOptions, OuterFamily, Wire};
use zeroize::Zeroize;

pub const LIVE_KEY: &str = "oftc.ephemeral-bootstrap.v1";
pub const PREFLIGHT_KEY: &str = "oftc.ephemeral-preflight.v1";
pub const MODE_KEY: &str = "oftc.outer-mode.v1";

const ENVELOPE_MAGIC: [u8; 5] = [0x4f, 0x46, 0x54, 0x43, 0x01];
const ENVELOPE_HEADER: usize = 5 + 8 + 16 + 2;
const MAX_SECRET: usize = 4096;
const MAX_LIFETIME_SECONDS: u64 = 120;
const HBR1_MAGIC: [u8; 4] = *b"HBR1";
const MAX_HBR1: usize = 4096;
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
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

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
        // Volatile, so the compiler cannot drop the stores as dead.
        self.0.zeroize();
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

    /// `[1, transport, family, tcp_fallback, idi_v4 x4]`. The inverse of
    /// [`ConnectMode::decode`]: an option set that decode would reject is not
    /// encoded, so a host cannot build a start the provider refuses.
    pub fn encode(&self) -> Result<[u8; 8], EnvelopeError> {
        let options = &self.0;
        let transport = match options.wire {
            Wire::Udp4500 => 1,
            Wire::Tcp4443 => 2,
        };
        let (family, idi) = match (options.family, options.idi_v4) {
            (OuterFamily::Ipv4, None) => (4, [0; 4]),
            (OuterFamily::Ipv6, Some(idi)) => (6, idi.octets()),
            _ => return Err(EnvelopeError::Invalid),
        };
        let bytes = [
            1,
            transport,
            family,
            u8::from(options.tcp_fallback),
            idi[0],
            idi[1],
            idi[2],
            idi[3],
        ];
        // One validity rule, shared with the decoder.
        Self::decode(&bytes)?;
        Ok(bytes)
    }

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
/// not binary data is rejected, so the backend must not drop it. The data is
/// the envelope that carries the PSK and token, so it is wiped on drop and
/// never printed, and the type is deliberately not `Clone`.
#[derive(Debug)]
pub enum OptionValue {
    Data(Secret),
    NotData,
}

/// The `startTunnel` options this provider reads.
#[derive(Debug, Default)]
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
        if wire.len() < 12 || wire.len() > MAX_HBR1 || wire[..4] != HBR1_MAGIC {
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
        if gateway.contains(&0)
            || !uid.iter().all(u8::is_ascii_hexdigit)
            || psk.contains(&0)
            || token.contains(&0)
        {
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

/// Frame an `HBR1` record: magic, four big-endian lengths (gateway, uid, psk,
/// token), then the fields. Framing only; the fields are not validated, so
/// tests can build records the provider must reject. Hosts use [`encode_hbr1`].
fn frame_hbr1(gateway: &str, uid: &str, psk: &[u8], token: &[u8]) -> Vec<u8> {
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

/// Frame the outer envelope: magic, expiry (u64 BE), 16-byte session id,
/// secret length (u16 BE), secret. Framing only, like [`frame_hbr1`].
fn frame_envelope(expires_at: u64, session_id: [u8; 16], secret: &[u8]) -> Vec<u8> {
    let mut data = ENVELOPE_MAGIC.to_vec();
    data.extend_from_slice(&expires_at.to_be_bytes());
    data.extend_from_slice(&session_id);
    data.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    data.extend_from_slice(secret);
    data
}

/// Encode a live (`token` non-empty) or preflight (`token` empty) `HBR1`
/// record. The result is checked by [`BootstrapInput::decode`], so every
/// record this returns is one the provider accepts.
pub fn encode_hbr1(
    gateway: &str,
    uid: &str,
    psk: &[u8],
    token: &[u8],
) -> Result<Secret, EnvelopeError> {
    // Lengths are u16 on the wire: refuse before one could wrap.
    let total = 12 + gateway.len() + uid.len() + psk.len() + token.len();
    if total > MAX_HBR1 {
        return Err(EnvelopeError::Invalid);
    }
    let wire = Secret(frame_hbr1(gateway, uid, psk, token));
    BootstrapInput::decode(wire.as_bytes(), !token.is_empty())?;
    Ok(wire)
}

/// A preflight record: the same as a live one, with no token.
pub fn preflight_wire(gateway: &str, uid: &str, psk: &[u8]) -> Result<Secret, EnvelopeError> {
    encode_hbr1(gateway, uid, psk, b"")
}

/// Wrap `secret` (an `HBR1` record) in the outer envelope. `now` is the
/// caller's clock read *after* any browser sign-in, so the expiry is relative
/// to completion. The lifetime window is [`decode_envelope`]'s, so an envelope
/// this returns is one the provider accepts at `now`.
pub fn encode_envelope(
    expires_at: u64,
    session_id: [u8; 16],
    secret: &[u8],
    now: u64,
) -> Result<Secret, EnvelopeError> {
    if !(1..=MAX_SECRET).contains(&secret.len())
        || expires_at <= now
        || expires_at - now > MAX_LIFETIME_SECONDS
    {
        return Err(EnvelopeError::Invalid);
    }
    Ok(Secret(frame_envelope(expires_at, session_id, secret)))
}

/// The session ids already used, with their expiry. One envelope starts one
/// tunnel, so this must outlive any one [`Provider`](crate::provider::Provider):
/// like Swift's static `usedIDs`, the real table is process-wide (see
/// [`consume`]).
#[derive(Default)]
struct ReplayTable(BTreeMap<[u8; 16], u64>);

static PROCESS_REPLAYS: Mutex<ReplayTable> = Mutex::new(ReplayTable(BTreeMap::new()));

/// Validate and consume the start options at unix time `now`, against the
/// process-wide replay table. Every rejection leaves the table unchanged.
pub fn consume(options: &StartOptions, now: u64) -> Result<StartMode, EnvelopeError> {
    let mut table = PROCESS_REPLAYS.lock().unwrap_or_else(PoisonError::into_inner);
    consume_in(&mut table, options, now)
}

fn consume_in(
    table: &mut ReplayTable,
    options: &StartOptions,
    now: u64,
) -> Result<StartMode, EnvelopeError> {
    let preflight = options.preflight.is_some();
    if options.live.is_some() == preflight {
        return Err(EnvelopeError::Invalid);
    }
    let Some(OptionValue::Data(data)) =
        (if preflight { &options.preflight } else { &options.live })
    else {
        return Err(EnvelopeError::Invalid);
    };
    let (id, expires_at, secret) = decode_envelope(data.as_bytes(), now)?;
    if id == [0; 16] {
        return Err(EnvelopeError::Invalid);
    }
    let input = BootstrapInput::decode(secret.as_bytes(), !preflight)?;
    if preflight && options.mode.is_some() {
        return Err(EnvelopeError::Invalid);
    }
    let mode = match &options.mode {
        Some(OptionValue::Data(bytes)) => ConnectMode::decode(bytes.as_bytes())?,
        Some(OptionValue::NotData) => return Err(EnvelopeError::Invalid),
        None => ConnectMode::UDP_DEFAULT,
    };
    table.0.retain(|_, expiry| *expiry > now);
    if table.0.len() >= MAX_REMEMBERED_STARTS || table.0.contains_key(&id) {
        return Err(EnvelopeError::Invalid);
    }
    table.0.insert(id, expires_at);
    Ok(if preflight { StartMode::Preflight(input) } else { StartMode::Live(input, mode) })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const UID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Framing-only builders: they let tests make records the provider must reject.
    pub fn hbr1(gateway: &str, uid: &str, psk: &[u8], token: &[u8]) -> Vec<u8> {
        frame_hbr1(gateway, uid, psk, token)
    }

    pub fn envelope(expires_at: u64, id: [u8; 16], secret: &[u8]) -> Vec<u8> {
        frame_envelope(expires_at, id, secret)
    }

    /// A session id no other test has used, since the real table is process-wide.
    pub fn id() -> [u8; 16] {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut id = [0xA5; 16];
        id[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        id
    }

    /// A fixed id for tests that use a private table.
    fn fixed_id() -> [u8; 16] {
        std::array::from_fn(|i| i as u8 + 1)
    }

    pub fn live(now: u64, id: [u8; 16]) -> StartOptions {
        let secret = hbr1("integration.invalid", UID, b"synthetic", b"synthetic-token");
        StartOptions {
            live: Some(OptionValue::Data(Secret::new(envelope(now + 60, id, &secret)))),
            ..StartOptions::default()
        }
    }

    fn preflight(now: u64, id: [u8; 16]) -> StartOptions {
        let secret = hbr1("integration.invalid", UID, b"synthetic", b"");
        StartOptions {
            preflight: Some(OptionValue::Data(Secret::new(envelope(now + 60, id, &secret)))),
            ..StartOptions::default()
        }
    }

    fn data(bytes: &[u8]) -> Option<OptionValue> {
        Some(OptionValue::Data(Secret::new(bytes.to_vec())))
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }

    // Bytes printed by the shipped Swift `preflightWire`, `BootstrapWire.encode`
    // and `ConnectMode.encode` (BootstrapInput.swift, Bootstrap.swift) for the
    // same inputs. The Rust encoders must reproduce them exactly.
    const SWIFT_PREFLIGHT: &str = "484252310013002000090000696e746567726174696f6e2e696e76616c6964\
        414141414141414141414141414141414141414141414141414141414141414173796e746865746963";

    #[test]
    fn encoders_reproduce_the_bytes_swift_builds_and_round_trip_through_the_decoders() {
        let preflight = preflight_wire("integration.invalid", UID, b"synthetic").unwrap();
        assert_eq!(preflight.as_bytes(), unhex(SWIFT_PREFLIGHT));
        let id: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
        let envelope = encode_envelope(1060, id, preflight.as_bytes(), 1000).unwrap();
        assert_eq!(
            envelope.as_bytes(),
            unhex(&format!(
                "4f465443010000000000000424{}0048{SWIFT_PREFLIGHT}",
                "0102030405060708090a0b0c0d0e0f10"
            ))
        );
        let (got_id, expires_at, secret) = decode_envelope(envelope.as_bytes(), 1000).unwrap();
        assert_eq!((got_id, expires_at), (id, 1060));
        let input = BootstrapInput::decode(secret.as_bytes(), false).unwrap();
        assert_eq!(
            (input.gateway.as_str(), input.uid.as_str()),
            ("integration.invalid", UID)
        );
        assert_eq!(input.psk.as_bytes(), b"synthetic");
        assert!(input.token.is_empty());
        // A live record differs only in the token and its length field.
        let live =
            encode_hbr1("integration.invalid", UID, b"synthetic", b"synthetic-token").unwrap();
        let mut expected = unhex(SWIFT_PREFLIGHT);
        expected[10..12].copy_from_slice(&[0, 15]);
        expected.extend_from_slice(b"synthetic-token");
        assert_eq!(live.as_bytes(), expected);
        assert_eq!(
            BootstrapInput::decode(live.as_bytes(), true)
                .unwrap()
                .token
                .as_bytes(),
            b"synthetic-token"
        );
    }

    #[test]
    fn connect_mode_encodes_what_swift_encodes_and_round_trips() {
        let tcp6 = ConnectMode(ConnectOptions {
            wire: Wire::Tcp4443,
            family: OuterFamily::Ipv6,
            idi_v4: Some(Ipv4Addr::new(192, 0, 0, 2)),
            tcp_fallback: false,
        });
        let udp6 = ConnectMode(ConnectOptions {
            wire: Wire::Udp4500,
            tcp_fallback: true,
            ..tcp6.0
        });
        for (mode, swift) in [
            (ConnectMode::UDP_DEFAULT, "0101040100000000"),
            (tcp6, "01020600c0000002"),
            (udp6, "01010601c0000002"),
        ] {
            let bytes = mode.encode().unwrap();
            assert_eq!(bytes.to_vec(), unhex(swift));
            assert_eq!(ConnectMode::decode(&bytes).unwrap(), mode);
        }
        // Options the decoder rejects are not encoded: TCP with a fallback, an
        // IPv6 outer with no IDi, an IPv4 outer with one.
        for bad in [
            ConnectOptions {
                tcp_fallback: true,
                ..tcp6.0
            },
            ConnectOptions {
                idi_v4: None,
                ..tcp6.0
            },
            ConnectOptions {
                family: OuterFamily::Ipv4,
                ..tcp6.0
            },
        ] {
            assert_eq!(
                ConnectMode(bad).encode(),
                Err(EnvelopeError::Invalid),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn encoders_refuse_what_the_provider_would_refuse() {
        // HBR1: the same boundaries `BootstrapInput::decode` enforces, plus
        // the 4096 cap before a u16 length could wrap.
        assert!(encode_hbr1("g", "short", b"p", b"t").is_err());
        assert!(encode_hbr1("g", UID, b"", b"t").is_err());
        assert!(encode_hbr1("g", UID, b"p\0q", b"t").is_err());
        assert!(preflight_wire("", UID, b"p").is_err());
        assert!(encode_hbr1(&"a".repeat(253), UID, &vec![b'p'; 1024], &vec![b't'; 2000]).is_err());
        assert!(encode_hbr1(&"a".repeat(70_000), UID, b"p", b"t").is_err());
        // Envelope: lifetime is (now, now + 120], and the secret is 1..=4096.
        for (expires_at, ok) in [(1000, false), (1001, true), (1120, true), (1121, false)] {
            assert_eq!(
                encode_envelope(expires_at, [1; 16], b"x", 1000).is_ok(),
                ok,
                "{expires_at}"
            );
        }
        assert!(encode_envelope(1060, [1; 16], b"", 1000).is_err());
        assert!(encode_envelope(1060, [1; 16], &vec![b'x'; MAX_SECRET], 1000).is_ok());
        assert!(encode_envelope(1060, [1; 16], &vec![b'x'; MAX_SECRET + 1], 1000).is_err());
    }

    #[test]
    fn preflight_has_no_token_and_a_replay_is_rejected() {
        let mut starts = ReplayTable::default();
        let options = preflight(1000, fixed_id());
        let Ok(StartMode::Preflight(input)) = consume_in(&mut starts, &options, 1000) else {
            panic!("wrong mode");
        };
        assert!(input.token.is_empty());
        assert_eq!(input.uid, UID);
        assert_eq!(consume_in(&mut starts, &options, 1000).unwrap_err(), EnvelopeError::Invalid);
    }

    #[test]
    fn an_id_is_reusable_once_its_entry_has_expired() {
        let mut starts = ReplayTable::default();
        consume_in(&mut starts, &preflight(1000, fixed_id()), 1000).unwrap();
        assert!(matches!(
            consume_in(&mut starts, &preflight(1100, fixed_id()), 1100),
            Ok(StartMode::Preflight(_))
        ));
    }

    #[test]
    fn live_and_preflight_together_are_ambiguous() {
        let mut both = live(1000, fixed_id());
        both.preflight = preflight(1000, [9; 16]).preflight;
        let mut starts = ReplayTable::default();
        assert_eq!(consume_in(&mut starts, &both, 1000).unwrap_err(), EnvelopeError::Invalid);
        assert_eq!(
            consume_in(&mut starts, &StartOptions::default(), 1000).unwrap_err(),
            EnvelopeError::Invalid
        );
    }

    #[test]
    fn a_rejected_start_does_not_burn_its_id() {
        let mut starts = ReplayTable::default();
        let mut bad_mode = live(1000, fixed_id());
        bad_mode.mode = Some(OptionValue::NotData);
        assert!(consume_in(&mut starts, &bad_mode, 1000).is_err());
        assert!(consume_in(&mut starts, &live(1000, fixed_id()), 1000).is_ok());
    }

    #[test]
    fn a_preflight_with_a_mode_is_rejected() {
        let mut options = preflight(1000, fixed_id());
        options.mode = data(&[1, 1, 4, 1, 0, 0, 0, 0]);
        assert_eq!(
            consume_in(&mut ReplayTable::default(), &options, 1000).unwrap_err(),
            EnvelopeError::Invalid
        );
    }

    #[test]
    fn a_zero_session_id_and_non_data_options_are_rejected() {
        let mut starts = ReplayTable::default();
        assert_eq!(
            consume_in(&mut starts, &live(1000, [0; 16]), 1000).unwrap_err(),
            EnvelopeError::Invalid
        );
        let not_data = StartOptions { live: Some(OptionValue::NotData), ..Default::default() };
        assert_eq!(consume_in(&mut starts, &not_data, 1000).unwrap_err(), EnvelopeError::Invalid);
    }

    #[test]
    fn the_replay_set_is_bounded() {
        let mut starts = ReplayTable::default();
        for n in 1..=MAX_REMEMBERED_STARTS as u8 {
            consume_in(&mut starts, &live(1000, [n; 16]), 1000).unwrap();
        }
        assert!(consume_in(&mut starts, &live(1000, [200; 16]), 1000).is_err());
    }

    #[test]
    fn envelope_lifetime_and_framing_are_enforced() {
        let secret = hbr1("integration.invalid", UID, b"p", b"t");
        // The lifetime window is (now, now + 120]: the browser flow of a SAML
        // login may finish late, so the envelope is built after it.
        for (expires_at, accepted) in [(1000, false), (1001, true), (1120, true), (1121, false)] {
            let result = decode_envelope(&envelope(expires_at, fixed_id(), &secret), 1000);
            match accepted {
                true => assert!(result.is_ok(), "{expires_at}"),
                false => assert_eq!(result.unwrap_err(), EnvelopeError::Expired, "{expires_at}"),
            }
        }
        let mut truncated = envelope(1060, fixed_id(), &secret);
        truncated.pop();
        assert_eq!(decode_envelope(&truncated, 1000).unwrap_err(), EnvelopeError::Invalid);
        let mut wrong_magic = envelope(1060, fixed_id(), &secret);
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
        assert!(BootstrapInput::decode(&hbr1("gate\0way", UID, b"p", b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", UID, b"", b"t"), true).is_err());
        assert!(BootstrapInput::decode(&hbr1("g", UID, b"p", &[0xff]), true).is_err());
        let mut binary_gateway = hbr1("g", UID, b"p", b"t");
        binary_gateway[12] = 0xff;
        assert!(BootstrapInput::decode(&binary_gateway, true).is_err());
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
        let mut options = live(1500, fixed_id());
        options.mode = data(&[1, 2, 6, 0, 192, 0, 0, 2]);
        let Ok(StartMode::Live(_, ConnectMode(selected))) =
            consume_in(&mut ReplayTable::default(), &options, 1530)
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
        let Ok(StartMode::Live(_, mode)) = consume_in(&mut ReplayTable::default(), &live(1000, fixed_id()), 1000)
        else {
            panic!("expected a live start");
        };
        assert_eq!(mode, ConnectMode::UDP_DEFAULT);
    }

    #[test]
    fn connect_mode_rejects_every_inconsistent_encoding() {
        // TCP never takes a second fallback.
        assert!(ConnectMode::decode(&[1, 2, 6, 1, 192, 0, 0, 2]).is_err());
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
        let ok = ConnectMode::decode(&[1, 1, 6, 1, 192, 0, 0, 2]).unwrap().0;
        assert_eq!(ok.idi_v4, Some(Ipv4Addr::new(192, 0, 0, 2)));
        assert!(ok.tcp_fallback);
    }

    #[test]
    fn a_secrets_debug_output_is_redacted() {
        assert_eq!(format!("{:?}", Secret(b"SYNTHETIC".to_vec())), "Secret(..)");
    }

    #[test]
    fn the_process_wide_table_rejects_a_replay_across_callers() {
        let options = live(unix_secs(), id());
        assert!(consume(&options, unix_secs()).is_ok());
        assert!(consume(&options, unix_secs()).is_err());
    }

    fn unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn hbr1_field_lengths_are_bounded_at_both_edges() {
        let gateway = |n: usize| hbr1(&"a".repeat(n), UID, b"p", b"t");
        // Gateway 253 is the DNS limit; 254 is one over. (Labels are not checked here.)
        assert!(BootstrapInput::decode(&gateway(253), true).is_ok());
        assert!(BootstrapInput::decode(&gateway(254), true).is_err());
        let psk = |n: usize| hbr1("g", UID, &vec![b'p'; n], b"t");
        assert!(BootstrapInput::decode(&psk(1024), true).is_ok());
        assert!(BootstrapInput::decode(&psk(1025), true).is_err());
        let token = |n: usize| hbr1("g", UID, b"p", &vec![b't'; n]);
        assert!(BootstrapInput::decode(&token(1024), true).is_ok());
        assert!(BootstrapInput::decode(&token(1025), true).is_err());
    }

    #[test]
    fn the_uid_must_be_exactly_32_hex_digits_in_either_case() {
        assert!(BootstrapInput::decode(&hbr1("g", &format!("{UID}A"), b"p", b"t"), true).is_err());
        let mixed = "aBcDeF0123456789AbCdEf0123456789";
        assert_eq!(mixed.len(), 32);
        assert_eq!(BootstrapInput::decode(&hbr1("g", mixed, b"p", b"t"), true).unwrap().uid, mixed);
    }

    #[test]
    fn a_record_over_4096_bytes_or_an_oversized_envelope_is_rejected() {
        // Fields individually in range, together over the 4096 cap.
        let mut over = hbr1(&"a".repeat(253), UID, &vec![b'p'; 1024], &vec![b't'; 1024]);
        over.extend(vec![0; 4096]);
        assert!(BootstrapInput::decode(&over, true).is_err());
        // The envelope's secret over its cap, and a size field over the cap or zero.
        let big = envelope(1060, fixed_id(), &vec![b'x'; MAX_SECRET + 1]);
        assert_eq!(decode_envelope(&big, 1000).unwrap_err(), EnvelopeError::Invalid);
        for size in [0, MAX_SECRET as u16 + 1] {
            assert_eq!(
                decode_envelope(&envelope_with_size(size), 1000).unwrap_err(),
                EnvelopeError::Invalid
            );
        }
    }

    fn envelope_with_size(size: u16) -> Vec<u8> {
        let mut data = envelope(1060, fixed_id(), b"x");
        data[29..31].copy_from_slice(&size.to_be_bytes());
        data
    }

    #[test]
    fn option_values_and_inputs_never_print_their_bytes() {
        let printed = format!("{:?}", live(1000, fixed_id()));
        // Derived Debug would print a Vec<u8> as decimals; "HBR1" is 72, 66, 82, 49.
        assert!(printed.contains("Secret(..)") && !printed.contains("72, 66, 82, 49"), "{printed}");
        let input = BootstrapInput::decode(&hbr1("g", UID, b"hunter2", b"tok"), true).unwrap();
        let printed = format!("{input:?}");
        assert!(printed.contains("Secret(..)") && !printed.contains("104, 117, 110"), "{printed}");
    }
}
