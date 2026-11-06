//! The `.oftc` profile bundle: one or more profiles and their PSKs in a file a
//! colleague can import.
//!
//! The bytes are the format the Swift host wrote (`ProfileBundle.swift`, now removed): pretty-printed, keys sorted, `" : "`
//! between a key and its value, `/` unescaped, one trailing newline. The PSK is not
//! the authentication secret (SAML is), but the file is configuration for a private
//! gateway, so it is shared with the people who need it.

use std::io;

use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::keychain::PSK_MAX;
use crate::profile::{Profile, Transport};

pub const FORMAT: &str = "oftc-profiles";
pub const VERSION: i64 = 1;
/// The most a bundle may hold, read from standard input as one byte over.
pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_PROFILES: usize = 16;

/// Why a bundle was refused, with the message the verb prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Unreadable,
    WrongFormat,
    UnsupportedVersion,
    TooLarge,
    Empty,
    /// The name of the profile whose settings or PSK are not acceptable.
    Invalid(String),
}

impl BundleError {
    pub fn message(&self) -> String {
        match self {
            BundleError::Unreadable | BundleError::WrongFormat => {
                "That file isn't an OFTC profile file".to_owned()
            }
            BundleError::UnsupportedVersion => {
                "That profile file is from a newer OFTC; update OFTC and try again".to_owned()
            }
            BundleError::TooLarge => "That profile file is too large".to_owned(),
            BundleError::Empty => "That profile file contains no profiles".to_owned(),
            BundleError::Invalid(name) => {
                format!("The profile \"{name}\" in that file has invalid settings")
            }
        }
    }
}

fn serialize_psk<S: Serializer>(psk: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(psk)
}

fn deserialize_psk<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// One profile in a bundle. Fields are declared in sorted-key order: that is the
/// order they are written.
#[derive(Serialize, Deserialize)]
pub struct Item {
    pub gateway: String,
    pub name: String,
    #[serde(serialize_with = "serialize_psk", deserialize_with = "deserialize_psk")]
    pub psk: Zeroizing<String>,
    #[serde(rename = "samlPort")]
    pub saml_port: u32,
    pub transport: Transport,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    format: String,
    profiles: Vec<Item>,
    version: i64,
}

/// `serde_json`'s pretty printer with `" : "`, which is how Foundation writes a
/// key and its value.
struct FoundationFormatter(serde_json::ser::PrettyFormatter<'static>);

impl serde_json::ser::Formatter for FoundationFormatter {
    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.begin_array(w)
    }
    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_array(w)
    }
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_array_value(w, first)
    }
    fn end_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_array_value(w)
    }
    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.begin_object(w)
    }
    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_object(w)
    }
    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        self.0.begin_object_key(w, first)
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b" : ")
    }
    fn end_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.0.end_object_value(w)
    }
}

/// The bytes of a bundle holding `profiles`. They hold PSKs, so the buffer is
/// zeroized when dropped.
pub fn encode(profiles: Vec<Item>) -> Option<Zeroizing<Vec<u8>>> {
    let wire = Wire {
        format: FORMAT.to_owned(),
        profiles,
        version: VERSION,
    };
    let mut bytes = Zeroizing::new(Vec::new());
    let formatter = FoundationFormatter(serde_json::ser::PrettyFormatter::with_indent(b"  "));
    wire.serialize(&mut serde_json::Serializer::with_formatter(
        &mut *bytes,
        formatter,
    ))
    .ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

/// A profile read from a bundle, validated, with its PSK.
pub struct Incoming {
    pub profile: Profile,
    pub psk: Zeroizing<Vec<u8>>,
}

/// Parses and validates untrusted bytes. Nothing is stored here. The checks and
/// their order are the Swift decoder's: size, shape, format, version, count, then
/// each profile's settings and PSK.
pub fn decode(data: &[u8]) -> Result<Vec<Incoming>, BundleError> {
    if data.len() > MAX_BYTES {
        return Err(BundleError::TooLarge);
    }
    let wire: Wire = serde_json::from_slice(data).map_err(|_| BundleError::Unreadable)?;
    if wire.format != FORMAT {
        return Err(BundleError::WrongFormat);
    }
    if wire.version != VERSION {
        return Err(BundleError::UnsupportedVersion);
    }
    if wire.profiles.is_empty() {
        return Err(BundleError::Empty);
    }
    if wire.profiles.len() > MAX_PROFILES {
        return Err(BundleError::TooLarge);
    }
    wire.profiles
        .into_iter()
        .map(|item| {
            let invalid = || BundleError::Invalid(item.name.clone());
            let profile = Profile::new(
                &item.gateway,
                item.saml_port,
                item.transport,
                Some(&item.name),
                None,
            )
            .map_err(|_| invalid())?;
            let psk = Zeroizing::new(item.psk.as_bytes().to_vec());
            if !(1..=PSK_MAX).contains(&psk.len()) || psk.contains(&0) {
                return Err(invalid());
            }
            Ok(Incoming { profile, psk })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::fixture;

    fn item(name: &str, gateway: &str, port: u32, transport: Transport, psk: &str) -> Item {
        Item {
            gateway: gateway.to_owned(),
            name: name.to_owned(),
            psk: Zeroizing::new(psk.to_owned()),
            saml_port: port,
            transport,
        }
    }

    /// The same two profiles the Swift `ProfileBundle` encoded to
    /// `fixtures/swift/bundle.oftc`. The second one's PSK holds every character
    /// the writer might escape differently: `/`, quotes, backslash, a tab, two
    /// other control characters, DEL, U+2028, a private-use and an astral character.
    fn swift_items() -> Vec<Item> {
        vec![
            item(
                "Example Office",
                "vpn.example.com",
                9443,
                Transport::Udp,
                "plain-secret",
            ),
            item(
                "Zürich lab ✓",
                "lab.example.com",
                8443,
                Transport::Tcp,
                "a/b \"q\" \\ \t\u{01}\u{1f}\u{7f}é\u{2028}\u{e000}😀",
            ),
        ]
    }

    #[test]
    fn golden_and_roundtrip() {
        let golden = std::fs::read(fixture("swift/bundle.oftc")).unwrap();
        assert_eq!(*encode(swift_items()).unwrap(), golden);
        let decoded = decode(&golden).unwrap();
        let expected = swift_items();
        assert_eq!(decoded.len(), expected.len());
        for (got, want) in decoded.iter().zip(&expected) {
            assert_eq!(got.profile.gateway, want.gateway);
            assert_eq!(got.profile.display_name(), want.name);
            assert_eq!(got.profile.saml_port, want.saml_port);
            assert_eq!(got.profile.transport, want.transport);
            assert_eq!(got.psk.as_slice(), want.psk.as_bytes());
        }
    }

    /// `decode` refuses what the Swift decoder refused, with the same message.
    #[test]
    fn failure_table() {
        let one = |name: &str, gateway: &str, port: &str, psk: &str| {
            format!(
                r#"{{"format":"oftc-profiles","version":1,"profiles":[{{"name":"{name}","gateway":"{gateway}","samlPort":{port},"transport":"udp","psk":"{psk}"}}]}}"#
            )
        };
        let invalid = |name: &str| Err(BundleError::Invalid(name.to_owned()));
        let sixteen = format!(
            r#"{{"format":"oftc-profiles","version":1,"profiles":[{}]}}"#,
            vec![r#"{"name":"A","gateway":"a.example.com","samlPort":1,"transport":"udp","psk":"p"}"#; 16].join(",")
        );
        let rows: Vec<(String, Result<usize, BundleError>)> = vec![
            // Shape, then format, version, count, in that order.
            (String::new(), Err(BundleError::Unreadable)),
            ("[]".to_owned(), Err(BundleError::Unreadable)),
            (r#"{"format":"oftc-profiles","version":1}"#.to_owned(), Err(BundleError::Unreadable)),
            (
                r#"{"format":"oftc-profiles","version":"1","profiles":[]}"#.to_owned(),
                Err(BundleError::Unreadable),
            ),
            (
                r#"{"format":"other","version":2,"profiles":[]}"#.to_owned(),
                Err(BundleError::WrongFormat),
            ),
            (
                r#"{"format":"oftc-profiles","version":2,"profiles":[]}"#.to_owned(),
                Err(BundleError::UnsupportedVersion),
            ),
            (r#"{"format":"oftc-profiles","version":1,"profiles":[]}"#.to_owned(), Err(BundleError::Empty)),
            (" ".repeat(MAX_BYTES + 1), Err(BundleError::TooLarge)),
            (
                format!(
                    r#"{{"format":"oftc-profiles","version":1,"profiles":[{}]}}"#,
                    vec![r#"{"name":"A","gateway":"a.example.com","samlPort":1,"transport":"udp","psk":"p"}"#; 17].join(",")
                ),
                Err(BundleError::TooLarge),
            ),
            (sixteen, Ok(16)),
            // Each profile's own settings and PSK.
            (one("A", "vpn.example.com", "9443", "p"), Ok(1)),
            (one("A", "bad host", "9443", "p"), invalid("A")),
            (one("A", "vpn.example.com", "0", "p"), invalid("A")),
            (one("A", "vpn.example.com", "65536", "p"), invalid("A")),
            (one("tab\\there", "vpn.example.com", "9443", "p"), invalid("tab\there")),
            (one("A", "vpn.example.com", "9443", ""), invalid("A")),
            (one("A", "vpn.example.com", "9443", &"k".repeat(1024)), Ok(1)),
            (one("A", "vpn.example.com", "9443", &"k".repeat(1025)), invalid("A")),
            (one("A", "vpn.example.com", "9443", "nul\\u0000byte"), invalid("A")),
        ];
        for (text, expected) in rows {
            let got = decode(text.as_bytes()).map(|items| items.len());
            assert_eq!(got, expected, "{:.80}", text);
        }
    }
}
