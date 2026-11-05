//! Gateway TLS trust: verify by default, let the user review+pin the cert
//! (trust-on-first-use), or opt out with `--insecure`.
//!
//! Uses the system `openssl` and `curl` so the crate stays dependency-free.
//!
//! This is the one implementation of the pin store (`<dir>/<host>_<port>.pem`: where
//! it is, its PEM shape, how it is written and read). The curl flags below and
//! `oftc_host::trust` both go through it.
#![allow(dead_code)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// `$HOME/.config/oftc/gateways/` — where pinned gateway certs live.
pub fn trust_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/oftc/gateways")
}

/// `<dir>/<host>_<port>.pem`.
pub fn pin_path(dir: &Path, host: &str, port: u32) -> PathBuf {
    dir.join(format!("{host}_{port}.pem"))
}

pub fn pinned_path(host: &str, port: u32) -> PathBuf {
    pin_path(&trust_dir(), host, port)
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding and no line breaks.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Strict standard base64: whole 4-character groups, padding only at the end, no
/// whitespace. The empty string decodes to nothing.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, group) in bytes.chunks(4).enumerate() {
        let last = (index + 1) * 4 == bytes.len();
        let padding = group.iter().rev().take_while(|b| **b == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for byte in &group[..4 - padding] {
            n = n << 6 | BASE64.iter().position(|c| c == byte)? as u32;
        }
        n <<= 6 * padding as u32;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - padding]);
    }
    Some(out)
}

/// The pin file's contents for a DER certificate: `-----BEGIN CERTIFICATE-----`,
/// the base64 in 64-column lines, `-----END CERTIFICATE-----`, each ending in LF.
pub fn pem_encode(der: &[u8]) -> String {
    let body = base64_encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The DER inside a pin: every line that does not start with `-----` is base64.
pub fn pem_decode(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .split(['\n', '\r'])
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64_decode(&body)
}

/// The pinned certificate's DER, or `None` when there is no readable pin.
pub fn read_pin(dir: &Path, host: &str, port: u32) -> Option<Vec<u8>> {
    pem_decode(&fs::read_to_string(pin_path(dir, host, port)).ok()?)
}

/// Pins `der` for `host:port`: the directory is created `0700` if missing and the
/// file replaces any old pin atomically, `0600` from the first byte.
pub fn write_pin(dir: &Path, host: &str, port: u32, der: &[u8]) -> std::io::Result<()> {
    let name = format!("{host}_{port}.pem");
    if host.is_empty() || name.contains(['/', '\0']) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let temp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| file.write_all(pem_encode(der).as_bytes()))
        .and_then(|()| fs::rename(&temp, dir.join(&name)));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

/// Fetch the gateway's leaf certificate as PEM (via `openssl s_client`).
pub fn fetch_cert_pem(host: &str, port: u32) -> Result<String, Box<dyn Error>> {
    let out = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{host}:{port}"),
            "-servername",
            host,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let begin = text
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("no certificate in openssl output (is the gateway reachable?)")?;
    let tail = "-----END CERTIFICATE-----";
    let end = text.find(tail).ok_or("truncated certificate from openssl")?;
    Ok(text[begin..end + tail.len()].to_string())
}

/// Human-readable summary of a PEM cert (subject, issuer, dates, SHA-256 FP).
pub fn cert_info(pem: &str) -> Result<String, Box<dyn Error>> {
    let mut child = Command::new("openssl")
        .args([
            "x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("openssl stdin unavailable")?
        .write_all(pem.as_bytes())?;
    let out = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `sha256//<base64>` curl pin of the certificate's public key. Pinning the key
/// rather than trusting the certificate as a CA also covers gateways whose
/// certificate carries no matching hostname (FortiGate factory certificates).
pub fn pubkey_pin(pem: &str) -> Result<String, Box<dyn Error>> {
    fn run(program: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child.stdin.take().ok_or("stdin unavailable")?.write_all(input)?;
        let out = child.wait_with_output()?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(format!("{program} failed").into());
        }
        Ok(out.stdout)
    }
    let key = run("openssl", &["x509", "-pubkey", "-noout"], pem.as_bytes())?;
    let der = run("openssl", &["pkey", "-pubin", "-outform", "der"], &key)?;
    let digest = run("openssl", &["dgst", "-sha256", "-binary"], &der)?;
    let encoded = run("openssl", &["base64", "-A"], &digest)?;
    Ok(format!("sha256//{}", String::from_utf8_lossy(&encoded).trim()))
}

/// curl TLS flags for this host: `-k` if insecure, else the pinned public key
/// if a cert is pinned, else nothing (system trust store verification).
pub fn curl_tls_args(host: &str, port: u32, insecure: bool) -> Vec<String> {
    if insecure {
        return vec!["-k".into()];
    }
    let p = pinned_path(host, port);
    if let Ok(pem) = fs::read_to_string(&p) {
        return match pubkey_pin(&pem) {
            Ok(pin) => vec!["-k".into(), "--pinnedpubkey".into(), pin],
            // An unreadable pin must fail closed, not fall back to `-k`.
            Err(_) => vec!["--cacert".into(), p.to_string_lossy().into_owned()],
        };
    }
    Vec::new()
}

pub fn is_pinned(host: &str, port: u32) -> bool {
    pinned_path(host, port).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIICCjCCAbACCQCuByFg61aM6jAKBggqhkjOPQQDAjATMREwDwYDVQQDDAhwaW4t
dGVzdDAeFw0yNjExMDMxMjU0MDNaFw0zNjEwMzExMjU0MDNaMBMxETAPBgNVBAMM
CHBpbi10ZXN0MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP//
//8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAA
AAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+
J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncD
fYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIh
AP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABFnYWXJw2naj
VBZITMN0xV18IjUSSOC2/J7dcNmx6DudOa8ju1dT+vtA/jIhEQpPLAKHkm+abfFP
yh5hvl88r7AwCgYIKoZIzj0EAwIDSAAwRQIhALnJQmaWs4oZ9a3bxfw+YYIt8KQ+
JiXTJWiM0eCck27dAiBuHoTMMNAFsN+B5BHaiH7ZDKeDambYjrfbW17VzyobcQ==
-----END CERTIFICATE-----";

    #[test]
    fn pubkey_pin_matches_curl_format() {
        assert_eq!(pubkey_pin(CERT).unwrap(), "sha256//eQagMgCPOyFjB44B/bZ67nLUw2Xk3RWzZ3W0966cCUE=");
        assert!(pubkey_pin("not a certificate").is_err());
    }

    #[test]
    fn base64_known_answers_and_rejections() {
        for (raw, text) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg==")] {
            assert_eq!(base64_encode(raw.as_bytes()), text);
            assert_eq!(base64_decode(text).as_deref(), Some(raw.as_bytes()));
        }
        // Unpadded, misplaced padding, whitespace and foreign characters are refused.
        for bad in ["Zg", "Zg=A", "Zg==Zm9v", "Zm9v\n", "Zm9*", "Z==="] {
            assert_eq!(base64_decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn write_pin_replaces_atomically_and_stays_inside_the_directory() {
        let dir = std::env::temp_dir().join(format!("oftc-tls-pin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_pin(&dir, "gw.example", 9443, b"one").unwrap();
        write_pin(&dir, "gw.example", 9443, b"two").unwrap();
        assert_eq!(read_pin(&dir, "gw.example", 9443).as_deref(), Some(&b"two"[..]));
        // Only the pin remains: no temporary file is left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        for host in ["../escape", "a/b", ""] {
            assert!(write_pin(&dir, host, 1, b"x").is_err(), "{host:?}");
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
