//! Gateway TLS trust: verify by default, let the user review+pin the cert
//! (trust-on-first-use), or opt out with `--insecure`.
//!
//! Uses the system `openssl` and `curl` so the crate stays dependency-free.
#![allow(dead_code)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// `$HOME/.config/oftc/gateways/` — where pinned gateway certs live.
pub fn trust_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/oftc/gateways")
}

pub fn pinned_path(host: &str, port: u32) -> PathBuf {
    trust_dir().join(format!("{host}_{port}.pem"))
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

/// Pin a cert for `host:port`; returns the path it was written to.
pub fn pin(host: &str, port: u32, pem: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = trust_dir();
    fs::create_dir_all(&dir)?;
    let p = pinned_path(host, port);
    fs::write(&p, pem)?;
    Ok(p)
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
}
