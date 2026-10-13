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

/// curl TLS flags for this host: `-k` if insecure, else `--cacert <pin>` if a
/// cert is pinned, else nothing (system trust store verification).
pub fn curl_tls_args(host: &str, port: u32, insecure: bool) -> Vec<String> {
    if insecure {
        return vec!["-k".into()];
    }
    let p = pinned_path(host, port);
    if p.exists() {
        return vec!["--cacert".into(), p.to_string_lossy().into_owned()];
    }
    Vec::new()
}

pub fn is_pinned(host: &str, port: u32) -> bool {
    pinned_path(host, port).exists()
}
