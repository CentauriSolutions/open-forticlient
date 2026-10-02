//! SAML-over-IPsec credential acquisition.
//!
//! Ports the flow in ../../docs/saml-ipsec-protocol.md and tools/saml_catch.py:
//!   1. bind a loopback HTTP listener on an ephemeral port `p`
//!   2. POST `https://<server>:<saml_port>/saml_login?` with `UID` + `REDIRECT_PORT=p`
//!      -> gateway returns `<script>window.location="https://<server>:<port>/saml?<id>"</script>`
//!   3. open that URL in the system browser; the user does SSO
//!   4. the gateway redirects the browser to `http://localhost:<p>/?tokenid=…&username=…`
//!   5. capture tokenid + username
//!
//! The HTTPS POST shells out to `curl` (macOS ships it) so the crate stays
//! dependency-free — std has no TLS client. Everything else is std.
//!
//! The `tokenid` is a single-use IKE credential: never logged (caller masks) and
//! never written to disk.
#![allow(dead_code)]

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    /// Single-use EAP OTP. Do not log or store.
    pub tokenid: String,
    /// The UID sent to the gateway's /saml_login bootstrap. The gateway keys its
    /// SAML auth cache by this value, and iked's EAP identity MUST equal it or
    /// FNBAM's cache lookup misses (the -301). Set by `obtain()`.
    pub uid: String,
}

#[derive(Debug, Clone)]
pub struct SamlConfig {
    pub server: String,
    pub saml_port: u32,
    /// Skip TLS verification of the gateway cert (FortiClient warns-but-proceeds;
    /// off by default here — turn on only if the gateway cert is self-signed).
    pub insecure: bool,
    /// Overall time to wait for the browser SSO to complete.
    pub timeout: Duration,
}

impl Default for SamlConfig {
    fn default() -> Self {
        SamlConfig {
            server: String::new(),
            saml_port: 9443,
            insecure: false,
            timeout: Duration::from_secs(300),
        }
    }
}

/// Run the full SAML flow and return the EAP identity + OTP.
pub fn obtain(cfg: &SamlConfig) -> Result<Credentials, Box<dyn Error>> {
    if cfg.server.is_empty() {
        return Err("SAML: empty server".into());
    }
    // 1. loopback listener on an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    // 2. bootstrap POST -> SAML URL. The UID we send here is what the gateway
    //    keys its SAML auth cache by, and it MUST match iked's EAP identity
    //    (CONNECT +0x80) or FNBAM's cache lookup misses → -301. Use the device
    //    UID (hardware UUID, dashes stripped) exactly like the official client,
    //    and thread it back so the CONNECT side uses the identical value.
    let uid = crate::profile::fct_uid().unwrap_or(gen_uid()?);
    let html = bootstrap_post(cfg, port, &uid)?;
    let saml_url = extract_saml_url(&html)
        .ok_or("SAML: could not find the window.location redirect in the gateway response")?;

    // 3. open the SAML URL in the system browser
    eprintln!("Opening browser for SSO:\n  {saml_url}");
    open_browser(&saml_url)?;
    eprintln!("Waiting for the SAML callback on http://127.0.0.1:{port}/ (up to {}s)…",
        cfg.timeout.as_secs());

    // 4/5. catch the redirect
    let mut creds = wait_for_callback(&listener, cfg.timeout)?;
    creds.uid = uid;
    Ok(creds)
}

/// 16 random bytes as uppercase hex, matching FortiClient's UID shape.
fn gen_uid() -> Result<String, Box<dyn Error>> {
    let mut b = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02X}")).collect())
}

/// POST the bootstrap request via curl; returns the response body.
fn bootstrap_post(cfg: &SamlConfig, redirect_port: u16, uid: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("https://{}:{}/saml_login?", cfg.server, cfg.saml_port);
    let data = format!("UID={uid}&REDIRECT_PORT={redirect_port}");
    let mut args: Vec<String> = vec!["-s".into(), "--max-time".into(), "30".into()];
    args.extend(crate::tls::curl_tls_args(&cfg.server, cfg.saml_port, cfg.insecure));
    args.extend([
        "-X".into(), "POST".into(),
        "-H".into(), "Content-Type: application/x-www-form-urlencoded".into(),
        "-H".into(), format!("UID: {uid}"),
        "--data".into(), data,
        url,
    ]);
    let out = Command::new("curl").args(&args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "SAML bootstrap POST failed ({}). {}{}",
            out.status,
            err.trim(),
            if !cfg.insecure && !crate::tls::is_pinned(&cfg.server, cfg.saml_port) {
                "  (if this is a TLS cert error, run `oftc trust` to review+pin the gateway cert, or pass --insecure)"
            } else {
                ""
            }
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Find the gateway's redirect target: the first quoted URL containing `/saml?`.
fn extract_saml_url(html: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let mut rest = html;
        while let Some(start) = rest.find(quote) {
            let after = &rest[start + 1..];
            if let Some(end) = after.find(quote) {
                let candidate = &after[..end];
                if candidate.contains("/saml?") && candidate.starts_with("http") {
                    return Some(candidate.to_string());
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    None
}

fn open_browser(url: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("open").arg(url).status()?;
    if !status.success() {
        return Err(format!("failed to open browser ({status})").into());
    }
    Ok(())
}

/// Accept loopback connections until one carries tokenid+username, or timeout.
fn wait_for_callback(listener: &TcpListener, timeout: Duration) -> Result<Credentials, Box<dyn Error>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = [0u8; 16384];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let creds = parse_callback(&req);
                // Always answer so the browser tab shows a friendly message.
                let page = b"<html><body><h3>open-forticlient: SAML callback captured. \
                             You can close this tab.</h3></body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    page.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(page);
                let _ = stream.flush();
                if let Some(c) = creds {
                    return Ok(c);
                }
                // not the callback (e.g. a favicon request) — keep waiting
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("SAML: timed out waiting for the browser callback".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Pull tokenid+username from the request line query, or from an HTML form body
/// (the two shapes FortiTray handles).
fn parse_callback(req: &str) -> Option<Credentials> {
    // request line: "GET /?tokenid=..&username=.. HTTP/1.1"
    if let Some(line) = req.lines().next() {
        if let Some(path) = line.split_whitespace().nth(1) {
            if let Some(q) = path.split_once('?').map(|(_, q)| q) {
                let mut tokenid = None;
                let mut username = None;
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        match k {
                            "tokenid" | "token" => tokenid = Some(percent_decode(v)),
                            "username" | "user" => username = Some(percent_decode(v)),
                            _ => {}
                        }
                    }
                }
                if let (Some(t), Some(u)) = (tokenid.clone(), username.clone()) {
                    return Some(Credentials { username: u, tokenid: t, uid: String::new() });
                }
                // tokenid may arrive without username in some flows
                if let Some(t) = tokenid {
                    return Some(Credentials { username: username.unwrap_or_default(), tokenid: t, uid: String::new() });
                }
            }
        }
    }
    // fallback: HTML form fields in a POST body
    let t = find_form_value(req, "tokenid")?;
    let u = find_form_value(req, "username").unwrap_or_default();
    Some(Credentials { username: u, tokenid: t, uid: String::new() })
}

/// Minimal `name="KEY" value="VAL"` scan (no regex dependency).
fn find_form_value(body: &str, key: &str) -> Option<String> {
    let needle = format!("name=\"{key}\"");
    let at = body.find(&needle)?;
    let after = &body[at + needle.len()..];
    let vat = after.find("value=\"")? + "value=\"".len();
    let val = &after[vat..];
    let end = val.find('"')?;
    Some(val[..end].to_string())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_saml_url_from_js() {
        let html = r#"<html><script>window.location="https://gw.example.com:9443/saml?abc123def4567890"</script></html>"#;
        assert_eq!(
            extract_saml_url(html).as_deref(),
            Some("https://gw.example.com:9443/saml?abc123def4567890")
        );
    }

    #[test]
    fn extracts_saml_url_single_quotes() {
        let html = "location.replace('https://gw/saml?xyz')";
        assert_eq!(extract_saml_url(html).as_deref(), Some("https://gw/saml?xyz"));
    }

    #[test]
    fn no_saml_url() {
        assert!(extract_saml_url("<html>nope</html>").is_none());
    }

    #[test]
    fn parses_query_callback() {
        let req = "GET /?tokenid=deadbeefdeadbeefdeadbeefdeadbeef&username=chris%40sfcompute.com HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let c = parse_callback(req).unwrap();
        assert_eq!(c.tokenid, "deadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(c.username, "chris@sfcompute.com");
    }

    #[test]
    fn parses_form_callback() {
        let req = "POST / HTTP/1.1\r\n\r\n<input name=\"tokenid\" value=\"abcd1234\"><input name=\"username\" value=\"u@x\">";
        let c = parse_callback(req).unwrap();
        assert_eq!(c.tokenid, "abcd1234");
        assert_eq!(c.username, "u@x");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%40b"), "a@b");
        assert_eq!(percent_decode("x+y"), "x y");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
