//! SAML-over-IPsec credential acquisition.
//!
//! Implements the flow in docs/saml-ipsec-protocol.md:
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

use crate::log::log;

pub struct Credentials {
    pub username: String,
    /// Single-use EAP OTP. Do not log or store.
    pub tokenid: String,
    /// The UID sent to the gateway's /saml_login bootstrap. The gateway keys its
    /// SAML auth cache by this value, and iked's EAP identity MUST equal it or
    /// FNBAM's cache lookup misses (the -301). Set by `obtain()`.
    pub uid: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        for byte in unsafe { self.tokenid.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
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

/// Why `obtain` failed, so the supervisor can choose a retry policy: an
/// unreachable gateway is cheap to retry (no browser opened), while an
/// unanswered SSO tab means nobody is there and retrying just stacks up tabs.
#[derive(Debug)]
pub enum SamlError {
    /// Failed before the browser opened (offline, DNS, TLS, gateway down).
    Unreachable(String),
    /// The browser opened but nobody completed SSO before the timeout.
    Timeout,
}

impl std::fmt::Display for SamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SamlError::Unreachable(e) => write!(f, "{e}"),
            SamlError::Timeout => f.write_str("SAML: timed out waiting for the browser callback"),
        }
    }
}

impl Error for SamlError {}

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
    let uid = crate::uid::platform_uid().unwrap_or(gen_uid()?);
    let html =
        bootstrap_post(cfg, port, &uid).map_err(|e| SamlError::Unreachable(e.to_string()))?;
    let saml_url = extract_saml_url(&html)
        .ok_or("SAML: could not find the window.location redirect in the gateway response")?;

    // 3. open the SAML URL in the system browser
    // The URL can carry a short-lived login handle; do not persist it in logs.
    log!("Opening browser for SSO");
    open_browser(&saml_url)?;
    log!("Waiting for the SAML callback on http://127.0.0.1:{port}/ (up to {}s)…",
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
                let mut req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let creds = parse_callback(&req);
                // The callback lands on "/"; anything else (favicon, probes) gets
                // a bare 404 rather than a misleading status page.
                let on_root = req
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|p| p == "/" || p.starts_with("/?"));
                let (status, page) = if on_root {
                    ("200 OK", callback_page(creds.as_ref()))
                } else {
                    ("404 Not Found", String::new())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    page.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(page.as_bytes());
                let _ = stream.flush();
                for byte in unsafe { req.as_bytes_mut() } {
                    unsafe { std::ptr::write_volatile(byte, 0) };
                }
                buf.fill(0);
                if let Some(c) = creds {
                    return Ok(c);
                }
                // not the callback (e.g. a favicon request) — keep waiting
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(SamlError::Timeout.into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

const CALLBACK_HTML: &str = include_str!("callback.html");

/// Log lines naming the tunnel being signed in, from the supervisor's
/// `OFTC_PROFILE_NAME` / `OFTC_PROFILE_GATEWAY`; empty when neither is set.
fn tunnel_lines() -> String {
    let line = |label: &str, dots: usize, value: String| {
        format!(
            "<div class=\"l\"><span class=\"d\">&gt; {label} {} </span>{}</div>\n",
            ".".repeat(dots),
            html_escape(&value)
        )
    };
    let mut out = String::new();
    if let Ok(name) = std::env::var("OFTC_PROFILE_NAME") {
        if !name.is_empty() { out.push_str(&line("tunnel", 31, name)); }
    }
    if let Ok(gateway) = std::env::var("OFTC_PROFILE_GATEWAY") {
        if !gateway.is_empty() { out.push_str(&line("gateway", 30, gateway)); }
    }
    out
}

/// The browser-tab page: success or failure, with the prompt showing the SAML
/// username (else the local `$USER`). The username and tunnel names are
/// HTML-escaped.
fn callback_page(creds: Option<&Credentials>) -> String {
    let user = creds
        .map(|c| c.username.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "operator".into());
    CALLBACK_HTML
        .replace("{{TUNNEL}}", &tunnel_lines())
        .replace("{{STATE}}", if creds.is_some() { "ok" } else { "fail" })
        .replace("{{USER}}", &html_escape(&user))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
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
                // tokenid may arrive without username in some flows.
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
    match String::from_utf8(out) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            let value = String::from_utf8_lossy(&bytes).into_owned();
            bytes.fill(0);
            value
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_page_escapes_username_and_sets_state() {
        let c = Credentials { username: "<x>@y".into(), tokenid: "t".into(), uid: String::new() };
        let page = callback_page(Some(&c));
        assert!(page.contains(r#"<body class="ok">"#));
        assert!(page.contains("&lt;x&gt;@y:~$"));
        assert!(!page.contains("{{"));
        assert!(callback_page(None).contains(r#"<body class="fail">"#));
    }

    #[test]
    fn callback_page_names_the_tunnel_when_the_supervisor_sets_it() {
        std::env::set_var("OFTC_PROFILE_NAME", "Colo <1>");
        std::env::set_var("OFTC_PROFILE_GATEWAY", "vpn.lab.example");
        let page = callback_page(None);
        std::env::remove_var("OFTC_PROFILE_NAME");
        std::env::remove_var("OFTC_PROFILE_GATEWAY");
        assert!(page.contains("&gt; tunnel ") && page.contains("Colo &lt;1&gt;"));
        assert!(page.contains("&gt; gateway ") && page.contains("vpn.lab.example"));
        assert!(!page.contains("{{"));
    }

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
