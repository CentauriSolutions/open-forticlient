//! oftc — open-forticlient keep-alive controller (prototype).
//!
//! Goal (ROADMAP §C / Issue 6): bring up the FortiGate IPsec IKEv2 + SAML tunnel
//! by driving Fortinet's own `fctctld`/`iked` over the vpn_control socket, and
//! never issue a DISCONNECT on screen lock — so the tunnel survives lock.
//!
//! This file is the CLI skeleton. `probe` and `build-connect` work today;
//! `connect` is the not-yet-implemented full bring-up.

mod connect;
mod control;
mod doctor;
mod fctcrypt;
mod profile;
mod proto;
mod saml;
mod tls;

use std::error::Error;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "oftc — open-forticlient keep-alive controller (prototype)

USAGE:
    oftc probe [--socket PATH]
        Connect to fctctld's control socket and confirm it accepts us.
        Harmless: connects and immediately closes, sends nothing.
        Default socket: {main}

    oftc build-connect [--profile NAME] [--out FILE] [--with-psk]
        Load the installed profile (vpn.plist via plutil) + iked.conf, assemble
        the CONNECT body, and write it to FILE (default: connect-body.bin).
        Offline — does not touch the daemon. --with-psk includes the secret PSK
        (writes a secret to disk); omitted by default.

    oftc saml [--profile NAME] [--insecure] [--show-token]
        Run only the SAML flow (POST /saml_login?, open browser, catch the
        loopback redirect) and print the username + tokenid. Opens a browser
        and needs a real SSO login. Token is masked unless --show-token.

    oftc trust [--profile NAME]
        Show the gateway's TLS certificate (subject/issuer/dates/SHA-256) and
        offer to pin it for trust-on-first-use. Run once if the gateway uses a
        self-signed or internal-CA cert.

    oftc connect [--profile NAME] [--insecure] [--no-auto-otp]
        Full bring-up: SAML -> CONNECT -> answer the OTP prompt -> watch STATUS,
        and never disconnect on lock. Logs every control-socket message.

    oftc disconnect [--profile NAME]
        Tear the tunnel down cleanly (sends DISCONNECT to the daemon).

    oftc doctor [--dry-run] [--restore] [--yes]
        Check that FortiClient (fctctld + iked) is installed and reachable, that
        a PSK is configured, and whether FortiTray is running. FortiTray drops
        the VPN on screen lock; doctor offers to disable it (and its launch
        agents) via a macOS admin prompt. --dry-run prints the commands without
        running; --restore re-enables FortiTray; --yes skips the confirmation.

    oftc install [--profile NAME] [--keep-tray]
        Install the oftc LaunchAgent (so launchd manages a persistent connect
        session) and disable FortiTray's launch agents. --keep-tray installs our
        agent only. Copies the binary + PSK to stable per-user locations.

    oftc up / oftc down [--profile NAME]
        Poke the installed agent: `up` starts a connect session (opens the SSO
        browser, holds the tunnel across lock); `down` disconnects and stops it.

    oftc uninstall [--purge] [--keep-tray-disabled]
        Remove the oftc agent and re-enable FortiTray. --purge also removes the
        stored PSK and logs; --keep-tray-disabled leaves FortiTray disabled.

    oftc status [--profile NAME]
        Show config + tunnel state: server, PSK source, whether the tunnel is up,
        whether an oftc session is holding it, and if FortiTray is running.

    oftc show-psk [--profile NAME]
        Print the plaintext pre-shared key (decrypted from AuthInfo, or the
        override) to stdout. It is a secret — handle with care.
",
        main = proto::MAIN_SOCKET
    );
    std::process::exit(2);
}

/// Mask a secret for display (length + short prefix), like saml_catch.py.
fn mask(s: &str) -> String {
    let prefix: String = s.chars().take(4).collect();
    format!("<{} chars, starts {:?}>", s.len(), prefix)
}

fn saml_config(p: &profile::Profile, args: &[String]) -> saml::SamlConfig {
    saml::SamlConfig {
        server: p.server.clone(),
        saml_port: p.saml_port,
        insecure: has_flag(args, "--insecure"),
        ..Default::default()
    }
}

fn arg_val(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("probe") => cmd_probe(&args),
        Some("build-connect") => cmd_build_connect(&args),
        Some("saml") => cmd_saml(&args),
        Some("trust") => cmd_trust(&args),
        Some("connect") => cmd_connect(&args),
        Some("send-connect") => cmd_send_connect(&args),
        Some("disconnect") => cmd_disconnect(&args),
        Some("doctor") => doctor::doctor(&args),
        Some("install") => doctor::install(&args),
        Some("uninstall") => doctor::uninstall(&args),
        Some("up") => doctor::up(&args),
        Some("down") => doctor::down(&args),
        Some("show-psk") => doctor::show_psk(&args),
        Some("status") => doctor::status(&args),
        _ => usage(),
    }
}

/// Phase 0 empirical check: does fctctld accept an unprivileged, non-FortiTray
/// peer? Connecting is enough (the socket is launchd-activated).
fn cmd_probe(args: &[String]) -> Result<(), Box<dyn Error>> {
    let sock = arg_val(args, "--socket").unwrap_or_else(|| proto::MAIN_SOCKET.to_string());
    print!("connecting to {sock} ... ");
    std::io::stdout().flush().ok();
    let stream = UnixStream::connect(&sock)?;
    stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
    println!("OK — fctctld accepted the connection (unprivileged peer, no auth).");
    drop(stream);
    Ok(())
}

/// Assemble the CONNECT body from the installed config and write it out, so we
/// can inspect it and (later) diff the iked.conf fctctld generates from it.
fn cmd_build_connect(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = profile::resolve_profile(arg_val(args, "--profile").as_deref());
    let out = arg_val(args, "--out").unwrap_or_else(|| "connect-body.bin".to_string());
    let with_psk = has_flag(args, "--with-psk");

    let p = profile::Profile::load(&name)?;
    eprintln!(
        "profile {:?}:\n  server={:?} user={:?} saml_port={}\n  peer={:?} psk={}\n  ike v{} transport={} udp={} tcp={} p1dh={} p2dh={} pfs={}",
        p.name, p.server, p.user, p.saml_port, p.peer_ip,
        if p.psk.is_empty() { "<none found>" } else { "<present>" },
        p.ike_version, p.transport_mode, p.udp_port, p.tcp_port, p.p1_dh_group, p.p2_dh_group, p.pfs,
    );
    if p.server.is_empty() {
        eprintln!("warning: no Server found — is the profile name right? (try --profile \"Office VPN\")");
    }

    let tok = arg_val(args, "--token");
    let body = connect::ConnConfig::from_profile(&p, with_psk, tok.as_deref()).into_bytes();
    std::fs::write(&out, &body)?;
    println!(
        "wrote {} byte CONNECT body to {}{}",
        body.len(),
        out,
        if with_psk { "  (contains the PSK — do not commit)" } else { "  (PSK omitted; pass --with-psk to include)" }
    );
    Ok(())
}

/// Run only the SAML flow and print the result (token masked by default).
fn cmd_saml(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = profile::resolve_profile(arg_val(args, "--profile").as_deref());
    let p = profile::Profile::load(&name)?;
    if p.server.is_empty() {
        return Err(format!("no Server for profile {name:?} (try --profile \"Office VPN\")").into());
    }
    let creds = saml::obtain(&saml_config(&p, args))?;
    let shown = if has_flag(args, "--show-token") {
        creds.tokenid.clone()
    } else {
        mask(&creds.tokenid)
    };
    println!("SAML OK\n  username = {}\n  tokenid  = {}", creds.username, shown);
    Ok(())
}

/// Review and (optionally) pin the gateway's TLS certificate.
fn cmd_trust(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = profile::resolve_profile(arg_val(args, "--profile").as_deref());
    let p = profile::Profile::load(&name)?;
    if p.server.is_empty() {
        return Err(format!("no Server for profile {name:?} (try --profile \"Office VPN\")").into());
    }
    eprintln!("Fetching certificate for {}:{} …", p.server, p.saml_port);
    let pem = tls::fetch_cert_pem(&p.server, p.saml_port)?;
    let info = tls::cert_info(&pem)?;
    println!("--- gateway certificate ---\n{}---------------------------", info);
    print!("Trust and pin this certificate for {}:{}? [y/N] ", p.server, p.saml_port);
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        let path = tls::pin(&p.server, p.saml_port, &pem)?;
        println!("pinned -> {}", path.display());
    } else {
        println!("not pinned.");
    }
    Ok(())
}

/// Send a prebuilt CONNECT body (no SAML) and log the daemon's replies. For
/// iterating on the connect-validation path without burning a single-use token;
/// the validation runs before any credential is used.
fn cmd_send_connect(args: &[String]) -> Result<(), Box<dyn Error>> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let path = arg_val(args, "--body").ok_or("need --body FILE (from build-connect)")?;
    let body = std::fs::read(&path)?;
    let mut stream = UnixStream::connect(proto::MAIN_SOCKET)?;
    eprintln!("-> CONNECT ({} bytes) from {path}", body.len());
    proto::Message::new(proto::Command::Connect, body).write_to(&mut stream)?;
    // Optional: after a delay (once iked is up), push an OTP for timing tests.
    if let Some(tok) = arg_val(args, "--otp") {
        let secs: u64 = arg_val(args, "--otp-delay").and_then(|s| s.parse().ok()).unwrap_or(4);
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("<- SEND_OTP after {secs}s (token {} chars)", tok.len());
        control::otp_message(&tok).write_to(&mut stream)?;
    }
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while std::time::Instant::now() < deadline {
        match proto::Message::read_from(&mut stream) {
            Ok(m) => {
                let prev: String = m.body.iter().take(16).map(|b| format!("{b:02x}")).collect();
                eprintln!(
                    "<- {:?} field16={} body={}B {}  status={:?}",
                    m.command, m.field16, m.body.len(), prev, m.status_code()
                );
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    Ok(())
}

/// Tear the tunnel down cleanly: send DISCONNECT (cmd 5) — the same message
/// FortiTray wrongly sends on lock, but here it is an explicit user teardown.
/// Body is the 0x40-byte gateway id (server FQDN, zero-padded).
fn cmd_disconnect(args: &[String]) -> Result<(), Box<dyn Error>> {
    use std::io::ErrorKind;
    use std::time::Instant;
    let name = profile::resolve_profile(arg_val(args, "--profile").as_deref());
    let p = profile::Profile::load(&name)?;
    let mut body = vec![0u8; 0x40];
    let s = p.server.as_bytes();
    let n = s.len().min(0x3f);
    body[..n].copy_from_slice(&s[..n]);
    let mut stream = UnixStream::connect(proto::MAIN_SOCKET)?;
    proto::Message::new(proto::Command::Disconnect, body).write_to(&mut stream)?;
    eprintln!("-> DISCONNECT ({})", p.server);
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match proto::Message::read_from(&mut stream) {
            Ok(m) => {
                if m.command == proto::Command::Status {
                    if let Some(c) = m.status_code() {
                        eprintln!("   STATUS code = {c}");
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    Ok(())
}

fn cmd_connect(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = profile::resolve_profile(arg_val(args, "--profile").as_deref());
    let p = profile::Profile::load(&name)?;
    if p.server.is_empty() {
        return Err(format!("no Server for profile {name:?} (try --profile \"Office VPN\")").into());
    }
    if p.psk.is_empty() {
        // Fail loudly rather than sending an empty PSK (which the gateway
        // rejects as "wrong PSK" with no hint why). Reached when the profile's
        // AuthInfo could not be decrypted — e.g. a FortiClient build whose `Enc`
        // key/scheme differs from the one oftc reverse-engineered.
        return Err(
            "no usable pre-shared key. The profile's AuthInfo is not the PSK (it either did \
             not decrypt, or it holds the saved SAML username rather than the key), and no \
             override is set. Get the FortiGate phase1 psksecret from an admin (they can run \
             `oftc show-psk`) and provide it via $FORTIGATE_PSK, a .env (FORTIGATE_PSK=…), or \
             ~/.config/oftc/psk, then retry."
            .into(),
        );
    }
    // 1. SAML -> (username, tokenid)
    let creds = saml::obtain(&saml_config(&p, args))?;
    eprintln!("SAML OK: username={} tokenid={}", creds.username, mask(&creds.tokenid));

    // 2-3. CONNECT -> (delay) push OTP over the socket (iked needs the token in
    // g_fct_eap_password before the EAP step) -> hold socket open; never
    // DISCONNECT on lock. Delay lands after iked is up (~1s) and before EAP
    // (~3.5s). Token is also embedded in CONNECT (ipsec/auth) as a belt-and-braces.
    let opts = control::SessionOpts {
        auto_otp: !has_flag(args, "--no-otp"),
        otp_delay: std::time::Duration::from_secs(
            arg_val(args, "--otp-delay").and_then(|s| s.parse().ok()).unwrap_or(2),
        ),
    };
    control::run(&p, &creds, &opts)?;
    Ok(())
}
