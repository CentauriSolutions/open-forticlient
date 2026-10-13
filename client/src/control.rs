//! Drive `fctctld` over the control socket: send CONNECT, answer the OTP prompt
//! with the SAML token, and watch STATUS events. Deliberately does NOT register
//! for or react to screen lock — that is the whole point (the tunnel stays up).
#![allow(dead_code)]

use std::error::Error;
use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::connect::ConnConfig;
use crate::log::log;
use crate::profile::Profile;
use crate::proto::{Command, Message, MAIN_SOCKET};
use crate::saml::Credentials;

pub struct SessionOpts {
    /// Push the SAML token as the EAP OTP.
    pub auto_otp: bool,
    /// Delay after CONNECT before sending the OTP, so iked is up to receive it
    /// (sending immediately loses it: fctctld logs "iked is down").
    pub otp_delay: Duration,
}

impl Default for SessionOpts {
    fn default() -> Self {
        SessionOpts { auto_otp: true, otp_delay: Duration::from_secs(4) }
    }
}

// SEND_OTP body: token (0x400) + a second field (0x40); total message 0x478,
// so body = 0x478 - 20-byte header = 0x464. (From FortiTray's ipsec_send_otp.)
const OTP_BODY_LEN: usize = 0x464;
const OTP_TOKEN_MAX: usize = 0x400;

/// STATUS code fctctld sends once the tunnel is up (observed: 1 connecting ->
/// 8 -> 2, then held until a drop sends 3).
const STATUS_UP: u32 = 2;
const STATUS_ERROR: u32 = 3;

/// How a session ended. `up_at` lets the supervisor tell "the tunnel came up
/// and later dropped" from "it never came up", which need different retry
/// policies.
pub struct SessionEnd {
    /// When the daemon first reported the tunnel up, if it ever did.
    pub up_at: Option<Instant>,
    pub result: Result<(), Box<dyn Error>>,
}

/// Bring the tunnel up and hold it. `on_up` fires once, when the daemon first
/// reports the tunnel up.
pub fn run(p: &Profile, creds: &Credentials, opts: &SessionOpts, on_up: &mut dyn FnMut()) -> SessionEnd {
    let mut up_at = None;
    let result = hold(p, creds, opts, &mut up_at, on_up);
    SessionEnd { up_at, result }
}

fn hold(
    p: &Profile,
    creds: &Credentials,
    opts: &SessionOpts,
    up_at: &mut Option<Instant>,
    on_up: &mut dyn FnMut(),
) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(MAIN_SOCKET)?;

    // The token travels INSIDE the CONNECT (EAP password at +0xc1); fctctld
    // writes it with the username to ipsec/auth for iked. No separate OTP send
    // is needed for the primary SAML auth.
    // The EAP identity (CONNECT +0x80) must equal the UID we sent to the SAML
    // bootstrap — the gateway keys its SAML auth cache by it, and FNBAM looks it
    // up by the EAP identity. Thread the exact value through so they match.
    let mut prof = p.clone();
    if !creds.uid.is_empty() {
        prof.uid = creds.uid.clone();
    }
    let body = ConnConfig::from_profile(&prof, true, Some(&creds.tokenid)).into_bytes();
    log!("-> CONNECT ({} byte body, token embedded) on {MAIN_SOCKET}", body.len());
    Message::new(Command::Connect, body).write_to(&mut stream)?;

    if opts.auto_otp {
        log!("   waiting {}s, then also pushing OTP over the socket (fallback)…", opts.otp_delay.as_secs());
        std::thread::sleep(opts.otp_delay);
        send_otp(&mut stream, &creds.tokenid)?;
    }

    // Hold the control socket open: that is what keeps the tunnel up. We never
    // close it on our own, and we register nothing for screen lock — so a lock
    // does not tear the tunnel down. Read timeouts just let us log periodically.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    log!("   holding control socket open — tunnel stays up while this runs (Ctrl-C to disconnect).");
    log!("   watch: tail -f \"/Library/Application Support/Fortinet/FortiClient/Logs/fctctl.log\"");
    loop {
        match Message::read_from(&mut stream) {
            Ok(msg) => {
                log_incoming(&msg);
                if msg.command == Command::Status {
                    if let Some(code) = msg.status_code() {
                        log!("   STATUS code = {code}");
                        // Keep holding through every non-error code — that is
                        // the whole point, survive lock. Code 3 = error: stop
                        // so we don't hold a dead socket.
                        if code == STATUS_UP && up_at.is_none() {
                            *up_at = Some(Instant::now());
                            log!("tunnel up");
                            on_up();
                        }
                        if code == STATUS_ERROR {
                            return Err(
                                "ipsec connection failed (daemon STATUS code 3)".into(),
                            );
                        }
                    }
                }
                if msg.command == Command::Disconnect {
                    log!("   daemon signalled DISCONNECT — ending");
                    break;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // idle; keep holding the socket (and thus the tunnel) open
            }
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                log!("control socket closed by the daemon");
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Build a SEND_OTP message carrying the token at body+0.
pub fn otp_message(token: &str) -> Message {
    let mut body = vec![0u8; OTP_BODY_LEN];
    let t = token.as_bytes();
    let n = t.len().min(OTP_TOKEN_MAX - 1);
    body[..n].copy_from_slice(&t[..n]);
    Message::new(Command::SendOtp, body)
}

fn send_otp(stream: &mut UnixStream, token: &str) -> Result<(), Box<dyn Error>> {
    log!("<- SEND_OTP (token {} chars, masked)", token.len());
    otp_message(token).write_to(stream)?;
    Ok(())
}

fn log_incoming(msg: &Message) {
    let preview: String = msg
        .body
        .iter()
        .take(48)
        .map(|b| format!("{b:02x}"))
        .collect();
    log!(
        "<- {:?} field4={} field16={} body={}B {}{}",
        msg.command,
        msg.field4,
        msg.field16,
        msg.body.len(),
        preview,
        if msg.body.len() > 48 { "…" } else { "" }
    );
}
