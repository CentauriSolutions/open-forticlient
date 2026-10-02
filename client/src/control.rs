//! Drive `fctctld` over the control socket: send CONNECT, answer the OTP prompt
//! with the SAML token, and watch STATUS events. Deliberately does NOT register
//! for or react to screen lock — that is the whole point (the tunnel stays up).
#![allow(dead_code)]

use std::error::Error;
use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::connect::ConnConfig;
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

pub fn run(p: &Profile, creds: &Credentials, opts: &SessionOpts) -> Result<(), Box<dyn Error>> {
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
    eprintln!("-> CONNECT ({} byte body, token embedded) on {MAIN_SOCKET}", body.len());
    Message::new(Command::Connect, body).write_to(&mut stream)?;

    if opts.auto_otp {
        eprintln!("   waiting {}s, then also pushing OTP over the socket (fallback)…", opts.otp_delay.as_secs());
        std::thread::sleep(opts.otp_delay);
        send_otp(&mut stream, &creds.tokenid)?;
    }

    // Hold the control socket open: that is what keeps the tunnel up. We never
    // close it on our own, and we register nothing for screen lock — so a lock
    // does not tear the tunnel down. Read timeouts just let us log periodically.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    eprintln!("   holding control socket open — tunnel stays up while this runs (Ctrl-C to disconnect).");
    eprintln!("   watch: tail -f \"/Library/Application Support/Fortinet/FortiClient/Logs/fctctl.log\"");
    loop {
        match Message::read_from(&mut stream) {
            Ok(msg) => {
                log_incoming(&msg);
                if msg.command == Command::Status {
                    if let Some(code) = msg.status_code() {
                        eprintln!("   STATUS code = {code}");
                        // code 1 = connecting, higher = connected/up (keep
                        // holding — that is the whole point, survive lock);
                        // code 3 = error: stop so we don't hold a dead socket.
                        if code == 3 {
                            return Err(
                                "ipsec connection failed (daemon STATUS code 3)".into(),
                            );
                        }
                    }
                }
                if msg.command == Command::Disconnect {
                    eprintln!("   daemon signalled DISCONNECT — ending");
                    break;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // idle; keep holding the socket (and thus the tunnel) open
            }
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                eprintln!("control socket closed by the daemon");
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
    eprintln!("<- SEND_OTP (token {} chars, masked)", token.len());
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
    eprintln!(
        "<- {:?} field4={} field16={} body={}B {}{}",
        msg.command,
        msg.field4,
        msg.field16,
        msg.body.len(),
        preview,
        if msg.body.len() > 48 { "…" } else { "" }
    );
}
