//! Trust-on-first-use for gateway certificates that macOS does not trust, such as a
//! FortiGate's factory certificate. A decision is stored as a pinned certificate
//! (the store lives in `oftc_host_bootstrap::tls`, which the SAML bootstrap checks by
//! public key). Nothing is trusted without the user's explicit choice.
//!
//! Ported from the Swift `GatewayTrust`. The one deliberate change is the probe:
//! `URLSession` is replaced by [`ChainSource`] (the chain the gateway presents,
//! from `openssl s_client`) plus [`Evaluator`] (the system trust decision on it), so
//! the verdict is plain logic over two seams. Only `SystemTrustEvaluator` and
//! `OpensslChainSource` touch the system; every table test injects doubles.
//!
//! The library has no caller yet: the reconnect supervisor is the only one.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use oftc_host_bootstrap::tls;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- certificates

/// A gateway certificate as shown to the user for a trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub validity: String,
}

/// The `openssl x509 -noout -subject ...` text for a DER certificate.
pub trait X509Text {
    fn describe(&self, der: &[u8]) -> Option<String>;
}

/// `/usr/bin/openssl x509`, as the Swift code ran it.
pub struct OpensslText;

impl X509Text for OpensslText {
    fn describe(&self, der: &[u8]) -> Option<String> {
        let mut child = Command::new("/usr/bin/openssl")
            .args([
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-startdate",
                "-enddate",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        // Feed the input from a thread: a certificate larger than the pipe buffer
        // must not deadlock against our own read.
        let mut stdin = child.stdin.take()?;
        let input = der.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().ok()?;
        let _ = writer.join();
        if output.status.success() {
            String::from_utf8(output.stdout).ok()
        } else {
            None
        }
    }
}

impl Certificate {
    pub fn new(der: Vec<u8>, subject: &str, issuer: &str, serial: &str, validity: &str) -> Self {
        Certificate {
            der,
            subject: subject.to_owned(),
            issuer: issuer.to_owned(),
            serial: serial.to_owned(),
            validity: validity.to_owned(),
        }
    }

    /// `None` unless `der` is a single DER SEQUENCE spanning all the bytes (the
    /// Swift code asked `SecCertificateCreateWithData`, which is stricter). The
    /// display fields come from openssl; whatever it does not give is `Unknown`.
    pub fn from_der(der: Vec<u8>, text: &dyn X509Text) -> Option<Certificate> {
        if !is_der_sequence(&der) {
            return None;
        }
        let described = text.describe(&der).unwrap_or_default();
        let field = |name: &str| -> Option<String> {
            described.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
        };
        let unknown = || "Unknown".to_owned();
        let validity = match (field("notBefore"), field("notAfter")) {
            (Some(from), Some(to)) => format!("{from} to {to}"),
            _ => unknown(),
        };
        Some(Certificate {
            subject: field("subject").unwrap_or_else(unknown),
            issuer: field("issuer").unwrap_or_else(unknown),
            serial: field("serial").unwrap_or_else(unknown),
            validity,
            der,
        })
    }

    pub fn from_pem(pem: &str, text: &dyn X509Text) -> Option<Certificate> {
        Certificate::from_der(tls::pem_decode(pem)?, text)
    }

    /// Upper-case hex pairs separated by colons.
    pub fn sha256(&self) -> String {
        Sha256::digest(&self.der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn pem(&self) -> String {
        tls::pem_encode(&self.der)
    }
}

/// A DER SEQUENCE whose declared length is exactly the rest of the bytes.
fn is_der_sequence(der: &[u8]) -> bool {
    let [0x30, first, rest @ ..] = der else {
        return false;
    };
    let (length, content) = if *first < 0x80 {
        (usize::from(*first), rest)
    } else {
        let count = usize::from(*first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return false;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |n, b| n << 8 | usize::from(*b));
        (length, &rest[count..])
    };
    length > 0 && content.len() == length
}

// --------------------------------------------------------------------- the pin

/// The pinned certificate for `host:port`, if the pin parses as a certificate.
pub fn pinned(dir: &Path, host: &str, port: u32, text: &dyn X509Text) -> Option<Certificate> {
    Certificate::from_der(tls::read_pin(dir, host, port)?, text)
}

// ----------------------------------------------------------------------- probe

/// What the probe concluded about a gateway's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    SystemTrusted,
    Untrusted(Certificate),
    Unreachable,
}

pub trait TrustProbe {
    fn probe(&self, host: &str, port: u32) -> Verdict;
}

/// The host a chain is evaluated against: a name, or an address (IP literals have
/// no name to match, so the evaluator checks them as addresses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Name(String),
    Address(IpAddr),
}

impl Target {
    /// `[::1]` and `::1` are both the address; anything else is a name, unchanged.
    pub fn parse(host: &str) -> Target {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match bare.parse::<IpAddr>() {
            Ok(address) => Target::Address(address),
            Err(_) => Target::Name(host.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evaluation {
    Trusted,
    /// The chain is complete enough to evaluate and the system does not trust it.
    Rejected,
    /// The evaluation could not be made, or failed for a reason that is not a
    /// verdict on the certificate (see [`classify_failure`]).
    Error,
}

/// The system trust decision on a chain (leaf first).
pub trait Evaluator {
    fn evaluate(&self, chain: &[Vec<u8>], target: &Target, allow_network_fetch: bool)
        -> Evaluation;
}

/// The chain a gateway presents in its TLS handshake, leaf first; `None` when the
/// connection or handshake failed or presented no certificate.
pub trait ChainSource {
    fn fetch(&self, host: &str, port: u32) -> Option<Vec<Vec<u8>>>;
}

/// The probe: fetch the chain, ask the system. `URLSession` could fetch missing
/// intermediates, so the evaluation allows network fetches too.
pub struct ChainProbe<'a> {
    pub source: &'a dyn ChainSource,
    pub evaluator: &'a dyn Evaluator,
    pub text: &'a dyn X509Text,
}

impl TrustProbe for ChainProbe<'_> {
    fn probe(&self, host: &str, port: u32) -> Verdict {
        let Some(chain) = self
            .source
            .fetch(host, port)
            .filter(|chain| !chain.is_empty())
        else {
            return Verdict::Unreachable;
        };
        match self.evaluator.evaluate(&chain, &Target::parse(host), true) {
            Evaluation::Trusted => Verdict::SystemTrusted,
            Evaluation::Error => Verdict::Unreachable,
            Evaluation::Rejected => Certificate::from_der(chain[0].clone(), self.text)
                .map_or(Verdict::Unreachable, Verdict::Untrusted),
        }
    }
}

/// At most this many certificates are read from one handshake.
pub const MAX_CHAIN: usize = 8;

/// The certificates in `openssl s_client -showcerts` output, in order. Other text
/// and non-certificate PEM blocks are skipped, CRLF is accepted, and `s_client`'s
/// closing repeat of the leaf is dropped by ignoring a DER already seen. A block
/// that is truncated ends the list; one that is not base64 makes the whole output
/// unusable, since the leaf could be the broken one.
pub fn parse_chain(output: &str) -> Option<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut rest = output;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        let body: String = after[..end].split(['\n', '\r']).collect();
        let der = tls::base64_decode(body.trim())?;
        if !chain.contains(&der) && chain.len() < MAX_CHAIN {
            chain.push(der);
        }
        rest = &after[end + END.len()..];
    }
    Some(chain).filter(|chain| !chain.is_empty())
}

/// `host:port` as `openssl -connect` wants it: an IPv6 literal is bracketed.
pub fn connect_arg(host: &str, port: u32) -> String {
    match Target::parse(host) {
        Target::Address(IpAddr::V6(address)) => format!("[{address}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// The `openssl s_client` argument list: SNI is sent for names only.
pub fn s_client_args(host: &str, port: u32) -> Vec<String> {
    let mut args = vec![
        "s_client".to_owned(),
        "-connect".into(),
        connect_arg(host, port),
    ];
    if let Target::Name(name) = Target::parse(host) {
        args.extend(["-servername".to_owned(), name]);
    }
    args.push("-showcerts".into());
    args
}

/// `/usr/bin/openssl s_client`, killed after `timeout`.
pub struct OpensslChainSource {
    pub timeout: Duration,
}

impl Default for OpensslChainSource {
    fn default() -> Self {
        OpensslChainSource {
            timeout: Duration::from_secs(15),
        }
    }
}

impl ChainSource for OpensslChainSource {
    fn fetch(&self, host: &str, port: u32) -> Option<Vec<Vec<u8>>> {
        let mut child = Command::new("/usr/bin/openssl")
            .args(s_client_args(host, port))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut stdout = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = stdout.read_to_end(&mut text);
            text
        });
        let deadline = Instant::now() + self.timeout;
        let finished = loop {
            match child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        };
        let text = reader.join().ok()?;
        if !finished {
            return None;
        }
        parse_chain(&String::from_utf8_lossy(&text))
    }
}

/// `NSOSStatusErrorDomain`: the domain of the `CFError` `SecTrustEvaluateWithError`
/// gives for a failed chain, with the `OSStatus` as the code.
pub const OSSTATUS_DOMAIN: &str = "NSOSStatusErrorDomain";

/// The codes below were observed from `SecTrustEvaluateWithError` on throwaway
/// chains (see `trust/loopback.rs`); only these mean the chain itself is what the
/// system rejects.
const ERR_NOT_TRUSTED: i64 = -67843; // errSecNotTrusted: a self-signed leaf
const ERR_UNTRUSTED_ISSUER: i64 = -25318; // errSecCreateChainFailed: no chain to a trusted root could be built
const ERR_CERTIFICATE_EXPIRED: i64 = -67818;
const ERR_HOST_NAME_MISMATCH: i64 = -67602;

/// -25318 is also what a missing or truncated chain gives (the chain cannot be built),
/// so a network-dependent one would still prompt. Deliberately *not* listed, so they are
/// `Error` (silent, fail-closed, retried until the acquisition deadline): -67819 (not
/// yet valid), -67820 (revoked), -67635 and -67654.
///
/// What a failed `SecTrustEvaluateWithError` says about the chain. The old
/// `URLSession` check treated every failure as "untrusted", which cannot tell a bad
/// certificate from an evaluation that could not run (a network-dependent step such
/// as an issuer or revocation fetch failing while the network is down). A prompt is
/// only right for the first: anything not known to be a verdict on the certificate
/// is `Error`, which the probe reports as `Unreachable` (no prompt, the supervisor
/// retries).
pub fn classify_failure(domain: &str, code: i64) -> Evaluation {
    let about_the_chain = domain == OSSTATUS_DOMAIN
        && matches!(
            code,
            ERR_NOT_TRUSTED
                | ERR_UNTRUSTED_ISSUER
                | ERR_CERTIFICATE_EXPIRED
                | ERR_HOST_NAME_MISMATCH
        );
    if about_the_chain {
        Evaluation::Rejected
    } else {
        Evaluation::Error
    }
}

/// The one diagnostic line for an evaluation that did not come out `Trusted`: the
/// verdict it was mapped to, the `CFError` domain and code (`none` when the
/// evaluation was not reached), and the chain length. No names, no certificate bytes.
pub fn failure_line(
    verdict: Evaluation,
    domain: &str,
    code: Option<i64>,
    chain_len: usize,
) -> String {
    let code = code.map_or_else(|| "none".to_owned(), |code| code.to_string());
    format!("OFTC trust: evaluation {verdict:?} domain={domain} code={code} chain={chain_len}")
}

/// `SecTrust` on `chain` (leaf first). Empty `anchors` means the system's own;
/// otherwise only `anchors` are trusted (this is how a test supplies a root). A
/// result other than `Trusted` is reported to `log` (see [`failure_line`]).
#[cfg(target_os = "macos")]
pub fn evaluate_chain(
    chain: &[Vec<u8>],
    target: &Target,
    allow_network_fetch: bool,
    anchors: &[Vec<u8>],
    log: &dyn Fn(&str),
) -> Evaluation {
    let setup_failed = || {
        log(&failure_line(Evaluation::Error, "setup", None, chain.len()));
        Evaluation::Error
    };
    use security_framework::certificate::SecCertificate;
    use security_framework::policy::SecPolicy;
    use security_framework::secure_transport::SslProtocolSide;
    use security_framework::trust::SecTrust;

    let hostname = match target {
        Target::Name(name) => name.clone(),
        Target::Address(address) => address.to_string(),
    };
    let load = |ders: &[Vec<u8>]| -> Option<Vec<SecCertificate>> {
        ders.iter()
            .map(|der| SecCertificate::from_der(der).ok())
            .collect()
    };
    let (Some(certificates), Some(roots)) = (load(chain), load(anchors)) else {
        return setup_failed();
    };
    let policy = SecPolicy::create_ssl(SslProtocolSide::CLIENT, Some(&hostname));
    let Ok(mut trust) = SecTrust::create_with_certificates(&certificates, &[policy]) else {
        return setup_failed();
    };
    if trust
        .set_network_fetch_allowed(allow_network_fetch)
        .is_err()
    {
        return setup_failed();
    }
    if !roots.is_empty()
        && (trust.set_anchor_certificates(&roots).is_err()
            || trust.set_trust_anchor_certificates_only(true).is_err())
    {
        return setup_failed();
    }
    match trust.evaluate_with_error() {
        Ok(()) => Evaluation::Trusted,
        Err(error) => {
            let domain = error.domain().to_string();
            let code = i64::try_from(error.code()).ok();
            let verdict = code.map_or(Evaluation::Error, |code| classify_failure(&domain, code));
            log(&failure_line(verdict, &domain, code, chain.len()));
            verdict
        }
    }
}

/// The system trust store through Security.framework's `SecTrust`.
#[cfg(target_os = "macos")]
pub struct SystemTrustEvaluator<'a> {
    /// One line per evaluation that was not `Trusted` (the supervisor's diagnostic).
    pub log: &'a dyn Fn(&str),
}

#[cfg(target_os = "macos")]
impl Evaluator for SystemTrustEvaluator<'_> {
    fn evaluate(
        &self,
        chain: &[Vec<u8>],
        target: &Target,
        allow_network_fetch: bool,
    ) -> Evaluation {
        evaluate_chain(chain, target, allow_network_fetch, &[], self.log)
    }
}

// ---------------------------------------------------------------------- review

/// What the user is asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub profile_name: String,
    pub host: String,
    pub port: u32,
    pub certificate: Certificate,
    pub reason: Reason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Untrusted,
    Changed { previous: Certificate },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Trust,
    Decline,
    /// Nobody could be asked (no GUI session, the prompt could not run).
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    NotACertificateProblem,
    Trusted(Certificate),
    Declined,
}

pub trait TrustPrompt {
    fn ask(&self, review: &Review) -> Decision;
}

/// Everything [`Reviewer::review`] needs besides the gateway.
pub struct Reviewer<'a> {
    pub pin_dir: &'a Path,
    pub probe: &'a dyn TrustProbe,
    pub prompt: &'a dyn TrustPrompt,
    pub text: &'a dyn X509Text,
}

impl Reviewer<'_> {
    /// Called after the SAML bootstrap failed before any browser sign-in. Only a
    /// certificate that macOS and the pin both reject leads to a prompt.
    pub fn review(&self, host: &str, port: u32, profile_name: &str) -> Outcome {
        let Verdict::Untrusted(certificate) = self.probe.probe(host, port) else {
            return Outcome::NotACertificateProblem;
        };
        let previous = pinned(self.pin_dir, host, port, self.text);
        if previous
            .as_ref()
            .is_some_and(|old| old.sha256() == certificate.sha256())
        {
            return Outcome::NotACertificateProblem;
        }
        let reason = previous.map_or(Reason::Untrusted, |previous| Reason::Changed { previous });
        let review = Review {
            profile_name: profile_name.to_owned(),
            host: host.to_owned(),
            port,
            certificate: certificate.clone(),
            reason,
        };
        match self.prompt.ask(&review) {
            Decision::Unavailable => Outcome::NotACertificateProblem,
            Decision::Decline => Outcome::Declined,
            Decision::Trust => match tls::write_pin(self.pin_dir, host, port, &certificate.der) {
                Ok(()) => Outcome::Trusted(certificate),
                Err(_) => Outcome::Declined,
            },
        }
    }
}

// ------------------------------------------------------------- the prompt child

/// The JSON `OFTCAgent review-certificate` reads on stdin: Swift `JSONEncoder`
/// defaults, so `Data` is base64 and an absent `previous` is omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptRequest {
    pub profile_name: String,
    pub host: String,
    pub port: u32,
    pub certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
}

impl PromptRequest {
    pub fn for_review(review: &Review) -> PromptRequest {
        PromptRequest {
            profile_name: review.profile_name.clone(),
            host: review.host.clone(),
            port: review.port,
            certificate: tls::base64_encode(&review.certificate.der),
            previous: match &review.reason {
                Reason::Untrusted => None,
                Reason::Changed { previous } => Some(tls::base64_encode(&previous.der)),
            },
        }
    }

    pub fn to_json(&self) -> Option<Vec<u8>> {
        serde_json::to_vec(self).ok()
    }

    pub fn from_json(json: &[u8]) -> Option<PromptRequest> {
        serde_json::from_slice(json).ok()
    }
}

/// The child's exit status: 10 trust, 11 decline, anything else nothing to show.
pub fn decision_from_exit(code: Option<i32>) -> Decision {
    match code {
        Some(10) => Decision::Trust,
        Some(11) => Decision::Decline,
        _ => Decision::Unavailable,
    }
}

/// Runs the prompt child with `request` on its stdin; its exit status, or `None`
/// when it could not be started or was killed by a signal.
pub trait PromptChild {
    fn run(&self, request: &[u8]) -> Option<i32>;
}

/// `<executable> review-certificate`, with the request on stdin.
pub struct ProcessChild {
    pub executable: PathBuf,
}

impl PromptChild for ProcessChild {
    fn run(&self, request: &[u8]) -> Option<i32> {
        let mut child = Command::new(&self.executable)
            .arg("review-certificate")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            // A child that exits without reading closes the pipe; its status says so.
            let _ = stdin.write_all(request);
        }
        child.wait().ok()?.code()
    }
}

/// The prompt as the supervisor uses it: ask in a short-lived child, because the
/// supervisor's worker threads cannot build an AppKit window. With no GUI session
/// there is nobody to ask.
pub struct ChildPrompt<'a> {
    pub child: &'a dyn PromptChild,
    pub has_gui_session: &'a dyn Fn() -> bool,
}

impl TrustPrompt for ChildPrompt<'_> {
    fn ask(&self, review: &Review) -> Decision {
        if !(self.has_gui_session)() {
            return Decision::Unavailable;
        }
        match PromptRequest::for_review(review).to_json() {
            Some(request) => decision_from_exit(self.child.run(&request)),
            None => Decision::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "macos"))]
mod loopback;
