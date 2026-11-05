//! The real chain source and the real system evaluator against `openssl s_server` on
//! loopback: no gateway, nothing installed in any trust store, no Keychain access.
//!
//! The certificates are generated here with `/usr/bin/openssl` (LibreSSL on macOS) and
//! chain to a root that macOS does not trust, so every served chain must be
//! `Untrusted`. A certificate macOS *does* trust cannot be made without changing the
//! trust store, so the served-chain cases are all untrusted; the trusted verdict and
//! the `CFError` classification are covered by the anchored test at the end (the
//! throwaway root as the only anchor). Live-only: proxies, AIA fetching and what an
//! evaluation reports when the network is down.
//!
//! The leaf cases differ in what the server sends, not in the verdict: the verdict
//! cannot say *why* the system rejected a chain. What each case pins is that the
//! real `s_client` output parses into the chain that was served (length and leaf
//! first), that `SecTrust` accepts that chain as evaluable (an `Error` would surface
//! as `Unreachable`), and that the certificate offered to the user is the leaf.
//!
//! Marked `#[ignore]` like the other loopback tests: sandboxed agent environments deny
//! local-network access, and CI runs `--include-ignored`.

use std::fs;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::*;

const OPENSSL: &str = "/usr/bin/openssl";
const STEP_DEADLINE: Duration = Duration::from_secs(20);
const READY_DEADLINE: Duration = Duration::from_secs(5);
const START_ATTEMPTS: usize = 5;

/// A child that is killed and reaped when dropped, panic included. Its output goes
/// nowhere, so it can never block on a full pipe.
struct Proc(Child);

impl Proc {
    fn spawn(dir: &Path, args: &[&str]) -> Option<Proc> {
        Command::new(OPENSSL)
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
            .map(Proc)
    }

    fn exited(&mut self) -> bool {
        !matches!(self.0.try_wait(), Ok(None))
    }

    /// Whether it finished successfully within `STEP_DEADLINE`; killed otherwise.
    fn succeeded(mut self) -> bool {
        let deadline = Instant::now() + STEP_DEADLINE;
        while Instant::now() < deadline {
            match self.0.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        false
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + READY_DEADLINE;
        while !self.exited() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A scratch directory, deleted on drop.
struct Scratch(PathBuf);

impl Scratch {
    /// One directory per test: the tests run in parallel in one process.
    fn new(test: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "oftc-trust-loopback-{}-{test}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const CA_CONFIG: &str = "\
[ca]
default_ca = main
[main]
database = index.txt
new_certs_dir = .
serial = serial
default_md = sha256
policy = anything
unique_subject = no
[anything]
commonName = supplied
[req]
distinguished_name = dn
[dn]
CN = Common Name
";

const CA_EXT: &str = "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign\n";

enum Window {
    Valid,
    Expired,
}

/// Throwaway certificates, issued with `openssl ca` (the only way LibreSSL will back-date
/// a validity period).
struct Pki<'a>(&'a Path);

impl Pki<'_> {
    fn new(dir: &Path) -> Pki<'_> {
        fs::write(dir.join("ca.cnf"), CA_CONFIG).unwrap();
        fs::write(dir.join("index.txt"), "").unwrap();
        fs::write(dir.join("serial"), "01\n").unwrap();
        Pki(dir)
    }

    fn run(&self, args: &[&str]) -> bool {
        Proc::spawn(self.0, args).is_some_and(Proc::succeeded)
    }

    /// `name.key` and `name.pem`: a certificate for `CN=name` with `extensions`,
    /// signed by `signer` (`None`: by itself).
    fn issue(&self, name: &str, signer: Option<&str>, extensions: &str, window: Window) -> bool {
        let (key, csr, pem, ext) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.pem"),
            format!("{name}.ext"),
        );
        fs::write(self.0.join(&ext), extensions).unwrap();
        let signer_key = signer.map(|s| format!("{s}.key"));
        let signer_pem = signer.map(|s| format!("{s}.pem"));
        let subject = format!("/CN={name}");
        let mut sign = vec!["ca", "-batch", "-config", "ca.cnf", "-notext"];
        match (&signer_key, &signer_pem) {
            (Some(key), Some(pem)) => sign.extend(["-keyfile", key, "-cert", pem]),
            _ => sign.extend(["-selfsign", "-keyfile", &key]),
        }
        sign.extend(["-in", &csr, "-out", &pem, "-extfile", &ext]);
        match window {
            Window::Valid => sign.extend(["-days", "2"]),
            Window::Expired => sign.extend([
                "-startdate",
                "20000101000000Z",
                "-enddate",
                "20000102000000Z",
            ]),
        }
        self.run(&[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            &key,
        ]) && self.run(&[
            "req", "-new", "-key", &key, "-config", "ca.cnf", "-subj", &subject, "-out", &csr,
        ]) && self.run(&sign)
    }
}

/// `s_server` serving `leaf`, then the `intermediates` (named by `-CAfile`: LibreSSL reads
/// only the first certificate of `-cert`), on a free loopback port. Its `s_server`
/// takes a port only, so it listens on every interface for the few milliseconds a case
/// runs, with a throwaway certificate.
struct Server {
    port: u32,
    _process: Proc,
}

fn serve(dir: &Path, leaf: &str, intermediates: &[&str]) -> Option<Server> {
    let extra: String = intermediates
        .iter()
        .map(|name| fs::read_to_string(dir.join(format!("{name}.pem"))).unwrap())
        .collect();
    fs::write(dir.join("extra.pem"), extra).unwrap();
    let (key, cert) = (format!("{leaf}.key"), format!("{leaf}.pem"));
    for _ in 0..START_ATTEMPTS {
        // A free port, found by binding and releasing it; another process may take
        // it before `s_server` does, in which case `s_server` exits and we pick again.
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let accept = port.to_string();
        let mut args = vec![
            "s_server", "-accept", &accept, "-cert", &cert, "-key", &key, "-quiet", "-www",
        ];
        if !intermediates.is_empty() {
            args.extend(["-CAfile", "extra.pem"]);
        }
        let mut process = Proc::spawn(dir, &args)?;
        let deadline = Instant::now() + READY_DEADLINE;
        while Instant::now() < deadline && !process.exited() {
            let target = (Ipv4Addr::LOCALHOST, port).into();
            if TcpStream::connect_timeout(&target, Duration::from_millis(200)).is_ok() {
                if process.exited() {
                    break;
                }
                return Some(Server {
                    port: u32::from(port),
                    _process: process,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    None
}

fn der_of(dir: &Path, name: &str) -> Vec<u8> {
    let pem = fs::read_to_string(dir.join(format!("{name}.pem"))).unwrap();
    tls::pem_decode(&pem).unwrap()
}

#[test]
#[ignore = "loopback sockets require local-network permission in the sandbox"]
fn system_evaluator_rejects_every_untrusted_chain_and_a_closed_port_is_unreachable() {
    if !Path::new(OPENSSL).exists() {
        // Skipped (the crate denies print macros, so with no note): not a macOS system.
        return;
    }
    let scratch = Scratch::new("served");
    let dir = scratch.0.as_path();
    let pki = Pki::new(dir);
    let leaf_ext = |san: &str| format!("basicConstraints = CA:FALSE\nsubjectAltName = {san}\n");
    let loopback = leaf_ext("IP:127.0.0.1");
    let issued = pki.issue("root", None, CA_EXT, Window::Valid)
        && pki.issue("mid", Some("root"), CA_EXT, Window::Valid)
        && pki.issue("selfsigned", None, &loopback, Window::Valid)
        && pki.issue("expired", Some("root"), &loopback, Window::Expired)
        && pki.issue(
            "wrongname",
            Some("root"),
            &leaf_ext("IP:192.0.2.1,DNS:gateway.example.com"),
            Window::Valid,
        )
        && pki.issue("leaf", Some("mid"), &loopback, Window::Valid);
    assert!(issued, "openssl could not generate the certificates");

    // (leaf, the intermediates sent after it). The root is never sent: s_server leaves a
    // self-signed root out of the chain it presents, as any server would.
    let cases: [(&str, &[&str]); 5] = [
        ("selfsigned", &[]),
        ("expired", &[]),
        ("wrongname", &[]),
        ("leaf", &["mid"]),
        ("leaf", &[]),
    ];
    let source = OpensslChainSource {
        timeout: Duration::from_secs(10),
    };
    let probe = ChainProbe {
        source: &source,
        evaluator: &SystemTrustEvaluator,
        text: &OpensslText,
    };
    for (leaf, rest) in cases {
        let label = format!("{leaf} + {rest:?}");
        let chain: Vec<&str> = std::iter::once(leaf).chain(rest.iter().copied()).collect();
        let server = serve(dir, leaf, rest).unwrap_or_else(|| panic!("{label}: no s_server"));

        let fetched = source.fetch("127.0.0.1", server.port).expect(&label);
        let served: Vec<Vec<u8>> = chain.iter().map(|name| der_of(dir, name)).collect();
        assert_eq!(fetched, served, "{label}: the chain s_client saw");

        match probe.probe("127.0.0.1", server.port) {
            Verdict::Untrusted(certificate) => {
                assert_eq!(certificate.der, served[0], "{label}: the leaf is offered");
                assert!(
                    certificate.subject.contains(leaf),
                    "{label}: {certificate:?}"
                );
            }
            other => panic!("{label}: {other:?}"),
        }
    }

    // Nothing listens: the port was free a moment ago and no server is started on it.
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert_eq!(
        probe.probe("127.0.0.1", u32::from(closed)),
        Verdict::Unreachable
    );
}

/// `SecTrust` through `evaluate_chain` with the throwaway root as the only anchor
/// (the system store cannot be extended in a test), and with none. No sockets.
/// Pins the real `CFError` codes against `classify_failure`: a chain the anchor
/// vouches for is `Trusted`, and each kind of genuine failure stays `Rejected`.
#[test]
fn anchored_evaluation_trusts_a_good_chain_and_rejects_each_bad_one() {
    if !Path::new(OPENSSL).exists() {
        return;
    }
    let scratch = Scratch::new("anchored");
    let dir = scratch.0.as_path();
    let pki = Pki::new(dir);
    let leaf_ext = |san: &str| format!("basicConstraints = CA:FALSE\nsubjectAltName = {san}\n");
    let loopback = leaf_ext("IP:127.0.0.1");
    let issued = pki.issue("root", None, CA_EXT, Window::Valid)
        && pki.issue("mid", Some("root"), CA_EXT, Window::Valid)
        && pki.issue("leaf", Some("mid"), &loopback, Window::Valid)
        && pki.issue("expired", Some("root"), &loopback, Window::Expired)
        && pki.issue(
            "wrongname",
            Some("root"),
            &leaf_ext("IP:192.0.2.1"),
            Window::Valid,
        );
    assert!(issued, "openssl could not generate the certificates");

    let target = Target::parse("127.0.0.1");
    let ders = |names: &[&str]| -> Vec<Vec<u8>> { names.iter().map(|n| der_of(dir, n)).collect() };
    let root = ders(&["root"]);
    // (chain, anchors, expected, what it pins)
    type Case<'a> = (&'a [&'a str], &'a [Vec<u8>], Evaluation, &'a str);
    let cases: [Case; 5] = [
        (
            &["leaf", "mid"],
            &root,
            Evaluation::Trusted,
            "trusted chain",
        ),
        (
            &["leaf", "mid"],
            &[],
            Evaluation::Rejected,
            "root not in the system store",
        ),
        (&["expired", "root"], &root, Evaluation::Rejected, "expired"),
        (
            &["wrongname", "root"],
            &root,
            Evaluation::Rejected,
            "name mismatch",
        ),
        (
            &["leaf"],
            &root,
            Evaluation::Rejected,
            "intermediate missing",
        ),
    ];
    for (names, anchors, expected, label) in cases {
        let got = evaluate_chain(&ders(names), &target, false, anchors);
        assert_eq!(got, expected, "{label}");
    }
    // Not a certificate at all: the evaluation cannot be made.
    assert_eq!(
        evaluate_chain(&[vec![0x30, 0x01, 0x00]], &target, false, &[]),
        Evaluation::Error
    );
}
