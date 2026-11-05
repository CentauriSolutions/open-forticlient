use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;

const SWIFT_PIN: &str =
    include_str!("../../tests/fixtures/swift/trust/gateways/gw.example_9443.pem");
const SWIFT_REQUEST: &str = include_str!("../../tests/fixtures/swift/trust/review-request.json");
const SWIFT_REQUEST_CHANGED: &str =
    include_str!("../../tests/fixtures/swift/trust/review-request-changed.json");
const RUST_REQUEST: &str = include_str!("../../tests/fixtures/rust/trust/review-request.json");
const RUST_REQUEST_CHANGED: &str =
    include_str!("../../tests/fixtures/rust/trust/review-request-changed.json");

/// `openssl x509 -in SWIFT_PIN -outform DER | shasum -a 256`.
const FIXTURE_SHA256: &str =
    "B0:2E:1D:6B:EC:23:23:92:C1:F1:A9:E2:2E:B9:A0:48:06:BA:04:CC:88:1C:A4:95:32:73:41:1C:E9:D6:46:F1";

/// Gives back canned `openssl x509` text, or nothing.
struct Text(Option<&'static str>);

impl X509Text for Text {
    fn describe(&self, _: &[u8]) -> Option<String> {
        self.0.map(str::to_owned)
    }
}

const NO_TEXT: Text = Text(None);

type Chain = Vec<Vec<u8>>;
type Call = (Chain, Target, bool);

fn fixture_der() -> Vec<u8> {
    tls::pem_decode(SWIFT_PIN).unwrap()
}

fn fixture() -> Certificate {
    Certificate::from_der(fixture_der(), &NO_TEXT).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oftc-trust-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn certificate_fingerprint_pem_and_fields() {
    let certificate = fixture();
    // The fingerprint is a known answer, and the PEM is the exact shape Swift wrote.
    assert_eq!(certificate.sha256(), FIXTURE_SHA256);
    assert_eq!(certificate.pem(), SWIFT_PIN);
    assert_eq!(
        Certificate::from_pem(&certificate.pem(), &NO_TEXT),
        Some(certificate)
    );
    // openssl's text becomes the display fields (key case and padding are ignored);
    // a missing field is Unknown, and one date alone gives no validity.
    let text = Text(Some(
        "subject= /CN=pin-test\nIssuer=/O=Example CA\nserial=AE07\nnotBefore=Nov  3 2026 GMT\n",
    ));
    let described = Certificate::from_der(fixture_der(), &text).unwrap();
    assert_eq!(
        (
            described.subject.as_str(),
            described.issuer.as_str(),
            described.serial.as_str()
        ),
        ("/CN=pin-test", "/O=Example CA", "AE07")
    );
    assert_eq!(described.validity, "Unknown");
    let both = Text(Some("notBefore=A\nnotAfter=B\n"));
    assert_eq!(
        Certificate::from_der(fixture_der(), &both)
            .unwrap()
            .validity,
        "A to B"
    );
    assert_eq!(fixture().subject, "Unknown");
}

#[test]
fn certificate_rejects_what_is_not_der() {
    let good = fixture_der();
    let mut trailing = good.clone();
    trailing.push(0);
    let mut short = good.clone();
    short.pop();
    for (name, der) in [
        ("empty", vec![]),
        ("not a sequence", vec![0x04, 0x01, 0x00]),
        ("zero length", vec![0x30, 0x00]),
        ("trailing byte", trailing),
        ("truncated", short),
        ("indefinite length", vec![0x30, 0x80, 0x00, 0x00]),
        ("length field cut off", vec![0x30, 0x82, 0x01]),
    ] {
        assert!(Certificate::from_der(der, &NO_TEXT).is_none(), "{name}");
    }
    assert!(Certificate::from_pem(
        "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
        &NO_TEXT
    )
    .is_none());
}

#[test]
fn openssl_describes_the_fixture() {
    let certificate = Certificate::from_der(fixture_der(), &OpensslText).unwrap();
    assert!(certificate.subject.contains("pin-test"), "{certificate:?}");
    assert!(certificate.validity.contains(" to "), "{certificate:?}");
}

#[test]
fn swift_written_pin_is_read_by_both_readers_and_rust_writes_the_same_bytes() {
    let dir = temp_dir("pin");
    fs::create_dir_all(dir.join("swift")).unwrap();
    fs::write(
        tls::pin_path(&dir.join("swift"), "gw.example", 9443),
        SWIFT_PIN,
    )
    .unwrap();
    // trust::pinned and the curl public-key pin both accept the Swift file.
    assert_eq!(
        pinned(&dir.join("swift"), "gw.example", 9443, &NO_TEXT),
        Some(fixture())
    );
    assert!(tls::pubkey_pin(SWIFT_PIN).unwrap().starts_with("sha256//"));
    // Writing the same DER produces the Swift file byte for byte, and the pin
    // directory and file are owner-only.
    let rust = dir.join("rust");
    tls::write_pin(&rust, "gw.example", 9443, &fixture_der()).unwrap();
    let file = tls::pin_path(&rust, "gw.example", 9443);
    assert_eq!(fs::read_to_string(&file).unwrap(), SWIFT_PIN);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&rust).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // A pin that is not a certificate is no pin.
    fs::write(
        &file,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    assert_eq!(pinned(&rust, "gw.example", 9443, &NO_TEXT), None);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn chain_output_is_parsed_leaf_first() {
    let leaf = fixture_der();
    let other = vec![0x30, 0x01, 0x05];
    let block = |der: &[u8]| tls::pem_encode(der);
    let (a, b) = (block(&leaf), block(&other));
    let many: String = (0u8..12).map(|i| block(&[0x30, 0x01, i])).collect();
    let cases: Vec<(&str, String, Option<Chain>)> = vec![
        (
            "one block",
            format!("CONNECTED\n{a}done\n"),
            Some(vec![leaf.clone()]),
        ),
        (
            "several, in order",
            format!("{a}{b}"),
            Some(vec![leaf.clone(), other.clone()]),
        ),
        (
            "text around, plus s_client's repeat of the leaf",
            format!("depth=0\n{a}{b}---\nServer certificate\n{a}subject=x\n"),
            Some(vec![leaf.clone(), other.clone()]),
        ),
        (
            "CRLF",
            format!("{a}{b}").replace('\n', "\r\n"),
            Some(vec![leaf.clone(), other.clone()]),
        ),
        (
            "truncated last block ends the list",
            format!("{a}-----BEGIN CERTIFICATE-----\nMIIC\n"),
            Some(vec![leaf.clone()]),
        ),
        (
            "only a truncated block",
            "-----BEGIN CERTIFICATE-----\nMIIC\n".to_owned(),
            None,
        ),
        (
            "no certificate",
            "connect: Connection refused\n".to_owned(),
            None,
        ),
        (
            "malformed base64 spoils everything",
            format!("{a}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
            None,
        ),
        (
            "other PEM blocks are skipped",
            format!("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n{a}"),
            Some(vec![leaf.clone()]),
        ),
        (
            "capped",
            many,
            Some((0u8..8).map(|i| vec![0x30, 0x01, i]).collect()),
        ),
    ];
    for (name, output, expected) in cases {
        assert_eq!(parse_chain(&output), expected, "{name}");
    }
}

#[test]
fn connect_arguments_for_names_and_addresses() {
    let cases = [
        ("gw.example", "gw.example:9443", Some("gw.example")),
        ("203.0.113.7", "203.0.113.7:9443", None),
        ("::1", "[::1]:9443", None),
        ("[::1]", "[::1]:9443", None),
        ("2001:db8::7", "[2001:db8::7]:9443", None),
    ];
    for (host, connect, sni) in cases {
        let args = s_client_args(host, 9443);
        assert_eq!(args[..3], ["s_client", "-connect", connect], "{host}");
        let servername = args
            .iter()
            .position(|a| a == "-servername")
            .map(|i| args[i + 1].as_str());
        assert_eq!(servername, sni, "{host}");
        assert_eq!(args.last().unwrap(), "-showcerts");
    }
    // The pin file name uses the host exactly as the profile spells it.
    let file = |host| {
        tls::pin_path(Path::new("/pins"), host, 9443)
            .to_string_lossy()
            .into_owned()
    };
    assert_eq!(file("[::1]"), "/pins/[::1]_9443.pem");
    assert_eq!(file("203.0.113.7"), "/pins/203.0.113.7_9443.pem");
    assert_eq!(file("gw.example"), "/pins/gw.example_9443.pem");
    assert_eq!(
        Target::parse("[::1]"),
        Target::Address("::1".parse().unwrap())
    );
    assert_eq!(
        Target::parse("GW.Example"),
        Target::Name("GW.Example".into())
    );
}

struct Source(Option<Vec<Vec<u8>>>);

impl ChainSource for Source {
    fn fetch(&self, _: &str, _: u32) -> Option<Vec<Vec<u8>>> {
        self.0.clone()
    }
}

/// Answers with `answer` and records what it was asked.
struct Evaluate {
    answer: Evaluation,
    calls: RefCell<Vec<Call>>,
}

impl Evaluator for Evaluate {
    fn evaluate(&self, chain: &[Vec<u8>], target: &Target, fetch: bool) -> Evaluation {
        self.calls
            .borrow_mut()
            .push((chain.to_vec(), target.clone(), fetch));
        self.answer
    }
}

fn probe(chain: Option<Vec<Vec<u8>>>, answer: Evaluation, host: &str) -> (Verdict, Vec<Call>) {
    let evaluator = Evaluate {
        answer,
        calls: RefCell::new(Vec::new()),
    };
    let verdict = ChainProbe {
        source: &Source(chain),
        evaluator: &evaluator,
        text: &NO_TEXT,
    }
    .probe(host, 9443);
    (verdict, evaluator.calls.into_inner())
}

#[test]
fn verdict_table() {
    let leaf = fixture_der();
    let intermediate = vec![0x30, 0x01, 0x05];
    let chain = vec![leaf.clone(), intermediate.clone()];
    let untrusted = Verdict::Untrusted(fixture());
    // Rejected is Untrusted whatever the chain looks like: only the leaf is shown.
    for (name, chain) in [
        ("leaf only", vec![leaf.clone()]),
        ("leaf and intermediate", chain.clone()),
        ("intermediate withheld", vec![leaf.clone()]),
    ] {
        assert_eq!(
            probe(Some(chain), Evaluation::Rejected, "gw.example").0,
            untrusted,
            "{name}"
        );
    }
    assert_eq!(
        probe(Some(chain.clone()), Evaluation::Trusted, "gw.example").0,
        Verdict::SystemTrusted
    );
    assert_eq!(
        probe(Some(chain.clone()), Evaluation::Error, "gw.example").0,
        Verdict::Unreachable
    );
    // No chain (refused, handshake failure, timeout) or an empty one never reaches
    // the evaluator.
    for none in [None, Some(vec![])] {
        let (verdict, calls) = probe(none, Evaluation::Trusted, "gw.example");
        assert_eq!((verdict, calls.len()), (Verdict::Unreachable, 0));
    }
    // A rejected chain whose leaf is not a certificate has nothing to show.
    assert_eq!(
        probe(
            Some(vec![vec![1, 2, 3]]),
            Evaluation::Rejected,
            "gw.example"
        )
        .0,
        Verdict::Unreachable
    );
    // The evaluator gets the chain leaf first, the name unchanged (an address for an
    // IP literal) and network fetches allowed, which is how missing intermediates
    // are found.
    for (host, target) in [
        ("GW.example", Target::Name("GW.example".into())),
        (
            "203.0.113.7",
            Target::Address("203.0.113.7".parse().unwrap()),
        ),
        ("[::1]", Target::Address("::1".parse().unwrap())),
    ] {
        assert_eq!(
            probe(Some(chain.clone()), Evaluation::Trusted, host).1,
            vec![(chain.clone(), target, true)],
            "{host}"
        );
    }
}

struct Probe(Verdict);

impl TrustProbe for Probe {
    fn probe(&self, _: &str, _: u32) -> Verdict {
        self.0.clone()
    }
}

struct Answer {
    decision: Decision,
    asked: RefCell<Vec<Review>>,
}

impl TrustPrompt for Answer {
    fn ask(&self, review: &Review) -> Decision {
        self.asked.borrow_mut().push(review.clone());
        self.decision
    }
}

#[test]
fn review_table() {
    let dir = temp_dir("review");
    let certificate = fixture();
    let changed = {
        let mut der = fixture_der();
        let last = der.len() - 1;
        der[last] ^= 1;
        Certificate::new(der, "x", "y", "2", "-")
    };
    let pin_file = tls::pin_path(&dir, "gw.example", 9443);
    let run = |verdict: Verdict, decision: Decision| {
        let answer = Answer {
            decision,
            asked: RefCell::new(Vec::new()),
        };
        let outcome = Reviewer {
            pin_dir: &dir,
            probe: &Probe(verdict),
            prompt: &answer,
            text: &NO_TEXT,
        }
        .review("gw.example", 9443, "Example Office");
        (outcome, answer.asked.into_inner())
    };

    // Only an untrusted certificate asks.
    for verdict in [Verdict::SystemTrusted, Verdict::Unreachable] {
        assert_eq!(
            run(verdict, Decision::Trust),
            (Outcome::NotACertificateProblem, vec![])
        );
    }
    // No answer available changes nothing; declining pins nothing but is reported.
    let (outcome, asked) = run(
        Verdict::Untrusted(certificate.clone()),
        Decision::Unavailable,
    );
    assert_eq!(
        (outcome, asked.len(), pin_file.exists()),
        (Outcome::NotACertificateProblem, 1, false)
    );
    let (outcome, asked) = run(Verdict::Untrusted(certificate.clone()), Decision::Decline);
    assert_eq!((outcome, pin_file.exists()), (Outcome::Declined, false));
    assert_eq!(asked[0].reason, Reason::Untrusted);
    assert_eq!(
        (
            asked[0].profile_name.as_str(),
            asked[0].host.as_str(),
            asked[0].port
        ),
        ("Example Office", "gw.example", 9443)
    );
    // Trusting pins exactly that DER, owner-only, in an owner-only directory.
    let (outcome, _) = run(Verdict::Untrusted(certificate.clone()), Decision::Trust);
    assert_eq!(outcome, Outcome::Trusted(certificate.clone()));
    assert_eq!(fs::read(&pin_file).unwrap(), SWIFT_PIN.as_bytes());
    assert_eq!(
        fs::metadata(&pin_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // The pinned certificate does not ask again.
    assert_eq!(
        run(Verdict::Untrusted(certificate.clone()), Decision::Trust),
        (Outcome::NotACertificateProblem, vec![])
    );
    // A different certificate is a change shown with the old one; declining keeps
    // the old pin, and unavailable changes nothing.
    let (outcome, asked) = run(Verdict::Untrusted(changed.clone()), Decision::Decline);
    assert_eq!(outcome, Outcome::Declined);
    assert_eq!(
        asked[0].reason,
        Reason::Changed {
            previous: certificate.clone()
        }
    );
    assert_eq!(fs::read(&pin_file).unwrap(), SWIFT_PIN.as_bytes());
    assert_eq!(
        run(Verdict::Untrusted(changed.clone()), Decision::Unavailable).0,
        Outcome::NotACertificateProblem
    );
    // Trusting the change replaces the pin.
    assert_eq!(
        run(Verdict::Untrusted(changed.clone()), Decision::Trust).0,
        Outcome::Trusted(changed.clone())
    );
    assert_eq!(
        tls::read_pin(&dir, "gw.example", 9443),
        Some(changed.der.clone())
    );
    // A pin that cannot be written counts as declined: the "directory" is a file.
    let blocked = dir.join("blocked");
    fs::write(&blocked, "").unwrap();
    let answer = Answer {
        decision: Decision::Trust,
        asked: RefCell::new(Vec::new()),
    };
    let outcome = Reviewer {
        pin_dir: &blocked,
        probe: &Probe(Verdict::Untrusted(certificate)),
        prompt: &answer,
        text: &NO_TEXT,
    }
    .review("gw.example", 9443, "");
    assert_eq!(outcome, Outcome::Declined);
    fs::remove_dir_all(&dir).unwrap();
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn prompt_request_matches_the_swift_encoder_and_the_committed_rust_golden() {
    let certificate = fixture();
    let review = |reason| Review {
        profile_name: "Example Office".into(),
        host: "gw.example".into(),
        port: 9443,
        certificate: certificate.clone(),
        reason,
    };
    let plain = PromptRequest::for_review(&review(Reason::Untrusted));
    let mut previous = certificate.clone();
    previous.der.push(0);
    let changed = PromptRequest::for_review(&review(Reason::Changed { previous }));
    // Swift writes the keys in no fixed order and escapes `/`, so compare parsed
    // values; a request without a previous certificate has no `previous` key.
    assert_eq!(
        json(std::str::from_utf8(&plain.to_json().unwrap()).unwrap()),
        json(SWIFT_REQUEST)
    );
    assert_eq!(
        json(std::str::from_utf8(&changed.to_json().unwrap()).unwrap()),
        json(SWIFT_REQUEST_CHANGED)
    );
    assert!(json(SWIFT_REQUEST).get("previous").is_none());
    // The Swift files decode, and the bytes inside are the certificate.
    let read = PromptRequest::from_json(SWIFT_REQUEST_CHANGED.as_bytes()).unwrap();
    assert_eq!(
        tls::base64_decode(&read.certificate),
        Some(certificate.der.clone())
    );
    assert_eq!(read, changed);
    assert_eq!(
        PromptRequest::from_json(SWIFT_REQUEST.as_bytes()),
        Some(plain.clone())
    );
    // The files the Swift check decodes are what this writer produces.
    assert_eq!(
        RUST_REQUEST,
        format!("{}\n", String::from_utf8(plain.to_json().unwrap()).unwrap())
    );
    assert_eq!(
        RUST_REQUEST_CHANGED,
        format!(
            "{}\n",
            String::from_utf8(changed.to_json().unwrap()).unwrap()
        )
    );
    assert_eq!(PromptRequest::from_json(b"{}"), None);
}

struct Child(Option<i32>, RefCell<Vec<Vec<u8>>>);

impl PromptChild for Child {
    fn run(&self, request: &[u8]) -> Option<i32> {
        self.1.borrow_mut().push(request.to_vec());
        self.0
    }
}

#[test]
fn child_prompt_maps_exit_codes_and_missing_gui() {
    let review = Review {
        profile_name: "Example Office".into(),
        host: "gw.example".into(),
        port: 9443,
        certificate: fixture(),
        reason: Reason::Untrusted,
    };
    let ask = |code, gui: bool| {
        let child = Child(code, RefCell::new(Vec::new()));
        let decision = ChildPrompt {
            child: &child,
            has_gui_session: &|| gui,
        }
        .ask(&review);
        (decision, child.1.into_inner().len())
    };
    for (code, decision) in [
        (Some(10), Decision::Trust),
        (Some(11), Decision::Decline),
        (Some(12), Decision::Unavailable),
        (Some(0), Decision::Unavailable),
        (Some(1), Decision::Unavailable),
        (None, Decision::Unavailable),
    ] {
        assert_eq!(ask(code, true), (decision, 1), "{code:?}");
    }
    // Without a GUI session the child is not even started.
    assert_eq!(ask(Some(10), false), (Decision::Unavailable, 0));
    // The child gets exactly the request JSON.
    let child = Child(Some(10), RefCell::new(Vec::new()));
    ChildPrompt {
        child: &child,
        has_gui_session: &|| true,
    }
    .ask(&review);
    assert_eq!(
        PromptRequest::from_json(&child.1.borrow()[0]),
        Some(PromptRequest::for_review(&review))
    );
    // A program that cannot be started is Unavailable.
    let missing = ProcessChild {
        executable: PathBuf::from("/nonexistent/oftc-agent"),
    };
    assert_eq!(
        decision_from_exit(missing.run(b"{}")),
        Decision::Unavailable
    );
}
