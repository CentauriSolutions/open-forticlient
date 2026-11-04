//! The host verbs: argv to output and exit code.
//!
//! [`run`] takes every outside dependency as an argument ([`Backends`], [`Io`],
//! [`HostEnv`]) and returns the exit code; it never exits the process. The text
//! each verb prints and the code it returns are the verb protocol that `oftc` and
//! the menu parse, documented in `docs/host-verbs.md` and pinned by the golden
//! table in the tests.

use std::io::Read;

use zeroize::Zeroizing;

use crate::env::HostEnv;
use crate::keychain::{read_psk_line, Keychain, KeychainError};
use crate::out::Out;
use crate::profile::{Profile, Transport};
use crate::registry::{self, ProfileEntry};

/// One line of the usage text: how a verb is spelled, and who implements it.
pub struct Verb {
    pub synopsis: &'static str,
    /// True when `oftc_host_main` handles it; false while Swift still does.
    pub rust: bool,
}

impl Verb {
    pub fn name(&self) -> &'static str {
        self.synopsis.split(' ').next().unwrap_or("")
    }
}

const fn rust(synopsis: &'static str) -> Verb {
    Verb {
        synopsis,
        rust: true,
    }
}

const fn swift(synopsis: &'static str) -> Verb {
    Verb {
        synopsis,
        rust: false,
    }
}

/// Every verb, in the order the usage text lists them. Each later change moves
/// verbs from `swift` to `rust` here and in `Host/main.swift`.
pub const VERBS: &[Verb] = &[
    swift("activate"),
    swift("deactivate"),
    swift("agent-status"),
    swift("register-agent"),
    swift("unregister-agent"),
    swift("install-config"),
    rust("list-profiles"),
    swift("check-update [url]"),
    swift("launcher-alias ensure|remove"),
    swift("export-profiles [id...]"),
    swift("import-profiles"),
    rust("save-profile <gateway> <saml-port> [--tcp] [--name <name>]"),
    swift("import-profile <FortiClient-profile>"),
    rust("show-profile"),
    swift("erase-profile"),
    rust("has-psk"),
    swift("set-autostart on|off"),
    swift("supervise-autostart"),
    swift("start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    swift("supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    rust("provision-psk [--stdin] [gateway]"),
    swift("migrate-psk <FortiClient-profile> <gateway>"),
    swift("preflight <gateway> <32-hex-UID>"),
    swift("start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    swift(
        "supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]",
    ),
    swift("rekey-once"),
    swift("rekey-ike-once"),
    swift("rekey-counts"),
    swift("status"),
    swift("stop"),
    swift("remove-config"),
];

/// The usage text, as `OFTCAgent` prints it for a bad command line.
pub fn usage() -> String {
    let verbs: Vec<&str> = VERBS.iter().map(|verb| verb.synopsis).collect();
    format!("Usage: OFTCAgent [--profile <id>] {}", verbs.join("|"))
}

/// The verbs this crate implements, for the Swift stub to delegate.
pub fn rust_verbs() -> impl Iterator<Item = &'static str> {
    VERBS.iter().filter(|verb| verb.rust).map(Verb::name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ListProfiles,
    ShowProfile,
    HasPsk,
    ProvisionPsk {
        gateway: Option<String>,
        stdin: bool,
    },
    SaveProfile {
        profile: Profile,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// From a leading `--profile <id>`.
    pub profile: Option<String>,
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// `--profile` without a valid id: exit 2 with its own message.
    ProfileFlag,
    /// Anything else wrong with the command line, or a verb this crate does not
    /// implement: the usage text, exit 2.
    Usage,
}

pub fn parse(args: &[String]) -> Result<Invocation, ParseError> {
    let (profile, args) = match args.first().map(String::as_str) {
        Some("--profile") => match args.get(1) {
            Some(id) if args.len() >= 3 && registry::is_valid_id(id) => {
                (Some(id.clone()), &args[2..])
            }
            _ => return Err(ParseError::ProfileFlag),
        },
        _ => (None, args),
    };
    let Some(verb) = args.first() else {
        return Err(ParseError::Usage);
    };
    let rest = &args[1..];
    let command = match (verb.as_str(), rest) {
        ("list-profiles", []) => Command::ListProfiles,
        ("show-profile", []) => Command::ShowProfile,
        ("has-psk", []) => Command::HasPsk,
        ("provision-psk", rest) => {
            let (stdin, rest) = match rest.first().map(String::as_str) {
                Some("--stdin") => (true, &rest[1..]),
                _ => (false, rest),
            };
            if rest.len() > 1 {
                return Err(ParseError::Usage);
            }
            Command::ProvisionPsk {
                gateway: rest.first().cloned(),
                stdin,
            }
        }
        ("save-profile", [gateway, port, flags @ ..]) => parse_save_profile(gateway, port, flags)?,
        _ => return Err(ParseError::Usage),
    };
    Ok(Invocation { profile, command })
}

fn parse_save_profile(gateway: &str, port: &str, flags: &[String]) -> Result<Command, ParseError> {
    let mut transport = Transport::Udp;
    let mut name: Option<&str> = None;
    let mut rest = flags;
    while let Some(flag) = rest.first() {
        match (flag.as_str(), rest.get(1)) {
            ("--tcp", _) => {
                transport = Transport::Tcp;
                rest = &rest[1..];
            }
            ("--name", Some(value)) => {
                name = Some(value);
                rest = &rest[2..];
            }
            _ => return Err(ParseError::Usage),
        }
    }
    let port: u32 = port.parse().map_err(|_| ParseError::Usage)?;
    let profile =
        Profile::new(gateway, port, transport, name, None).map_err(|_| ParseError::Usage)?;
    Ok(Command::SaveProfile { profile })
}

/// Where a secret typed by the user comes from.
pub trait SecretPrompt {
    fn read_secret(&self) -> Result<Zeroizing<Vec<u8>>, KeychainError>;
}

/// Everything a verb reaches outside this process.
pub struct Backends<'a> {
    pub keychain: &'a dyn Keychain,
    pub prompt: &'a dyn SecretPrompt,
    /// The FortiClient profile name for a gateway, to name a migrated profile.
    pub legacy_name: &'a dyn Fn(&str) -> Option<String>,
}

pub struct Io<'a> {
    pub stdin: &'a mut dyn Read,
    pub out: &'a mut Out,
}

fn finish(io: &mut Io, text: &str, code: i32) -> i32 {
    io.out.line(text);
    code
}

/// The profile a verb acts on: the `--profile` one, or the only one.
fn require_entry(
    selected: &Option<String>,
    root: &std::path::Path,
) -> Result<ProfileEntry, String> {
    let mut entries = registry::entries(root);
    if let Some(id) = selected {
        return entries
            .into_iter()
            .find(|entry| &entry.id == id)
            .ok_or_else(|| {
                format!("OFTC profile unavailable: no profile named {id}; run oftc setup")
            });
    }
    match entries.len() {
        1 => Ok(entries.remove(0)),
        0 => Err("OFTC profile unavailable; run oftc setup".to_owned()),
        _ => Err(format!(
            "Several OFTC profiles are configured; choose one with --profile <id> ({})",
            entries
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub fn run(args: &[String], env: &HostEnv, backends: &Backends, io: &mut Io) -> i32 {
    let invocation = match parse(args) {
        Ok(invocation) => invocation,
        Err(ParseError::ProfileFlag) => {
            return finish(
                io,
                "--profile needs a name of 1-32 lowercase letters, digits or hyphens",
                2,
            )
        }
        Err(ParseError::Usage) => return finish(io, &usage(), 2),
    };
    let root = env.root();
    // The first run after an upgrade moves the single-profile layout into place.
    registry::migrate_legacy(root, backends.legacy_name);
    let selected = invocation.profile;
    match invocation.command {
        Command::ListProfiles => {
            let lines: Vec<String> = registry::entries(root)
                .iter()
                .map(|entry| {
                    let p = &entry.profile;
                    [
                        entry.id.as_str(),
                        entry.name(),
                        &p.gateway,
                        &p.saml_port.to_string(),
                        p.transport.as_str(),
                    ]
                    .join("\t")
                })
                .collect();
            finish(io, &lines.join("\n"), 0)
        }
        Command::ShowProfile => match require_entry(&selected, root) {
            Ok(entry) => {
                let p = &entry.profile;
                let text = format!(
                    "OFTC profile {} ({}): gateway={} saml-port={} transport={}",
                    entry.id,
                    entry.name(),
                    p.gateway,
                    p.saml_port,
                    p.transport.as_str()
                );
                finish(io, &text, 0)
            }
            Err(message) => finish(io, &message, 1),
        },
        Command::HasPsk => match require_entry(&selected, root) {
            Ok(entry) => match backends.keychain.get(&entry.profile.gateway) {
                Ok(_) => finish(io, "OFTC PSK available", 0),
                Err(_) => finish(io, "OFTC PSK unavailable", 1),
            },
            Err(message) => finish(io, &message, 1),
        },
        Command::ProvisionPsk { gateway, stdin } => {
            let gateway = match gateway {
                Some(gateway) => gateway,
                None => match require_entry(&selected, root) {
                    Ok(entry) => entry.profile.gateway,
                    Err(message) => return finish(io, &message, 1),
                },
            };
            if gateway.is_empty()
                || gateway.len() > 253
                || gateway.contains('/')
                || gateway.contains(':')
            {
                return finish(io, "Invalid gateway name", 2);
            }
            let (psk, source) = if stdin {
                (read_psk_line(io.stdin), "standard input")
            } else {
                (backends.prompt.read_secret(), "the terminal")
            };
            let Ok(psk) = psk else {
                return finish(io, &format!("Could not read a valid PSK from {source}"), 1);
            };
            match backends.keychain.set(&gateway, &psk) {
                Ok(()) => finish(io, "OFTC PSK stored in Keychain", 0),
                Err(_) => finish(io, "Could not save OFTC Keychain PSK", 1),
            }
        }
        Command::SaveProfile { profile } => {
            if registry::entries(root)
                .iter()
                .any(|entry| entry.profile.gateway == profile.gateway)
            {
                return finish(
                    io,
                    &format!("OFTC already has a profile for {}", profile.gateway),
                    1,
                );
            }
            match registry::add(root, &profile, selected.as_deref()) {
                Ok(entry) => finish(io, &format!("OFTC profile saved: id={}", entry.id), 0),
                Err(_) => finish(
                    io,
                    "Could not save OFTC profile (a profile with that id may already exist)",
                    1,
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryKeychain;
    use crate::out::Capture;
    use crate::profile::testutil::{fixture, TempDir};
    use std::cell::RefCell;
    use std::path::Path;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn save_profile(gateway: &str, port: u32, transport: Transport, name: Option<&str>) -> Command {
        Command::SaveProfile {
            profile: Profile::new(gateway, port, transport, name, None).unwrap(),
        }
    }

    #[test]
    fn parse_table() {
        let invocation = |profile: Option<&str>, command| {
            Ok(Invocation {
                profile: profile.map(str::to_owned),
                command,
            })
        };
        let rows: Vec<(Vec<&str>, Result<Invocation, ParseError>)> = vec![
            (
                vec!["list-profiles"],
                invocation(None, Command::ListProfiles),
            ),
            (
                vec!["--profile", "lab", "show-profile"],
                invocation(Some("lab"), Command::ShowProfile),
            ),
            (vec!["has-psk"], invocation(None, Command::HasPsk)),
            // Arity: Swift's `case ... where args.count == n` guards.
            (vec!["list-profiles", "x"], Err(ParseError::Usage)),
            (vec!["has-psk", "x"], Err(ParseError::Usage)),
            (vec!["show-profile", "x"], Err(ParseError::Usage)),
            (vec![], Err(ParseError::Usage)),
            (vec!["activate"], Err(ParseError::Usage)), // still Swift's
            (vec!["nonsense"], Err(ParseError::Usage)),
            // --profile needs a valid id and a verb after it.
            (vec!["--profile"], Err(ParseError::ProfileFlag)),
            (vec!["--profile", "lab"], Err(ParseError::ProfileFlag)),
            (
                vec!["--profile", "Bad_Id", "has-psk"],
                Err(ParseError::ProfileFlag),
            ),
            (vec!["--profile", "lab", "nonsense"], Err(ParseError::Usage)),
            // provision-psk: optional --stdin, then an optional gateway.
            (
                vec!["provision-psk"],
                invocation(
                    None,
                    Command::ProvisionPsk {
                        gateway: None,
                        stdin: false,
                    },
                ),
            ),
            (
                vec!["provision-psk", "vpn.example.com"],
                invocation(
                    None,
                    Command::ProvisionPsk {
                        gateway: Some("vpn.example.com".into()),
                        stdin: false,
                    },
                ),
            ),
            (
                vec!["provision-psk", "--stdin"],
                invocation(
                    None,
                    Command::ProvisionPsk {
                        gateway: None,
                        stdin: true,
                    },
                ),
            ),
            (
                vec!["provision-psk", "--stdin", "vpn.example.com"],
                invocation(
                    None,
                    Command::ProvisionPsk {
                        gateway: Some("vpn.example.com".into()),
                        stdin: true,
                    },
                ),
            ),
            (vec!["provision-psk", "a", "b"], Err(ParseError::Usage)),
            (
                vec!["provision-psk", "vpn.example.com", "--stdin"],
                Err(ParseError::Usage),
            ),
            // save-profile: flags repeat, the last --name wins, bad settings are usage errors.
            (
                vec!["save-profile", "vpn.example.com", "9443"],
                invocation(
                    None,
                    save_profile("vpn.example.com", 9443, Transport::Udp, None),
                ),
            ),
            (
                vec![
                    "save-profile",
                    "vpn.example.com",
                    "9443",
                    "--name",
                    "A",
                    "--tcp",
                    "--name",
                    "B",
                ],
                invocation(
                    None,
                    save_profile("vpn.example.com", 9443, Transport::Tcp, Some("B")),
                ),
            ),
            (
                vec!["save-profile", "vpn.example.com"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "vpn.example.com", "9443", "--name"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "vpn.example.com", "9443", "--udp"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "vpn.example.com", "port"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "vpn.example.com", "0"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "vpn.example.com", "-1"],
                Err(ParseError::Usage),
            ),
            (
                vec!["save-profile", "bad host", "9443"],
                Err(ParseError::Usage),
            ),
            (
                vec![
                    "save-profile",
                    "vpn.example.com",
                    "9443",
                    "--name",
                    "tab\there",
                ],
                Err(ParseError::Usage),
            ),
        ];
        for (args, expected) in rows {
            assert_eq!(parse(&strings(&args)), expected, "{args:?}");
        }
    }

    /// Host/main.swift is the other copy of the usage text and the list of verbs it
    /// delegates; neither may drift from `VERBS`.
    #[test]
    fn swift_stub_agrees_with_the_verb_table() {
        let swift = include_str!("../../../Host/main.swift");
        let literal = swift
            .lines()
            .find_map(|line| line.strip_prefix("private let usage = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("usage literal in main.swift");
        assert_eq!(literal, usage());
        let list = swift
            .lines()
            .find_map(|line| line.strip_prefix("private let rustVerbs: Set<String> = ["))
            .and_then(|rest| rest.strip_suffix(']'))
            .expect("rustVerbs in main.swift");
        let mut stub: Vec<&str> = list
            .split(',')
            .map(|v| v.trim().trim_matches('"'))
            .collect();
        let mut table: Vec<&str> = rust_verbs().collect();
        stub.sort_unstable();
        table.sort_unstable();
        assert_eq!(stub, table);
        // Every verb the Rust side claims has a parser arm.
        for verb in rust_verbs() {
            assert_ne!(parse(&strings(&[verb])), Err(ParseError::ProfileFlag));
            let args = strings(&[verb, "a", "b", "c", "d"]);
            let known = verb == "save-profile" || parse(&args) == Err(ParseError::Usage);
            assert!(known, "{verb}");
        }
    }

    struct Scripted(RefCell<Option<Result<Vec<u8>, KeychainError>>>);

    impl SecretPrompt for Scripted {
        fn read_secret(&self) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
            self.0
                .borrow_mut()
                .take()
                .expect("prompt not expected")
                .map(Zeroizing::new)
        }
    }

    struct Harness {
        dir: TempDir,
        env: HostEnv,
        keychain: MemoryKeychain,
        prompt: Scripted,
    }

    impl Harness {
        fn new() -> Harness {
            let dir = TempDir::new("commands");
            let env = HostEnv::new("com.example.oftc", &dir.0).unwrap();
            Harness {
                dir,
                env,
                keychain: MemoryKeychain::default(),
                prompt: Scripted(RefCell::new(None)),
            }
        }

        fn run(&self, args: &[&str], stdin: &str) -> (String, i32) {
            let capture = Capture::default();
            let mut out = Out::new(Box::new(capture.clone()));
            let backends = Backends {
                keychain: &self.keychain,
                prompt: &self.prompt,
                legacy_name: &|gateway| {
                    (gateway == "vpn.example.com").then(|| "Example Office".to_owned())
                },
            };
            let mut stdin = stdin.as_bytes();
            let mut io = Io {
                stdin: &mut stdin,
                out: &mut out,
            };
            let code = run(&strings(args), &self.env, &backends, &mut io);
            (capture.text(), code)
        }

        fn expect(&self, args: &[&str], stdout: &str, code: i32) {
            assert_eq!(self.run(args, ""), (stdout.to_owned(), code), "{args:?}");
        }
    }

    /// The verb protocol: stdout bytes and exit code per verb and branch.
    #[test]
    fn golden_outputs() {
        let h = Harness::new();
        // No profiles yet.
        h.expect(&["list-profiles"], "\n", 0);
        h.expect(
            &["show-profile"],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        h.expect(
            &["has-psk"],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        h.expect(
            &["--profile", "lab", "show-profile"],
            "OFTC profile unavailable: no profile named lab; run oftc setup\n",
            1,
        );
        // save-profile derives the id from the name, or from the gateway.
        h.expect(
            &[
                "save-profile",
                "vpn.example.com",
                "9443",
                "--name",
                "Example Office",
            ],
            "OFTC profile saved: id=example-office\n",
            0,
        );
        h.expect(
            &["save-profile", "vpn.example.com", "8443"],
            "OFTC already has a profile for vpn.example.com\n",
            1,
        );
        h.expect(&["show-profile"],
            "OFTC profile example-office (Example Office): gateway=vpn.example.com saml-port=9443 transport=udp\n", 0);
        h.expect(
            &[
                "--profile",
                "lab",
                "save-profile",
                "lab.example.com",
                "8443",
                "--tcp",
            ],
            "OFTC profile saved: id=lab\n",
            0,
        );
        h.expect(
            &[
                "--profile",
                "lab",
                "save-profile",
                "other.example.com",
                "8443",
            ],
            "Could not save OFTC profile (a profile with that id may already exist)\n",
            1,
        );
        h.expect(&["list-profiles"],
            "example-office\tExample Office\tvpn.example.com\t9443\tudp\nlab\tlab.example.com\tlab.example.com\t8443\ttcp\n", 0);
        // Two profiles: a bare verb must choose.
        h.expect(&["show-profile"],
            "Several OFTC profiles are configured; choose one with --profile <id> (example-office, lab)\n", 1);
        h.expect(&["--profile", "lab", "show-profile"],
            "OFTC profile lab (lab.example.com): gateway=lab.example.com saml-port=8443 transport=tcp\n", 0);
        // Command-line errors.
        h.expect(
            &["--profile", "Bad", "list-profiles"],
            "--profile needs a name of 1-32 lowercase letters, digits or hyphens\n",
            2,
        );
        h.expect(
            &["save-profile", "bad host", "9443"],
            &format!("{}\n", usage()),
            2,
        );
        h.expect(&["status"], &format!("{}\n", usage()), 2);
    }

    #[test]
    fn psk_verbs() {
        let h = Harness::new();
        h.run(
            &[
                "--profile",
                "lab",
                "save-profile",
                "lab.example.com",
                "8443",
            ],
            "",
        );
        h.expect(&["has-psk"], "OFTC PSK unavailable\n", 1);
        // From standard input, for the profile's gateway: only the first line.
        assert_eq!(
            h.run(&["provision-psk", "--stdin"], "s3cret\nignored\n"),
            ("OFTC PSK stored in Keychain\n".to_owned(), 0)
        );
        assert_eq!(
            h.keychain.get("lab.example.com").unwrap().as_slice(),
            b"s3cret"
        );
        h.expect(&["has-psk"], "OFTC PSK available\n", 0);
        // From the terminal prompt, for a named gateway that has no profile.
        *h.prompt.0.borrow_mut() = Some(Ok(b"typed".to_vec()));
        h.expect(
            &["provision-psk", "other.example.com"],
            "OFTC PSK stored in Keychain\n",
            0,
        );
        assert_eq!(
            h.keychain.get("other.example.com").unwrap().as_slice(),
            b"typed"
        );
        // Failures: the prompt, an unusable stdin, an unusable gateway.
        *h.prompt.0.borrow_mut() = Some(Err(KeychainError::Unavailable));
        h.expect(
            &["provision-psk", "other.example.com"],
            "Could not read a valid PSK from the terminal\n",
            1,
        );
        assert_eq!(
            h.run(&["provision-psk", "--stdin"], "\n"),
            (
                "Could not read a valid PSK from standard input\n".to_owned(),
                1
            )
        );
        for gateway in ["a/b", "a:443"] {
            h.expect(
                &["provision-psk", "--stdin", gateway],
                "Invalid gateway name\n",
                2,
            );
        }
        assert_eq!(
            h.keychain.get("lab.example.com").unwrap().as_slice(),
            b"s3cret"
        );
    }

    /// The first run after an upgrade moves the original layout aside.
    #[test]
    fn a_verb_migrates_the_legacy_layout_first() {
        let h = Harness::new();
        let root = h.env.root();
        std::fs::create_dir_all(root).unwrap();
        for file in ["profile.json", "connection-preferences.json"] {
            std::fs::copy(fixture("swift/legacy-root").join(file), root.join(file)).unwrap();
        }
        h.expect(
            &["list-profiles"],
            "example-office\tExample Office\tvpn.example.com\t9443\ttcp\n",
            0,
        );
        assert!(!Path::new(&root.join("profile.json")).exists());
        let _ = &h.dir;
    }
}
