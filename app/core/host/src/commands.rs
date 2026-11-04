//! The host verbs: argv to output and exit code.
//!
//! [`run`] takes every outside dependency as an argument ([`Backends`], [`Io`],
//! [`HostEnv`]) and returns the exit code; it never exits the process. The text
//! each verb prints and the code it returns are the verb protocol that `oftc` and
//! the menu parse, documented in `docs/host-verbs.md` and pinned by the golden
//! table in the tests.

use std::io::Read;

use oftc_apple::manager::VpnControl;
use oftc_provider::envelope::ConnectMode;
use zeroize::Zeroizing;

use crate::acquire::{Acquirer, Clock};
use crate::env::HostEnv;
use crate::keychain::{read_psk_line, Keychain, KeychainError};
use crate::out::Out;
use crate::profile::{Profile, Transport};
use crate::registry::{self, ProfileEntry};
use crate::start::parse_start_flags;
use crate::vpn::{self, Ctx, Rekey};

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
    rust("install-config"),
    rust("list-profiles"),
    swift("check-update [url]"),
    swift("launcher-alias ensure|remove"),
    swift("export-profiles [id...]"),
    swift("import-profiles"),
    rust("save-profile <gateway> <saml-port> [--tcp] [--name <name>]"),
    swift("import-profile <FortiClient-profile>"),
    rust("show-profile"),
    rust("erase-profile"),
    rust("has-psk"),
    swift("set-autostart on|off"),
    swift("supervise-autostart"),
    rust("start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    swift("supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    rust("provision-psk [--stdin] [gateway]"),
    swift("migrate-psk <FortiClient-profile> <gateway>"),
    rust("preflight <gateway> <32-hex-UID>"),
    rust("start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    swift(
        "supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]",
    ),
    rust("rekey-once"),
    rust("rekey-ike-once"),
    rust("rekey-counts"),
    rust("status"),
    swift("stop"),
    rust("remove-config"),
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
    InstallConfig,
    Status,
    RemoveConfig,
    EraseProfile,
    RekeyOnce,
    RekeyIkeOnce,
    RekeyCounts,
    Preflight {
        gateway: String,
        uid: String,
    },
    StartLive {
        gateway: String,
        port: u32,
        mode: ConnectMode,
        insecure: bool,
    },
    /// The flags are checked after the profile is found, as the Swift verb did.
    StartProfile {
        flags: Vec<String>,
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
        ("install-config", []) => Command::InstallConfig,
        ("status", []) => Command::Status,
        ("remove-config", []) => Command::RemoveConfig,
        ("erase-profile", []) => Command::EraseProfile,
        ("rekey-once", []) => Command::RekeyOnce,
        ("rekey-ike-once", []) => Command::RekeyIkeOnce,
        ("rekey-counts", []) => Command::RekeyCounts,
        ("preflight", [gateway, uid]) => Command::Preflight {
            gateway: gateway.clone(),
            uid: uid.clone(),
        },
        ("start-live", [gateway, port, flags @ ..]) => {
            let port: u32 = port.parse().map_err(|_| ParseError::Usage)?;
            let (mode, insecure) = parse_start_flags(flags).ok_or(ParseError::Usage)?;
            if !(1..=65535).contains(&port) || gateway.is_empty() {
                return Err(ParseError::Usage);
            }
            Command::StartLive {
                gateway: gateway.clone(),
                port,
                mode,
                insecure,
            }
        }
        ("start-profile", flags) => Command::StartProfile {
            flags: flags.to_vec(),
        },
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
    pub vpn: &'a dyn VpnControl,
    pub acquirer: &'a dyn Acquirer,
    pub clock: &'a dyn Clock,
    /// A fresh single-use session id for each start envelope.
    pub session_id: &'a dyn Fn() -> [u8; 16],
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
pub(crate) fn require_entry(
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
    let ctx = Ctx {
        env,
        backends,
        selected: &selected,
    };
    let vpn_verb = |(text, code): (String, i32), io: &mut Io| finish(io, &text, code);
    match invocation.command {
        Command::InstallConfig => vpn_verb(vpn::install_config(&ctx), io),
        Command::Status => vpn_verb(vpn::status(&ctx), io),
        Command::RemoveConfig => vpn_verb(vpn::remove_config(&ctx), io),
        Command::EraseProfile => vpn_verb(vpn::erase_profile(&ctx), io),
        Command::RekeyOnce => vpn_verb(vpn::rekey_once(&ctx, Rekey::Child), io),
        Command::RekeyIkeOnce => vpn_verb(vpn::rekey_once(&ctx, Rekey::Ike), io),
        Command::RekeyCounts => vpn_verb(vpn::rekey_counts(&ctx), io),
        Command::Preflight { gateway, uid } => vpn_verb(vpn::preflight(&ctx, &gateway, &uid), io),
        Command::StartLive {
            gateway,
            port,
            mode,
            insecure,
        } => vpn_verb(vpn::start_live(&ctx, &gateway, port, mode, insecure), io),
        Command::StartProfile { flags } => vpn_verb(vpn::start_profile(&ctx, &flags), io),
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
    use oftc_apple::error::AppleError;
    use oftc_apple::manager::{MockEntry, MockVpn, StartKind, VpnStatus};
    use oftc_host_bootstrap::{AcquireFailure, TunnelProfile};
    use oftc_provider::envelope::{
        consume, encode_hbr1, OptionValue, Secret, StartMode, StartOptions as ProviderOptions,
    };
    use std::cell::{Cell, RefCell};
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The provider remembers session ids for the whole process, and tests run in
    /// parallel, so each start gets an id no other test has used.
    fn unique_session_id() -> [u8; 16] {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut id = [0x5A; 16];
        id[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        id
    }

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
            let known = matches!(verb, "save-profile" | "start-profile")
                || parse(&args) == Err(ParseError::Usage);
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

    /// Time that moves only when told: `sleep` advances it and runs the hook.
    struct FakeClock {
        unix: Cell<u64>,
        mono: Cell<Duration>,
        on_sleep: RefCell<Option<Box<dyn FnMut()>>>,
    }

    impl Clock for FakeClock {
        fn unix_secs(&self) -> u64 {
            self.unix.get()
        }
        fn now(&self) -> Duration {
            self.mono.get()
        }
        fn sleep(&self, duration: Duration) {
            self.mono.set(self.mono.get() + duration);
            self.unix.set(self.unix.get() + duration.as_secs());
            if let Some(hook) = self.on_sleep.borrow_mut().as_mut() {
                hook();
            }
        }
    }

    type AcquireCall = (String, Vec<u8>, u32, bool, TunnelProfile);

    /// Stands in for the browser: records what it was asked, may take "minutes",
    /// and may change the VPN entry meanwhile.
    struct FakeAcquirer {
        clock: Rc<FakeClock>,
        result: RefCell<Result<Vec<u8>, AcquireFailure>>,
        takes_secs: Cell<u64>,
        meanwhile: RefCell<Option<Box<dyn FnMut()>>>,
        calls: RefCell<Vec<AcquireCall>>,
    }

    impl Acquirer for FakeAcquirer {
        fn acquire(
            &self,
            gateway: &str,
            psk: &[u8],
            saml_port: u32,
            insecure: bool,
            profile: TunnelProfile,
        ) -> Result<Zeroizing<Vec<u8>>, AcquireFailure> {
            self.calls.borrow_mut().push((
                gateway.to_owned(),
                psk.to_vec(),
                saml_port,
                insecure,
                profile,
            ));
            self.clock
                .unix
                .set(self.clock.unix.get() + self.takes_secs.get());
            if let Some(hook) = self.meanwhile.borrow_mut().as_mut() {
                hook();
            }
            match &*self.result.borrow() {
                Ok(wire) => Ok(Zeroizing::new(wire.clone())),
                Err(AcquireFailure::BeforeBrowser) => Err(AcquireFailure::BeforeBrowser),
                Err(AcquireFailure::Other) => Err(AcquireFailure::Other),
            }
        }
    }

    /// A scripted provider reply, the line it should produce, and the exit code.
    type Row = (Result<Vec<u8>, AppleError>, &'static str, i32);

    const UID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PROVIDER: &str = "com.example.oftc.provider";

    struct Harness {
        dir: TempDir,
        env: HostEnv,
        keychain: MemoryKeychain,
        prompt: Scripted,
        vpn: MockVpn,
        clock: Rc<FakeClock>,
        acquirer: FakeAcquirer,
    }

    impl Harness {
        fn new() -> Harness {
            let dir = TempDir::new("commands");
            let env = HostEnv::new("com.example.oftc", &dir.0).unwrap();
            let clock = Rc::new(FakeClock {
                unix: Cell::new(1000),
                mono: Cell::new(Duration::ZERO),
                on_sleep: RefCell::new(None),
            });
            let wire = encode_hbr1("vpn.example.com", UID, b"secret", b"token").unwrap();
            let acquirer = FakeAcquirer {
                clock: clock.clone(),
                result: RefCell::new(Ok(wire.as_bytes().to_vec())),
                takes_secs: Cell::new(0),
                meanwhile: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
            };
            Harness {
                dir,
                env,
                keychain: MemoryKeychain::default(),
                prompt: Scripted(RefCell::new(None)),
                vpn: MockVpn::new(),
                clock,
                acquirer,
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
                vpn: &self.vpn,
                acquirer: &self.acquirer,
                clock: &*self.clock,
                session_id: &unique_session_id,
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
        h.expect(&["stop"], &format!("{}\n", usage()), 2); // still Swift's
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

    // ---- the VPN verbs, against MockVpn and a scripted browser ----

    impl Harness {
        /// One profile ("Example Office", udp, 9443), its PSK and its VPN entry.
        fn setup(&self) -> Arc<MockEntry> {
            self.run(
                &[
                    "save-profile",
                    "vpn.example.com",
                    "9443",
                    "--name",
                    "Example Office",
                ],
                "",
            );
            self.keychain.set("vpn.example.com", b"secret").unwrap();
            self.vpn.add_entry(PROVIDER, Some("example-office"), true)
        }

        fn started_as_provider_sees_it(&self, entry: &MockEntry, now: u64) -> StartMode {
            let (kind, envelope, mode) = entry.started().remove(0);
            let data = |bytes: &[u8]| Some(OptionValue::Data(Secret::new(bytes.to_vec())));
            let options = match kind {
                StartKind::Live => ProviderOptions {
                    live: data(&envelope),
                    mode: mode.as_deref().and_then(data),
                    ..Default::default()
                },
                StartKind::Preflight => {
                    assert_eq!(mode, None, "a preflight carries no mode");
                    ProviderOptions {
                        preflight: data(&envelope),
                        ..Default::default()
                    }
                }
            };
            consume(&options, now).expect("the provider accepts what the host built")
        }
    }

    #[test]
    fn parse_vpn_verbs() {
        let udp = parse_start_flags(&[]).unwrap();
        let cmd = |args: &[&str]| parse(&strings(args)).map(|i| i.command);
        assert_eq!(cmd(&["install-config"]), Ok(Command::InstallConfig));
        assert_eq!(cmd(&["rekey-ike-once"]), Ok(Command::RekeyIkeOnce));
        assert_eq!(
            cmd(&["start-live", "vpn.example.com", "9443"]),
            Ok(Command::StartLive {
                gateway: "vpn.example.com".into(),
                port: 9443,
                mode: udp.0,
                insecure: false
            })
        );
        // Swift's `args.count` guards, the port range, and flag errors are all usage.
        for args in [
            &["status", "x"][..],
            &["preflight", "vpn.example.com"],
            &["preflight", "a", "b", "c"],
            &["start-live", "vpn.example.com"],
            &["start-live", "vpn.example.com", "0"],
            &["start-live", "vpn.example.com", "65536"],
            &["start-live", "", "9443"],
            &["start-live", "vpn.example.com", "9443", "--bogus"],
            &[
                "start-live",
                "vpn.example.com",
                "9443",
                "--ipv6-outer",
                "127.0.0.1",
            ],
        ] {
            assert_eq!(cmd(args), Err(ParseError::Usage), "{args:?}");
        }
        // start-profile defers its flags until the profile is known.
        assert_eq!(
            cmd(&["start-profile", "--bogus"]),
            Ok(Command::StartProfile {
                flags: vec!["--bogus".into()]
            })
        );
    }

    #[test]
    fn install_config_is_idempotent_and_scoped_to_its_profile() {
        let h = Harness::new();
        h.expect(
            &["install-config"],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        h.run(
            &[
                "save-profile",
                "vpn.example.com",
                "9443",
                "--name",
                "Example Office",
            ],
            "",
        );
        // Another profile's entry and another app's entry are not this profile's.
        h.vpn.add_entry(PROVIDER, Some("lab"), true);
        h.vpn
            .add_entry("com.other.provider", Some("example-office"), true);
        h.expect(&["install-config"], "OFTC configuration saved\n", 0);
        let created: Vec<_> = h
            .vpn
            .load_all()
            .unwrap()
            .into_iter()
            .filter(|e| {
                e.profile_key.as_deref() == Some("example-office") && e.provider_id == PROVIDER
            })
            .collect();
        assert_eq!(created.len(), 1);
        h.expect(
            &["install-config"],
            "OFTC configuration already exists\n",
            0,
        );
        assert_eq!(h.vpn.load_all().unwrap().len(), 3, "nothing was added");
        // A duplicate is refused rather than guessed at.
        h.vpn.add_entry(PROVIDER, Some("example-office"), true);
        h.expect(
            &["status"],
            "Multiple OFTC configurations; refusing to guess\n",
            1,
        );
    }

    #[test]
    fn status_reports_each_state_or_absence() {
        let h = Harness::new();
        h.run(&["save-profile", "vpn.example.com", "9443"], "");
        h.expect(&["status"], "OFTC configuration absent\n", 0);
        let entry = h.vpn.add_entry(PROVIDER, Some("vpn-example-com"), true);
        for (status, word) in [
            (VpnStatus::Invalid, "invalid"),
            (VpnStatus::Disconnected, "disconnected"),
            (VpnStatus::Connecting, "connecting"),
            (VpnStatus::Connected, "connected"),
            (VpnStatus::Reasserting, "reasserting"),
            (VpnStatus::Disconnecting, "disconnecting"),
        ] {
            entry.set_status(status);
            h.expect(&["status"], &format!("OFTC VPN status: {word}\n"), 0);
        }
    }

    /// An entry with no profile key belongs to the profile migrated from the
    /// original single-profile layout, and to no other.
    #[test]
    fn an_unkeyed_entry_belongs_only_to_the_profile_that_adopted_it() {
        let h = Harness::new();
        h.run(&["save-profile", "vpn.example.com", "9443"], "");
        h.vpn.add_entry(PROVIDER, None, true);
        h.expect(&["status"], "OFTC configuration absent\n", 0);

        // A profile migrated from the original layout adopts the unkeyed entry.
        let h = Harness::new();
        let root = h.env.root();
        std::fs::create_dir_all(root).unwrap();
        for file in ["profile.json", "connection-preferences.json"] {
            std::fs::copy(fixture("swift/legacy-root").join(file), root.join(file)).unwrap();
        }
        h.vpn.add_entry(PROVIDER, None, true);
        h.expect(&["status"], "OFTC VPN status: disconnected\n", 0);
    }

    #[test]
    fn remove_config_removes_every_entry_of_this_app_and_only_those() {
        let h = Harness::new();
        h.expect(&["remove-config"], "OFTC configuration absent\n", 0);
        h.vpn.add_entry(PROVIDER, Some("a"), true);
        h.vpn.add_entry(PROVIDER, None, false);
        h.vpn.add_entry("com.other.provider", Some("a"), true);
        // No profile is needed, and none exists here.
        h.expect(&["remove-config"], "OFTC configuration removed\n", 0);
        let left = h.vpn.load_all().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].provider_id, "com.other.provider");
    }

    #[test]
    fn erase_profile_refuses_while_connected_then_erases_everything_of_the_profile() {
        let h = Harness::new();
        let entry = h.setup();
        let other = h.vpn.add_entry(PROVIDER, Some("lab"), true);
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
        let pin_dir = h.env.pin_dir();
        std::fs::create_dir_all(&pin_dir).unwrap();
        let pin = pin_dir.join("vpn.example.com_9443.pem");
        let other_pin = pin_dir.join("lab.example.com_8443.pem");
        std::fs::write(&pin, "x").unwrap();
        std::fs::write(&other_pin, "x").unwrap();

        entry.set_status(VpnStatus::Connecting);
        h.expect(
            &["--profile", "example-office", "erase-profile"],
            "Disconnect Example Office before erasing its profile\n",
            1,
        );
        assert!(h.keychain.get("vpn.example.com").is_ok() && pin.exists());
        assert_eq!(h.vpn.load_all().unwrap().len(), 2);

        entry.set_status(VpnStatus::Disconnected);
        h.expect(
            &["--profile", "example-office", "erase-profile"],
            "OFTC profile, VPN entry and Keychain PSK erased\n",
            0,
        );
        assert_eq!(
            h.vpn.load_all().unwrap().len(),
            1,
            "only the lab entry remains"
        );
        assert!(h.keychain.get("vpn.example.com").is_err());
        assert!(!pin.exists() && other_pin.exists());
        assert!(!registry::entry_directory(h.env.root(), "example-office").exists());
        assert!(registry::entry_directory(h.env.root(), "lab").exists());

        // With no --profile, every profile goes; with none left there is nothing to do.
        other.set_status(VpnStatus::Invalid);
        h.expect(
            &["erase-profile"],
            "OFTC profile, VPN entry and Keychain PSK erased\n",
            0,
        );
        assert!(h.vpn.load_all().unwrap().is_empty() && !other_pin.exists());
        h.expect(
            &["erase-profile"],
            "OFTC profile absent; nothing erased\n",
            0,
        );
    }

    #[test]
    fn rekey_probes_report_the_provider_reply() {
        let h = Harness::new();
        let entry = h.setup();
        h.expect(&["rekey-once"], "OFTC VPN is not connected\n", 1);
        assert!(entry.sent().is_empty());
        entry.set_status(VpnStatus::Connected);
        let rows: Vec<Row> = vec![
            (
                Ok(b"rekey_passed".to_vec()),
                "CHILD_SA rekey probe passed",
                0,
            ),
            (
                Ok(b"rekey_failed stage=7".to_vec()),
                "CHILD_SA rekey probe failed (stage 7)",
                1,
            ),
            (
                Ok(b"rekey_failed stage=201".to_vec()),
                "CHILD_SA rekey probe failed",
                1,
            ),
            (Ok(vec![0xff]), "CHILD_SA rekey probe failed", 1),
            (
                Err(AppleError::TimedOut),
                "CHILD_SA rekey probe timed out",
                1,
            ),
            (
                Err(AppleError::StaleEntry),
                "Could not request CHILD_SA rekey probe",
                1,
            ),
        ];
        for (reply, text, code) in rows {
            entry.push_reply(reply.clone());
            h.expect(&["rekey-once"], &format!("{text}\n"), code);
        }
        entry.push_reply(Ok(b"rekey_passed".to_vec()));
        h.expect(&["rekey-ike-once"], "IKE_SA rekey probe passed\n", 0);
        let sent = entry.sent();
        assert_eq!(sent[0], b"oftc.rekey-child-once.v1");
        assert_eq!(sent.last().unwrap(), b"oftc.rekey-ike-once.v1");
    }

    #[test]
    fn rekey_counts_passes_the_reply_through_and_ignores_the_enabled_flag() {
        let h = Harness::new();
        h.run(&["save-profile", "vpn.example.com", "9443"], "");
        let entry = h.vpn.add_entry(PROVIDER, Some("vpn-example-com"), false);
        entry.set_status(VpnStatus::Connected);
        let rows: Vec<Row> = vec![
            (
                Ok(b"child_rekeys local=2 remote=1".to_vec()),
                "child_rekeys local=2 remote=1",
                0,
            ),
            (
                Ok(b"something else".to_vec()),
                "CHILD_SA rekey counts unavailable",
                1,
            ),
            (
                Err(AppleError::TimedOut),
                "CHILD_SA rekey counts unavailable",
                1,
            ),
            (
                Err(AppleError::StaleEntry),
                "Could not request CHILD_SA rekey counts",
                1,
            ),
        ];
        for (reply, text, code) in rows {
            entry.push_reply(reply);
            h.expect(&["rekey-counts"], &format!("{text}\n"), code);
        }
        // The probes, unlike the counts, need an enabled entry.
        h.expect(&["rekey-once"], "OFTC VPN is not connected\n", 1);
        entry.set_status(VpnStatus::Disconnected);
        h.expect(&["rekey-counts"], "OFTC VPN is not connected\n", 1);
    }

    #[test]
    fn preflight_checks_its_inputs_then_reports_the_stage_and_stops_the_tunnel() {
        let h = Harness::new();
        h.expect(
            &["preflight", "vpn.example.com", "nope"],
            "Expected a 32-character hexadecimal UID\n",
            2,
        );
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "PSK unavailable in OFTC Keychain service\n",
            1,
        );
        h.keychain.set("vpn.example.com", b"secret").unwrap();
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        let entry = h.setup();
        h.vpn.remove(&h.vpn.load_all().unwrap()[0]).unwrap();
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "No OFTC configuration; run install-config\n",
            1,
        );
        let entry2 = h.vpn.add_entry(PROVIDER, Some("example-office"), true);
        let _ = entry;

        // The provider comes up on the first poll; its first reply is lost, so the
        // loop asks again rather than giving up.
        let hook = entry2.clone();
        *h.clock.on_sleep.borrow_mut() = Some(Box::new(move || {
            if hook.sent().is_empty() {
                hook.set_status(VpnStatus::Connected);
                hook.push_reply(Err(AppleError::TimedOut));
                hook.push_reply(Ok(b"preflight_passed stage=ike".to_vec()));
            }
        }));
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "preflight_passed stage=ike\n",
            0,
        );
        assert_eq!(entry2.stops(), 1);
        assert_eq!(entry2.sent().len(), 2);
        let StartMode::Preflight(input) = h.started_as_provider_sees_it(&entry2, 1000) else {
            panic!("not a preflight");
        };
        assert_eq!(
            (input.gateway.as_str(), input.uid.as_str()),
            ("vpn.example.com", UID)
        );
        assert_eq!(input.psk.as_bytes(), b"secret");
    }

    #[test]
    fn a_failed_stage_exits_1_and_silence_times_out_after_45_seconds() {
        let h = Harness::new();
        let entry = h.setup();
        entry.set_status(VpnStatus::Disconnected);
        let hook = entry.clone();
        *h.clock.on_sleep.borrow_mut() = Some(Box::new(move || {
            hook.set_status(VpnStatus::Connected);
            hook.push_reply(Ok(b"preflight_failed stage=3".to_vec()));
        }));
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "preflight_failed stage=3\n",
            1,
        );
        assert_eq!(entry.stops(), 1);

        // Never connects: the fake clock runs to the deadline.
        let h = Harness::new();
        let entry = h.setup();
        h.expect(
            &["preflight", "vpn.example.com", UID],
            "Provider preflight did not report a stage before timeout\n",
            1,
        );
        assert_eq!(entry.stops(), 1);
        assert_eq!(h.clock.mono.get(), Duration::from_secs(45));
    }

    #[test]
    fn start_live_refuses_before_opening_a_browser_when_it_cannot_start() {
        let h = Harness::new();
        let live = ["start-live", "vpn.example.com", "9443"];
        h.expect(&live, "OFTC profile unavailable; run oftc setup\n", 1);
        let entry = h.setup();
        h.vpn.remove(&h.vpn.load_all().unwrap()[0]).unwrap();
        h.expect(&live, "No OFTC configuration; run install-config\n", 1);
        let entry2 = h.vpn.add_entry(PROVIDER, Some("example-office"), true);
        let _ = entry;
        entry2.set_status(VpnStatus::Connected);
        h.expect(
            &live,
            "OFTC configuration unavailable or VPN already active\n",
            1,
        );
        entry2.set_status(VpnStatus::Disconnected);
        h.keychain.delete("vpn.example.com").unwrap();
        h.expect(&live, "PSK unavailable in OFTC Keychain service\n", 1);
        assert!(
            h.acquirer.calls.borrow().is_empty(),
            "no sign-in was attempted"
        );
        assert!(entry2.started().is_empty());
    }

    /// The envelope is stamped after the sign-in, so a login that takes minutes
    /// cannot age it out (the Swift check `afterSAML` pinned this for Swift).
    #[test]
    fn start_live_stamps_the_envelope_after_the_sign_in_and_hands_over_the_mode() {
        let h = Harness::new();
        let entry = h.setup();
        h.acquirer.takes_secs.set(500);
        h.expect(
            &[
                "start-live",
                "vpn.example.com",
                "9443",
                "--tcp",
                "--insecure-saml",
            ],
            "Live start requested; inspect status before any fresh-token retry\n",
            0,
        );
        let calls = h.acquirer.calls.borrow();
        let profile = TunnelProfile {
            name: "Example Office".into(),
            gateway: "vpn.example.com".into(),
        };
        assert_eq!(
            calls[0],
            (
                "vpn.example.com".to_owned(),
                b"secret".to_vec(),
                9443,
                true,
                profile
            )
        );
        let (_, envelope, mode) = entry.started().remove(0);
        assert_eq!(
            &envelope[5..13],
            &1560u64.to_be_bytes(),
            "now (1500) + 60, not 1000 + 60"
        );
        assert_eq!(mode.as_deref(), Some(&[1, 2, 4, 0, 0, 0, 0, 0][..]));
        let StartMode::Live(input, _) = h.started_as_provider_sees_it(&entry, 1500) else {
            panic!("not live");
        };
        assert_eq!(input.token.as_bytes(), b"token");
    }

    #[test]
    fn start_live_failures_start_nothing() {
        let h = Harness::new();
        let entry = h.setup();
        let live = ["start-live", "vpn.example.com", "9443"];
        for failure in [AcquireFailure::BeforeBrowser, AcquireFailure::Other] {
            *h.acquirer.result.borrow_mut() = Err(failure);
            h.expect(&live, "SAML bootstrap failed\n", 1);
        }
        // Someone connected while the browser was open: do not start over it.
        *h.acquirer.result.borrow_mut() = Ok(encode_hbr1("vpn.example.com", UID, b"p", b"t")
            .unwrap()
            .as_bytes()
            .to_vec());
        let hook = entry.clone();
        *h.acquirer.meanwhile.borrow_mut() =
            Some(Box::new(move || hook.set_status(VpnStatus::Connected)));
        h.expect(
            &live,
            "OFTC configuration or status changed before start\n",
            1,
        );
        assert!(entry.started().is_empty());
    }

    #[test]
    fn start_profile_uses_the_profiles_own_settings() {
        let h = Harness::new();
        h.expect(
            &["start-profile", "--bogus"],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        h.run(
            &[
                "--profile",
                "lab",
                "save-profile",
                "lab.example.com",
                "8443",
                "--tcp",
            ],
            "",
        );
        h.keychain.set("lab.example.com", b"labpsk").unwrap();
        let entry = h.vpn.add_entry(PROVIDER, Some("lab"), true);
        // The flags are checked once the profile is found.
        h.expect(&["start-profile", "--bogus"], &format!("{}\n", usage()), 2);
        h.expect(
            &["start-profile", "--insecure-saml"],
            "Live start requested; inspect status before any fresh-token retry\n",
            0,
        );
        let calls = h.acquirer.calls.borrow();
        assert_eq!(
            (calls[0].0.as_str(), calls[0].2, calls[0].3),
            ("lab.example.com", 8443, true)
        );
        // The profile's TCP transport applies without --tcp on the command line.
        assert_eq!(
            entry.started()[0].2.as_deref(),
            Some(&[1, 2, 4, 0, 0, 0, 0, 0][..])
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
