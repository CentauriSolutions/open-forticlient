//! The host verbs: argv to output and exit code.
//!
//! [`run`] takes every outside dependency as an argument ([`Backends`], [`Io`],
//! [`HostEnv`]) and returns the exit code; it never exits the process. The text
//! each verb prints and the code it returns are the verb protocol that `oftc` and
//! the menu parse, documented in `docs/host-verbs.md` and pinned by the golden
//! table in the tests.

use std::io::Read;

use oftc_apple::error::AppleError;
use oftc_apple::login::LoginItems;
use oftc_apple::login::{LoginItem, LoginStatus};
use oftc_apple::sysext::{EventSink, ExtensionControl, ExtensionEvent, Finish};
use zeroize::Zeroizing;

use crate::agent::{self, Launchctl};
use crate::env::HostEnv;
use crate::intent;
use crate::keychain::{read_psk_line, Keychain, KeychainError};
use crate::out::Out;
use crate::profile::{Profile, Transport};
use crate::registry::{self, ProfileEntry};

/// One line of the usage text: how a verb is spelled, and who implements it.
pub struct Verb {
    pub synopsis: &'static str,
    /// True when `oftc_host_main` handles it; false while Swift still does.
    pub rust: bool,
    /// Not in the usage text: a verb the scripts and the menu run that the
    /// shipped usage never listed. Kept out so the text stays byte-for-byte.
    pub hidden: bool,
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
        hidden: false,
    }
}

const fn hidden(synopsis: &'static str) -> Verb {
    Verb {
        synopsis,
        rust: true,
        hidden: true,
    }
}

const fn swift(synopsis: &'static str) -> Verb {
    Verb {
        synopsis,
        rust: false,
        hidden: false,
    }
}

/// Every verb, in the order the usage text lists them. Each later change moves
/// verbs from `swift` to `rust` here and in `Host/main.swift`.
pub const VERBS: &[Verb] = &[
    rust("activate"),
    rust("deactivate"),
    rust("agent-status"),
    rust("register-agent"),
    rust("unregister-agent"),
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
    hidden("login-settings"),
    hidden("unregister-menu-login"),
];

/// The usage text, as `OFTCAgent` prints it for a bad command line.
pub fn usage() -> String {
    let verbs: Vec<&str> = VERBS
        .iter()
        .filter(|verb| !verb.hidden)
        .map(|verb| verb.synopsis)
        .collect();
    format!("Usage: OFTCAgent [--profile <id>] {}", verbs.join("|"))
}

/// The verbs this crate implements, for the Swift stub to delegate.
pub fn rust_verbs() -> impl Iterator<Item = &'static str> {
    VERBS.iter().filter(|verb| verb.rust).map(Verb::name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Activate,
    Deactivate,
    AgentStatus,
    RegisterAgent,
    UnregisterAgent,
    LoginSettings,
    UnregisterMenuLogin,
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
        ("activate", []) => Command::Activate,
        ("deactivate", []) => Command::Deactivate,
        ("agent-status", []) => Command::AgentStatus,
        ("register-agent", []) => Command::RegisterAgent,
        ("unregister-agent", []) => Command::UnregisterAgent,
        ("login-settings", []) => Command::LoginSettings,
        ("unregister-menu-login", []) => Command::UnregisterMenuLogin,
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
    pub extensions: &'a dyn ExtensionControl,
    pub login: &'a dyn LoginItems,
    pub launchctl: &'a dyn Launchctl,
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

/// `activate` and `deactivate`: submit the request and narrate it, as the Swift
/// delegate did. The events print as they happen, while the request waits on
/// the user.
fn change_extension(activate: bool, env: &HostEnv, backends: &Backends, io: &mut Io) -> i32 {
    let provider = env.provider_id();
    let sink: EventSink = {
        let out = io.out.clone();
        let provider = provider.clone();
        std::sync::Arc::new(move |event| {
            match event {
                ExtensionEvent::NeedsApproval => {
                    out.line(&format!("macOS approval required for {provider}"));
                    out.line("In System Settings → General → Login Items & Extensions, click ⓘ next to OFTC under Extensions and turn on Network Extension.");
                }
                ExtensionEvent::Replacing { from, to } => out.line(&format!(
                    "System extension replacement: {}/{} -> {}/{}",
                    from.short, from.build, to.short, to.build
                )),
            }
            out.flush();
        })
    };
    let result = if activate {
        backends.extensions.activate(&provider, sink)
    } else {
        backends.extensions.deactivate(&provider, sink)
    };
    match result {
        Ok(Finish::Completed) => finish(io, "System extension request completed", 0),
        Ok(Finish::WillCompleteAfterReboot) => {
            finish(io, "Extension replacement accepted; reboot required", 3)
        }
        Err(AppleError::Ns { domain, code, .. }) => finish(
            io,
            &format!("System extension request failed: domain={domain} code={code}"),
            1,
        ),
        Err(other) => finish(io, &format!("System extension request failed: {other}"), 1),
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
        Command::Activate => change_extension(true, env, backends, io),
        Command::Deactivate => change_extension(false, env, backends, io),
        Command::AgentStatus => finish(io, agent::status(backends.login), 0),
        Command::RegisterAgent => match agent::register(backends.login, backends.launchctl) {
            Ok(()) => finish(io, "OFTC login agent registered", 0),
            Err(e) => finish(io, &format!("Could not register OFTC login agent: {e}"), 1),
        },
        Command::UnregisterAgent => match agent::unregister(backends.login) {
            Ok(()) => finish(io, "OFTC login agent unregistered", 0),
            Err(e) => finish(
                io,
                &format!("Could not unregister OFTC login agent: {e}"),
                1,
            ),
        },
        Command::UnregisterMenuLogin => {
            let main = LoginItem::MainApp;
            let registered = matches!(
                backends.login.status(&main),
                LoginStatus::Enabled | LoginStatus::RequiresApproval
            );
            if registered && backends.login.unregister(&main).is_err() {
                return finish(io, "Could not unregister the OFTC menu login item", 1);
            }
            finish(io, "OFTC menu login item unregistered", 0)
        }
        Command::LoginSettings => {
            let state = |on: bool| if on { "enabled" } else { "disabled" };
            let menu = backends.login.status(&LoginItem::MainApp) == LoginStatus::Enabled;
            let mut lines = vec![format!("Menu launch at login: {}", state(menu))];
            let agent_enabled = agent::status(backends.login) == "enabled";
            for entry in registry::entries(root) {
                let legacy = entry.profile.adopts_unkeyed_vpn_entry == Some(true) && agent_enabled;
                let on =
                    intent::connect_at_login(&registry::entry_directory(root, &entry.id), legacy);
                lines.push(format!(
                    "VPN connect at login ({}): {}",
                    entry.id,
                    state(on)
                ));
            }
            finish(io, &lines.join("\n"), 0)
        }
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
    use crate::agent::{agent_item, RecordingLaunchctl};
    use crate::keychain::MemoryKeychain;
    use crate::out::Capture;
    use crate::profile::testutil::{fixture, TempDir};
    use oftc_apple::login::MockLoginItems;
    use oftc_apple::sysext::{ExtensionVersion, MockExtensions};
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
            (vec!["activate"], invocation(None, Command::Activate)),
            (vec!["activate", "x"], Err(ParseError::Usage)),
            (vec!["agent-status", "x"], Err(ParseError::Usage)),
            (
                vec!["--profile", "lab", "unregister-menu-login"],
                invocation(Some("lab"), Command::UnregisterMenuLogin),
            ),
            (vec!["status"], Err(ParseError::Usage)), // still Swift's
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
        extensions: MockExtensions,
        login: MockLoginItems,
        launchctl: RecordingLaunchctl,
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
                extensions: MockExtensions::new(),
                login: MockLoginItems::new(),
                launchctl: RecordingLaunchctl::new(true),
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
                extensions: &self.extensions,
                login: &self.login,
                launchctl: &self.launchctl,
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

    fn version(short: &str, build: &str) -> ExtensionVersion {
        ExtensionVersion {
            short: short.into(),
            build: build.into(),
        }
    }

    /// `activate` and `deactivate`: the narration and exit code of each way a
    /// request can end, and which request was made for which identifier.
    #[test]
    fn extension_requests() {
        let h = Harness::new();
        let provider = "com.example.oftc.provider";
        h.extensions
            .script_activate(Vec::new(), Ok(Finish::Completed));
        h.expect(&["activate"], "System extension request completed\n", 0);
        h.extensions.script_activate(
            vec![
                ExtensionEvent::NeedsApproval,
                ExtensionEvent::Replacing {
                    from: version("1.0", "7"),
                    to: version("1.1", "8"),
                },
            ],
            Ok(Finish::WillCompleteAfterReboot),
        );
        h.expect(
            &["activate"],
            &format!(
                "macOS approval required for {provider}\n\
                 In System Settings → General → Login Items & Extensions, click ⓘ next to OFTC under Extensions and turn on Network Extension.\n\
                 System extension replacement: 1.0/7 -> 1.1/8\n\
                 Extension replacement accepted; reboot required\n"
            ),
            3,
        );
        h.extensions.script_deactivate(
            Vec::new(),
            Err(AppleError::from_nserror(
                "OSSystemExtensionErrorDomain",
                8,
                "bad",
            )),
        );
        h.expect(
            &["deactivate"],
            "System extension request failed: domain=OSSystemExtensionErrorDomain code=8\n",
            1,
        );
        // A request the system never answers is not an NSError.
        h.expect(
            &["deactivate"],
            "System extension request failed: timed out waiting for the system\n",
            1,
        );
        let kinds: Vec<_> = h.extensions.requests();
        assert_eq!(
            kinds,
            [
                ("activate", provider.to_owned()),
                ("activate", provider.to_owned()),
                ("deactivate", provider.to_owned()),
                ("deactivate", provider.to_owned()),
            ]
        );
    }

    /// The login verbs over every status the system reports.
    #[test]
    fn login_verbs() {
        let h = Harness::new();
        let agent = agent_item();
        for (status, text) in [
            (LoginStatus::NotRegistered, "not-registered"),
            (LoginStatus::RequiresApproval, "requires-approval"),
            (LoginStatus::NotFound, "not-found"),
            (LoginStatus::Enabled, "enabled"),
        ] {
            h.login.set_status(&agent, status);
            h.expect(&["agent-status"], &format!("{text}\n"), 0);
        }

        h.login.set_status(&agent, LoginStatus::NotRegistered);
        h.expect(&["register-agent"], "OFTC login agent registered\n", 0);
        assert_eq!(h.launchctl.calls(), [crate::agent::AGENT_LABEL]);
        h.login.set_status(&agent, LoginStatus::RequiresApproval);
        h.expect(
            &["register-agent"],
            "Could not register OFTC login agent: OFTC login agent is requires-approval\n",
            1,
        );
        h.expect(&["unregister-agent"], "OFTC login agent unregistered\n", 0);
        assert_eq!(h.login.status(&agent), LoginStatus::NotRegistered);
        h.login
            .script_register(&agent, Err(AppleError::from_nserror("d", 1, "denied")));
        h.expect(
            &["register-agent"],
            "Could not register OFTC login agent: denied\n",
            1,
        );
        h.login.set_status(&agent, LoginStatus::Unknown);
        h.expect(
            &["unregister-agent"],
            "Could not unregister OFTC login agent: OFTC login agent is unknown\n",
            1,
        );

        // The menu login item: only a registered one is touched.
        let main = LoginItem::MainApp;
        h.expect(
            &["unregister-menu-login"],
            "OFTC menu login item unregistered\n",
            0,
        );
        assert!(h.login.calls().iter().all(|(_, item)| item != &main));
        h.login.set_status(&main, LoginStatus::RequiresApproval);
        h.expect(
            &["unregister-menu-login"],
            "OFTC menu login item unregistered\n",
            0,
        );
        assert_eq!(h.login.status(&main), LoginStatus::NotRegistered);
        h.login.set_status(&main, LoginStatus::Enabled);
        h.login
            .script_unregister(&main, Err(AppleError::from_nserror("d", 1, "no")));
        h.expect(
            &["unregister-menu-login"],
            "Could not unregister the OFTC menu login item\n",
            1,
        );
    }

    /// `login-settings` lists the menu item, then each profile's preference; a
    /// migrated profile inherits an already registered agent.
    #[test]
    fn login_settings_reads_each_profile() {
        let h = Harness::new();
        h.expect(&["login-settings"], "Menu launch at login: disabled\n", 0);
        let root = h.env.root();
        std::fs::create_dir_all(root).unwrap();
        for file in ["profile.json", "connection-preferences.json"] {
            std::fs::copy(fixture("swift/legacy-root").join(file), root.join(file)).unwrap();
        }
        // Migration moves the stored preference (true) with the profile.
        h.run(&["list-profiles"], "");
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
        h.login
            .set_status(&LoginItem::MainApp, LoginStatus::Enabled);
        // An enabled agent does not switch on a profile that did not adopt it.
        h.login.set_status(&agent_item(), LoginStatus::Enabled);
        h.expect(
            &["login-settings"],
            "Menu launch at login: enabled\n\
             VPN connect at login (example-office): enabled\n\
             VPN connect at login (lab): disabled\n",
            0,
        );
    }
}
