//! The host verbs: argv to output and exit code.
//!
//! [`run`] takes every outside dependency as an argument ([`Backends`], [`Io`],
//! [`HostEnv`]) and returns the exit code; it never exits the process. The text
//! each verb prints and the code it returns are the verb protocol that `oftc` and
//! the menu parse, documented in `docs/host-verbs.md` and pinned by the golden
//! table in the tests.

use std::io::Read;
use std::time::{Duration, SystemTime};

use oftc_apple::error::AppleError;
use oftc_apple::login::LoginItems;
use oftc_apple::login::{LoginItem, LoginStatus};
use oftc_apple::manager::VpnControl;
use oftc_apple::sysext::{EventSink, ExtensionControl, ExtensionEvent, Finish};
use oftc_provider::envelope::ConnectMode;
use zeroize::Zeroizing;

use crate::acquire::{Acquirer, Clock};
use crate::agent::{self, Launchctl};
use crate::bundle;
use crate::env::HostEnv;
use crate::intent;
use crate::keychain::{read_psk_line, Keychain, KeychainError};
use crate::out::Out;
use crate::profile::{Profile, Transport};
use crate::registry::{self, FortiClientSource, ProfileEntry};
use crate::typed::Failure;
use oftc_ui_edge::ErrorCode;
use crate::serve;
use crate::start::parse_start_flags;
use crate::supervisor::Signals;
use crate::trust::Outcome as Trust;
use crate::vpn::{self, Ctx, Rekey};

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
    rust("install-config"),
    rust("list-profiles"),
    swift("check-update [url]"),
    swift("launcher-alias ensure|remove"),
    rust("export-profiles [id...]"),
    rust("import-profiles"),
    rust("save-profile <gateway> <saml-port> [--tcp] [--name <name>]"),
    rust("import-profile <FortiClient-profile>"),
    rust("show-profile"),
    rust("erase-profile"),
    rust("has-psk"),
    rust("set-autostart on|off"),
    rust("supervise-autostart"),
    rust("start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    rust("supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    rust("provision-psk [--stdin] [gateway]"),
    rust("migrate-psk <FortiClient-profile> <gateway>"),
    rust("preflight <gateway> <32-hex-UID>"),
    rust("start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]"),
    rust(
        "supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]",
    ),
    rust("rekey-once"),
    rust("rekey-ike-once"),
    rust("rekey-counts"),
    rust("status"),
    rust("stop"),
    rust("remove-config"),
    hidden("login-settings"),
    hidden("unregister-menu-login"),
    hidden("host serve"),
    hidden("host restart"),
    hidden("host register"),
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
    /// `host serve`: the socket service (`serve`).
    HostServe,
    /// `host restart`: `launchctl kickstart -k` of the host service.
    HostRestart,
    /// `host register`: registers the host service with the system and starts it.
    HostRegister,
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
    Stop,
    SetAutostart {
        enabled: bool,
    },
    SuperviseAutostart,
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
    SuperviseLive {
        gateway: String,
        port: u32,
        mode: ConnectMode,
        insecure: bool,
    },
    /// Like `StartProfile`, the flags are checked after the profile is found.
    SuperviseProfile {
        flags: Vec<String>,
    },
    ExportProfiles {
        ids: Vec<String>,
    },
    ImportProfiles,
    ImportProfile {
        forticlient_name: String,
    },
    MigratePsk {
        forticlient_name: String,
        gateway: String,
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
        ("host", [sub]) if sub == "serve" => Command::HostServe,
        ("host", [sub]) if sub == "restart" => Command::HostRestart,
        ("host", [sub]) if sub == "register" => Command::HostRegister,
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
        ("stop", []) => Command::Stop,
        ("set-autostart", [state]) if state == "on" || state == "off" => Command::SetAutostart {
            enabled: state == "on",
        },
        ("supervise-autostart", []) => Command::SuperviseAutostart,
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
        ("supervise-live", [gateway, port, flags @ ..]) => {
            let port: u32 = port.parse().map_err(|_| ParseError::Usage)?;
            let (mode, insecure) = parse_start_flags(flags).ok_or(ParseError::Usage)?;
            if !(1..=65535).contains(&port) || gateway.is_empty() {
                return Err(ParseError::Usage);
            }
            Command::SuperviseLive {
                gateway: gateway.clone(),
                port,
                mode,
                insecure,
            }
        }
        ("start-profile", flags) => Command::StartProfile {
            flags: flags.to_vec(),
        },
        ("supervise-profile", flags) => Command::SuperviseProfile {
            flags: flags.to_vec(),
        },
        ("export-profiles", ids) => Command::ExportProfiles { ids: ids.to_vec() },
        ("import-profiles", []) => Command::ImportProfiles,
        ("import-profile", [name]) => Command::ImportProfile {
            forticlient_name: name.clone(),
        },
        ("migrate-psk", [name, gateway]) => Command::MigratePsk {
            forticlient_name: name.clone(),
            gateway: gateway.clone(),
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

/// What an installed FortiClient profile provides, for `import-profile` and
/// `migrate-psk`. `None` when the profile is missing or unusable.
pub trait FortiClientProfiles: Send + Sync {
    /// The installed profiles that could be imported, without their PSKs (the
    /// `list_sources` op). The default reads FortiClient's own property list.
    fn list(&self) -> Vec<FortiClientSource> {
        registry::forticlient_sources(std::path::Path::new(registry::FORTICLIENT_VPN_PLIST))
    }
    fn import(&self, name: &str) -> Option<FortiClientProfile>;
    /// The PSK of profile `name`, only when it is for exactly `gateway`.
    fn psk(&self, name: &str, gateway: &str) -> Option<Zeroizing<Vec<u8>>>;
}

pub struct FortiClientProfile {
    pub gateway: String,
    pub saml_port: u32,
    pub psk: Zeroizing<Vec<u8>>,
}

/// Everything a verb reaches outside this process.
pub struct Backends<'a> {
    pub keychain: &'a dyn Keychain,
    pub prompt: &'a dyn SecretPrompt,
    pub forticlient: &'a dyn FortiClientProfiles,
    /// The FortiClient profile name for a gateway, to name a migrated profile.
    pub legacy_name: &'a dyn Fn(&str) -> Option<String>,
    pub extensions: &'a dyn ExtensionControl,
    pub login: &'a dyn LoginItems,
    pub launchctl: &'a dyn Launchctl,
    pub vpn: &'a dyn VpnControl,
    pub acquirer: &'a dyn Acquirer,
    pub clock: &'a dyn Clock,
    /// A fresh single-use session id for each start envelope.
    pub session_id: &'a dyn Fn() -> [u8; 16],
    /// SIGINT and SIGTERM, for the supervisor.
    pub signals: &'a dyn Signals,
    /// Asks the user about an untrusted gateway certificate (host, port, profile
    /// name); the host builds it from `trust`.
    pub review: &'a dyn Fn(&str, u32, &str) -> Trust,
    /// One diagnostic line from the supervisor (stderr in the host).
    pub diagnostic: &'a dyn Fn(&str),
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
    let ctx = Ctx {
        env,
        backends,
        selected: &selected,
    };
    let vpn_verb = |(text, code): (String, i32), io: &mut Io| finish(io, &text, code);
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
        Command::HostServe => {
            let spawner = serve::ops_system::ProcessSpawner {
                exe: env.exe().map(Into::into),
                logs: env.logs_dir(),
            };
            let updates = serve::ops_update::CurlUpdates::from_bundle(env.exe());
            let (text, code) = serve::run(
                env,
                env.root(),
                backends.vpn,
                backends.extensions,
                backends.login,
                backends.signals,
                serve::ops::OpsDeps {
                    keychain: backends.keychain,
                    forticlient: backends.forticlient,
                    launchctl: backends.launchctl,
                    spawner: &spawner,
                    updates: &updates,
                    opener: &serve::ops_system::SystemOpener,
                    pause: &std::thread::sleep,
                },
            );
            if text.is_empty() {
                code
            } else {
                finish(io, &text, code)
            }
        }
        Command::HostRestart => {
            if backends.launchctl.kickstart(agent::HOST_LABEL) {
                finish(io, "OFTC host restarted", 0)
            } else {
                finish(
                    io,
                    "Could not restart OFTC host; is its service registered?",
                    1,
                )
            }
        }
        Command::HostRegister => {
            // The UI's way to bring the service up on a Mac where nothing registered it yet:
            // the same policy as `register-agent`, then a start. Exit 4 means macOS wants the
            // user to allow it in Login Items; the UI says so instead of retrying.
            match agent::register_host(backends.login, backends.launchctl) {
                Ok(()) if backends.launchctl.kickstart(agent::HOST_LABEL) => {
                    finish(io, "OFTC host service registered", 0)
                }
                Ok(()) => finish(
                    io,
                    "OFTC host service registered, but it did not start",
                    1,
                ),
                Err(e) => {
                    let approval = agent::host_status(backends.login) == "requires-approval";
                    finish(
                        io,
                        &format!("Could not register OFTC host service: {e}"),
                        if approval { 4 } else { 1 },
                    )
                }
            }
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
        Command::Stop => vpn_verb(vpn::stop(&ctx), io),
        Command::SetAutostart { enabled } => set_autostart(io, env, backends, &selected, enabled),
        Command::SuperviseAutostart => supervise_autostart(io, env, backends),
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
        Command::SuperviseLive {
            gateway,
            port,
            mode,
            insecure,
        } => vpn_verb(
            vpn::supervise_live(&ctx, &gateway, port, mode, insecure),
            io,
        ),
        // An agent property list from before multi-profile support runs this verb
        // with no profile; it now means "start the autostart set".
        Command::SuperviseProfile { .. } if env.bundled_agent() && selected.is_none() => {
            supervise_autostart(io, env, backends)
        }
        Command::SuperviseProfile { flags } => {
            if let Err(message) = agent::redirect_output(env) {
                return finish(io, &message, 1);
            }
            vpn_verb(vpn::supervise_profile(&ctx, &flags), io)
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
            match save_psk(backends.keychain, &gateway, &psk) {
                Ok(()) => finish(io, "OFTC PSK stored in Keychain", 0),
                Err(failure) => failure_line(io, failure),
            }
        }
        Command::ExportProfiles { ids } => export_profiles(io, backends, root, &ids),
        Command::ImportProfiles => import_profiles(io, backends, root),
        Command::ImportProfile { forticlient_name } => {
            import_profile(io, backends, root, selected.as_deref(), &forticlient_name)
        }
        Command::MigratePsk {
            forticlient_name,
            gateway,
        } => match backends.forticlient.psk(&forticlient_name, &gateway) {
            None => finish(
                io,
                "Could not obtain plaintext PSK for that profile and gateway",
                1,
            ),
            Some(psk) => match save_psk(backends.keychain, &gateway, &psk) {
                Ok(()) => finish(
                    io,
                    "Existing local profile PSK migrated into OFTC Keychain",
                    0,
                ),
                Err(failure) => failure_line(io, failure),
            },
        },
        Command::SaveProfile { profile } => {
            match save_profile(root, &profile, selected.as_deref()) {
                Ok(entry) => finish(io, &format!("OFTC profile saved: id={}", entry.id), 0),
                Err(failure) => failure_line(io, failure),
            }
        }
    }
}

fn failure_line(io: &mut Io, failure: Failure) -> i32 {
    let (text, code) = failure.outcome();
    finish(io, &text, code)
}

/// Stores `psk` as the Keychain item of `gateway`.
pub(crate) fn save_psk(keychain: &dyn Keychain, gateway: &str, psk: &[u8]) -> Result<(), Failure> {
    keychain
        .set(gateway, psk)
        .map_err(|_| Failure::internal("Could not save OFTC Keychain PSK"))
}

/// Creates a profile (under `requested`, or an id derived from its name). A gateway
/// that already has a profile is refused with that profile's id.
pub(crate) fn save_profile(
    root: &std::path::Path,
    profile: &Profile,
    requested: Option<&str>,
) -> Result<ProfileEntry, Failure> {
    if let Some(existing) = registry::entries(root)
        .iter()
        .find(|entry| entry.profile.gateway == profile.gateway)
    {
        return Err(Failure::new(
            ErrorCode::AlreadyConfigured,
            &format!("OFTC already has a profile for {}", profile.gateway),
        )
        .for_profile(&existing.id));
    }
    registry::add(root, profile, requested).map_err(|_| {
        Failure::internal("Could not save OFTC profile (a profile with that id may already exist)")
    })
}

/// `set-autostart on|off`: the selected profile's connect-at-login choice. Stopping
/// a tunnel leaves it alone; it is a separate per-profile setting.
fn set_autostart(
    io: &mut Io,
    env: &HostEnv,
    backends: &Backends,
    selected: &Option<String>,
    enabled: bool,
) -> i32 {
    let entry = match require_entry(selected, env.root()) {
        Ok(entry) => entry,
        Err(message) => return finish(io, &message, 1),
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(backends.clock.unix_secs());
    match change_autostart(
        backends.login,
        backends.launchctl,
        env.root(),
        &entry,
        enabled,
        now,
    ) {
        Ok(()) => finish(
            io,
            &format!(
                "Connect at login for {}: {}",
                entry.id,
                if enabled { "on" } else { "off" }
            ),
            0,
        ),
        Err(failure) => failure_line(io, failure),
    }
}

/// Sets `entry`'s connect-at-login choice. A refused registration is typed from the
/// agent's state afterwards: approval pending, or the agent not found.
pub(crate) fn change_autostart(
    login: &dyn LoginItems,
    launchctl: &dyn Launchctl,
    root: &std::path::Path,
    entry: &ProfileEntry,
    enabled: bool,
    now: SystemTime,
) -> Result<(), Failure> {
    let adopted = entry.profile.adopts_unkeyed_vpn_entry == Some(true);
    agent::set_connect_at_login(
        login,
        launchctl,
        &registry::entry_directory(root, &entry.id),
        adopted,
        enabled,
        now,
    )
    .map_err(|error| {
        let code = match agent::status(login) {
            "requires-approval" => ErrorCode::ApprovalRequired,
            "not-found" => ErrorCode::AgentUnavailable,
            _ => ErrorCode::Internal,
        };
        Failure::new(
            code,
            &format!("Could not change automatic connection: {error}"),
        )
    })
}

/// `supervise-autostart`, run by the login agent: one supervisor process per
/// profile whose connect-at-login choice (or one-use request) says to connect. They
/// serialise their own SAML sign-ins, so they can all start at once.
fn supervise_autostart(io: &mut Io, env: &HostEnv, backends: &Backends) -> i32 {
    if let Err(message) = agent::redirect_output(env) {
        return finish(io, &message, 1);
    }
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(backends.clock.unix_secs());
    let mut children = Vec::new();
    for entry in registry::entries(env.root()) {
        let directory = registry::entry_directory(env.root(), &entry.id);
        let adopted = entry.profile.adopts_unkeyed_vpn_entry == Some(true);
        if !intent::should_start(&directory, now, adopted) {
            continue;
        }
        let Some(exe) = env.exe() else { continue };
        let log = agent::open_log(&env.logs_dir().join(format!("{}.log", entry.id))).ok();
        match agent::spawn_supervisor(exe, &entry.id, log) {
            Ok(child) => children.push(child),
            Err(_) => io
                .out
                .line(&format!("Could not start supervisor for {}", entry.id)),
        }
    }
    if children.is_empty() {
        return finish(
            io,
            "OFTC automatic VPN connection is disabled for every profile",
            0,
        );
    }
    for mut child in children {
        let _ = child.wait();
    }
    finish(io, "OFTC supervisors exited", 0)
}

fn has_gateway(root: &std::path::Path, gateway: &str) -> bool {
    registry::entries(root)
        .iter()
        .any(|entry| entry.profile.gateway == gateway)
}

/// The `.oftc` bundle of the profiles with `ids` (all when none), each with its PSK
/// from the Keychain. Nothing is produced unless every profile has its PSK.
pub(crate) fn export_bundle(
    root: &std::path::Path,
    keychain: &dyn Keychain,
    ids: &[String],
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let all = registry::entries(root);
    let chosen: Vec<&ProfileEntry> = if ids.is_empty() {
        all.iter().collect()
    } else {
        let mut chosen = Vec::new();
        for id in ids {
            match all.iter().find(|entry| &entry.id == id) {
                Some(entry) => chosen.push(entry),
                None => {
                    return Err(Failure::new(
                        ErrorCode::NotConfigured,
                        &format!("OFTC profile unavailable: no profile named {id}"),
                    ))
                }
            }
        }
        chosen
    };
    if chosen.is_empty() {
        return Err(Failure::new(
            ErrorCode::NotConfigured,
            "No OFTC profiles to export",
        ));
    }
    let mut items = Vec::with_capacity(chosen.len());
    for entry in chosen {
        let p = &entry.profile;
        let psk = keychain
            .get(&p.gateway)
            .ok()
            .and_then(|psk| String::from_utf8(psk.to_vec()).ok());
        let Some(psk) = psk else {
            return Err(Failure::new(
                ErrorCode::PskUnavailable,
                &format!("PSK unavailable for {}; nothing exported", entry.name()),
            ));
        };
        items.push(bundle::Item {
            gateway: p.gateway.clone(),
            name: entry.name().to_owned(),
            psk: Zeroizing::new(psk),
            saml_port: p.saml_port,
            transport: p.transport,
        });
    }
    bundle::encode(items).ok_or_else(|| Failure::internal("Could not write the profile file"))
}

/// `export-profiles`: [`export_bundle`] to standard output.
fn export_profiles(
    io: &mut Io,
    backends: &Backends,
    root: &std::path::Path,
    ids: &[String],
) -> i32 {
    match export_bundle(root, backends.keychain, ids) {
        Ok(data) => {
            io.out.bytes(&data);
            0
        }
        Err(failure) => failure_line(io, failure),
    }
}

/// A `.oftc` file's bytes (at most [`bundle::MAX_BYTES`] of them) as profiles.
pub(crate) fn decode_bundle(data: &[u8]) -> Result<Vec<bundle::Incoming>, Failure> {
    bundle::decode(data).map_err(|error| Failure::new(ErrorCode::InvalidFile, &error.message()))
}

/// What importing one profile of a bundle did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Imported {
    Added { name: String, id: String },
    /// The gateway already has a profile; it and its PSK are left alone.
    Skipped { name: String },
}

impl Imported {
    fn line(&self) -> String {
        match self {
            Imported::Added { name, id } => format!("Imported {name}: id={id}"),
            Imported::Skipped { name } => format!("Skipped {name}: already configured"),
        }
    }
}

/// The profiles imported before a failure, and the failure if there was one.
pub(crate) struct ImportReport {
    pub done: Vec<Imported>,
    pub failure: Option<Failure>,
}

/// Imports `incoming`. A gateway that already has a profile is skipped, so importing
/// never changes an existing profile or its PSK.
pub(crate) fn import_bundle(
    root: &std::path::Path,
    keychain: &dyn Keychain,
    incoming: Vec<bundle::Incoming>,
) -> ImportReport {
    let mut done = Vec::new();
    for item in incoming {
        let name = item.profile.display_name().to_owned();
        if has_gateway(root, &item.profile.gateway) {
            done.push(Imported::Skipped { name });
            continue;
        }
        if let Err(failure) = save_psk(keychain, &item.profile.gateway, &item.psk) {
            return ImportReport {
                done,
                failure: Some(failure),
            };
        }
        match registry::add(root, &item.profile, None) {
            Ok(entry) => done.push(Imported::Added { name, id: entry.id }),
            Err(_) => {
                return ImportReport {
                    done,
                    failure: Some(Failure::internal(&format!(
                        "Could not save the profile \"{name}\""
                    ))),
                }
            }
        }
    }
    ImportReport {
        done,
        failure: None,
    }
}

/// Reads a bundle from standard input and imports it.
fn import_profiles(io: &mut Io, backends: &Backends, root: &std::path::Path) -> i32 {
    let mut input = Zeroizing::new(Vec::new());
    // A read error is an empty (so unreadable) file, as before.
    let _ = io
        .stdin
        .take(bundle::MAX_BYTES as u64 + 1)
        .read_to_end(&mut input);
    let incoming = match decode_bundle(&input) {
        Ok(incoming) => incoming,
        Err(failure) => return failure_line(io, failure),
    };
    let report = import_bundle(root, backends.keychain, incoming);
    let mut lines: Vec<String> = report.done.iter().map(Imported::line).collect();
    match report.failure {
        None => finish(io, &lines.join("\n"), 0),
        Some(failure) => {
            lines.push(failure.text);
            finish(io, &lines.join("\n"), failure.exit)
        }
    }
}

/// Creates a profile from an installed FortiClient profile and stores its PSK.
/// Everything that would refuse the profile is checked before the Keychain is
/// written, so a refused import leaves an existing PSK alone.
fn import_profile(
    io: &mut Io,
    backends: &Backends,
    root: &std::path::Path,
    requested_id: Option<&str>,
    forticlient_name: &str,
) -> i32 {
    let Some(imported) = backends.forticlient.import(forticlient_name) else {
        return finish(io, "Could not import FortiClient profile", 1);
    };
    let Ok(profile) = Profile::new(
        &imported.gateway,
        imported.saml_port,
        Transport::Udp,
        Some(forticlient_name),
        None,
    ) else {
        return finish(io, "Imported profile has invalid connection settings", 1);
    };
    let refused = "Could not save OFTC profile (a profile with that id may already exist)";
    if has_gateway(root, &profile.gateway) {
        let message = format!("OFTC already has a profile for {}", profile.gateway);
        return finish(io, &message, 1);
    }
    if requested_id.is_some_and(|id| registry::entries(root).iter().any(|e| e.id == id)) {
        return finish(io, refused, 1);
    }
    if let Err(failure) = save_psk(backends.keychain, &profile.gateway, &imported.psk) {
        return failure_line(io, failure);
    }
    match registry::add(root, &profile, requested_id) {
        Ok(entry) => {
            let message = format!(
                "FortiClient profile imported into OFTC configuration and Keychain: id={}",
                entry.id
            );
            finish(io, &message, 0)
        }
        Err(_) => finish(io, refused, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{agent_item, RecordingLaunchctl};
    use crate::keychain::MemoryKeychain;
    use crate::out::Capture;
    use crate::profile::testutil::{fixture, TempDir};
    use crate::supervisor::ManualSignals;
    use oftc_apple::error::AppleError;
    use oftc_apple::login::MockLoginItems;
    use oftc_apple::manager::{MockEntry, MockVpn, StartKind, VpnStatus};
    use oftc_apple::sysext::{ExtensionVersion, MockExtensions};
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
            (vec!["activate"], invocation(None, Command::Activate)),
            (vec!["activate", "x"], Err(ParseError::Usage)),
            (
                vec!["--profile", "lab", "unregister-menu-login"],
                invocation(Some("lab"), Command::UnregisterMenuLogin),
            ),
            (
                vec!["supervise-profile"],
                invocation(None, Command::SuperviseProfile { flags: vec![] }),
            ),
            // The hidden service verbs take exactly one subverb.
            (vec!["host", "serve"], invocation(None, Command::HostServe)),
            (
                vec!["--profile", "lab", "host", "restart"],
                invocation(Some("lab"), Command::HostRestart),
            ),
            (
                vec!["host", "register"],
                invocation(None, Command::HostRegister),
            ),
            (vec!["host"], Err(ParseError::Usage)),
            (vec!["host", "serve", "x"], Err(ParseError::Usage)),
            (vec!["host", "stop"], Err(ParseError::Usage)),
            (vec!["stop"], invocation(None, Command::Stop)),
            (vec!["stop", "x"], Err(ParseError::Usage)),
            (
                vec!["--profile", "lab", "set-autostart", "on"],
                invocation(Some("lab"), Command::SetAutostart { enabled: true }),
            ),
            (
                vec!["set-autostart", "off"],
                invocation(None, Command::SetAutostart { enabled: false }),
            ),
            (vec!["set-autostart"], Err(ParseError::Usage)),
            (vec!["set-autostart", "yes"], Err(ParseError::Usage)),
            (vec!["set-autostart", "on", "x"], Err(ParseError::Usage)),
            (
                vec!["supervise-autostart"],
                invocation(None, Command::SuperviseAutostart),
            ),
            (vec!["supervise-autostart", "x"], Err(ParseError::Usage)),
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
            // The bundle verbs: export takes any ids, the others a fixed arity.
            (
                vec!["export-profiles"],
                invocation(None, Command::ExportProfiles { ids: vec![] }),
            ),
            (
                vec!["export-profiles", "a", "b"],
                invocation(
                    None,
                    Command::ExportProfiles {
                        ids: vec!["a".into(), "b".into()],
                    },
                ),
            ),
            (
                vec!["import-profiles"],
                invocation(None, Command::ImportProfiles),
            ),
            (vec!["import-profiles", "x"], Err(ParseError::Usage)),
            (
                vec!["import-profile", "Example Office"],
                invocation(
                    None,
                    Command::ImportProfile {
                        forticlient_name: "Example Office".into(),
                    },
                ),
            ),
            (vec!["import-profile"], Err(ParseError::Usage)),
            (vec!["import-profile", "a", "b"], Err(ParseError::Usage)),
            (
                vec!["migrate-psk", "Example Office", "vpn.example.com"],
                invocation(
                    None,
                    Command::MigratePsk {
                        forticlient_name: "Example Office".into(),
                        gateway: "vpn.example.com".into(),
                    },
                ),
            ),
            (
                vec!["migrate-psk", "Example Office"],
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

    /// `Host/main.swift` keeps only the verbs that need AppKit, bookmarks or URLSession;
    /// everything else must reach this crate. The two lists may not drift, or a verb
    /// would fall through to Rust's usage text (or never reach it).
    #[test]
    fn swift_stub_agrees_with_the_verb_table() {
        let swift = include_str!("../../../Host/main.swift");
        let mut stub: Vec<&str> = swift
            .lines()
            .filter_map(|line| line.strip_prefix("case (\""))
            .filter_map(|rest| rest.split('"').next())
            .filter(|verb| !verb.is_empty())
            .collect();
        // Not in the usage text: the menu's own entry points.
        let mut table: Vec<&str> = VERBS
            .iter()
            .filter(|verb| !verb.rust)
            .map(Verb::name)
            .chain([
                "--after-install",
                "preview-menu",
                "render-menu-previews",
                "review-certificate",
                "quit-menu",
            ])
            .collect();
        stub.sort_unstable();
        table.sort_unstable();
        assert_eq!(stub, table);
        // Every verb the Rust side claims has a parser arm.
        for verb in rust_verbs() {
            assert_ne!(parse(&strings(&[verb])), Err(ParseError::ProfileFlag));
            let args = strings(&[verb, "a", "b", "c", "d"]);
            let known = matches!(
                verb,
                "save-profile" | "start-profile" | "supervise-profile" | "export-profiles"
            ) || parse(&args) == Err(ParseError::Usage);
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
            _cancelled: &dyn Fn() -> bool,
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

    /// One installed FortiClient profile, "Example Office", and one with an unusable
    /// gateway.
    struct Installed;

    impl FortiClientProfiles for Installed {
        fn import(&self, name: &str) -> Option<FortiClientProfile> {
            let (gateway, saml_port) = match name {
                "Example Office" => ("vpn.example.com", 9443),
                "Odd Gateway" => ("bad host", 9443),
                _ => return None,
            };
            Some(FortiClientProfile {
                gateway: gateway.to_owned(),
                saml_port,
                psk: Zeroizing::new(b"forti-secret".to_vec()),
            })
        }

        fn psk(&self, name: &str, gateway: &str) -> Option<Zeroizing<Vec<u8>>> {
            let found = self.import(name)?;
            (found.gateway == gateway).then_some(found.psk)
        }
    }

    /// A Keychain that refuses to write one gateway's PSK, when told to.
    #[derive(Default)]
    struct Flaky {
        inner: MemoryKeychain,
        deny: std::sync::Mutex<Option<String>>,
    }

    impl Keychain for Flaky {
        fn get(&self, gateway: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
            self.inner.get(gateway)
        }
        fn set(&self, gateway: &str, psk: &[u8]) -> Result<(), KeychainError> {
            if self.deny.lock().unwrap().as_deref() == Some(gateway) {
                return Err(KeychainError::Failed);
            }
            self.inner.set(gateway, psk)
        }
        fn delete(&self, gateway: &str) -> Result<(), KeychainError> {
            self.inner.delete(gateway)
        }
    }

    struct Harness {
        dir: TempDir,
        env: HostEnv,
        keychain: Flaky,
        prompt: Scripted,
        extensions: MockExtensions,
        login: MockLoginItems,
        launchctl: RecordingLaunchctl,
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
                keychain: Flaky::default(),
                prompt: Scripted(RefCell::new(None)),
                extensions: MockExtensions::new(),
                login: MockLoginItems::new(),
                launchctl: RecordingLaunchctl::new(true),
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
                forticlient: &Installed,
                legacy_name: &|gateway| {
                    (gateway == "vpn.example.com").then(|| "Example Office".to_owned())
                },
                extensions: &self.extensions,
                login: &self.login,
                launchctl: &self.launchctl,
                vpn: &self.vpn,
                acquirer: &self.acquirer,
                clock: &*self.clock,
                session_id: &unique_session_id,
                signals: &ManualSignals::default(),
                review: &|_, _, _| Trust::NotACertificateProblem,
                diagnostic: &|_| {},
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

    /// The usage text is a protocol too (`oftc` and the install scripts print it): the
    /// hidden verbs (`login-settings`, `unregister-menu-login`, `host serve`,
    /// `host restart`, `host register`) must never appear in it, and nothing else may change.
    #[test]
    fn usage_text_is_pinned() {
        assert_eq!(
            usage(),
            "Usage: OFTCAgent [--profile <id>] activate|deactivate|agent-status|register-agent|unregister-agent|install-config|list-profiles|check-update [url]|launcher-alias ensure|remove|export-profiles [id...]|import-profiles|save-profile <gateway> <saml-port> [--tcp] [--name <name>]|import-profile <FortiClient-profile>|show-profile|erase-profile|has-psk|set-autostart on|off|supervise-autostart|start-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-profile [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|provision-psk [--stdin] [gateway]|migrate-psk <FortiClient-profile> <gateway>|preflight <gateway> <32-hex-UID>|start-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|supervise-live <gateway> <saml-port> [--tcp] [--ipv6-outer <CLAT-IPv4>] [--insecure-saml]|rekey-once|rekey-ike-once|rekey-counts|status|stop|remove-config"
        );
        for hidden in VERBS.iter().filter(|verb| verb.hidden) {
            assert!(!usage().contains(hidden.synopsis), "{}", hidden.synopsis);
        }
        // `host` is claimed by Rust, so the Swift stub hands it over.
        assert!(rust_verbs().any(|verb| verb == "host"));
    }

    /// `host restart` kickstarts the host service's launchd label, and says so when
    /// launchd refuses (the service is not registered).
    #[test]
    fn host_restart_kickstarts_the_service() {
        let mut h = Harness::new();
        h.expect(&["host", "restart"], "OFTC host restarted\n", 0);
        assert_eq!(h.launchctl.kicked(), [crate::agent::HOST_LABEL]);
        h.launchctl = RecordingLaunchctl::new(false);
        h.expect(
            &["host", "restart"],
            "Could not restart OFTC host; is its service registered?\n",
            1,
        );
    }

    /// `host register` registers the service, then starts it; a pending approval is exit 4 so
    /// the UI can say what to allow rather than retry.
    #[test]
    fn host_register_registers_and_starts_the_service() {
        let h = Harness::new();
        let host = crate::agent::host_item();
        h.login.set_status(&host, LoginStatus::NotRegistered);
        h.expect(&["host", "register"], "OFTC host service registered\n", 0);
        assert_eq!(h.launchctl.calls(), [crate::agent::HOST_LABEL]);
        assert_eq!(h.launchctl.kicked(), [crate::agent::HOST_LABEL]);
        h.login.set_status(&host, LoginStatus::RequiresApproval);
        h.expect(
            &["host", "register"],
            "Could not register OFTC host service: OFTC host service is requires-approval\n",
            4,
        );
        h.login.set_status(&host, LoginStatus::Unknown);
        h.expect(
            &["host", "register"],
            "Could not register OFTC host service: OFTC host service is unknown\n",
            1,
        );
        // Registered and enabled, but launchd would not start it.
        let mut h = Harness::new();
        h.launchctl = RecordingLaunchctl::failing_kickstart();
        h.login.set_status(&host, LoginStatus::NotRegistered);
        h.expect(
            &["host", "register"],
            "OFTC host service registered, but it did not start\n",
            1,
        );
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
        // A supervisor needs one profile before anything else.
        h.expect(
            &["supervise-profile"],
            "Several OFTC profiles are configured; choose one with --profile <id> (example-office, lab)\n",
            1,
        );
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
            &["supervise-live", "vpn.example.com"],
            &["supervise-live", "vpn.example.com", "65536"],
            &["supervise-live", "vpn.example.com", "9443", "--bogus"],
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
        for uid in ["nope", &format!("{UID}A"), &UID.replace('A', "G")] {
            h.expect(
                &["preflight", "vpn.example.com", uid],
                "Expected a 32-character hexadecimal UID\n",
                2,
            );
        }
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

        // The provider comes up on the first poll; its early replies are empty or
        // lost, so the loop asks again rather than giving up.
        let hook = entry2.clone();
        *h.clock.on_sleep.borrow_mut() = Some(Box::new(move || {
            if hook.sent().is_empty() {
                hook.set_status(VpnStatus::Connected);
                // No stage yet (the provider's nil reply), then a lost reply.
                hook.push_reply(Ok(Vec::new()));
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
        assert_eq!(entry2.sent().len(), 3);
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
        drop(calls);
        // An explicit --tcp on a TCP profile is not doubled into a usage error.
        h.expect(
            &["start-profile", "--tcp"],
            "Live start requested; inspect status before any fresh-token retry\n",
            0,
        );
        // A UDP profile gets the UDP default (with its TCP fallback).
        h.run(
            &[
                "--profile",
                "udp",
                "save-profile",
                "udp.example.com",
                "9443",
            ],
            "",
        );
        h.keychain.set("udp.example.com", b"udppsk").unwrap();
        let udp = h.vpn.add_entry(PROVIDER, Some("udp"), true);
        h.expect(
            &["--profile", "udp", "start-profile"],
            "Live start requested; inspect status before any fresh-token retry\n",
            0,
        );
        assert_eq!(
            udp.started()[0].2.as_deref(),
            Some(&[1, 1, 4, 1, 0, 0, 0, 0][..])
        );
        // The profile's TCP transport applies without --tcp on the command line.
        assert_eq!(
            entry.started()[0].2.as_deref(),
            Some(&[1, 2, 4, 0, 0, 0, 0, 0][..])
        );
    }

    /// `export-profiles` and `import-profiles`: the bundle on stdout and stdin.
    #[test]
    fn bundle_verbs() {
        let h = Harness::new();
        h.expect(&["export-profiles"], "No OFTC profiles to export\n", 1);
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
        h.run(&["save-profile", "lab.example.com", "8443", "--tcp"], "");
        h.expect(
            &["export-profiles", "nope"],
            "OFTC profile unavailable: no profile named nope\n",
            1,
        );
        // A profile without a PSK stops the export before anything is written (the
        // gateway names a profile that has no name).
        h.keychain.set("vpn.example.com", b"office-psk").unwrap();
        h.expect(
            &["export-profiles"],
            "PSK unavailable for lab.example.com; nothing exported\n",
            1,
        );
        h.keychain.set("lab.example.com", b"lab-psk").unwrap();
        let (exported, code) = h.run(&["export-profiles"], "");
        assert_eq!(code, 0);
        // Listing order (by name), the gateway standing in for a missing name.
        assert!(
            exported.starts_with("{\n  \"format\" : \"oftc-profiles\""),
            "{exported}"
        );
        assert!(exported.ends_with("  \"version\" : 1\n}\n"));
        assert!(
            exported.find("Example Office").unwrap()
                < exported
                    .find("lab.example.com\",\n      \"name\" : \"lab.example.com")
                    .unwrap()
        );
        // Only the named ids, in the order given.
        let (lab_only, _) = h.run(&["export-profiles", "lab-example-com"], "");
        assert!(!lab_only.contains("Example Office") && lab_only.contains("lab-psk"));

        // Importing it elsewhere recreates both profiles and both PSKs.
        let other = Harness::new();
        let expected = "Imported Example Office: id=example-office\nImported lab.example.com: id=lab-example-com\n";
        assert_eq!(
            other.run(&["import-profiles"], &exported),
            (expected.to_owned(), 0)
        );
        assert_eq!(
            other.keychain.get("lab.example.com").unwrap().as_slice(),
            b"lab-psk"
        );
        other.expect(
            &["list-profiles"],
            "example-office\tExample Office\tvpn.example.com\t9443\tudp\nlab-example-com\tlab.example.com\tlab.example.com\t8443\ttcp\n",
            0,
        );
        // Importing again skips what exists and leaves its PSK alone.
        other.keychain.set("lab.example.com", b"changed").unwrap();
        assert_eq!(
            other.run(&["import-profiles"], &exported),
            (
                "Skipped Example Office: already configured\nSkipped lab.example.com: already configured\n".to_owned(),
                0
            )
        );
        assert_eq!(
            other.keychain.get("lab.example.com").unwrap().as_slice(),
            b"changed"
        );
    }

    #[test]
    fn import_profiles_failures() {
        let h = Harness::new();
        let item = |gateway: &str| {
            format!(
                r#"{{"name":"P {gateway}","gateway":"{gateway}","samlPort":9443,"transport":"udp","psk":"s"}}"#
            )
        };
        let bundle = |items: &[String]| {
            format!(
                r#"{{"format":"oftc-profiles","version":1,"profiles":[{}]}}"#,
                items.join(",")
            )
        };
        // The bundle's own failure messages, and nothing stored.
        h.expect(
            &["import-profiles"],
            "That file isn't an OFTC profile file\n",
            1,
        );
        let invalid = bundle(&[item("a.example.com"), item("bad host")]);
        assert_eq!(
            h.run(&["import-profiles"], &invalid),
            (
                "The profile \"P bad host\" in that file has invalid settings\n".to_owned(),
                1
            )
        );
        h.expect(&["list-profiles"], "\n", 0);
        // The same gateway twice in one bundle imports once.
        let twice = bundle(&[item("a.example.com"), item("a.example.com")]);
        assert_eq!(
            h.run(&["import-profiles"], &twice),
            ("Imported P a.example.com: id=p-a-example-com\nSkipped P a.example.com: already configured\n".to_owned(), 0)
        );
        // A Keychain failure stops the import, after reporting what was imported.
        let three = bundle(&[
            item("b.example.com"),
            item("c.example.com"),
            item("d.example.com"),
        ]);
        *h.keychain.deny.lock().unwrap() = Some("c.example.com".to_owned());
        assert_eq!(
            h.run(&["import-profiles"], &three),
            (
                "Imported P b.example.com: id=p-b-example-com\nCould not save OFTC Keychain PSK\n"
                    .to_owned(),
                1
            )
        );
        // import-profile stops at a Keychain failure too, creating no profile.
        *h.keychain.deny.lock().unwrap() = Some("vpn.example.com".to_owned());
        h.expect(
            &["import-profile", "Example Office"],
            "Could not save OFTC Keychain PSK\n",
            1,
        );
        assert!(!h.run(&["list-profiles"], "").0.contains("vpn.example.com"));
        // Input past 64 KiB is refused whatever it holds (the read stops one byte over).
        let big = " ".repeat(bundle::MAX_BYTES + 100);
        assert_eq!(
            h.run(&["import-profiles"], &big),
            ("That profile file is too large\n".to_owned(), 1)
        );
    }

    /// `import-profile` and `migrate-psk`: the FortiClient side is a double.
    #[test]
    fn forticlient_verbs() {
        let h = Harness::new();
        h.expect(
            &["import-profile", "Missing"],
            "Could not import FortiClient profile\n",
            1,
        );
        h.expect(
            &["import-profile", "Odd Gateway"],
            "Imported profile has invalid connection settings\n",
            1,
        );
        assert!(h.keychain.get("bad host").is_err());
        h.expect(
            &["import-profile", "Example Office"],
            "FortiClient profile imported into OFTC configuration and Keychain: id=example-office\n",
            0,
        );
        assert_eq!(
            h.keychain.get("vpn.example.com").unwrap().as_slice(),
            b"forti-secret"
        );
        // A gateway that already has a profile is refused before the Keychain is
        // touched, so its PSK survives (Swift overwrote it, then refused).
        h.keychain.set("vpn.example.com", b"kept").unwrap();
        h.expect(
            &["import-profile", "Example Office"],
            "OFTC already has a profile for vpn.example.com\n",
            1,
        );
        assert_eq!(
            h.keychain.get("vpn.example.com").unwrap().as_slice(),
            b"kept"
        );
        // `--profile` names the new profile's id; a taken id is refused the same way.
        let two = Harness::new();
        two.run(
            &[
                "--profile",
                "lab",
                "save-profile",
                "lab.example.com",
                "8443",
            ],
            "",
        );
        two.keychain.set("vpn.example.com", b"kept").unwrap();
        two.expect(
            &["--profile", "lab", "import-profile", "Example Office"],
            "Could not save OFTC profile (a profile with that id may already exist)\n",
            1,
        );
        assert_eq!(
            two.keychain.get("vpn.example.com").unwrap().as_slice(),
            b"kept"
        );
        two.expect(
            &["--profile", "office", "import-profile", "Example Office"],
            "FortiClient profile imported into OFTC configuration and Keychain: id=office\n",
            0,
        );

        // migrate-psk stores the PSK only for the gateway the profile names.
        let m = Harness::new();
        m.expect(
            &["migrate-psk", "Example Office", "other.example.com"],
            "Could not obtain plaintext PSK for that profile and gateway\n",
            1,
        );
        assert!(m.keychain.get("other.example.com").is_err());
        m.expect(
            &["migrate-psk", "Example Office", "vpn.example.com"],
            "Existing local profile PSK migrated into OFTC Keychain\n",
            0,
        );
        assert_eq!(
            m.keychain.get("vpn.example.com").unwrap().as_slice(),
            b"forti-secret"
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
        // A menu item waiting for approval is not enabled.
        h.login
            .set_status(&LoginItem::MainApp, LoginStatus::RequiresApproval);
        h.expect(
            &["login-settings"],
            "Menu launch at login: disabled\n\
             VPN connect at login (example-office): enabled\n\
             VPN connect at login (lab): disabled\n",
            0,
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
        // With no stored preference the adopting profile inherits the agent, and
        // only while the agent is enabled.
        std::fs::remove_file(
            registry::entry_directory(root, "example-office").join("connection-preferences.json"),
        )
        .unwrap();
        h.expect(
            &["login-settings"],
            "Menu launch at login: enabled\n\
             VPN connect at login (example-office): enabled\n\
             VPN connect at login (lab): disabled\n",
            0,
        );
        h.login
            .set_status(&agent_item(), LoginStatus::RequiresApproval);
        h.expect(
            &["login-settings"],
            "Menu launch at login: enabled\n\
             VPN connect at login (example-office): disabled\n\
             VPN connect at login (lab): disabled\n",
            0,
        );
    }

    /// A profile named `Example Office` and one named `Lab`, saved through the verb.
    fn two_profiles(h: &Harness) {
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
        h.run(
            &["save-profile", "lab.example.com", "8443", "--name", "Lab"],
            "",
        );
    }

    #[test]
    fn stop_signals_the_supervisor_before_stopping_the_tunnel() {
        let h = Harness::new();
        h.expect(&["stop"], "OFTC profile unavailable; run oftc setup\n", 1);
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
        // No entry: nothing to stop, and with no supervisor the request still succeeds.
        h.expect(&["stop"], "OFTC configuration absent\n", 0);
        let directory = registry::entry_directory(h.env.root(), "example-office");
        let entry = h.vpn.add_entry(PROVIDER, Some("example-office"), true);
        // A supervisor's lock names the lease the request is addressed to.
        let lease = crate::lease::SupervisorLease::acquire(&directory).unwrap();
        h.expect(&["stop"], "Stop requested\n", 0);
        assert_eq!(entry.stops(), 1);
        assert!(lease.stop_requested());
        // A lock that is not a lease id cannot be answered: the VPN is left running.
        drop(lease);
        std::fs::write(directory.join("supervisor.lock"), "broken").unwrap();
        h.expect(
            &["stop"],
            "Could not signal OFTC supervisor; VPN left running\n",
            1,
        );
        assert_eq!(entry.stops(), 1);
        // Other profiles' entries are not stopped.
        std::fs::remove_file(directory.join("supervisor.lock")).unwrap();
        let other = h.vpn.add_entry(PROVIDER, Some("lab"), true);
        h.expect(&["stop"], "Stop requested\n", 0);
        assert_eq!((entry.stops(), other.stops()), (2, 0));
    }

    #[test]
    fn set_autostart_registers_without_signing_in_and_undoes_a_failed_registration() {
        let h = Harness::new();
        h.expect(
            &["set-autostart", "on"],
            "OFTC profile unavailable; run oftc setup\n",
            1,
        );
        two_profiles(&h);
        h.expect(
            &["set-autostart", "on"],
            "Several OFTC profiles are configured; choose one with --profile <id> (example-office, lab)\n",
            1,
        );
        let lab = registry::entry_directory(h.env.root(), "lab");
        let prefs = || std::fs::read_to_string(lab.join("connection-preferences.json")).ok();
        let request = || lab.join("agent-request.json");
        let agent = agent_item();

        // Off needs no agent.
        h.expect(
            &["--profile", "lab", "set-autostart", "off"],
            "Connect at login for lab: off\n",
            0,
        );
        assert_eq!(prefs().as_deref(), Some(r#"{"connectAtLogin":false}"#));
        assert!(h.login.calls().is_empty());

        // On, agent not yet enabled: registered, with a request that keeps this
        // registration from opening a sign-in.
        h.expect(
            &["--profile", "lab", "set-autostart", "on"],
            "Connect at login for lab: on\n",
            0,
        );
        assert_eq!(prefs().as_deref(), Some(r#"{"connectAtLogin":true}"#));
        assert!(request().exists());
        assert_eq!(h.login.calls(), [("register", agent.clone())]);
        assert_eq!(h.launchctl.calls(), [crate::agent::AGENT_LABEL]);

        // On again, agent enabled: only the launchd override is cleared.
        std::fs::remove_file(request()).unwrap();
        h.expect(
            &["--profile", "lab", "set-autostart", "on"],
            "Connect at login for lab: on\n",
            0,
        );
        assert!(!request().exists());
        assert_eq!(h.login.calls().len(), 1);
        assert_eq!(h.launchctl.calls().len(), 2);

        // Registration refused: the request and the previous choice are put back.
        h.login.set_status(&agent, LoginStatus::NotRegistered);
        h.login
            .script_register(&agent, Err(AppleError::from_nserror("d", 1, "denied")));
        h.expect(
            &["--profile", "lab", "set-autostart", "on"],
            "Could not change automatic connection: denied\n",
            1,
        );
        assert_eq!(prefs().as_deref(), Some(r#"{"connectAtLogin":true}"#)); // was on
        assert!(!request().exists());
        h.expect(
            &["--profile", "lab", "set-autostart", "off"],
            "Connect at login for lab: off\n",
            0,
        );
        h.login.set_status(&agent, LoginStatus::RequiresApproval);
        h.expect(
            &["--profile", "lab", "set-autostart", "on"],
            "Could not change automatic connection: OFTC login agent is requires-approval\n",
            1,
        );
        assert_eq!(prefs().as_deref(), Some(r#"{"connectAtLogin":false}"#));
        assert!(!request().exists());
    }

    /// The login agent starts a supervisor process for each profile that asks to
    /// connect, and one that does not is left alone.
    #[test]
    fn supervise_autostart_starts_one_supervisor_per_profile_that_connects() {
        use std::os::unix::fs::PermissionsExt;
        let mut h = Harness::new();
        let disabled = "OFTC automatic VPN connection is disabled for every profile\n";
        h.expect(&["supervise-autostart"], disabled, 0);
        two_profiles(&h);
        // The "executable" records how it was started in the profile's log.
        let script = h.dir.0.join("fake-agent");
        std::fs::write(&script, "#!/bin/sh\necho \"args=$*\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::lease::make_private_dir(&h.env.logs_dir()).unwrap();
        let logs = h.env.logs_dir();
        let log = |id: &str| std::fs::read_to_string(logs.join(format!("{id}.log"))).ok();

        // Nothing asked to connect yet.
        h.env = h.env.clone().with_exe(&script);
        h.expect(&["supervise-autostart"], disabled, 0);
        // Registering the agent leaves a request that keeps that registration from
        // opening a sign-in; it is spent by the first start.
        h.expect(
            &["--profile", "lab", "set-autostart", "on"],
            "Connect at login for lab: on\n",
            0,
        );
        h.expect(&["supervise-autostart"], disabled, 0);
        assert_eq!(log("lab"), None);

        h.expect(&["supervise-autostart"], "OFTC supervisors exited\n", 0);
        assert_eq!(
            log("lab").as_deref(),
            Some("args=--profile lab supervise-profile\n")
        );
        assert_eq!(log("example-office"), None);
        let mode = std::fs::metadata(logs.join("lab.log"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        // A second profile that connects runs beside the first; one that cannot be
        // started is reported and the rest still run.
        h.expect(
            &["--profile", "example-office", "set-autostart", "on"],
            "Connect at login for example-office: on\n",
            0,
        );
        h.expect(&["supervise-autostart"], "OFTC supervisors exited\n", 0);
        assert_eq!(
            log("example-office").as_deref(),
            Some("args=--profile example-office supervise-profile\n")
        );
        h.env = h.env.clone().with_exe(&h.dir.0.join("missing"));
        h.expect(
            &["supervise-autostart"],
            &format!("Could not start supervisor for example-office\nCould not start supervisor for lab\n{disabled}"),
            0,
        );
        // With no executable to start, a profile that wants to connect is skipped.
        h.env = HostEnv::new("com.example.oftc", &h.dir.0).unwrap();
        h.expect(&["supervise-autostart"], disabled, 0);
    }
}
