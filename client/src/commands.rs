//! CLI for the OFTC-owned macOS app and packet-tunnel provider.
//!
//! The signed app owns NetworkExtension preferences, the Keychain PSK, SAML,
//! IKE/ESP, and reconnect supervision. This binary passes only explicit
//! commands to its host executable.

use std::error::Error;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_APP: &str = "/Applications/OFTC.app";
const HOST_BINARY: &str = "Contents/MacOS/OFTCAgent";
const AGENT_LABEL: &str = "com.chris.openforticlient.oftc.agent";
const PROVIDER_ID: &str = "com.chris.openforticlient.oftc.provider";

/// One configured VPN, as reported by the host's `list-profiles`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Profile {
    id: String,
    name: String,
    gateway: String,
    port: u16,
    transport: String,
}

fn valid_profile_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && !name.chars().any(char::is_control)
}

/// Parses `list-profiles` output: id, name, gateway, port, transport per line.
fn parse_profiles(text: &str) -> Vec<Profile> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let profile = Profile {
                id: fields.next()?.to_string(),
                name: fields.next()?.to_string(),
                gateway: fields.next()?.to_string(),
                port: fields.next()?.parse().ok()?,
                transport: fields.next()?.to_string(),
            };
            (fields.next().is_none() && !profile.id.is_empty()).then_some(profile)
        })
        .collect()
}

/// Picks profiles by id or display name; no names selects every profile.
fn select_profiles(all: Vec<Profile>, names: &[String]) -> Result<Vec<Profile>, String> {
    if all.is_empty() {
        return Err("no OFTC profile is configured; run `oftc setup`".into());
    }
    if names.is_empty() {
        return Ok(all);
    }
    let mut chosen: Vec<Profile> = Vec::new();
    for name in names {
        let found = all
            .iter()
            .find(|p| p.id == *name)
            .or_else(|| all.iter().find(|p| p.name.eq_ignore_ascii_case(name)))
            .ok_or_else(|| {
                let known: Vec<_> = all.iter().map(|p| p.id.as_str()).collect();
                format!("no profile named {name}; configured: {}", known.join(", "))
            })?;
        if !chosen.iter().any(|p| p.id == found.id) {
            chosen.push(found.clone());
        }
    }
    Ok(chosen)
}

const HELP: &str = "oftc — OFTC macOS VPN client

USAGE:
    oftc setup --import NAME           Add a profile from a FortiClient profile.
    oftc setup --gateway HOST --saml-port PORT [--tcp] [--name NAME]
    oftc setup --from FILE             Import profiles from a file made by `oftc export` (- is stdin).
    oftc setup --from-development
    oftc setup                         Add a profile interactively, or repair setup.
    oftc profiles                      List configured profiles.
    oftc export [PROFILE...] [-o FILE] Write profiles, with their PSKs, to a file to share.
    oftc connect [PROFILE...]          Connect profiles; none named connects all.
    oftc disconnect [PROFILE...]       Stop profiles; none named stops all.
    oftc remove PROFILE...             Delete profiles, their VPN entries and PSKs.
    oftc status [PROFILE...]           Show VPN, profile, agent, and rekey state.
    oftc autostart PROFILE on|off      Connect that profile at login.
    oftc uninstall [--erase-profile]  Remove OFTC; keep credentials by default.
    oftc help

Every profile is its own VPN and can be connected at the same time as the
others. PROFILE is a profile id or its name. Setup uses local FortiClient
settings as defaults when available, then activates the extension and installs
the profile's macOS VPN entry. It does not connect. A missing PSK is read
securely from the terminal. Connect runs a supervised session per profile that
recovers from unexpected drops; browser sign-ins happen one at a time.
Uninstall may prompt for administrator access. For a development build, prefix
any command with --app /absolute/path/OFTC.app.";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Setup(PathBuf, SetupSource),
    Profiles(PathBuf),
    Export(PathBuf, Vec<String>, Option<PathBuf>),
    Connect(PathBuf, Vec<String>),
    Disconnect(PathBuf, Vec<String>),
    Remove(PathBuf, Vec<String>),
    Status(PathBuf, Vec<String>),
    Autostart(PathBuf, String, bool),
    Uninstall { erase_profile: bool },
}

#[derive(Debug, PartialEq, Eq)]
enum SetupSource {
    Existing,
    Import(String),
    File(String),
    ImportWithDefaults {
        name: String,
        gateway: String,
        port: u16,
    },
    Development,
    Manual {
        gateway: String,
        port: u16,
        tcp: bool,
        name: Option<String>,
    },
}

struct SetupCandidate {
    label: String,
    gateway: String,
    port: u16,
    tcp: bool,
    source: SetupSource,
}

const FORTICLIENT_PLIST: &str = "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist";
const DEVELOPMENT_BUNDLE_ID: &str = "com.chris.openforticlient.gate0";

fn plist_raw(plist: &Path, key: &str) -> Option<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 8192 {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    Some(value.trim_end_matches('\n').to_string())
}

fn regular_file(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn valid_gateway(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
}

fn development_candidate() -> Option<SetupCandidate> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let profile = home
        .join("Library/Application Support")
        .join(DEVELOPMENT_BUNDLE_ID)
        .join("profile.json");
    development_candidate_from(&profile)
}

fn development_candidate_from(profile: &Path) -> Option<SetupCandidate> {
    if !regular_file(&profile) || plist_raw(&profile, "version")?.trim() != "1" {
        return None;
    }
    let gateway = plist_raw(&profile, "gateway")?;
    let port = plist_raw(&profile, "samlPort")?
        .trim()
        .parse::<u16>()
        .ok()?;
    let tcp = match plist_raw(&profile, "transport")?.trim() {
        "udp" => false,
        "tcp" => true,
        _ => return None,
    };
    if !valid_gateway(&gateway) || port == 0 {
        return None;
    }
    Some(SetupCandidate {
        label: "OFTC development profile".into(),
        gateway,
        port,
        tcp,
        source: SetupSource::Development,
    })
}

fn forticlient_candidates() -> Vec<SetupCandidate> {
    forticlient_candidates_from(Path::new(FORTICLIENT_PLIST))
}

fn forticlient_candidates_from(plist: &Path) -> Vec<SetupCandidate> {
    if !regular_file(plist) {
        return Vec::new();
    }
    let Some(names) = plist_raw(plist, "Profiles") else {
        return Vec::new();
    };
    names
        .lines()
        .filter_map(|name| {
            let name = name.trim();
            if name.is_empty()
                || name.len() > 128
                || name.contains('.')
                || name.chars().any(char::is_control)
            {
                return None;
            }
            let prefix = format!("Profiles.{name}");
            let gateway = plist_raw(plist, &format!("{prefix}.Server"))?;
            if !valid_gateway(&gateway) {
                return None;
            }
            let port = plist_raw(plist, &format!("{prefix}.IKESamlPort"))
                .and_then(|value| value.trim().parse::<u16>().ok())
                .filter(|port| *port != 0)
                .unwrap_or(9443);
            Some(SetupCandidate {
                label: format!("FortiClient profile: {name}"),
                gateway: gateway.clone(),
                port,
                tcp: false,
                source: SetupSource::ImportWithDefaults {
                    name: name.into(),
                    gateway,
                    port,
                },
            })
        })
        .collect()
}

fn prompt(label: &str, default: &str) -> Result<String, Box<dyn Error>> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 {
        return Err("setup cancelled before saving a profile".into());
    }
    let answer = answer.trim();
    Ok(if answer.is_empty() {
        default.into()
    } else {
        answer.into()
    })
}

fn interactive_source(existing: &[Profile]) -> Result<SetupSource, Box<dyn Error>> {
    let mut candidates = Vec::new();
    if let Some(candidate) = development_candidate() {
        candidates.push(candidate);
    }
    candidates.extend(forticlient_candidates());
    candidates.retain(|c| !existing.iter().any(|p| p.gateway == c.gateway));
    println!("OFTC setup sources:");
    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "  {}) {} — {}:{} ({})",
            index + 1,
            candidate.label,
            candidate.gateway,
            candidate.port,
            if candidate.tcp { "TCP" } else { "UDP" }
        );
    }
    println!("  {}) Enter connection details", candidates.len() + 1);
    let default_choice = if candidates.is_empty() {
        candidates.len() + 1
    } else {
        1
    };
    let choice = prompt("Source", &default_choice.to_string())?
        .parse::<usize>()
        .map_err(|_| "choose a numbered setup source")?;
    if !(1..=candidates.len() + 1).contains(&choice) {
        return Err("choose a numbered setup source".into());
    }
    let candidate = if choice <= candidates.len() {
        Some(candidates.swap_remove(choice - 1))
    } else {
        None
    };
    let gateway = prompt(
        "Gateway",
        candidate.as_ref().map_or("", |source| &source.gateway),
    )?;
    if !valid_gateway(&gateway) {
        return Err("gateway must be a valid host name".into());
    }
    let default_port = candidate.as_ref().map_or(9443, |source| source.port);
    let port = prompt("SAML port", &default_port.to_string())?
        .parse::<u16>()
        .map_err(|_| "SAML port must be in 1..65535")?;
    if port == 0 {
        return Err("SAML port must be in 1..65535".into());
    }
    let default_transport = if candidate.as_ref().is_some_and(|source| source.tcp) {
        "tcp"
    } else {
        "udp"
    };
    let tcp = match prompt("Transport (udp/tcp)", default_transport)?
        .to_lowercase()
        .as_str()
    {
        "udp" => false,
        "tcp" => true,
        _ => return Err("transport must be udp or tcp".into()),
    };
    let source = match candidate {
        Some(candidate)
            if candidate.gateway == gateway && candidate.port == port && candidate.tcp == tcp =>
        {
            candidate.source
        }
        _ => {
            let name = prompt("Name", &gateway)?;
            if !valid_profile_name(&name) {
                return Err("name must be 1-64 printable characters".into());
            }
            SetupSource::Manual {
                gateway,
                port,
                tcp,
                name: Some(name),
            }
        }
    };
    Ok(source)
}

fn parse(args: &[String]) -> Result<Option<Action>, String> {
    let mut index = 0;
    let mut explicit_app = false;
    let app = if args.first().is_some_and(|s| s == "--app") {
        let path = args.get(1).ok_or("--app requires an absolute .app path")?;
        let app = PathBuf::from(path);
        if !app.is_absolute() || app.extension().is_none_or(|s| s != "app") {
            return Err("--app requires an absolute .app path".into());
        }
        index = 2;
        explicit_app = true;
        app
    } else {
        PathBuf::from(DEFAULT_APP)
    };
    let tail = &args[index..];
    let command = tail.first().map(String::as_str).unwrap_or("help");
    if (command == "help" && tail.len() == 1 || tail.is_empty()) && !explicit_app {
        return Ok(None);
    }
    let extra = &tail[1..];
    match command {
        "setup" => {
            let source = match extra {
                [] => SetupSource::Existing,
                [flag, name] if flag == "--import" && !name.is_empty() => {
                    SetupSource::Import(name.clone())
                }
                [flag, path] if flag == "--from" && !path.is_empty() => {
                    SetupSource::File(path.clone())
                }
                [flag] if flag == "--from-development" => SetupSource::Development,
                [gateway_flag, gateway, port_flag, port, rest @ ..]
                    if gateway_flag == "--gateway"
                        && port_flag == "--saml-port"
                        && !gateway.is_empty() =>
                {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| "--saml-port must be in 1..65535")?;
                    if port == 0 {
                        return Err("--saml-port must be in 1..65535".into());
                    }
                    let (tcp, name) = match rest {
                        [] => (false, None),
                        [tcp] if tcp == "--tcp" => (true, None),
                        [flag, name] if flag == "--name" => (false, Some(name.clone())),
                        [tcp, flag, name] if tcp == "--tcp" && flag == "--name" => {
                            (true, Some(name.clone()))
                        }
                        _ => return Err("invalid setup options; run `oftc help`".into()),
                    };
                    if name.as_deref().is_some_and(|n| !valid_profile_name(n)) {
                        return Err("--name must be 1-64 printable characters".into());
                    }
                    SetupSource::Manual {
                        gateway: gateway.clone(),
                        port,
                        tcp,
                        name,
                    }
                }
                _ => return Err("invalid setup options; run `oftc help`".into()),
            };
            Ok(Some(Action::Setup(app, source)))
        }
        "profiles" if extra.is_empty() => Ok(Some(Action::Profiles(app))),
        "export" => {
            let mut names = Vec::new();
            let mut output = None;
            let mut rest = extra.iter();
            while let Some(arg) = rest.next() {
                if arg == "-o" || arg == "--output" {
                    let path = rest.next().ok_or("--output needs a file path")?;
                    if path.is_empty() || output.replace(PathBuf::from(path)).is_some() {
                        return Err("give --output once, with a file path".into());
                    }
                } else if arg.is_empty() || arg.starts_with('-') {
                    return Err("usage: oftc export [PROFILE...] [-o FILE]".into());
                } else {
                    names.push(arg.clone());
                }
            }
            Ok(Some(Action::Export(app, names, output)))
        }
        "connect" | "disconnect" | "status" => {
            if extra.iter().any(|name| name.is_empty() || name.starts_with('-')) {
                return Err(format!("{command} takes profile names only; run `oftc help`"));
            }
            let names = extra.to_vec();
            Ok(Some(match command {
                "connect" => Action::Connect(app, names),
                "disconnect" => Action::Disconnect(app, names),
                _ => Action::Status(app, names),
            }))
        }
        "remove" => {
            if extra.is_empty() || extra.iter().any(|name| name.is_empty() || name.starts_with('-')) {
                return Err("usage: oftc remove PROFILE...".into());
            }
            Ok(Some(Action::Remove(app, extra.to_vec())))
        }
        "autostart" => match extra {
            [name, setting] if !name.starts_with('-') && (setting == "on" || setting == "off") => {
                Ok(Some(Action::Autostart(app, name.clone(), setting == "on")))
            }
            _ => Err("usage: oftc autostart PROFILE on|off".into()),
        },
        "uninstall" if !explicit_app && (extra.is_empty() || extra == ["--erase-profile"]) => {
            Ok(Some(Action::Uninstall {
                erase_profile: !extra.is_empty(),
            }))
        }
        _ => Err(format!(
            "unknown command or options: {command}; run `oftc help`"
        )),
    }
}

fn host_executable(app: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let executable = app.join(HOST_BINARY);
    if !executable.is_file() {
        return Err(format!(
            "OFTC host executable missing at {}; install the signed OFTC app or pass --app",
            executable.display()
        )
        .into());
    }
    Ok(executable)
}

fn host_command(executable: &Path, profile: Option<&str>, args: &[&str]) -> Command {
    let mut command = Command::new(executable);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    command.args(args);
    command
}

fn run_host(executable: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    run_host_as(executable, None, args)
}

fn run_host_for(executable: &Path, profile: &str, args: &[&str]) -> Result<(), Box<dyn Error>> {
    run_host_as(executable, Some(profile), args)
}

fn run_host_as(
    executable: &Path,
    profile: Option<&str>,
    args: &[&str],
) -> Result<(), Box<dyn Error>> {
    let status = host_command(executable, profile, args).status()?;
    if !status.success() {
        return Err(format!("OFTC host exited with {status}").into());
    }
    Ok(())
}

fn host_output(executable: &Path, command: &str) -> Result<std::process::Output, Box<dyn Error>> {
    Ok(host_command(executable, None, &[command]).output()?)
}

fn host_output_for(
    executable: &Path,
    profile: &str,
    args: &[&str],
) -> Result<std::process::Output, Box<dyn Error>> {
    Ok(host_command(executable, Some(profile), args).output()?)
}

fn list_profiles(executable: &Path) -> Result<Vec<Profile>, Box<dyn Error>> {
    let output = host_output(executable, "list-profiles")?;
    if !output.status.success() {
        return Err("could not read OFTC profiles".into());
    }
    Ok(parse_profiles(&String::from_utf8_lossy(&output.stdout)))
}

fn has_psk(executable: &Path, profile: &str) -> Result<bool, Box<dyn Error>> {
    Ok(host_output_for(executable, profile, &["has-psk"])?
        .status
        .success())
}

fn try_development_psk(executable: &Path, profile: &str) {
    let Some(development) = development_candidate() else {
        return;
    };
    for candidate in forticlient_candidates() {
        if candidate.gateway != development.gateway {
            continue;
        }
        let SetupSource::ImportWithDefaults { name, .. } = candidate.source else {
            continue;
        };
        let migrated = host_output_for(
            executable,
            profile,
            &["migrate-psk", &name, &development.gateway],
        );
        if migrated.is_ok_and(|result| result.status.success()) {
            println!("Saved FortiClient PSK copied into the OFTC Keychain item.");
            return;
        }
    }
}

/// Imports a profile file (a path, or `-` for stdin) through the host and
/// returns the ids of the profiles it created.
fn import_bundle(host: &Path, source: &str) -> Result<Vec<String>, Box<dyn Error>> {
    use std::io::Read;
    let mut content = Vec::new();
    if source == "-" {
        io::stdin().take(70_000).read_to_end(&mut content)?;
    } else {
        fs::File::open(source)
            .map_err(|error| format!("could not open {source}: {error}"))?
            .take(70_000)
            .read_to_end(&mut content)?;
    }
    let mut child = host_command(host, None, &["import-profiles"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("host stdin unavailable")?.write_all(&content)?;
    let output = child.wait_with_output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    println!("{}", text.trim_end());
    if !output.status.success() {
        return Err("profile import failed".into());
    }
    Ok(text
        .lines()
        .filter_map(|line| line.rsplit_once("id="))
        .map(|(_, id)| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect())
}

/// Writes the named profiles (all when none) and their PSKs for sharing.
fn run_export(app: &Path, names: &[String], output: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    let chosen = select_profiles(list_profiles(&host)?, names)?;
    let mut args = vec!["export-profiles"];
    args.extend(chosen.iter().map(|profile| profile.id.as_str()));
    let result = host_command(&host, None, &args).output()?;
    if !result.status.success() {
        return Err(String::from_utf8_lossy(&result.stdout).trim().to_string().into());
    }
    match output {
        None => io::stdout().write_all(&result.stdout)?,
        Some(path) => {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options
                .open(path)
                .map_err(|error| format!("could not create {}: {error}", path.display()))?
                .write_all(&result.stdout)?;
            eprintln!(
                "Wrote {} profile(s) to {}. It includes each VPN PSK; share it only with the people who need it.",
                chosen.len(),
                path.display()
            );
        }
    }
    Ok(())
}

/// Runs a host command that creates a profile and returns the new profile id.
fn add_profile(host: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = host_command(host, None, args).output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    print!("{text}");
    if !output.status.success() {
        return Err(format!("OFTC host exited with {}", output.status).into());
    }
    text.lines()
        .filter_map(|line| line.rsplit_once("id="))
        .map(|(_, id)| id.trim().to_string())
        .next_back()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "OFTC host did not report the new profile".into())
}

fn run_setup(app: &Path, source: SetupSource) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    let existing = list_profiles(&host)?;
    let mut source = source;
    if source == SetupSource::Existing {
        let interactive = io::stdin().is_terminal();
        let add_another = if existing.is_empty() {
            if !interactive {
                return Err("no OFTC profile is configured; run `oftc setup` in a terminal or pass setup options".into());
            }
            true
        } else {
            for profile in &existing {
                println!("Configured: {} ({}) — {}", profile.name, profile.id, profile.gateway);
            }
            interactive
                && prompt("Add another VPN? (y/n)", "n")?
                    .to_lowercase()
                    .starts_with('y')
        };
        if add_another {
            source = interactive_source(&existing)?;
        }
    }
    let ids: Vec<String> = match source {
        SetupSource::Existing => existing.iter().map(|p| p.id.clone()).collect(),
        SetupSource::Import(name) => vec![add_profile(&host, &["import-profile", &name])?],
        SetupSource::File(path) => import_bundle(&host, &path)?,
        SetupSource::ImportWithDefaults {
            name,
            gateway,
            port,
        } => match add_profile(&host, &["import-profile", &name]) {
            Ok(id) => vec![id],
            Err(_) => {
                if list_profiles(&host)?.len() > existing.len() {
                    return Err("FortiClient import partly completed; inspect `oftc profiles` before retrying".into());
                }
                println!("FortiClient credentials were unavailable. Using its connection settings; enter the PSK when prompted.");
                vec![add_profile(
                    &host,
                    &["save-profile", &gateway, &port.to_string(), "--name", &name],
                )?]
            }
        },
        SetupSource::Development => {
            let id = add_profile(&host, &["import-development-profile"])?;
            if !has_psk(&host, &id)? {
                try_development_psk(&host, &id);
            }
            vec![id]
        }
        SetupSource::Manual {
            gateway,
            port,
            tcp,
            name,
        } => {
            let port = port.to_string();
            let mut args = vec!["save-profile", gateway.as_str(), port.as_str()];
            if tcp {
                args.push("--tcp");
            }
            if let Some(name) = &name {
                args.extend(["--name", name.as_str()]);
            }
            vec![add_profile(&host, &args)?]
        }
    };
    for id in &ids {
        if !has_psk(&host, id)? {
            println!("Enter the VPN PSK for {id}; it will be saved in your OFTC Keychain item.");
            run_host_for(&host, id, &["provision-psk"])?;
        }
    }
    run_host(&host, &["activate"])?;
    for id in &ids {
        run_host_for(&host, id, &["install-config"])?;
    }
    println!("OFTC setup complete. Run `oftc connect` when ready.");
    Ok(())
}

/// Stops every profile's supervisor and tunnel.
fn stop_all_profiles(host: &Path) -> Result<(), Box<dyn Error>> {
    let mut failed = false;
    for profile in list_profiles(host)? {
        if let Err(error) = run_host_for(host, &profile.id, &["stop"]) {
            eprintln!("could not stop {}: {error}", profile.name);
            failed = true;
        }
    }
    if failed {
        return Err("one or more profiles could not be stopped".into());
    }
    Ok(())
}

fn profile_state(host: &Path, profile: &Profile) -> Result<String, Box<dyn Error>> {
    let output = host_output_for(host, &profile.id, &["status"])?;
    if !output.status.success() {
        return Err(format!("could not read status of {}", profile.name).into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Starts a supervised session for each selected profile. Profiles are
/// independent processes, so they connect concurrently; their browser sign-ins
/// queue behind each other. A supervisor outlives this command and logs to
/// ~/Library/Logs/OFTC/<id>.log.
fn run_connect(app: &Path, names: &[String]) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    let requested = app.canonicalize()?;
    let host = host_executable(&requested)?;
    let profiles = select_profiles(list_profiles(&host)?, names)?;
    let (home, _, _) = user_home_and_target()?;
    let legacy = agent_plist(&home);
    if legacy.symlink_metadata().is_ok() {
        if installed_host(&legacy)? != host {
            return Err(
                "OFTC login agent points to a different app; remove it before changing apps".into(),
            );
        }
        for profile in &profiles {
            if !profile_state(&host, profile)?.contains("status: disconnected") {
                return Err("disconnect OFTC before migrating its legacy login agent".into());
            }
        }
        uninstall_legacy_agent()?;
    }
    let logs = home.join("Library/Logs/OFTC");
    fs::create_dir_all(&logs)?;
    let mut failures = Vec::new();
    for profile in &profiles {
        let outcome = (|| -> Result<Option<u32>, Box<dyn Error>> {
            if !has_psk(&host, &profile.id)? {
                return Err("PSK is unavailable; run `oftc setup`".into());
            }
            let state = profile_state(&host, profile)?;
            if state.contains("absent") {
                return Err("VPN configuration is unavailable; run `oftc setup`".into());
            }
            if !state.contains("status: disconnected") {
                return Ok(None); // already active
            }
            let log_path = logs.join(format!("{}.log", profile.id));
            let log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(0x100) // O_NOFOLLOW on macOS
                .open(&log_path)?;
            let child = host_command(&host, Some(&profile.id), &["supervise-profile"])
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .process_group(0)
                .spawn()?;
            Ok(Some(child.id()))
        })();
        match outcome {
            Ok(Some(pid)) => println!(
                "Connecting {} (supervisor pid {pid}); log: {}",
                profile.name,
                logs.join(format!("{}.log", profile.id)).display()
            ),
            Ok(None) => println!("{} is already active.", profile.name),
            Err(error) => {
                eprintln!("{}: {error}", profile.name);
                failures.push(profile.name.clone());
            }
        }
    }
    if !failures.is_empty() {
        return Err(format!("could not connect: {}", failures.join(", ")).into());
    }
    println!("Complete browser sign-in when prompted; profiles sign in one at a time.");
    Ok(())
}

fn run_profiles(app: &Path) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    let profiles = list_profiles(&host)?;
    if profiles.is_empty() {
        println!("No OFTC profiles are configured; run `oftc setup`.");
    }
    for profile in profiles {
        println!(
            "{} ({}) — {} port {} {}",
            profile.name,
            profile.id,
            profile.gateway,
            profile.port,
            profile.transport.to_uppercase()
        );
    }
    Ok(())
}

fn run_status(app: &Path, names: &[String]) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    let all = list_profiles(&host)?;
    if all.is_empty() {
        println!("OFTC profile: not configured");
    }
    for profile in select_profiles(all, names).unwrap_or_default() {
        let state = profile_state(&host, &profile)?;
        println!("{} ({}): {state}", profile.name, profile.id);
        let shown = host_output_for(&host, &profile.id, &["show-profile"])?;
        if shown.status.success() {
            print!("  {}", String::from_utf8_lossy(&shown.stdout));
        }
        if state.contains("status: connected") {
            let rekeys = host_output_for(&host, &profile.id, &["rekey-counts"])?;
            if rekeys.status.success() {
                print!("  {}", String::from_utf8_lossy(&rekeys.stdout));
            } else {
                println!("  CHILD_SA rekey counts unavailable");
            }
        }
    }
    let (home, _, target) = user_home_and_target()?;
    let legacy = agent_plist(&home);
    let agent = if legacy.is_file() {
        if loaded(&target) {
            "legacy agent loaded"
        } else {
            "legacy agent stopped"
        }
        .to_string()
    } else {
        let status = bundled_agent_status(&host)?;
        if status == "enabled" && loaded(&target) {
            "bundled agent loaded".to_string()
        } else {
            format!("bundled agent {status}")
        }
    };
    println!("Login agent: {agent}");
    let login = host_output(&host, "login-settings")?;
    if login.status.success() {
        print!("{}", String::from_utf8_lossy(&login.stdout));
    }
    Ok(())
}

/// Stops each named profile, waits for it alone, then deletes it: its VPN
/// entry, Keychain PSK, settings and saved certificate pin. Others keep running.
fn run_remove(app: &Path, names: &[String]) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    for profile in select_profiles(list_profiles(&host)?, names)? {
        run_host_for(&host, &profile.id, &["stop"])?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let text = profile_state(&host, &profile)?;
            if text.contains("status: disconnected")
                || text.contains("status: invalid")
                || text.contains("absent")
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("{} did not disconnect; nothing was removed", profile.name).into());
            }
            thread::sleep(Duration::from_millis(250));
        }
        run_host_for(&host, &profile.id, &["erase-profile"])?;
        println!("Removed {}.", profile.name);
    }
    Ok(())
}

fn wait_disconnected(host: &Path) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut idle = true;
        for profile in list_profiles(host)? {
            let text = profile_state(host, &profile)?;
            idle &= text.contains("status: disconnected")
                || text.contains("status: invalid")
                || text.contains("absent");
        }
        if idle {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "OFTC VPN did not disconnect; uninstall stopped before removing its configuration"
                    .into(),
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn extension_active() -> Result<bool, Box<dyn Error>> {
    let output = Command::new("/usr/bin/systemextensionsctl")
        .arg("list")
        .output()?;
    if !output.status.success() {
        return Err("could not read macOS system extension state".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .any(|line| line.contains(PROVIDER_ID) && line.contains("[activated")))
}

fn run_uninstall(erase_profile: bool) -> Result<(), Box<dyn Error>> {
    let helper = Path::new("/usr/local/libexec/oftc/remove-package");
    if !helper.is_file() {
        return Err(
            "OFTC package removal helper is missing; uninstall requires the installed package"
                .into(),
        );
    }
    let host = host_executable(Path::new(DEFAULT_APP))?;
    let (home, _, target) = user_home_and_target()?;
    if agent_plist(&home).is_file() {
        uninstall_legacy_agent()?;
    } else {
        stop_all_profiles(&host)?;
    }
    run_host(&host, &["unregister-agent"])?;
    if !wait_unloaded(&target) {
        return Err("OFTC login agent is still loaded; package removal stopped".into());
    }
    wait_disconnected(&host)?;
    run_host(&host, &["unregister-menu-login"])?;
    run_host(&host, &["quit-menu"])?;
    if erase_profile {
        run_host(&host, &["erase-profile"])?;
    }
    if extension_active()? {
        run_host(&host, &["deactivate"])?;
    }
    run_host(&host, &["remove-config"])?;
    let status = Command::new("/usr/bin/sudo").arg(helper).status()?;
    if !status.success() {
        return Err("package removal stopped; complete any macOS system extension approval and rerun `oftc uninstall`".into());
    }
    Ok(())
}

fn agent_plist(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{AGENT_LABEL}.plist"))
}

fn bundled_agent_status(host: &Path) -> Result<String, Box<dyn Error>> {
    let output = host_output(host, "agent-status")?;
    if !output.status.success() {
        return Err("could not read bundled OFTC agent status".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn user_home_and_target() -> Result<(PathBuf, String, String), Box<dyn Error>> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?);
    if !home.is_absolute() || !home.is_dir() {
        return Err("HOME must be an existing absolute user directory".into());
    }
    let output = Command::new("/usr/bin/id").arg("-u").output()?;
    let uid = String::from_utf8(output.stdout)?.trim().to_string();
    if !output.status.success()
        || uid.is_empty()
        || uid == "0"
        || !uid.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("run standalone agent commands as the logged-in GUI user, not root".into());
    }
    let domain = format!("gui/{uid}");
    let target = format!("{domain}/{AGENT_LABEL}");
    Ok((home, domain, target))
}

fn launchctl(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("/bin/launchctl").args(args).status()?;
    if !status.success() {
        return Err(format!("launchctl {} exited with {status}", args.join(" ")).into());
    }
    Ok(())
}

fn loaded(target: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", target])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn wait_unloaded(target: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while loaded(target) {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

fn plist_field(plist: &Path, key: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()?;
    if !output.status.success() {
        return Err(format!("could not read {key} from installed OFTC agent plist").into());
    }
    Ok(String::from_utf8(output.stdout)?
        .trim_end_matches('\n')
        .to_string())
}

fn installed_host(plist: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if !plist.is_file() {
        return Err("login agent is not installed; run `oftc connect`".into());
    }
    if plist_field(plist, "Label")? != AGENT_LABEL
        || plist_field(plist, "ProgramArguments.1")? != "supervise-profile"
    {
        return Err("installed OFTC agent plist has an unexpected label or command".into());
    }
    let path = PathBuf::from(plist_field(plist, "ProgramArguments.0")?);
    if !path.is_absolute() || path.file_name().is_none_or(|name| name != "OFTCAgent") {
        return Err("installed OFTC agent has an unexpected host path".into());
    }
    Ok(path)
}

fn stop_legacy_agent() -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let host = installed_host(&agent_plist(&home))?;
    launchctl(&["disable", &target])?;
    // The host's stop command first signals its supervisor lease, preventing a
    // fresh SAML attempt, then asks NetworkExtension to stop the VPN.
    let stop_result = if host.is_file() {
        stop_all_profiles(&host)
    } else {
        Err(format!("installed app host is missing at {}", host.display()).into())
    };
    let bootout_result = if loaded(&target) {
        launchctl(&["bootout", &target])
    } else {
        Ok(())
    };
    bootout_result?;
    stop_result?;
    println!("OFTC agent stopped and disabled for future GUI logins.");
    Ok(())
}

fn uninstall_legacy_agent() -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let plist = agent_plist(&home);
    if !plist.is_file() {
        return Err("OFTC agent is not installed".into());
    }
    // Even if the app has moved and its `stop` command cannot run, disabling
    // and booting out the job still lets the operator remove the agent.
    let stop_result = stop_legacy_agent();
    if !wait_unloaded(&target) {
        return Err("OFTC agent is still loaded; it was not removed".into());
    }
    fs::remove_file(&plist)?;
    launchctl(&["enable", &target])?; // Clear the disabled override for a future install.
    println!(
        "Removed legacy OFTC LaunchAgent. App, VPN configuration, profile, Keychain PSK, and logs remain."
    );
    if let Err(error) = stop_result {
        return Err(format!("agent removed, but VPN stop could not be confirmed: {error}").into());
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(action) = parse(args)? else {
        println!("{HELP}");
        return Ok(());
    };
    match action {
        Action::Setup(app, source) => run_setup(&app, source),
        Action::Profiles(app) => run_profiles(&app),
        Action::Export(app, names, output) => run_export(&app, &names, output.as_deref()),
        Action::Connect(app, names) => run_connect(&app, &names),
        Action::Remove(app, names) => run_remove(&app.canonicalize()?, &names),
        Action::Disconnect(app, names) => {
            let host = host_executable(&app.canonicalize()?)?;
            let (home, _, _) = user_home_and_target()?;
            if agent_plist(&home).is_file() {
                if installed_host(&agent_plist(&home))? != host {
                    return Err(
                        "OFTC login agent points to a different app; disconnect using that app"
                            .into(),
                    );
                }
                stop_legacy_agent()?;
            }
            let profiles = select_profiles(list_profiles(&host)?, &names)?;
            let mut failed = Vec::new();
            for profile in profiles {
                match run_host_for(&host, &profile.id, &["stop"]) {
                    Ok(()) => println!("Stop requested for {}.", profile.name),
                    Err(error) => {
                        eprintln!("{}: {error}", profile.name);
                        failed.push(profile.name);
                    }
                }
            }
            if !failed.is_empty() {
                return Err(format!("could not stop: {}", failed.join(", ")).into());
            }
            Ok(())
        }
        Action::Status(app, names) => run_status(&app, &names),
        Action::Autostart(app, name, enabled) => {
            let host = host_executable(&app)?;
            let profile = select_profiles(list_profiles(&host)?, &[name])?.remove(0);
            run_host_for(
                &host,
                &profile.id,
                &["set-autostart", if enabled { "on" } else { "off" }],
            )
        }
        Action::Uninstall { erase_profile } => run_uninstall(erase_profile),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    fn sample_profiles() -> Vec<Profile> {
        parse_profiles(
            "office-vpn\tOffice VPN\tvpn.office.example\t9443\tudp\nwarehouse\tWarehouse\tvpn.warehouse.example\t9444\ttcp\nbroken line\n",
        )
    }

    #[test]
    fn profiles_parse_and_select_by_id_or_name() {
        let all = sample_profiles();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].port, 9444);
        assert_eq!(select_profiles(all.clone(), &[]).unwrap().len(), 2);
        let picked = select_profiles(all.clone(), &words("warehouse")).unwrap();
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].id, "warehouse");
        let by_name = select_profiles(all.clone(), &["office vpn".to_string()]).unwrap();
        assert_eq!(by_name[0].id, "office-vpn");
        assert_eq!(
            select_profiles(all.clone(), &words("warehouse warehouse")).unwrap().len(),
            1
        );
        assert!(select_profiles(all, &words("nope")).is_err());
        assert!(select_profiles(Vec::new(), &[]).is_err());
    }

    #[test]
    fn remove_needs_named_profiles() {
        assert_eq!(
            parse(&words("remove warehouse")).unwrap(),
            Some(Action::Remove(DEFAULT_APP.into(), words("warehouse")))
        );
        assert!(parse(&words("remove")).is_err());
        assert!(parse(&words("remove --all")).is_err());
    }

    #[test]
    fn export_and_file_import_parse() {
        assert_eq!(
            parse(&words("export")).unwrap(),
            Some(Action::Export(DEFAULT_APP.into(), Vec::new(), None))
        );
        assert_eq!(
            parse(&words("export office-vpn Warehouse -o /tmp/vpns.oftc")).unwrap(),
            Some(Action::Export(
                DEFAULT_APP.into(),
                words("office-vpn Warehouse"),
                Some("/tmp/vpns.oftc".into())
            ))
        );
        assert!(parse(&words("export -o")).is_err());
        assert!(parse(&words("export -o a -o b")).is_err());
        assert!(parse(&words("export --bogus")).is_err());
        assert_eq!(
            parse(&words("setup --from vpns.oftc")).unwrap(),
            Some(Action::Setup(
                DEFAULT_APP.into(),
                SetupSource::File("vpns.oftc".into())
            ))
        );
        assert!(parse(&words("setup --from")).is_err());
    }

    #[test]
    fn public_lifecycle_is_small_and_exact() {
        assert_eq!(
            parse(&words("connect")).unwrap(),
            Some(Action::Connect(DEFAULT_APP.into(), Vec::new()))
        );
        assert_eq!(
            parse(&words("disconnect warehouse office-vpn")).unwrap(),
            Some(Action::Disconnect(DEFAULT_APP.into(), words("warehouse office-vpn")))
        );
        assert_eq!(
            parse(&words("status")).unwrap(),
            Some(Action::Status(DEFAULT_APP.into(), Vec::new()))
        );
        assert_eq!(
            parse(&words("autostart warehouse on")).unwrap(),
            Some(Action::Autostart(DEFAULT_APP.into(), "warehouse".into(), true))
        );
        assert!(parse(&words("autostart warehouse maybe")).is_err());
        assert_eq!(
            parse(&words("profiles")).unwrap(),
            Some(Action::Profiles(DEFAULT_APP.into()))
        );
        assert_eq!(
            parse(&words("uninstall")).unwrap(),
            Some(Action::Uninstall {
                erase_profile: false
            })
        );
        assert_eq!(
            parse(&words("uninstall --erase-profile")).unwrap(),
            Some(Action::Uninstall {
                erase_profile: true
            })
        );
        assert_eq!(
            parse(&words("setup")).unwrap(),
            Some(Action::Setup(DEFAULT_APP.into(), SetupSource::Existing))
        );
        assert!(parse(&words("connect-once")).is_err());
        assert!(parse(&words("start-agent")).is_err());
        assert!(parse(&words("activate")).is_err());
        assert!(parse(&words("rekey-counts")).is_err());
        assert!(parse(&words("connect --insecure-saml")).is_err());
        assert_eq!(
            parse(&words("--app /tmp/OFTC.app disconnect")).unwrap(),
            Some(Action::Disconnect("/tmp/OFTC.app".into(), Vec::new()))
        );
        assert!(parse(&words("--app /tmp/OFTC.app uninstall")).is_err());
    }

    #[test]
    fn setup_sources_and_transport_are_exact() {
        assert_eq!(
            parse(&words("setup --import Office")).unwrap(),
            Some(Action::Setup(
                DEFAULT_APP.into(),
                SetupSource::Import("Office".into())
            ))
        );
        assert_eq!(
            parse(&words("setup --from-development")).unwrap(),
            Some(Action::Setup(DEFAULT_APP.into(), SetupSource::Development))
        );
        assert_eq!(
            parse(&words(
                "--app /tmp/OFTC.app setup --gateway vpn.example.test --saml-port 9443 --tcp"
            ))
            .unwrap(),
            Some(Action::Setup(
                PathBuf::from("/tmp/OFTC.app"),
                SetupSource::Manual {
                    gateway: "vpn.example.test".into(),
                    port: 9443,
                    tcp: true,
                    name: None
                }
            ))
        );
        assert_eq!(
            parse(&words(
                "setup --gateway vpn.example.test --saml-port 9443 --name Lab"
            ))
            .unwrap(),
            Some(Action::Setup(
                DEFAULT_APP.into(),
                SetupSource::Manual {
                    gateway: "vpn.example.test".into(),
                    port: 9443,
                    tcp: false,
                    name: Some("Lab".into())
                }
            ))
        );
        assert!(parse(&words("setup --gateway vpn.example.test --saml-port 0")).is_err());
        assert!(parse(&words("setup --gateway vpn.example.test --saml-port 65536")).is_err());
        assert!(parse(&words(
            "setup --gateway vpn.example.test --saml-port 9443 --tcp --tcp"
        ))
        .is_err());
        assert!(parse(&words(
            "setup --gateway vpn.example.test --saml-port 9443 --insecure-saml"
        ))
        .is_err());
        assert!(parse(&words("--app ../OFTC.app status")).is_err());
    }

    #[test]
    fn help_and_development_app_path_are_explicit() {
        assert_eq!(parse(&words("help")).unwrap(), None);
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(
            parse(&words("--app /tmp/OFTC.app connect")).unwrap(),
            Some(Action::Connect("/tmp/OFTC.app".into(), Vec::new()))
        );
        assert!(parse(&words("--app /tmp/OFTC.app help")).is_err());
    }

    #[test]
    fn legacy_migration_accepts_only_the_known_agent() {
        let path = std::env::temp_dir().join(format!(
            "oftc-legacy-agent-validation-{}.plist",
            std::process::id()
        ));
        let valid = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.chris.openforticlient.oftc.agent</string>
<key>ProgramArguments</key><array>
<string>/Applications/OFTC.app/Contents/MacOS/OFTCAgent</string>
<string>supervise-profile</string>
</array></dict></plist>"#;
        fs::write(&path, valid).unwrap();
        assert_eq!(
            installed_host(&path).unwrap(),
            Path::new("/Applications/OFTC.app/Contents/MacOS/OFTCAgent")
        );
        fs::write(
            &path,
            valid.replace("supervise-profile", "unrelated-command"),
        )
        .unwrap();
        assert!(installed_host(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn setup_discovers_nonsecret_local_defaults() {
        assert!(valid_gateway("vpn.example.test"));
        assert!(!valid_gateway("vpn.example.test\u{1b}[2J"));
        let temp = std::env::temp_dir().join(format!("oftc-setup-test-{}", std::process::id()));
        fs::create_dir(&temp).unwrap();
        let development = temp.join("development.json");
        let forticlient = temp.join("forticlient.json");
        fs::write(
            &development,
            r#"{"version":1,"gateway":"vpn.example.test","samlPort":9443,"transport":"udp"}"#,
        )
        .unwrap();
        fs::write(
            &forticlient,
            r#"{"Profiles":{"Work VPN":{"Server":"vpn.example.test","IKESamlPort":9443}}}"#,
        )
        .unwrap();
        let dev = development_candidate_from(&development).unwrap();
        assert_eq!(dev.gateway, "vpn.example.test");
        assert_eq!(dev.source, SetupSource::Development);
        let imported = forticlient_candidates_from(&forticlient);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].port, 9443);
        assert_eq!(
            imported[0].source,
            SetupSource::ImportWithDefaults {
                name: "Work VPN".into(),
                gateway: "vpn.example.test".into(),
                port: 9443,
            }
        );
        fs::remove_dir_all(temp).unwrap();
    }
}
