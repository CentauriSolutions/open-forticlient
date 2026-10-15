//! CLI for the OFTC-owned macOS app and packet-tunnel provider.
//!
//! The signed app owns NetworkExtension preferences, the Keychain PSK, SAML,
//! IKE/ESP, and reconnect supervision. This binary passes only explicit
//! commands to its host executable.

use std::error::Error;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_APP: &str = "/Applications/OFTC.app";
const HOST_BINARY: &str = "Contents/MacOS/OFTCAgent";
const AGENT_LABEL: &str = "com.chris.openforticlient.oftc.agent";
const PROVIDER_ID: &str = "com.chris.openforticlient.oftc.provider";

const HELP: &str = "oftc — OFTC macOS VPN client

USAGE:
    oftc setup --import NAME
    oftc setup --gateway HOST --saml-port PORT [--tcp]
    oftc setup --from-development
    oftc setup                         Choose a profile and answer setup prompts.
    oftc connect                       Connect and enable starts at GUI login.
    oftc disconnect                    Stop and disable automatic starts.
    oftc status                        Show VPN, profile, agent, and rekey state.
    oftc uninstall [--erase-profile]  Remove OFTC; keep credentials by default.
    oftc help

Setup uses local OFTC development or FortiClient settings as defaults when
available, then activates the extension and installs its macOS VPN entry. It
does not connect. A missing PSK is read securely from the terminal.
Connect runs a supervised session that can recover from unexpected drops.
Uninstall may prompt for administrator access. For a development build, prefix
setup, connect, or status with --app /absolute/path/OFTC.app.";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Setup(PathBuf, SetupSource),
    Connect(PathBuf),
    Disconnect,
    Status(PathBuf),
    Uninstall { erase_profile: bool },
}

#[derive(Debug, PartialEq, Eq)]
enum SetupSource {
    Existing,
    Import(String),
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

fn interactive_source() -> Result<SetupSource, Box<dyn Error>> {
    let mut candidates = Vec::new();
    if let Some(candidate) = development_candidate() {
        candidates.push(candidate);
    }
    candidates.extend(forticlient_candidates());
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
        _ => SetupSource::Manual { gateway, port, tcp },
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
                [flag] if flag == "--from-development" => SetupSource::Development,
                [gateway_flag, gateway, port_flag, port, rest @ ..]
                    if gateway_flag == "--gateway"
                        && port_flag == "--saml-port"
                        && !gateway.is_empty()
                        && (rest.is_empty() || rest == ["--tcp"]) =>
                {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| "--saml-port must be in 1..65535")?;
                    if port == 0 {
                        return Err("--saml-port must be in 1..65535".into());
                    }
                    SetupSource::Manual {
                        gateway: gateway.clone(),
                        port,
                        tcp: !rest.is_empty(),
                    }
                }
                _ => return Err("invalid setup options; run `oftc help`".into()),
            };
            Ok(Some(Action::Setup(app, source)))
        }
        "connect" if extra.is_empty() => Ok(Some(Action::Connect(app))),
        "disconnect" if extra.is_empty() && !explicit_app => Ok(Some(Action::Disconnect)),
        "status" if extra.is_empty() => Ok(Some(Action::Status(app))),
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

fn run_host(executable: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new(executable).args(args).status()?;
    if !status.success() {
        return Err(format!("OFTC host exited with {status}").into());
    }
    Ok(())
}

fn host_output(executable: &Path, command: &str) -> Result<std::process::Output, Box<dyn Error>> {
    Ok(Command::new(executable).arg(command).output()?)
}

fn has_psk(executable: &Path) -> Result<bool, Box<dyn Error>> {
    Ok(host_output(executable, "has-psk")?.status.success())
}

fn try_development_psk(executable: &Path) {
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
        let migrated = Command::new(executable)
            .args(["migrate-psk", &name, &development.gateway])
            .output();
        if migrated.is_ok_and(|result| result.status.success()) {
            println!("Saved FortiClient PSK copied into the OFTC Keychain item.");
            return;
        }
    }
}

fn run_setup(app: &Path, source: SetupSource) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    match source {
        SetupSource::Existing => {
            if host_output(&host, "show-profile")?.status.success() {
                run_host(&host, &["show-profile"])?;
            } else if io::stdin().is_terminal() {
                return run_setup(app, interactive_source()?);
            } else {
                return Err("no OFTC profile is configured; run `oftc setup` in a terminal or pass setup options".into());
            }
        }
        SetupSource::Import(name) => {
            if host_output(&host, "show-profile")?.status.success() {
                return Err("OFTC already has a profile; setup will not overwrite it".into());
            }
            run_host(&host, &["import-profile", &name])?;
        }
        SetupSource::ImportWithDefaults {
            name,
            gateway,
            port,
        } => {
            if host_output(&host, "show-profile")?.status.success() {
                return Err("OFTC already has a profile; setup will not overwrite it".into());
            }
            if run_host(&host, &["import-profile", &name]).is_err() {
                if host_output(&host, "show-profile")?.status.success() {
                    return Err("FortiClient import partly completed; inspect `oftc status` before retrying".into());
                }
                println!("FortiClient credentials were unavailable. Using its connection settings; enter the PSK when prompted.");
                run_host(&host, &["save-profile", &gateway, &port.to_string()])?;
            }
        }
        SetupSource::Development => {
            run_host(&host, &["import-development-profile"])?;
            if !has_psk(&host)? {
                try_development_psk(&host);
            }
        }
        SetupSource::Manual { gateway, port, tcp } => {
            if host_output(&host, "show-profile")?.status.success() {
                return Err("OFTC already has a profile; setup will not overwrite it".into());
            }
            let port = port.to_string();
            if tcp {
                run_host(&host, &["save-profile", &gateway, &port, "--tcp"])?;
            } else {
                run_host(&host, &["save-profile", &gateway, &port])?;
            }
        }
    }
    if !has_psk(&host)? {
        println!("Enter the VPN PSK; it will be saved in your OFTC Keychain item.");
        run_host(&host, &["provision-psk"])?;
    }
    run_host(&host, &["activate"])?;
    run_host(&host, &["install-config"])?;
    println!("OFTC setup complete. Run `oftc connect` when ready.");
    Ok(())
}

fn run_connect(app: &Path) -> Result<(), Box<dyn Error>> {
    host_executable(app)?;
    let requested = app.canonicalize()?;
    let host = host_executable(&requested)?;
    run_host(&host, &["show-profile"])?;
    if !has_psk(&host)? {
        return Err("OFTC PSK is unavailable; run `oftc setup`".into());
    }
    let vpn = host_output(&host, "status")?;
    if !vpn.status.success() || String::from_utf8_lossy(&vpn.stdout).contains("absent") {
        return Err("OFTC VPN configuration is unavailable; run `oftc setup`".into());
    }
    let (home, _, target) = user_home_and_target()?;
    let legacy = agent_plist(&home);
    if legacy.symlink_metadata().is_ok() {
        let installed = installed_host(&legacy)?;
        if installed != host {
            return Err(
                "OFTC login agent points to a different app; remove it before changing apps".into(),
            );
        }
        if !vpn.stdout.is_empty()
            && !String::from_utf8_lossy(&vpn.stdout).contains("status: disconnected")
        {
            return Err("disconnect OFTC before migrating its legacy login agent".into());
        }
        uninstall_legacy_agent()?;
    } else if bundled_agent_status(&host)? == "not-registered" && loaded(&target) {
        return Err(
            "an OFTC agent is loaded without a known registration; stop it before connecting"
                .into(),
        );
    }
    start_bundled_agent(&host, &home, &target)
}

fn run_status(app: &Path) -> Result<(), Box<dyn Error>> {
    let host = host_executable(app)?;
    let vpn = host_output(&host, "status")?;
    if !vpn.status.success() {
        return Err("could not read OFTC VPN status".into());
    }
    let vpn_text = String::from_utf8_lossy(&vpn.stdout);
    print!("{vpn_text}");
    let profile = host_output(&host, "show-profile")?;
    if profile.status.success() {
        print!("{}", String::from_utf8_lossy(&profile.stdout));
    } else {
        println!("OFTC profile: not configured");
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
    if vpn_text.contains("status: connected") {
        let rekeys = host_output(&host, "rekey-counts")?;
        if rekeys.status.success() {
            print!("{}", String::from_utf8_lossy(&rekeys.stdout));
        } else {
            println!("CHILD_SA rekey counts unavailable");
        }
    }
    Ok(())
}

fn wait_disconnected(host: &Path) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = host_output(host, "status")?;
        let text = String::from_utf8_lossy(&status.stdout);
        if status.status.success()
            && (text.contains("status: disconnected")
                || text.contains("status: invalid")
                || text.contains("absent"))
        {
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
        let status = host_output(&host, "status")?;
        let text = String::from_utf8_lossy(&status.stdout);
        if status.status.success()
            && !text.contains("status: disconnected")
            && !text.contains("status: invalid")
            && !text.contains("absent")
        {
            run_host(&host, &["stop"])?;
        }
    }
    run_host(&host, &["unregister-agent"])?;
    if !wait_unloaded(&target) {
        return Err("OFTC login agent is still loaded; package removal stopped".into());
    }
    wait_disconnected(&host)?;
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

fn agent_log(home: &Path) -> PathBuf {
    home.join("Library/Logs/OFTC/agent.log")
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

fn start_bundled_agent(host: &Path, home: &Path, target: &str) -> Result<(), Box<dyn Error>> {
    let registration = bundled_agent_status(host)?;
    if registration == "unknown" {
        return Err("OFTC bundled login agent is unavailable; reinstall the app".into());
    }
    if registration == "requires-approval" {
        return Err("allow OFTC in System Settings → General → Login Items & Extensions, then rerun `oftc connect`".into());
    }
    // The old external plist uses the same launchd label. ServiceManagement
    // may report it as enabled even after its file and job are removed. Clear
    // that stale registration before installing the app-bundled service.
    if registration == "enabled" && !loaded(target) {
        run_host(host, &["unregister-agent"])?;
    }
    run_host(host, &["register-agent"])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !loaded(target) {
        if Instant::now() >= deadline {
            return Err(
                "OFTC login agent registered but did not load; check System Settings and retry"
                    .into(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    // register() bootstraps RunAtLoad. Kickstart also covers a previously
    // registered job that exited after a deliberate macOS VPN stop.
    launchctl(&["kickstart", target])?;
    println!("OFTC agent launch requested; it will also start at future GUI logins.");
    println!("VPN: oftc status");
    println!("Logs: {}", agent_log(home).display());
    Ok(())
}

fn stop_legacy_agent() -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let host = installed_host(&agent_plist(&home))?;
    launchctl(&["disable", &target])?;
    // The host's stop command first signals its supervisor lease, preventing a
    // fresh SAML attempt, then asks NetworkExtension to stop the VPN.
    let stop_result = if host.is_file() {
        run_host(&host, &["stop"])
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
        Action::Connect(app) => run_connect(&app),
        Action::Disconnect => {
            let (home, _, target) = user_home_and_target()?;
            let host = host_executable(Path::new(DEFAULT_APP))?;
            let stop_result = if agent_plist(&home).is_file() {
                stop_legacy_agent()
            } else {
                run_host(&host, &["stop"])
            };
            let unregister_result = run_host(&host, &["unregister-agent"]);
            stop_result?;
            unregister_result?;
            if !wait_unloaded(&target) {
                return Err("OFTC login agent is still loaded after disconnect".into());
            }
            println!("OFTC agent disabled for future GUI logins.");
            Ok(())
        }
        Action::Status(app) => run_status(&app),
        Action::Uninstall { erase_profile } => run_uninstall(erase_profile),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn public_lifecycle_is_small_and_exact() {
        assert_eq!(
            parse(&words("connect")).unwrap(),
            Some(Action::Connect(DEFAULT_APP.into()))
        );
        assert_eq!(
            parse(&words("disconnect")).unwrap(),
            Some(Action::Disconnect)
        );
        assert_eq!(
            parse(&words("status")).unwrap(),
            Some(Action::Status(DEFAULT_APP.into()))
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
        assert!(parse(&words("--app /tmp/OFTC.app disconnect")).is_err());
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
                    tcp: true
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
            Some(Action::Connect("/tmp/OFTC.app".into()))
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
