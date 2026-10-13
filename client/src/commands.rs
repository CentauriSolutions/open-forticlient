//! CLI for the OFTC-owned macOS app and packet-tunnel provider.
//!
//! The signed app owns NetworkExtension preferences, the Keychain PSK, SAML,
//! IKE/ESP, and reconnect supervision. This binary passes only explicit
//! commands to its host executable.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_APP: &str = "/Applications/OFTC development probe.app";
const HOST_BINARY: &str = "Contents/MacOS/IntegrationHost";
const AGENT_LABEL: &str = "com.open-forticlient.oftc.standalone";

const HELP: &str = "oftc — OFTC macOS VPN client

USAGE:
    oftc [--app /absolute/path/OFTC.app] COMMAND [OPTIONS]

SETUP (explicit, one-time):
    activate                         Activate the signed network extension.
    install-config                   Add OFTC's macOS VPN configuration.
    import-profile NAME              Import one FortiClient profile and PSK into
                                     OFTC's profile store and Keychain.
    save-profile GATEWAY PORT [--tcp] Save an OFTC-owned profile; UDP is default.
    provision-psk GATEWAY            Read a PSK from the terminal into Keychain.
    migrate-psk NAME GATEWAY         Import a PSK from one FortiClient profile.
    show-profile                     Show the OFTC-owned nonsecret profile.

DAILY USE:
    connect [--insecure-saml]        Connect and supervise with fresh SAML on
                                     recoverable drops; holds this terminal.
    connect-once [--insecure-saml]   Start one connection without supervision.
    status                           Show OFTC's macOS VPN status.
    rekey-counts                     Show successful local and peer CHILD rekeys.
    disconnect                       Stop the tunnel; disable agent autostart
                                     when a standalone agent is installed.
    remove-config                    Remove OFTC's macOS VPN configuration.

PER-USER LAUNCH AGENT (verified TLS only):
    install-agent                    Stage a disabled LaunchAgent for this app.
    start-agent                      Start it now and at future GUI logins.
    stop-agent                       Stop VPN and disable future login starts.
    uninstall-agent                  Stop it and remove only the LaunchAgent.

The LaunchAgent runs the app host's `supervise-profile` directly. Install does
not connect; start requires the OFTC profile, PSK, and VPN configuration to be
ready. The app path selected at install is saved in the agent. `--app` is only
accepted with install-agent and direct host commands. The default app path is
the installed signed development app; `--app` selects another app explicitly.";

#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    app: PathBuf,
    args: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Host(Invocation),
    Disconnect,
    InstallAgent(PathBuf),
    StartAgent,
    StopAgent,
    UninstallAgent,
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
    if command == "help" && tail.len() == 1 || tail.is_empty() {
        return Ok(None);
    }
    let extra = &tail[1..];
    if extra.is_empty() {
        match command {
            "install-agent" => return Ok(Some(Action::InstallAgent(app))),
            "start-agent" | "stop-agent" | "uninstall-agent" if explicit_app => {
                return Err(
                    "--app is only used when installing the agent; its app path is saved".into(),
                );
            }
            "start-agent" => return Ok(Some(Action::StartAgent)),
            "stop-agent" => return Ok(Some(Action::StopAgent)),
            "uninstall-agent" => return Ok(Some(Action::UninstallAgent)),
            "disconnect" if explicit_app => {
                return Err("--app cannot override agent-managed disconnect".into())
            }
            "disconnect" => return Ok(Some(Action::Disconnect)),
            _ => {}
        }
    }
    let mut host_args = Vec::new();
    match command {
        "activate" | "install-config" | "show-profile" | "status" | "rekey-counts" | "remove-config"
            if extra.is_empty() =>
        {
            host_args.push(command.to_string())
        }
        "import-profile" | "provision-psk" if extra.len() == 1 && !extra[0].is_empty() => {
            host_args.extend_from_slice(tail);
        }
        "migrate-psk" if extra.len() == 2 && extra.iter().all(|s| !s.is_empty()) => {
            host_args.extend_from_slice(tail);
        }
        "save-profile" if extra.len() == 2 || extra.len() == 3 && extra[2] == "--tcp" => {
            let valid_port = extra[1].parse::<u16>().is_ok_and(|p| p > 0);
            if extra[0].is_empty() || !valid_port {
                return Err("save-profile requires a gateway and port in 1..65535".into());
            }
            host_args.extend_from_slice(tail);
        }
        "connect" | "connect-once"
            if extra.is_empty() || extra.len() == 1 && extra[0] == "--insecure-saml" =>
        {
            host_args.push(
                if command == "connect" {
                    "supervise-profile"
                } else {
                    "start-profile"
                }
                .into(),
            );
            host_args.extend_from_slice(extra);
        }
        _ => {
            return Err(format!(
                "unknown command or options: {command}; run `oftc help`"
            ))
        }
    }
    Ok(Some(Action::Host(Invocation {
        app,
        args: host_args,
    })))
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

fn run_host(executable: &Path, args: &[String]) -> Result<(), Box<dyn Error>> {
    let status = Command::new(executable).args(args).status()?;
    if !status.success() {
        return Err(format!("OFTC host exited with {status}").into());
    }
    Ok(())
}

fn agent_plist(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{AGENT_LABEL}.plist"))
}

fn agent_log(home: &Path) -> PathBuf {
    home.join("Library/Logs/open-forticlient/standalone.log")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn agent_contents(executable: &Path, log: &Path) -> Result<String, Box<dyn Error>> {
    let executable = executable.to_str().ok_or("OFTC app path must be UTF-8")?;
    let log = log.to_str().ok_or("home path must be UTF-8")?;
    if executable.chars().any(char::is_control) || log.chars().any(char::is_control) {
        return Err("OFTC app and home paths must not contain control characters".into());
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>supervise-profile</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#,
        xml_escape(executable),
        xml_escape(log),
        xml_escape(log)
    ))
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
        return Err(format!("could not read {key} from installed standalone agent plist").into());
    }
    Ok(String::from_utf8(output.stdout)?
        .trim_end_matches('\n')
        .to_string())
}

fn installed_host(plist: &Path) -> Result<PathBuf, Box<dyn Error>> {
    if !plist.is_file() {
        return Err(
            "agent is not installed; run `oftc install-agent`".into(),
        );
    }
    if plist_field(plist, "Label")? != AGENT_LABEL
        || plist_field(plist, "ProgramArguments.1")? != "supervise-profile"
    {
        return Err("installed standalone agent plist has an unexpected label or command".into());
    }
    let path = PathBuf::from(plist_field(plist, "ProgramArguments.0")?);
    if !path.is_absolute()
        || path
            .file_name()
            .is_none_or(|name| name != "IntegrationHost")
    {
        return Err("installed standalone agent has an unexpected host path".into());
    }
    Ok(path)
}

fn install_agent(app: &Path) -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let plist = agent_plist(&home);
    if plist.symlink_metadata().is_ok() || loaded(&target) {
        return Err("standalone agent already installed or loaded; stop and uninstall it before changing apps".into());
    }
    let app = app.canonicalize()?;
    let executable = host_executable(&app)?;
    let log = agent_log(&home);
    let contents = agent_contents(&executable, &log)?;
    fs::create_dir_all(plist.parent().ok_or("invalid LaunchAgent path")?)?;
    fs::create_dir_all(log.parent().ok_or("invalid log path")?)?;

    // Disable before the plist appears, so install cannot start a VPN at this
    // or the next login. start-agent is the explicit opt-in to autostart.
    launchctl(&["disable", &target])?;
    let temp = plist.with_extension(format!("plist.{}.tmp", std::process::id()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, &plist)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        let _ = launchctl(&["enable", &target]);
        return Err(error);
    }
    println!("Staged disabled standalone agent: {}", plist.display());
    println!("App host: {}", executable.display());
    println!("Start now and at future GUI logins: oftc start-agent");
    Ok(())
}

fn start_agent() -> Result<(), Box<dyn Error>> {
    let (home, domain, target) = user_home_and_target()?;
    let plist = agent_plist(&home);
    let host = installed_host(&plist)?;
    if !host.is_file() {
        return Err(format!(
            "installed app host is missing at {}; reinstall the standalone agent for a new app",
            host.display()
        )
        .into());
    }
    launchctl(&["enable", &target])?;
    let was_loaded = loaded(&target);
    if !was_loaded {
        let plist_arg = plist.to_str().ok_or("LaunchAgent path must be UTF-8")?;
        if let Err(error) = launchctl(&["bootstrap", &domain, plist_arg]) {
            let _ = launchctl(&["disable", &target]);
            return Err(error);
        }
    }
    // A fresh bootstrap can leave a RunAtLoad job in launchd's speculative
    // spawn state. Kickstart ensures this explicit start request runs it now.
    // Without -k, this does not terminate an already running supervisor.
    if let Err(error) = launchctl(&["kickstart", &target]) {
        let _ = launchctl(&["disable", &target]);
        if !was_loaded {
            let _ = launchctl(&["bootout", &target]);
        }
        return Err(error);
    }
    println!("Standalone supervisor launch requested; it will also start at future GUI logins.");
    println!("VPN: oftc status");
    println!("Logs: {}", agent_log(&home).display());
    Ok(())
}

fn stop_agent() -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let host = installed_host(&agent_plist(&home))?;
    launchctl(&["disable", &target])?;
    // The host's stop command first signals its supervisor lease, preventing a
    // fresh SAML attempt, then asks NetworkExtension to stop the VPN.
    let stop_result = if host.is_file() {
        run_host(&host, &["stop".into()])
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
    println!("Standalone supervisor stopped and disabled for future GUI logins.");
    Ok(())
}

fn uninstall_agent() -> Result<(), Box<dyn Error>> {
    let (home, _domain, target) = user_home_and_target()?;
    let plist = agent_plist(&home);
    if !plist.is_file() {
        return Err("standalone agent is not installed".into());
    }
    // Even if the app has moved and its `stop` command cannot run, disabling
    // and booting out the job still lets the operator remove the agent.
    let stop_result = stop_agent();
    if !wait_unloaded(&target) {
        return Err("standalone agent is still loaded; it was not removed".into());
    }
    fs::remove_file(&plist)?;
    launchctl(&["enable", &target])?; // Clear the disabled override for a future install.
    println!("Removed standalone LaunchAgent. OFTC app, VPN configuration, profile, Keychain PSK, and logs remain.");
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
        Action::Host(invocation) => run_host(&host_executable(&invocation.app)?, &invocation.args),
        Action::Disconnect => {
            let (home, _, target) = user_home_and_target()?;
            if agent_plist(&home).is_file() || loaded(&target) {
                stop_agent()
            } else {
                run_host(&host_executable(Path::new(DEFAULT_APP))?, &["stop".into()])
            }
        }
        Action::InstallAgent(app) => install_agent(&app),
        Action::StartAgent => start_agent(),
        Action::StopAgent => stop_agent(),
        Action::UninstallAgent => uninstall_agent(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn selected_backend_and_supervision_are_explicit() {
        let Action::Host(parsed) = parse(&words("connect")).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(parsed.app, PathBuf::from(DEFAULT_APP));
        assert_eq!(parsed.args, ["supervise-profile"]);
        let Action::Host(parsed) = parse(&words("connect-once")).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(parsed.args, ["start-profile"]);
        assert_eq!(parse(&words("disconnect")).unwrap(), Some(Action::Disconnect));
        assert!(parse(&words("--app /tmp/OFTC.app disconnect")).is_err());
    }

    #[test]
    fn setup_and_transport_are_exact() {
        let Action::Host(parsed) = parse(&words(
            "--app /tmp/OFTC.app save-profile vpn.example.test 9443 --tcp",
        ))
        .unwrap()
        .unwrap() else {
            panic!()
        };
        assert_eq!(parsed.app, PathBuf::from("/tmp/OFTC.app"));
        assert_eq!(
            parsed.args,
            ["save-profile", "vpn.example.test", "9443", "--tcp"]
        );
        assert!(parse(&words("save-profile vpn.example.test 0")).is_err());
        assert!(parse(&words("connect --tcp")).is_err());
        assert!(parse(&words("status --profile Office")).is_err());
        assert!(parse(&words("--app ../OFTC.app status")).is_err());
    }

    #[test]
    fn agent_is_opt_in_and_does_not_persist_insecure_saml() {
        assert_eq!(
            parse(&words("install-agent")).unwrap(),
            Some(Action::InstallAgent(DEFAULT_APP.into()))
        );
        assert_eq!(
            parse(&words("--app /tmp/OFTC.app install-agent")).unwrap(),
            Some(Action::InstallAgent("/tmp/OFTC.app".into()))
        );
        assert_eq!(
            parse(&words("start-agent")).unwrap(),
            Some(Action::StartAgent)
        );
        assert_eq!(
            parse(&words("stop-agent")).unwrap(),
            Some(Action::StopAgent)
        );
        assert_eq!(
            parse(&words("uninstall-agent")).unwrap(),
            Some(Action::UninstallAgent)
        );
        assert!(parse(&words("--app /tmp/OFTC.app stop-agent")).is_err());
        assert!(parse(&words("install-agent --insecure-saml")).is_err());
        assert!(parse(&words("start-agent --insecure-saml")).is_err());
    }

    #[test]
    fn agent_plist_runs_only_supervisor() {
        let host = Path::new("/Applications/OFTC & Test.app/Contents/MacOS/IntegrationHost");
        let log = Path::new("/Users/example/Library/Logs/open-forticlient/standalone.log");
        let plist = agent_contents(host, log).unwrap();
        assert!(plist.contains("com.open-forticlient.oftc.standalone"));
        assert!(plist.contains("OFTC &amp; Test.app"));
        assert!(plist.contains("<string>supervise-profile</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        assert!(plist.contains("<key>KeepAlive</key><false/>"));
        assert!(!plist.contains("--insecure-saml"));
        assert!(!plist.contains("fctctld"));
        assert!(!plist.contains("FortiTray"));
    }

    #[test]
    fn macos_can_parse_installed_agent_fields() {
        let host = Path::new("/Applications/OFTC & Test.app/Contents/MacOS/IntegrationHost");
        let log = Path::new("/Users/example/Library/Logs/open-forticlient/standalone.log");
        let temp =
            std::env::temp_dir().join(format!("oftc-agent-test-{}.plist", std::process::id()));
        fs::write(&temp, agent_contents(host, log).unwrap()).unwrap();
        let lint = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&temp)
            .status()
            .unwrap();
        let extracted = installed_host(&temp);
        fs::remove_file(&temp).unwrap();
        assert!(lint.success());
        assert_eq!(extracted.unwrap(), host);
    }
}
