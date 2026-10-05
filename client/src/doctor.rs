//! `oftc doctor` — environment preflight and a guided, reversible FortiTray
//! disable.
//!
//! oftc drives Fortinet's own `fctctld` + `iked` (the VPN engine), so those must
//! be installed and running — we do NOT replace them. The one piece we must get
//! out of the way is **FortiTray**, the GUI agent whose `systemWillSleep` handler
//! issues a `DISCONNECT` on every screen lock (the whole reason this project
//! exists). FortiTray is (re)launched by two *user* LaunchAgents:
//!
//!   - `com.fortinet.fct_launcher`  (RunAtLoad — starts FCTLauncher → FortiTray)
//!   - `com.fortinet.fortiagent`    (KeepAlive on `…/data/fct_is_running`)
//!
//! Both are independent of the VPN LaunchDaemons (`servctl2`/`vpn`/
//! `PrivilegedHelper`), so disabling them stops the lock teardown while leaving
//! the engine oftc needs. Stopping/`disable`-ing a user LaunchAgent needs root,
//! so we ask macOS for it via `osascript … with administrator privileges`, which
//! shows the standard authentication dialog. `--restore` undoes it.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// Our LaunchAgent label (user GUI domain). Holds the fctctld control socket so
/// the tunnel survives terminal-close and screen lock; poked up/down on demand.
const OFTC_LABEL: &str = "com.open-forticlient.oftc";

const FCT_APP: &str = "/Applications/FortiClient.app";
const FCT_DAEMON: &str = "/Library/Application Support/Fortinet/FortiClient/bin/fctctld";
const FCT_IKED: &str = "/Library/Application Support/Fortinet/FortiClient/bin/iked";

/// launchd labels (as `launchctl list` prints them) that launch/keep the tray.
const TRAY_AGENTS: [&str; 2] = ["com.fortinet.fct_launcher", "com.fortinet.fortiagent"];
/// Their on-disk plists, needed to `bootstrap` them back on `--restore`.
const TRAY_PLISTS: [&str; 2] = [
    "/Library/LaunchAgents/com.fortinet.forticlient.fct_launcher.plist",
    "/Library/LaunchAgents/com.fortinet.forticlient.fortiagent.plist",
];

pub fn doctor(args: &[String]) -> Result<(), Box<dyn Error>> {
    let restore = args.iter().any(|a| a == "--restore");
    let dry = args.iter().any(|a| a == "--dry-run");
    let yes = args.iter().any(|a| a == "--yes");

    if restore {
        return restore_tray(dry);
    }

    println!("open-forticlient doctor\n");

    // 1. FortiClient must be installed — oftc drives its fctctld + iked.
    let app = path_exists(FCT_APP);
    let daemon = path_exists(FCT_DAEMON);
    let iked = path_exists(FCT_IKED);
    check("FortiClient app present", app, FCT_APP);
    check("VPN daemon (fctctld) present", daemon, FCT_DAEMON);
    check("iked present", iked, FCT_IKED);
    if !(daemon && iked) {
        return Err("FortiClient is not installed. oftc drives FortiClient's own \
             fctctld + iked (it does not replace them) — install FortiClient 7.4.x first."
            .into());
    }

    // 2. engine reachable, and our credential is set. fctctld is launched on
    //    demand by launchd, so "not running now" is normal — the control socket
    //    being present is the real readiness signal (launchd starts fctctld when
    //    oftc connects to it).
    if proc_running("fctctld") {
        println!("  [ ok ] fctctld running");
    } else {
        println!("  [info] fctctld not running (normal — launchd starts it on connect)");
    }
    check(
        "control socket present",
        path_exists(crate::proto::MAIN_SOCKET),
        crate::proto::MAIN_SOCKET,
    );
    // A PSK is available if the operator set one, OR we can decrypt the profile's
    // own AuthInfo (FortiClient's Enc uses a hardcoded key — see fctcrypt.rs).
    let psk_ok = crate::profile::Profile::load(&crate::profile::resolve_profile(None))
        .map(|p| p.psk_is_plaintext)
        .unwrap_or(false);
    check(
        "PSK available (override or decrypted from AuthInfo)",
        psk_ok,
        "no $FORTIGATE_PSK/.env/~/.config/oftc/psk and AuthInfo could not be decrypted",
    );

    let uid = console_uid();

    if dry {
        println!("\n--- `oftc doctor` would run this as root (via a macOS auth prompt): ---");
        println!("{}", disable_script(&uid));
        println!("\n--- `oftc doctor --restore` would run: ---");
        println!("{}", restore_script(&uid));
        return Ok(());
    }

    // 3. FortiTray — the lock-disconnect culprit.
    println!();
    if tray_neutralized(&uid) {
        println!("[ ok ] FortiTray is stopped and its launch agents are disabled — the lock");
        println!("       teardown is neutralized and stays that way across login/reboot.");
        return Ok(());
    }

    if proc_running("FortiTray") {
        println!("[WARN] FortiTray is RUNNING. It DISCONNECTs the VPN on every screen lock.");
    } else {
        println!("[WARN] FortiTray isn't running, but its launch agents aren't disabled, so it");
        println!("       will come back at next login and DISCONNECT the VPN on screen lock.");
    }
    println!("       To use oftc as the keep-alive client, disable it. This stops FortiTray");
    println!("       and disables its two launch agents ({}),", TRAY_AGENTS.join(", "));
    println!("       and leaves fctctld/iked — the VPN engine oftc drives — untouched.");
    println!("       Reversible any time with:  oftc doctor --restore");

    if !yes && !confirm("\nDisable FortiTray now? macOS will prompt you for admin. [y/N] ")? {
        println!("Left FortiTray running. Nothing changed.");
        return Ok(());
    }

    run_privileged(
        &disable_script(&uid),
        "open-forticlient wants to disable FortiTray, the FortiClient component that \
         drops your VPN on screen lock. The VPN engine (fctctld/iked) is left running.",
    )?;

    std::thread::sleep(std::time::Duration::from_millis(800));
    if proc_running("FortiTray") {
        println!("FortiTray still appears to be running; it may relaunch. Re-run `oftc doctor`, \
             or check `launchctl print gui/{uid}/com.fortinet.fct_launcher`.");
    } else {
        println!("[ ok ] FortiTray stopped and its launch agents disabled. Lock teardown neutralized.");
        println!("       Undo any time with:  oftc doctor --restore");
    }
    Ok(())
}

fn restore_tray(dry: bool) -> Result<(), Box<dyn Error>> {
    let script = restore_script(&console_uid());
    if dry {
        println!("--- `oftc doctor --restore` would run this as root: ---\n{script}");
        return Ok(());
    }
    run_privileged(
        &script,
        "open-forticlient wants to re-enable FortiClient's FortiTray launch agents.",
    )?;
    println!("[ ok ] Re-enabled FortiTray's launch agents. FortiTray starts on next login");
    println!("       (or launch FortiClient now). Note: the stock lock-disconnect behavior returns.");
    Ok(())
}

/// True when `disable_script` has already taken effect: FortiTray isn't running
/// and both tray agents are disabled and unloaded. All of this is readable
/// without root, so callers can skip the admin prompt.
fn tray_neutralized(uid: &str) -> bool {
    if proc_running("FortiTray") || proc_running("FCTLauncher") {
        return false;
    }
    let Some(disabled) = run_trimmed("launchctl", &["print-disabled", &format!("gui/{uid}")]) else {
        return false;
    };
    TRAY_AGENTS.iter().all(|label| {
        agent_disabled(&disabled, label)
            && !Command::new("launchctl")
                .args(["print", &format!("gui/{uid}/{label}")])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    })
}

/// Whether `launchctl print-disabled` output lists `label` as `=> disabled`.
fn agent_disabled(print_disabled: &str, label: &str) -> bool {
    let quoted = format!("\"{label}\"");
    print_disabled.lines().any(|l| {
        let l = l.trim();
        l.starts_with(&quoted) && l.ends_with("=> disabled")
    })
}

/// The root shell script that stops FortiTray and disables its launch agents.
/// `|| true` so a not-currently-loaded agent doesn't fail the whole run.
fn disable_script(uid: &str) -> String {
    let mut cmds = vec![
        "/usr/bin/pkill -x FortiTray || true".to_string(),
        "/usr/bin/pkill -x FCTLauncher || true".to_string(),
    ];
    for label in TRAY_AGENTS {
        cmds.push(format!("/bin/launchctl bootout gui/{uid}/{label} || true"));
        cmds.push(format!("/bin/launchctl disable gui/{uid}/{label} || true"));
    }
    cmds.join("; ")
}

fn restore_script(uid: &str) -> String {
    let mut cmds = Vec::new();
    for label in TRAY_AGENTS {
        cmds.push(format!("/bin/launchctl enable gui/{uid}/{label} || true"));
    }
    for plist in TRAY_PLISTS {
        cmds.push(format!("/bin/launchctl bootstrap gui/{uid} {plist} || true"));
    }
    cmds.join("; ")
}

/// Ask macOS to run `script` as root. `do shell script … with administrator
/// privileges` shows the native auth dialog; on approval the script runs as
/// root, on cancel osascript exits non-zero and nothing changed.
fn run_privileged(script: &str, prompt: &str) -> Result<(), Box<dyn Error>> {
    let applescript = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
        esc(script),
        esc(prompt),
    );
    let status = Command::new("osascript").arg("-e").arg(&applescript).status()?;
    if !status.success() {
        return Err("privileged step cancelled or failed (no changes if you cancelled the prompt)".into());
    }
    Ok(())
}

/// Escape for embedding inside an AppleScript double-quoted string.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The logged-in user's uid (the GUI launchd domain we target). oftc runs as the
/// user, so `id -u` is correct; fall back to the console owner, then 501.
fn console_uid() -> String {
    run_trimmed("id", &["-u"])
        .filter(|s| !s.is_empty())
        .or_else(|| run_trimmed("stat", &["-f", "%u", "/dev/console"]))
        .unwrap_or_else(|| "501".to_string())
}

fn run_trimmed(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn path_exists(p: &str) -> bool {
    std::path::Path::new(p).exists()
}

fn proc_running(name: &str) -> bool {
    Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check(label: &str, ok: bool, detail: &str) {
    if ok {
        println!("  [ ok ] {label}");
    } else {
        println!("  [FAIL] {label}  — {detail}");
    }
}

fn confirm(prompt: &str) -> Result<bool, Box<dyn Error>> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

// ───────────────────────────── install / up / down ──────────────────────────
//
// The tunnel lives only while a process holds fctctld's control socket, so we
// run `oftc connect` as a user LaunchAgent that launchd manages, and poke it
// up/down. It must be a LaunchAgent (not a root LaunchDaemon): SSO opens a
// browser and catches a loopback redirect, which only works in the GUI session.

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}
fn plist_path() -> String {
    format!("{}/Library/LaunchAgents/{OFTC_LABEL}.plist", home())
}
fn install_bin() -> String {
    format!("{}/Library/Application Support/open-forticlient/oftc", home())
}
fn log_path() -> String {
    format!("{}/Library/Logs/open-forticlient/oftc.log", home())
}
fn psk_path() -> String {
    format!("{}/.config/oftc/psk", home())
}

fn arg_val<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

fn mkdir_p(path: &str) -> std::io::Result<()> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn launchctl(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn plist_contents(bin: &str, profile: &str, log: &str, home: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>connect</string>
    <string>--profile</string>
    <string>{profile}</string>
    <string>--supervise</string>
  </array>
  <key>RunAtLoad</key><false/>
  <!-- KeepAlive is false ON PURPOSE. `connect --supervise` self-heals: one
       process stays alive and re-runs SSO->CONNECT after any drop (so a long
       suspend reconnects on wake). We do NOT want launchd to drive reconnection
       — a conditional KeepAlive ({{SuccessfulExit:false}}) wedges across the
       sleep/wake power transition (the respawn pends on a semaphore that never
       fires), which is exactly the bug this replaced. launchd only loads the
       job; `oftc up` starts it, `oftc down` boots it out. -->
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Interactive</string>
  <key>EnvironmentVariables</key>
  <dict><key>HOME</key><string>{home}</string></dict>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        label = OFTC_LABEL,
        bin = xml_escape(bin),
        profile = xml_escape(profile),
        home = xml_escape(home),
        log = xml_escape(log),
    )
}

/// Make the plaintext PSK available to the agent at ~/.config/oftc/psk (0600),
/// since launchd runs oftc with no .env and no $FORTIGATE_PSK in scope.
fn ensure_psk_file() -> Result<(), Box<dyn Error>> {
    let path = psk_path();
    if path_exists(&path) {
        return Ok(());
    }
    match crate::profile::plaintext_psk_override() {
        Some(psk) => {
            mkdir_p(&path)?;
            fs::write(&path, format!("{psk}\n"))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            println!("  stored PSK at {path} (0600) for the background agent");
        }
        None => {
            // No operator override — that's fine: oftc decrypts the profile's
            // own AuthInfo at runtime (fctcrypt), so the agent needs nothing.
            println!("  PSK: will be decrypted from the profile's AuthInfo at run time");
        }
    }
    Ok(())
}

pub fn install(args: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = crate::profile::resolve_profile(arg_val(args, "--profile"));
    let keep_tray = args.iter().any(|a| a == "--keep-tray");
    let uid = console_uid();

    if !(path_exists(FCT_DAEMON) && path_exists(FCT_IKED)) {
        return Err("FortiClient (fctctld + iked) is not installed — oftc drives it, so install \
             FortiClient 7.4.x first."
            .into());
    }

    println!("Installing open-forticlient agent (profile {profile:?})…");

    // 1. a stable copy of the binary the agent will run.
    let exe = std::env::current_exe()?;
    let bin = install_bin();
    mkdir_p(&bin)?;
    fs::copy(&exe, &bin)?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
    println!("  binary -> {bin}");

    // 2. PSK where the agent can read it; 3. log dir.
    ensure_psk_file()?;
    mkdir_p(&log_path())?;

    // 4. the LaunchAgent plist.
    let plist = plist_path();
    mkdir_p(&plist)?;
    fs::write(&plist, plist_contents(&bin, &profile, &log_path(), &home()))?;
    println!("  agent  -> {plist}");

    // 5. load it into our GUI domain (no root needed for our own agent).
    let domain = format!("gui/{uid}");
    let target = format!("gui/{uid}/{OFTC_LABEL}");
    let _ = launchctl(&["bootout", &target]); // ignore "not loaded"
    if !launchctl(&["bootstrap", &domain, &plist]) {
        eprintln!("  warning: `launchctl bootstrap {domain}` failed; try `oftc up` anyway.");
    }
    let _ = launchctl(&["enable", &target]);

    // 6. neutralize FortiTray (root) unless asked to keep it.
    if keep_tray {
        println!("  (left FortiTray as-is; --keep-tray). It will still drop the VPN on lock.");
    } else if tray_neutralized(&uid) {
        println!("  FortiTray already disabled — skipping the admin step.");
    } else {
        println!("  disabling FortiTray so it can't DISCONNECT on lock (needs admin)…");
        run_privileged(
            &disable_script(&uid),
            "open-forticlient is installing: disable FortiTray (which drops the VPN on screen \
             lock). The VPN engine fctctld/iked stays running.",
        )?;
    }

    println!("\nInstalled. Bring the tunnel up with:  oftc up");
    println!("Take it down with:  oftc down     Remove everything with:  oftc uninstall");
    Ok(())
}

pub fn up(args: &[String]) -> Result<(), Box<dyn Error>> {
    let uid = console_uid();
    if !path_exists(&plist_path()) {
        return Err("not installed — run `oftc install` first".into());
    }
    let _ = args;
    let domain = format!("gui/{uid}");
    let target = format!("gui/{uid}/{OFTC_LABEL}");
    // `down` boots the agent out, so (re)load it before starting.
    let _ = launchctl(&["bootstrap", &domain, &plist_path()]);
    let _ = launchctl(&["enable", &target]);
    if !launchctl(&["kickstart", "-k", &target]) {
        return Err(format!("could not start the agent ({target}); is it installed?").into());
    }
    println!("Agent started — it holds the tunnel across screen lock and self-reconnects if the");
    println!("SA drops (e.g. after a long suspend): the session re-runs SSO + CONNECT in-process,");
    println!("backing off between attempts. A browser tab opens for SSO on each (re)connect; a");
    println!("cached IdP login completes it silently.");
    println!("  logs:  tail -f {}", log_path());
    println!("  down:  oftc down");
    Ok(())
}

pub fn down(args: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = crate::profile::resolve_profile(arg_val(args, "--profile"));
    let uid = console_uid();
    let bin = if path_exists(&install_bin()) {
        install_bin()
    } else {
        std::env::current_exe()?.to_string_lossy().into_owned()
    };
    // Order matters: the agent SUPERVISES, so a bare DISCONNECT would just make it
    // re-SSO and reconnect. Kill the supervisor FIRST — `bootout` SIGTERMs the
    // process and unloads the job (closing its socket, which drops the tunnel) —
    // and only THEN send a DISCONNECT to clean up any iked/daemon state left over.
    let _ = launchctl(&["bootout", &format!("gui/{uid}/{OFTC_LABEL}")]);
    let _ = Command::new(&bin).args(["disconnect", "--profile", &profile]).status();
    println!("Tunnel disconnected and agent unloaded (won't auto-reconnect until `oftc up`).");
    Ok(())
}

pub fn uninstall(args: &[String]) -> Result<(), Box<dyn Error>> {
    let keep_tray_disabled = args.iter().any(|a| a == "--keep-tray-disabled");
    let purge = args.iter().any(|a| a == "--purge");
    let uid = console_uid();

    // stop + remove our agent.
    let _ = down(args);
    let _ = launchctl(&["bootout", &format!("gui/{uid}/{OFTC_LABEL}")]);
    let _ = fs::remove_file(plist_path());
    let _ = fs::remove_file(install_bin());
    println!("Removed the oftc agent.");

    // restore FortiTray unless the user wants it left disabled.
    if keep_tray_disabled {
        println!("Left FortiTray disabled (--keep-tray-disabled).");
    } else {
        println!("Re-enabling FortiTray (needs admin)…");
        restore_tray(false)?;
    }

    if purge {
        let _ = fs::remove_file(psk_path());
        let _ = fs::remove_file(log_path());
        println!("Purged PSK and logs.");
    } else {
        println!("Kept {} (use --purge to remove).", psk_path());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_print_disabled() {
        let out = "disabled services = {\n\t\t\"com.fortinet.forticlient.fortitray\" => enabled\n\t\t\"com.fortinet.fct_launcher\" => disabled\n\t\t\"com.fortinet.fortiagent\" => enabled\n\t}";
        assert!(agent_disabled(out, "com.fortinet.fct_launcher"));
        assert!(!agent_disabled(out, "com.fortinet.fortiagent"));
        assert!(!agent_disabled(out, "com.fortinet.missing"));
    }
}

// ───────────────────────────── show-psk / status ────────────────────────────

const FCTCTL_LOG: &str = "/Library/Application Support/Fortinet/FortiClient/Logs/fctctl.log";

/// Print the plaintext pre-shared key (decrypted from AuthInfo, or the override)
/// to stdout — e.g. to hand to a colleague on the same gateway. It is a secret.
pub fn show_psk(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = crate::profile::resolve_profile(arg_val(args, "--profile"));
    let p = crate::profile::Profile::load(&name)?;
    if p.psk.is_empty() {
        return Err("no PSK to show: the profile's AuthInfo is not the PSK (it did not decrypt, \
             or it holds the saved SAML username), and no override is set. On a profile where \
             AuthInfo *is* the PSK (e.g. an admin's), this prints it; otherwise set \
             $FORTIGATE_PSK."
            .into());
    }
    eprintln!("# plaintext pre-shared key for profile {name:?} — secret, handle with care:");
    println!("{}", p.psk);
    Ok(())
}

/// Show the current config + tunnel state at a glance.
pub fn status(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = crate::profile::resolve_profile(arg_val(args, "--profile"));
    let p = crate::profile::Profile::load(&name)?;

    println!("open-forticlient status\n");
    println!("  profile : {name:?}");
    println!("  server  : {}:{}", p.server, p.saml_port);
    let psk_src = if crate::profile::plaintext_psk_override().is_some() {
        "operator override ($FORTIGATE_PSK / .env / ~/.config/oftc/psk)"
    } else if !p.psk.is_empty() {
        "decrypted from the profile's AuthInfo"
    } else {
        "NONE — connect will fail (set $FORTIGATE_PSK)"
    };
    println!("  PSK     : {psk_src}");

    let iked = proc_running("iked");
    let held = Command::new("pgrep")
        .args(["-f", "oftc connect"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let (last_event, vpnip) = fctctl_status();

    println!();
    if iked {
        let ip = vpnip.unwrap_or_default();
        let on_iface = !ip.is_empty() && iface_has_ip(&ip);
        let tail = if on_iface {
            format!(", internal IP {ip} on a utun interface")
        } else if !ip.is_empty() {
            format!(", last internal IP {ip}")
        } else {
            String::new()
        };
        println!("  tunnel  : UP (iked running{tail})");
    } else {
        println!("  tunnel  : DOWN (iked not running)");
    }
    println!(
        "  held by : {}",
        if held {
            "an oftc session holding the control socket"
        } else {
            "nothing (if a tunnel is up, fctctld may tear it down)"
        }
    );
    if let Some(ev) = last_event {
        println!("  last    : {ev}");
    }

    println!();
    if proc_running("FortiTray") {
        println!("  [WARN] FortiTray is running — it will DISCONNECT the VPN on screen lock.");
        println!("         Run `oftc doctor` (or `oftc install`) to disable it.");
    } else {
        println!("  [ ok ] FortiTray not running — the lock teardown is neutralized.");
    }
    Ok(())
}

/// Scan fctctld's log for the most recent ipsec event + assigned internal IP.
fn fctctl_status() -> (Option<String>, Option<String>) {
    let text = match fs::read_to_string(FCTCTL_LOG) {
        Ok(t) => t,
        Err(_) => return (None, None),
    };
    let mut last_event = None;
    let mut vpnip = None;
    for line in text.lines() {
        if (line.contains("Ipsec phase2") && line.contains("established"))
            || line.contains("Close ipsec connection")
            || line.contains("Received racoon error report")
        {
            last_event = Some(summarize_log(line));
        }
        if let Some(idx) = line.find("Internal Addr4:") {
            let v = line[idx + "Internal Addr4:".len()..].trim();
            if !v.is_empty() {
                vpnip = Some(v.to_string());
            }
        }
    }
    (last_event, vpnip)
}

/// "20261005 10:12:41.091 TZ=-0700 [ipsec:INFO] ipsec_control:1196 <msg>" → "10:12:41  <msg>".
fn summarize_log(line: &str) -> String {
    let ts = line.split_whitespace().nth(1).unwrap_or("?");
    let msg = line
        .rsplit_once("ipsec_control:")
        .map(|(_, rest)| rest.splitn(2, ' ').nth(1).unwrap_or(rest).trim())
        .unwrap_or_else(|| line.trim());
    format!("{ts}  {msg}")
}

fn iface_has_ip(ip: &str) -> bool {
    Command::new("ifconfig")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(ip))
        .unwrap_or(false)
}

// ───────────────────────────── dump-profile (diagnostic) ────────────────────

/// Print a profile's fields with every `Enc …` value redacted and classified
/// (PSK-like / saved-username / email-like / undecryptable). Safe to share: no
/// secret values are printed. Helps locate where a machine actually stores the
/// PSK when `AuthInfo` turns out to be the saved username.
pub fn dump_profile(args: &[String]) -> Result<(), Box<dyn Error>> {
    let name = crate::profile::resolve_profile(arg_val(args, "--profile"));
    let p = crate::profile::Profile::load(&name)?;

    println!("open-forticlient profile dump\n");
    println!(
        "  FortiClient version: {}",
        run_trimmed(
            "defaults",
            &["read", "/Applications/FortiClient.app/Contents/Info.plist", "CFBundleShortVersionString"],
        )
        .unwrap_or_else(|| "unknown".into())
    );
    println!("  profile: {name:?}\n");

    let out = Command::new("plutil")
        .args(["-p", "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist"])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let header = format!("\"{name}\" => {{");

    let mut in_block = false;
    for line in text.lines() {
        if !in_block {
            if line.starts_with("    \"") && line.contains(&header) {
                in_block = true;
            }
            continue;
        }
        if line == "    }" {
            break;
        }
        let Some(rest) = line.strip_prefix("      \"") else {
            continue;
        };
        let Some((key, val)) = rest.split_once("\" => ") else {
            continue;
        };
        let val = val.trim();
        let is_enc = val
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .map(|v| v.starts_with("Enc "))
            .unwrap_or(false);
        if is_enc {
            let enc = val.trim_matches('"');
            println!("  {key} = Enc <redacted>  ->  {}", classify_enc(enc, &p.user));
        } else {
            println!("  {key} = {val}");
        }
    }
    Ok(())
}

fn classify_enc(enc: &str, user: &str) -> String {
    match crate::fctcrypt::decrypt_enc(enc) {
        None => "did NOT decrypt (a different FortiClient build can change the Enc scheme)".into(),
        Some(d) if !user.is_empty() && d == *user => {
            "saved username (equals the profile's User) — NOT the PSK".into()
        }
        Some(d) if d.contains('@') => "email-like — NOT the PSK".into(),
        Some(d) => format!("PSK-like: a {}-char key (oftc would use this)", d.len()),
    }
}
