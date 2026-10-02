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
use std::io::Write;
use std::process::Command;

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
    check(
        "plaintext PSK configured",
        crate::profile::plaintext_psk_override().is_some(),
        "set $FORTIGATE_PSK, a .env FORTIGATE_PSK=…, or ~/.config/oftc/psk",
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
    if !proc_running("FortiTray") {
        println!("[ ok ] FortiTray is not running — the lock teardown is already neutralized.");
        println!("       If it returns after login/reboot, re-run `oftc doctor`.");
        return Ok(());
    }

    println!("[WARN] FortiTray is RUNNING. It DISCONNECTs the VPN on every screen lock.");
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
