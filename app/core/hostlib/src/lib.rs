//! The static library the Swift `OFTCAgent` links: one entry point, `oftc_host_main`.
//!
//! This is the only host crate with FFI `unsafe`. The verbs themselves are in
//! `oftc-host`; this crate composes the real backends around them.
#![cfg(target_os = "macos")]
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::{c_char, c_int, CStr};
use std::io::{stdin, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process;
use std::thread;

use oftc_apple::login::ServiceLoginItems;
use oftc_apple::manager::{NeVpnControl, StartKeys};
use oftc_apple::sysext::SystemExtensions;
use oftc_host::acquire::{random_session_id, SamlAcquirer, SystemClock};
use oftc_host::agent::SystemLaunchctl;
use oftc_host::commands::{run, Backends, FortiClientProfile, FortiClientProfiles, Io};
use oftc_host::env::HostEnv;
use oftc_host::keychain::SecKeychain;
use oftc_host::out::Out;
use oftc_host::registry::{forticlient_name_for_gateway, FORTICLIENT_VPN_PLIST};
use oftc_host::trust::{
    ChainProbe, ChildPrompt, OpensslChainSource, OpensslText, ProcessChild, Reviewer,
    SystemTrustEvaluator,
};
use oftc_host::supervisor::Presence;
use oftc_host::{OsSignals, TtyPrompt};
use oftc_provider::envelope::{LIVE_KEY, MODE_KEY, PREFLIGHT_KEY};
use zeroize::Zeroizing;

// The C entry the Swift setup window still calls. Re-exported so the symbols are
// in this one static library; `oftc-migration` is no longer linked on its own.
pub use oftc_migration::{oftc_migrate_free, oftc_migrate_profile_psk};

type CfRef = *const std::ffi::c_void;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CfRef;
    fn CGGetOnlineDisplayList(max: u32, displays: *mut u32, count: *mut u32) -> i32;
    fn CGDisplayIsAsleep(display: u32) -> u32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(object: CfRef);
    fn CFStringCreateWithCString(
        allocator: CfRef,
        text: *const std::ffi::c_char,
        encoding: u32,
    ) -> CfRef;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFBooleanGetValue(boolean: CfRef) -> u8;
}

const CF_UTF8: u32 = 0x0800_0100;

/// A boolean the session dictionary holds under `key`, if it holds one.
fn session_flag(session: CfRef, key: &std::ffi::CStr) -> Option<bool> {
    // SAFETY: `key` is NUL-terminated; the string it makes is released below, and the
    // value is borrowed from `session`, which the caller keeps alive for the call.
    unsafe {
        let name = CFStringCreateWithCString(std::ptr::null(), key.as_ptr(), CF_UTF8);
        if name.is_null() {
            return None;
        }
        let value = CFDictionaryGetValue(session, name);
        CFRelease(name);
        (!value.is_null()).then(|| CFBooleanGetValue(value) != 0)
    }
}

/// Whether the displays are known to be all asleep: the list call worked, at least
/// one display is online, and every one reports asleep. When that cannot be
/// determined (an error, or no display at all, as on a headless Mac) the user is
/// assumed able to answer, so recovery is never held for good.
fn all_displays_asleep(status: i32, asleep: &[bool]) -> bool {
    status == 0 && !asleep.is_empty() && asleep.iter().all(|asleep| *asleep)
}

fn displays_asleep() -> bool {
    let mut displays = [0u32; 16];
    let mut count = 0u32;
    // SAFETY: `displays` has room for the 16 ids we ask for and `count` is a valid
    // out-pointer.
    let status = unsafe { CGGetOnlineDisplayList(16, displays.as_mut_ptr(), &mut count) };
    let online = &displays[..(count as usize).min(16)];
    // SAFETY: takes a display id by value.
    let asleep: Vec<bool> = online
        .iter()
        .map(|display| unsafe { CGDisplayIsAsleep(*display) } != 0)
        .collect();
    all_displays_asleep(status, &asleep)
}

/// Whether the user could answer a browser sign-in now: a display is awake
/// and the console session is this user's, logged in and not locked. A dark wake
/// (network up, display off) and the login window both read false.
struct OsPresence;

impl Presence for OsPresence {
    fn can_answer(&self) -> bool {
        if displays_asleep() {
            return false;
        }
        // SAFETY: returns a retained dictionary or null.
        let session = unsafe { CGSessionCopyCurrentDictionary() };
        if session.is_null() {
            return false;
        }
        let on_console = session_flag(session, c"kCGSSessionOnConsoleKey");
        let locked = session_flag(session, c"CGSSessionScreenIsLocked");
        // SAFETY: `session` is a live Core Foundation object we own.
        unsafe { CFRelease(session) };
        on_console == Some(true) && locked != Some(true)
    }
}

/// Whether a user is logged in to a GUI session, so a window can be shown. The
/// supervisor started by a login agent before login has nobody to ask.
fn has_gui_session() -> bool {
    // SAFETY: returns a retained dictionary or null; a non-null one is released here.
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return false;
    }
    // SAFETY: `session` is a live Core Foundation object we own.
    unsafe { CFRelease(session) };
    true
}

/// The installed FortiClient's profiles, through `oftc-migration`.
struct InstalledFortiClient;

impl FortiClientProfiles for InstalledFortiClient {
    fn import(&self, name: &str) -> Option<FortiClientProfile> {
        let imported = oftc_migration::import_profile(name)?;
        Some(FortiClientProfile {
            gateway: imported.gateway,
            saml_port: imported.saml_port,
            psk: imported.psk,
        })
    }

    fn psk(&self, name: &str, gateway: &str) -> Option<Zeroizing<Vec<u8>>> {
        oftc_migration::migrate_psk(name, gateway)
    }
}

/// `sysexits.h` EX_SOFTWARE: a bug, as opposed to a command that failed.
const EXIT_INTERNAL: i32 = 70;

fn host_main(args: Vec<String>, bundle_id: &str) -> i32 {
    let mut out = Out::process();
    let code = match HostEnv::from_process(bundle_id) {
        Some(env) => {
            let keychain = SecKeychain::new(&env.keychain_service());
            let vpn = NeVpnControl::new(StartKeys {
                live: LIVE_KEY.to_owned(),
                preflight: PREFLIGHT_KEY.to_owned(),
                mode: MODE_KEY.to_owned(),
            });
            let clock = SystemClock::new();
            // Untrusted gateway certificates are shown by a short-lived child of this
            // executable: the supervisor's worker threads cannot build an AppKit window.
            let text = OpensslText;
            let source = OpensslChainSource::default();
            let diagnostic = |line: &str| {
                let _ = writeln!(std::io::stderr(), "{line}");
            };
            let probe = ChainProbe {
                source: &source,
                evaluator: &SystemTrustEvaluator { log: &diagnostic },
                text: &text,
            };
            let child = ProcessChild {
                executable: env.exe().map(Into::into).unwrap_or_default(),
            };
            let prompt = ChildPrompt {
                child: &child,
                has_gui_session: &has_gui_session,
            };
            let pin_dir = env.pin_dir();
            let reviewer = Reviewer {
                pin_dir: &pin_dir,
                probe: &probe,
                prompt: &prompt,
                text: &text,
            };
            let backends = Backends {
                keychain: &keychain,
                prompt: &TtyPrompt,
                forticlient: &InstalledFortiClient,
                legacy_name: &|gateway| {
                    forticlient_name_for_gateway(FORTICLIENT_VPN_PLIST.as_ref(), gateway)
                },
                vpn: &vpn,
                acquirer: &SamlAcquirer,
                clock: &clock,
                session_id: &random_session_id,
                extensions: &SystemExtensions,
                login: &ServiceLoginItems,
                launchctl: &SystemLaunchctl,
                signals: &OsSignals,
                presence: &OsPresence,
                review: &|host, port, name| reviewer.review(host, port, name),
                diagnostic: &diagnostic,
            };
            let mut input = stdin().lock();
            let mut io = Io {
                stdin: &mut input,
                out: &mut out,
            };
            run(&args, &env, &backends, &mut io)
        }
        // No bundle identifier (or no home): what the Swift host answered with usage.
        None => {
            out.line(&oftc_host::commands::usage());
            2
        }
    };
    out.flush();
    code
}

/// Runs a host verb and exits the process with its code. Never returns.
///
/// `argv[0]` is the program name and is skipped. The verb runs on a worker thread
/// while the calling (main) thread serves the main queue, which the
/// NetworkExtension and SystemExtensions callbacks of later verbs need. A panic
/// becomes one line on stderr and exit 70; the app workspace must stay
/// `panic = "unwind"` for that to work.
///
/// # Safety
/// `argv` must point to `argc` valid NUL-terminated strings and `bundle_id` to a
/// valid NUL-terminated string; all are only read.
#[no_mangle]
pub unsafe extern "C" fn oftc_host_main(
    argc: c_int,
    argv: *const *const c_char,
    bundle_id: *const c_char,
) -> ! {
    let args: Vec<String> = (1..argc.max(0) as usize)
        // SAFETY: the caller guarantees `argc` valid strings at `argv`.
        .map(|i| {
            unsafe { CStr::from_ptr(*argv.add(i)) }
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    // SAFETY: the caller guarantees a valid string.
    let bundle_id = unsafe { CStr::from_ptr(bundle_id) }
        .to_string_lossy()
        .into_owned();
    // The default hook would print the panic message, which could carry anything.
    panic::set_hook(Box::new(|_| {}));
    thread::spawn(move || {
        let code = panic::catch_unwind(AssertUnwindSafe(|| host_main(args, &bundle_id)))
            .unwrap_or_else(|_| {
                let _ = writeln!(std::io::stderr(), "OFTC host internal error");
                EXIT_INTERNAL
            });
        process::exit(code)
    });
    dispatch2::dispatch_main()
}

#[cfg(test)]
mod tests {
    use super::all_displays_asleep;

    /// Hold only when displays exist and every one is asleep; any doubt lets the
    /// recovery run.
    #[test]
    fn only_all_online_displays_asleep_holds_the_recovery() {
        // (list status, each online display asleep?, hold)
        let rows: [(i32, &[bool], bool); 6] = [
            (0, &[], false),             // headless: no display to be asleep
            (-1, &[true, true], false),  // the call failed: unknown
            (0, &[true, false], false),  // one awake is enough
            (0, &[false], false),
            (0, &[true], true),
            (0, &[true, true], true),
        ];
        for (status, asleep, hold) in rows {
            assert_eq!(all_displays_asleep(status, asleep), hold, "{status} {asleep:?}");
        }
    }
}
