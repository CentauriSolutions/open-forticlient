//! The static library the Swift `OFTCAgent` links: one entry point, `oftc_host_main`.
//!
//! This is the only host crate with FFI `unsafe`. The verbs themselves are in
//! `oftc-host`; this crate composes the real backends around them.
#![cfg(target_os = "macos")]
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::{c_char, c_int, CStr, CString};
use std::io::{stdin, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process;
use std::thread;

use oftc_apple::login::{LoginItems, LoginStatus, ServiceLoginItems};
use oftc_apple::manager::{NeVpnControl, StartKeys};
use oftc_apple::sysext::SystemExtensions;
use oftc_host::acquire::{random_session_id, SamlAcquirer, SystemClock};
use oftc_host::agent::{agent_item, SystemLaunchctl};
use oftc_host::commands::{run, Backends, FortiClientProfile, FortiClientProfiles, Io};
use oftc_host::env::HostEnv;
use oftc_host::keychain::SecKeychain;
use oftc_host::out::Out;
use oftc_host::registry::{forticlient_name_for_gateway, FORTICLIENT_VPN_PLIST};
use oftc_host::trust::{
    ChainProbe, ChildPrompt, OpensslChainSource, OpensslText, ProcessChild, Reviewer,
    SystemTrustEvaluator,
};
use oftc_host::{OsSignals, TtyPrompt};
use oftc_provider::envelope::{LIVE_KEY, MODE_KEY, PREFLIGHT_KEY};
use zeroize::Zeroizing;

// The C entry the Swift setup window still calls. Re-exported so the symbols are
// in this one static library; `oftc-migration` is no longer linked on its own.
pub use oftc_migration::{oftc_migrate_free, oftc_migrate_profile_psk};

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> *const std::ffi::c_void;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(object: *const std::ffi::c_void);
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

/// The profile registry, per-profile supervisor phase and connect-at-login choice
/// as one JSON document (`oftc_host::snapshot`), for the menu to read in process
/// instead of decoding Rust's files itself. Returns a NUL-terminated string to free
/// with [`oftc_host_free`], or null when the bundle identifier or home is unusable.
///
/// # Safety
/// `bundle_id` must point to a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn oftc_host_snapshot_json(bundle_id: *const c_char) -> *mut c_char {
    // SAFETY: the caller guarantees a valid string.
    let bundle_id = unsafe { CStr::from_ptr(bundle_id) }.to_string_lossy();
    // A panic must not unwind into Swift.
    panic::catch_unwind(|| {
        let env = HostEnv::from_process(&bundle_id)?;
        let text = oftc_host::snapshot::json(
            env.root(),
            &|gateway| forticlient_name_for_gateway(FORTICLIENT_VPN_PLIST.as_ref(), gateway),
            &|| ServiceLoginItems.status(&agent_item()) == LoginStatus::Enabled,
            std::time::SystemTime::now(),
        );
        CString::new(text).ok()
    })
    .ok()
    .flatten()
    .map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Frees a string returned by [`oftc_host_snapshot_json`]. Null is ignored.
///
/// # Safety
/// `text` must be null or a pointer returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn oftc_host_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: the caller guarantees it came from `CString::into_raw` here.
        drop(unsafe { CString::from_raw(text) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The exported read function, called as Swift would: a temporary home holding
    /// one profile that did not adopt the original layout (so the real login-item
    /// status is never asked for), the string freed, and null for a missing bundle id.
    #[test]
    fn snapshot_round_trips_through_the_c_functions() {
        let home = std::env::temp_dir().join(format!("oftc-hostlib-{}", std::process::id()));
        let profile = home.join("Library/Application Support/com.example.oftc/profiles/lab");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(
            profile.join("profile.json"),
            r#"{"gateway":"lab.example.com","samlPort":8443,"transport":"tcp","version":1}"#,
        )
        .unwrap();
        std::env::set_var("HOME", &home);
        let bundle = CString::new("com.example.oftc").unwrap();
        // SAFETY: valid strings; the result is freed once.
        let text = unsafe {
            let raw = oftc_host_snapshot_json(bundle.as_ptr());
            assert!(!raw.is_null());
            let text = CStr::from_ptr(raw).to_str().unwrap().to_owned();
            oftc_host_free(raw);
            oftc_host_free(std::ptr::null_mut());
            text
        };
        assert_eq!(
            text,
            r#"{"profiles":[{"id":"lab","name":"lab.example.com","gateway":"lab.example.com","samlPort":8443,"transport":"tcp","adoptsUnkeyedVPNEntry":false,"phase":null,"connectAtLogin":false}]}"#
        );
        let empty = CString::new("").unwrap();
        // SAFETY: a valid string.
        assert!(unsafe { oftc_host_snapshot_json(empty.as_ptr()) }.is_null());
        let _ = std::fs::remove_dir_all(&home);
    }
}
