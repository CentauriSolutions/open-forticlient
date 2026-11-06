//! The socket ops against doubles: no real Network Extension, Keychain, launchd or
//! user directory. Each test pins behaviour no other one does.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use oftc_apple::manager::{VpnControl, VpnStatus};
use oftc_apple::sysext::{ExtensionEvent, ExtensionProperties, Finish};
use oftc_ui_edge::UpdateOffer;
use serde_json::{json, Value};

use super::tests::{me, settled, Client, Rig, FORTI_PSK};
use crate::keychain::Keychain;
use crate::profile::{Profile, Transport};
use crate::profile::testutil::TempDir;
use crate::registry;

/// Releases a held extension request when dropped, so a failed assertion cannot leave
/// the server waiting for a user who never comes.
struct Release<'a>(&'a Rig);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.extensions.release();
    }
}

/// Sends `line` and returns the progress lines of its id, then its reply.
fn op(client: &mut Client, line: &str) -> (Vec<Value>, Value) {
    let id = serde_json::from_str::<Value>(line).unwrap()["id"].clone();
    client.send(line);
    let mut progress = Vec::new();
    loop {
        let next = client.next().expect("a reply");
        if next["id"] != id {
            continue;
        }
        if next["event"] == "progress" {
            progress.push(json!([next["step"], next["state"]]));
        } else {
            return (progress, next);
        }
    }
}

fn error(reply: &Value) -> (&str, i64) {
    assert_eq!(reply["ok"], false, "{reply}");
    (
        reply["error"]["code"].as_str().unwrap(),
        reply["error"]["exit"].as_i64().unwrap(),
    )
}

fn ready(client: &mut Client) {
    client.hello();
    settled(client);
}

fn old_extension(rig: &Rig) {
    rig.extensions.mock.set_properties(
        &rig.env.provider_id(),
        Ok(vec![ExtensionProperties {
            short_version: "0.9".into(),
            build: "23".into(),
            enabled: true,
            awaiting_approval: false,
            uninstalling: false,
        }]),
    );
}

const ADD: &str = r#"{"id":9,"op":"add_profile","gateway":"vpn.example.com","saml_port":9443,"transport":"udp","name":"Office VPN","psk_source":"forticlient","label":"Example Office"}"#;

/// `connect` starts one supervisor for a disconnected profile and is idempotent: a
/// tunnel that is up, a sign-in that already holds the lease, and a missing PSK or entry
/// start nothing; each failure has its table code and exit code, and shows on the row
/// until the next op on that profile starts.
#[test]
fn connect_table() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let (_, reply) = op(&mut client, r#"{"id":2,"op":"connect","profile":"lab"}"#);
        assert_eq!(reply, json!({"id":2,"ok":true,"result":{}}));
        assert_eq!(*rig.spawner.ids.lock().unwrap(), ["lab"]);

        // Already up: still ok, nothing more started.
        rig.entry.set_status(VpnStatus::Connected);
        assert_eq!(op(&mut client, r#"{"id":3,"op":"connect"}"#).1["ok"], true);
        assert_eq!(rig.spawner.ids.lock().unwrap().len(), 1);

        // A supervisor that is still signing in holds the lease.
        rig.entry.set_status(VpnStatus::Disconnected);
        let lock = rig
            .env
            .root()
            .join("profiles/lab")
            .join(crate::lease::LOCK_FILE);
        let _lease = crate::lease::SupervisorLease::acquire(lock.parent().unwrap()).unwrap();
        assert_eq!(op(&mut client, r#"{"id":4,"op":"connect"}"#).1["ok"], true);
        assert_eq!(rig.spawner.ids.lock().unwrap().len(), 1);
        drop(_lease);

        // Failures: unknown profile, spawn failure, no PSK.
        let (_, reply) = op(&mut client, r#"{"id":5,"op":"connect","profile":"nope"}"#);
        assert_eq!(error(&reply), ("not_configured", 3));
        rig.spawner.fail.store(true, Ordering::SeqCst);
        let (_, reply) = op(&mut client, r#"{"id":6,"op":"connect","profile":"lab"}"#);
        assert_eq!(error(&reply), ("internal", 1));
        rig.spawner.fail.store(false, Ordering::SeqCst);
        rig.keychain.delete("lab.example.com").unwrap();
        let (_, reply) = op(&mut client, r#"{"id":7,"op":"connect","profile":"lab"}"#);
        assert_eq!(error(&reply), ("psk_unavailable", 4));
        assert_eq!(rig.spawner.ids.lock().unwrap().len(), 1);

        // The failure is on the row; connecting clears it.
        let status = client.call(r#"{"id":8,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["error"]["code"], "psk_unavailable");
        rig.keychain.set("lab.example.com", b"x").unwrap();
        assert_eq!(op(&mut client, r#"{"id":10,"op":"connect"}"#).1["ok"], true);
        let status = client.call(r#"{"id":11,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["error"], Value::Null);

        // A profile whose VPN entry is gone.
        rig.vpn
            .load_all()
            .unwrap()
            .iter()
            .for_each(|e| rig.vpn.remove(e).unwrap());
        let (_, reply) = op(&mut client, r#"{"id":12,"op":"connect","profile":"lab"}"#);
        assert_eq!(error(&reply), ("not_configured", 3));
    });
}

/// `disconnect` asks the supervisor and the tunnel to stop, and the row reads
/// `disconnecting` until the tunnel is down; stopping what is stopped succeeds.
#[test]
fn disconnect_shows_stopping_until_down() {
    let rig = Rig::new();
    rig.entry.set_status(VpnStatus::Connected);
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let (_, reply) = op(&mut client, r#"{"id":2,"op":"disconnect","profile":"lab"}"#);
        assert_eq!(reply["ok"], true);
        assert_eq!(rig.entry.stops(), 1);
        // The tunnel is still reported up by the system: the row says it is stopping.
        let status = client.call(r#"{"id":3,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["state"], "disconnecting");
        rig.entry.set_status(VpnStatus::Disconnected);
        let status = client.call(r#"{"id":4,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["state"], "disconnected");
        assert_eq!(
            op(&mut client, r#"{"id":5,"op":"disconnect"}"#).1["ok"],
            true
        );

        // A supervisor that cannot be told to stand down leaves the tunnel running:
        // the failure is shown on the row, which does not claim to be stopping.
        rig.entry.set_status(VpnStatus::Connected);
        let lock = rig
            .env
            .root()
            .join("profiles/lab")
            .join(crate::lease::LOCK_FILE);
        std::fs::write(&lock, "not a lease id").unwrap();
        let (_, reply) = op(&mut client, r#"{"id":6,"op":"disconnect","profile":"lab"}"#);
        assert_eq!(error(&reply), ("internal", 1));
        let status = client.call(r#"{"id":7,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["state"], "connected");
        assert_eq!(status["profiles"][0]["error"]["code"], "internal");
    });
}

/// `remove` stops the profile, waits for the tunnel, and erases its files, entry and
/// PSK; a tunnel that never comes down removes nothing (`tunnels_active`), and a
/// profile that is already gone is a success.
#[test]
fn remove_waits_then_erases() {
    let rig = Rig::new();
    rig.entry.set_status(VpnStatus::Connected);
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let (_, reply) = op(&mut client, r#"{"id":2,"op":"remove","profile":"lab"}"#);
        assert_eq!(error(&reply), ("tunnels_active", 3));
        // Nothing was removed and the row says why, not that it is disconnecting.
        let status = client.call(r#"{"id":20,"op":"status"}"#)["result"].clone();
        assert_eq!(status["profiles"][0]["state"], "connected");
        assert_eq!(status["profiles"][0]["error"]["code"], "tunnels_active");
        assert!(rig.keychain.get("lab.example.com").is_ok());
        assert_eq!(registry::entries(rig.env.root()).len(), 1);

        let entry = rig.entry.clone();
        *rig.on_pause.lock().unwrap() =
            Some(Box::new(move || entry.set_status(VpnStatus::Disconnected)));
        let (_, reply) = op(&mut client, r#"{"id":3,"op":"remove","profile":"lab"}"#);
        assert_eq!(reply, json!({"id":3,"ok":true,"result":{}}));
        assert!(registry::entries(rig.env.root()).is_empty());
        assert!(rig.keychain.get("lab.example.com").is_err());
        assert!(rig.vpn.load_all().unwrap().is_empty());
        assert_eq!(
            op(&mut client, r#"{"id":4,"op":"remove","profile":"lab"}"#).1["ok"],
            true
        );
    });
}

/// Export writes the bundle to the named file, mode 0600, and never over an existing
/// file; the PSKs are in the file and nowhere in any reply. Preview shows what the
/// file holds and which gateways are set up, import adds the others and is safe to
/// repeat, and a file that is not a bundle is `invalid_file`.
#[test]
fn files_round_trip_without_leaking_psks() {
    let rig = Rig::new();
    let out = TempDir::new("export");
    let file = out.0.join("lab.oftc");
    let path = file.to_str().unwrap();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let line = format!(r#"{{"id":2,"op":"export","path":"{path}"}}"#);
        assert_eq!(
            op(&mut client, &line).1,
            json!({"id":2,"ok":true,"result":{}})
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_to_string(&file)
            .unwrap()
            .contains("lab-secret-psk"));
        let line = format!(r#"{{"id":3,"op":"export","path":"{path}"}}"#);
        assert_eq!(error(&op(&mut client, &line).1), ("bad_request", 2));
        let relative = op(&mut client, r#"{"id":4,"op":"export","path":"lab.oftc"}"#).1;
        assert_eq!(error(&relative), ("bad_request", 2));
        let line = format!(r#"{{"id":5,"op":"export","profiles":["nope"],"path":"{path}x"}}"#);
        assert_eq!(error(&op(&mut client, &line).1), ("not_configured", 3));

        // Preview: the profile is already configured; nothing carries a PSK.
        let line = format!(r#"{{"id":6,"op":"import_preview","path":"{path}"}}"#);
        let preview = op(&mut client, &line).1;
        assert_eq!(
            preview["result"]["profiles"],
            json!([{"name":"Lab","gateway":"lab.example.com","saml_port":8443,
                "transport":"tcp","already_configured":true}])
        );
        // Remove it locally and import: it comes back with a new id; again adds nothing.
        rig.keychain.delete("lab.example.com").unwrap();
        std::fs::remove_dir_all(rig.env.root().join("profiles/lab")).unwrap();
        let line = format!(r#"{{"id":7,"op":"import","path":"{path}"}}"#);
        assert_eq!(op(&mut client, &line).1["result"], json!({"added":["lab"]}));
        assert!(rig.keychain.get("lab.example.com").is_ok());
        let line = format!(r#"{{"id":8,"op":"import","path":"{path}"}}"#);
        assert_eq!(op(&mut client, &line).1["result"], json!({"added":[]}));

        let junk = out.0.join("junk.oftc");
        std::fs::write(&junk, b"not a bundle").unwrap();
        let line = format!(
            r#"{{"id":9,"op":"import_preview","path":"{}"}}"#,
            junk.display()
        );
        assert_eq!(error(&op(&mut client, &line).1), ("invalid_file", 3));
        let line = r#"{"id":10,"op":"import","path":"/nonexistent/x.oftc"}"#;
        assert_eq!(error(&op(&mut client, line).1), ("invalid_file", 3));
        for seen in &client.log {
            assert!(!seen.contains("lab-secret-psk"), "{seen}");
        }
    });
}

/// `add_profile` reports each step in order and creates the profile, the PSK from
/// FortiClient (copied inside the host) and the VPN entry; no line carries the PSK.
/// A setup that stopped at the system extension is finished by the next call (same
/// profile, no duplicate), and a finished one answers `already_configured` with the id.
#[test]
fn add_profile_is_resumable_and_idempotent() {
    let rig = Rig::new();
    old_extension(&rig);
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        // The extension request is refused (nothing scripted: it times out).
        let (progress, reply) = op(&mut client, ADD);
        assert_eq!(error(&reply), ("internal", 1));
        assert_eq!(
            progress,
            [
                json!(["keychain", "running"]),
                json!(["keychain", "done"]),
                json!(["profile", "running"]),
                json!(["profile", "done"]),
                json!(["extension_approval", "running"]),
            ]
        );
        assert_eq!(registry::entries(rig.env.root()).len(), 2);
        assert!(rig.keychain.get("vpn.example.com").is_ok());

        rig.extensions
            .mock
            .script_activate(vec![ExtensionEvent::NeedsApproval], Ok(Finish::Completed));
        let (progress, reply) = op(&mut client, ADD);
        assert_eq!(reply["result"], json!({"profile_id":"office-vpn"}));
        assert_eq!(
            progress[4..],
            [
                json!(["extension_approval", "running"]),
                json!(["extension_approval", "waiting"]),
                json!(["extension_approval", "done"]),
                json!(["vpn_entry", "running"]),
                json!(["vpn_entry", "done"]),
            ]
        );
        assert_eq!(registry::entries(rig.env.root()).len(), 2);

        let (progress, reply) = op(&mut client, ADD);
        assert_eq!(error(&reply), ("already_configured", 3));
        assert_eq!(reply["error"]["profile_id"], "office-vpn");
        assert_eq!(progress.len(), 3);
        for seen in &client.log {
            assert!(!seen.contains(FORTI_PSK), "{seen}");
        }
    });
}

/// Arguments the profile rules refuse are `bad_request` before anything is touched; a
/// `saved` PSK that was never stored is `psk_unavailable`; an unknown PSK source does
/// not decode.
#[test]
fn add_profile_refusals() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let bad = r#"{"id":2,"op":"add_profile","gateway":"","saml_port":9443,"transport":"udp","psk_source":"saved"}"#;
        assert_eq!(error(&op(&mut client, bad).1), ("bad_request", 2));
        let typed = r#"{"id":3,"op":"add_profile","gateway":"vpn.example.com","saml_port":9443,"transport":"udp","psk_source":"typed"}"#;
        assert_eq!(error(&op(&mut client, typed).1), ("bad_request", 2));
        let saved = r#"{"id":4,"op":"add_profile","gateway":"vpn.example.com","saml_port":9443,"transport":"udp","psk_source":"saved"}"#;
        let (progress, reply) = op(&mut client, saved);
        assert_eq!(error(&reply), ("psk_unavailable", 4));
        assert_eq!(progress, [json!(["keychain", "running"])]);
        assert_eq!(registry::entries(rig.env.root()).len(), 1);
    });
}

/// A second op on a key some op holds is `busy` at once (exit 6) and an op on another
/// key is unaffected. `cancel` answers the held op with `cancelled` immediately; the
/// system request ends later without a second answer and without finishing the setup,
/// and the key is then free again.
#[test]
fn busy_and_cancel() {
    let rig = Rig::new();
    old_extension(&rig);
    // The held request will succeed; only the cancel keeps the op from going on.
    rig.extensions
        .mock
        .script_activate(Vec::new(), Ok(Finish::Completed));
    rig.extensions.hold();
    rig.serving(&me, |socket| {
        let _release = Release(&rig);
        let mut first = Client::connect(socket);
        ready(&mut first);
        first.send(ADD);
        rig.extensions.wait_entered();
        let mut second = Client::connect(socket);
        ready(&mut second);
        let (_, reply) = op(&mut second, &ADD.replace("\"id\":9", "\"id\":2"));
        assert_eq!(error(&reply), ("busy", 6));
        assert_eq!(
            op(&mut second, r#"{"id":3,"op":"connect","profile":"lab"}"#).1["ok"],
            true
        );

        // The held op's own progress arrived; cancel answers it.
        let waiting = loop {
            let line = first.next().unwrap();
            if line["state"] == "waiting" {
                break line;
            }
        };
        assert_eq!(waiting["id"], 9);
        let (_, cancelled) = op(&mut first, r#"{"id":10,"op":"cancel","target":9}"#);
        assert_eq!(cancelled["ok"], true);
        // The target was answered `cancelled` (before the cancel's own reply).
        let answered = first
            .log
            .iter()
            .any(|l| l.contains(r#""id":9,"ok":false"#) && l.contains("cancelled"));
        assert!(answered, "{:?}", first.log);
        // Still busy while the system request is open.
        let (_, reply) = op(&mut second, &ADD.replace("\"id\":9", "\"id\":4"));
        assert_eq!(error(&reply), ("busy", 6));

        rig.extensions.release();
        // After the request ends the key frees; the op did not go on to the VPN entry.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (_, reply) = op(&mut second, &ADD.replace("\"id\":9", "\"id\":5"));
            if reply["error"]["code"] != "busy" {
                break;
            }
            assert!(Instant::now() < deadline, "key never freed");
            thread::sleep(Duration::from_millis(20));
        }
        // Nothing more arrived for the cancelled request.
        first
            .reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        assert_eq!(first.next(), None);
        let keys: Vec<Option<String>> = rig
            .vpn
            .load_all()
            .unwrap()
            .iter()
            .map(|e| e.profile_key.clone())
            .collect();
        assert_eq!(keys, [Some("lab".to_owned())], "the cancelled op went on");
    });
}

/// The keys of one op are taken together or not at all, and released when it ends.
#[test]
fn busy_keys_are_all_or_nothing() {
    let busy = super::ops::Busy::default();
    let a = busy
        .acquire(vec!["profile:a".into(), "profile:b".into()])
        .unwrap();
    let failure = busy
        .acquire(vec!["profile:c".into(), "profile:b".into()])
        .err()
        .unwrap();
    assert_eq!(failure.code, oftc_ui_edge::ErrorCode::Busy);
    // `c` was not left taken by the refused attempt.
    drop(busy.acquire(vec!["profile:c".into()]).unwrap());
    drop(a);
    drop(
        busy.acquire(vec!["profile:a".into(), "profile:b".into()])
            .unwrap(),
    );
}

/// `settings_set`: each key reaches its own store, a refused registration is typed
/// from the state it left, and anything else is `bad_request`.
#[test]
fn settings_table() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let set = |client: &mut Client, id: u32, key: &str, value: &str| {
            op(
                client,
                &format!(r#"{{"id":{id},"op":"settings_set","key":"{key}","value":{value}}}"#),
            )
            .1
        };
        assert_eq!(set(&mut client, 2, "auto_update", "false")["ok"], true);
        let stored = std::fs::read_to_string(rig.env.root().join("host-settings.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap(),
            json!({"auto_update":false})
        );

        assert_eq!(set(&mut client, 3, "auto_start:lab", "true")["ok"], true);
        let profiles = client.call(r#"{"id":4,"op":"profiles"}"#);
        assert_eq!(profiles["result"]["profiles"][0]["auto_start"], true);
        assert_eq!(
            rig.launchctl.calls().len(),
            1,
            "registering the agent clears an override"
        );

        for (id, key, value, code, exit) in [
            (5, "auto_start:nope", "true", "not_configured", 3),
            (6, "auto_start:lab", "\"yes\"", "bad_request", 2),
            (7, "volume", "true", "bad_request", 2),
        ] {
            assert_eq!(
                error(&set(&mut client, id, key, value)),
                (code, exit),
                "{key}"
            );
        }

        // The menu item registers, and leaves approval pending.
        rig.login.script_register(
            &oftc_apple::login::LoginItem::MainApp,
            Ok(oftc_apple::login::LoginStatus::RequiresApproval),
        );
        assert_eq!(
            error(&set(&mut client, 8, "menu_login", "true")),
            ("approval_required", 4)
        );
    });
}

/// `check_update`, `open_settings` and `list_sources` pass what their backends say:
/// an offer or none, the pane asked for, and FortiClient profiles marked when their
/// gateway is already set up, with nothing secret.
#[test]
fn update_settings_and_sources() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        assert_eq!(
            op(&mut client, r#"{"id":2,"op":"check_update"}"#).1["result"],
            json!({"available":null})
        );
        *rig.feed.0.lock().unwrap() = Ok(Some(UpdateOffer {
            version: "0.9.1".into(),
            page: "https://example.com/r".into(),
        }));
        assert_eq!(
            op(&mut client, r#"{"id":3,"op":"check_update"}"#).1["result"]["available"]["version"],
            "0.9.1"
        );
        *rig.feed.0.lock().unwrap() = Err(super::ops_update::FeedUnreachable);
        assert_eq!(error(&op(&mut client, r#"{"id":4,"op":"check_update"}"#).1), ("internal", 1));

        assert_eq!(op(&mut client, r#"{"id":5,"op":"open_settings","pane":"login_items"}"#).1["ok"], true);
        assert_eq!(rig.opener.0.lock().unwrap().len(), 1);
        let bad = op(&mut client, r#"{"id":6,"op":"open_settings","pane":"display"}"#).1;
        assert_eq!(error(&bad), ("bad_request", 2));

        let sources = op(&mut client, r#"{"id":7,"op":"list_sources"}"#).1;
        assert_eq!(
            sources["result"]["sources"],
            json!([{"label":"Example Office","gateway":"vpn.example.com","saml_port":9443,"already_configured":false}])
        );
        assert!(!client.log.iter().any(|l| l.contains(FORTI_PSK)));
    });
}

/// `component_update` is refused while any tunnel is up and touches no profile; when
/// the extension is old it activates it (progress `waiting` then `done`), and when it
/// is already current it asks the system for nothing. A profile with no saved PSK stops
/// it before the system is asked, naming that profile.
#[test]
fn component_update_rules() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let (progress, reply) = op(&mut client, r#"{"id":2,"op":"component_update"}"#);
        assert_eq!(reply["ok"], true);
        assert_eq!(
            progress,
            [
                json!(["keychain", "running"]),
                json!(["keychain", "done"]),
                json!(["extension_approval", "running"]),
                json!(["extension_approval", "done"]),
                json!(["vpn_entry", "running"]),
                json!(["vpn_entry", "done"]),
            ]
        );

        old_extension(&rig);
        rig.entry.set_status(VpnStatus::Connected);
        let (progress, reply) = op(&mut client, r#"{"id":3,"op":"component_update"}"#);
        assert_eq!(error(&reply), ("tunnels_active", 3));
        assert!(progress.is_empty());

        rig.entry.set_status(VpnStatus::Disconnected);
        rig.extensions
            .mock
            .script_activate(vec![ExtensionEvent::NeedsApproval], Ok(Finish::Completed));
        let (progress, reply) = op(&mut client, r#"{"id":4,"op":"component_update"}"#);
        assert_eq!(reply["ok"], true);
        assert_eq!(progress[3], json!(["extension_approval", "waiting"]));
        assert_eq!(registry::entries(rig.env.root()).len(), 1);

        rig.keychain.delete("lab.example.com").unwrap();
        let (progress, reply) = op(&mut client, r#"{"id":5,"op":"component_update"}"#);
        assert_eq!(error(&reply), ("psk_unavailable", 4));
        assert_eq!(reply["error"]["profile_id"], "lab");
        assert_eq!(progress, [json!(["keychain", "running"])]);
    });
}

/// Setup that stopped at the system extension leaves a profile with no VPN entry;
/// `component_update` finishes it with no form, so the UI needs no `add_profile` for a
/// VPN that already exists.
#[test]
fn component_update_installs_missing_vpn_entries() {
    let rig = Rig::new();
    old_extension(&rig);
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        assert_eq!(error(&op(&mut client, ADD).1), ("internal", 1));
        rig.extensions
            .mock
            .script_activate(vec![], Ok(Finish::Completed));
        let (_, reply) = op(&mut client, r#"{"id":3,"op":"component_update"}"#);
        assert_eq!(reply["ok"], true);
        let (_, again) = op(&mut client, ADD);
        assert_eq!(error(&again), ("already_configured", 3));
    });
}

/// The extension is already current but every VPN entry is gone (an uninstall, then a
/// reinstall): `component_update` must not stop at "ready", it recreates the entries.
#[test]
fn component_update_recreates_entries_when_the_component_is_ready() {
    let rig = Rig::new();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let profile = Profile::new("vpn.example.com", 9443, Transport::Udp, Some("Office VPN"), None).unwrap();
        crate::commands::save_profile(rig.env.root(), &profile, None).unwrap();
        rig.keychain.set("vpn.example.com", b"psk").unwrap();
        let (progress, reply) = op(&mut client, r#"{"id":3,"op":"component_update"}"#);
        assert_eq!(reply["ok"], true);
        assert_eq!(progress[4..], [json!(["vpn_entry", "running"]), json!(["vpn_entry", "done"])]);
        assert_eq!(error(&op(&mut client, ADD).1), ("already_configured", 3));
    });
}

/// A request id that is still running cannot be reused, and an op nobody knows is
/// `unknown_op` without closing the connection.
#[test]
fn request_ids_and_unknown_ops() {
    let rig = Rig::new();
    old_extension(&rig);
    rig.extensions.hold();
    rig.serving(&me, |socket| {
        let _release = Release(&rig);
        let mut client = Client::connect(socket);
        ready(&mut client);
        client.send(ADD);
        rig.extensions.wait_entered();
        client.send(&ADD.replace("vpn.example.com", "other.example.com"));
        let reuse = loop {
            let line = client.next().unwrap();
            if line["ok"].is_boolean() {
                break line;
            }
        };
        assert_eq!(error(&reuse), ("bad_request", 2));
        rig.extensions.release();
        // The held request ends with its own answer (the unscripted request fails).
        while client.next().unwrap()["id"] != 9 {}
        assert_eq!(
            client.call(r#"{"id":3,"op":"teleport"}"#)["error"]["code"],
            "unknown_op"
        );
    });
}

/// A `.oftc` file holding `gateway`, for the ops that read one.
fn bundle_file(dir: &TempDir, gateway: &str) -> String {
    let data = crate::bundle::encode(vec![crate::bundle::Item {
        gateway: gateway.to_owned(),
        name: "Imported".to_owned(),
        psk: zeroize::Zeroizing::new("psk-for-test".to_owned()),
        saml_port: 9443,
        transport: crate::profile::Transport::Udp,
    }])
    .unwrap();
    let path = dir.0.join(format!("{gateway}.oftc"));
    std::fs::write(&path, &*data).unwrap();
    path.to_str().unwrap().to_owned()
}

/// While `remove` runs, an `add_profile` or `import` of the same gateway is `busy`
/// (it could create a VPN entry for a profile being erased); the other way round, a
/// `remove` of a profile that an `add_profile` is finishing is `busy` too.
#[test]
fn remove_and_setup_exclude_each_other() {
    let rig = Rig::new();
    let files = TempDir::new("exclude");
    let lab_file = bundle_file(&files, "lab.example.com");
    rig.entry.set_status(VpnStatus::Connected);
    rig.serving(&me, |socket| {
        let mut remover = Client::connect(socket);
        ready(&mut remover);
        let other = std::sync::Mutex::new(Client::connect(socket));
        other.lock().unwrap().hello();
        let seen = std::sync::Mutex::new(Vec::new());
        let entry = rig.entry.clone();
        // At the first wait for the tunnel, try the same gateway from another client.
        *rig.on_pause.lock().unwrap() = Some(Box::new(move || {
            let mut client = other.lock().unwrap();
            let add = r#"{"id":2,"op":"add_profile","gateway":"lab.example.com","saml_port":8443,"transport":"tcp","psk_source":"saved"}"#;
            seen.lock().unwrap().push(op(&mut client, add).1);
            let import = format!(r#"{{"id":3,"op":"import","path":"{lab_file}"}}"#);
            seen.lock().unwrap().push(op(&mut client, &import).1);
            for reply in seen.lock().unwrap().iter() {
                assert_eq!(error(reply), ("busy", 6), "{reply}");
            }
            entry.set_status(VpnStatus::Disconnected);
        }));
        let (_, reply) = op(&mut remover, r#"{"id":4,"op":"remove","profile":"lab"}"#);
        assert_eq!(reply["ok"], true, "{reply}");
    });

    // The reverse: an add_profile stopped at the extension leaves a profile; while a
    // second call finishes it, removing that profile is busy.
    let rig = Rig::new();
    old_extension(&rig);
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        assert_eq!(error(&op(&mut client, ADD).1), ("internal", 1));
        rig.extensions.hold();
        let _release = Release(&rig);
        client.send(ADD);
        rig.extensions.wait_entered();
        let mut second = Client::connect(socket);
        ready(&mut second);
        let remove = r#"{"id":5,"op":"remove","profile":"office-vpn"}"#;
        assert_eq!(error(&op(&mut second, remove).1), ("busy", 6));
    });
}

/// Paths that are not plain files cannot hold a worker or be written through: a FIFO
/// is refused at once, and an export path that is a dangling symlink is not
/// followed.
#[test]
fn special_paths_are_refused() {
    let rig = Rig::new();
    let dir = TempDir::new("special");
    let fifo = dir.0.join("pipe.oftc");
    assert!(std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let target = dir.0.join("target.oftc");
    let link = dir.0.join("link.oftc");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    rig.serving(&me, |socket| {
        let mut client = Client::connect(socket);
        ready(&mut client);
        let line = format!(
            r#"{{"id":2,"op":"import_preview","path":"{}"}}"#,
            fifo.display()
        );
        assert_eq!(error(&op(&mut client, &line).1), ("invalid_file", 3));
        let line = format!(r#"{{"id":3,"op":"export","path":"{}"}}"#, link.display());
        assert!(op(&mut client, &line).1["ok"] == false);
        assert!(!target.exists(), "export wrote through a symlink");
    });
}

/// A connection runs at most 8 ops at once; and when it drops, its ops stop at their
/// next step instead of finishing a setup nobody is waiting for.
#[test]
fn flights_are_capped_and_stop_with_the_connection() {
    let rig = Rig::new();
    old_extension(&rig);
    rig.extensions
        .mock
        .script_activate(Vec::new(), Ok(Finish::Completed));
    rig.extensions.hold();
    rig.serving(&me, |socket| {
        let _release = Release(&rig);
        let mut client = Client::connect(socket);
        ready(&mut client);
        for n in 0..8 {
            let gateway = format!("gw{n}.example.com");
            rig.keychain.set(&gateway, b"psk").unwrap();
            let line = ADD.replace("vpn.example.com", &gateway).replace(
                r#""psk_source":"forticlient","label":"Example Office""#,
                r#""psk_source":"saved""#,
            );
            client.send(&line.replace("\"id\":9", &format!("\"id\":{}", 10 + n)));
        }
        rig.extensions.wait_entered();
        let ninth = ADD.replace("\"id\":9", "\"id\":30");
        client.send(&ninth);
        let reply = loop {
            let line = client.next().unwrap();
            if line["id"] == 30 && line["ok"].is_boolean() {
                break line;
            }
        };
        assert_eq!(error(&reply), ("busy", 6));
        // Drop the connection, then let the held request end.
        drop(client);
        rig.extensions.release();
        // Each worker ends after its extension step; none goes on to a VPN entry.
        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            assert_eq!(
                rig.vpn.load_all().unwrap().len(),
                1,
                "an op went on after its client left"
            );
            thread::sleep(Duration::from_millis(50));
        }
    });
}
