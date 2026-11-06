//! Every golden document decodes into the typed form and encodes back to the same
//! JSON, so the types and the files cannot drift. The Swift UI decodes the same files.

use oftc_ui_edge::*;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

fn round_trips<T: DeserializeOwned + Serialize>(file: &str) -> T {
    let path = format!("{}/tests/golden/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    let wire: Value = serde_json::from_str(&text).unwrap();
    let typed: T = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), wire, "{file}");
    typed
}

#[test]
fn status_documents() {
    let status: StatusDocument = round_trips("status.json");
    assert_eq!(status.profiles[0].state, ConnectionState::Connected);
    assert_eq!(status.profiles[1].state, ConnectionState::SignIn);
    assert_eq!(status.profiles[1].phase, Some(Phase::Acquiring));
    assert_eq!(status.profiles[0].error, None);
    let error = status.profiles[1].error.as_ref().unwrap();
    assert_eq!(error.code, oftc_ui_edge::ErrorCode::NetworkBlocked);
    assert!(error.detail.contains("UDP"));
    let Event::Status { seq, status } = round_trips("event_status.json") else {
        panic!("not a status event");
    };
    assert_eq!(
        (seq, status.component.state),
        (1772, ComponentState::Checking)
    );
    assert_eq!(status.login.host_agent, LoginState::NotFound);
}

#[test]
fn traffic_events_flatten_the_sample() {
    let Event::Traffic { profile, sample } = round_trips("event_traffic.json") else {
        panic!("not a traffic event");
    };
    assert_eq!((profile.as_str(), sample.sample_seq), ("c2", 13));
    assert_eq!(sample.tx_rate, None);
}

#[test]
fn replies() {
    let hello: Request = Request::parse(include_bytes!("golden/hello_request.json")).unwrap();
    assert_eq!(hello.args::<HelloArgs>().unwrap().protocol, [1, 1]);
    let wire = |file: &str| -> String {
        let text = std::fs::read_to_string(format!(
            "{}/tests/golden/{file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        text.trim().to_owned()
    };
    let result = HelloResult {
        protocol: 1,
        host: HostBlock {
            version: "0.9.0".into(),
            build: "24".into(),
            provider_build: "24".into(),
        },
    };
    assert_eq!(reply_ok(1, &result), wire("hello_reply.json"));
    assert_eq!(
        reply_err(
            1,
            &ErrorBody::new(ErrorCode::UnsupportedSchema, "host speaks protocol 1")
        ),
        wire("error_unsupported_schema.json")
    );
    // `profiles`: the reply line's result is the typed list.
    let line: Value = serde_json::from_str(&wire("profiles_reply.json")).unwrap();
    let listed: ProfilesResult = serde_json::from_value(line["result"].clone()).unwrap();
    assert_eq!(listed.profiles[0].id, "c2");
    assert_eq!(reply_ok(3, &listed), wire("profiles_reply.json"));
}

/// The PR 3 documents: requests decode into their argument types, results and
/// progress encode to exactly the pinned lines, and the error body carries
/// `profile_id` only when there is one.
#[test]
fn setup_documents() {
    let wire = |file: &str| -> String {
        std::fs::read_to_string(format!(
            "{}/tests/golden/{file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
        .trim()
        .to_owned()
    };
    let add = Request::parse(wire("add_profile_request.json").as_bytes()).unwrap();
    let args = add.args::<AddProfileArgs>().unwrap();
    assert_eq!(args.psk_source, PskSource::Forticlient);
    assert_eq!(args.label.as_deref(), Some("Example Office"));
    assert_eq!(args.transport, Transport::Udp);
    // A PSK source this protocol does not have does not decode.
    let odd = r#"{"id":1,"op":"add_profile","gateway":"g","saml_port":1,"transport":"udp","psk_source":"typed"}"#;
    assert_eq!(
        Request::parse(odd.as_bytes())
            .unwrap()
            .args::<AddProfileArgs>(),
        None
    );

    assert_eq!(
        progress_line(9, Step::ExtensionApproval, StepState::Waiting),
        wire("event_progress.json")
    );
    assert_eq!(
        reply_err(
            10,
            &ErrorBody::new(ErrorCode::AlreadyConfigured, "vpn.example.com is already set up")
                .for_profile("c2")
        ),
        wire("error_already_configured.json")
    );
    let preview = PreviewResult {
        profiles: vec![PreviewItem {
            name: "Office VPN".into(),
            gateway: "vpn.example.com".into(),
            saml_port: 9443,
            transport: Transport::Tcp,
            already_configured: true,
        }],
    };
    assert_eq!(reply_ok(11, &preview), wire("import_preview_reply.json"));
    let sources = SourcesResult {
        sources: vec![SourceInfo {
            label: "Example Office".into(),
            gateway: "vpn.example.com".into(),
            saml_port: 9443,
            already_configured: false,
        }],
    };
    assert_eq!(reply_ok(12, &sources), wire("list_sources_reply.json"));
    let update = UpdateResult {
        available: Some(UpdateOffer {
            version: "0.9.1".into(),
            page: "https://example.com/oftc/releases/tag/v0.9.1".into(),
        }),
    };
    assert_eq!(reply_ok(13, &update), wire("check_update_reply.json"));
}
