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
