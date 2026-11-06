//! The wire types of the UI edge (`docs/ui-edge.md`, sections 4 and 5): what the
//! host serves on its local socket and what the CLI client and the Swift UI decode.
//!
//! One crate shared by the server, the CLI client and the tests, so the contract has
//! one definition. `tests/golden/*.json` pin every document byte-compatibly; the
//! Swift UI decodes the same files.
//!
//! Receivers ignore unknown fields. Unknown enum values decode to the variant marked
//! `#[serde(other)]` (`attention` for a connection state, "unavailable" elsewhere), so a
//! newer host never breaks an older reader within one protocol number.
#![forbid(unsafe_code)]

mod time;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use time::rfc3339;

/// The newest protocol number this crate speaks; also the `schema` of the status
/// document.
pub const PROTOCOL: u32 = 1;
/// The oldest protocol number the host still serves.
pub const PROTOCOL_MIN: u32 = 1;
/// At most this many bytes in one line, newline excluded; a longer line closes the
/// connection.
pub const MAX_LINE: usize = 64 * 1024;
/// The socket's file name, in the host's per-user directory
/// (`~/Library/Application Support/<bundle id>/`). The server binds it and the CLI
/// connects to it.
pub const SOCKET_FILE: &str = "host.sock";
/// Connections the host serves at once.
pub const MAX_CONNECTIONS: usize = 16;

/// Failure codes (4.7). `code` is the stable part; `detail` is for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ApprovalRequired,
    PskUnavailable,
    NotConfigured,
    AlreadyConfigured,
    MigrationNeeded,
    AgentUnavailable,
    HostUnavailable,
    UnsupportedSchema,
    TunnelsActive,
    Busy,
    UnknownOp,
    /// The arguments of a known op are missing or malformed (4.7: added by PR 3).
    BadRequest,
    /// A profile file or path the user named cannot be used.
    InvalidFile,
    /// The client asked for the op to stop (`cancel`).
    Cancelled,
    #[serde(other)]
    Internal,
}

impl ErrorCode {
    /// The process exit code the CLI uses for this failure: `2` usage, `3`
    /// configuration, `4` needs user action, `5` host unavailable or protocol
    /// mismatch, `6` busy, `1` anything else.
    pub fn exit(self) -> i32 {
        match self {
            ErrorCode::UnknownOp | ErrorCode::BadRequest => 2,
            ErrorCode::NotConfigured
            | ErrorCode::AlreadyConfigured
            | ErrorCode::MigrationNeeded
            | ErrorCode::TunnelsActive
            | ErrorCode::InvalidFile => 3,
            ErrorCode::ApprovalRequired | ErrorCode::PskUnavailable => 4,
            ErrorCode::AgentUnavailable
            | ErrorCode::HostUnavailable
            | ErrorCode::UnsupportedSchema => 5,
            ErrorCode::Busy => 6,
            ErrorCode::Internal | ErrorCode::Cancelled => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub detail: String,
    pub exit: i32,
    /// The profile the failure is about, for `already_configured` (the UI offers to
    /// select it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, detail: &str) -> ErrorBody {
        ErrorBody {
            code,
            detail: detail.to_owned(),
            exit: code.exit(),
            profile_id: None,
        }
    }

    pub fn for_profile(mut self, id: &str) -> ErrorBody {
        self.profile_id = Some(id.to_owned());
        self
    }
}

/// One request line: an integer `id`, an `op`, and the op's arguments.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    #[serde(flatten)]
    pub args: Map<String, Value>,
}

impl Request {
    /// `None` when the line is not a JSON object with an integer `id` and a string
    /// `op`; the server cannot answer such a line and closes the connection.
    pub fn parse(line: &[u8]) -> Option<Request> {
        serde_json::from_slice(line).ok()
    }

    /// The arguments as `T`, or `None` when they do not fit.
    pub fn args<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        serde_json::from_value(Value::Object(self.args.clone())).ok()
    }
}

/// `hello` arguments: the client's `[min, max]` protocol range.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HelloArgs {
    pub protocol: [u32; 2],
    pub client: Option<Client>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    pub kind: String,
    pub version: String,
    pub build: String,
}

/// `subscribe` arguments. Unknown topic names are ignored.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SubscribeArgs {
    pub topics: Vec<String>,
}

/// The `result` of `hello`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloResult {
    pub protocol: u32,
    pub host: HostBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostBlock {
    pub version: String,
    pub build: String,
    pub provider_build: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Checking,
    Ready,
    Missing,
    UpdateRequired,
    Approval,
    Newer,
    #[serde(other)]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub state: ComponentState,
    pub installed_build: Option<String>,
    pub expected_build: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginState {
    Enabled,
    Disabled,
    RequiresApproval,
    #[serde(other)]
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub menu_item: LoginState,
    pub agent: LoginState,
    pub host_agent: LoginState,
}

/// What a profile's row shows (`MenuConnectionState`, computed in the host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Disconnecting,
    SignIn,
    Reconnecting,
    Setup,
    #[serde(other)]
    Attention,
}

/// The raw NetworkExtension status, for support output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reasserting,
    Disconnecting,
    #[serde(other)]
    Invalid,
}

/// The supervisor's phase. `Unknown` is read, never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Acquiring,
    Connecting,
    Connected,
    Recovering,
    Failed,
    Stopped,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

/// One traffic measurement. Rates are bytes per second, `null` while unavailable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficSample {
    pub session: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: Option<f64>,
    pub tx_rate: Option<f64>,
    pub sample_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileError {
    pub code: ErrorCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub auto_start: bool,
    pub state: ConnectionState,
    pub ne_status: Option<NeStatus>,
    pub phase: Option<Phase>,
    pub connected_since: Option<String>,
    pub traffic: Option<TrafficSample>,
    pub error: Option<ProfileError>,
}

/// The status document: the `result` of `status` and the payload of `status` events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusDocument {
    pub schema: u32,
    pub generated: String,
    pub seq: u64,
    pub host: HostBlock,
    pub component: Component,
    pub login: Login,
    pub profiles: Vec<ProfileStatus>,
}

/// One profile as `profiles` lists it: the settings, nothing live.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub auto_start: bool,
}

/// The `result` of `profiles`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfilesResult {
    pub profiles: Vec<ProfileInfo>,
}

/// Server-to-client lines with no `id`, sent only after `subscribe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Status {
        seq: u64,
        status: StatusDocument,
    },
    Traffic {
        profile: String,
        #[serde(flatten)]
        sample: TrafficSample,
    },
}

/// `connect` and `disconnect`: one profile, or all of them without `profile`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProfileArgs {
    pub profile: Option<String>,
}

/// `remove`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RemoveArgs {
    pub profile: String,
}

/// `export`: the named profiles (all without `profiles`), written to `path`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ExportArgs {
    pub profiles: Option<Vec<String>>,
    pub path: String,
}

/// `import_preview` and `import`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PathArgs {
    pub path: String,
}

/// One profile of a `.oftc` file as `import_preview` shows it. The PSK is never part
/// of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreviewItem {
    pub name: String,
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub already_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreviewResult {
    pub profiles: Vec<PreviewItem>,
}

/// The `result` of `import`: the ids of the profiles this call created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportResult {
    pub added: Vec<String>,
}

/// Where `add_profile` gets the PSK. A typed PSK is stored first by the
/// `provision-psk --stdin` child (`saved`); it never crosses the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PskSource {
    Saved,
    Forticlient,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AddProfileArgs {
    pub gateway: String,
    pub saml_port: u32,
    pub transport: Transport,
    pub name: Option<String>,
    pub psk_source: PskSource,
    /// The FortiClient profile to take the PSK from, for `forticlient`.
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddProfileResult {
    pub profile_id: String,
}

/// One importable FortiClient profile. Never carries its PSK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub label: String,
    pub gateway: String,
    pub saml_port: u32,
    pub already_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourcesResult {
    pub sources: Vec<SourceInfo>,
}

/// `settings_set`: `menu_login` and `auto_update` take a boolean, `auto_start:<id>`
/// too.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SettingsArgs {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateOffer {
    pub version: String,
    pub page: String,
}

/// The `result` of `check_update`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateResult {
    pub available: Option<UpdateOffer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pane {
    Extensions,
    LoginItems,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PaneArgs {
    pub pane: Pane,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CancelArgs {
    pub target: u64,
}

/// The stages of `add_profile` and `component_update`; the UI owns the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Keychain,
    Profile,
    ExtensionApproval,
    VpnEntry,
    #[serde(other)]
    Other,
}

/// `running` has begun, `waiting` needs the user (not a failure), `done` finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Running,
    Waiting,
    Done,
    #[serde(other)]
    Unknown,
}

/// A progress line of request `id` (4.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub id: u64,
    pub event: ProgressTag,
    pub step: Step,
    pub state: StepState,
}

/// The constant `"progress"` of a progress line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressTag {
    Progress,
}

/// A progress line, without the newline.
pub fn progress_line(id: u64, step: Step, state: StepState) -> String {
    serde_json::to_string(&Progress {
        id,
        event: ProgressTag::Progress,
        step,
        state,
    })
    .unwrap_or_default()
}

#[derive(Serialize)]
struct Ok<'a, T: Serialize> {
    id: u64,
    ok: bool,
    result: &'a T,
}

#[derive(Serialize)]
struct Failed<'a> {
    id: u64,
    ok: bool,
    error: &'a ErrorBody,
}

/// A success reply line, without the newline.
pub fn reply_ok(id: u64, result: &impl Serialize) -> String {
    serde_json::to_string(&Ok {
        id,
        ok: true,
        result,
    })
    .unwrap_or_default()
}

/// A failure reply line, without the newline.
pub fn reply_err(id: u64, error: &ErrorBody) -> String {
    serde_json::to_string(&Failed {
        id,
        ok: false,
        error,
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4.7's table, one row per code: the exit code and the wire spelling.
    #[test]
    fn exit_codes_and_spellings() {
        use ErrorCode::*;
        for (code, name, exit) in [
            (ApprovalRequired, "approval_required", 4),
            (PskUnavailable, "psk_unavailable", 4),
            (NotConfigured, "not_configured", 3),
            (AlreadyConfigured, "already_configured", 3),
            (MigrationNeeded, "migration_needed", 3),
            (AgentUnavailable, "agent_unavailable", 5),
            (HostUnavailable, "host_unavailable", 5),
            (UnsupportedSchema, "unsupported_schema", 5),
            (TunnelsActive, "tunnels_active", 3),
            (Busy, "busy", 6),
            (UnknownOp, "unknown_op", 2),
            (BadRequest, "bad_request", 2),
            (InvalidFile, "invalid_file", 3),
            (Cancelled, "cancelled", 1),
            (Internal, "internal", 1),
        ] {
            assert_eq!(code.exit(), exit, "{name}");
            assert_eq!(serde_json::to_value(code).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<ErrorCode>(name.into()).unwrap(),
                code
            );
        }
        // A code from a newer host is "anything else".
        assert_eq!(
            serde_json::from_str::<ErrorCode>("\"from_the_future\"").unwrap(),
            Internal
        );
    }

    /// A line that cannot be answered is refused; arguments ride along beside `id`
    /// and `op`, and extra fields are ignored.
    #[test]
    fn request_lines() {
        let hello = Request::parse(
            br#"{"id":1,"op":"hello","protocol":[1,2],"client":{"kind":"ui","version":"0.9.0","build":"24"},"later":true}"#,
        )
        .unwrap();
        assert_eq!((hello.id, hello.op.as_str()), (1, "hello"));
        assert_eq!(hello.args::<HelloArgs>().unwrap().protocol, [1, 2]);
        for bad in [
            &br#"{"op":"status"}"#[..],
            br#"{"id":"1","op":"status"}"#,
            br#"{"id":-1,"op":"status"}"#,
            br#"{"id":1}"#,
            br#"[1,2]"#,
            b"not json",
        ] {
            assert_eq!(
                Request::parse(bad),
                None,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // Arguments that do not fit the op are `None`, not a panic.
        let broken = Request::parse(br#"{"id":2,"op":"hello","protocol":"1"}"#).unwrap();
        assert_eq!(broken.args::<HelloArgs>(), None);
    }

    #[test]
    fn reply_lines() {
        assert_eq!(
            reply_ok(7, &serde_json::json!({})),
            r#"{"id":7,"ok":true,"result":{}}"#
        );
        assert_eq!(
            reply_err(8, &ErrorBody::new(ErrorCode::Busy, "x")),
            r#"{"id":8,"ok":false,"error":{"code":"busy","detail":"x","exit":6}}"#
        );
    }
}
