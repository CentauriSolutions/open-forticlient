//! The CLI as a client of the host's local socket (`docs/ui-edge.md`, section 5).
//!
//! One connection, one `hello`, one request, one reply. The wire types and the
//! error-to-exit-code table come from the `oftc-ui-edge` crate, the same one the
//! host serves them from.
//!
//! The caller decides what an unreachable host means: for the verbs that also have a
//! direct path it falls back to it, because a client that needs a server cannot be the
//! thing that starts and registers the server.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use oftc_ui_edge::{ErrorBody, ErrorCode, HelloResult, MAX_LINE, PROTOCOL, PROTOCOL_MIN};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::json;

/// How long the host has to answer one line.
/// The app's version and build, read from `app/Host/Info.plist` by build.rs.
pub const APP_VERSION: &str = env!("OFTC_APP_VERSION");
pub const APP_BUILD: &str = env!("OFTC_APP_BUILD");

/// What `oftc --version` prints.
pub fn version_line() -> String {
    format!("oftc {APP_VERSION} (build {APP_BUILD})")
}

pub const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// Lines without our id (events, late replies) tolerated before giving up.
const SKIPPED_LINES: usize = 64;

/// Why a call did not produce a result.
#[derive(Debug)]
pub enum Error {
    /// The handshake never completed: nothing is listening, the connection was closed
    /// or refused before `hello` was answered, or the host stayed silent. The direct
    /// path is still available.
    Unreachable(String),
    /// The host answered with a failure. `line` is that reply as it came.
    Host { body: ErrorBody, line: String },
    /// The host went away after the handshake.
    Lost(String),
    /// The host sent something this client cannot read, or chose a protocol it does
    /// not speak.
    Protocol(String),
}

/// A successful call: what `hello` said and the request's `result`, as sent.
#[derive(Debug)]
pub struct Reply {
    pub hello_result: String,
    pub result: String,
}

#[derive(Deserialize)]
struct Line<'a> {
    id: Option<u64>,
    ok: Option<bool>,
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    error: Option<ErrorBody>,
}

struct Connection {
    writer: UnixStream,
    reader: BufReader<Deadline>,
}

/// The read half, with one deadline for the whole exchange: every read, however many
/// a trickling host makes one line of, gets only the time that is left.
struct Deadline {
    stream: UnixStream,
    end: Instant,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

impl Connection {
    fn send(&mut self, request: &serde_json::Value) -> std::io::Result<()> {
        let mut line = request.to_string();
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
    }

    /// The next line that answers `id`. Lines with no `id` are events and are skipped.
    fn reply(&mut self, id: u64) -> Result<(String, Outcome), ReadError> {
        for _ in 0..SKIPPED_LINES {
            let mut buf = Vec::new();
            let read = (&mut self.reader)
                .take(MAX_LINE as u64 + 2)
                .read_until(b'\n', &mut buf)
                .map_err(ReadError::Io)?;
            if read == 0 {
                return Err(ReadError::Closed);
            }
            if buf.last() != Some(&b'\n') {
                // Too long for the protocol, or cut off by the close.
                return Err(if buf.len() > MAX_LINE {
                    ReadError::Garbled("a line longer than the protocol allows".into())
                } else {
                    ReadError::Closed
                });
            }
            buf.pop();
            let text = String::from_utf8(buf)
                .map_err(|_| ReadError::Garbled("a reply that is not UTF-8".into()))?;
            if text.trim().is_empty() {
                continue;
            }
            let parsed: Line = serde_json::from_str(&text)
                .map_err(|_| ReadError::Garbled("a line that is not a JSON object".into()))?;
            if parsed.id != Some(id) {
                continue;
            }
            let outcome = match (parsed.ok, parsed.result, parsed.error) {
                (Some(true), Some(result), _) => Outcome::Result(result.get().to_owned()),
                (Some(false), _, Some(body)) => Outcome::Failed(body),
                _ => return Err(ReadError::Garbled("a reply with neither result nor error".into())),
            };
            return Ok((text, outcome));
        }
        Err(ReadError::Garbled("no reply among the lines sent".into()))
    }
}

enum Outcome {
    Result(String),
    Failed(ErrorBody),
}

enum ReadError {
    Io(std::io::Error),
    Closed,
    Garbled(String),
}

impl ReadError {
    fn describe(&self) -> String {
        match self {
            ReadError::Io(error) => error.to_string(),
            ReadError::Closed => "the host closed the connection".into(),
            ReadError::Garbled(what) => format!("the host sent {what}"),
        }
    }
}

/// `sun_path` holds 104 bytes including its NUL.
const MAX_SOCKET_PATH: usize = 103;

/// Connects to `socket`, says `hello`, sends `op` (none: the handshake is the whole
/// call, and `result` is empty) and returns the result. `timeout` is the total for
/// the exchange after the connection is made.
///
/// There is no connect timeout: `connect(2)` on a Unix socket does not wait for the
/// peer to accept; it returns at once, or fails with `ECONNREFUSED` or `ENOENT`, and
/// only a full backlog (16 connections, then the host refuses) would block it.
pub fn call(socket: &Path, op: Option<&str>, timeout: Duration) -> Result<Reply, Error> {
    use std::os::unix::ffi::OsStrExt;
    let length = socket.as_os_str().as_bytes().len();
    if length > MAX_SOCKET_PATH {
        return Err(Error::Unreachable(format!(
            "path too long: the host socket path is {length} bytes, at most {MAX_SOCKET_PATH} fit"
        )));
    }
    let stream = UnixStream::connect(socket).map_err(|error| {
        Error::Unreachable(format!("could not connect to {}: {error}", socket.display()))
    })?;
    let setup = stream
        .set_write_timeout(Some(timeout))
        .and_then(|()| stream.try_clone());
    let writer = setup.map_err(|error| Error::Unreachable(error.to_string()))?;
    let mut connection = Connection {
        reader: BufReader::new(Deadline {
            stream,
            end: Instant::now() + timeout,
        }),
        writer,
    };

    let hello = json!({
        "id": 1, "op": "hello", "protocol": [PROTOCOL_MIN, PROTOCOL],
        "client": {"kind": "cli", "version": APP_VERSION, "build": APP_BUILD},
    });
    connection
        .send(&hello)
        .map_err(|error| Error::Unreachable(error.to_string()))?;
    let hello_result = match connection.reply(1) {
        Ok((_, Outcome::Result(result))) => result,
        Ok((line, Outcome::Failed(body))) => return Err(Error::Host { body, line }),
        Err(ReadError::Garbled(what)) => return Err(Error::Protocol(format!("the host sent {what}"))),
        // Closed, silent or broken before the handshake finished: not a usable host.
        Err(other) => return Err(Error::Unreachable(other.describe())),
    };
    let hello: HelloResult = serde_json::from_str(&hello_result)
        .map_err(|_| Error::Protocol("the host's hello is not one this oftc can read".into()))?;
    if hello.protocol < PROTOCOL_MIN || hello.protocol > PROTOCOL {
        return Err(Error::Protocol(format!(
            "the host chose protocol {}, this oftc speaks {PROTOCOL_MIN} to {PROTOCOL}",
            hello.protocol
        )));
    }

    let Some(op) = op else {
        return Ok(Reply {
            hello_result,
            result: String::new(),
        });
    };
    connection
        .send(&json!({"id": 2, "op": op}))
        .map_err(|error| Error::Lost(error.to_string()))?;
    match connection.reply(2) {
        Ok((_, Outcome::Result(result))) => Ok(Reply {
            hello_result,
            result,
        }),
        Ok((line, Outcome::Failed(body))) => Err(Error::Host { body, line }),
        Err(ReadError::Garbled(what)) => Err(Error::Protocol(format!("the host sent {what}"))),
        Err(other) => Err(Error::Lost(other.describe())),
    }
}

/// What the CLI reports for a failure: the exit code, the text for stderr, and the
/// JSON object `--json` prints.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub exit: i32,
    pub message: String,
    pub json: String,
}

fn synthetic(code: ErrorCode, detail: &str) -> (String, i32) {
    let body = ErrorBody::new(code, detail);
    let line = json!({"ok": false, "error": body}).to_string();
    (line, body.exit)
}

fn wire_name(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "internal".into())
}

/// Maps a failed call to its exit code (section 4.7): the host's own `exit`, and for
/// a failure that happened on this side `host_unavailable` or `unsupported_schema`.
pub fn failure(error: Error) -> Failure {
    match error {
        Error::Host { body, line } => {
            // A code from a newer host keeps the exit it came with; a failure never
            // exits 0.
            let exit = if (1..=255).contains(&body.exit) { body.exit } else { 1 };
            let message = if body.code == ErrorCode::Internal {
                "the OFTC host reported an internal error".to_owned()
            } else {
                format!("{}: {}", wire_name(body.code), body.detail)
            };
            Failure {
                exit,
                message,
                json: line,
            }
        }
        Error::Unreachable(why) | Error::Lost(why) => {
            let (json, exit) = synthetic(ErrorCode::HostUnavailable, &why);
            Failure {
                exit,
                message: format!("host_unavailable: {why}"),
                json,
            }
        }
        Error::Protocol(why) => {
            let (json, exit) = synthetic(ErrorCode::UnsupportedSchema, &why);
            Failure {
                exit,
                message: format!("unsupported_schema: {why}; update OFTC"),
                json,
            }
        }
    }
}

/// A stand-in host for tests: a Unix socket in a temp directory, never the real one.
#[cfg(test)]
pub(crate) mod testutil {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    pub const HELLO_REPLY: &str =
        include_str!("../../app/core/ui-edge/tests/golden/hello_reply.json");
    pub const STATUS: &str = include_str!("../../app/core/ui-edge/tests/golden/status.json");
    pub const PROFILES_REPLY: &str =
        include_str!("../../app/core/ui-edge/tests/golden/profiles_reply.json");
    pub const UNSUPPORTED: &str =
        include_str!("../../app/core/ui-edge/tests/golden/error_unsupported_schema.json");
    pub const EVENT_STATUS: &str =
        include_str!("../../app/core/ui-edge/tests/golden/event_status.json");

    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new() -> TempDir {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "oftc-cli-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        pub fn socket(&self) -> PathBuf {
            self.0.join("h.sock")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What the double does with one request line.
    pub enum Act {
        /// Sends these lines.
        Say(Vec<String>),
        /// Closes the connection.
        Close,
        /// Says nothing and keeps the connection open.
        Hang,
        /// Sends these bytes as they are (no newline is added).
        Raw(Vec<u8>),
        /// Sends one byte of a line that never ends, 40 times, 50 ms apart.
        Drip,
    }

    /// Serves one connection: each request line, parsed, goes to `handler`. Returns
    /// the request lines it saw, in order.
    pub fn serve(
        dir: &TempDir,
        handler: impl Fn(&serde_json::Value) -> Act + Send + 'static,
    ) -> Arc<Mutex<Vec<serde_json::Value>>> {
        let listener = UnixListener::bind(dir.socket()).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut writer = stream.try_clone().unwrap();
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { return };
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                log.lock().unwrap().push(request.clone());
                match handler(&request) {
                    Act::Say(lines) => {
                        for line in lines {
                            writeln!(writer, "{}", line.trim_end()).unwrap();
                        }
                    }
                    Act::Close => return,
                    Act::Hang => thread::sleep(Duration::from_secs(5)),
                    Act::Raw(bytes) => writer.write_all(&bytes).unwrap(),
                    Act::Drip => {
                        for _ in 0..40 {
                            if writer.write_all(b"x").is_err() {
                                return;
                            }
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            }
        });
        seen
    }

    /// Answers `hello` with the golden reply and any other op with `reply(id)`.
    pub fn host(
        dir: &TempDir,
        reply: impl Fn(u64) -> String + Send + 'static,
    ) -> Arc<Mutex<Vec<serde_json::Value>>> {
        serve(dir, move |request| {
            if request["op"] == "hello" {
                Act::Say(vec![HELLO_REPLY.to_owned()])
            } else {
                Act::Say(vec![reply(request["id"].as_u64().unwrap())])
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use oftc_ui_edge::{reply_ok, StatusDocument};

    const SHORT: Duration = Duration::from_millis(300);

    fn status_reply(id: u64) -> String {
        let document: StatusDocument = serde_json::from_str(STATUS).unwrap();
        reply_ok(id, &document)
    }

    /// The handshake and the request on the wire, and what comes back as sent.
    #[test]
    fn hello_then_the_op_and_the_results_as_sent() {
        let dir = TempDir::new();
        let seen = host(&dir, status_reply);
        let reply = call(&dir.socket(), Some("status"), REPLY_TIMEOUT).unwrap();
        assert_eq!(
            serde_json::from_str::<StatusDocument>(&reply.result).unwrap(),
            serde_json::from_str::<StatusDocument>(STATUS).unwrap()
        );
        assert_eq!(
            reply.hello_result,
            r#"{"protocol":1,"host":{"version":"0.9.0","build":"24","provider_build":"24"}}"#
        );
        let seen = seen.lock().unwrap();
        assert_eq!(
            *seen,
            [
                serde_json::json!({"id":1,"op":"hello","protocol":[1,1],
                    "client":{"kind":"cli","version":APP_VERSION,"build":APP_BUILD}}),
                serde_json::json!({"id":2,"op":"status"}),
            ]
        );
    }

    /// Both ways a path can have no host behind it, and the two ways a host can fail
    /// the handshake without saying why, leave the direct path open.
    #[test]
    fn no_handshake_means_unreachable() {
        let dir = TempDir::new();
        // ENOENT: no socket at all.
        let missing = call(&dir.socket(), Some("status"), SHORT);
        assert!(matches!(missing, Err(Error::Unreachable(_))), "{missing:?}");
        // ECONNREFUSED: a socket file whose server is gone (a crash leaves one).
        drop(std::os::unix::net::UnixListener::bind(dir.socket()).unwrap());
        let refused = call(&dir.socket(), Some("status"), SHORT);
        assert!(matches!(refused, Err(Error::Unreachable(_))), "{refused:?}");
        std::fs::remove_file(dir.socket()).unwrap();
        // Closed without a word: the host's peer check does this.
        let dir = TempDir::new();
        serve(&dir, |_| Act::Close);
        let got = call(&dir.socket(), Some("status"), SHORT);
        assert!(matches!(got, Err(Error::Unreachable(_))), "{got:?}");
    }

    /// Runs `call` on a thread so that a missing deadline fails the test (after
    /// `limit`) instead of hanging it.
    fn call_within(dir: &TempDir, timeout: Duration, limit: Duration) -> Result<Reply, Error> {
        let (done, result) = std::sync::mpsc::channel();
        let socket = dir.socket();
        std::thread::spawn(move || {
            let _ = done.send(call(&socket, Some("status"), timeout));
        });
        result.recv_timeout(limit).expect("call outlived its deadline")
    }

    /// One deadline covers the whole exchange: a host that is silent, and one that
    /// keeps a line going a byte at a time, are both given up on in time.
    #[test]
    fn a_silent_or_dripping_host_hits_the_total_deadline() {
        for act in [|_: &_| Act::Hang, |_: &_| Act::Drip] {
            let dir = TempDir::new();
            serve(&dir, act);
            let got = call_within(&dir, SHORT, Duration::from_secs(3));
            assert!(matches!(got, Err(Error::Unreachable(_))), "{got:?}");
        }
    }

    /// More than the protocol's 64 KiB with no newline is refused, as the host does
    /// to a client: unsupported_schema, exit 5.
    #[test]
    fn an_oversized_line_is_refused() {
        let dir = TempDir::new();
        serve(&dir, |_| Act::Raw(vec![b'x'; oftc_ui_edge::MAX_LINE + 100]));
        let error = call_within(&dir, REPLY_TIMEOUT, Duration::from_secs(5)).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
        let failure = failure(error);
        assert_eq!(failure.exit, 5);
        assert!(failure.json.contains(r#""code":"unsupported_schema""#));
    }

    /// A path `sun_path` cannot hold is named, not reported as an OS error.
    #[test]
    fn a_path_too_long_for_a_socket_is_named() {
        let long = Path::new("/tmp").join("x".repeat(MAX_SOCKET_PATH));
        let Err(Error::Unreachable(why)) = call(&long, None, SHORT) else {
            panic!("expected unreachable");
        };
        assert!(why.starts_with("path too long"), "{why}");
    }

    /// A version mismatch is the host's answer, not an absence: it is reported with
    /// the host's own line and exit code, and nothing falls back.
    #[test]
    fn unsupported_schema_is_the_hosts_failure_with_its_line() {
        let dir = TempDir::new();
        serve(&dir, |_| Act::Say(vec![UNSUPPORTED.to_owned()]));
        let error = call(&dir.socket(), Some("status"), REPLY_TIMEOUT).unwrap_err();
        let Error::Host { body, line } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(body.code, ErrorCode::UnsupportedSchema);
        assert_eq!(line.as_str(), UNSUPPORTED.trim_end());
        let failure = failure(error);
        assert_eq!((failure.exit, failure.json.as_str()), (5, UNSUPPORTED.trim_end()));
    }

    /// A host that picks a protocol outside what we offered is refused on our side.
    #[test]
    fn a_protocol_we_did_not_offer_is_unsupported_schema() {
        let dir = TempDir::new();
        serve(&dir, |_| {
            Act::Say(vec![
                r#"{"id":1,"ok":true,"result":{"protocol":9,"host":{"version":"1","build":"1","provider_build":"1"}}}"#.into(),
            ])
        });
        let failure = failure(call(&dir.socket(), Some("status"), REPLY_TIMEOUT).unwrap_err());
        assert_eq!(failure.exit, 5);
        assert!(failure.message.starts_with("unsupported_schema:"), "{}", failure.message);
        assert!(failure.json.contains(r#""code":"unsupported_schema""#));
    }

    /// Events and strangers' ids are skipped; a line that is not an object is refused.
    #[test]
    fn lines_without_our_id_are_skipped_and_garbage_is_refused() {
        let dir = TempDir::new();
        serve(&dir, |request| {
            Act::Say(if request["op"] == "hello" {
                vec![EVENT_STATUS.to_owned(), HELLO_REPLY.to_owned()]
            } else {
                vec![r#"{"id":9,"ok":true,"result":{}}"#.into(), status_reply(2)]
            })
        });
        assert!(call(&dir.socket(), Some("status"), REPLY_TIMEOUT).is_ok());

        let dir = TempDir::new();
        host(&dir, |_| "not json".into());
        let error = call(&dir.socket(), Some("status"), REPLY_TIMEOUT).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)), "{error:?}");
    }

    /// Once the handshake is done a vanished host is a failed request (exit 5), not
    /// an absent host: the caller must not quietly redo it another way.
    #[test]
    fn a_drop_after_hello_is_lost_not_unreachable() {
        let dir = TempDir::new();
        serve(&dir, |request| {
            if request["op"] == "hello" {
                Act::Say(vec![HELLO_REPLY.to_owned()])
            } else {
                Act::Close
            }
        });
        let error = call(&dir.socket(), Some("status"), REPLY_TIMEOUT).unwrap_err();
        assert!(matches!(error, Error::Lost(_)), "{error:?}");
        let failure = failure(error);
        assert_eq!(failure.exit, 5);
        assert!(failure.json.contains(r#""code":"host_unavailable""#));
    }

    /// The host's `exit` wins, also for a code from a newer host; a failure never
    /// exits 0; `internal`'s detail is not shown.
    #[test]
    fn failure_follows_the_hosts_exit_and_hides_internal_detail() {
        let from = |code: &str, exit: i32| {
            let line = format!(
                r#"{{"id":2,"ok":false,"error":{{"code":"{code}","detail":"secret path","exit":{exit}}}}}"#
            );
            let body = serde_json::from_str::<serde_json::Value>(&line).unwrap()["error"].clone();
            failure(Error::Host {
                body: serde_json::from_value(body).unwrap(),
                line,
            })
        };
        assert_eq!(from("busy", 6).exit, 6);
        assert_eq!(from("from_the_future", 7).exit, 7);
        assert_eq!(from("busy", 0).exit, 1);
        assert_eq!(from("approval_required", 4).message, "approval_required: secret path");
        let internal = from("internal", 1);
        assert!(!internal.message.contains("secret"), "{}", internal.message);
    }
}
