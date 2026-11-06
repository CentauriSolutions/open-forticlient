//! One client connection: the handshake, the request loop and the event pusher.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use oftc_ui_edge::{
    progress_line, reply_err, reply_ok, CancelArgs, ErrorBody, ErrorCode, HelloArgs, HelloResult,
    HostBlock, Request, SubscribeArgs, PROTOCOL, PROTOCOL_MIN,
};

use super::collect::Collector;
use super::frame::{self, Line};
use super::hub::{Cursor, Hub, Topics};
use super::ops::{self, Busy, OpCx};
use super::Services;

/// A client that does not read for this long is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Ops one connection may have running at once.
const MAX_FLIGHTS: usize = 8;
/// At most one `status` event per this interval on one connection.
pub const STATUS_DEBOUNCE: Duration = Duration::from_millis(100);
/// How long a pusher sleeps with nothing to send before it looks again.
const IDLE: Duration = Duration::from_millis(250);

pub struct Shared<'a> {
    pub hub: &'a Hub,
    pub collector: &'a Collector<'a>,
    pub host: &'a HostBlock,
    pub hello_timeout: Duration,
    pub services: &'a Services<'a>,
    pub busy: &'a Busy,
}

/// A running op: whether `cancel` was asked, and whether its request has been
/// answered (by the op, or by `cancel` on its behalf, whichever came first).
#[derive(Default)]
struct Flight {
    cancel: AtomicBool,
    answered: AtomicBool,
}

/// The write half and its state, shared by the request loop and the pusher.
struct Conn {
    writer: Mutex<UnixStream>,
    /// A second handle on the socket, only to shut it down without the writer lock.
    handle: UnixStream,
    closed: AtomicBool,
    topics: Mutex<Topics>,
    /// Bumped by every `subscribe`, so a repeat subscription is owed the status again.
    epoch: AtomicU64,
    /// Where the newest subscription starts, taken before the sampler is woken so the
    /// first sample after subscribing is not mistaken for an old one.
    start: Mutex<Cursor>,
    /// Ops of this connection that have not ended, by request id.
    flights: Mutex<HashMap<u64, Arc<Flight>>>,
}

impl Conn {
    /// Sends the answer of a flight unless `cancel` already answered for it.
    fn answer(&self, flight: &Flight, line: &str) {
        if !flight.answered.swap(true, Ordering::SeqCst) {
            self.send(line);
        }
    }

    fn send(&self, line: &str) -> bool {
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let sent = writer
            .write_all(line.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .is_ok();
        drop(writer);
        if !sent {
            self.close();
        }
        sent
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.handle.shutdown(std::net::Shutdown::Both);
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

fn error(id: u64, code: ErrorCode, detail: &str) -> String {
    reply_err(id, &ErrorBody::new(code, detail))
}

/// The highest protocol both sides speak, if there is one.
fn negotiate(client: [u32; 2]) -> Option<u32> {
    let [min, max] = client;
    let chosen = max.min(PROTOCOL);
    // An inverted range (`min` above `max`) can never reach `chosen >= min`.
    (chosen >= min.max(PROTOCOL_MIN)).then_some(chosen)
}

/// Serves `stream` until it closes. The request loop runs on this thread, the pusher
/// on a second one that ends with it.
pub fn serve(stream: UnixStream, shared: &Shared) {
    let (Ok(reader), Ok(handle)) = (stream.try_clone(), stream.try_clone()) else {
        return;
    };
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let conn = Conn {
        writer: Mutex::new(stream),
        handle,
        closed: AtomicBool::new(false),
        topics: Mutex::new(Topics::default()),
        epoch: AtomicU64::new(0),
        start: Mutex::new(Cursor::default()),
        flights: Mutex::new(HashMap::new()),
    };
    // However this ends, the connection's topics stop counting as subscribers.
    let _subscribers = super::OnDrop(|| {
        let last = std::mem::take(&mut *conn.topics.lock().unwrap_or_else(PoisonError::into_inner));
        shared.hub.subscribed(last, Topics::default());
    });
    let (hello_done, hello_wait) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(|| push(&conn, shared.hub));
        // A total deadline for `hello`, not a timeout per read: a client that dribbles
        // a byte at a time must not keep a slot. Dropping the sender ends the wait.
        let conn = &conn;
        scope.spawn(move || {
            if hello_wait.recv_timeout(shared.hello_timeout) == Err(mpsc::RecvTimeoutError::Timeout)
            {
                conn.close();
            }
        });
        let _closed = super::OnDrop(|| {
            // Ops of a client that is gone stop at their next step.
            for flight in conn.flights.lock().unwrap_or_else(PoisonError::into_inner).values() {
                flight.cancel.store(true, Ordering::SeqCst);
            }
            conn.close();
            // The pusher may be asleep on the hub; it checks `closed` when it wakes.
            shared.hub.poke();
        });
        requests(scope, conn, BufReader::new(reader), shared, hello_done);
    });
}

fn requests<'scope, 'env>(
    scope: &'scope thread::Scope<'scope, 'env>,
    conn: &'env Conn,
    mut reader: BufReader<UnixStream>,
    shared: &'env Shared<'env>,
    hello_done: mpsc::Sender<()>,
) {
    let mut hello_done = Some(hello_done);
    let mut negotiated: Option<u32> = None;
    loop {
        let line = match frame::read_line(&mut reader) {
            Ok(Line::Complete(line)) if line.is_empty() => continue,
            Ok(Line::Complete(line)) => line,
            // Too long, closed, timed out, or broken: nothing to answer.
            _ => return,
        };
        // A line with no usable `id` and `op` cannot be answered.
        let Some(request) = Request::parse(&line) else {
            return;
        };
        let id = request.id;
        let Some(protocol) = negotiated else {
            if request.op != "hello" {
                conn.send(&error(id, ErrorCode::UnsupportedSchema, "hello first"));
                return;
            }
            let chosen = request
                .args::<HelloArgs>()
                .and_then(|h| negotiate(h.protocol));
            let Some(chosen) = chosen else {
                let detail = format!("host speaks protocol {PROTOCOL_MIN} to {PROTOCOL}");
                conn.send(&error(id, ErrorCode::UnsupportedSchema, &detail));
                return;
            };
            negotiated = Some(chosen);
            // Cancels the deadline: the receiver sees the sender go.
            drop(hello_done.take());
            let result = HelloResult {
                protocol: chosen,
                host: shared.host.clone(),
            };
            if !conn.send(&reply_ok(id, &result)) {
                return;
            }
            continue;
        };
        let reply = match request.op.as_str() {
            "hello" => reply_ok(
                id,
                &HelloResult {
                    protocol,
                    host: shared.host.clone(),
                },
            ),
            "status" => {
                shared.collector.refresh();
                match shared.hub.document() {
                    Some(document) => reply_ok(id, &document),
                    None => error(id, ErrorCode::Internal, "no status yet"),
                }
            }
            "profiles" => reply_ok(id, &shared.collector.profiles()),
            "subscribe" => match request.args::<SubscribeArgs>() {
                Some(args) => {
                    let topics = Topics {
                        status: args.topics.iter().any(|t| t == "status"),
                        traffic: args.topics.iter().any(|t| t == "traffic"),
                    };
                    // The reply goes out before the pusher may send the first event.
                    if !conn.send(&reply_ok(id, &serde_json::json!({}))) {
                        return;
                    }
                    shared.collector.refresh();
                    set_topics(conn, shared.hub, topics);
                    continue;
                }
                None => error(id, ErrorCode::UnknownOp, "subscribe needs topics"),
            },
            "unsubscribe" => {
                if !conn.send(&reply_ok(id, &serde_json::json!({}))) {
                    return;
                }
                set_topics(conn, shared.hub, Topics::default());
                continue;
            }
            "cancel" => match request.args::<CancelArgs>() {
                Some(args) => {
                    let flight = conn
                        .flights
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(&args.target)
                        .cloned();
                    // A target that is not running, or has ended, is already as cancelled
                    // as it can be.
                    if let Some(flight) = flight {
                        flight.cancel.store(true, Ordering::SeqCst);
                        conn.answer(&flight, &error(args.target, ErrorCode::Cancelled, "cancelled"));
                    }
                    reply_ok(id, &serde_json::json!({}))
                }
                None => error(id, ErrorCode::BadRequest, "cancel needs a target"),
            },
            other if ops::OPS.contains(&other) => {
                let flight = Arc::new(Flight::default());
                let mut flights = conn.flights.lock().unwrap_or_else(PoisonError::into_inner);
                if flights.contains_key(&id) {
                    drop(flights);
                    let reply = error(id, ErrorCode::BadRequest, "request id already running");
                    if !conn.send(&reply) {
                        return;
                    }
                    continue;
                }
                if flights.len() >= MAX_FLIGHTS {
                    drop(flights);
                    let reply = error(id, ErrorCode::Busy, "too many operations running");
                    if !conn.send(&reply) {
                        return;
                    }
                    continue;
                }
                flights.insert(id, flight.clone());
                drop(flights);
                // The worker answers when the op ends; a slow op blocks nothing else.
                scope.spawn(move || worker(conn, shared, request, &flight));
                continue;
            }
            other => error(id, ErrorCode::UnknownOp, &format!("unknown op {other}")),
        };
        if !conn.send(&reply) {
            return;
        }
    }
}

/// Runs one op and sends its answer. A panic in the op is an `internal` failure of
/// this request only.
fn worker(conn: &Conn, shared: &Shared, request: Request, flight: &Flight) {
    let id = request.id;
    let progress = |step, state| {
        if !flight.answered.load(Ordering::SeqCst) {
            conn.send(&progress_line(id, step, state));
        }
    };
    let cx = OpCx {
        services: shared.services,
        busy: shared.busy,
        collector: shared.collector,
        cancel: &flight.cancel,
        progress: &progress,
    };
    let line = match catch_unwind(AssertUnwindSafe(|| ops::run(&request, &cx))) {
        Ok(Some(Ok(result))) => reply_ok(id, &result),
        Ok(Some(Err(failure))) => reply_err(id, &failure.body()),
        Ok(None) => error(id, ErrorCode::UnknownOp, "unknown op"),
        Err(_) => error(id, ErrorCode::Internal, "internal failure"),
    };
    conn.answer(flight, &line);
    conn.flights
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
}

fn set_topics(conn: &Conn, hub: &Hub, topics: Topics) {
    let was = std::mem::replace(
        &mut *conn.topics.lock().unwrap_or_else(PoisonError::into_inner),
        topics,
    );
    *conn.start.lock().unwrap_or_else(PoisonError::into_inner) = hub.fresh_cursor();
    conn.epoch.fetch_add(1, Ordering::SeqCst);
    hub.subscribed(was, topics);
    hub.poke();
}

/// Sends what the connection is owed whenever the hub changes, until it closes.
fn push(conn: &Conn, hub: &Hub) {
    let mut cursor = hub.fresh_cursor();
    let mut seen = conn.epoch.load(Ordering::SeqCst);
    loop {
        if conn.closed() || hub.closing() {
            return;
        }
        let pokes = hub.pokes();
        let topics = *conn.topics.lock().unwrap_or_else(PoisonError::into_inner);
        let epoch = conn.epoch.load(Ordering::SeqCst);
        if epoch != seen {
            // A new subscription is owed the current status at once, and no old samples.
            cursor = *conn.start.lock().unwrap_or_else(PoisonError::into_inner);
            seen = epoch;
        }
        let mut sent_status = false;
        for event in hub.events_since(&mut cursor, topics) {
            sent_status |= matches!(event, oftc_ui_edge::Event::Status { .. });
            let Ok(line) = serde_json::to_string(&event) else {
                continue;
            };
            if !conn.send(&line) {
                return;
            }
        }
        if sent_status && hub.sleep(STATUS_DEBOUNCE) {
            return;
        }
        hub.wait_for_change(&cursor, topics, pokes, IDLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The overlap rule: the highest protocol both support, nothing when the ranges
    /// do not meet or the client's own range is inverted.
    #[test]
    fn protocol_negotiation() {
        for (client, chosen) in [
            ([1, 1], Some(1)),
            ([1, 5], Some(1)),
            ([0, 1], Some(1)),
            ([2, 3], None),
            ([0, 0], None),
            ([2, 1], None),
        ] {
            assert_eq!(negotiate(client), chosen, "{client:?}");
        }
    }
}
