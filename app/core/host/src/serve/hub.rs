//! The host's one in-memory status document and the latest traffic samples, with the
//! wake-ups that let each connection's pusher send only what changed.
//!
//! A connection never queues events: it remembers the newest `seq` and `sample_seq` it
//! sent and, when woken, sends the current document and the newest sample of each
//! profile if they are newer. A slow reader therefore costs the server nothing and
//! misses only intermediate states.

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oftc_apple::manager::VpnEntry;
use oftc_ui_edge::{ComponentState, Event, NeStatus, StatusDocument, TrafficSample};

pub struct Hub {
    state: Mutex<State>,
    changed: Condvar,
}

struct State {
    /// The newest document, with no `traffic` (that is overlaid when it is read).
    status: Option<StatusDocument>,
    /// The `sample_seq` of the newest sample; samples and status events share no counter.
    sample_seq: u64,
    samples: BTreeMap<String, TrafficSample>,
    subscribers: usize,
    traffic_subscribers: usize,
    entries: Vec<(String, VpnEntry)>,
    component: (ComponentState, Option<String>),
    component_checked: Option<Instant>,
    component_inflight: bool,
    pokes: u64,
    closing: bool,
}

/// What a connection has already been sent.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cursor {
    pub status_seq: u64,
    pub sample_seq: u64,
}

/// Which events a connection asked for.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Topics {
    pub status: bool,
    pub traffic: bool,
}

impl Default for Hub {
    fn default() -> Self {
        Hub::new()
    }
}

impl Hub {
    pub fn new() -> Hub {
        Hub {
            state: Mutex::new(State {
                status: None,
                sample_seq: 0,
                samples: BTreeMap::new(),
                subscribers: 0,
                traffic_subscribers: 0,
                entries: Vec::new(),
                component: (ComponentState::Checking, None),
                component_checked: None,
                component_inflight: false,
                pokes: 0,
                closing: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `document` as the newest if it differs from the current one in anything
    /// but `generated` and `seq`, numbering it one after the last. Returns whether it
    /// changed. Samples of profiles that are no longer connected are dropped with it.
    pub fn publish(&self, mut document: StatusDocument) -> bool {
        let mut state = self.lock();
        let connected: Vec<&str> = document
            .profiles
            .iter()
            .filter(|p| p.ne_status == Some(NeStatus::Connected))
            .map(|p| p.id.as_str())
            .collect();
        state
            .samples
            .retain(|id, _| connected.contains(&id.as_str()));
        let next = match &state.status {
            Some(previous) => {
                let mut same = document.clone();
                same.seq = previous.seq;
                same.generated = previous.generated.clone();
                if same == *previous {
                    return false;
                }
                previous.seq + 1
            }
            None => 1,
        };
        document.seq = next;
        state.status = Some(document);
        drop(state);
        self.changed.notify_all();
        true
    }

    /// The newest document with each connected profile's newest sample attached.
    pub fn document(&self) -> Option<StatusDocument> {
        Self::overlay(&self.lock())
    }

    fn overlay(state: &State) -> Option<StatusDocument> {
        let mut document = state.status.clone()?;
        for profile in &mut document.profiles {
            if profile.ne_status == Some(NeStatus::Connected) {
                profile.traffic = state.samples.get(&profile.id).cloned();
            }
        }
        Some(document)
    }

    /// The events a connection that has been sent `cursor` is owed, oldest first:
    /// the status document if it is newer, then the samples that are.
    pub fn events_since(&self, cursor: &mut Cursor, topics: Topics) -> Vec<Event> {
        let state = self.lock();
        let mut events = Vec::new();
        if topics.status {
            if let Some(document) = Self::overlay(&state) {
                if document.seq > cursor.status_seq {
                    cursor.status_seq = document.seq;
                    events.push(Event::Status {
                        seq: document.seq,
                        status: document,
                    });
                }
            }
        }
        if topics.traffic {
            let mut newer: Vec<(&String, &TrafficSample)> = state
                .samples
                .iter()
                .filter(|(_, sample)| sample.sample_seq > cursor.sample_seq)
                .collect();
            newer.sort_by_key(|(_, sample)| sample.sample_seq);
            for (profile, sample) in newer {
                events.push(Event::Traffic {
                    profile: profile.clone(),
                    sample: sample.clone(),
                });
            }
            cursor.sample_seq = state.sample_seq;
        }
        events
    }

    /// A cursor for a connection that just subscribed: the current status is owed, old
    /// samples are not.
    pub fn fresh_cursor(&self) -> Cursor {
        Cursor {
            status_seq: 0,
            sample_seq: self.lock().sample_seq,
        }
    }

    /// Wakes every waiter without a change, for a connection whose topics changed.
    pub fn poke(&self) {
        self.lock().pokes += 1;
        self.changed.notify_all();
    }

    pub fn pokes(&self) -> u64 {
        self.lock().pokes
    }

    /// Blocks until something is newer than `cursor` for `topics`, a poke after
    /// `pokes` was read, the hub closes, or `timeout` passes.
    pub fn wait_for_change(&self, cursor: &Cursor, topics: Topics, pokes: u64, timeout: Duration) {
        let state = self.lock();
        let _ = self.changed.wait_timeout_while(state, timeout, |state| {
            let newer_status = topics.status
                && state
                    .status
                    .as_ref()
                    .is_some_and(|d| d.seq > cursor.status_seq);
            let newer_sample = topics.traffic && state.sample_seq > cursor.sample_seq;
            !(newer_status || newer_sample || state.pokes != pokes || state.closing)
        });
    }

    /// Sleeps `duration`, or until the hub closes. True if it closed.
    pub fn sleep(&self, duration: Duration) -> bool {
        let state = self.lock();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, duration, |state| !state.closing)
            .unwrap_or_else(PoisonError::into_inner);
        state.closing
    }

    pub fn close(&self) {
        self.lock().closing = true;
        self.changed.notify_all();
    }

    pub fn closing(&self) -> bool {
        self.lock().closing
    }

    /// A connection subscribed (`was` and `now` are its topics before and after).
    pub fn subscribed(&self, was: Topics, now: Topics) {
        let mut state = self.lock();
        let count = |t: Topics| usize::from(t.status || t.traffic);
        state.subscribers = state.subscribers + count(now) - count(was);
        state.traffic_subscribers =
            state.traffic_subscribers + usize::from(now.traffic) - usize::from(was.traffic);
        drop(state);
        self.changed.notify_all();
    }

    pub fn has_subscribers(&self) -> bool {
        self.lock().subscribers > 0
    }

    /// Blocks while no connection wants traffic. False if the hub closed instead.
    pub fn wait_for_traffic_demand(&self) -> bool {
        let state = self.lock();
        let state = self
            .changed
            .wait_while(state, |s| s.traffic_subscribers == 0 && !s.closing)
            .unwrap_or_else(PoisonError::into_inner);
        !state.closing
    }

    /// The profiles whose tunnel is connected, with their entries, for the sampler.
    pub fn connected_entries(&self) -> Vec<(String, VpnEntry)> {
        let state = self.lock();
        let Some(document) = &state.status else {
            return Vec::new();
        };
        state
            .entries
            .iter()
            .filter(|(id, _)| {
                document
                    .profiles
                    .iter()
                    .any(|p| &p.id == id && p.ne_status == Some(NeStatus::Connected))
            })
            .cloned()
            .collect()
    }

    pub fn set_entries(&self, entries: Vec<(String, VpnEntry)>) {
        self.lock().entries = entries;
    }

    /// Records one round of measurements: each gets the next `sample_seq`, and a
    /// profile with no sample this round (not connected any more) loses its old one.
    pub fn push_samples(&self, round: Vec<(String, TrafficSample)>) {
        let mut state = self.lock();
        let keep: Vec<String> = round.iter().map(|(id, _)| id.clone()).collect();
        state.samples.retain(|id, _| keep.contains(id));
        for (id, mut sample) in round {
            state.sample_seq += 1;
            sample.sample_seq = state.sample_seq;
            state.samples.insert(id, sample);
        }
        drop(state);
        self.changed.notify_all();
    }

    pub fn component(&self) -> (ComponentState, Option<String>) {
        self.lock().component.clone()
    }

    /// Claims the component check if one is due (never run, or older than `max_age`)
    /// and none is running.
    pub fn claim_component_check(&self, max_age: Duration) -> bool {
        let mut state = self.lock();
        let due = state
            .component_checked
            .is_none_or(|t| t.elapsed() > max_age);
        if state.component_inflight || !due {
            return false;
        }
        state.component_inflight = true;
        true
    }

    pub fn finish_component_check(&self, result: (ComponentState, Option<String>)) {
        let mut state = self.lock();
        state.component = result;
        state.component_checked = Some(Instant::now());
        state.component_inflight = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rx: u64) -> TrafficSample {
        TrafficSample {
            session: "11111111".into(),
            rx_bytes: rx,
            tx_bytes: 0,
            rx_rate: None,
            tx_rate: None,
            sample_seq: 0,
        }
    }

    fn sequence(events: &[Event]) -> Vec<u64> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Traffic { sample, .. } => Some(sample.sample_seq),
                Event::Status { .. } => None,
            })
            .collect()
    }

    /// A subscriber is owed no old samples: with the counter already at 2, a fresh
    /// cursor sees only the third, and a cursor that has seen it sees nothing.
    #[test]
    fn a_new_subscription_gets_no_old_samples() {
        let hub = Hub::new();
        let traffic = Topics {
            status: false,
            traffic: true,
        };
        hub.push_samples(vec![("lab".into(), sample(1))]);
        hub.push_samples(vec![("lab".into(), sample(2))]);
        let mut cursor = hub.fresh_cursor();
        assert_eq!(cursor.sample_seq, 2);
        assert!(hub.events_since(&mut cursor, traffic).is_empty());
        hub.push_samples(vec![("lab".into(), sample(3)), ("other".into(), sample(9))]);
        assert_eq!(sequence(&hub.events_since(&mut cursor, traffic)), [3, 4]);
        assert!(hub.events_since(&mut cursor, traffic).is_empty());
        // A cursor that starts at zero (the connection's first) would be owed the newest.
        let mut stale = Cursor::default();
        assert_eq!(sequence(&hub.events_since(&mut stale, traffic)), [3, 4]);
    }
}
