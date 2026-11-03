//! Nonblocking liveness policy for one established IKE SA.
//!
//! The caller drives `tick` from a monotonic clock and sends each returned
//! packet on the existing IKE transport. An authenticated ESP packet, peer
//! INFORMATIONAL request, or IKE response may be reported via `observed_rx`.
//! Unauthenticated packets must never reset the grace period.
use crate::lifecycle::{Exchange, Lifecycle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessConfig {
    /// Start DPD after this much time without authenticated inbound traffic.
    pub idle_ms: u64,
    /// Retransmit the exact pending IKE packet at this interval.
    pub retry_ms: u64,
    /// Minimum probe age and inbound silence before asking for reconnect.
    pub silence_grace_ms: u64,
    /// Upper bound for an unanswered IKE control exchange, even if ESP flows.
    pub control_deadline_ms: u64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            idle_ms: 20_000,
            retry_ms: 5_000,
            silence_grace_ms: 60_000,
            control_deadline_ms: 120_000,
        }
    }
}

impl LivenessConfig {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.idle_ms == 0 || self.retry_ms == 0 || self.silence_grace_ms < self.retry_ms
            || self.control_deadline_ms < self.silence_grace_ms {
            return Err("invalid liveness timing");
        }
        Ok(self)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LivenessAction {
    None,
    /// Already sealed IKE bytes; frame for the chosen transport before sending.
    Send(Vec<u8>),
    /// Stop using this IKE SA and initiate a fresh connection with policy.
    Reconnect,
}

#[derive(Clone, Copy, Debug)]
struct PendingProbe {
    started_ms: u64,
    last_send_ms: u64,
}

pub struct Liveness {
    config: LivenessConfig,
    last_now_ms: u64,
    last_authenticated_rx_ms: u64,
    pending: Option<PendingProbe>,
    reconnect_required: bool,
}

impl Liveness {
    pub fn new(config: LivenessConfig, now_ms: u64) -> Result<Self, &'static str> {
        Ok(Self {
            config: config.validate()?,
            last_now_ms: now_ms,
            last_authenticated_rx_ms: now_ms,
            pending: None,
            reconnect_required: false,
        })
    }

    fn advance(&mut self, now_ms: u64) -> Result<(), &'static str> {
        if now_ms < self.last_now_ms {
            return Err("nonmonotonic liveness time");
        }
        self.last_now_ms = now_ms;
        Ok(())
    }

    /// Call only after ESP integrity/replay validation or IKE authentication.
    /// This protects the data plane during a path stall, but does not complete
    /// the pending DPD; only its matching authenticated response can do that.
    pub fn observed_rx(&mut self, now_ms: u64) -> Result<(), &'static str> {
        self.advance(now_ms)?;
        self.last_authenticated_rx_ms = now_ms;
        Ok(())
    }

    /// The caller must dispatch IKE responses here before the generic IKE
    /// response handler. A late valid response still completes the same DPD
    /// message ID; duplicate or forged responses leave this policy unchanged.
    pub fn complete_dpd(&mut self, lifecycle: &mut Lifecycle, packet: &[u8],
                        now_ms: u64) -> Result<(), String> {
        if now_ms < self.last_now_ms { return Err("nonmonotonic liveness time".into()); }
        if self.pending.is_none() || self.reconnect_required {
            return Err("no live DPD request pending".into());
        }
        if lifecycle.complete(packet)? != Exchange::Dpd {
            return Err("unexpected INFORMATIONAL response".into());
        }
        self.advance(now_ms).map_err(str::to_owned)?;
        self.last_authenticated_rx_ms = now_ms;
        self.pending = None;
        Ok(())
    }

    /// Returns promptly; no socket read or sleep occurs here. Retransmissions
    /// always use `Lifecycle::pending_packet` verbatim with the original ID/IV.
    pub fn tick(&mut self, lifecycle: &mut Lifecycle, now_ms: u64)
                -> Result<LivenessAction, String> {
        self.advance(now_ms).map_err(str::to_owned)?;
        if self.reconnect_required { return Ok(LivenessAction::Reconnect); }
        if let Some(pending) = &mut self.pending {
            let age = now_ms - pending.started_ms;
            let silence = now_ms - self.last_authenticated_rx_ms;
            if age >= self.config.control_deadline_ms
                || (age >= self.config.silence_grace_ms
                    && silence >= self.config.silence_grace_ms) {
                self.reconnect_required = true;
                return Ok(LivenessAction::Reconnect);
            }
            if now_ms - pending.last_send_ms >= self.config.retry_ms {
                let packet = lifecycle.pending_packet()
                    .ok_or("liveness policy lost pending IKE packet")?.to_vec();
                pending.last_send_ms = now_ms;
                return Ok(LivenessAction::Send(packet));
            }
            return Ok(LivenessAction::None);
        }
        if now_ms - self.last_authenticated_rx_ms < self.config.idle_ms {
            return Ok(LivenessAction::None);
        }
        // CREATE_CHILD_SA or DELETE owns the one permitted local IKE window.
        // Its caller owns retransmission and expiry; DPD waits for that window.
        if lifecycle.pending_packet().is_some() {
            return Ok(LivenessAction::None);
        }
        let packet = lifecycle.start(Exchange::Dpd)?.to_vec();
        self.pending = Some(PendingProbe { started_ms: now_ms, last_send_ms: now_ms });
        Ok(LivenessAction::Send(packet))
    }

    pub fn probe_pending(&self) -> bool { self.pending.is_some() }
    pub fn reconnect_required(&self) -> bool { self.reconnect_required }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Keys;
    use crate::lifecycle::ChildSpis;

    fn lifecycle() -> Lifecycle {
        Lifecycle::new([1; 8], [2; 8], Keys {
            sk_d: [1; 32], sk_ai: [2; 32], sk_ar: [3; 32], sk_ei: [4; 32],
            sk_er: [5; 32], sk_pi: [6; 32], sk_pr: [7; 32],
        }, 6, 0, Some(ChildSpis { inbound: [1, 2, 3, 4], outbound: [5, 6, 7, 8] }))
            .unwrap()
    }

    #[test]
    fn forty_second_stall_keeps_same_pending_dpd_and_esp_sa() {
        let mut lc = lifecycle();
        let mut policy = Liveness::new(LivenessConfig::default(), 0).unwrap();
        assert_eq!(policy.tick(&mut lc, 19_999).unwrap(), LivenessAction::None);
        let first = match policy.tick(&mut lc, 20_000).unwrap() {
            LivenessAction::Send(packet) => packet,
            other => panic!("expected DPD: {other:?}"),
        };
        for t in (25_000..=60_000).step_by(5_000) {
            assert_eq!(policy.tick(&mut lc, t).unwrap(), LivenessAction::Send(first.clone()));
            assert!(lc.child_active());
            assert_eq!(lc.next_local_id(), 6);
        }
        assert!(!policy.reconnect_required());
    }

    #[test]
    fn silence_grace_and_control_deadline_are_distinct() {
        let mut lc = lifecycle();
        let mut policy = Liveness::new(LivenessConfig::default(), 0).unwrap();
        assert!(matches!(policy.tick(&mut lc, 20_000).unwrap(), LivenessAction::Send(_)));
        policy.observed_rx(70_000).unwrap(); // authenticated ESP resumed
        assert!(matches!(policy.tick(&mut lc, 80_000).unwrap(), LivenessAction::Send(_)));
        assert!(lc.child_active());
        assert_eq!(policy.tick(&mut lc, 140_000).unwrap(), LivenessAction::Reconnect);
        assert_eq!(policy.tick(&mut lc, 145_000).unwrap(), LivenessAction::Reconnect);
        assert!(lc.child_active()); // caller owns disposal and reconnection
    }

    #[test]
    fn unauthenticated_traffic_cannot_extend_grace() {
        let mut lc = lifecycle();
        let mut policy = Liveness::new(LivenessConfig::default(), 0).unwrap();
        assert!(matches!(policy.tick(&mut lc, 20_000).unwrap(), LivenessAction::Send(_)));
        // No observed_rx call for malformed, unauthenticated or replayed packets.
        assert_eq!(policy.tick(&mut lc, 79_999).unwrap(), LivenessAction::Send(
            lc.pending_packet().unwrap().to_vec()));
        assert_eq!(policy.tick(&mut lc, 80_000).unwrap(), LivenessAction::Reconnect);
    }

    #[test]
    fn invalid_config_and_backward_time_are_rejected() {
        assert!(Liveness::new(LivenessConfig { retry_ms: 0,
            ..LivenessConfig::default() }, 0).is_err());
        let mut lc = lifecycle();
        let mut policy = Liveness::new(LivenessConfig::default(), 30).unwrap();
        assert!(policy.tick(&mut lc, 29).is_err());
        assert!(policy.observed_rx(29).is_err());
    }
}
