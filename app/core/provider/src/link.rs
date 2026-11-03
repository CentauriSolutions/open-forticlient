//! What the provider needs from an engine session, and the real thing.
//!
//! [`Link`] is one connected session; [`Backend`] makes one. They exist so the
//! state machine can be tested without a gateway (the tests use fakes); the only
//! production implementation is [`SessionBackend`] over [`oftc_engine::Session`].
//!
//! Statuses are the raw nonsecret codes the Swift provider saw from
//! `provider-ffi`, because they are folded into provider failure codes (and
//! `rekey_failed stage=<n>` replies) that the host reads.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oftc_engine::transport::{wait_readable, ConnectOptions};
use oftc_engine::{Cancellation, ConnectInput, Event, NetworkSettings, RekeyStage, Session};

use crate::envelope::BootstrapInput;

pub const CANCELLED: i32 = 4;
pub const INTERNAL: i32 = 7;
pub const PACKET_DROPPED: i32 = 8;
pub const RECONNECT_NEEDED: i32 = 9;
const NOT_CONNECTED: i32 = 2;
const SESSION_ERROR_BASE: i32 = 100;

/// How long a receive waits for the outer socket before reporting [`Inbound::Idle`].
const RECEIVE_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A decrypted inner IP packet.
    Packet(Vec<u8>),
    /// The gateway deleted the IKE or the CHILD SA.
    PeerDeleted,
    /// Nothing the provider acts on: DPD, NAT keepalive, a dropped datagram, a timeout.
    Idle,
}

pub type Status = i32;

/// One established session. Every method may be called from any thread, and
/// `receive` must not keep the other methods waiting while it blocks.
pub trait Link: Send + Sync + 'static {
    fn settings(&self) -> NetworkSettings;
    /// Wait a bounded time for the next inbound event.
    fn receive(&self) -> Result<Inbound, Status>;
    /// `Err(PACKET_DROPPED)` is not fatal; any other error is.
    fn send_ip(&self, packet: &[u8]) -> Result<(), Status>;
    fn tick_liveness(&self) -> Result<(), Status>;
    fn send_nat_keepalive(&self) -> Result<(), Status>;
    /// `(child local, child peer, ike)` successful rekeys.
    fn rekey_counts(&self) -> Result<(u32, u32, u32), Status>;
    fn rekey_child_once(&self) -> Result<(), Status>;
    fn rekey_ike_once(&self) -> Result<(), Status>;
    /// End any blocked `receive` promptly. The provider calls this while holding
    /// its state lock, so it must not block, wait for any other call on this
    /// link, or take a lock the provider uses.
    fn cancel(&self);
    /// Send the authenticated DELETEs and drop the session. Called once.
    fn teardown(&self);
}

pub trait Backend: Send + Sync + 'static {
    type Link: Link;

    /// Connect, consuming the secrets. `cancel` ends a connect in progress.
    /// `Err` is the raw status; the provider reports it as `100 + status`.
    fn connect(
        &self,
        input: BootstrapInput,
        options: ConnectOptions,
        cancel: Cancellation,
    ) -> Result<Self::Link, Status>;

    /// The no-token preflight: 0 passed, otherwise the stage that failed.
    fn preflight(&self, input: &BootstrapInput) -> Status;
}

fn mapped(error: oftc_engine::Error) -> Status {
    use oftc_engine::Error;
    match error {
        Error::Cancelled => CANCELLED,
        Error::InvalidInput => 1,
        Error::Resolve => SESSION_ERROR_BASE,
        Error::Socket => SESSION_ERROR_BASE + 1,
        Error::Timeout(_) => SESSION_ERROR_BASE + 2,
        Error::SaInit => SESSION_ERROR_BASE + 3,
        Error::ResponderAuth => SESSION_ERROR_BASE + 4,
        Error::EapChallenge => SESSION_ERROR_BASE + 5,
        Error::EapRejected => SESSION_ERROR_BASE + 6,
        Error::EapVerification => SESSION_ERROR_BASE + 7,
        Error::FinalAuth => SESSION_ERROR_BASE + 8,
        Error::ChildSa => SESSION_ERROR_BASE + 9,
        Error::Esp => SESSION_ERROR_BASE + 10,
        Error::PacketDropped => PACKET_DROPPED,
        Error::Control => SESSION_ERROR_BASE + 11,
        Error::Inactive => SESSION_ERROR_BASE + 12,
        Error::ReconnectNeeded => RECONNECT_NEEDED,
        Error::Rekey(stage) => match stage {
            RekeyStage::LocalOffer => 120,
            RekeyStage::NoResponse => 121,
            RekeyStage::PeerNoProposal => 122,
            RekeyStage::PeerInvalidKe => 123,
            RekeyStage::PeerNoAdditionalSas => 124,
            RekeyStage::PeerTsUnacceptable => 125,
            RekeyStage::PeerOtherNotify => 126,
            RekeyStage::ResponseMalformed => 127,
            RekeyStage::ResponseSuite => 128,
            RekeyStage::ResponseSelectors => 129,
            RekeyStage::Keymat => 130,
            RekeyStage::Install => 131,
            RekeyStage::OldDelete => 132,
        },
    }
}

/// The engine's own [`Session`] behind a mutex.
pub struct SessionBackend;

impl Backend for SessionBackend {
    type Link = SessionLink;

    fn connect(
        &self,
        input: BootstrapInput,
        options: ConnectOptions,
        cancel: Cancellation,
    ) -> Result<SessionLink, Status> {
        let BootstrapInput { gateway, uid, psk, token } = input;
        let connect = ConnectInput {
            gateway,
            uid,
            psk: psk.into_string().map_err(|_| 1)?,
            tokenid: token.into_string().map_err(|_| 1)?,
        };
        let session = Session::connect_with_options(connect, cancel.clone(), options)
            .map_err(mapped)?;
        Ok(SessionLink { settings: session.settings().clone(), session: Mutex::new(Some(session)), cancel })
    }

    fn preflight(&self, input: &BootstrapInput) -> Status {
        oftc_preflight::preflight(&input.gateway, &input.uid, input.psk.as_bytes())
    }
}

pub struct SessionLink {
    settings: NetworkSettings,
    session: Mutex<Option<Session>>,
    cancel: Cancellation,
}

impl SessionLink {
    fn lock(&self) -> MutexGuard<'_, Option<Session>> {
        // A panic while holding the session leaves it usable for teardown.
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with<T>(&self, f: impl FnOnce(&mut Session) -> Result<T, oftc_engine::Error>)
        -> Result<T, Status> {
        let mut guard = self.lock();
        f(guard.as_mut().ok_or(NOT_CONNECTED)?).map_err(mapped)
    }
}

impl Link for SessionLink {
    fn settings(&self) -> NetworkSettings {
        self.settings.clone()
    }

    fn receive(&self) -> Result<Inbound, Status> {
        // Wait for the outer socket without holding the session, so sends and
        // liveness ticks are not delayed by up to a full wait (Issue 39).
        let fd = match self.lock().as_ref() {
            Some(session) if !session.has_queued() => Some(session.outer_fd()),
            _ => None,
        };
        if let Some(fd) = fd {
            wait_readable(fd, RECEIVE_WAIT);
        }
        self.with(|session| {
            Ok(match session.receive_ready()? {
                Event::IpPacket(packet) => Inbound::Packet(packet),
                Event::PeerDeletedChild | Event::PeerDeletedIke => Inbound::PeerDeleted,
                Event::PeerDpd | Event::NatKeepalive | Event::Rejected | Event::Timeout => {
                    Inbound::Idle
                }
            })
        })
    }

    fn send_ip(&self, packet: &[u8]) -> Result<(), Status> {
        self.with(|session| session.send_ip(packet))
    }

    fn tick_liveness(&self) -> Result<(), Status> {
        self.with(Session::tick_liveness)
    }

    fn send_nat_keepalive(&self) -> Result<(), Status> {
        self.with(Session::send_nat_keepalive)
    }

    fn rekey_counts(&self) -> Result<(u32, u32, u32), Status> {
        self.with(|session| {
            let (local, peer) = session.rekey_counts();
            Ok((local, peer, session.ike_rekey_count()))
        })
    }

    fn rekey_child_once(&self) -> Result<(), Status> {
        self.with(Session::rekey_child_once)
    }

    fn rekey_ike_once(&self) -> Result<(), Status> {
        self.with(Session::rekey_ike_once)
    }

    fn cancel(&self) {
        self.cancel.cancel();
    }

    fn teardown(&self) {
        // Take it out first: the guard must not be held across the DELETE exchange.
        let session = self.lock().take();
        if let Some(session) = session {
            // The outcome is diagnostic only; the tunnel is going away either way.
            let _ = session.disconnect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_connect_reports_the_cancelled_status() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let input = BootstrapInput::decode(
            &crate::envelope::tests::hbr1(
                "gateway.invalid", crate::envelope::tests::UID, b"synthetic", b"token"),
            true,
        )
        .unwrap();
        let result = SessionBackend.connect(input, ConnectOptions::default(), cancel);
        assert_eq!(result.err(), Some(CANCELLED));
    }

    #[test]
    fn a_link_reports_not_connected_after_teardown_and_teardown_is_idempotent() {
        // No gateway to connect to, so build the link around an empty session.
        let link = SessionLink {
            settings: NetworkSettings {
                outer_remote_ipv4: std::net::Ipv4Addr::new(203, 0, 113, 7),
                outer_remote_ip: std::net::Ipv4Addr::new(203, 0, 113, 7).into(),
                assigned_ipv4: std::net::Ipv4Addr::new(10, 99, 0, 12),
                netmask: None,
                split_routes: Vec::new(),
                dns_servers: Vec::new(),
                dns_domains: Vec::new(),
                inner_mtu: 1280,
            },
            session: Mutex::new(None),
            cancel: Cancellation::default(),
        };
        link.teardown();
        link.teardown();
        assert_eq!(link.send_ip(&[0x45]), Err(NOT_CONNECTED));
        assert_eq!(link.rekey_counts(), Err(NOT_CONNECTED));
    }

    #[test]
    fn engine_errors_keep_the_codes_the_host_reads() {
        use oftc_engine::Error;
        assert_eq!(mapped(Error::Resolve), 100);
        assert_eq!(mapped(Error::Timeout(0)), 102);
        assert_eq!(mapped(Error::Inactive), 112);
        assert_eq!(mapped(Error::PacketDropped), PACKET_DROPPED);
        assert_eq!(mapped(Error::ReconnectNeeded), RECONNECT_NEEDED);
        assert_eq!(mapped(Error::Rekey(RekeyStage::OldDelete)), 132);
    }
}
