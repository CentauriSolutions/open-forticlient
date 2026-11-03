//! The seam between the engine and an operating system's packet interface.
//!
//! The engine produces plain [`NetworkSettings`] after a tunnel is up and moves
//! inner IP packets in both directions. A [`Tunnel`] is whatever carries those
//! settings and packets to and from the OS: the NetworkExtension packet flow
//! today, and anything else (a `utun` device, a test double) later. Lifecycle
//! (start, stop, provider messages) belongs to the caller, not this trait.
//!
//! [`loopback`] gives an in-memory pair for tests: the [`LoopbackTunnel`] side
//! is handed to the code under test, and the [`LoopbackPeer`] side plays the OS.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use crate::session::NetworkSettings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    /// The OS side is gone; no more packets will flow.
    Closed,
    /// The OS refused the settings (addresses, routes or DNS).
    SettingsRejected,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TunnelError::Closed => "tunnel interface closed",
            TunnelError::SettingsRejected => "tunnel settings rejected",
        })
    }
}

impl std::error::Error for TunnelError {}

pub trait Tunnel {
    /// Install the addresses, routes, DNS and MTU. Called once the tunnel is up.
    fn apply_settings(&mut self, settings: &NetworkSettings) -> Result<(), TunnelError>;

    /// Block until the OS has at least one outbound inner IP packet and return
    /// the batch. Returns [`TunnelError::Closed`] when the interface is gone.
    fn read_packets(&mut self) -> Result<Vec<Vec<u8>>, TunnelError>;

    /// Hand one inbound inner IP packet to the OS.
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError>;

    /// Remove everything `apply_settings` installed.
    fn clear_settings(&mut self) -> Result<(), TunnelError>;
}

struct State {
    outbound: VecDeque<Vec<u8>>,
    written: Vec<Vec<u8>>,
    settings: Option<NetworkSettings>,
    clears: usize,
    reject_settings: bool,
    closed: bool,
    /// Live `LoopbackPeer` handles; the interface closes when the last drops.
    peers: usize,
    /// Threads currently blocked in `read_packets`.
    waiting: usize,
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    blocked: Condvar,
}

impl Shared {
    // A panic in one test thread must not turn into a second panic in teardown.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The engine-facing half of an in-memory tunnel.
pub struct LoopbackTunnel(Arc<Shared>);

/// The OS-facing half: injects outbound packets and inspects what was done.
/// Dropping the last peer closes the interface, so a test that forgets
/// [`LoopbackPeer::close`] fails instead of hanging in `read_packets`.
pub struct LoopbackPeer(Arc<Shared>);

/// Create a connected in-memory tunnel and its peer.
pub fn loopback() -> (LoopbackTunnel, LoopbackPeer) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            outbound: VecDeque::new(),
            written: Vec::new(),
            settings: None,
            clears: 0,
            reject_settings: false,
            closed: false,
            peers: 1,
            waiting: 0,
        }),
        ready: Condvar::new(),
        blocked: Condvar::new(),
    });
    (LoopbackTunnel(shared.clone()), LoopbackPeer(shared))
}

impl Tunnel for LoopbackTunnel {
    fn apply_settings(&mut self, settings: &NetworkSettings) -> Result<(), TunnelError> {
        let mut state = self.0.lock();
        if state.closed {
            return Err(TunnelError::Closed);
        }
        if state.reject_settings {
            return Err(TunnelError::SettingsRejected);
        }
        state.settings = Some(settings.clone());
        Ok(())
    }

    fn read_packets(&mut self) -> Result<Vec<Vec<u8>>, TunnelError> {
        let mut state = self.0.lock();
        loop {
            if !state.outbound.is_empty() {
                return Ok(state.outbound.drain(..).collect());
            }
            if state.closed {
                return Err(TunnelError::Closed);
            }
            state.waiting += 1;
            self.0.blocked.notify_all();
            state = self.0.ready.wait(state).unwrap_or_else(PoisonError::into_inner);
            state.waiting -= 1;
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let mut state = self.0.lock();
        if state.closed {
            return Err(TunnelError::Closed);
        }
        state.written.push(packet.to_vec());
        Ok(())
    }

    fn clear_settings(&mut self) -> Result<(), TunnelError> {
        let mut state = self.0.lock();
        state.settings = None;
        state.clears += 1;
        Ok(())
    }
}

impl Clone for LoopbackPeer {
    fn clone(&self) -> Self {
        self.0.lock().peers += 1;
        Self(self.0.clone())
    }
}

impl Drop for LoopbackPeer {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.peers -= 1;
        if state.peers == 0 {
            state.closed = true;
            self.0.ready.notify_all();
        }
    }
}

impl LoopbackPeer {
    /// Queue one outbound packet as if the OS had routed it into the tunnel.
    /// Once the interface is closed the packet is discarded, as the OS would.
    pub fn inject(&self, packet: &[u8]) {
        let mut state = self.0.lock();
        if state.closed {
            return;
        }
        state.outbound.push_back(packet.to_vec());
        self.0.ready.notify_all();
    }

    /// Block until a thread is waiting in `read_packets`. Lets a test close or
    /// inject only after the reader is really blocked, with no sleeps.
    pub fn wait_until_blocked(&self) {
        let mut state = self.0.lock();
        while state.waiting == 0 {
            state = self.0.blocked.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Take every packet the engine has written so far.
    pub fn take_written(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0.lock().written)
    }

    /// The settings currently installed, if any.
    pub fn settings(&self) -> Option<NetworkSettings> {
        self.0.lock().settings.clone()
    }

    /// How many times `clear_settings` has been called.
    pub fn clear_count(&self) -> usize {
        self.0.lock().clears
    }

    /// Make the next `apply_settings` calls fail, as an OS refusal would.
    pub fn reject_settings(&self) {
        self.0.lock().reject_settings = true;
    }

    /// Simulate the OS closing the interface: blocked reads return `Closed`.
    pub fn close(&self) {
        self.0.lock().closed = true;
        self.0.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    fn settings() -> NetworkSettings {
        NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::new(203, 0, 113, 7),
            outer_remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            assigned_ipv4: Ipv4Addr::new(10, 99, 0, 12),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 255)),
            split_routes: vec![crate::AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(10, 0, 8, 0)),
                last: IpAddr::V4(Ipv4Addr::new(10, 0, 15, 255)),
            }],
            dns_servers: vec![Ipv4Addr::new(10, 0, 8, 1)],
            dns_domains: vec!["corp.example".into()],
            inner_mtu: 1280,
        }
    }

    #[test]
    fn applies_and_clears_settings() {
        let (mut tunnel, peer) = loopback();
        assert_eq!(peer.settings(), None);
        tunnel.apply_settings(&settings()).unwrap();
        assert_eq!(peer.settings(), Some(settings()));
        tunnel.clear_settings().unwrap();
        assert_eq!(peer.settings(), None);
        assert_eq!(peer.clear_count(), 1);
    }

    #[test]
    fn round_trips_packets_in_both_directions() {
        let (mut tunnel, peer) = loopback();
        peer.inject(&[0x45, 1]);
        peer.inject(&[0x45, 2]);
        assert_eq!(tunnel.read_packets().unwrap(), vec![vec![0x45, 1], vec![0x45, 2]]);
        tunnel.write_packet(&[0x45, 3]).unwrap();
        tunnel.write_packet(&[0x45, 4]).unwrap();
        assert_eq!(peer.take_written(), vec![vec![0x45, 3], vec![0x45, 4]]);
        assert!(peer.take_written().is_empty());
    }

    #[test]
    fn read_blocks_until_a_packet_arrives() {
        let (mut tunnel, peer) = loopback();
        let reader = thread::spawn(move || tunnel.read_packets());
        peer.wait_until_blocked();
        peer.inject(&[0x45, 9]);
        assert_eq!(reader.join().unwrap().unwrap(), vec![vec![0x45, 9]]);
    }

    #[test]
    fn close_wakes_a_blocked_read_and_fails_later_calls() {
        let (mut tunnel, peer) = loopback();
        let mut blocked = LoopbackTunnel(tunnel.0.clone());
        let reader = thread::spawn(move || blocked.read_packets());
        peer.wait_until_blocked();
        peer.close();
        assert_eq!(reader.join().unwrap(), Err(TunnelError::Closed));
        assert_eq!(tunnel.write_packet(&[0x45]), Err(TunnelError::Closed));
        assert_eq!(tunnel.apply_settings(&settings()), Err(TunnelError::Closed));
    }

    #[test]
    fn queued_packets_are_delivered_before_closed_is_reported() {
        let (mut tunnel, peer) = loopback();
        peer.inject(&[0x45, 5]);
        peer.close();
        assert_eq!(tunnel.read_packets().unwrap(), vec![vec![0x45, 5]]);
        assert_eq!(tunnel.read_packets(), Err(TunnelError::Closed));
    }

    #[test]
    fn rejected_settings_are_reported_and_not_installed() {
        let (mut tunnel, peer) = loopback();
        peer.reject_settings();
        assert_eq!(tunnel.apply_settings(&settings()), Err(TunnelError::SettingsRejected));
        assert_eq!(peer.settings(), None);
    }

    #[test]
    fn dropping_the_last_peer_closes_the_interface() {
        let (mut tunnel, peer) = loopback();
        let second = peer.clone();
        let mut blocked = LoopbackTunnel(tunnel.0.clone());
        let reader = thread::spawn(move || blocked.read_packets());
        peer.wait_until_blocked();
        drop(peer);
        // One peer is still alive, so the reader must still be waiting.
        second.inject(&[0x45, 7]);
        assert_eq!(reader.join().unwrap().unwrap(), vec![vec![0x45, 7]]);
        drop(second);
        assert_eq!(tunnel.read_packets(), Err(TunnelError::Closed));
    }

    #[test]
    fn packets_injected_after_close_are_discarded() {
        let (mut tunnel, peer) = loopback();
        peer.close();
        peer.inject(&[0x45, 8]);
        assert_eq!(tunnel.read_packets(), Err(TunnelError::Closed));
    }

    #[test]
    fn clear_settings_still_works_after_close() {
        let (mut tunnel, peer) = loopback();
        peer.close();
        tunnel.clear_settings().unwrap();
        assert_eq!(peer.clear_count(), 1);
    }
}
