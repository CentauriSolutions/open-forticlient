//! Provider-owned IKE/EAP/ESP session. No profile, browser, or FFI access.
//! The provider supplies a fresh SAML token in memory and owns this value.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(test)] use std::net::UdpSocket;
#[cfg(test)] use std::net::TcpListener;
#[cfg(test)] use std::io::{Read, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

use crate::{auth, child_sa, engine, ephemeral, ike_rekey, init, lifecycle, liveness, mschapv2, rekey, transport};

pub(crate) const READ_SLICE: Duration = Duration::from_millis(250);
const READY_SLICE: Duration = Duration::from_millis(2);
const INNER_MTU: usize = 1280;
const MAX_QUEUED_INNER: usize = 32;
// Gateway configuration records 24h IKE and 12h CHILD lifetimes. Rekey early;
// the actual peer expiry policy still needs live observation.
const CHILD_REKEY_SOFT: Duration = Duration::from_secs(20 * 60);
const CHILD_REKEY_JITTER: u64 = 120;
const CHILD_HARD: Duration = Duration::from_secs(35 * 60);
const IKE_REKEY_SOFT: Duration = Duration::from_secs(20 * 60 * 60);
const IKE_HARD: Duration = Duration::from_secs(23 * 60 * 60);

fn child_soft_after(inbound_spi: u32) -> Duration {
    CHILD_REKEY_SOFT + Duration::from_secs(u64::from(inbound_spi) % CHILD_REKEY_JITTER)
}

fn wipe(value: &mut str) {
    for byte in unsafe { value.as_bytes_mut() } {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Consumed by one connection attempt. Do not clone or log this value.
pub struct ConnectInput {
    pub gateway: String,
    pub uid: String,
    pub psk: String,
    pub tokenid: String,
}

impl Drop for ConnectInput {
    fn drop(&mut self) {
        wipe(&mut self.psk);
        wipe(&mut self.tokenid);
    }
}

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) { self.0.store(true, Ordering::SeqCst); }
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.0.load(Ordering::SeqCst) { Err(Error::Cancelled) } else { Ok(()) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Cancelled,
    InvalidInput,
    Resolve,
    Socket,
    Timeout(u32),
    SaInit,
    ResponderAuth,
    EapChallenge,
    EapRejected,
    EapVerification,
    FinalAuth,
    ChildSa,
    Esp,
    /// An inner packet was rejected before ESP encryption; the SA remains usable.
    PacketDropped,
    Control,
    Inactive,
    /// Authenticated traffic did not recover within the DPD grace window.
    ReconnectNeeded,
    /// Fixed, nonsecret classification for a failed authenticated CHILD rekey.
    Rekey(RekeyStage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyStage {
    LocalOffer,
    NoResponse,
    PeerNoProposal,
    PeerInvalidKe,
    PeerNoAdditionalSas,
    PeerTsUnacceptable,
    PeerOtherNotify,
    ResponseMalformed,
    ResponseSuite,
    ResponseSelectors,
    Keymat,
    Install,
    OldDelete,
}

fn classify_rekey_reply(error: rekey::Error) -> Error {
    use rekey::Error as E;
    let stage = match error {
        E::PeerNotify(14) => RekeyStage::PeerNoProposal,
        E::PeerNotify(17) => RekeyStage::PeerInvalidKe,
        E::PeerNotify(35) => RekeyStage::PeerNoAdditionalSas,
        E::PeerNotify(38) => RekeyStage::PeerTsUnacceptable,
        E::PeerNotify(_) => RekeyStage::PeerOtherNotify,
        E::UnsupportedSuite => RekeyStage::ResponseSuite,
        E::SelectorChanged => RekeyStage::ResponseSelectors,
        _ => RekeyStage::ResponseMalformed,
    };
    Error::Rekey(stage)
}

/// Plain tunnel configuration; no keying material crosses this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    /// Resolved outer gateway address. The IPv4 compatibility field is
    /// unspecified for IPv6 until the provider settings ABI is upgraded.
    pub outer_remote_ipv4: Ipv4Addr,
    pub outer_remote_ip: IpAddr,
    pub assigned_ipv4: Ipv4Addr,
    pub netmask: Option<Ipv4Addr>,
    pub split_routes: Vec<engine::AddressRange>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_domains: Vec<String>,
    pub inner_mtu: usize,
}

impl NetworkSettings {
    fn from_configuration(value: child_sa::Configuration, outer_remote_ip: IpAddr) -> Self {
        Self {
            outer_remote_ipv4: match outer_remote_ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            outer_remote_ip,
            assigned_ipv4: value.assigned_ipv4,
            netmask: value.netmask,
            split_routes: value.split_routes,
            dns_servers: value.dns_servers,
            dns_domains: value.dns_domains,
            inner_mtu: INNER_MTU,
        }
    }
    /// A missing mode-config mask must not imply a broader local subnet.
    pub fn interface_mask(&self) -> Ipv4Addr {
        self.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 255))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    IpPacket(Vec<u8>),
    PeerDpd,
    PeerDeletedChild,
    PeerDeletedIke,
    NatKeepalive,
    /// Malformed, unauthenticated, or replayed outer datagram was dropped.
    Rejected,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// CHILD and IKE DELETE both received authenticated acknowledgements.
    Clean,
    /// The peer initiated and we acknowledged IKE DELETE.
    PeerDeleted,
    /// No new DELETE was possible, commonly because a DPD exchange was pending.
    LocalOnly,
    ChildDeleteUnconfirmed,
    IkeDeleteUnconfirmed,
}

enum Poll {
    Event(Event),
    Ack(lifecycle::Exchange),
    RekeyReply(u8, Vec<u8>),
    IkeRekeyReply(u8, Vec<u8>),
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    oftc_crypto::random_array().map_err(|_| Error::SaInit)
}

fn new_key() -> Result<(oftc_crypto::Group20Key, [u8; 96]), Error> {
    oftc_crypto::Group20Key::generate().map_err(|_| Error::SaInit)
}

fn shared(key: &oftc_crypto::Group20Key, peer: &[u8; 96]) -> Result<[u8; 48], Error> {
    key.shared_secret(peer).map(|secret| *secret).map_err(|_| Error::SaInit)
}

fn matching_reply(ike: &[u8], expected_id: u32, spi_i: &[u8; 8],
                  protected: Option<(&[u8; 8], &auth::Keys)>) -> bool {
    if ike.len() < 28 || ike[..8] != *spi_i || ike[17] != 0x20
        || ike[18] != if expected_id == 0 { 34 } else { 35 }
        || ike[19] != 0x20 || ike[20..24] != expected_id.to_be_bytes()
        || u32::from_be_bytes(ike[24..28].try_into().unwrap()) as usize != ike.len() {
        return false;
    }
    match protected {
        None => expected_id == 0 && ike[8..16] != [0; 8],
        Some((spi_r, keys)) => {
            if expected_id == 0 || ike.len() < 80 || ike[8..16] != *spi_r
                || ike[16] != 46 { return false; }
            let icv_start = ike.len() - 16;
            let Ok(mac) = auth::prf_sha256(&keys.sk_ar, &ike[..icv_start]) else {
                return false;
            };
            mac[..16].iter().zip(&ike[icv_start..])
                .fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
        }
    }
}

fn exchange(socket: &mut transport::Connection, cancel: &Cancellation, packet: &[u8],
            expected_id: u32, spi_i: &[u8; 8],
            protected: Option<(&[u8; 8], &auth::Keys)>) -> Result<Vec<u8>, Error> {
    let udp = socket.wire() == transport::Wire::Udp4500;
    let waits = if udp {
        if expected_id >= 3 { [10, 20] } else { [2, 3] }
    } else if expected_id >= 3 { [30, 0] } else { [5, 0] };
    for seconds in waits {
        if seconds == 0 { break; }
        cancel.check()?;
        socket.send_ike(packet, cancel)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            cancel.check()?;
            let Some(frame) = socket.read(deadline, cancel)? else { break; };
            let ike = match socket.wire() {
                transport::Wire::Udp4500 => init::unframe_udp(&frame).ok(),
                transport::Wire::Tcp4443 => transport::tcp_ike(&frame),
            };
            if let Some(ike) = ike {
                if matching_reply(ike, expected_id, spi_i, protected) {
                    return Ok(ike.to_vec());
                }
            }
        }
    }
    Err(Error::Timeout(expected_id))
}

struct InitOutcome {
    socket: transport::Connection,
    remote: SocketAddr,
    local: SocketAddr,
    spi_i: [u8; 8],
    nonce_i: [u8; 32],
    first: Vec<u8>,
    first_reply: Vec<u8>,
    response: init::Response,
    keys: auth::Keys,
}

fn sa_init_attempt(gateway: &str, cancel: &Cancellation,
                   options: transport::ConnectOptions) -> Result<InitOutcome, Error> {
    let remote = transport::resolve(gateway, options, cancel)?;
    cancel.check()?;
    let (mut socket, local) = transport::Connection::open(remote, options.wire)?;
    let (key, public) = new_key()?;
    let mut spi_i = random::<8>()?;
    if spi_i == [0; 8] { spi_i[7] = 1; }
    let nonce_i = random::<32>()?;
    let first = init::request(spi_i, nonce_i, public, local, remote);
    let first_reply = exchange(&mut socket, cancel, &first, 0, &spi_i, None)?;
    let response = init::parse_response(&first_reply, &spi_i, local, remote)
        .map_err(|_| Error::SaInit)?;
    if response.selected != 1 { return Err(Error::SaInit); }
    let mut dh = shared(&key, &response.peer_public)?;
    let keys_result = auth::derive_keys(&nonce_i, &response.nonce, &spi_i,
                                         &response.spi_r, &dh);
    dh.fill(0);
    let keys = keys_result.map_err(|_| Error::SaInit)?;
    Ok(InitOutcome { socket, remote, local, spi_i, nonce_i,
        first, first_reply, response, keys })
}

pub struct Session {
    socket: transport::Connection,
    engine: Option<engine::Engine<engine::esp::SystemCrypto>>,
    lifecycle: lifecycle::Lifecycle,
    settings: NetworkSettings,
    cancel: Cancellation,
    queued_inner: VecDeque<Vec<u8>>,
    liveness_started: Instant,
    liveness: liveness::Liveness,
    rekey_tsi: Vec<u8>,
    rekey_tsr: Vec<u8>,
    peer_old_deadline: Option<(u32, Instant)>,
    child_started: Instant,
    child_soft_after: Duration,
    ike_started: Instant,
    local_rekeys: u32,
    peer_rekeys: u32,
    ike_rekeys: u32,
}

impl Session {
    /// Default IPv4 UDP path for the existing provider ABI. One token use.
    pub fn connect(input: ConnectInput, cancel: Cancellation) -> Result<Self, Error> {
        Self::connect_with_options(input, cancel, transport::ConnectOptions::default())
    }

    /// Explicit outer transport and family. UDP is the default. If enabled,
    /// fallback happens only before EAP, after a bounded SA_INIT failure; TCP
    /// gets a fresh IKE SPI and key. Never retry SAML or an authenticated SA.
    /// Call off the provider packet thread.
    pub fn connect_with_options(mut input: ConnectInput, cancel: Cancellation,
                                options: transport::ConnectOptions) -> Result<Self, Error> {
        cancel.check()?;
        options.validate()?;
        if input.gateway.is_empty() || input.psk.is_empty() || input.tokenid.is_empty()
            || input.uid.len() != 32 || !input.uid.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput);
        }
        let attempt = match sa_init_attempt(&input.gateway, &cancel, options) {
            Err(error) => match options.fallback_after(error) {
                Some(tcp) => sa_init_attempt(&input.gateway, &cancel, tcp)?,
                None => return Err(error),
            },
            Ok(attempt) => attempt,
        };
        let InitOutcome { mut socket, remote, local, spi_i, nonce_i,
            first, first_reply, response: init_response, keys } = attempt;
        let idi_v4 = match (options.family, local.ip()) {
            (transport::OuterFamily::Ipv4, IpAddr::V4(addr)) => addr,
            (transport::OuterFamily::Ipv6, IpAddr::V6(_)) => options.idi_v4.unwrap(),
            _ => return Err(Error::Socket),
        };

        let request = auth::first_request_with_child_spi(&spi_i, &init_response.spi_r,
                                                          &keys, idi_v4)
            .map_err(|_| Error::SaInit)?;
        let first_auth_reply = exchange(&mut socket, &cancel, &request.packet, 1,
                                        &spi_i, Some((&init_response.spi_r, &keys)))?;
        let initial = auth::parse_response(&first_auth_reply, &spi_i,
                        &init_response.spi_r, &keys, 1).map_err(|_| Error::ResponderAuth)?;
        auth::verify_responder_auth(&initial, input.psk.as_bytes(), &first_reply,
                                    &nonce_i, &keys).map_err(|_| Error::ResponderAuth)?;
        if initial.eap_code != Some(1) || initial.eap_type != Some(1) {
            return Err(Error::EapChallenge);
        }
        let idr = initial.idr.as_deref().ok_or(Error::ResponderAuth)?.to_vec();
        let identity = auth::identity_reply(&spi_i, &init_response.spi_r, &keys,
                        initial.eap_id.ok_or(Error::EapChallenge)?, input.uid.as_bytes())
            .map_err(|_| Error::EapChallenge)?;
        let challenge_reply = exchange(&mut socket, &cancel, &identity, 2,
                                       &spi_i, Some((&init_response.spi_r, &keys)))?;
        let challenge_summary = auth::parse_response(&challenge_reply, &spi_i,
                        &init_response.spi_r, &keys, 2).map_err(|_| Error::EapChallenge)?;
        let challenge = mschapv2::parse_challenge(challenge_summary.eap.as_deref()
                        .ok_or(Error::EapChallenge)?).map_err(|_| Error::EapChallenge)?;
        cancel.check()?;
        let prepared_result = mschapv2::respond(&challenge, &input.uid, &input.tokenid);
        wipe(&mut input.tokenid);
        let prepared = prepared_result.map_err(|_| Error::EapChallenge)?;
        let response = auth::eap_reply(&spi_i, &init_response.spi_r, &keys, 3,
                                       &prepared.eap_response).map_err(|_| Error::EapChallenge)?;
        let method_reply = exchange(&mut socket, &cancel, &response, 3,
                                    &spi_i, Some((&init_response.spi_r, &keys)))?;
        let method = auth::parse_response(&method_reply, &spi_i,
                        &init_response.spi_r, &keys, 3).map_err(|_| Error::EapVerification)?;
        if method.eap_code == Some(4) || method.eap_mschap_opcode == Some(4) {
            return Err(Error::EapRejected);
        }
        let verified = prepared.verify_success(method.eap.as_deref()
            .ok_or(Error::EapVerification)?).map_err(|_| Error::EapVerification)?;
        let ack = auth::eap_reply(&spi_i, &init_response.spi_r, &keys, 4,
                                  &verified.success_ack).map_err(|_| Error::EapVerification)?;
        let outer_reply = exchange(&mut socket, &cancel, &ack, 4,
                                   &spi_i, Some((&init_response.spi_r, &keys)))?;
        let outer = auth::parse_response(&outer_reply, &spi_i,
                        &init_response.spi_r, &keys, 4).map_err(|_| Error::EapVerification)?;
        if outer.eap.as_deref().is_none_or(|e| e.len() != 4 || e[0] != 3) {
            return Err(Error::EapVerification);
        }
        let final_request = auth::final_auth_request(&spi_i, &init_response.spi_r,
            &keys, 5, verified.msk(), &first, &init_response.nonce, &request.idi)
            .map_err(|_| Error::FinalAuth)?;
        let final_reply = exchange(&mut socket, &cancel, &final_request, 5,
                                   &spi_i, Some((&init_response.spi_r, &keys)))?;
        let final_summary = auth::parse_response(&final_reply, &spi_i,
            &init_response.spi_r, &keys, 5).map_err(|_| Error::FinalAuth)?;
        auth::verify_final_auth(&final_summary, &idr, verified.msk(),
            &first_reply, &nonce_i, &keys).map_err(|_| Error::FinalAuth)?;
        let rekey_tsi = final_summary.tsi.as_ref().ok_or(Error::ChildSa)?.clone();
        let rekey_tsr = final_summary.tsr.as_ref().ok_or(Error::ChildSa)?.clone();
        let negotiated = child_sa::parse_final(
            final_summary.sa.as_deref().ok_or(Error::ChildSa)?,
            final_summary.tsi.as_deref().ok_or(Error::ChildSa)?,
            final_summary.tsr.as_deref().ok_or(Error::ChildSa)?,
            final_summary.cp.as_deref().ok_or(Error::ChildSa)?,
            request.child_spi, &request.offered_tsi, &request.offered_tsr,
        ).map_err(|_| Error::ChildSa)?;
        let child_spis = lifecycle::ChildSpis {
            inbound: request.child_spi,
            outbound: negotiated.peer_inbound_spi.to_be_bytes(),
        };
        let (handoff, config) = child_sa::into_engine(
            negotiated, &keys.sk_d, &nonce_i, &init_response.nonce,
            |key, data| auth::prf_sha256(key, data).map_err(|_| child_sa::Error::Crypto),
            socket.wire().engine(), INNER_MTU, 8192,
        ).map_err(|_| Error::ChildSa)?;
        let engine = engine::Engine::install(handoff, engine::esp::SystemCrypto)
            .map_err(|_| Error::ChildSa)?;
        let lifecycle = lifecycle::Lifecycle::new(
            spi_i, init_response.spi_r, keys, 6, 0, Some(child_spis)
        ).map_err(|_| Error::Control)?;
        cancel.check()?;
        let liveness_started = Instant::now();
        let liveness = liveness::Liveness::new(liveness::LivenessConfig::default(), 0)
            .map_err(|_| Error::Control)?;
        Ok(Self { socket, engine: Some(engine), lifecycle,
            settings: NetworkSettings::from_configuration(config, remote.ip()),
            cancel, queued_inner: VecDeque::new(), liveness_started, liveness,
            rekey_tsi, rekey_tsr, peer_old_deadline: None,
            child_started: liveness_started,
            child_soft_after: child_soft_after(u32::from_be_bytes(child_spis.inbound)),
            ike_started: liveness_started,
            local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0 })
    }

    pub fn settings(&self) -> &NetworkSettings { &self.settings }

    fn liveness_now_ms(&self) -> u64 {
        self.liveness_started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }

    fn observed_authenticated_rx(&mut self) -> Result<(), Error> {
        self.liveness.observed_rx(self.liveness_now_ms()).map_err(|_| Error::Control)
    }

    /// Drive one DPD timer step without reading from the outer socket or
    /// waiting for a reply. The provider calls this periodically on a worker.
    pub fn tick_liveness(&mut self) -> Result<(), Error> {
        self.cancel.check()?;
        let now = Instant::now();
        if now.duration_since(self.ike_started) >= IKE_HARD
            || now.duration_since(self.child_started) >= CHILD_HARD {
            self.engine = None;
            return Err(Error::ReconnectNeeded);
        }
        if now.duration_since(self.ike_started) >= IKE_REKEY_SOFT
            && self.lifecycle.pending_packet().is_none()
            && !self.liveness.probe_pending()
            && self.peer_old_deadline.is_none()
            && self.rekey_ike_once().is_err() {
                self.engine = None;
                return Err(Error::ReconnectNeeded);
            }
        if now.duration_since(self.child_started) >= self.child_soft_after
            && self.lifecycle.pending_packet().is_none()
            && !self.liveness.probe_pending()
            && self.peer_old_deadline.is_none()
            && self.rekey_child_once().is_err() {
                self.engine = None;
                return Err(Error::ReconnectNeeded);
            }
        self.tick_liveness_at(self.liveness_now_ms())
    }

    fn tick_liveness_at(&mut self, now_ms: u64) -> Result<(), Error> {
        self.cancel.check()?;
        if self.peer_old_deadline.is_some_and(|(_, deadline)| Instant::now() >= deadline) {
            self.engine = None;
            return Err(Error::ReconnectNeeded);
        }
        if self.liveness.reconnect_required() { return Err(Error::ReconnectNeeded); }
        if !self.lifecycle.ike_active() || !self.lifecycle.child_active()
            || self.engine.is_none() { return Err(Error::Inactive); }
        match self.liveness.tick(&mut self.lifecycle, now_ms).map_err(|_| Error::Control)? {
            liveness::LivenessAction::None => Ok(()),
            liveness::LivenessAction::Send(packet) => {
                self.socket.send_ike(&packet, &self.cancel)
            }
            liveness::LivenessAction::Reconnect => {
                self.engine = None;
                Err(Error::ReconnectNeeded)
            }
        }
    }

    /// One outer NAT keepalive. The provider schedules this only while active.
    pub fn send_nat_keepalive(&mut self) -> Result<(), Error> {
        self.cancel.check()?;
        if !self.lifecycle.ike_active() { return Err(Error::Inactive); }
        let result = self.socket.send_nat_keepalive(&self.cancel);
        if result.is_err() { self.engine = None; }
        result
    }

    /// Encrypt and send exactly one inner IP packet on the retained outer socket.
    pub fn send_ip(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.cancel.check()?;
        if !self.lifecycle.ike_active() || !self.lifecycle.child_active() {
            return Err(Error::Inactive);
        }
        let wire = match self.engine.as_mut().ok_or(Error::Inactive)?.send_ip(packet) {
            Ok(wire) => wire,
            Err(engine::Error::PolicyDenied | engine::Error::MtuExceeded
                | engine::Error::Esp(engine::esp::Error::InvalidPacket)) => {
                return Err(Error::PacketDropped);
            }
            _ => return Err(Error::Esp),
        };
        let result = self.socket.send_esp(wire, &self.cancel);
        if result.is_err() { self.engine = None; }
        result
    }

    fn send_ike(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.socket.send_ike(packet, &self.cancel)
    }

    fn read_one(&mut self) -> Result<Poll, Error> {
        self.read_one_within(READ_SLICE)
    }

    fn read_one_within(&mut self, slice: Duration) -> Result<Poll, Error> {
        let deadline = Instant::now() + slice;
        let Some(frame) = self.socket.read(deadline, &self.cancel)?
            else { return Ok(Poll::Event(Event::Timeout)); };
        if self.socket.wire() == transport::Wire::Tcp4443 {
            // The CHILD DELETE reply retires ESP before the IKE DELETE reply.
            // Keep decoding authenticated IKE on this stream after ESP is gone.
            if self.engine.is_none() {
                return match transport::tcp_ike(&frame) {
                    Some(ike) => self.handle_ike(ike),
                    None => Ok(Poll::Event(Event::Rejected)),
                };
            }
            return match self.engine.as_mut() {
                Some(engine) => match engine.receive_tcp(&frame) {
                    Ok(inbound) => match inbound.into_iter().next() {
                        Some(engine::Inbound::Ip(ip)) => {
                            self.observed_authenticated_rx()?;
                            Ok(Poll::Event(Event::IpPacket(ip)))
                        }
                        Some(engine::Inbound::Ike(ike)) => self.handle_ike(&ike),
                        Some(engine::Inbound::NatKeepalive) => Ok(Poll::Event(Event::NatKeepalive)),
                        None => Ok(Poll::Event(Event::Rejected)),
                    },
                    Err(engine::Error::Framing(_)) => Err(Error::Socket),
                    Err(engine::Error::PolicyDenied | engine::Error::MtuExceeded) => {
                        // Both checks happen only after ESP authentication.
                        self.observed_authenticated_rx()?;
                        Ok(Poll::Event(Event::Rejected))
                    }
                    Err(_) => Ok(Poll::Event(Event::Rejected)),
                },
                None => Ok(Poll::Event(Event::Rejected)),
            };
        }
        match engine::esp::classify_udp4500(&frame) {
            Ok(engine::esp::Udp4500::NatKeepalive) => Ok(Poll::Event(Event::NatKeepalive)),
            Ok(engine::esp::Udp4500::Esp(_)) => match self.engine.as_mut() {
                Some(engine) => match engine.receive_udp(&frame) {
                    Ok(engine::Inbound::Ip(ip)) => {
                        self.observed_authenticated_rx()?;
                        Ok(Poll::Event(Event::IpPacket(ip)))
                    }
                    Err(engine::Error::PolicyDenied | engine::Error::MtuExceeded) => {
                        self.observed_authenticated_rx()?;
                        Ok(Poll::Event(Event::Rejected))
                    }
                    _ => Ok(Poll::Event(Event::Rejected)),
                },
                None => Ok(Poll::Event(Event::Rejected)),
            },
            Ok(engine::esp::Udp4500::Ike(ike)) => self.handle_ike(ike),
            Err(_) => Ok(Poll::Event(Event::Rejected)),
        }
    }

    fn handle_ike(&mut self, ike: &[u8]) -> Result<Poll, Error> {
        // Header fields and an unknown exchange type are not authenticated.
        // Late IKE_AUTH retransmissions and forged packets must not tear down
        // an established ESP SA. The lifecycle codec authenticates supported
        // INFORMATIONAL packets before producing a state transition.
        if ike.len() < 28 { return Ok(Poll::Event(Event::Rejected)); }
        if ike[18] == 36 && ike[19] == 0x20 {
            let ike_rekey = self.lifecycle.ike_rekey_pending();
            let result = if ike_rekey { self.lifecycle.complete_ike_rekey(ike) }
                         else { self.lifecycle.complete_rekey(ike) };
            return match result {
                Ok((first, inner)) => {
                    self.observed_authenticated_rx()?;
                    if ike_rekey { Ok(Poll::IkeRekeyReply(first, inner)) }
                    else { Ok(Poll::RekeyReply(first, inner)) }
                }
                Err(_) => Ok(Poll::Event(Event::Rejected)),
            };
        }
        if ike[18] == 36 && ike[19] == 0x00 {
            return self.handle_peer_rekey(ike);
        }
        if ike[18] != 37 {
            return Ok(Poll::Event(Event::Rejected));
        }
        match ike[19] {
            0x20 => {
                // Late duplicate responses have no pending request to complete.
                if self.lifecycle.pending_packet().is_none() {
                    return Ok(Poll::Event(Event::Rejected));
                }
                if self.liveness.probe_pending() {
                    let now_ms = self.liveness_now_ms();
                    return match self.liveness.complete_dpd(
                        &mut self.lifecycle, ike, now_ms) {
                        Ok(()) => Ok(Poll::Ack(lifecycle::Exchange::Dpd)),
                        Err(_) => Ok(Poll::Event(Event::Rejected)),
                    };
                }
                match self.lifecycle.complete(ike) {
                    Ok(kind) => {
                        self.observed_authenticated_rx()?;
                        if kind == lifecycle::Exchange::DeleteChild
                            || kind == lifecycle::Exchange::DeleteIke { self.engine = None; }
                        Ok(Poll::Ack(kind))
                    }
                    Err(_) => Ok(Poll::Event(Event::Rejected)),
                }
            }
            0x00 => {
                let request = match self.lifecycle.handle_peer_request(ike) {
                    Ok(request) => request,
                    Err(_) => return Ok(Poll::Event(Event::Rejected)),
                };
                self.observed_authenticated_rx()?;
                let (event, response) = match request {
                    lifecycle::PeerRequest::New { event, response } => (Some(event), response),
                    lifecycle::PeerRequest::Retransmit { response } => (None, response),
                };
                self.send_ike(&response)?;
                match event {
                    Some(lifecycle::PeerEvent::Dpd) => Ok(Poll::Event(Event::PeerDpd)),
                    Some(lifecycle::PeerEvent::DeleteChild) => {
                        self.engine = None;
                        Ok(Poll::Event(Event::PeerDeletedChild))
                    }
                    Some(lifecycle::PeerEvent::DeleteIke) => {
                        self.engine = None;
                        Ok(Poll::Event(Event::PeerDeletedIke))
                    }
                    Some(lifecycle::PeerEvent::DeleteOldChild(spi)) => {
                        if let Some(engine) = self.engine.as_mut() {
                            let _ = engine.retire_old_inbound(u32::from_be_bytes(spi));
                        }
                        if self.peer_old_deadline.is_some_and(|(old, _)|
                            old == u32::from_be_bytes(spi)) {
                            self.peer_old_deadline = None;
                        }
                        Ok(Poll::Event(Event::Rejected))
                    }
                    None => Ok(Poll::Event(Event::Rejected)),
                }
            }
            _ => Ok(Poll::Event(Event::Rejected)),
        }
    }

    fn handle_peer_rekey(&mut self, ike: &[u8]) -> Result<Poll, Error> {
        if let Some(response) = self.lifecycle.cached_peer_response(ike) {
            let response = response.to_vec();
            self.send_ike(&response)?;
            return Ok(Poll::Event(Event::Rejected));
        }
        let (first, inner) = match self.lifecycle.open_peer_rekey(ike) {
            Ok(value) => value,
            Err(_) => return Ok(Poll::Event(Event::Rejected)),
        };
        if first == 33 {
            // Peer-initiated IKE_SA rekey needs reverse-orientation IKE keys.
            // Do not misparse it as an ESP rekey or tear down a healthy SA.
            // RFC 7296 TEMPORARY_FAILURE asks the peer to retry later.
            let notify = [0, 0, 0, 8, 0, 0, 0, 43];
            let response = self.lifecycle.respond_peer_rekey(ike, 41, &notify)
                .map_err(|_| Error::Control)?;
            self.send_ike(&response)?;
            self.observed_authenticated_rx()?;
            return Ok(Poll::Event(Event::Rejected));
        }
        // Simultaneous local/peer rekey needs nonce-collision resolution. A
        // bounded reconnect is safer than acknowledging an uninstalled pair.
        if self.peer_old_deadline.is_some() || self.lifecycle.pending_packet()
            .is_some_and(|p| p[18] == 36) {
            self.engine = None;
            return Err(Error::ReconnectNeeded);
        }
        // Traffic selectors are expressed from the exchange initiator's
        // perspective: the peer's TSi/TSr reverse our local offer's roles.
        let offer = rekey::parse_peer_request(first, &inner,
            &self.rekey_tsr, &self.rekey_tsi).map_err(|_| {
                self.engine = None; Error::ReconnectNeeded
            })?;
        let (old_inbound, old_outbound) = self.engine.as_ref()
            .ok_or(Error::Inactive)?.active_spis();
        if offer.old_peer_inbound_spi != old_outbound {
            self.engine = None;
            return Err(Error::ReconnectNeeded);
        }
        let fresh = ephemeral::Ephemeral::new(old_inbound,
            self.rekey_tsi.clone(), self.rekey_tsr.clone()).map_err(|_| Error::ChildSa)?;
        let keymat = fresh.keymat_as_responder(&offer.ni, &offer.ke_i,
            self.lifecycle.sk_d()).map_err(|_| Error::ChildSa)?;
        let (reply_first, reply_inner) = rekey::encode_peer_response(&offer,
            fresh.offer.new_inbound_spi, &fresh.offer.ni, &fresh.offer.ke_i)
            .map_err(|_| Error::ChildSa)?;
        self.engine.as_mut().ok_or(Error::Inactive)?.install_rekey(
            fresh.offer.new_inbound_spi, offer.new_peer_inbound_spi,
            engine::esp::Keys { encryption: keymat.outbound_encryption,
                                integrity: keymat.outbound_integrity },
            engine::esp::Keys { encryption: keymat.inbound_encryption,
                                integrity: keymat.inbound_integrity })
            .map_err(|_| Error::ChildSa)?;
        let new_child = lifecycle::ChildSpis {
            inbound: fresh.offer.new_inbound_spi.to_be_bytes(),
            outbound: offer.new_peer_inbound_spi.to_be_bytes(),
        };
        if self.lifecycle.replace_child(new_child).is_err() {
            self.engine = None;
            return Err(Error::ReconnectNeeded);
        }
        let response = self.lifecycle.respond_peer_rekey(ike, reply_first, &reply_inner)
            .map_err(|_| { self.engine = None; Error::ReconnectNeeded })?;
        self.send_ike(&response)?;
        self.observed_authenticated_rx()?;
        self.peer_old_deadline = Some((old_inbound, Instant::now() + Duration::from_secs(60)));
        self.child_started = Instant::now();
        self.child_soft_after = child_soft_after(fresh.offer.new_inbound_spi);
        self.peer_rekeys = self.peer_rekeys.saturating_add(1);
        Ok(Poll::Event(Event::Rejected))
    }

    /// Poll one outer packet. Cancellation wakes within READ_SLICE.
    pub fn receive(&mut self) -> Result<Event, Error> {
        self.receive_within(READ_SLICE)
    }

    /// Like `receive`, but only waits `READY_SLICE`. The caller has already
    /// waited for the outer socket to become readable without holding the
    /// session, so sends are not stuck behind a full read slice.
    pub fn receive_ready(&mut self) -> Result<Event, Error> {
        self.receive_within(READY_SLICE)
    }

    fn receive_within(&mut self, slice: Duration) -> Result<Event, Error> {
        self.cancel.check()?;
        if let Some(ip) = self.queued_inner.pop_front() {
            return Ok(Event::IpPacket(ip));
        }
        match self.read_one_within(slice)? {
            Poll::Event(event) => Ok(event),
            Poll::Ack(_) | Poll::RekeyReply(_, _) | Poll::IkeRekeyReply(_, _) =>
                Ok(Event::Rejected),
        }
    }

    /// True when an inner packet is already queued, so waiting on the socket
    /// would only delay it.
    pub fn has_queued(&self) -> bool { !self.queued_inner.is_empty() }

    /// The outer socket's descriptor, for readiness waits made without
    /// holding the session. Only ever polled, never read or written.
    pub fn outer_fd(&self) -> i32 { self.socket.raw_fd() }

    fn await_info(&mut self, kind: lifecycle::Exchange,
                  honor_cancel: bool, queue_ip: bool) -> Result<(), Error> {
        let packet = self.lifecycle.pending_packet().ok_or(Error::Control)?.to_vec();
        let id = self.lifecycle.next_local_id();
        for seconds in [2, 3] {
            if honor_cancel { self.cancel.check()?; }
            self.send_ike(&packet)?;
            let deadline = Instant::now() + Duration::from_secs(seconds);
            loop {
                if honor_cancel { self.cancel.check()?; }
                if !self.lifecycle.ike_active() { return Err(Error::Inactive); }
                if !deadline.saturating_duration_since(Instant::now()).is_zero() {
                    match self.read_one()? {
                        Poll::Ack(got) if got == kind => return Ok(()),
                        Poll::Ack(_) => return Err(Error::Control),
                        Poll::RekeyReply(_, _) | Poll::IkeRekeyReply(_, _) =>
                            return Err(Error::Control),
                        Poll::Event(Event::IpPacket(ip)) if queue_ip => {
                            if self.queued_inner.len() < MAX_QUEUED_INNER {
                                self.queued_inner.push_back(ip);
                            }
                        }
                        // A crossed CHILD DELETE leaves our own request pending.
                        // Wait for its authenticated reply before sending IKE DELETE.
                        Poll::Event(Event::PeerDeletedChild)
                            if kind == lifecycle::Exchange::DeleteChild => {},
                        Poll::Event(Event::PeerDeletedChild | Event::PeerDeletedIke) => {
                            return Err(Error::Inactive);
                        }
                        _ => {},
                    }
                } else { break; }
            }
        }
        Err(Error::Timeout(id))
    }

    /// Bounded authenticated liveness exchange; retransmits one sealed packet.
    /// A failed probe invalidates data-plane use pending an explicit reconnect.
    pub fn probe_liveness(&mut self) -> Result<(), Error> {
        self.cancel.check()?;
        let packet = match self.lifecycle.start(lifecycle::Exchange::Dpd) {
            Ok(packet) => packet,
            Err(_) => { self.engine = None; return Err(Error::Control); }
        };
        debug_assert!(!packet.is_empty());
        let result = self.await_info(lifecycle::Exchange::Dpd, true, true);
        if result.is_err() { self.engine = None; }
        result
    }

    /// Bounded local CHILD_SA rekey on the established IKE socket. This is an
    /// explicit probe entry point until gateway response/selector behavior is
    /// observed. It consumes no SAML token and installs no routes or DNS.
    /// Any indeterminate exchange fails closed so a supervisor can reconnect.
    pub fn rekey_child_once(&mut self) -> Result<(), Error> {
        self.cancel.check()?;
        if !self.lifecycle.ike_active() || self.lifecycle.pending_packet().is_some()
            || self.liveness.probe_pending() { return Err(Error::Control); }
        let (old_inbound, _) = self.engine.as_ref().ok_or(Error::Inactive)?.active_spis();
        let fresh = ephemeral::Ephemeral::new(old_inbound,
            self.rekey_tsi.clone(), self.rekey_tsr.clone())
            .map_err(|_| Error::Rekey(RekeyStage::LocalOffer))?;
        let (first, inner) = rekey::encode_request(&fresh.offer)
            .map_err(|_| Error::Rekey(RekeyStage::LocalOffer))?;
        let packet = self.lifecycle.start_rekey(first, &inner)
            .map_err(|_| Error::Control)?.to_vec();
        let waits: &[u64] = if self.socket.wire() == transport::Wire::Udp4500 {
            &[2, 3]
        } else { &[30] };
        let mut reply = None;
        for seconds in waits {
            self.cancel.check()?;
            self.send_ike(&packet)?; // exact sealed packet on UDP retry
            let deadline = Instant::now() + Duration::from_secs(*seconds);
            while Instant::now() < deadline {
                self.cancel.check()?;
                if !self.lifecycle.ike_active() { return Err(Error::Inactive); }
                match self.read_one()? {
                    Poll::RekeyReply(first, inner) => { reply = Some((first, inner)); break; }
                    Poll::IkeRekeyReply(_, _) => return Err(Error::Control),
                    Poll::Event(Event::IpPacket(ip)) => {
                        if self.queued_inner.len() < MAX_QUEUED_INNER {
                            self.queued_inner.push_back(ip);
                        }
                    }
                    Poll::Event(Event::PeerDeletedChild | Event::PeerDeletedIke) =>
                        return Err(Error::Inactive),
                    _ => {},
                }
            }
            if reply.is_some() { break; }
        }
        let Some((first, inner)) = reply else {
            self.engine = None;
            return Err(Error::Rekey(RekeyStage::NoResponse));
        };
        let accepted = rekey::parse_response(first, &inner, &fresh.offer)
            .map_err(classify_rekey_reply)?;
        let keymat = fresh.keymat(&accepted, self.lifecycle.sk_d())
            .map_err(|_| Error::Rekey(RekeyStage::Keymat))?;
        let inbound_spi = fresh.offer.new_inbound_spi;
        let outbound_spi = accepted.peer_inbound_spi;
        let new_child = lifecycle::ChildSpis {
            inbound: inbound_spi.to_be_bytes(), outbound: outbound_spi.to_be_bytes(),
        };
        let engine = self.engine.as_mut().ok_or(Error::Inactive)?;
        let old = engine.install_rekey(inbound_spi, outbound_spi,
            engine::esp::Keys { encryption: keymat.inbound_encryption,
                                integrity: keymat.inbound_integrity },
            engine::esp::Keys { encryption: keymat.outbound_encryption,
                                integrity: keymat.outbound_integrity })
            .map_err(|_| Error::Rekey(RekeyStage::Install))?;
        if self.lifecycle.replace_child(new_child).is_err() {
            self.engine = None;
            return Err(Error::Rekey(RekeyStage::Install));
        }
        debug_assert_eq!(old.0, old_inbound);
        self.lifecycle.start_old_child_delete(old_inbound.to_be_bytes())
            .map_err(|_| { self.engine = None; Error::Rekey(RekeyStage::OldDelete) })?;
        let result = self.await_info(lifecycle::Exchange::DeleteOldChild, true, true);
        if let Err(error) = result {
            self.engine = None;
            return Err(if error == Error::Cancelled { error }
                       else { Error::Rekey(RekeyStage::OldDelete) });
        }
        self.engine.as_mut().ok_or(Error::Inactive)?
            .retire_old_inbound(old_inbound)
            .map_err(|_| Error::Rekey(RekeyStage::OldDelete))?;
        self.child_started = Instant::now();
        self.child_soft_after = child_soft_after(inbound_spi);
        self.local_rekeys = self.local_rekeys.saturating_add(1);
        Ok(())
    }

    /// Renew the IKE SA with fresh ECP-384 DH and message windows while the
    /// existing ESP CHILD SA keeps carrying packets. No SAML token is needed.
    pub fn rekey_ike_once(&mut self) -> Result<(), Error> {
        self.cancel.check()?;
        if !self.lifecycle.ike_active() || self.lifecycle.pending_packet().is_some()
            || self.liveness.probe_pending() || self.peer_old_deadline.is_some() {
            return Err(Error::Control);
        }
        let (key, ke_i) = new_key()?;
        let mut spi_i = random::<8>()?;
        if spi_i == [0; 8] { spi_i[7] = 1; }
        let offer = ike_rekey::Offer { spi_i, ni: random::<32>()?, ke_i };
        let (first, inner) = ike_rekey::encode_request(&offer).map_err(|_| Error::Control)?;
        let packet = self.lifecycle.start_ike_rekey(first, &inner)
            .map_err(|_| Error::Control)?.to_vec();
        let waits: &[u64] = if self.socket.wire() == transport::Wire::Udp4500 {
            &[2, 3]
        } else { &[30] };
        let mut reply = None;
        for seconds in waits {
            self.cancel.check()?;
            self.send_ike(&packet)?;
            let deadline = Instant::now() + Duration::from_secs(*seconds);
            while Instant::now() < deadline {
                self.cancel.check()?;
                if !self.lifecycle.ike_active() { return Err(Error::Inactive); }
                match self.read_one()? {
                    Poll::IkeRekeyReply(first, inner) => {
                        reply = Some((first, inner)); break;
                    }
                    Poll::Event(Event::IpPacket(ip)) => {
                        if self.queued_inner.len() < MAX_QUEUED_INNER {
                            self.queued_inner.push_back(ip);
                        }
                    }
                    Poll::Event(Event::PeerDeletedChild | Event::PeerDeletedIke) =>
                        return Err(Error::Inactive),
                    _ => {},
                }
            }
            if reply.is_some() { break; }
        }
        let (first, inner) = reply.ok_or(Error::Control)?;
        let accepted = ike_rekey::parse_response(first, &inner, &offer)
            .map_err(|_| Error::Control)?;
        let mut dh = shared(&key, &accepted.ke_r)?;
        let keys = ike_rekey::derive_keys(self.lifecycle.sk_d(), &dh, &offer, &accepted)
            .map_err(|_| Error::Control);
        dh.fill(0);
        let keys = keys?;
        self.lifecycle.start_old_ike_delete_for_rekey().map_err(|_| Error::Control)?;
        match self.await_info(lifecycle::Exchange::DeleteIkeRekey, true, true) {
            Ok(()) => {},
            Err(Error::Timeout(_)) => {
                // New SA is established; the peer may retire the old SA on its
                // own timer. Keep using the new keys after bounded retries.
                self.lifecycle.abandon_old_ike_delete_for_rekey()
                    .map_err(|_| Error::Control)?;
            }
            Err(error) => return Err(error),
        }
        self.lifecycle.install_ike_rekey(offer.spi_i, accepted.spi_r, keys)
            .map_err(|_| Error::Control)?;
        self.ike_started = Instant::now();
        self.ike_rekeys = self.ike_rekeys.saturating_add(1);
        Ok(())
    }

    /// Nonsecret evidence for sustained-operation checks.
    pub fn rekey_counts(&self) -> (u32, u32) {
        (self.local_rekeys, self.peer_rekeys)
    }

    pub fn ike_rekey_count(&self) -> u32 { self.ike_rekeys }

    /// Bounded authenticated CHILD then IKE DELETE. The provider first cancels
    /// any in-flight poll; teardown uses its own token so the cancellation
    /// does not suppress DELETE writes or reads.
    pub fn disconnect(mut self) -> Teardown {
        self.cancel = Cancellation::default();
        if !self.lifecycle.ike_active() { return Teardown::PeerDeleted; }
        if self.lifecycle.pending_packet().is_some() { return Teardown::LocalOnly; }
        if self.lifecycle.child_active() {
            let child_result = self.lifecycle.start(lifecycle::Exchange::DeleteChild)
                .map(|_| ()).map_err(|_| Error::Control)
                .and_then(|_| self.await_info(lifecycle::Exchange::DeleteChild, false, false));
            if !self.lifecycle.ike_active() { return Teardown::PeerDeleted; }
            if child_result.is_err() {
                return Teardown::ChildDeleteUnconfirmed;
            }
        }
        if !self.lifecycle.ike_active() { return Teardown::PeerDeleted; }
        let ike_result = self.lifecycle.start(lifecycle::Exchange::DeleteIke)
            .map(|_| ()).map_err(|_| Error::Control)
            .and_then(|_| self.await_info(lifecycle::Exchange::DeleteIke, false, false));
        if !self.lifecycle.ike_active() && ike_result.is_err() { return Teardown::PeerDeleted; }
        if ike_result.is_err() {
            return Teardown::IkeDeleteUnconfirmed;
        }
        Teardown::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_shared_and_prevents_connect() {
        let cancellation = Cancellation::default();
        let other = cancellation.clone();
        other.cancel();
        let input = ConnectInput {
            gateway: "example.invalid".into(), uid: "A".repeat(32),
            psk: "synthetic".into(), tokenid: "synthetic".into(),
        };
        assert!(matches!(Session::connect(input, cancellation), Err(Error::Cancelled)));
    }

    #[test]
    fn input_validation_precedes_dns() {
        let input = ConnectInput {
            gateway: "example.invalid".into(), uid: "not-a-machine-uid".into(),
            psk: "synthetic".into(), tokenid: "synthetic".into(),
        };
        assert!(matches!(Session::connect(input, Cancellation::default()), Err(Error::InvalidInput)));
    }

    #[test]
    fn network_settings_carry_no_sa_material() {
        let config = child_sa::Configuration {
            assigned_ipv4: Ipv4Addr::new(192, 0, 2, 5), netmask: None,
            dns_servers: vec![], dns_domains: vec![],
            split_routes: vec![engine::AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(10, 0, 8, 0)),
                last: IpAddr::V4(Ipv4Addr::new(10, 0, 8, 255)),
            }], route_source: child_sa::RouteSource::ConfigurationSubnet,
        };
        let ipv6 = NetworkSettings::from_configuration(config.clone(),
            IpAddr::V6("64:ff9b::cb00:7101".parse().unwrap()));
        assert_eq!(ipv6.outer_remote_ip,
            IpAddr::V6("64:ff9b::cb00:7101".parse().unwrap()));
        assert_eq!(ipv6.outer_remote_ipv4, Ipv4Addr::UNSPECIFIED);
        let settings = NetworkSettings::from_configuration(config,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert_eq!(settings.inner_mtu, 1280);
        assert_eq!(settings.split_routes.len(), 1);
        assert_eq!(settings.interface_mask(), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(settings.outer_remote_ipv4, Ipv4Addr::new(203, 0, 113, 1));
    }

    fn keys(seed: u8) -> engine::esp::Keys {
        engine::esp::Keys {
            encryption: [seed; 32], integrity: [seed.wrapping_add(1); 20],
        }
    }

    fn ike_keys() -> auth::Keys {
        auth::Keys {
            sk_d: [1; 32], sk_ai: [2; 32], sk_ar: [3; 32],
            sk_ei: [4; 32], sk_er: [5; 32], sk_pi: [6; 32], sk_pr: [7; 32],
        }
    }

    fn peer_packet_body(id: u32, flags: u8, exchange: u8,
                        first: u8, body: &[u8]) -> Vec<u8> {
        let keys = ike_keys();
        let iv = [9u8; 16];
        let mut plain = body.to_vec();
        let pad = (16 - ((plain.len() + 1) % 16)) % 16;
        plain.resize(plain.len() + pad, 0);
        plain.push(pad as u8);
        let ciphertext = oftc_crypto::aes256_cbc_encrypt(&keys.sk_er, &iv, &plain).unwrap();
        let mut packet = Vec::new();
        packet.extend_from_slice(&[1; 8]);
        packet.extend_from_slice(&[2; 8]);
        packet.extend_from_slice(&[46, 0x20, exchange, flags]);
        packet.extend_from_slice(&id.to_be_bytes());
        let sk_len = 4 + 16 + ciphertext.len() + 16;
        packet.extend_from_slice(&((28 + sk_len) as u32).to_be_bytes());
        packet.extend_from_slice(&[first, 0]);
        packet.extend_from_slice(&(sk_len as u16).to_be_bytes());
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&ciphertext);
        let icv = auth::prf_sha256(&keys.sk_ar, &packet).unwrap();
        packet.extend_from_slice(&icv[..16]);
        packet
    }

    fn peer_packet(id: u32, flags: u8, exchange: u8) -> Vec<u8> {
        peer_packet_body(id, flags, exchange, 0, &[])
    }

    fn peer_info(id: u32, flags: u8) -> Vec<u8> {
        peer_packet(id, flags, 37)
    }

    fn peer_child_delete(id: u32) -> Vec<u8> {
        peer_packet_body(id, 0x00, 37, 42,
            &[0, 0, 0, 12, 3, 4, 0, 1, 0x22, 0x22, 0x22, 0x22])
    }

    #[test]
    fn exchange_candidate_rejects_wrong_spi_type_and_mac() {
        let keys = ike_keys();
        let good = peer_packet(3, 0x20, 35);
        assert!(matching_reply(&good, 3, &[1; 8], Some((&[2; 8], &keys))));
        let mut bad = good.clone();
        bad[50] ^= 1;
        assert!(!matching_reply(&bad, 3, &[1; 8], Some((&[2; 8], &keys))));
        assert!(!matching_reply(&good, 4, &[1; 8], Some((&[2; 8], &keys))));
        assert!(!matching_reply(&good, 3, &[9; 8], Some((&[2; 8], &keys))));
        assert!(!matching_reply(&good, 3, &[1; 8], Some((&[9; 8], &keys))));
        let late = peer_packet(3, 0x20, 37);
        assert!(!matching_reply(&late, 3, &[1; 8], Some((&[2; 8], &keys))));
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn exchange_ignores_forged_matching_id_until_authenticated_reply() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(peer.local_addr().unwrap()).unwrap();
        peer.connect(client.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let good = peer_packet(3, 0x20, 35);
        let expected = good.clone();
        let responder = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            peer.recv(&mut buffer).unwrap();
            let mut wrong_spi = good.clone();
            wrong_spi[8] ^= 1;
            peer.send(&init::udp_frame(&wrong_spi)).unwrap();
            let mut bad_mac = good.clone();
            bad_mac[50] ^= 1;
            peer.send(&init::udp_frame(&bad_mac)).unwrap();
            peer.send(&init::udp_frame(&good)).unwrap();
        });
        let keys = ike_keys();
        let received = exchange(&mut transport::Connection::Udp(client),
            &Cancellation::default(), &[0; 28],
            3, &[1; 8], Some((&[2; 8], &keys))).unwrap();
        assert_eq!(received, expected);
        responder.join().unwrap();
    }

    fn handoff(peer: bool) -> engine::AuthenticatedChildSa {
        let client = engine::AddressRange {
            first: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            last: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        };
        let remote = engine::AddressRange {
            first: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
            last: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
        };
        let selector = |addresses| engine::TrafficSelector {
            addresses, protocol: 0, first_port: 0, last_port: u16::MAX,
        };
        engine::AuthenticatedChildSa {
            suite: engine::EspSuite::Aes256CbcHmacSha1_96,
            esn: false,
            peer_inbound_spi: if peer { 0x1111_1111 } else { 0x2222_2222 },
            local_inbound_spi: if peer { 0x2222_2222 } else { 0x1111_1111 },
            outbound_keys: keys(if peer { 0x44 } else { 0x22 }),
            inbound_keys: keys(if peer { 0x22 } else { 0x44 }),
            assigned_ip: if peer { remote.first } else { client.first },
            local_selectors: vec![selector(if peer { remote } else { client })],
            remote_selectors: vec![selector(if peer { client } else { remote })],
            installed_routes: vec![if peer { client } else { remote }],
            inner_mtu: INNER_MTU, transport: engine::Transport::Udp4500,
            max_tcp_record: 4096,
        }
    }

    fn ip(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0; 84];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&84u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn retained_socket_sends_and_receives_synthetic_esp() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(peer_socket.local_addr().unwrap()).unwrap();
        peer_socket.connect(client_socket.local_addr().unwrap()).unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let settings = NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::LOCALHOST,
            outer_remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            assigned_ipv4: Ipv4Addr::new(192, 0, 2, 2), netmask: None,
            split_routes: vec![engine::AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
                last: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
            }], dns_servers: vec![], dns_domains: vec![], inner_mtu: INNER_MTU,
        };
        let mut session = Session {
            socket: transport::Connection::Udp(client_socket),
            engine: Some(engine::Engine::install(handoff(false), engine::esp::SystemCrypto).unwrap()),
            lifecycle: lifecycle::Lifecycle::new([1; 8], [2; 8], ike_keys(), 6, 0,
                Some(lifecycle::ChildSpis { inbound: [0x11; 4], outbound: [0x22; 4] })).unwrap(),
            settings,
            cancel: Cancellation::default(),
            queued_inner: VecDeque::new(),
            liveness_started: Instant::now(),
            liveness: liveness::Liveness::new(liveness::LivenessConfig::default(), 0).unwrap(),
            rekey_tsi: Vec::new(), rekey_tsr: Vec::new(),
            peer_old_deadline: None,
            child_started: Instant::now(), child_soft_after: CHILD_REKEY_SOFT,
            ike_started: Instant::now(), local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0,
        };
        let mut peer = engine::Engine::install(handoff(true), engine::esp::SystemCrypto).unwrap();
        let request = ip(Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(198, 51, 100, 254));
        let denied = ip(Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(session.send_ip(&denied), Err(Error::PacketDropped));
        let mut too_large = ip(Ipv4Addr::new(192, 0, 2, 2),
            Ipv4Addr::new(198, 51, 100, 254));
        too_large.resize(INNER_MTU + 1, 0);
        too_large[2..4].copy_from_slice(&((INNER_MTU + 1) as u16).to_be_bytes());
        assert_eq!(session.send_ip(&too_large), Err(Error::PacketDropped));
        assert_eq!(session.send_ip(&[0x45, 0, 0]), Err(Error::PacketDropped));
        assert_eq!(session.engine.as_ref().unwrap().next_outbound_sequence(), Some(1));
        session.send_ip(&request).unwrap();
        let mut wire = [0u8; 4096];
        let len = peer_socket.recv(&mut wire).unwrap();
        assert_eq!(peer.receive_udp(&wire[..len]).unwrap(), engine::Inbound::Ip(request));
        let reply = ip(Ipv4Addr::new(198, 51, 100, 254), Ipv4Addr::new(192, 0, 2, 2));
        let engine::Outbound::UdpPayload(encrypted) = peer.send_ip(&reply).unwrap() else { panic!() };
        // A late authenticated IKE_AUTH response and a bad-MAC INFORMATIONAL
        // cannot remove the established ESP engine or consume peer message 0.
        peer_socket.send(&init::udp_frame(&peer_packet(5, 0x20, 35))).unwrap();
        assert_eq!(session.receive().unwrap(), Event::Rejected);
        let mut corrupt_info = peer_info(0, 0x00);
        corrupt_info[50] ^= 0x80;
        peer_socket.send(&init::udp_frame(&corrupt_info)).unwrap();
        assert_eq!(session.receive().unwrap(), Event::Rejected);
        peer_socket.send(&encrypted).unwrap();
        assert_eq!(session.receive().unwrap(), Event::IpPacket(reply.clone()));
        peer_socket.send(&[1, 2, 3]).unwrap();
        assert_eq!(session.receive().unwrap(), Event::Rejected);
        peer_socket.send(&init::udp_frame(&peer_info(0, 0x00))).unwrap();
        assert_eq!(session.receive().unwrap(), Event::PeerDpd);
        let n = peer_socket.recv(&mut wire).unwrap();
        assert_eq!(&wire[..4], &[0; 4]);
        assert_eq!(wire[4 + 19], 0x28);
        assert_eq!(n, 84);
        session.queued_inner.extend((0..MAX_QUEUED_INNER).map(|_| vec![0]));
        let engine::Outbound::UdpPayload(overflow_ip) = peer.send_ip(&reply).unwrap() else { panic!() };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut buffer = [0u8; 4096];
                let len = peer_socket.recv(&mut buffer).unwrap();
                assert_eq!(len, 84);
                assert_eq!(buffer[4 + 18], 37);
                assert_eq!(buffer[4 + 19], 0x08);
                assert_eq!(u32::from_be_bytes(buffer[24..28].try_into().unwrap()), 6);
                peer_socket.send(&overflow_ip).unwrap();
                peer_socket.send(&init::udp_frame(&peer_info(6, 0x20))).unwrap();
            });
            session.probe_liveness().unwrap();
        });
        assert_eq!(session.queued_inner.len(), MAX_QUEUED_INNER);
        assert!(session.engine.is_some());
        session.queued_inner.clear();
        session.cancel.cancel();
        assert_eq!(session.receive(), Err(Error::Cancelled));
        let peer_thread = std::thread::spawn(move || {
            for expected_id in [7, 8] {
                let mut buffer = [0u8; 4096];
                let len = peer_socket.recv(&mut buffer).unwrap();
                assert!(len >= 84);
                assert_eq!(buffer[4 + 18], 37);
                assert_eq!(buffer[4 + 19], 0x08);
                assert_eq!(u32::from_be_bytes(buffer[24..28].try_into().unwrap()), expected_id);
                peer_socket.send(&init::udp_frame(&peer_info(expected_id, 0x20))).unwrap();
            }
        });
        let teardown = session.disconnect();
        peer_thread.join().unwrap();
        assert_eq!(teardown, Teardown::Clean);
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn retained_tcp_stream_sends_and_receives_synthetic_esp_across_partial_record() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut socket, _) = transport::Connection::open(
            listener.local_addr().unwrap(), transport::Wire::Tcp4443).unwrap();
        let (mut peer_socket, _) = listener.accept().unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let cancel = Cancellation::default();
        // A real connection sends SA_INIT first. Verify the once-only prefix
        // and leave this same stream in place for subsequent ESP records.
        let first_ike = peer_packet(5, 0x20, 35);
        socket.send_ike(&first_ike, &cancel).unwrap();
        let mut prefix = [0u8; 6];
        peer_socket.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"IKETCP");
        let mut length = [0u8; 2];
        peer_socket.read_exact(&mut length).unwrap();
        let n = u16::from_be_bytes(length) as usize;
        let mut rest = vec![0u8; n - 2];
        peer_socket.read_exact(&mut rest).unwrap();
        let mut initial_record = length.to_vec();
        initial_record.extend(rest);
        assert_eq!(init::unframe_tcp(&initial_record).unwrap(), first_ike);

        let mut client_sa = handoff(false);
        client_sa.transport = engine::Transport::Tcp4443;
        let mut peer_sa = handoff(true);
        peer_sa.transport = engine::Transport::Tcp4443;
        let mut session = Session {
            socket,
            engine: Some(engine::Engine::install(client_sa, engine::esp::SystemCrypto).unwrap()),
            lifecycle: lifecycle::Lifecycle::new([1; 8], [2; 8], ike_keys(), 6, 0,
                Some(lifecycle::ChildSpis { inbound: [0x11; 4], outbound: [0x22; 4] })).unwrap(),
            settings: NetworkSettings {
                outer_remote_ipv4: Ipv4Addr::LOCALHOST,
                outer_remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                assigned_ipv4: Ipv4Addr::new(192, 0, 2, 2), netmask: None,
                split_routes: vec![], dns_servers: vec![], dns_domains: vec![],
                inner_mtu: INNER_MTU,
            },
            cancel, queued_inner: VecDeque::new(),
            liveness_started: Instant::now(),
            liveness: liveness::Liveness::new(liveness::LivenessConfig::default(), 0).unwrap(),
            rekey_tsi: Vec::new(), rekey_tsr: Vec::new(),
            peer_old_deadline: None,
            child_started: Instant::now(), child_soft_after: CHILD_REKEY_SOFT,
            ike_started: Instant::now(), local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0,
        };
        let mut peer = engine::Engine::install(peer_sa, engine::esp::SystemCrypto).unwrap();
        let request = ip(Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(198, 51, 100, 254));
        session.send_ip(&request).unwrap();
        peer_socket.read_exact(&mut length).unwrap();
        let n = u16::from_be_bytes(length) as usize;
        let mut rest = vec![0u8; n - 2];
        peer_socket.read_exact(&mut rest).unwrap();
        let mut wire = length.to_vec();
        wire.extend(rest);
        assert_eq!(peer.receive_tcp(&wire).unwrap(), vec![engine::Inbound::Ip(request)]);

        let reply = ip(Ipv4Addr::new(198, 51, 100, 254), Ipv4Addr::new(192, 0, 2, 2));
        let engine::Outbound::TcpFrame(frame) = peer.send_ip(&reply).unwrap() else { panic!() };
        let encrypted = engine::tcp_esp::encode_frame(&frame, 4096).unwrap();
        peer_socket.write_all(&encrypted[..7]).unwrap();
        assert_eq!(session.receive().unwrap(), Event::Timeout);
        peer_socket.write_all(&encrypted[7..]).unwrap();
        assert_eq!(session.receive().unwrap(), Event::IpPacket(reply));
        session.cancel.cancel();
        let peer_thread = std::thread::spawn(move || {
            for expected_id in [6, 7] {
                let mut length = [0u8; 2];
                peer_socket.read_exact(&mut length).unwrap();
                let n = u16::from_be_bytes(length) as usize;
                let mut rest = vec![0u8; n - 2];
                peer_socket.read_exact(&mut rest).unwrap();
                let mut record = length.to_vec();
                record.extend(rest);
                let ike = init::unframe_tcp(&record).unwrap();
                assert_eq!(ike[18], 37);
                assert_eq!(ike[19], 0x08);
                assert_eq!(u32::from_be_bytes(ike[20..24].try_into().unwrap()), expected_id);
                peer_socket.write_all(&init::tcp_frame(&peer_info(expected_id, 0x20)).unwrap()).unwrap();
            }
        });
        let teardown = session.disconnect();
        peer_thread.join().unwrap();
        assert_eq!(teardown, Teardown::Clean);
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn peer_child_delete_during_dpd_is_not_reported_as_liveness() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(peer_socket.local_addr().unwrap()).unwrap();
        peer_socket.connect(client_socket.local_addr().unwrap()).unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let settings = NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::LOCALHOST,
            outer_remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            assigned_ipv4: Ipv4Addr::new(192, 0, 2, 2), netmask: None,
            split_routes: vec![engine::AddressRange {
                first: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
                last: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)),
            }], dns_servers: vec![], dns_domains: vec![], inner_mtu: INNER_MTU,
        };
        let mut session = Session {
            socket: transport::Connection::Udp(client_socket),
            engine: Some(engine::Engine::install(handoff(false), engine::esp::SystemCrypto).unwrap()),
            lifecycle: lifecycle::Lifecycle::new([1; 8], [2; 8], ike_keys(), 6, 0,
                Some(lifecycle::ChildSpis { inbound: [0x11; 4], outbound: [0x22; 4] })).unwrap(),
            settings, cancel: Cancellation::default(), queued_inner: VecDeque::new(),
            liveness_started: Instant::now(),
            liveness: liveness::Liveness::new(liveness::LivenessConfig::default(), 0).unwrap(),
            rekey_tsi: Vec::new(), rekey_tsr: Vec::new(),
            peer_old_deadline: None,
            child_started: Instant::now(), child_soft_after: CHILD_REKEY_SOFT,
            ike_started: Instant::now(), local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0,
        };
        let peer_thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let len = peer_socket.recv(&mut buffer).unwrap();
            assert_eq!(len, 84); // our empty DPD request
            peer_socket.send(&init::udp_frame(&peer_child_delete(0))).unwrap();
            let n = peer_socket.recv(&mut buffer).unwrap();
            assert!(n >= 84); // authenticated reply to peer delete
            assert_eq!(buffer[4 + 19], 0x28);
        });
        assert_eq!(session.probe_liveness(), Err(Error::Inactive));
        assert!(session.engine.is_none());
        assert!(!session.lifecycle.child_active());
        peer_thread.join().unwrap();
        assert_eq!(session.disconnect(), Teardown::LocalOnly);
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn crossed_child_delete_still_completes_ike_teardown() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(peer_socket.local_addr().unwrap()).unwrap();
        peer_socket.connect(client_socket.local_addr().unwrap()).unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let session = Session {
            socket: transport::Connection::Udp(client_socket),
            engine: Some(engine::Engine::install(handoff(false), engine::esp::SystemCrypto).unwrap()),
            lifecycle: lifecycle::Lifecycle::new([1; 8], [2; 8], ike_keys(), 6, 0,
                Some(lifecycle::ChildSpis { inbound: [0x11; 4], outbound: [0x22; 4] })).unwrap(),
            settings: NetworkSettings {
                outer_remote_ipv4: Ipv4Addr::LOCALHOST,
                outer_remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                assigned_ipv4: Ipv4Addr::new(192, 0, 2, 2), netmask: None,
                split_routes: vec![], dns_servers: vec![], dns_domains: vec![], inner_mtu: INNER_MTU,
            },
            cancel: Cancellation::default(), queued_inner: VecDeque::new(),
            liveness_started: Instant::now(),
            liveness: liveness::Liveness::new(liveness::LivenessConfig::default(), 0).unwrap(),
            rekey_tsi: Vec::new(), rekey_tsr: Vec::new(),
            peer_old_deadline: None,
            child_started: Instant::now(), child_soft_after: CHILD_REKEY_SOFT,
            ike_started: Instant::now(), local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0,
        };
        let peer_thread = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let n = peer_socket.recv(&mut buffer).unwrap();
            assert!(n >= 84);
            assert_eq!(buffer[4 + 18], 37);
            assert_eq!(buffer[4 + 19], 0x08);
            assert_eq!(u32::from_be_bytes(buffer[4 + 20..4 + 24].try_into().unwrap()), 6);
            assert_eq!(buffer[4 + 28], 42); // our CHILD DELETE

            peer_socket.send(&init::udp_frame(&peer_child_delete(0))).unwrap();
            let n = peer_socket.recv(&mut buffer).unwrap();
            assert!(n >= 84);
            assert_eq!(buffer[4 + 19], 0x28);
            assert_eq!(u32::from_be_bytes(buffer[4 + 20..4 + 24].try_into().unwrap()), 0);
            assert_eq!(buffer[4 + 28], 0); // empty crossed DELETE response

            peer_socket.send(&init::udp_frame(&peer_info(6, 0x20))).unwrap();
            let n = peer_socket.recv(&mut buffer).unwrap();
            assert!(n >= 84);
            assert_eq!(buffer[4 + 19], 0x08);
            assert_eq!(u32::from_be_bytes(buffer[4 + 20..4 + 24].try_into().unwrap()), 7);
            assert_eq!(buffer[4 + 28], 42); // subsequent IKE DELETE
            peer_socket.send(&init::udp_frame(&peer_info(7, 0x20))).unwrap();
        });
        assert_eq!(session.disconnect(), Teardown::Clean);
        peer_thread.join().unwrap();
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn nonblocking_dpd_survives_stall_and_late_reply_then_requests_reconnect() {
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket.connect(peer_socket.local_addr().unwrap()).unwrap();
        peer_socket.connect(client_socket.local_addr().unwrap()).unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut session = Session {
            socket: transport::Connection::Udp(client_socket),
            engine: Some(engine::Engine::install(handoff(false), engine::esp::SystemCrypto).unwrap()),
            lifecycle: lifecycle::Lifecycle::new([1; 8], [2; 8], ike_keys(), 6, 0,
                Some(lifecycle::ChildSpis { inbound: [0x11; 4], outbound: [0x22; 4] })).unwrap(),
            settings: NetworkSettings {
                outer_remote_ipv4: Ipv4Addr::LOCALHOST,
                outer_remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                assigned_ipv4: Ipv4Addr::new(192, 0, 2, 2), netmask: None,
                split_routes: vec![], dns_servers: vec![], dns_domains: vec![],
                inner_mtu: INNER_MTU,
            },
            cancel: Cancellation::default(), queued_inner: VecDeque::new(),
            liveness_started: Instant::now() - Duration::from_secs(20),
            liveness: liveness::Liveness::new(liveness::LivenessConfig::default(), 0).unwrap(),
            rekey_tsi: Vec::new(), rekey_tsr: Vec::new(),
            peer_old_deadline: None,
            child_started: Instant::now(), child_soft_after: CHILD_REKEY_SOFT,
            ike_started: Instant::now(), local_rekeys: 0, peer_rekeys: 0, ike_rekeys: 0,
        };
        let mut peer = engine::Engine::install(handoff(true), engine::esp::SystemCrypto).unwrap();
        let mut wire = [0u8; 4096];
        assert_eq!(session.tick_liveness_at(20_000), Ok(()));
        let n = peer_socket.recv(&mut wire).unwrap();
        let first_dpd = wire[..n].to_vec();
        assert_eq!(first_dpd[4 + 18], 37);
        assert_eq!(u32::from_be_bytes(first_dpd[4 + 20..4 + 24].try_into().unwrap()), 6);
        assert_eq!(session.tick_liveness_at(60_000), Ok(()));
        let n = peer_socket.recv(&mut wire).unwrap();
        assert_eq!(&wire[..n], first_dpd);
        assert!(session.engine.is_some());
        assert_eq!(session.lifecycle.next_local_id(), 6);

        // Model a 41-second path stall without a real sleep. An invalid-MAC
        // response cannot complete DPD or refresh authenticated activity.
        session.liveness_started = Instant::now() - Duration::from_secs(61);
        let mut forged = peer_info(6, 0x20);
        forged[50] ^= 0x80;
        peer_socket.send(&init::udp_frame(&forged)).unwrap();
        assert_eq!(session.receive(), Ok(Event::Rejected));
        assert!(session.liveness.probe_pending());
        peer_socket.send(&init::udp_frame(&peer_info(6, 0x20))).unwrap();
        assert_eq!(session.receive(), Ok(Event::Rejected));
        assert!(!session.liveness.probe_pending());
        assert_eq!(session.lifecycle.next_local_id(), 7);

        let reply = ip(Ipv4Addr::new(198, 51, 100, 254), Ipv4Addr::new(192, 0, 2, 2));
        let engine::Outbound::UdpPayload(encrypted) = peer.send_ip(&reply).unwrap() else { panic!() };
        peer_socket.send(&encrypted).unwrap();
        assert_eq!(session.receive(), Ok(Event::IpPacket(reply)));
        assert_eq!(session.tick_liveness_at(80_000), Ok(()));
        assert!(session.engine.is_some());
        assert_eq!(session.tick_liveness_at(82_000), Ok(()));
        let n = peer_socket.recv(&mut wire).unwrap();
        assert_eq!(u32::from_be_bytes(wire[4 + 20..4 + 24].try_into().unwrap()), 7);
        assert_eq!(n, 84);
        assert_eq!(session.tick_liveness_at(142_000), Err(Error::ReconnectNeeded));
        assert!(session.engine.is_none());
        assert_eq!(session.tick_liveness_at(147_000), Err(Error::ReconnectNeeded));
    }
}
