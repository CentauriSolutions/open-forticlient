//! Offline boundary between a verified IKE CHILD_SA, a packet tunnel, and ESP transports.
//! This imports the engine modules without changing their implementations.

pub mod esp;
pub mod tcp_esp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidHandoff,
    UnsupportedSuite,
    UnsupportedSelector,
    PolicyDenied,
    MtuExceeded,
    WrongTransport,
    Esp(esp::Error),
    Framing(tcp_esp::FramingError),
}

impl From<esp::Error> for Error {
    fn from(value: esp::Error) -> Self {
        Self::Esp(value)
    }
}
impl From<tcp_esp::FramingError> for Error {
    fn from(value: tcp_esp::FramingError) -> Self {
        Self::Framing(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp4500,
    Tcp4443,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspSuite {
    Aes256CbcHmacSha1_96,
    Other { encryption: u16, integrity: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    pub first: IpAddr,
    pub last: IpAddr,
}

impl AddressRange {
    fn bounds(&self) -> Option<(u128, u128, u8)> {
        match (self.first, self.last) {
            (IpAddr::V4(a), IpAddr::V4(b)) => Some((u32::from(a) as u128, u32::from(b) as u128, 4)),
            (IpAddr::V6(a), IpAddr::V6(b)) => Some((u128::from(a), u128::from(b), 6)),
            _ => None,
        }
    }
    fn valid_for(&self, family: u8) -> bool {
        matches!(self.bounds(), Some((first, last, f)) if f == family && first <= last)
    }
    fn contains(&self, addr: IpAddr) -> bool {
        match (self.bounds(), addr) {
            (Some((first, last, 4)), IpAddr::V4(a)) => {
                (first..=last).contains(&(u32::from(a) as u128))
            }
            (Some((first, last, 6)), IpAddr::V6(a)) => (first..=last).contains(&u128::from(a)),
            _ => false,
        }
    }
    fn contains_range(&self, other: &Self) -> bool {
        self.contains(other.first) && self.contains(other.last)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSelector {
    pub addresses: AddressRange,
    pub protocol: u8, // zero means any IP protocol
    pub first_port: u16,
    pub last_port: u16,
}

impl TrafficSelector {
    fn supported(&self, family: u8) -> bool {
        self.addresses.valid_for(family)
            && self.protocol == 0
            && self.first_port == 0
            && self.last_port == u16::MAX
    }
}

/// Produced only after responder AUTH, EAP, final IKE_AUTH, and CHILD_SA
/// negotiation have all been authenticated by the IKE core. The source of this
/// type is a trust boundary; offline tests use public synthetic values.
pub struct AuthenticatedChildSa {
    pub suite: EspSuite,
    pub esn: bool,
    pub peer_inbound_spi: u32,
    pub local_inbound_spi: u32,
    pub outbound_keys: esp::Keys,
    pub inbound_keys: esp::Keys,
    pub assigned_ip: IpAddr,
    pub local_selectors: Vec<TrafficSelector>,
    pub remote_selectors: Vec<TrafficSelector>,
    pub installed_routes: Vec<AddressRange>,
    pub inner_mtu: usize,
    pub transport: Transport,
    pub max_tcp_record: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    UdpPayload(Vec<u8>),
    TcpFrame(tcp_esp::Frame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Ip(Vec<u8>),
    Ike(Vec<u8>),
    NatKeepalive,
}

pub struct Engine<C: esp::Crypto> {
    outgoing: esp::OutboundSa<C>,
    incoming: esp::InboundSa<C>,
    active_inbound_spi: u32,
    active_outbound_spi: u32,
    old_incoming: Vec<(u32, esp::InboundSa<C>)>,
    crypto: C,
    assigned_ip: IpAddr,
    local_selectors: Vec<TrafficSelector>,
    remote_selectors: Vec<TrafficSelector>,
    routes: Vec<AddressRange>,
    mtu: usize,
    transport: Transport,
    tcp_decoder: Option<tcp_esp::StreamDecoder>,
}

impl<C: esp::Crypto + Clone> Engine<C> {
    pub fn install(sa: AuthenticatedChildSa, crypto: C) -> Result<Self, Error> {
        if sa.suite != EspSuite::Aes256CbcHmacSha1_96 {
            return Err(Error::UnsupportedSuite);
        }
        if sa.esn
            || sa.peer_inbound_spi == 0
            || sa.local_inbound_spi == 0
            || sa.local_selectors.is_empty()
            || sa.remote_selectors.is_empty()
            || sa.installed_routes.is_empty()
            || sa.installed_routes.len() > 64
            || sa.inner_mtu < 576
            || sa.inner_mtu > 65_535
            || (sa.assigned_ip.is_ipv6() && sa.inner_mtu < 1280)
        {
            return Err(Error::InvalidHandoff);
        }
        let family = if sa.assigned_ip.is_ipv4() { 4 } else { 6 };
        if !sa.local_selectors.iter().all(|s| s.supported(family))
            || !sa.remote_selectors.iter().all(|s| s.supported(family))
        {
            return Err(Error::UnsupportedSelector);
        }
        if !sa
            .local_selectors
            .iter()
            .any(|s| s.addresses.contains(sa.assigned_ip))
            || !sa.installed_routes.iter().all(|route| {
                route.valid_for(family)
                    && sa
                        .remote_selectors
                        .iter()
                        .any(|s| s.addresses.contains_range(route))
            })
        {
            return Err(Error::InvalidHandoff);
        }
        let tcp_decoder = if sa.transport == Transport::Tcp4443 {
            // 2-byte record length + ESP SPI/sequence + IV + CBC padded IP/trailer + ICV.
            let padded = (sa.inner_mtu + 2).div_ceil(16) * 16;
            if 2 + 8 + 16 + padded + 12 > sa.max_tcp_record {
                return Err(Error::InvalidHandoff);
            }
            Some(tcp_esp::StreamDecoder::new(false, sa.max_tcp_record)?)
        } else {
            None
        };
        let outgoing = esp::OutboundSa::new(sa.peer_inbound_spi, sa.outbound_keys, crypto.clone())?;
        let incoming = esp::InboundSa::new(sa.local_inbound_spi, sa.inbound_keys, crypto.clone())?;
        Ok(Self {
            outgoing,
            incoming,
            active_inbound_spi: sa.local_inbound_spi,
            active_outbound_spi: sa.peer_inbound_spi,
            old_incoming: Vec::new(),
            crypto,
            assigned_ip: sa.assigned_ip,
            local_selectors: sa.local_selectors,
            remote_selectors: sa.remote_selectors,
            routes: sa.installed_routes,
            mtu: sa.inner_mtu,
            transport: sa.transport,
            tcp_decoder,
        })
    }

    pub fn next_outbound_sequence(&self) -> Option<u32> {
        self.outgoing.next_sequence()
    }

    pub fn active_spis(&self) -> (u32, u32) {
        (self.active_inbound_spi, self.active_outbound_spi)
    }

    /// Authenticated rekey handover. Build both new SAs before changing the
    /// active outbound SA; each retained inbound SPI keeps its own replay
    /// window. Two old inbound SAs bound collision overlap.
    pub fn install_rekey(&mut self, inbound_spi: u32, outbound_spi: u32,
                         inbound_keys: esp::Keys, outbound_keys: esp::Keys)
                         -> Result<(u32, u32), Error> {
        if inbound_spi <= 255 || outbound_spi <= 255
            || inbound_spi == self.active_inbound_spi
            || self.old_incoming.iter().any(|(spi, _)| *spi == inbound_spi)
            || outbound_spi == self.active_outbound_spi
            || self.old_incoming.len() >= 2 {
            return Err(Error::InvalidHandoff);
        }
        let incoming = esp::InboundSa::new(inbound_spi, inbound_keys, self.crypto.clone())?;
        let outgoing = esp::OutboundSa::new(outbound_spi, outbound_keys, self.crypto.clone())?;
        let old_incoming = std::mem::replace(&mut self.incoming, incoming);
        self.old_incoming.push((self.active_inbound_spi, old_incoming));
        self.outgoing = outgoing;
        let old = (self.active_inbound_spi, self.active_outbound_spi);
        self.active_inbound_spi = inbound_spi;
        self.active_outbound_spi = outbound_spi;
        Ok(old)
    }

    /// Retire only an old local inbound SPI after authenticated DELETE or a
    /// bounded grace. The active inbound SPI cannot be removed here.
    pub fn retire_old_inbound(&mut self, spi: u32) -> Result<(), Error> {
        let index = self.old_incoming.iter().position(|(old, _)| *old == spi)
            .ok_or(Error::InvalidHandoff)?;
        self.old_incoming.remove(index);
        Ok(())
    }

    /// Packet tunnel calls this only for packets emitted by its own assigned interface.
    pub fn send_ip(&mut self, packet: &[u8]) -> Result<Outbound, Error> {
        let (src, dst) = endpoints(packet)?;
        if packet.len() > self.mtu {
            return Err(Error::MtuExceeded);
        }
        if src != self.assigned_ip
            || !self
                .local_selectors
                .iter()
                .any(|s| s.addresses.contains(src))
            || !self
                .remote_selectors
                .iter()
                .any(|s| s.addresses.contains(dst))
            || !self.routes.iter().any(|r| r.contains(dst))
        {
            return Err(Error::PolicyDenied);
        }
        let esp = self.outgoing.seal(packet)?;
        Ok(match self.transport {
            Transport::Udp4500 => Outbound::UdpPayload(esp),
            Transport::Tcp4443 => Outbound::TcpFrame(tcp_esp::Frame::Esp(esp)),
        })
    }

    pub fn receive_udp(&mut self, payload: &[u8]) -> Result<Inbound, Error> {
        if self.transport != Transport::Udp4500 {
            return Err(Error::WrongTransport);
        }
        match esp::classify_udp4500(payload)? {
            esp::Udp4500::Esp(bytes) => self.open_esp(bytes),
            esp::Udp4500::Ike(bytes) => Ok(Inbound::Ike(bytes.to_vec())),
            esp::Udp4500::NatKeepalive => Ok(Inbound::NatKeepalive),
        }
    }

    /// TCP records share the established IKE stream. Caller owns the originator
    /// writer, including its once-per-connection IKETCP prefix.
    pub fn receive_tcp(&mut self, bytes: &[u8]) -> Result<Vec<Inbound>, Error> {
        let Some(decoder) = self.tcp_decoder.as_mut() else {
            return Err(Error::WrongTransport);
        };
        let frames = decoder.feed(bytes)?;
        frames
            .into_iter()
            .map(|frame| match frame {
                tcp_esp::Frame::Esp(bytes) => self.open_esp(&bytes),
                tcp_esp::Frame::Ike(bytes) => Ok(Inbound::Ike(bytes)),
            })
            .collect()
    }

    fn open_esp(&mut self, bytes: &[u8]) -> Result<Inbound, Error> {
        if bytes.len() < 4 { return Err(Error::Esp(esp::Error::InvalidPacket)); }
        let spi = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let ip = if spi == self.active_inbound_spi {
            self.incoming.open(bytes)?
        } else {
            self.old_incoming.iter_mut().find(|(old, _)| *old == spi)
                .ok_or(Error::Esp(esp::Error::InvalidSa))?.1.open(bytes)?
        };
        let (src, dst) = endpoints(&ip)?;
        if ip.len() > self.mtu {
            return Err(Error::MtuExceeded);
        }
        if dst != self.assigned_ip
            || !self
                .local_selectors
                .iter()
                .any(|s| s.addresses.contains(dst))
            || !self
                .remote_selectors
                .iter()
                .any(|s| s.addresses.contains(src))
        {
            return Err(Error::PolicyDenied);
        }
        Ok(Inbound::Ip(ip))
    }
}

fn endpoints(packet: &[u8]) -> Result<(IpAddr, IpAddr), Error> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20
                || header > packet.len()
                || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
            {
                return Err(Error::Esp(esp::Error::InvalidPacket));
            }
            Ok((
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
            ))
        }
        Some(6) if packet.len() >= 40 => {
            if packet.len() != 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])) {
                return Err(Error::Esp(esp::Error::InvalidPacket));
            }
            Ok((
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
                )),
            ))
        }
        _ => Err(Error::Esp(esp::Error::InvalidPacket)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use esp::SystemCrypto;

    fn ip(a: [u8; 4], b: [u8; 4], len: usize) -> Vec<u8> {
        let mut p = vec![0; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 1;
        p[12..16].copy_from_slice(&a);
        p[16..20].copy_from_slice(&b);
        p
    }
    fn keys(seed: u8) -> esp::Keys {
        esp::Keys {
            encryption: [seed; 32],
            integrity: [seed.wrapping_add(1); 20],
        }
    }
    fn range(a: [u8; 4], b: [u8; 4]) -> AddressRange {
        AddressRange {
            first: IpAddr::V4(a.into()),
            last: IpAddr::V4(b.into()),
        }
    }
    fn selector(addresses: AddressRange) -> TrafficSelector {
        TrafficSelector {
            addresses,
            protocol: 0,
            first_port: 0,
            last_port: u16::MAX,
        }
    }
    fn handoff(peer: bool, transport: Transport) -> AuthenticatedChildSa {
        let local = range([192, 0, 2, 0], [192, 0, 2, 255]);
        let remote = range([198, 51, 100, 0], [198, 51, 100, 255]);
        AuthenticatedChildSa {
            suite: EspSuite::Aes256CbcHmacSha1_96,
            esn: false,
            peer_inbound_spi: if peer { 0x11111111 } else { 0x22222222 },
            local_inbound_spi: if peer { 0x22222222 } else { 0x11111111 },
            outbound_keys: keys(if peer { 0x44 } else { 0x22 }),
            inbound_keys: keys(if peer { 0x22 } else { 0x44 }),
            assigned_ip: IpAddr::V4(if peer {
                [198, 51, 100, 2].into()
            } else {
                [192, 0, 2, 1].into()
            }),
            local_selectors: vec![selector(if peer { remote } else { local })],
            remote_selectors: vec![selector(if peer { local } else { remote })],
            installed_routes: vec![if peer { local } else { remote }],
            inner_mtu: 1400,
            transport,
            max_tcp_record: tcp_esp::DEFAULT_MAX_RECORD,
        }
    }
    fn pair(t: Transport) -> (Engine<SystemCrypto>, Engine<SystemCrypto>) {
        (
            Engine::install(handoff(false, t), SystemCrypto).unwrap(),
            Engine::install(handoff(true, t), SystemCrypto).unwrap(),
        )
    }

    #[test]
    fn synthetic_udp_both_directions_integrity_replay_and_demux() {
        let (mut a, mut b) = pair(Transport::Udp4500);
        let request = ip([192, 0, 2, 1], [198, 51, 100, 2], 84);
        let Outbound::UdpPayload(wire) = a.send_ip(&request).unwrap() else {
            panic!()
        };
        assert!(matches!(
            esp::classify_udp4500(&wire),
            Ok(esp::Udp4500::Esp(_))
        ));
        let mut corrupted = wire.clone();
        corrupted[25] ^= 1;
        assert_eq!(
            b.receive_udp(&corrupted),
            Err(Error::Esp(esp::Error::AuthenticationFailed))
        );
        assert_eq!(b.receive_udp(&wire), Ok(Inbound::Ip(request)));
        assert_eq!(b.receive_udp(&wire), Err(Error::Esp(esp::Error::Replay)));
        let reply = ip([198, 51, 100, 2], [192, 0, 2, 1], 100);
        let Outbound::UdpPayload(wire) = b.send_ip(&reply).unwrap() else {
            panic!()
        };
        assert_eq!(a.receive_udp(&wire), Ok(Inbound::Ip(reply)));
        assert_eq!(a.receive_udp(&[0xff]), Ok(Inbound::NatKeepalive));
        let mut ike = vec![0; 32];
        ike[4] = 1;
        assert_eq!(a.receive_udp(&ike), Ok(Inbound::Ike(ike[4..].to_vec())));
        assert_eq!(a.receive_tcp(&[]), Err(Error::WrongTransport));
    }

    #[test]
    fn synthetic_tcp_shared_stream_fragmented_records_and_replay() {
        let (mut a, mut b) = pair(Transport::Tcp4443);
        let request = ip([192, 0, 2, 1], [198, 51, 100, 2], 84);
        let Outbound::TcpFrame(frame) = a.send_ip(&request).unwrap() else {
            panic!()
        };
        let mut writer = tcp_esp::OriginatorWriter::new(Vec::new(), tcp_esp::DEFAULT_MAX_RECORD);
        let mut ike = vec![0; 28];
        ike[24..28].copy_from_slice(&28u32.to_be_bytes());
        writer.send(&tcp_esp::Frame::Ike(ike)).unwrap();
        writer.send(&frame).unwrap();
        let stream = writer.into_inner();
        assert_eq!(&stream[..6], tcp_esp::PREFIX);
        // B's established originator stream parser expects the one prefix.
        let mut parser = tcp_esp::StreamDecoder::new(true, tcp_esp::DEFAULT_MAX_RECORD).unwrap();
        let frames: Vec<_> = stream
            .chunks(3)
            .flat_map(|c| parser.feed(c).unwrap())
            .collect();
        assert!(matches!(
            &frames[..],
            [tcp_esp::Frame::Ike(_), tcp_esp::Frame::Esp(_)]
        ));
        let tcp_esp::Frame::Esp(esp) = &frames[1] else {
            panic!()
        };
        // B receives ESP on the established responder stream: no responder prefix.
        let inbound_record =
            tcp_esp::encode_frame(&tcp_esp::Frame::Esp(esp.clone()), 8192).unwrap();
        let mut received = Vec::new();
        for chunk in inbound_record.chunks(2) {
            received.extend(b.receive_tcp(chunk).unwrap());
        }
        assert_eq!(received, vec![Inbound::Ip(request)]);
        assert_eq!(
            b.receive_tcp(&inbound_record),
            Err(Error::Esp(esp::Error::Replay))
        );
        let reply = ip([198, 51, 100, 2], [192, 0, 2, 1], 100);
        let Outbound::TcpFrame(frame) = b.send_ip(&reply).unwrap() else {
            panic!()
        };
        let responder_record = tcp_esp::encode_frame(&frame, 8192).unwrap();
        assert_eq!(
            a.receive_tcp(&responder_record),
            Ok(vec![Inbound::Ip(reply)])
        );
        let ike_record = tcp_esp::encode_frame(
            &tcp_esp::Frame::Ike(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28,
            ]),
            8192,
        )
        .unwrap();
        assert!(matches!(a.receive_tcp(&ike_record), Ok(v) if matches!(&v[..], [Inbound::Ike(_)])));
        assert_eq!(a.receive_udp(&[]), Err(Error::WrongTransport));
    }

    #[test]
    fn policy_mtu_and_handoff_fail_closed_before_sequence() {
        let (mut a, _) = pair(Transport::Udp4500);
        let good = ip([192, 0, 2, 1], [198, 51, 100, 2], 84);
        assert_eq!(a.next_outbound_sequence(), Some(1));
        for bad in [
            ip([192, 0, 2, 9], [198, 51, 100, 2], 84),
            ip([192, 0, 2, 1], [203, 0, 113, 5], 84),
        ] {
            assert_eq!(a.send_ip(&bad), Err(Error::PolicyDenied));
        }
        assert_eq!(
            a.send_ip(&ip([192, 0, 2, 1], [198, 51, 100, 2], 1401)),
            Err(Error::MtuExceeded)
        );
        assert_eq!(a.next_outbound_sequence(), Some(1));
        assert!(a.send_ip(&good).is_ok());
        let mut h = handoff(false, Transport::Udp4500);
        h.esn = true;
        assert!(matches!(
            Engine::install(h, SystemCrypto),
            Err(Error::InvalidHandoff)
        ));
        let mut h = handoff(false, Transport::Udp4500);
        h.suite = EspSuite::Other {
            encryption: 20,
            integrity: 0,
        };
        assert!(matches!(
            Engine::install(h, SystemCrypto),
            Err(Error::UnsupportedSuite)
        ));
        let mut h = handoff(false, Transport::Udp4500);
        h.remote_selectors[0].protocol = 6;
        assert!(matches!(
            Engine::install(h, SystemCrypto),
            Err(Error::UnsupportedSelector)
        ));
        let mut h = handoff(false, Transport::Udp4500);
        h.installed_routes = vec![range([203, 0, 113, 0], [203, 0, 113, 255])];
        assert!(matches!(
            Engine::install(h, SystemCrypto),
            Err(Error::InvalidHandoff)
        ));
        let mut h = handoff(false, Transport::Tcp4443);
        h.max_tcp_record = 100;
        assert!(matches!(
            Engine::install(h, SystemCrypto),
            Err(Error::InvalidHandoff)
        ));
    }

    #[test]
    fn split_route_must_be_inside_selector_and_controls_outbound_only() {
        let mut h = handoff(false, Transport::Udp4500);
        h.installed_routes = vec![range([198, 51, 100, 0], [198, 51, 100, 127])];
        let mut a = Engine::install(h, SystemCrypto).unwrap();
        let inside = ip([192, 0, 2, 1], [198, 51, 100, 2], 84);
        let outside_route = ip([192, 0, 2, 1], [198, 51, 100, 200], 84);
        assert_eq!(a.send_ip(&outside_route), Err(Error::PolicyDenied));
        assert_eq!(a.next_outbound_sequence(), Some(1));
        assert!(a.send_ip(&inside).is_ok());
        // Return traffic is checked against authenticated selectors and local
        // address; installed outbound split routes do not restrict its source.
        let from_other_peer_address = ip([198, 51, 100, 200], [192, 0, 2, 1], 84);
        let mut peer = esp::OutboundSa::new(0x11111111, keys(0x44), SystemCrypto).unwrap();
        assert_eq!(
            a.receive_udp(&peer.seal(&from_other_peer_address).unwrap()),
            Ok(Inbound::Ip(from_other_peer_address))
        );
    }

    #[test]
    fn ipv6_inner_packet_and_minimum_mtu_boundary() {
        let local: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let remote: Ipv6Addr = "2001:db8:2::2".parse().unwrap();
        let mut a_h = handoff(false, Transport::Udp4500);
        let mut b_h = handoff(true, Transport::Udp4500);
        for (h, mine, peer) in [(&mut a_h, local, remote), (&mut b_h, remote, local)] {
            h.assigned_ip = IpAddr::V6(mine);
            h.local_selectors = vec![selector(AddressRange {
                first: IpAddr::V6(mine),
                last: IpAddr::V6(mine),
            })];
            h.remote_selectors = vec![selector(AddressRange {
                first: IpAddr::V6(peer),
                last: IpAddr::V6(peer),
            })];
            h.installed_routes = vec![AddressRange {
                first: IpAddr::V6(peer),
                last: IpAddr::V6(peer),
            }];
            h.inner_mtu = 1280;
        }
        let mut a = Engine::install(a_h, SystemCrypto).unwrap();
        let mut b = Engine::install(b_h, SystemCrypto).unwrap();
        let mut p = vec![0; 1280];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&1240u16.to_be_bytes());
        p[8..24].copy_from_slice(&local.octets());
        p[24..40].copy_from_slice(&remote.octets());
        let Outbound::UdpPayload(wire) = a.send_ip(&p).unwrap() else {
            panic!()
        };
        assert_eq!(b.receive_udp(&wire), Ok(Inbound::Ip(p.clone())));
        p.push(0);
        p[4..6].copy_from_slice(&1241u16.to_be_bytes());
        assert_eq!(a.send_ip(&p), Err(Error::MtuExceeded));
        assert_eq!(a.next_outbound_sequence(), Some(2));
    }

    #[test]
    fn inbound_authenticated_packet_outside_selector_is_denied() {
        let (mut a, mut b) = pair(Transport::Udp4500);
        // A packet with a valid ESP integrity tag but a source outside A's
        // negotiated peer selector must not enter the packet tunnel.
        let bogus = ip([198, 51, 101, 2], [192, 0, 2, 1], 84);
        let mut raw = esp::OutboundSa::new(0x11111111, keys(0x44), SystemCrypto).unwrap();
        let wire = raw.seal(&bogus).unwrap();
        assert_eq!(a.receive_udp(&wire), Err(Error::PolicyDenied));
        assert_eq!(a.receive_udp(&wire), Err(Error::Esp(esp::Error::Replay)));
        // Peer-side engine itself would also refuse to emit it.
        assert_eq!(b.send_ip(&bogus), Err(Error::PolicyDenied));
    }

    #[test]
    fn rekey_keeps_old_and_new_replay_windows_then_retires_old_spi() {
        let (mut a, mut b) = pair(Transport::Udp4500);
        let reply = ip([198, 51, 100, 2], [192, 0, 2, 1], 84);
        let mut old_wires = Vec::new();
        for _ in 0..3 {
            let Outbound::UdpPayload(wire) = b.send_ip(&reply).unwrap() else { panic!() };
            old_wires.push(wire);
        }
        assert_eq!(a.receive_udp(&old_wires[0]), Ok(Inbound::Ip(reply.clone())));
        assert_eq!(a.install_rekey(0x44444444, 0x33333333,
            keys(0x66), keys(0x55)).unwrap(), (0x11111111, 0x22222222));
        assert_eq!(b.install_rekey(0x33333333, 0x44444444,
            keys(0x55), keys(0x66)).unwrap(), (0x22222222, 0x11111111));
        let Outbound::UdpPayload(new_wire) = b.send_ip(&reply).unwrap() else { panic!() };
        assert_eq!(a.receive_udp(&new_wire), Ok(Inbound::Ip(reply.clone())));
        assert_eq!(a.receive_udp(&old_wires[1]), Ok(Inbound::Ip(reply.clone())));
        assert_eq!(a.receive_udp(&new_wire), Err(Error::Esp(esp::Error::Replay)));
        assert_eq!(a.receive_udp(&old_wires[1]), Err(Error::Esp(esp::Error::Replay)));
        a.retire_old_inbound(0x11111111).unwrap();
        assert_eq!(a.receive_udp(&old_wires[2]), Err(Error::Esp(esp::Error::InvalidSa)));
        assert_eq!(a.active_spis(), (0x44444444, 0x33333333));
        assert_eq!(a.next_outbound_sequence(), Some(1));
    }
}
