//! One connected outer socket. TCP keeps RFC 9329 record boundaries across
//! partial reads and sends its IKETCP prefix once per connection.
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::session::{Cancellation, Error, READ_SLICE};
use crate::{engine, init};

const MAX_RECORD: usize = 8192;
const DNS_DEADLINE: Duration = Duration::from_secs(3);
const TCP_CONNECT_DEADLINE: Duration = Duration::from_secs(4);
// A TCP path can stall for 30-40 seconds without the IKE SA being dead.
// A short write deadline would tear down a healthy tunnel before liveness
// has its own 60-second authenticated-silence grace period.
const WRITE_DEADLINE: Duration = Duration::from_secs(45);
// Length 7 (includes the length field), the four-zero non-ESP marker every
// TCP-carried IKE record has, then the 0xff NAT keepalive byte. This is what
// FortiClient sends every ~20 s; a bare 00 03 ff (no marker) draws a gateway RST.
const TCP_KEEPALIVE_RECORD: [u8; 7] = [0, 7, 0, 0, 0, 0, 0xff];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    Udp4500,
    Tcp4443,
}

impl Wire {
    pub fn port(self) -> u16 {
        match self { Self::Udp4500 => 4500, Self::Tcp4443 => 4443 }
    }
    pub fn engine(self) -> engine::Transport {
        match self {
            Self::Udp4500 => engine::Transport::Udp4500,
            Self::Tcp4443 => engine::Transport::Tcp4443,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterFamily { Ipv4, Ipv6 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectOptions {
    pub wire: Wire,
    pub family: OuterFamily,
    /// Required for IPv6 outer connections; use the caller-observed CLAT
    /// address. The FortiGate dialect still sends an ID_IPV4_ADDR payload.
    pub idi_v4: Option<Ipv4Addr>,
    /// Only after UDP SA_INIT gets no usable response or its socket fails.
    /// TCP starts with a new SPI, DH key, and NAT-detection hashes.
    pub tcp_fallback: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { wire: Wire::Udp4500, family: OuterFamily::Ipv4,
            idi_v4: None, tcp_fallback: true }
    }
}

impl ConnectOptions {
    pub fn validate(self) -> Result<(), Error> {
        match (self.family, self.idi_v4) {
            (OuterFamily::Ipv4, None) => Ok(()),
            (OuterFamily::Ipv6, Some(addr)) if usable_idi(addr) => Ok(()),
            _ => Err(Error::InvalidInput),
        }
    }

    pub fn fallback_after(self, error: Error) -> Option<Self> {
        if self.wire == Wire::Udp4500 && self.tcp_fallback
            && matches!(error, Error::Timeout(0) | Error::Socket) {
            Some(Self { wire: Wire::Tcp4443, tcp_fallback: false, ..self })
        } else {
            None
        }
    }
}

fn usable_idi(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn selected_addr(addresses: impl IntoIterator<Item = SocketAddr>, family: OuterFamily)
    -> Option<SocketAddr> {
    addresses.into_iter().find(|addr| match (family, addr) {
        (OuterFamily::Ipv4, SocketAddr::V4(v4)) => {
            !v4.ip().is_unspecified() && !v4.ip().is_multicast()
        }
        (OuterFamily::Ipv6, SocketAddr::V6(v6)) => {
            !v6.ip().is_unspecified() && !v6.ip().is_multicast()
                && v6.ip().to_ipv4_mapped().is_none()
        }
        _ => false,
    })
}

/// getaddrinfo may block indefinitely. The bounded caller owns no secrets in
/// the worker, and a late result cannot initiate a connection.
pub fn resolve(gateway: &str, options: ConnectOptions, cancel: &Cancellation)
    -> Result<SocketAddr, Error> {
    let gateway = gateway.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new().name("oftc-outer-dns".into()).spawn(move || {
        let result = (gateway.as_str(), options.wire.port()).to_socket_addrs()
            .ok().and_then(|addresses| selected_addr(addresses, options.family));
        let _ = sender.send(result);
    }).map_err(|_| Error::Resolve)?;
    let deadline = Instant::now() + DNS_DEADLINE;
    loop {
        cancel.check()?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(Error::Resolve); }
        match receiver.recv_timeout(left.min(READ_SLICE)) {
            Ok(Some(remote)) => return Ok(remote),
            Ok(None) => return Err(Error::Resolve),
            Err(mpsc::RecvTimeoutError::Timeout) => {},
            Err(_) => return Err(Error::Resolve),
        }
    }
}

#[derive(Default)]
pub(crate) struct TcpReader {
    length: [u8; 2],
    length_read: usize,
    frame: Vec<u8>,
    target: Option<usize>,
}

impl TcpReader {
    fn feed(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.target.is_none() {
            let take = (2 - self.length_read).min(bytes.len());
            self.length[self.length_read..self.length_read + take]
                .copy_from_slice(&bytes[..take]);
            self.length_read += take;
            if self.length_read < 2 { return Ok(None); }
            let size = u16::from_be_bytes(self.length) as usize;
            if !(2..=MAX_RECORD).contains(&size) { return Err(Error::Socket); }
            self.target = Some(size);
            self.frame.extend_from_slice(&self.length);
            return self.feed(&bytes[take..]);
        }
        let remaining = self.target.unwrap() - self.frame.len();
        if bytes.len() > remaining { return Err(Error::Socket); }
        self.frame.extend_from_slice(bytes);
        if self.frame.len() != self.target.unwrap() { return Ok(None); }
        let record = std::mem::take(&mut self.frame);
        self.length_read = 0;
        self.target = None;
        Ok(Some(record))
    }
    fn next_len(&self) -> usize {
        self.target.map(|target| target - self.frame.len())
            .unwrap_or(2 - self.length_read)
    }
}

pub(crate) enum Connection {
    Udp(UdpSocket),
    Tcp { stream: TcpStream, reader: TcpReader, prefix_sent: bool, failed: bool },
}

impl Connection {
    pub fn open(remote: SocketAddr, wire: Wire) -> Result<(Self, SocketAddr), Error> {
        match wire {
            Wire::Udp4500 => {
                let bind = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let socket = UdpSocket::bind(bind).map_err(|_| Error::Socket)?;
                socket.connect(remote).map_err(|_| Error::Socket)?;
                let local = socket.local_addr().map_err(|_| Error::Socket)?;
                Ok((Self::Udp(socket), local))
            }
            Wire::Tcp4443 => {
                let stream = TcpStream::connect_timeout(&remote, TCP_CONNECT_DEADLINE)
                    .map_err(|_| Error::Socket)?;
                let local = stream.local_addr().map_err(|_| Error::Socket)?;
                Ok((Self::Tcp {
                    stream, reader: TcpReader::default(), prefix_sent: false, failed: false
                }, local))
            }
        }
    }

    pub fn send_ike(&mut self, ike: &[u8], cancel: &Cancellation) -> Result<(), Error> {
        match self {
            Self::Udp(socket) => {
                let frame = init::udp_frame(ike);
                if socket.send(&frame).map_err(|_| Error::Socket)? != frame.len() {
                    return Err(Error::Socket);
                }
                Ok(())
            }
            Self::Tcp { stream, prefix_sent, failed, .. } => {
                if *failed { return Err(Error::Socket); }
                let frame = init::tcp_frame(ike).map_err(|_| Error::Socket)?;
                let result = (|| {
                    if !*prefix_sent {
                        write_bounded(stream, b"IKETCP", cancel)?;
                        *prefix_sent = true;
                    }
                    write_bounded(stream, &frame, cancel)
                })();
                if result.is_err() { *failed = true; }
                result
            }
        }
    }

    pub fn send_esp(&mut self, outbound: engine::Outbound,
                    cancel: &Cancellation) -> Result<(), Error> {
        match (self, outbound) {
            (Self::Udp(socket), engine::Outbound::UdpPayload(wire)) => {
                if socket.send(&wire).map_err(|_| Error::Socket)? != wire.len() {
                    return Err(Error::Socket);
                }
                Ok(())
            }
            (Self::Tcp { stream, prefix_sent, failed, .. },
             engine::Outbound::TcpFrame(frame)) => {
                if !*prefix_sent || *failed { return Err(Error::Socket); }
                let wire = engine::tcp_esp::encode_frame(&frame, MAX_RECORD)
                    .map_err(|_| Error::Socket)?;
                let result = write_bounded(stream, &wire, cancel);
                if result.is_err() { *failed = true; }
                result
            }
            _ => Err(Error::Socket),
        }
    }

    pub fn send_nat_keepalive(&mut self, cancel: &Cancellation) -> Result<(), Error> {
        match self {
            Self::Udp(socket) => {
                if socket.send(&[0xff]).map_err(|_| Error::Socket)? != 1 {
                    return Err(Error::Socket);
                }
                Ok(())
            }
            Self::Tcp { stream, prefix_sent, failed, .. } => {
                if !*prefix_sent || *failed { return Err(Error::Socket); }
                let result = write_bounded(stream, &TCP_KEEPALIVE_RECORD, cancel);
                if result.is_err() { *failed = true; }
                result
            }
        }
    }

    /// Returns a complete TCP record (including its two-byte length) or one
    /// whole UDP datagram. A partial TCP record survives a normal poll timeout.
    pub fn read(&mut self, deadline: Instant, cancel: &Cancellation)
        -> Result<Option<Vec<u8>>, Error> {
        match self {
            Self::Udp(socket) => {
                let mut buf = [0u8; MAX_RECORD];
                loop {
                    cancel.check()?;
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() { return Ok(None); }
                    socket.set_read_timeout(Some(left.min(READ_SLICE)))
                        .map_err(|_| Error::Socket)?;
                    match socket.recv(&mut buf) {
                        Ok(len) => return Ok(Some(buf[..len].to_vec())),
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut |
                            std::io::ErrorKind::WouldBlock) => {},
                        Err(_) => return Err(Error::Socket),
                    }
                }
            }
            Self::Tcp { stream, reader, failed, .. } => loop {
                if *failed { return Err(Error::Socket); }
                cancel.check()?;
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() { return Ok(None); }
                stream.set_read_timeout(Some(left.min(READ_SLICE)))
                    .map_err(|_| Error::Socket)?;
                let mut buf = [0u8; MAX_RECORD];
                let size = reader.next_len();
                match stream.read(&mut buf[..size]) {
                    Ok(0) => { *failed = true; return Err(Error::Socket); }
                    Ok(n) => {
                        match reader.feed(&buf[..n]) {
                            Ok(Some(record)) => return Ok(Some(record)),
                            Ok(None) => {},
                            Err(error) => { *failed = true; return Err(error); }
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut |
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {},
                    Err(_) => { *failed = true; return Err(Error::Socket); }
                }
            }
        }
    }

    pub fn raw_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        match self {
            Self::Udp(socket) => socket.as_raw_fd(),
            Self::Tcp { stream, .. } => stream.as_raw_fd(),
        }
    }

    pub fn wire(&self) -> Wire {
        match self { Self::Udp(_) => Wire::Udp4500, Self::Tcp { .. } => Wire::Tcp4443 }
    }
}

fn write_bounded(stream: &mut TcpStream, mut bytes: &[u8],
                 cancel: &Cancellation) -> Result<(), Error> {
    let deadline = Instant::now() + WRITE_DEADLINE;
    while !bytes.is_empty() {
        cancel.check()?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(Error::Socket); }
        stream.set_write_timeout(Some(left.min(READ_SLICE))).map_err(|_| Error::Socket)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Socket),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut |
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {},
            Err(_) => return Err(Error::Socket),
        }
    }
    Ok(())
}

pub fn tcp_ike(record: &[u8]) -> Option<&[u8]> {
    init::unframe_tcp(record).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ipv4_udp_and_ipv6_needs_explicit_clat_idi() {
        assert_eq!(ConnectOptions::default().wire, Wire::Udp4500);
        assert_eq!(ConnectOptions::default().validate(), Ok(()));
        assert_eq!(ConnectOptions {
            wire: Wire::Tcp4443, family: OuterFamily::Ipv6,
            idi_v4: None, tcp_fallback: false
        }.validate(), Err(Error::InvalidInput));
        assert_eq!(ConnectOptions {
            wire: Wire::Udp4500, family: OuterFamily::Ipv6,
            idi_v4: Some(Ipv4Addr::new(192, 0, 0, 2)), tcp_fallback: true
        }.validate(), Ok(()));
    }

    #[test]
    fn address_selection_rejects_mapped_v4_for_native_ipv6() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:4500".parse().unwrap();
        let nat64: SocketAddr = "[64:ff9b::c000:201]:4500".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:4500".parse().unwrap();
        assert_eq!(selected_addr([v4, mapped, nat64], OuterFamily::Ipv6), Some(nat64));
        assert_eq!(selected_addr([nat64, v4], OuterFamily::Ipv4), Some(v4));
    }

    #[test]
    fn partial_tcp_record_is_retained_without_unbounded_allocation() {
        let mut reader = TcpReader::default();
        assert!(reader.feed(&[0]).unwrap().is_none());
        assert_eq!(reader.next_len(), 1);
        assert!(reader.feed(&[6]).unwrap().is_none());
        assert_eq!(reader.next_len(), 4);
        assert!(reader.feed(&[0, 0]).unwrap().is_none());
        assert_eq!(reader.feed(&[0, 0]).unwrap(), Some(vec![0, 6, 0, 0, 0, 0]));
        assert_eq!(reader.next_len(), 2);
        assert_eq!(reader.feed(&[0, 0]), Err(Error::Socket));
        assert_eq!(reader.feed(&[0xff, 0xff]), Err(Error::Socket));
    }

    #[test]
    fn tcp_fallback_is_bounded_to_pre_auth_udp_sa_init_failure() {
        let original = ConnectOptions::default();
        for error in [Error::Timeout(0), Error::Socket] {
            let next = original.fallback_after(error).unwrap();
            assert_eq!(next.wire, Wire::Tcp4443);
            assert!(!next.tcp_fallback);
            assert_eq!(next.fallback_after(error), None);
        }
        for error in [Error::Timeout(1), Error::EapChallenge,
            Error::EapRejected, Error::SaInit, Error::Cancelled] {
            assert_eq!(original.fallback_after(error), None);
        }
        assert_eq!(ConnectOptions { tcp_fallback: false, ..original }
            .fallback_after(Error::Timeout(0)), None);
    }

    #[test]
    #[ignore = "loopback sockets require local-network permission in the sandbox"]
    fn tcp_nat_keepalive_is_the_marked_seven_byte_record() {
        assert_eq!(TCP_KEEPALIVE_RECORD, [0, 7, 0, 0, 0, 0, 0xff]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut conn = Connection::Tcp {
            stream, reader: TcpReader::default(), prefix_sent: true, failed: false,
        };
        assert_eq!(conn.send_nat_keepalive(&Cancellation::default()), Ok(()));
        let mut wire = [0u8; 16];
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(peer.read(&mut wire).unwrap(), 7);
        assert_eq!(&wire[..7], &TCP_KEEPALIVE_RECORD);
    }
}
