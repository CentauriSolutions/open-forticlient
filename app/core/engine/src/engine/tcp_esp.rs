//! Isolated RFC 9329 framing sketch. This module opens no sockets and handles no keys.
use std::io::{self, Write};

pub const PREFIX: &[u8; 6] = b"IKETCP";
pub const DEFAULT_MAX_RECORD: usize = 8192;
const MAX_WIRE_RECORD: usize = u16::MAX as usize;
const IKE_HEADER_LEN: usize = 28;
const ESP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Ike(Vec<u8>), // IKE header and payloads, without the non-ESP marker
    Esp(Vec<u8>), // SPI, sequence number, and encrypted ESP body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    InvalidPrefix,
    InvalidLength,
    RecordTooLarge,
    ShortIke,
    IkeLengthMismatch,
    ShortEsp,
    UnknownShortPayload,
    Truncated,
    Closed,
    InvalidFallbackLimit,
}

fn validate_ike(ike: &[u8]) -> Result<(), FramingError> {
    if ike.len() < IKE_HEADER_LEN {
        return Err(FramingError::ShortIke);
    }
    let declared = u32::from_be_bytes(ike[24..28].try_into().unwrap()) as usize;
    if declared != ike.len() {
        return Err(FramingError::IkeLengthMismatch);
    }
    Ok(())
}

fn validate_esp(esp: &[u8]) -> Result<(), FramingError> {
    if esp.len() < ESP_HEADER_LEN || esp[..4] == [0; 4] {
        return Err(FramingError::ShortEsp);
    }
    Ok(())
}

/// A record length includes its own two bytes. The IKE marker is inside that length.
pub fn encode_frame(frame: &Frame, max_record: usize) -> Result<Vec<u8>, FramingError> {
    let (payload, marker_len) = match frame {
        Frame::Ike(ike) => {
            validate_ike(ike)?;
            (ike.as_slice(), 4)
        }
        Frame::Esp(esp) => {
            validate_esp(esp)?;
            (esp.as_slice(), 0)
        }
    };
    let len = payload
        .len()
        .checked_add(2 + marker_len)
        .ok_or(FramingError::RecordTooLarge)?;
    if len > MAX_WIRE_RECORD || len > max_record {
        return Err(FramingError::RecordTooLarge);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    if marker_len != 0 {
        out.extend_from_slice(&[0; 4]);
    }
    out.extend_from_slice(payload);
    Ok(out)
}

/// Own one originator TCP connection. A write failure poisons it; reconnect with a new writer.
pub struct OriginatorWriter<W: Write> {
    inner: W,
    max_record: usize,
    prefix_sent: bool,
    failed: bool,
}

impl<W: Write> OriginatorWriter<W> {
    pub fn new(inner: W, max_record: usize) -> Self {
        Self {
            inner,
            max_record,
            prefix_sent: false,
            failed: false,
        }
    }

    pub fn send(&mut self, frame: &Frame) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection is unusable",
            ));
        }
        let record = encode_frame(frame, self.max_record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        let result = (|| {
            if !self.prefix_sent {
                self.inner.write_all(PREFIX)?;
                self.prefix_sent = true;
            }
            self.inner.write_all(&record)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prefix,
    Length,
    Payload(usize),
}

/// Incremental parser for one TCP stream. A client reads responder bytes with
/// `expect_prefix = false`; a responder reads originator bytes with `true`.
pub struct StreamDecoder {
    phase: Phase,
    pending: Vec<u8>,
    max_record: usize,
    closed: bool,
}

impl StreamDecoder {
    pub fn new(expect_prefix: bool, max_record: usize) -> Result<Self, FramingError> {
        if !(34..=MAX_WIRE_RECORD).contains(&max_record) {
            return Err(FramingError::InvalidLength);
        }
        Ok(Self {
            phase: if expect_prefix {
                Phase::Prefix
            } else {
                Phase::Length
            },
            pending: Vec::new(),
            max_record,
            closed: false,
        })
    }

    /// Supply bounded read chunks. Records can be split or coalesced arbitrarily.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<Vec<Frame>, FramingError> {
        if self.closed {
            return Err(FramingError::Closed);
        }
        let mut frames = Vec::new();
        while !input.is_empty() {
            let target = match self.phase {
                Phase::Prefix => PREFIX.len(),
                Phase::Length => 2,
                Phase::Payload(n) => n,
            };
            let take = (target - self.pending.len()).min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.pending.len() != target {
                continue;
            }
            let result = match self.phase {
                Phase::Prefix => {
                    if self.pending.as_slice() != PREFIX {
                        Err(FramingError::InvalidPrefix)
                    } else {
                        self.pending.clear();
                        self.phase = Phase::Length;
                        Ok(None)
                    }
                }
                Phase::Length => {
                    let len = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
                    self.pending.clear();
                    if len < 2 {
                        Err(FramingError::InvalidLength)
                    } else if len > self.max_record {
                        Err(FramingError::RecordTooLarge)
                    } else if len == 2 {
                        Ok(None)
                    }
                    // RFC 9329: silently ignore empty records
                    else {
                        self.phase = Phase::Payload(len - 2);
                        Ok(None)
                    }
                }
                Phase::Payload(_) => {
                    let payload = std::mem::take(&mut self.pending);
                    self.phase = Phase::Length;
                    classify(payload)
                }
            };
            match result {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => (),
                Err(e) => {
                    self.closed = true;
                    self.pending.clear();
                    return Err(e);
                }
            }
        }
        Ok(frames)
    }

    /// EOF discards a partial record. A new connection needs a new decoder.
    pub fn finish(&mut self) -> Result<(), FramingError> {
        if self.closed {
            return Err(FramingError::Closed);
        }
        self.closed = true;
        if self.phase == Phase::Length && self.pending.is_empty() {
            Ok(())
        } else {
            self.pending.clear();
            Err(FramingError::Truncated)
        }
    }
}

fn classify(payload: Vec<u8>) -> Result<Option<Frame>, FramingError> {
    if payload == [0xff] {
        return Ok(None);
    } // incoming NAT keepalive: silently drop
    if payload.len() < 4 {
        return Err(FramingError::UnknownShortPayload);
    }
    if payload[..4] == [0; 4] {
        // IKE syntax belongs to the IKE layer, which may need to send
        // INVALID_SYNTAX without closing this TCP connection (RFC 9329 6.1).
        Ok(Some(Frame::Ike(payload[4..].to_vec())))
    } else {
        // The CHILD_SA layer handles unknown SPIs and ESP validity.
        Ok(Some(Frame::Esp(payload)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackAction {
    SendUdpInit { retransmission: bool },
    ConnectTcp,
    SendTcpInitWithNewSpiAndNatDetection,
    UseUdp,
    UseTcp,
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackPhase {
    Ready,
    Udp,
    TcpConnecting,
    TcpInit,
    UdpSelected,
    TcpSelected,
    Failed,
}

/// One bounded SA_INIT decision path. The caller supplies finite UDP/TCP timers.
/// No transport switch retains the UDP IKE SA.
pub struct Fallback {
    phase: FallbackPhase,
    udp_sent: u8,
    udp_limit: u8,
}

impl Fallback {
    pub fn new(udp_limit: u8) -> Result<Self, FramingError> {
        if udp_limit < 2 {
            return Err(FramingError::InvalidFallbackLimit);
        }
        Ok(Self {
            phase: FallbackPhase::Ready,
            udp_sent: 0,
            udp_limit,
        })
    }

    pub fn begin(&mut self) -> Option<FallbackAction> {
        if self.phase != FallbackPhase::Ready {
            return None;
        }
        self.phase = FallbackPhase::Udp;
        self.udp_sent = 1;
        Some(FallbackAction::SendUdpInit {
            retransmission: false,
        })
    }

    pub fn udp_timeout(&mut self) -> Option<FallbackAction> {
        if self.phase != FallbackPhase::Udp {
            return None;
        }
        if self.udp_sent < self.udp_limit {
            self.udp_sent += 1;
            Some(FallbackAction::SendUdpInit {
                retransmission: true,
            })
        } else {
            self.phase = FallbackPhase::TcpConnecting;
            Some(FallbackAction::ConnectTcp)
        }
    }

    pub fn udp_reply(&mut self) -> Option<FallbackAction> {
        if self.phase != FallbackPhase::Udp {
            return None;
        }
        self.phase = FallbackPhase::UdpSelected;
        Some(FallbackAction::UseUdp)
    }

    pub fn tcp_connected(&mut self) -> Option<FallbackAction> {
        if self.phase != FallbackPhase::TcpConnecting {
            return None;
        }
        self.phase = FallbackPhase::TcpInit;
        Some(FallbackAction::SendTcpInitWithNewSpiAndNatDetection)
    }

    pub fn tcp_reply(&mut self) -> Option<FallbackAction> {
        if self.phase != FallbackPhase::TcpInit {
            return None;
        }
        self.phase = FallbackPhase::TcpSelected;
        Some(FallbackAction::UseTcp)
    }

    pub fn tcp_failed_or_timed_out(&mut self) -> Option<FallbackAction> {
        if !matches!(
            self.phase,
            FallbackPhase::TcpConnecting | FallbackPhase::TcpInit
        ) {
            return None;
        }
        self.phase = FallbackPhase::Failed;
        Some(FallbackAction::Exhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ike() -> Vec<u8> {
        let mut ike = vec![0; 28];
        ike[..8].copy_from_slice(&[1; 8]);
        ike[17] = 0x20;
        ike[18] = 34;
        ike[24..28].copy_from_slice(&28u32.to_be_bytes());
        ike
    }
    fn esp() -> Vec<u8> {
        vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0xaa]
    }
    fn decoder(prefix: bool) -> StreamDecoder {
        StreamDecoder::new(prefix, DEFAULT_MAX_RECORD).unwrap()
    }

    #[test]
    fn exact_wire_format_and_one_prefix_per_originator_connection() {
        let i = Frame::Ike(ike());
        let e = Frame::Esp(esp());
        let mut writer = OriginatorWriter::new(Vec::new(), DEFAULT_MAX_RECORD);
        writer.send(&i).unwrap();
        writer.send(&e).unwrap();
        writer.send(&i).unwrap();
        let bytes = writer.into_inner();
        assert_eq!(&bytes[..6], PREFIX);
        assert_eq!(&bytes[6..12], &[0, 34, 0, 0, 0, 0]);
        assert_eq!(&bytes[40..42], &[0, 11]);
        assert_eq!(&bytes[42..51], esp()); // ESP begins with its nonzero SPI
        assert_eq!(&bytes[51..57], &[0, 34, 0, 0, 0, 0]);
        let mut next = OriginatorWriter::new(Vec::new(), DEFAULT_MAX_RECORD);
        next.send(&e).unwrap();
        assert_eq!(&next.into_inner()[..6], PREFIX);
    }

    #[test]
    fn fragmented_and_coalesced_reads_demultiplex_both_directions() {
        let i = Frame::Ike(ike());
        let e = Frame::Esp(esp());
        let mut wire = PREFIX.to_vec();
        wire.extend(encode_frame(&i, DEFAULT_MAX_RECORD).unwrap());
        wire.extend([0, 2]); // empty message ignored
        wire.extend([0, 3, 0xff]); // keepalive ignored
        wire.extend(encode_frame(&e, DEFAULT_MAX_RECORD).unwrap());
        let mut d = decoder(true);
        let mut got = Vec::new();
        for byte in &wire {
            got.extend(d.feed(&[*byte]).unwrap());
        }
        assert_eq!(got, vec![i.clone(), e.clone()]);
        assert_eq!(d.finish(), Ok(()));
        let mut responder = decoder(false); // responder sends no prefix
        let mut reply = encode_frame(&e, DEFAULT_MAX_RECORD).unwrap();
        reply.extend(encode_frame(&i, DEFAULT_MAX_RECORD).unwrap());
        assert_eq!(responder.feed(&reply), Ok(vec![e, i]));
    }

    #[test]
    fn malformed_framing_closes_but_inner_syntax_passes_upward() {
        let mut d = decoder(true);
        assert_eq!(d.feed(b"IKEXXX"), Err(FramingError::InvalidPrefix));
        assert_eq!(d.feed(b"IKETCP"), Err(FramingError::Closed));
        for len in [0u16, 1] {
            let mut d = decoder(false);
            assert_eq!(d.feed(&len.to_be_bytes()), Err(FramingError::InvalidLength));
        }
        let mut d = StreamDecoder::new(false, 34).unwrap();
        assert_eq!(
            d.feed(&35u16.to_be_bytes()),
            Err(FramingError::RecordTooLarge)
        );
        let mut d = decoder(false);
        assert_eq!(
            d.feed(&[0, 3, 0x7e]),
            Err(FramingError::UnknownShortPayload)
        );
        let mut d = decoder(false);
        assert_eq!(d.feed(&[0, 6, 0, 0, 0, 0]), Ok(vec![Frame::Ike(vec![])]));
        let mut d = decoder(false);
        assert_eq!(
            d.feed(&[0, 6, 1, 2, 3, 4]),
            Ok(vec![Frame::Esp(vec![1, 2, 3, 4])])
        );
        let mut bad_ike = ike();
        bad_ike[27] = 29;
        let mut wire = vec![0, 34, 0, 0, 0, 0];
        wire.extend(&bad_ike);
        let mut d = decoder(false);
        assert_eq!(d.feed(&wire), Ok(vec![Frame::Ike(bad_ike)]));
    }

    #[test]
    fn eof_disposes_of_partial_data() {
        let mut clean = decoder(false);
        assert_eq!(clean.finish(), Ok(()));
        let mut d = decoder(true);
        d.feed(b"IKE").unwrap();
        assert_eq!(d.finish(), Err(FramingError::Truncated));
        let mut d = decoder(false);
        d.feed(&[0, 11, 1, 2]).unwrap();
        assert_eq!(d.finish(), Err(FramingError::Truncated));
        assert_eq!(d.feed(&[0, 2]), Err(FramingError::Closed));
        let mut d = decoder(false);
        d.feed(&[0]).unwrap();
        assert_eq!(d.finish(), Err(FramingError::Truncated));
    }

    #[test]
    fn encoder_checks_lengths() {
        assert_eq!(
            encode_frame(&Frame::Ike(vec![0; 27]), DEFAULT_MAX_RECORD),
            Err(FramingError::ShortIke)
        );
        assert_eq!(
            encode_frame(&Frame::Esp(vec![1; 65_534]), MAX_WIRE_RECORD),
            Err(FramingError::RecordTooLarge)
        );
        assert_eq!(
            encode_frame(&Frame::Esp(esp()), 10),
            Err(FramingError::RecordTooLarge)
        );
    }

    struct ShortWriter {
        bytes: Vec<u8>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let n = input.len().min(3);
            self.bytes.extend_from_slice(&input[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_all_handles_partial_writes() {
        let mut w = OriginatorWriter::new(ShortWriter { bytes: Vec::new() }, DEFAULT_MAX_RECORD);
        w.send(&Frame::Esp(esp())).unwrap();
        let bytes = w.into_inner().bytes;
        assert_eq!(&bytes[..6], PREFIX);
        assert_eq!(&bytes[6..8], &[0, 11]);
        assert_eq!(&bytes[8..], esp());
    }

    struct FailingWriter {
        writes: usize,
    }
    impl Write for FailingWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            } else {
                Ok(input.len().min(3))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failure_poisoned_until_new_connection() {
        let mut w = OriginatorWriter::new(FailingWriter { writes: 0 }, DEFAULT_MAX_RECORD);
        assert!(w.send(&Frame::Esp(esp())).is_err());
        assert_eq!(
            w.send(&Frame::Esp(esp())).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn bounded_udp_attempts_then_one_fresh_tcp_attempt() {
        let mut p = Fallback::new(2).unwrap();
        assert_eq!(
            p.begin(),
            Some(FallbackAction::SendUdpInit {
                retransmission: false
            })
        );
        assert_eq!(
            p.udp_timeout(),
            Some(FallbackAction::SendUdpInit {
                retransmission: true
            })
        );
        assert_eq!(p.udp_timeout(), Some(FallbackAction::ConnectTcp));
        assert_eq!(p.udp_timeout(), None);
        assert_eq!(
            p.tcp_connected(),
            Some(FallbackAction::SendTcpInitWithNewSpiAndNatDetection)
        );
        assert_eq!(p.tcp_failed_or_timed_out(), Some(FallbackAction::Exhausted));
        assert_eq!(p.tcp_connected(), None);
        let mut tcp_ok = Fallback::new(2).unwrap();
        tcp_ok.begin();
        tcp_ok.udp_timeout();
        tcp_ok.udp_timeout();
        tcp_ok.tcp_connected();
        assert_eq!(tcp_ok.tcp_reply(), Some(FallbackAction::UseTcp));
        assert_eq!(tcp_ok.tcp_failed_or_timed_out(), None);
        let mut q = Fallback::new(2).unwrap();
        q.begin();
        assert_eq!(q.udp_reply(), Some(FallbackAction::UseUdp));
        assert_eq!(q.udp_timeout(), None);
        assert!(Fallback::new(1).is_err());
    }
}
