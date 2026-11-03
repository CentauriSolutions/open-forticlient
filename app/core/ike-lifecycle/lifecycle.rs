//! Offline IKEv2 INFORMATIONAL lifecycle codec for one established IKE SA and
//! one ESP CHILD_SA. The surrounding tunnel owns timers, UDP/TCP framing, and
//! actual installation/removal of SAs.
use crate::auth::{self, Keys};

const SK: u8 = 46;
const DELETE: u8 = 42;
const INFORMATIONAL: u8 = 37;
const CREATE_CHILD_SA: u8 = 36;
const MAX_IKE_PACKET: usize = 4096;
const ICV_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildSpis {
    /// Our inbound ESP SPI; this goes into an initiator CHILD_SA DELETE request.
    pub inbound: [u8; 4],
    /// The peer's inbound ESP SPI; this appears in its CHILD_SA DELETE request.
    pub outbound: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exchange {
    Dpd,
    DeleteChild,
    DeleteIke,
    DeleteIkeRekey,
    Rekey,
    RekeyIke,
    DeleteOldChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    Dpd,
    DeleteChild,
    DeleteIke,
    DeleteOldChild([u8; 4]),
}

#[derive(Debug, Eq, PartialEq)]
pub enum PeerRequest {
    New { event: PeerEvent, response: Vec<u8> },
    Retransmit { response: Vec<u8> },
}

struct Pending {
    kind: Exchange,
    msg_id: u32,
    expected_child_reply_spi: Option<[u8; 4]>,
    packet: Vec<u8>,
}

/// Starts after final IKE_AUTH succeeds. The caller passes its next unused
/// local request ID and the responder's next unused request ID (normally zero).
pub struct Lifecycle {
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    keys: Keys,
    next_local_id: u32,
    next_peer_id: u32,
    child: Option<ChildSpis>,
    old_children: Vec<ChildSpis>,
    pending: Option<Pending>,
    last_peer_request: Option<Vec<u8>>,
    last_peer_response: Option<Vec<u8>>,
    closed: bool,
}

impl Lifecycle {
    pub fn new(
        spi_i: [u8; 8],
        spi_r: [u8; 8],
        keys: Keys,
        next_local_id: u32,
        next_peer_id: u32,
        child: Option<ChildSpis>,
    ) -> Result<Self, String> {
        if spi_i == [0; 8] || spi_r == [0; 8] {
            return Err("zero IKE SPI".into());
        }
        if child.is_some_and(|c| c.inbound == [0; 4] || c.outbound == [0; 4]) {
            return Err("zero CHILD_SA SPI".into());
        }
        Ok(Self {
            spi_i,
            spi_r,
            keys,
            next_local_id,
            next_peer_id,
            child,
            old_children: Vec::new(),
            pending: None,
            last_peer_request: None,
            last_peer_response: None,
            closed: false,
        })
    }

    /// The returned packet is raw IKE, without UDP/4500 or RFC 9329 framing.
    /// Retransmit `pending_packet()` verbatim; do not reseal the same ID.
    pub fn start(&mut self, kind: Exchange) -> Result<&[u8], String> {
        if self.closed {
            return Err("IKE SA already deleted".into());
        }
        if self.pending.is_some() {
            return Err("INFORMATIONAL request already pending".into());
        }
        let child = match kind {
            Exchange::DeleteChild => Some(self.child.ok_or("no active CHILD_SA")?),
            _ => None,
        };
        if self.next_local_id == u32::MAX {
            return Err("IKE message ID exhausted".into());
        }
        let (first, inner) = match kind {
            Exchange::Dpd => (0, Vec::new()),
            Exchange::DeleteChild => delete_payload(3, child.unwrap().inbound),
            Exchange::DeleteIke => delete_payload(1, [0; 4]),
            Exchange::Rekey | Exchange::RekeyIke | Exchange::DeleteIkeRekey =>
                return Err("use the specialized lifecycle start method".into()),
            Exchange::DeleteOldChild => return Err("use start_old_child_delete".into()),
        };
        let packet = seal(
            &self.spi_i,
            &self.spi_r,
            self.next_local_id,
            0x08,
            first,
            &inner,
            &self.keys.sk_ei,
            &self.keys.sk_ai,
        )?;
        self.pending = Some(Pending {
            kind,
            msg_id: self.next_local_id,
            expected_child_reply_spi: child.map(|c| c.outbound),
            packet,
        });
        Ok(&self.pending.as_ref().unwrap().packet)
    }

    /// One locally initiated CHILD_SA rekey shares the INFORMATIONAL message
    /// ID/window. The caller retains its ephemeral key until completion.
    pub fn start_rekey(&mut self, first: u8, inner: &[u8]) -> Result<&[u8], String> {
        if self.closed || self.child.is_none() || self.pending.is_some()
            || self.next_local_id == u32::MAX || first == 0 || inner.is_empty() {
            return Err("cannot start CHILD_SA rekey".into());
        }
        let packet = seal_for(CREATE_CHILD_SA, &self.spi_i, &self.spi_r,
            self.next_local_id, 0x08, first, inner, &self.keys.sk_ei, &self.keys.sk_ai)?;
        self.pending = Some(Pending { kind: Exchange::Rekey,
            msg_id: self.next_local_id, expected_child_reply_spi: None, packet });
        Ok(&self.pending.as_ref().unwrap().packet)
    }

    pub fn start_ike_rekey(&mut self, first: u8, inner: &[u8]) -> Result<&[u8], String> {
        if self.closed || self.pending.is_some() || self.next_local_id == u32::MAX
            || first == 0 || inner.is_empty() {
            return Err("cannot start IKE_SA rekey".into());
        }
        let packet = seal_for(CREATE_CHILD_SA, &self.spi_i, &self.spi_r,
            self.next_local_id, 0x08, first, inner, &self.keys.sk_ei, &self.keys.sk_ai)?;
        self.pending = Some(Pending { kind: Exchange::RekeyIke,
            msg_id: self.next_local_id, expected_child_reply_spi: None, packet });
        Ok(&self.pending.as_ref().unwrap().packet)
    }

    /// Verify SK, exchange type, response flag and the outstanding message ID
    /// before exposing plaintext to the strict CHILD_SA response parser.
    pub fn complete_rekey(&mut self, packet: &[u8]) -> Result<(u8, Vec<u8>), String> {
        let pending = self.pending.as_ref().ok_or("no rekey pending")?;
        if pending.kind != Exchange::Rekey { return Err("different request pending".into()); }
        let result = open_inner(packet, &self.spi_i, &self.spi_r,
            pending.msg_id, 0x20, CREATE_CHILD_SA, &self.keys.sk_er, &self.keys.sk_ar)?;
        self.next_local_id += 1;
        self.pending = None;
        Ok(result)
    }

    pub fn complete_ike_rekey(&mut self, packet: &[u8]) -> Result<(u8, Vec<u8>), String> {
        let pending = self.pending.as_ref().ok_or("no IKE rekey pending")?;
        if pending.kind != Exchange::RekeyIke { return Err("different request pending".into()); }
        let result = open_inner(packet, &self.spi_i, &self.spi_r,
            pending.msg_id, 0x20, CREATE_CHILD_SA, &self.keys.sk_er, &self.keys.sk_ar)?;
        self.next_local_id += 1;
        self.pending = None;
        Ok(result)
    }

    /// The final request on the old IKE SA. Retain the sealed packet for
    /// authenticated retransmission and acknowledgement before key switch.
    pub fn start_old_ike_delete_for_rekey(&mut self) -> Result<&[u8], String> {
        if self.closed || self.pending.is_some() || self.next_local_id == u32::MAX {
            return Err("cannot delete old IKE SA".into());
        }
        let (first, inner) = delete_payload(1, [0; 4]);
        let packet = seal(&self.spi_i, &self.spi_r, self.next_local_id, 0x08,
             first, &inner, &self.keys.sk_ei, &self.keys.sk_ai)?;
        self.pending = Some(Pending { kind: Exchange::DeleteIkeRekey,
            msg_id: self.next_local_id, expected_child_reply_spi: None, packet });
        Ok(&self.pending.as_ref().unwrap().packet)
    }

    pub fn abandon_old_ike_delete_for_rekey(&mut self) -> Result<(), String> {
        if !self.pending.as_ref().is_some_and(|p| p.kind == Exchange::DeleteIkeRekey) {
            return Err("no old IKE delete pending".into());
        }
        self.pending = None;
        Ok(())
    }

    /// CHILD SAs are inherited by the new IKE SA; its message windows reset.
    pub fn install_ike_rekey(&mut self, spi_i: [u8; 8], spi_r: [u8; 8],
                             keys: Keys) -> Result<(), String> {
        if self.closed || self.pending.is_some() || spi_i == [0; 8] || spi_r == [0; 8] {
            return Err("invalid IKE rekey installation".into());
        }
        self.spi_i = spi_i;
        self.spi_r = spi_r;
        self.keys = keys;
        self.next_local_id = 0;
        self.next_peer_id = 0;
        self.last_peer_request = None;
        self.last_peer_response = None;
        Ok(())
    }

    /// Authenticate a peer CREATE_CHILD_SA request without acknowledging it.
    /// Commit the peer ID and retransmission cache only after a valid response
    /// has been constructed and its replacement SA installed.
    pub fn open_peer_rekey(&self, packet: &[u8]) -> Result<(u8, Vec<u8>), String> {
        if self.closed || self.next_peer_id == u32::MAX { return Err("IKE SA closed".into()); }
        open_inner(packet, &self.spi_i, &self.spi_r, self.next_peer_id,
            0x00, CREATE_CHILD_SA, &self.keys.sk_er, &self.keys.sk_ar)
    }

    pub fn respond_peer_rekey(&mut self, request: &[u8], first: u8,
                              inner: &[u8]) -> Result<Vec<u8>, String> {
        // Authenticate again so the request whose response is cached is exact.
        self.open_peer_rekey(request)?;
        let response = seal_for(CREATE_CHILD_SA, &self.spi_i, &self.spi_r,
            self.next_peer_id, 0x28, first, inner, &self.keys.sk_ei, &self.keys.sk_ai)?;
        self.next_peer_id += 1;
        self.last_peer_request = Some(request.to_vec());
        self.last_peer_response = Some(response.clone());
        Ok(response)
    }

    pub fn cached_peer_response(&self, packet: &[u8]) -> Option<&[u8]> {
        if self.last_peer_request.as_deref() == Some(packet) {
            self.last_peer_response.as_deref()
        } else { None }
    }

    pub fn sk_d(&self) -> &[u8; 32] { &self.keys.sk_d }

    /// Switch the active pair only after authenticated CREATE_CHILD_SA and
    /// successful data-plane installation. Retain the old pair for DELETE.
    pub fn replace_child(&mut self, replacement: ChildSpis) -> Result<ChildSpis, String> {
        if self.closed || replacement.inbound == [0; 4] || replacement.outbound == [0; 4]
            || self.old_children.len() >= 2
            || self.old_children.iter().any(|c| c.inbound == replacement.inbound)
            || self.child.is_some_and(|c| c.inbound == replacement.inbound) {
            return Err("invalid CHILD_SA replacement".into());
        }
        let old = self.child.replace(replacement).ok_or("no active CHILD_SA")?;
        self.old_children.push(old);
        Ok(old)
    }

    pub fn start_old_child_delete(&mut self, inbound: [u8; 4]) -> Result<&[u8], String> {
        if self.closed || self.pending.is_some() || self.next_local_id == u32::MAX {
            return Err("cannot start old CHILD_SA DELETE".into());
        }
        let old = *self.old_children.iter().find(|c| c.inbound == inbound)
            .ok_or("unknown old CHILD_SA")?;
        let (first, inner) = delete_payload(3, old.inbound);
        let packet = seal(&self.spi_i, &self.spi_r, self.next_local_id,
            0x08, first, &inner, &self.keys.sk_ei, &self.keys.sk_ai)?;
        self.pending = Some(Pending { kind: Exchange::DeleteOldChild,
            msg_id: self.next_local_id, expected_child_reply_spi: Some(old.outbound), packet });
        Ok(&self.pending.as_ref().unwrap().packet)
    }

    pub fn pending_packet(&self) -> Option<&[u8]> {
        self.pending.as_ref().map(|p| p.packet.as_slice())
    }

    pub fn ike_rekey_pending(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| p.kind == Exchange::RekeyIke)
    }

    pub fn complete(&mut self, packet: &[u8]) -> Result<Exchange, String> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("no INFORMATIONAL request pending")?;
        let kind = pending.kind;
        let id = pending.msg_id;
        let pending_expected_child_reply_spi = pending.expected_child_reply_spi;
        let body = open(
            packet,
            &self.spi_i,
            &self.spi_r,
            id,
            0x20,
            &self.keys.sk_er,
            &self.keys.sk_ar,
        )?;
        match (kind, body) {
            (Exchange::Dpd | Exchange::DeleteIke | Exchange::DeleteIkeRekey,
             Body::Empty) => (),
            (Exchange::DeleteChild, Body::Empty) => (),
            (Exchange::DeleteChild, Body::DeleteChild(spi))
                if pending.expected_child_reply_spi == Some(spi) =>
            {
                ()
            }
            (Exchange::DeleteOldChild, Body::Empty) => (),
            (Exchange::DeleteOldChild, Body::DeleteChild(spi))
                if pending.expected_child_reply_spi == Some(spi) => (),
            (Exchange::Rekey | Exchange::RekeyIke, _) =>
                return Err("use CREATE_CHILD_SA completion".into()),
            _ => return Err("unexpected INFORMATIONAL response payload".into()),
        }
        self.next_local_id += 1;
        self.pending = None;
        if kind == Exchange::DeleteChild {
            self.child = None;
        }
        if kind == Exchange::DeleteOldChild {
            self.old_children.retain(|c| Some(c.outbound) !=
                pending_expected_child_reply_spi);
        }
        if kind == Exchange::DeleteIke {
            self.child = None;
            self.closed = true;
        }
        Ok(kind)
    }

    /// Parses a responder-initiated request. A byte-identical retransmission
    /// returns the cached response without applying the event a second time.
    pub fn handle_peer_request(&mut self, packet: &[u8]) -> Result<PeerRequest, String> {
        if self.last_peer_request.as_deref() == Some(packet) {
            return Ok(PeerRequest::Retransmit {
                response: self.last_peer_response.as_ref().unwrap().clone(),
            });
        }
        if self.closed {
            return Err("IKE SA already deleted".into());
        }
        if self.next_peer_id == u32::MAX {
            return Err("peer IKE message ID exhausted".into());
        }
        let body = open(
            packet,
            &self.spi_i,
            &self.spi_r,
            self.next_peer_id,
            0x00,
            &self.keys.sk_er,
            &self.keys.sk_ar,
        )?;
        let (event, first, inner) = match body {
            Body::Empty => (PeerEvent::Dpd, 0, Vec::new()),
            Body::DeleteIke => (PeerEvent::DeleteIke, 0, Vec::new()),
            Body::DeleteChild(spi) if self.child.is_some_and(|c| c.outbound == spi) => {
                // RFC 7296 §1.4.1: if our DELETE for this same pair is already
                // outstanding, each side replies empty to the crossed request.
                // Repeating our inbound SPI here could delete the wrong SA.
                let (first, inner) = if self.pending.as_ref().is_some_and(|p| {
                    p.kind == Exchange::DeleteChild && p.expected_child_reply_spi == Some(spi)
                }) {
                    (0, Vec::new())
                } else {
                    delete_payload(3, self.child.unwrap().inbound)
                };
                (PeerEvent::DeleteChild, first, inner)
            }
            Body::DeleteChild(spi) if self.old_children.iter().any(|c| c.outbound == spi) => {
                let old = *self.old_children.iter().find(|c| c.outbound == spi).unwrap();
                let crossed = self.pending.as_ref().is_some_and(|p| {
                    p.kind == Exchange::DeleteOldChild
                        && p.expected_child_reply_spi == Some(spi)
                });
                let (first, inner) = if crossed { (0, Vec::new()) }
                    else { delete_payload(3, old.inbound) };
                (PeerEvent::DeleteOldChild(old.inbound), first, inner)
            }
            _ => return Err("unknown or unexpected peer DELETE SPI".into()),
        };
        let response = seal(
            &self.spi_i,
            &self.spi_r,
            self.next_peer_id,
            0x28,
            first,
            &inner,
            &self.keys.sk_ei,
            &self.keys.sk_ai,
        )?;
        self.next_peer_id += 1;
        self.last_peer_request = Some(packet.to_vec());
        self.last_peer_response = Some(response.clone());
        if event == PeerEvent::DeleteChild {
            self.child = None;
        }
        if let PeerEvent::DeleteOldChild(inbound) = event {
            self.old_children.retain(|c| c.inbound != inbound);
        }
        if event == PeerEvent::DeleteIke {
            self.child = None;
            self.pending = None;
            self.closed = true;
        }
        Ok(PeerRequest::New { event, response })
    }

    pub fn child_active(&self) -> bool {
        self.child.is_some()
    }
    pub fn ike_active(&self) -> bool {
        !self.closed
    }
    pub fn next_local_id(&self) -> u32 {
        self.next_local_id
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Body {
    Empty,
    DeleteChild([u8; 4]),
    DeleteIke,
}

fn delete_payload(protocol: u8, spi: [u8; 4]) -> (u8, Vec<u8>) {
    let mut payload = Vec::with_capacity(if protocol == 1 { 8 } else { 12 });
    payload.extend_from_slice(&[0, 0]); // no next payload; reserved generic flags
    payload.extend_from_slice(&(if protocol == 1 { 8u16 } else { 12u16 }).to_be_bytes());
    payload.extend_from_slice(&[
        protocol,
        if protocol == 1 { 0 } else { 4 },
        0,
        if protocol == 1 { 0 } else { 1 },
    ]);
    if protocol == 3 {
        payload.extend_from_slice(&spi);
    }
    (DELETE, payload)
}

fn parse_body(first: u8, plaintext: &[u8]) -> Result<Body, String> {
    match first {
        0 if plaintext.is_empty() => Ok(Body::Empty),
        0 => Err("trailing plaintext in empty INFORMATIONAL".into()),
        DELETE => {
            if plaintext.len() != 8 && plaintext.len() != 12 {
                return Err("invalid DELETE length".into());
            }
            if plaintext[0] != 0
                || u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize != plaintext.len()
            {
                return Err("invalid DELETE payload header".into());
            }
            match &plaintext[4..] {
                [1, 0, 0, 0] => Ok(Body::DeleteIke),
                [3, 4, 0, 1, a, b, c, d] if [*a, *b, *c, *d] != [0; 4] => {
                    Ok(Body::DeleteChild([*a, *b, *c, *d]))
                }
                _ => Err("unsupported DELETE protocol or SPI count".into()),
            }
        }
        _ => Err("unsupported INFORMATIONAL payload".into()),
    }
}

fn cbc(encrypt: bool, key: &[u8; 32], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() || input.len() % 16 != 0 {
        return Err("invalid CBC length".into());
    }
    let out = if encrypt {
        oftc_crypto::aes256_cbc_encrypt(key, iv, input)
    } else {
        oftc_crypto::aes256_cbc_decrypt(key, iv, input)
    };
    out.map_err(|_| "AES-256-CBC failed".into())
}

fn random_iv() -> Result<[u8; 16], String> {
    oftc_crypto::random_array().map_err(|_| "secure random failed".into())
}

fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn seal(
    spi_i: &[u8; 8], spi_r: &[u8; 8], msg_id: u32, flags: u8,
    first: u8, inner: &[u8], enc: &[u8; 32], integ: &[u8; 32],
) -> Result<Vec<u8>, String> {
    seal_for(INFORMATIONAL, spi_i, spi_r, msg_id, flags, first, inner, enc, integ)
}

fn seal_for(
    exchange: u8,
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    msg_id: u32,
    flags: u8,
    first: u8,
    inner: &[u8],
    enc: &[u8; 32],
    integ: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut plaintext = inner.to_vec();
    let pad_len = (16 - ((plaintext.len() + 1) % 16)) % 16;
    plaintext.resize(plaintext.len() + pad_len, 0);
    plaintext.push(pad_len as u8);
    let iv = random_iv()?;
    let ciphertext = cbc(true, enc, &iv, &plaintext)?;
    plaintext.fill(0);
    let sk_len = 4 + 16 + ciphertext.len() + ICV_LEN;
    let total = 28 + sk_len;
    if total > MAX_IKE_PACKET {
        return Err("INFORMATIONAL packet too large".into());
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(spi_i);
    out.extend_from_slice(spi_r);
    out.extend_from_slice(&[SK, 0x20, exchange, flags]);
    out.extend_from_slice(&msg_id.to_be_bytes());
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&[first, 0]);
    out.extend_from_slice(&(sk_len as u16).to_be_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&auth::prf_sha256(integ, &out)?[..ICV_LEN]);
    Ok(out)
}

fn open(
    packet: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
    msg_id: u32,
    flags: u8,
    enc: &[u8; 32],
    integ: &[u8; 32],
) -> Result<Body, String> {
    let (first, plaintext) = open_inner(packet, spi_i, spi_r, msg_id, flags,
        INFORMATIONAL, enc, integ)?;
    parse_body(first, &plaintext)
}

fn open_inner(
    packet: &[u8], spi_i: &[u8; 8], spi_r: &[u8; 8], msg_id: u32,
    flags: u8, exchange: u8, enc: &[u8; 32], integ: &[u8; 32],
) -> Result<(u8, Vec<u8>), String> {
    if packet.len() < 80 || packet.len() > MAX_IKE_PACKET {
        return Err("INFORMATIONAL size out of bounds".into());
    }
    if packet[..8] != *spi_i
        || packet[8..16] != *spi_r
        || packet[16..20] != [SK, 0x20, exchange, flags]
        || u32::from_be_bytes(packet[20..24].try_into().unwrap()) != msg_id
        || u32::from_be_bytes(packet[24..28].try_into().unwrap()) as usize != packet.len()
        || u16::from_be_bytes([packet[30], packet[31]]) as usize != packet.len() - 28
    {
        return Err("unexpected INFORMATIONAL header".into());
    }
    let icv_at = packet.len() - ICV_LEN;
    if (icv_at - 48) % 16 != 0 {
        return Err("invalid INFORMATIONAL ciphertext length".into());
    }
    let expected = auth::prf_sha256(integ, &packet[..icv_at])?;
    if !equal_ct(&expected[..ICV_LEN], &packet[icv_at..]) {
        return Err("INFORMATIONAL integrity check failed".into());
    }
    let iv: [u8; 16] = packet[32..48].try_into().unwrap();
    let mut plaintext = cbc(false, enc, &iv, &packet[48..icv_at])?;
    let result = (|| {
        let pad = *plaintext.last().ok_or("empty encrypted payload")? as usize;
        if pad + 1 > plaintext.len() {
            return Err("invalid IKE padding length".into());
        }
        let end = plaintext.len() - pad - 1;
        Ok((packet[28], plaintext[..end].to_vec()))
    })();
    plaintext.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_keys() -> Keys {
        Keys {
            sk_d: [1; 32],
            sk_ai: [2; 32],
            sk_ar: [3; 32],
            sk_ei: [4; 32],
            sk_er: [5; 32],
            sk_pi: [6; 32],
            sk_pr: [7; 32],
        }
    }
    fn spis() -> ChildSpis {
        ChildSpis {
            inbound: [1, 2, 3, 4],
            outbound: [5, 6, 7, 8],
        }
    }
    fn response(id: u32, body: Body, keys: &Keys) -> Vec<u8> {
        let (first, inner) = match body {
            Body::Empty => (0, Vec::new()),
            Body::DeleteChild(spi) => delete_payload(3, spi),
            Body::DeleteIke => delete_payload(1, [0; 4]),
        };
        seal(
            &[1; 8],
            &[2; 8],
            id,
            0x20,
            first,
            &inner,
            &keys.sk_er,
            &keys.sk_ar,
        )
        .unwrap()
    }
    fn peer_request(id: u32, body: Body, keys: &Keys) -> Vec<u8> {
        let (first, inner) = match body {
            Body::Empty => (0, Vec::new()),
            Body::DeleteChild(spi) => delete_payload(3, spi),
            Body::DeleteIke => delete_payload(1, [0; 4]),
        };
        seal(
            &[1; 8],
            &[2; 8],
            id,
            0x00,
            first,
            &inner,
            &keys.sk_er,
            &keys.sk_ar,
        )
        .unwrap()
    }
    fn lifecycle(keys: Keys) -> Lifecycle {
        Lifecycle::new([1; 8], [2; 8], keys, 5, 0, Some(spis())).unwrap()
    }

    #[test]
    fn dpd_retransmits_exact_request_and_advances_only_after_authenticated_empty_reply() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let first = lc.start(Exchange::Dpd).unwrap().to_vec();
        assert_eq!(first[18], INFORMATIONAL);
        assert_eq!(first[19], 0x08);
        assert_eq!(first[28], 0);
        assert_eq!(lc.pending_packet().unwrap(), first);
        assert!(lc.start(Exchange::Dpd).is_err());
        assert!(lc.complete(&response(6, Body::Empty, &keys)).is_err());
        assert_eq!(lc.pending_packet().unwrap(), first);
        let mut tampered = response(5, Body::Empty, &keys);
        tampered[50] ^= 0x80;
        assert!(lc.complete(&tampered).is_err());
        assert_eq!(lc.next_local_id(), 5);
        assert_eq!(
            lc.complete(&response(5, Body::Empty, &keys)).unwrap(),
            Exchange::Dpd
        );
        assert_eq!(lc.next_local_id(), 6);
        assert!(lc.pending_packet().is_none());
        assert!(lc.complete(&response(5, Body::Empty, &keys)).is_err());
    }

    #[test]
    fn late_dpd_reply_recovers_after_first_timeout_and_duplicate_is_ignored() {
        use crate::liveness::{Liveness, LivenessAction, LivenessConfig};

        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let mut policy = Liveness::new(LivenessConfig::default(), 0).unwrap();
        let first = match policy.tick(&mut lc, 20_000).unwrap() {
            LivenessAction::Send(packet) => packet,
            other => panic!("expected first DPD: {other:?}"),
        };
        for t in (25_000..=60_000).step_by(5_000) {
            assert_eq!(policy.tick(&mut lc, t).unwrap(), LivenessAction::Send(first.clone()));
        }
        let mut forged = response(5, Body::Empty, &keys);
        forged[52] ^= 1;
        assert!(policy.complete_dpd(&mut lc, &forged, 65_000).is_err());
        assert!(policy.probe_pending());
        assert_eq!(lc.next_local_id(), 5);

        let late = response(5, Body::Empty, &keys);
        policy.complete_dpd(&mut lc, &late, 65_000).unwrap();
        assert!(!policy.probe_pending());
        assert!(!policy.reconnect_required());
        assert_eq!(lc.next_local_id(), 6);
        assert!(lc.child_active());
        assert!(policy.complete_dpd(&mut lc, &late, 66_000).is_err());
        assert_eq!(policy.tick(&mut lc, 84_999).unwrap(), LivenessAction::None);
        assert!(matches!(policy.tick(&mut lc, 85_000).unwrap(), LivenessAction::Send(_)));
        assert_eq!(lc.next_local_id(), 6);
    }

    #[test]
    fn child_delete_uses_our_inbound_spi_and_requires_expected_peer_spi() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let request = lc.start(Exchange::DeleteChild).unwrap().to_vec();
        assert_eq!(
            open(
                &request,
                &[1; 8],
                &[2; 8],
                5,
                0x08,
                &keys.sk_ei,
                &keys.sk_ai
            )
            .unwrap(),
            Body::DeleteChild(spis().inbound)
        );
        assert!(lc
            .complete(&response(5, Body::DeleteChild([9; 4]), &keys))
            .is_err());
        assert!(lc.child_active());
        assert_eq!(
            lc.complete(&response(5, Body::DeleteChild(spis().outbound), &keys))
                .unwrap(),
            Exchange::DeleteChild
        );
        assert!(!lc.child_active());
        assert!(lc.start(Exchange::DeleteChild).is_err());
    }

    #[test]
    fn child_delete_accepts_empty_reply_after_authentication() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        lc.start(Exchange::DeleteChild).unwrap();
        assert_eq!(
            lc.complete(&response(5, Body::Empty, &keys)).unwrap(),
            Exchange::DeleteChild
        );
    }

    #[test]
    fn ike_delete_requires_empty_reply_and_closes() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let req = lc.start(Exchange::DeleteIke).unwrap().to_vec();
        assert_eq!(
            open(&req, &[1; 8], &[2; 8], 5, 0x08, &keys.sk_ei, &keys.sk_ai).unwrap(),
            Body::DeleteIke
        );
        assert!(lc.complete(&response(5, Body::DeleteIke, &keys)).is_err());
        lc.complete(&response(5, Body::Empty, &keys)).unwrap();
        assert!(!lc.ike_active());
        assert!(!lc.child_active());
        assert!(lc.start(Exchange::Dpd).is_err());
    }

    #[test]
    fn peer_dpd_response_is_authenticated_and_duplicate_does_not_advance() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let req = peer_request(0, Body::Empty, &keys);
        let reply = match lc.handle_peer_request(&req).unwrap() {
            PeerRequest::New {
                event: PeerEvent::Dpd,
                response,
            } => response,
            _ => panic!("expected new DPD"),
        };
        assert_eq!(
            open(&reply, &[1; 8], &[2; 8], 0, 0x28, &keys.sk_ei, &keys.sk_ai).unwrap(),
            Body::Empty
        );
        assert_eq!(
            lc.handle_peer_request(&req).unwrap(),
            PeerRequest::Retransmit { response: reply }
        );
        assert!(lc
            .handle_peer_request(&peer_request(2, Body::Empty, &keys))
            .is_err());
    }

    #[test]
    fn peer_delete_validates_spi_and_sends_counterpart() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        assert!(lc
            .handle_peer_request(&peer_request(0, Body::DeleteChild([9; 4]), &keys))
            .is_err());
        let req = peer_request(0, Body::DeleteChild(spis().outbound), &keys);
        let reply = match lc.handle_peer_request(&req).unwrap() {
            PeerRequest::New {
                event: PeerEvent::DeleteChild,
                response,
            } => response,
            _ => panic!("expected child delete"),
        };
        assert_eq!(
            open(&reply, &[1; 8], &[2; 8], 0, 0x28, &keys.sk_ei, &keys.sk_ai).unwrap(),
            Body::DeleteChild(spis().inbound)
        );
        assert!(!lc.child_active());
        assert!(matches!(
            lc.handle_peer_request(&req).unwrap(),
            PeerRequest::Retransmit { .. }
        ));
    }

    #[test]
    fn peer_ike_delete_returns_empty_reply_and_closes() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let req = peer_request(0, Body::DeleteIke, &keys);
        let reply = match lc.handle_peer_request(&req).unwrap() {
            PeerRequest::New {
                event: PeerEvent::DeleteIke,
                response,
            } => response,
            _ => panic!("expected IKE delete"),
        };
        assert_eq!(
            open(&reply, &[1; 8], &[2; 8], 0, 0x28, &keys.sk_ei, &keys.sk_ai).unwrap(),
            Body::Empty
        );
        assert!(!lc.ike_active());
    }

    #[test]
    fn crossed_child_deletes_preserve_pending_reply_validation() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        lc.start(Exchange::DeleteChild).unwrap();
        let peer = peer_request(0, Body::DeleteChild(spis().outbound), &keys);
        let peer_reply = match lc.handle_peer_request(&peer).unwrap() {
            PeerRequest::New {
                event: PeerEvent::DeleteChild,
                response,
            } => response,
            _ => panic!("expected crossed CHILD_SA delete"),
        };
        assert_eq!(
            open(
                &peer_reply,
                &[1; 8],
                &[2; 8],
                0,
                0x28,
                &keys.sk_ei,
                &keys.sk_ai
            )
            .unwrap(),
            Body::Empty
        );
        assert!(!lc.child_active());
        assert_eq!(
            lc.handle_peer_request(&peer).unwrap(),
            PeerRequest::Retransmit {
                response: peer_reply
            }
        );
        // The peer also acknowledges our outstanding delete with an empty
        // response; message ID and integrity checks still apply.
        assert_eq!(
            lc.complete(&response(5, Body::Empty, &keys)).unwrap(),
            Exchange::DeleteChild
        );
    }

    #[test]
    fn message_id_exhaustion_is_explicit() {
        let keys = synthetic_keys();
        let mut local =
            Lifecycle::new([1; 8], [2; 8], synthetic_keys(), u32::MAX, 0, Some(spis())).unwrap();
        assert!(local.start(Exchange::Dpd).is_err());
        let mut peer =
            Lifecycle::new([1; 8], [2; 8], synthetic_keys(), 5, u32::MAX, Some(spis())).unwrap();
        assert!(peer
            .handle_peer_request(&peer_request(u32::MAX, Body::Empty, &keys))
            .is_err());
    }

    #[test]
    fn rejects_wrong_flags_spis_lengths_and_unsupported_payloads() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        lc.start(Exchange::Dpd).unwrap();
        for offset in [0, 8, 16, 17, 18, 19, 20, 24, 30] {
            let mut bad = response(5, Body::Empty, &keys);
            bad[offset] ^= 1;
            assert!(lc.complete(&bad).is_err(), "offset {offset}");
        }
        assert!(lc
            .complete(&response(5, Body::DeleteChild(spis().outbound), &keys))
            .is_err());
        let mut bad = response(5, Body::Empty, &keys);
        bad.pop();
        assert!(lc.complete(&bad).is_err());
    }

    #[test]
    fn rejects_malformed_delete_shapes() {
        for malformed in [
            vec![0, 0, 0, 8, 3, 4, 0, 0],
            vec![0, 0, 0, 8, 1, 4, 0, 0],
            vec![0, 0, 0, 8, 1, 0, 0, 1],
            vec![0, 0, 0, 12, 3, 4, 0, 1, 0, 0, 0, 0],
            vec![42, 0, 0, 8, 1, 0, 0, 0],
        ] {
            assert!(parse_body(DELETE, &malformed).is_err());
        }
        assert!(parse_body(0, &[1]).is_err());
        assert!(parse_body(41, &[]).is_err());
    }

    #[test]
    fn recognized_payload_critical_and_reserved_bits_are_ignored() {
        // RFC 7296 requires recipients to ignore these bits for a payload
        // type they already understand.
        let mut delete = delete_payload(1, [0; 4]).1;
        delete[1] = 0xff;
        assert_eq!(parse_body(DELETE, &delete).unwrap(), Body::DeleteIke);

        let keys = synthetic_keys();
        let mut packet = response(5, Body::Empty, &keys);
        packet[29] = 0xff;
        let icv_at = packet.len() - ICV_LEN;
        let icv = auth::prf_sha256(&keys.sk_ar, &packet[..icv_at]).unwrap();
        packet[icv_at..].copy_from_slice(&icv[..ICV_LEN]);
        assert_eq!(
            open(&packet, &[1; 8], &[2; 8], 5, 0x20, &keys.sk_er, &keys.sk_ar).unwrap(),
            Body::Empty
        );
    }

    #[test]
    fn child_rekey_uses_one_authenticated_message_window_and_old_delete() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let request = lc.start_rekey(41, &[33, 0, 0, 4]).unwrap().to_vec();
        assert_eq!(request[18], CREATE_CHILD_SA);
        assert_eq!(lc.pending_packet(), Some(request.as_slice()));
        assert!(lc.start(Exchange::Dpd).is_err());
        let reply = seal_for(CREATE_CHILD_SA, &[1; 8], &[2; 8], 5, 0x20,
            33, &[40, 0, 0, 4], &keys.sk_er, &keys.sk_ar).unwrap();
        let mut forged = reply.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(lc.complete_rekey(&forged).is_err());
        assert_eq!(lc.pending_packet(), Some(request.as_slice()));
        assert_eq!(lc.complete_rekey(&reply).unwrap(), (33, vec![40, 0, 0, 4]));
        assert_eq!(lc.next_local_id(), 6);
        let old = lc.replace_child(ChildSpis { inbound: [9; 4], outbound: [8; 4] }).unwrap();
        assert_eq!(old, spis());
        let deletion = lc.start_old_child_delete(old.inbound).unwrap().to_vec();
        assert_eq!(deletion[18], INFORMATIONAL);
        assert_eq!(lc.complete(&response(6, Body::Empty, &keys)).unwrap(),
                   Exchange::DeleteOldChild);
        assert!(lc.child_active());
        assert!(lc.start_old_child_delete(old.inbound).is_err());
    }

    #[test]
    fn ike_rekey_authenticates_reply_in_old_window_then_inherits_child_and_resets_ids() {
        let mut lc = lifecycle(synthetic_keys());
        let old_keys = synthetic_keys();
        let request = lc.start_ike_rekey(33, &[40, 0, 0, 4]).unwrap().to_vec();
        assert_eq!(request[18], CREATE_CHILD_SA);
        assert!(lc.start_old_ike_delete_for_rekey().is_err());
        let reply = seal_for(CREATE_CHILD_SA, &[1; 8], &[2; 8], 5, 0x20,
            33, &[40, 0, 0, 4], &old_keys.sk_er, &old_keys.sk_ar).unwrap();
        let mut forged = reply.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(lc.complete_ike_rekey(&forged).is_err());
        assert_eq!(lc.pending_packet(), Some(request.as_slice()));
        assert_eq!(lc.complete_ike_rekey(&reply).unwrap(), (33, vec![40, 0, 0, 4]));
        let old_delete = lc.start_old_ike_delete_for_rekey().unwrap().to_vec();
        assert_eq!(old_delete[18], INFORMATIONAL);
        assert_eq!(u32::from_be_bytes(old_delete[20..24].try_into().unwrap()), 6);
        let ack = response(6, Body::Empty, &old_keys);
        assert_eq!(lc.complete(&ack).unwrap(), Exchange::DeleteIkeRekey);
        assert!(lc.child_active());
        lc.install_ike_rekey([9; 8], [8; 8], synthetic_keys()).unwrap();
        assert!(lc.child_active());
        assert_eq!(lc.next_local_id(), 0);
        let new_dpd = lc.start(Exchange::Dpd).unwrap().to_vec();
        assert_eq!(&new_dpd[..8], &[9; 8]);
        assert_eq!(&new_dpd[8..16], &[8; 8]);
        assert_eq!(u32::from_be_bytes(new_dpd[20..24].try_into().unwrap()), 0);
        assert!(lc.complete(&reply).is_err());
    }

    #[test]
    fn peer_rekey_caches_response_only_after_explicit_commit() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let peer = seal_for(CREATE_CHILD_SA, &[1; 8], &[2; 8], 0, 0x00,
            41, &[33, 0, 0, 4], &keys.sk_er, &keys.sk_ar).unwrap();
        assert_eq!(lc.open_peer_rekey(&peer).unwrap(), (41, vec![33, 0, 0, 4]));
        assert!(lc.cached_peer_response(&peer).is_none());
        let reply = lc.respond_peer_rekey(&peer, 33, &[40, 0, 0, 4]).unwrap();
        assert_eq!(reply[18], CREATE_CHILD_SA);
        assert_eq!(lc.cached_peer_response(&peer), Some(reply.as_slice()));
        assert!(lc.open_peer_rekey(&peer).is_err());
        assert_eq!(lc.next_local_id(), 5);
    }

    #[test]
    fn peer_delete_of_retired_child_preserves_new_active_child() {
        let keys = synthetic_keys();
        let mut lc = lifecycle(synthetic_keys());
        let old = lc.replace_child(ChildSpis { inbound: [9; 4], outbound: [8; 4] }).unwrap();
        let peer = peer_request(0, Body::DeleteChild(old.outbound), &keys);
        let response = lc.handle_peer_request(&peer).unwrap();
        assert!(matches!(response, PeerRequest::New {
            event: PeerEvent::DeleteOldChild(spi), ..
        } if spi == old.inbound));
        assert!(lc.child_active());
        assert!(lc.start_old_child_delete(old.inbound).is_err());
        assert!(matches!(lc.handle_peer_request(&peer).unwrap(),
                         PeerRequest::Retransmit { .. }));
        assert_eq!(lc.next_local_id(), 5);
    }
}
