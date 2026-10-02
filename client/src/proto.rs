//! The `vpn_control` control-socket wire protocol.
//!
//! Framing (see ../../docs/control-socket.md): a fixed 20-byte header of five
//! little-endian u32s — `length, _, command, _, flags` — followed by a body.
//! `length` counts the whole message including the header.
#![allow(dead_code)]

use std::io::{self, Read, Write};

pub const HEADER_LEN: usize = 20;

pub const MAIN_SOCKET: &str = "/var/run/fctvpnctrl.sock";
pub const WORKER_SOCKET: &str =
    "/Library/Application Support/Fortinet/FortiClient/ipsec/fctvpnctrl_woker.sock";

/// Control-socket command, carried in the header at offset +0x08.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,      // 1  — body = the CONNECT config struct (see connect.rs)
    Disconnect,   // 5  — body = 0x40-byte gateway id
    Status,       // 6  — daemon -> client events (status int at body +0x00)
    GetOtp,       // 9  — daemon -> client, worker socket
    SendOtp,      // 10 — client -> daemon, the SAML tokenid as EAP OTP
    RacoonError,  // 12
    CertVerify,   // 16
    Sign,         // 17
    Banner,       // 21
    SystemSleep,  // 22 — daemon suspends iked
    SystemWakeUp, // 23 — daemon resumes iked
    Other(u32),
}

impl Command {
    pub fn to_u32(self) -> u32 {
        match self {
            Command::Connect => 1,
            Command::Disconnect => 5,
            Command::Status => 6,
            Command::GetOtp => 9,
            Command::SendOtp => 10,
            Command::RacoonError => 12,
            Command::CertVerify => 16,
            Command::Sign => 17,
            Command::Banner => 21,
            Command::SystemSleep => 22,
            Command::SystemWakeUp => 23,
            Command::Other(v) => v,
        }
    }

    pub fn from_u32(v: u32) -> Command {
        match v {
            1 => Command::Connect,
            5 => Command::Disconnect,
            6 => Command::Status,
            9 => Command::GetOtp,
            10 => Command::SendOtp,
            12 => Command::RacoonError,
            16 => Command::CertVerify,
            17 => Command::Sign,
            21 => Command::Banner,
            22 => Command::SystemSleep,
            23 => Command::SystemWakeUp,
            other => Command::Other(other),
        }
    }
}

/// A single control-socket message.
#[derive(Debug, Clone)]
pub struct Message {
    pub command: Command,
    /// Header word at +0x04 (usually 0).
    pub field4: u32,
    /// Header word at +0x10 (status/flags on some messages; 0 otherwise).
    pub field16: u32,
    pub body: Vec<u8>,
}

impl Message {
    pub fn new(command: Command, body: Vec<u8>) -> Self {
        Message { command, field4: 0, field16: 0, body }
    }

    /// Serialize to bytes: 20-byte header + body.
    pub fn encode(&self) -> Vec<u8> {
        let total = (HEADER_LEN + self.body.len()) as u32;
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&total.to_le_bytes()); // +0x00 length
        out.extend_from_slice(&self.field4.to_le_bytes()); // +0x04
        out.extend_from_slice(&self.command.to_u32().to_le_bytes()); // +0x08 command
        out.extend_from_slice(&0u32.to_le_bytes()); // +0x0c
        out.extend_from_slice(&self.field16.to_le_bytes()); // +0x10 flags
        out.extend_from_slice(&self.body);
        out
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.encode())
    }

    /// For a STATUS message, the status/event code (first body word).
    pub fn status_code(&self) -> Option<u32> {
        if self.body.len() >= 4 {
            Some(u32::from_le_bytes(self.body[0..4].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Read one message: the 20-byte header, then `length - 20` body bytes.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Message> {
        let mut hdr = [0u8; HEADER_LEN];
        r.read_exact(&mut hdr)?;
        let total = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let field4 = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        let command = Command::from_u32(u32::from_le_bytes(hdr[8..12].try_into().unwrap()));
        let field16 = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
        if total < HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message length {total} < header {HEADER_LEN}"),
            ));
        }
        let mut body = vec![0u8; total - HEADER_LEN];
        r.read_exact(&mut body)?;
        Ok(Message { command, field4, field16, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        let m = Message::new(Command::SystemWakeUp, vec![]);
        let bytes = m.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 20);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 23);
        let back = Message::read_from(&mut &bytes[..]).unwrap();
        assert_eq!(back.command, Command::SystemWakeUp);
        assert!(back.body.is_empty());
    }

    #[test]
    fn command_mapping() {
        for v in [1u32, 5, 6, 9, 10, 12, 16, 17, 21, 22, 23, 99] {
            assert_eq!(Command::from_u32(v).to_u32(), v);
        }
    }
}
