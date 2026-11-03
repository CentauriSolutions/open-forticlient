//! IKEv2 with EAP-MSCHAPv2, ESP and the outer UDP/TCP transport for one
//! FortiGate tunnel. The crate opens sockets and holds keys but never touches
//! the operating system's tunnel interface; callers move inner packets.

// Several protocol modules carry offline APIs the session does not call yet
// (rekey collision handling, TCP fallback, SA overlap). Issue 50 decides which
// to delete; until then they stay compiled and tested.
#![allow(dead_code)]

pub mod auth;
mod child_sa;
mod engine;
mod ephemeral;
mod ike_rekey;
pub mod init;
mod lifecycle;
mod liveness;
pub mod mschapv2;
mod rekey;
mod session;
pub mod transport;
pub mod tunnel;

pub use engine::AddressRange;
pub use session::*;
