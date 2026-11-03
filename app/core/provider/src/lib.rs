//! The packet tunnel provider's logic, free of Apple frameworks.
//!
//! This is the Rust port of `app/Provider` and its support files. It drives
//! [`oftc_engine`] directly and reaches the operating system only through
//! [`oftc_engine::tunnel::Tunnel`], so it builds and tests without
//! NetworkExtension. A backend (the NetworkExtension one lives elsewhere) supplies
//! the `Tunnel`, forwards start and stop, and moves provider messages.

pub mod envelope;
pub mod link;
pub mod provider;
pub mod settings;
pub mod traffic;
