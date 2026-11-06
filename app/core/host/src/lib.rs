//! Non-UI host logic for the OFTC agent, in Rust.
//!
//! The Swift `OFTCAgent` hands the verbs listed in [`commands::VERBS`] to
//! `oftc-hostlib`, which calls [`commands::run`]. Everything here is plain Rust
//! behind small seams ([`keychain::Keychain`], [`commands::SecretPrompt`]) so it
//! builds and tests without the Keychain or a terminal; `os` holds the only
//! `unsafe` code, and `keychain::SecKeychain` the only Apple framework call.
//!
//! Formats written here are read by the Swift UI and by old supervisors, so each
//! is pinned against files the shipped Swift code wrote (`tests/fixtures/swift`).
#![deny(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod acquire;
pub mod agent;
pub mod bundle;
pub mod commands;
pub mod env;
pub mod intent;
pub mod keychain;
pub mod lease;
pub mod out;
pub mod profile;
pub mod reason;
pub mod registry;
pub mod serve;
pub mod snapshot;
pub mod start;
pub mod status;
pub mod supervisor;
pub mod trust;
mod vpn;

#[allow(unsafe_code)]
mod os;
pub use os::{OsSignals, TtyPrompt};
