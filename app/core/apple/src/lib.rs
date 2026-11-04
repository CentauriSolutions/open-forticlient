//! Host-side Apple API access for the Rust host, behind traits.
//!
//! This crate is the seam between the Rust host logic and NetworkExtension.
//! Nothing here names an Apple type: the traits and [`manager::MockVpn`] build and
//! test on every platform, and the real backend is added behind
//! `cfg(target_os = "macos")`.
//!
//! Unsafe code is denied crate-wide. It is allowed only in the macOS backend:
//! the shared `objc` module and `manager::ne`, which calls the generated
//! (all-`unsafe`) NetworkExtension bindings.
#![deny(unsafe_code)]

pub mod completion;
pub mod error;
pub mod manager;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod objc;
