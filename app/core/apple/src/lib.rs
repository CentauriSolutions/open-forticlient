//! Host-side Apple API access for the Rust host, behind traits.
//!
//! This crate is the seam between the Rust host logic and NetworkExtension.
//! Nothing here names an Apple type: the traits and [`manager::MockVpn`] build and
//! test on every platform, and the real backend is added behind
//! `cfg(target_os = "macos")`.
//!
//! Unsafe code is denied crate-wide; the backend's quarantined `objc` module is
//! the only place that will lift that.
#![deny(unsafe_code)]

pub mod completion;
pub mod error;
pub mod manager;
