//! The NetworkExtension packet tunnel provider: the Objective-C class the
//! system instantiates and the glue that hands its three entry points to
//! [`provider::Engine`].
//!
//! `sys` is the only module here that contains `unsafe`; everything else is
//! safe Rust over the helpers it exports.

pub mod provider;
#[allow(unsafe_code)]
mod sys;
pub mod tunnel;
