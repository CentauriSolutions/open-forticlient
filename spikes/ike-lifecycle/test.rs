//! Standalone test root. Production imports `lifecycle.rs` beside its own
//! `auth` module, so both modules refer to the same owned `auth::Keys` type.
#![allow(dead_code)]
#[path = "../ike-auth/auth.rs"]
mod auth;
mod lifecycle;
mod liveness;
