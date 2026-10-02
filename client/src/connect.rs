//! The CONNECT (command 1) body: the ~0x72ac connection-config struct that
//! FortiTray serializes verbatim and `fctctld` parses to generate `iked.conf`.
//!
//! Offsets were recovered statically by cross-referencing FortiTray's
//! `ipsec_print_conn_config` (reader/writer) with `fctctld`'s
//! `iked_conf_gen_config_file` (reader) — see ../../docs/control-socket.md,
//! section "CONNECT (cmd 1) body". Both halves agree on every offset below.
#![allow(dead_code)]

use crate::profile::Profile;

/// Total size of the serialized config struct (CONNECT body length).
pub const CONNECT_LEN: usize = 0x72ac;

/// Field offsets within the CONNECT body (relative to body start).
pub mod off {
    pub const SERVER: usize = 0x0000; // char[0x80], peer FQDN
    pub const USER: usize = 0x0080; // char[~0xC4]
    pub const PASSWORD: usize = 0x00c1; // cstr — EAP password / SAML token
    pub const AUTH_METHOD: usize = 0x0144; // i32: 0 = PSK+EAP/SAML, 1 = cert
    pub const CERT_STORAGE: usize = 0x0148; // i32
    pub const PSK: usize = 0x014c; // cstr
    pub const ADV_SETTINGS_ENABLED: usize = 0x474c; // i32 (= 1)
    pub const IKE_VERSION: usize = 0x4750; // i32
    pub const IKE_EAP_METHOD: usize = 0x4754; // i32
    pub const SAML_EXTERNAL_BROWSER: usize = 0x4758; // i32
    pub const SAML_FIDO: usize = 0x475c; // i32
    pub const SSO_ENABLED: usize = 0x4760; // i32
    pub const SAML_PORT: usize = 0x4764; // i32
    pub const IKE_EXG_MODE: usize = 0x4768; // char[0x10]
    pub const IKE_DH_GROUP: usize = 0x4778; // i32
    pub const IKE_DH_GROUPS: usize = 0x477c; // char[0x200]
    pub const P1_PROPS: usize = 0x497c; // char[0x200]
    pub const P1_KEY_LIFE: usize = 0x4b7c; // i32
    pub const DPD_ENABLED: usize = 0x4b80; // i32
    pub const NATT_ENABLED: usize = 0x4b84; // i32
    pub const SASE_MODE: usize = 0x4b88; // i32
    pub const TRANSPORT_MODE: usize = 0x4b8c; // i32
    pub const UDP_PORT: usize = 0x4b90; // i32
    pub const TCP_PORT: usize = 0x4b94; // i32
    pub const FALLBACK_TCP: usize = 0x4b98; // i32 — try TCP 4443 when UDP fails
    pub const XAUTH_ENABLED: usize = 0x4b9c; // i32
    pub const VIP_ENABLED: usize = 0x4ba0; // i32
    pub const MODE_CFG: usize = 0x4ba8; // i32 (mode-config / VIP type)
    pub const FRAGMENTATION: usize = 0x4bb0; // i32
    pub const REMOTE_NET: usize = 0x4bb8; // char[0x100]
    pub const SPLIT_EXCLUDE: usize = 0x4cd8; // char[0x100]
    pub const VIP_ADDR: usize = 0x4dd8; // char[0x40]
    pub const VIP_MASK: usize = 0x4e18; // char[0x40]
    pub const VIP_DNS: usize = 0x4e58; // char[0x40]
    pub const SRCID: usize = 0x4e98; // cstr (local-ID)
    pub const P2_PROPS: usize = 0x4f9c; // char[0x200]
    pub const P2_DH_GROUP: usize = 0x519c; // i32
    pub const P2_KEY_LIFE_TYPE: usize = 0x51a0; // char[0x20]
    pub const P2_KEY_LIFE: usize = 0x51c0; // i32
    pub const P2_KEY_LIFE_KBYTES: usize = 0x51c4; // i32
    pub const P2_REPLAY_DETECTION: usize = 0x51c8; // i32
    pub const P2_PFS: usize = 0x51cc; // i32
}

/// A fixed-size CONNECT config buffer with offset-addressed fields.
pub struct ConnConfig {
    buf: Vec<u8>,
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnConfig {
    pub fn new() -> Self {
        ConnConfig { buf: vec![0u8; CONNECT_LEN] }
    }

    pub fn put_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub fn get_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.buf[off..off + 4].try_into().unwrap())
    }

    /// Write a NUL-terminated string into a fixed field, clamped to `max` bytes
    /// (including the terminator).
    pub fn put_str(&mut self, off: usize, max: usize, s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(max.saturating_sub(1));
        self.buf[off..off + n].copy_from_slice(&bytes[..n]);
        self.buf[off + n] = 0;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Build a CONNECT body for this profile. `include_psk` gates writing the
    /// (secret) pre-shared key into the buffer; leave it off when dumping the
    /// struct for inspection so no secret lands on disk.
    pub fn from_profile(p: &Profile, include_psk: bool, token: Option<&str>) -> ConnConfig {
        let mut c = ConnConfig::new();
        c.put_str(off::SERVER, 0x80, &p.server);
        // EAP identity at +0x80 (user occupies 0x80..0xc1). fctctld writes this
        // to ipsec/auth as the EAP username, and the gateway's FNBAM correlates
        // the SAML session by the FortiClient UID (the Mac's hardware UUID,
        // dashes stripped) — NOT the login email. Sending the email got -301
        // (FNBAM found no matching SAML session). Fall back to the email only if
        // the UID could not be read.
        let eap_identity = if p.uid.is_empty() { &p.user } else { &p.uid };
        c.put_str(off::USER, 0x41, eap_identity);
        // The SAML token is the EAP password at +0xc1. fctctld reads user(+0x80)
        // + password(+0xc1) and writes them to ipsec/auth, which iked reads at
        // startup for its EAP identity+password. It must be present in CONNECT
        // (not sent later over the socket) and requires xauth != 0 below, or
        // fctctld skips the auth-file write entirely.
        if let Some(t) = token {
            c.put_str(off::PASSWORD, 0x83, t);
        }
        c.put_u32(off::AUTH_METHOD, 0); // PSK-remote + EAP/SAML-local
        if include_psk {
            c.put_str(off::PSK, 0x100, &p.psk);
        }
        c.put_u32(off::ADV_SETTINGS_ENABLED, 1);
        c.put_u32(off::IKE_VERSION, p.ike_version);
        c.put_u32(off::IKE_EAP_METHOD, 0); // auto / gateway-chosen
        c.put_u32(off::SAML_EXTERNAL_BROWSER, 1);
        c.put_u32(off::SSO_ENABLED, 1);
        c.put_u32(off::SAML_PORT, p.saml_port);
        c.put_str(off::IKE_EXG_MODE, 0x10, "aggressive"); // IKEv2 ignores
        c.put_u32(off::IKE_DH_GROUP, p.p1_dh_group);
        c.put_str(off::IKE_DH_GROUPS, 0x200, &p.p1_dh_group.to_string());
        // Proposal strings are tokenized by `fctctld` on BOTH '|' and ',' into a
        // flat [enc, auth, enc, auth, …] list; each pair becomes one
        // ikesa/childsa line (group from the DH group when PFS is on). Dashes do
        // NOT delimit. These reproduce the stock iked.conf (2 ikesa: aes256/sha1
        // + aes256/sha256; 2 childsa: aes256/sha1).
        // TODO: derive from profile Phase1/2Proposals (its literal "DES" is not
        // what the official client emits — it uses aes256).
        c.put_str(off::P1_PROPS, 0x200, "aes256|sha1,aes256|sha256");
        c.put_u32(off::P1_KEY_LIFE, p.p1_key_life);
        c.put_u32(off::DPD_ENABLED, p.dpd);
        c.put_u32(off::NATT_ENABLED, p.natt);
        c.put_u32(off::SASE_MODE, 0);
        c.put_u32(off::TRANSPORT_MODE, p.transport_mode);
        c.put_u32(off::UDP_PORT, p.udp_port);
        c.put_u32(off::TCP_PORT, p.tcp_port);
        // Enable UDP->TCP(4443) fallback. `_tunnelctl_start` reads this at +0x4b98
        // ("fallback-TCP: %d") and configures the transport accordingly; without
        // it, iked only tries UDP 4500 and gives up (-306) on a UDP-blocked
        // network. transport_mode 2 = auto/fallback.
        c.put_u32(off::FALLBACK_TCP, if p.transport_mode >= 2 { 1 } else { 0 });
        // Keep xauth as the profile sets it (1 here). The daemon requires
        // xauth != 0 to run iked_gen_auth_data (which writes the EAP creds to
        // ipsec/auth); with the token present at +0xc1 the "user password must
        // be specified" validation also passes. (Forcing xauth=0 passed
        // validation but disabled the auth-file write → EAP had no identity.)
        c.put_u32(off::XAUTH_ENABLED, p.xauth);
        c.put_u32(off::VIP_ENABLED, p.vip_enabled);
        c.put_u32(off::MODE_CFG, p.mode_cfg);
        c.put_u32(off::FRAGMENTATION, 0);
        c.put_str(off::P2_PROPS, 0x200, "aes256|sha1,aes256|sha1");
        c.put_u32(off::P2_DH_GROUP, p.p2_dh_group);
        c.put_str(off::P2_KEY_LIFE_TYPE, 0x20, "seconds");
        c.put_u32(off::P2_KEY_LIFE, p.p2_key_life);
        c.put_u32(off::P2_KEY_LIFE_KBYTES, p.p2_key_life_kbytes);
        c.put_u32(off::P2_REPLAY_DETECTION, 0);
        c.put_u32(off::P2_PFS, p.pfs);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_right_size_and_le() {
        let mut c = ConnConfig::new();
        c.put_u32(off::SAML_PORT, 9443);
        c.put_str(off::SERVER, 0x80, "vpn.example.com");
        assert_eq!(c.as_bytes().len(), CONNECT_LEN);
        assert_eq!(c.get_u32(off::SAML_PORT), 9443);
        assert_eq!(&c.as_bytes()[0..3], b"vpn");
        assert_eq!(c.as_bytes()[0x80 - 1], 0); // no spill into USER
    }
}
