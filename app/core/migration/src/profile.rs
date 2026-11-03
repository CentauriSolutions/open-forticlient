//! Load VPN parameters from the installed FortiClient config.
//!
//! Non-secret fields come from `conf/vpn.plist` (read via the system `plutil`,
//! so we stay dependency-free); the decrypted PSK and the resolved peer IP come
//! from the world-readable generated `ipsec/iked.conf`.
#![allow(dead_code)]

use std::error::Error;
use std::fs;
use std::process::Command;

pub const VPN_PLIST: &str = "/Library/Application Support/Fortinet/FortiClient/conf/vpn.plist";
pub const IKED_CONF: &str = "/Library/Application Support/Fortinet/FortiClient/ipsec/iked.conf";

#[derive(Debug, Default, Clone)]
pub struct Profile {
    pub name: String,
    pub server: String,
    pub user: String,
    pub psk: String,
    /// True when `psk` is the operator-supplied plaintext pre-shared key (the
    /// form fctctld expects to encrypt), false when it fell back to the
    /// already-encrypted `AuthInfo` (which will not authenticate).
    pub psk_is_plaintext: bool,
    /// FortiClient endpoint UID — the EAP identity the gateway correlates the
    /// SAML session by. Equals the Mac's hardware UUID with dashes removed.
    pub uid: String,
    pub peer_ip: String,
    pub saml_port: u32,
    pub ike_version: u32,
    pub transport_mode: u32,
    pub udp_port: u32,
    pub tcp_port: u32,
    pub p1_dh_group: u32,
    pub p2_dh_group: u32,
    pub p1_key_life: u32,
    pub p2_key_life: u32,
    pub p2_key_life_kbytes: u32,
    pub natt: u32,
    pub dpd: u32,
    pub pfs: u32,
    pub mode_cfg: u32,
    pub vip_enabled: u32,
    pub xauth: u32,
}

/// `plutil -extract <keypath> raw` — returns a single scalar value, or None.
fn plutil_extract(plist: &str, keypath: &str) -> Option<String> {
    let out = Command::new("plutil")
        .args(["-extract", keypath, "raw", "-o", "-", plist])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn p_u32(plist: &str, keypath: &str, default: u32) -> u32 {
    plutil_extract(plist, keypath)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// The profile names configured under `Profiles` in vpn.plist (direct children).
/// Parses `plutil -p` output: Profiles sits at 2-space indent, its profile-name
/// children at 4 (`    "NAME" => {`), deeper keys at 6+ (excluded).
pub fn list_profiles() -> Vec<String> {
    let out = match std::process::Command::new("plutil").args(["-p", VPN_PLIST]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut names = Vec::new();
    let mut in_profiles = false;
    for line in text.lines() {
        if !in_profiles {
            if line.starts_with("  \"Profiles\" =>") {
                in_profiles = true;
            }
            continue;
        }
        if line == "  }" {
            break; // end of the Profiles dict
        }
        if let Some(rest) = line.strip_prefix("    \"") {
            if let Some(end) = rest.find("\" => {") {
                names.push(rest[..end].to_string());
            }
        }
    }
    names
}

/// Resolve the profile to use: an explicit `--profile` wins; otherwise, if the
/// machine has exactly one configured profile, use it (so colleagues needn't
/// know its name). Falls back to "Office VPN" and warns when it is ambiguous.
pub fn resolve_profile(explicit: Option<&str>) -> String {
    if let Some(name) = explicit {
        return name.to_string();
    }
    let all = list_profiles();
    match all.len() {
        1 => {
            eprintln!("using the only configured profile: {:?} (pass --profile to override)", all[0]);
            all.into_iter().next().unwrap()
        }
        0 => "Office VPN".to_string(),
        _ => {
            eprintln!(
                "multiple profiles found ({}); defaulting to \"Office VPN\" — pass --profile \"NAME\" to pick one.",
                all.join(", ")
            );
            "Office VPN".to_string()
        }
    }
}

/// The operator-supplied plaintext pre-shared key. fctctld encrypts the
/// CONNECT-body PSK into iked.conf, so we must hand it the plaintext (the
/// FortiGate phase1 `psksecret`), not vpn.plist's already-encrypted `AuthInfo`.
/// Sources, in order: `$FORTIGATE_PSK`/`$OFTC_PSK`, a `.env` file searched from
/// the CWD upward (so `FORTIGATE_PSK=…` works), then `~/.config/oftc/psk`. The
/// secret stays out of the repo (`.env` is gitignored) and off the command line.
pub fn plaintext_psk_override() -> Option<String> {
    for key in ["FORTIGATE_PSK", "OFTC_PSK"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    let mut dir = std::env::current_dir().ok();
    for _ in 0..5 {
        let d = match dir {
            Some(d) => d,
            None => break,
        };
        if let Ok(s) = fs::read_to_string(d.join(".env")) {
            if let Some(v) =
                env_value(&s, "FORTIGATE_PSK").or_else(|| env_value(&s, "OFTC_PSK"))
            {
                return Some(v);
            }
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }
    if let Ok(home) = std::env::var("HOME") {
        if let Ok(s) = fs::read_to_string(format!("{home}/.config/oftc/psk")) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// The FortiClient endpoint UID = the Mac's hardware platform UUID with the
/// dashes removed (verified: `ioreg` IOPlatformUUID `4ADBB32B-1E71-…` matches the
/// UID `4ADBB32B1E71…` the gateway logged). iked uses this as the EAP identity:
/// fctctld writes it to `ipsec/auth` from CONNECT `+0x80`, so the official
/// client's auth file is UID(32)+token(32), where ours (with the email) was
/// shorter and FNBAM could not correlate it to the SAML session (the -301).
pub fn fct_uid() -> Option<String> {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains("IOPlatformUUID") {
            if let Some(v) = line.split('"').nth(3) {
                let id: String = v.chars().filter(|c| *c != '-').collect();
                if !id.is_empty() {
                    return Some(id.to_uppercase());
                }
            }
        }
    }
    None
}

/// Pull `KEY=value` from `.env`-style contents (honoring an optional `export`
/// and surrounding quotes); returns the first non-empty match.
fn env_value(contents: &str, key: &str) -> Option<String> {
    for raw in contents.lines() {
        let line = raw.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim().trim_matches('"').trim_matches('\'').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

impl Profile {
    pub fn load(profile_name: &str) -> Result<Profile, Box<dyn Error>> {
        let base = format!("Profiles.{profile_name}");
        let mut p = Profile {
            name: profile_name.to_string(),
            server: plutil_extract(VPN_PLIST, &format!("{base}.Server")).unwrap_or_default(),
            user: plutil_extract(VPN_PLIST, &format!("{base}.User")).unwrap_or_default(),
            saml_port: p_u32(VPN_PLIST, &format!("{base}.IKESamlPort"), 9443),
            ike_version: p_u32(VPN_PLIST, &format!("{base}.IKEVersion"), 2),
            transport_mode: p_u32(VPN_PLIST, &format!("{base}.TransportMode"), 2),
            udp_port: p_u32(VPN_PLIST, &format!("{base}.UdpPort"), 4500),
            tcp_port: p_u32(VPN_PLIST, &format!("{base}.TcpPort"), 4443),
            p1_dh_group: p_u32(VPN_PLIST, &format!("{base}.Phase1DHGroup"), 20),
            p2_dh_group: p_u32(VPN_PLIST, &format!("{base}.Phase2DHGroup"), 20),
            p1_key_life: p_u32(VPN_PLIST, &format!("{base}.Phase1KeyLifeSec"), 86400),
            p2_key_life: p_u32(VPN_PLIST, &format!("{base}.Phase2KeyLifeSec"), 43200),
            p2_key_life_kbytes: p_u32(VPN_PLIST, &format!("{base}.Phase2KeyLifeKbytes"), 5120),
            natt: p_u32(VPN_PLIST, &format!("{base}.EnableNATT"), 1),
            dpd: p_u32(VPN_PLIST, &format!("{base}.EnableDPD"), 1),
            pfs: p_u32(VPN_PLIST, &format!("{base}.Phase2PFSEnabled"), 1),
            mode_cfg: p_u32(VPN_PLIST, &format!("{base}.EnableModeConfig"), 1),
            vip_enabled: p_u32(VPN_PLIST, &format!("{base}.EnableVIP"), 1),
            xauth: p_u32(VPN_PLIST, &format!("{base}.EnableXAuth"), 1),
            ..Default::default()
        };
        // PSK. fctctld does NOT pass the CONNECT-body PSK through — it ENCRYPTS
        // it with this host's `ipsec/private/local.key` and writes the result as
        // iked.conf's `psk "Enc <hex>"`, which iked then decrypts at runtime. So
        // the body must carry the *plaintext* pre-shared key (the FortiGate
        // phase1 `psksecret`). vpn.plist's `AuthInfo` is that same secret ALREADY
        // encrypted, so sending it double-encrypts and iked derives the wrong
        // key → gateway AUTH/EAP fails (the -309 we chased). The operator
        // supplies the plaintext out-of-band via `$OFTC_PSK` or
        // `~/.config/oftc/psk`, so the secret never lives in the repo.
        // Prefer an operator-supplied plaintext PSK; otherwise decrypt the
        // profile's own `AuthInfo` (the `Enc …` blob) — FortiClient's encryption
        // uses a key hardcoded in its binaries, so this works locally with no
        // root or prompt (see fctcrypt.rs / docs/fct-enc-crypto.md).
        //
        // Caveat: `AuthInfo` is "the saved credential", which is the PSK on some
        // profiles but the saved SAML username on others. If it decrypts to the
        // profile's own username, it is NOT the PSK — ignore it so we don't send
        // the gateway an email as the key (that profile must use an override).
        let username = p.user.clone();
        p.psk = plaintext_psk_override()
            .or_else(|| {
                plutil_extract(VPN_PLIST, &format!("{base}.AuthInfo"))
                    .and_then(|enc| crate::fctcrypt::decrypt_enc(&enc))
                    .filter(|dec| !dec.is_empty() && *dec != username)
            })
            .unwrap_or_default();
        p.psk_is_plaintext = !p.psk.is_empty();
        // EAP identity: the FortiClient UID (hardware UUID, dashes stripped).
        p.uid = fct_uid().unwrap_or_default();
        // Resolved peer IP from the generated iked.conf when present.
        if let Ok(conf) = fs::read_to_string(IKED_CONF) {
            p.parse_iked_conf(&conf);
        }
        Ok(p)
    }

    /// iked.conf is OpenIKED syntax with backslash line continuations; a flat
    /// whitespace token scan is enough to pull `peer <ip>` and `psk "<secret>"`.
    fn parse_iked_conf(&mut self, conf: &str) {
        let toks: Vec<&str> = conf.split_whitespace().collect();
        for i in 0..toks.len() {
            if toks[i] == "peer" {
                if let Some(v) = toks.get(i + 1) {
                    self.peer_ip = v.to_string();
                }
            }
        }
        // Fallback PSK only if vpn.plist's AuthInfo was missing. The value is a
        // quoted string that contains a space (`psk "Enc 420d…"`), so read the
        // whole thing between the quotes rather than a whitespace token.
        if self.psk.is_empty() {
            if let Some(rest) = conf.split("psk \"").nth(1) {
                if let Some(end) = rest.find('"') {
                    self.psk = rest[..end].to_string();
                }
            }
        }
    }
}

/// The address fctctld will actually dial for `server`, if it will be IPv6.
///
/// fctctld's `_resolv_addr` calls getaddrinfo(name, NULL, AF_UNSPEC,
/// SOCK_STREAM) and takes the first IPv4-or-IPv6 answer; std's resolver makes
/// the same call, so the first result here is what it will use. On an
/// IPv6-only network with NAT64/DNS64 (e.g. T-Mobile tethering, where the Mac's
/// IPv4 is a 464XLAT shim) that is a synthesized v6 address, even for an IPv4
/// literal, and FortiClient 7.4.3 can't use it: `fct_tunnel_ctl` dies with "Bad
/// file descriptor" right after IKE_SA_INIT and iked reports -307. Every such
/// attempt would burn a single-use SSO token, so callers check this first.
pub fn ipv6_gateway(server: &str) -> Option<std::net::Ipv6Addr> {
    use std::net::{IpAddr, ToSocketAddrs};
    match (server, 0).to_socket_addrs().ok()?.next()?.ip() {
        IpAddr::V6(a) => Some(a),
        IpAddr::V4(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iked_conf_tokens() {
        let mut p = Profile::default();
        p.parse_iked_conf(
            "ikev2 \"vpn\" active esp \\\nlocal 192.168.1.20 peer 203.0.113.10 \\\npsk \"deadbeef\" \\\niface en0\n",
        );
        assert_eq!(p.peer_ip, "203.0.113.10");
        assert_eq!(p.psk, "deadbeef");
    }
}
