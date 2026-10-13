//! Strict first-CHILD_SA handoff from an authenticated IKE_AUTH response.
//! The caller must verify IKE SK integrity and final responder AUTH first.

use crate::engine::{self, AddressRange, TrafficSelector};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSa,
    UnsupportedSuite,
    InvalidSelector,
    SelectorNotNarrowed,
    InvalidConfiguration,
    NoSplitRoute,
    InvalidNonce,
    Crypto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub assigned_ipv4: Ipv4Addr,
    pub netmask: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_domains: Vec<String>,
    pub split_routes: Vec<AddressRange>,
    pub route_source: RouteSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    ConfigurationSubnet,
    NarrowedRemoteSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub peer_inbound_spi: u32,
    pub local_inbound_spi: u32,
    pub local_selectors: Vec<TrafficSelector>,
    pub remote_selectors: Vec<TrafficSelector>,
    pub configuration: Configuration,
}

fn be16(bytes: &[u8]) -> u16 { u16::from_be_bytes([bytes[0], bytes[1]]) }

fn ipv4(bytes: &[u8]) -> Ipv4Addr { Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]) }

fn range_contains(outer: &AddressRange, inner: &AddressRange) -> bool {
    match (outer.first, outer.last, inner.first, inner.last) {
        (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(c), IpAddr::V4(d)) =>
            u32::from(a) <= u32::from(c) && u32::from(d) <= u32::from(b),
        _ => false,
    }
}

fn address_in(range: &AddressRange, address: Ipv4Addr) -> bool {
    range_contains(range, &AddressRange {
        first: IpAddr::V4(address), last: IpAddr::V4(address),
    })
}

/// `sa` is the SA payload *body*, excluding its four-byte generic payload header.
fn parse_sa(sa: &[u8]) -> Result<u32, Error> {
    if sa.len() < 12 || sa[0] != 0
        || be16(&sa[2..4]) as usize != sa.len()
        || sa[4] != 1 || sa[5] != 3 || sa[6] != 4 || !(2..=3).contains(&sa[7]) {
        return Err(Error::InvalidSa);
    }
    let spi = u32::from_be_bytes(sa[8..12].try_into().unwrap());
    if spi == 0 { return Err(Error::InvalidSa); }
    let mut offset = 12;
    let mut encr = false;
    let mut integ = false;
    let mut esn = false;
    for index in 0..sa[7] as usize {
        if sa.len() - offset < 8 { return Err(Error::InvalidSa); }
        let last = sa[offset];
        let transform_len = be16(&sa[offset + 2..offset + 4]) as usize;
        if last != if index + 1 == sa[7] as usize { 0 } else { 3 }
            || transform_len < 8 || transform_len > sa.len() - offset {
            return Err(Error::InvalidSa);
        }
        let typ = sa[offset + 4];
        let id = be16(&sa[offset + 6..offset + 8]);
        let attrs = &sa[offset + 8..offset + transform_len];
        match typ {
            1 if !encr && id == 12 && attrs == [0x80, 14, 1, 0] => encr = true,
            3 if !integ && id == 2 && attrs.is_empty() => integ = true,
            5 if !esn && id == 0 && attrs.is_empty() => esn = true,
            _ => return Err(Error::UnsupportedSuite),
        }
        offset += transform_len;
    }
    if offset != sa.len() || !encr || !integ { return Err(Error::UnsupportedSuite); }
    Ok(spi)
}

/// Accept only IPv4 protocol-any, full-port selectors the current engine enforces.
fn parse_ts(body: &[u8]) -> Result<Vec<TrafficSelector>, Error> {
    if body.len() < 4 || !(1..=64).contains(&body[0]) {
        return Err(Error::InvalidSelector);
    }
    let mut result = Vec::with_capacity(body[0] as usize);
    let mut offset = 4;
    for _ in 0..body[0] {
        if body.len() - offset < 16 { return Err(Error::InvalidSelector); }
        let ts = &body[offset..offset + 16];
        if ts[0] != 7 || ts[1] != 0 || be16(&ts[2..4]) != 16
            || be16(&ts[4..6]) != 0 || be16(&ts[6..8]) != u16::MAX {
            return Err(Error::InvalidSelector);
        }
        let first = ipv4(&ts[8..12]);
        let last = ipv4(&ts[12..16]);
        if u32::from(first) > u32::from(last) { return Err(Error::InvalidSelector); }
        result.push(TrafficSelector {
            addresses: AddressRange { first: IpAddr::V4(first), last: IpAddr::V4(last) },
            protocol: 0, first_port: 0, last_port: u16::MAX,
        });
        offset += 16;
    }
    if offset != body.len() { return Err(Error::InvalidSelector); }
    Ok(result)
}

fn mask_prefix(mask: Ipv4Addr) -> Option<u8> {
    let raw = u32::from(mask);
    let prefix = raw.leading_ones() as u8;
    let expected = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    if raw == expected { Some(prefix) } else { None }
}

fn split_range(address: Ipv4Addr, mask: Ipv4Addr) -> Result<AddressRange, Error> {
    let _ = mask_prefix(mask).ok_or(Error::InvalidConfiguration)?;
    let base = u32::from(address) & u32::from(mask);
    Ok(AddressRange {
        first: IpAddr::V4(Ipv4Addr::from(base)),
        last: IpAddr::V4(Ipv4Addr::from(base | !u32::from(mask))),
    })
}

fn domain(value: &[u8]) -> Result<String, Error> {
    let name = std::str::from_utf8(value).map_err(|_| Error::InvalidConfiguration)?;
    if name.is_empty() || name.len() > 253 || name.starts_with('.') || name.ends_with('.')
        || !name.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && label.as_bytes().first().unwrap().is_ascii_alphanumeric()
            && label.as_bytes().last().unwrap().is_ascii_alphanumeric()
            && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
        return Err(Error::InvalidConfiguration);
    }
    Ok(name.to_ascii_lowercase())
}

fn parse_cp(body: &[u8]) -> Result<Configuration, Error> {
    if body.len() < 4 || body[0] != 2 { return Err(Error::InvalidConfiguration); }
    let mut address = None;
    let mut netmask = None;
    let mut dns_servers = Vec::new();
    let mut dns_domains = Vec::new();
    let mut split_routes = Vec::new();
    let mut offset = 4;
    while offset < body.len() {
        if body.len() - offset < 4 { return Err(Error::InvalidConfiguration); }
        let typ = be16(&body[offset..offset + 2]) & 0x7fff;
        let len = be16(&body[offset + 2..offset + 4]) as usize;
        offset += 4;
        if len > body.len() - offset { return Err(Error::InvalidConfiguration); }
        let val = &body[offset..offset + len];
        match typ {
            1 if len == 4 && address.is_none() => address = Some(ipv4(val)),
            2 if len == 4 && netmask.is_none() => netmask = Some(ipv4(val)),
            3 if len == 4 && dns_servers.len() < 8 => dns_servers.push(ipv4(val)),
            3 if len == 0 => {},
            13 if len == 8 && split_routes.len() < 64 =>
                split_routes.push(split_range(ipv4(&val[..4]), ipv4(&val[4..]))?),
            13 if len == 0 => {},
            25 if !val.is_empty() && dns_domains.len() < 32 => dns_domains.push(domain(val)?),
            25 if len == 0 => {},
            // Optional, unsupported configuration must never become local policy.
            1 | 2 | 3 | 13 | 25 => return Err(Error::InvalidConfiguration),
            _ => {},
        }
        offset += len;
    }
    let assigned_ipv4 = address.ok_or(Error::InvalidConfiguration)?;
    if assigned_ipv4.is_unspecified() || assigned_ipv4.is_multicast() || assigned_ipv4.is_broadcast() {
        return Err(Error::InvalidConfiguration);
    }
    if netmask.is_some_and(|mask| mask_prefix(mask).is_none())
        || dns_servers.iter().any(|a| a.is_unspecified() || a.is_multicast())
        || (!dns_domains.is_empty() && dns_servers.is_empty()) {
        return Err(Error::InvalidConfiguration);
    }
    Ok(Configuration { assigned_ipv4, netmask, dns_servers, dns_domains, split_routes,
        route_source: RouteSource::ConfigurationSubnet })
}

/// Inputs are payload bodies from a cryptographically authenticated final IKE_AUTH response.
/// `offered_tsi/tsr` are the exact traffic-selector bodies sent in its initial request.
pub fn parse_final(sa: &[u8], tsi: &[u8], tsr: &[u8], cp: &[u8],
                   local_inbound_spi: [u8; 4], offered_tsi: &[u8], offered_tsr: &[u8])
                   -> Result<Negotiated, Error> {
    let local_inbound_spi = u32::from_be_bytes(local_inbound_spi);
    if local_inbound_spi == 0 { return Err(Error::InvalidSa); }
    let peer_inbound_spi = parse_sa(sa)?;
    if peer_inbound_spi == local_inbound_spi { return Err(Error::InvalidSa); }
    let local_selectors = parse_ts(tsi)?;
    let remote_selectors = parse_ts(tsr)?;
    let offered_local = parse_ts(offered_tsi)?;
    let offered_remote = parse_ts(offered_tsr)?;
    for (selected, offered) in [(&local_selectors, &offered_local),
                                (&remote_selectors, &offered_remote)] {
        if !selected.iter().all(|chosen| offered.iter().any(|o|
            range_contains(&o.addresses, &chosen.addresses))) {
            return Err(Error::SelectorNotNarrowed);
        }
    }
    let mut configuration = parse_cp(cp)?;
    if !local_selectors.iter().any(|s| address_in(&s.addresses, configuration.assigned_ipv4)) {
        return Err(Error::InvalidConfiguration);
    }
    if configuration.split_routes.is_empty() {
        // A narrowed TSr can supply the route policy when no CP subnet is sent.
        configuration.split_routes = remote_selectors.iter().map(|s| s.addresses).collect();
        configuration.route_source = RouteSource::NarrowedRemoteSelector;
        if configuration.split_routes.iter().any(|r| r.first == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            && r.last == IpAddr::V4(Ipv4Addr::BROADCAST)) {
            return Err(Error::NoSplitRoute);
        }
    }
    if configuration.split_routes.is_empty() || !configuration.split_routes.iter().all(|route|
        remote_selectors.iter().any(|s| range_contains(&s.addresses, route))) {
        return Err(Error::NoSplitRoute);
    }
    Ok(Negotiated { peer_inbound_spi, local_inbound_spi,
        local_selectors, remote_selectors, configuration })
}

/// First CHILD_SA uses Ni/Nr from IKE_SA_INIT and no new DH secret.
/// `prf` must be the IKE SA's negotiated PRF (SHA-256 for the current profile).
pub fn into_engine<F>(negotiated: Negotiated, sk_d: &[u8; 32], ni: &[u8], nr: &[u8],
                      mut prf: F, transport: engine::Transport, inner_mtu: usize,
                      max_tcp_record: usize) -> Result<(engine::AuthenticatedChildSa, Configuration), Error>
where F: FnMut(&[u8], &[u8]) -> Result<[u8; 32], Error> {
    if !(16..=256).contains(&ni.len()) || !(16..=256).contains(&nr.len()) {
        return Err(Error::InvalidNonce);
    }
    let mut seed = Vec::with_capacity(ni.len() + nr.len());
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    let mut keymat = [0u8; 104]; // I->R enc32+integ20, then R->I enc32+integ20
    let mut previous = [0u8; 32];
    let mut copied = 0;
    for counter in 1..=4u8 {
        let mut input = Vec::with_capacity(if counter == 1 { 0 } else { 32 } + seed.len() + 1);
        if counter != 1 { input.extend_from_slice(&previous); }
        input.extend_from_slice(&seed);
        input.push(counter);
        let next = match prf(sk_d, &input) {
            Ok(next) => next,
            Err(error) => {
                input.fill(0);
                previous.fill(0);
                seed.fill(0);
                keymat.fill(0);
                return Err(error);
            }
        };
        input.fill(0);
        previous.fill(0);
        previous = next;
        let take = (keymat.len() - copied).min(32);
        keymat[copied..copied + take].copy_from_slice(&previous[..take]);
        copied += take;
        if copied == keymat.len() { break; }
    }
    previous.fill(0);
    seed.fill(0);
    let outgoing = engine::esp::Keys {
        encryption: keymat[..32].try_into().unwrap(),
        integrity: keymat[32..52].try_into().unwrap(),
    };
    let incoming = engine::esp::Keys {
        encryption: keymat[52..84].try_into().unwrap(),
        integrity: keymat[84..104].try_into().unwrap(),
    };
    keymat.fill(0);
    let configuration = negotiated.configuration;
    let handoff = engine::AuthenticatedChildSa {
        suite: engine::EspSuite::Aes256CbcHmacSha1_96,
        esn: false,
        peer_inbound_spi: negotiated.peer_inbound_spi,
        local_inbound_spi: negotiated.local_inbound_spi,
        outbound_keys: outgoing,
        inbound_keys: incoming,
        assigned_ip: IpAddr::V4(configuration.assigned_ipv4),
        local_selectors: negotiated.local_selectors,
        remote_selectors: negotiated.remote_selectors,
        installed_routes: configuration.split_routes.clone(),
        inner_mtu, transport, max_tcp_record,
    };
    Ok((handoff, configuration))
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn oftc_swift_hmac(sha256: i32, key: *const u8, key_len: usize,
                           input: *const u8, input_len: usize,
                           digest: *mut u8, digest_len: usize) -> i32;
    }

    fn hmac256(key: &[u8], input: &[u8]) -> Result<[u8; 32], Error> {
        let mut digest = [0u8; 32];
        let rc = unsafe { oftc_swift_hmac(1, key.as_ptr(), key.len(), input.as_ptr(),
                                          input.len(), digest.as_mut_ptr(), digest.len()) };
        if rc != 0 { return Err(Error::Crypto); }
        Ok(digest)
    }

    fn transform(last: u8, typ: u8, id: u16, attrs: &[u8]) -> Vec<u8> {
        let mut out = vec![last, 0];
        out.extend_from_slice(&((8 + attrs.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[typ, 0]);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(attrs);
        out
    }
    fn sa(spi: u32, esn: Option<u16>) -> Vec<u8> {
        let mut out = vec![0, 0, 0, 0, 1, 3, 4, if esn.is_some() { 3 } else { 2 }];
        out.extend_from_slice(&spi.to_be_bytes());
        out.extend_from_slice(&transform(3, 1, 12, &[0x80, 14, 1, 0]));
        out.extend_from_slice(&transform(if esn.is_some() { 3 } else { 0 }, 3, 2, &[]));
        if let Some(id) = esn { out.extend_from_slice(&transform(0, 5, id, &[])); }
        let len = out.len() as u16;
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out
    }
    fn ts(first: Ipv4Addr, last: Ipv4Addr) -> Vec<u8> {
        let mut out = vec![1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255];
        out.extend_from_slice(&first.octets());
        out.extend_from_slice(&last.octets());
        out
    }
    fn attr(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    fn cp(route: bool) -> Vec<u8> {
        let mut out = vec![2, 0, 0, 0];
        attr(&mut out, 1, &[192, 0, 2, 42]);
        attr(&mut out, 2, &[255, 255, 255, 255]);
        attr(&mut out, 3, &[198, 51, 100, 53]);
        attr(&mut out, 25, b"internal.example");
        if route { attr(&mut out, 13, &[198, 51, 100, 0, 255, 255, 255, 0]); }
        out
    }
    fn parse(route: bool) -> Result<Negotiated, Error> {
        let any = ts(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        parse_final(&sa(0x12345678, None),
            &ts(Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(192, 0, 2, 42)),
            &ts(Ipv4Addr::new(198, 51, 100, 0), Ipv4Addr::new(198, 51, 100, 255)),
            &cp(route), 0x11223344u32.to_be_bytes(), &any, &any)
    }
    fn decode(hex: &str) -> Vec<u8> {
        hex.as_bytes().chunks_exact(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }

    #[test]
    fn valid_negotiation_and_keymat_matches_independent_python_hmac() {
        let negotiated = parse(true).unwrap();
        assert_eq!(negotiated.peer_inbound_spi, 0x12345678);
        assert_eq!(negotiated.configuration.dns_domains, ["internal.example"]);
        assert_eq!(negotiated.configuration.route_source, RouteSource::ConfigurationSubnet);
        assert_eq!(negotiated.configuration.split_routes[0].first,
                   IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)));
        let sk_d: [u8; 32] = std::array::from_fn(|i| i as u8);
        let ni: Vec<u8> = (1..=16).collect();
        let nr: Vec<u8> = (0xa0..=0xaf).collect();
        let (handoff, config) = into_engine(negotiated, &sk_d, &ni, &nr, hmac256,
            engine::Transport::Udp4500, 1400, 4096).unwrap();
        let expected = decode("1122441664339aa3376e733e4ce251e5e3b0a9bd3a8b1339b2bace66f6ec6f7e267fd043d456ef92dac8c5c4697667eb2c43069c4f4dc548b456b37f0ebfd338216f0893f2781a81c0fd1107321dd84a85cb4aefc53f9f366f088cee4cb3d65dd5914a61e96ba35a");
        assert_eq!(handoff.outbound_keys.encryption, expected[..32]);
        assert_eq!(handoff.outbound_keys.integrity, expected[32..52]);
        assert_eq!(handoff.inbound_keys.encryption, expected[52..84]);
        assert_eq!(handoff.inbound_keys.integrity, expected[84..104]);
        assert_eq!(handoff.assigned_ip, IpAddr::V4(config.assigned_ipv4));
        engine::Engine::install(handoff, engine::esp::SystemCrypto).map(|_| ()).unwrap();
    }

    #[test]
    fn accepts_explicit_no_esn_and_derived_selector_route() {
        assert_eq!(parse_sa(&sa(0x12345678, Some(0))).unwrap(), 0x12345678);
        let selected = parse(false).unwrap();
        assert_eq!(selected.configuration.route_source, RouteSource::NarrowedRemoteSelector);
        assert_eq!(selected.configuration.split_routes[0].first,
                   IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)));
    }

    #[test]
    fn rejects_esn_and_other_transforms() {
        assert_eq!(parse_sa(&sa(0x12345678, Some(1))), Err(Error::UnsupportedSuite));
        let mut bad = sa(0x12345678, None);
        bad[18] = 11; // ENCR_NULL instead of AES-CBC
        assert_eq!(parse_sa(&bad), Err(Error::UnsupportedSuite));
        let mut bad = sa(0x12345678, None);
        bad[2..4].copy_from_slice(&30u16.to_be_bytes());
        assert_eq!(parse_sa(&bad), Err(Error::InvalidSa));
    }

    #[test]
    fn rejects_unoffered_or_unsupported_selectors() {
        let offered = ts(Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 255));
        let chosen = ts(Ipv4Addr::new(192, 0, 3, 1), Ipv4Addr::new(192, 0, 3, 1));
        let any = ts(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        assert!(matches!(parse_final(&sa(1, None), &chosen, &any, &cp(true),
            2u32.to_be_bytes(), &offered, &any), Err(Error::SelectorNotNarrowed)));
        let mut port = chosen;
        port[4..6].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(parse_ts(&port), Err(Error::InvalidSelector));
    }

    #[test]
    fn rejects_inconsistent_cp_route_or_dns() {
        let mut bad = cp(true);
        bad[8..12].copy_from_slice(&[203, 0, 113, 9]); // assigned IP outside TSi
        let any = ts(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let local = ts(Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(192, 0, 2, 42));
        let remote = ts(Ipv4Addr::new(198, 51, 100, 0), Ipv4Addr::new(198, 51, 100, 255));
        assert!(matches!(parse_final(&sa(1, None), &local, &remote, &bad,
            2u32.to_be_bytes(), &any, &any), Err(Error::InvalidConfiguration)));
        let mut bad = cp(true);
        let offset = bad.windows(4).position(|w| w == [0, 13, 0, 8]).unwrap();
        bad[offset + 4..offset + 8].copy_from_slice(&[203, 0, 113, 0]);
        assert!(matches!(parse_final(&sa(1, None), &local, &remote, &bad,
            2u32.to_be_bytes(), &any, &any), Err(Error::NoSplitRoute)));
        let mut bad = cp(false);
        bad.extend_from_slice(&[0, 25, 0, 3, b'a', 0, b'b']);
        assert_eq!(parse_cp(&bad), Err(Error::InvalidConfiguration));
    }

    #[test]
    fn wildcard_without_subnet_is_not_silently_a_default_route() {
        let any = ts(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let local = ts(Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(192, 0, 2, 42));
        assert!(matches!(parse_final(&sa(1, None), &local, &any, &cp(false),
            2u32.to_be_bytes(), &any, &any), Err(Error::NoSplitRoute)));
    }

    #[test]
    fn truncated_payloads_and_crypto_failure_are_bounded() {
        let selected_sa = sa(0x12345678, None);
        let selector = ts(Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(192, 0, 2, 42));
        let configuration = cp(true);
        for size in 0..selected_sa.len() {
            assert!(parse_sa(&selected_sa[..size]).is_err());
        }
        for size in 0..selector.len() {
            assert!(parse_ts(&selector[..size]).is_err());
        }
        for size in 0..configuration.len() {
            // A shorter valid CP (before a complete next attribute) may still
            // be syntactically valid, so only check that no truncation panics.
            let _ = parse_cp(&configuration[..size]);
        }
        let negotiated = parse(true).unwrap();
        let result = into_engine(negotiated, &[0u8; 32], &[1u8; 16], &[2u8; 16],
            |_key, _data| Err(Error::Crypto), engine::Transport::Udp4500, 1400, 4096);
        assert!(matches!(result, Err(Error::Crypto)));
    }

    #[test]
    fn reserved_fields_are_ignored_on_receive() {
        let mut proposal = sa(0x12345678, None);
        proposal[1] = 0xa5;
        proposal[13] = 0x5a;
        proposal[17] = 0x7e;
        assert_eq!(parse_sa(&proposal), Ok(0x12345678));
        let mut selector = ts(Ipv4Addr::new(192, 0, 2, 42), Ipv4Addr::new(192, 0, 2, 42));
        selector[1..4].copy_from_slice(&[1, 2, 3]);
        assert_eq!(parse_ts(&selector).unwrap().len(), 1);
        let mut configuration = cp(true);
        configuration[1..4].copy_from_slice(&[1, 2, 3]);
        configuration[4] |= 0x80;
        assert_eq!(parse_cp(&configuration).unwrap().assigned_ipv4,
                   Ipv4Addr::new(192, 0, 2, 42));
    }
}
