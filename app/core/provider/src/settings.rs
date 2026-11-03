//! Validation of the authenticated settings before anything is installed.
//! Ports `SettingsMapper.make` and the bounds in `FFISettings.read`. The
//! engine's [`NetworkSettings`] is already typed, so the string-parsing cases of
//! the Swift code are gone; every rule about what a *value* may be is kept.
//! Turning valid settings into OS objects is the backend's job.

use std::net::{IpAddr, Ipv4Addr};

use oftc_engine::NetworkSettings;

pub const MAX_ROUTES: usize = 64;
pub const MAX_DNS_SERVERS: usize = 8;
pub const MAX_DNS_DOMAINS: usize = 32;
const MIN_MTU: usize = 576;
const MAX_MTU: usize = 9000;
const MAX_DOMAIN: usize = 253;
const MAX_LABEL: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsError {
    InvalidAddress,
    InvalidMask,
    InvalidRoute,
    InvalidDns,
    InvalidMtu,
    RecursiveEndpoint,
}

fn unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified() && u32::from(address) < 0xe000_0000
}

fn contiguous_nonzero_mask(mask: Ipv4Addr) -> bool {
    let inverse = !u32::from(mask);
    inverse & inverse.wrapping_add(1) == 0 && mask != Ipv4Addr::UNSPECIFIED
}

/// A CIDR block: aligned, power-of-two sized, IPv4.
fn valid_route(first: IpAddr, last: IpAddr) -> bool {
    let (IpAddr::V4(first), IpAddr::V4(last)) = (first, last) else {
        return false;
    };
    let (first, last) = (u64::from(u32::from(first)), u64::from(u32::from(last)));
    if first > last {
        return false;
    }
    let size = last - first + 1;
    size & (size - 1) == 0 && first & (size - 1) == 0
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_DOMAIN
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The outer gateway address: any unicast address, and for an IPv4-mapped IPv6
/// one the embedded IPv4 address, which still needs a route exclusion.
fn outer_ipv4(outer: IpAddr) -> Result<Option<Ipv4Addr>, SettingsError> {
    match outer {
        IpAddr::V4(address) if unicast(address) => Ok(Some(address)),
        IpAddr::V6(address) if !address.is_unspecified() && !address.is_multicast() => {
            match address.to_ipv4_mapped() {
                Some(peer) if !unicast(peer) => Err(SettingsError::InvalidAddress),
                mapped => Ok(mapped),
            }
        }
        _ => Err(SettingsError::InvalidAddress),
    }
}

pub fn validate(settings: &NetworkSettings) -> Result<(), SettingsError> {
    let assigned = settings.assigned_ipv4;
    if !unicast(assigned) || assigned == Ipv4Addr::BROADCAST {
        return Err(SettingsError::InvalidAddress);
    }
    // The mask the gateway supplied is checked but never widens routing: the
    // interface is installed as a /32 and only the split routes are routed.
    if !contiguous_nonzero_mask(settings.interface_mask()) {
        return Err(SettingsError::InvalidMask);
    }
    if !(MIN_MTU..=MAX_MTU).contains(&settings.inner_mtu) {
        return Err(SettingsError::InvalidMtu);
    }
    if settings.split_routes.is_empty() || settings.split_routes.len() > MAX_ROUTES {
        return Err(SettingsError::InvalidRoute);
    }
    if outer_ipv4(settings.outer_remote_ip)? == Some(assigned) {
        return Err(SettingsError::RecursiveEndpoint);
    }
    if !settings.split_routes.iter().all(|r| valid_route(r.first, r.last)) {
        return Err(SettingsError::InvalidRoute);
    }
    if settings.dns_servers.len() > MAX_DNS_SERVERS
        || settings.dns_domains.len() > MAX_DNS_DOMAINS
        || !settings.dns_domains.iter().all(|d| valid_domain(d))
        || (settings.dns_servers.is_empty() && !settings.dns_domains.is_empty())
        || !settings.dns_servers.iter().all(|s| unicast(*s))
    {
        return Err(SettingsError::InvalidDns);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_engine::AddressRange;
    use std::net::Ipv6Addr;

    fn cidr(first: [u8; 4], last: [u8; 4]) -> AddressRange {
        AddressRange { first: IpAddr::V4(first.into()), last: IpAddr::V4(last.into()) }
    }

    fn good() -> NetworkSettings {
        NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::new(203, 0, 113, 7),
            outer_remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            assigned_ipv4: Ipv4Addr::new(10, 99, 0, 12),
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            split_routes: vec![cidr([10, 0, 8, 0], [10, 0, 15, 255])],
            dns_servers: vec![Ipv4Addr::new(10, 0, 8, 1)],
            dns_domains: vec!["corp.example".into()],
            inner_mtu: 1280,
        }
    }

    fn with(change: impl FnOnce(&mut NetworkSettings)) -> Result<(), SettingsError> {
        let mut settings = good();
        change(&mut settings);
        validate(&settings)
    }

    #[test]
    fn accepts_good_settings_and_the_edge_cases_around_them() {
        assert_eq!(validate(&good()), Ok(()));
        // No mask supplied means /32; no DNS at all is allowed; the whole space
        // and a single host are valid routes; the MTU bounds are inclusive.
        assert_eq!(with(|s| { s.netmask = None; s.dns_servers.clear(); s.dns_domains.clear(); }), Ok(()));
        assert_eq!(with(|s| s.split_routes = vec![cidr([0, 0, 0, 0], [255, 255, 255, 255])]), Ok(()));
        assert_eq!(with(|s| s.split_routes = vec![cidr([10, 0, 0, 5], [10, 0, 0, 5])]), Ok(()));
        assert_eq!(with(|s| s.inner_mtu = 576), Ok(()));
        assert_eq!(with(|s| s.inner_mtu = 9000), Ok(()));
        assert_eq!(with(|s| s.dns_servers = vec![Ipv4Addr::new(10, 0, 8, 1); MAX_DNS_SERVERS]), Ok(()));
        assert_eq!(with(|s| s.dns_domains = vec!["a.example".into(); MAX_DNS_DOMAINS]), Ok(()));
        assert_eq!(with(|s| s.split_routes = vec![cidr([10, 0, 8, 0], [10, 0, 15, 255]); MAX_ROUTES]), Ok(()));
    }

    #[test]
    fn rejects_bad_assigned_addresses() {
        for bad in [[0, 0, 0, 0], [224, 0, 0, 1], [255, 255, 255, 255]] {
            assert_eq!(with(|s| s.assigned_ipv4 = bad.into()), Err(SettingsError::InvalidAddress));
        }
    }

    #[test]
    fn rejects_masks_that_are_not_a_nonzero_prefix() {
        for bad in [[255, 0, 255, 0], [0, 0, 0, 0], [0, 255, 255, 255]] {
            assert_eq!(with(|s| s.netmask = Some(bad.into())), Err(SettingsError::InvalidMask));
        }
    }

    #[test]
    fn rejects_mtu_outside_the_bounds() {
        for bad in [0, 575, 9001] {
            assert_eq!(with(|s| s.inner_mtu = bad), Err(SettingsError::InvalidMtu));
        }
    }

    #[test]
    fn rejects_empty_oversize_and_malformed_routes() {
        assert_eq!(with(|s| s.split_routes.clear()), Err(SettingsError::InvalidRoute));
        assert_eq!(
            with(|s| s.split_routes = vec![cidr([10, 0, 8, 0], [10, 0, 15, 255]); MAX_ROUTES + 1]),
            Err(SettingsError::InvalidRoute)
        );
        for (first, last) in [
            ([10, 0, 15, 255], [10, 0, 8, 0]), // reversed
            ([10, 0, 8, 0], [10, 0, 8, 2]),    // not a power of two
            ([10, 0, 8, 1], [10, 0, 8, 2]),    // misaligned
            ([10, 0, 8, 4], [10, 0, 8, 11]),   // power of two, misaligned
        ] {
            assert_eq!(
                with(|s| s.split_routes = vec![cidr(first, last)]),
                Err(SettingsError::InvalidRoute)
            );
        }
        let v6 = AddressRange {
            first: IpAddr::V6(Ipv6Addr::LOCALHOST),
            last: IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        assert_eq!(with(|s| s.split_routes = vec![v6]), Err(SettingsError::InvalidRoute));
    }

    #[test]
    fn checks_the_outer_endpoint() {
        let outer = |ip: IpAddr| move |s: &mut NetworkSettings| s.outer_remote_ip = ip;
        let v6 = |text: &str| IpAddr::V6(text.parse().unwrap());
        assert_eq!(with(outer(v6("2001:db8::7"))), Ok(()));
        assert_eq!(with(outer(v6("::ffff:203.0.113.7"))), Ok(()));
        for bad in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            v6("::"),
            v6("ff02::1"),
            v6("::ffff:0.0.0.0"),
            v6("::ffff:224.0.0.1"),
        ] {
            assert_eq!(with(outer(bad)), Err(SettingsError::InvalidAddress), "{bad}");
        }
    }

    #[test]
    fn rejects_an_outer_endpoint_equal_to_the_assigned_address() {
        let same = Ipv4Addr::new(10, 99, 0, 12);
        assert_eq!(
            with(|s| s.outer_remote_ip = IpAddr::V4(same)),
            Err(SettingsError::RecursiveEndpoint)
        );
        assert_eq!(
            with(|s| s.outer_remote_ip = IpAddr::V6(same.to_ipv6_mapped())),
            Err(SettingsError::RecursiveEndpoint)
        );
    }

    #[test]
    fn rejects_bad_dns() {
        assert_eq!(
            with(|s| s.dns_servers = vec![Ipv4Addr::new(10, 0, 8, 1); MAX_DNS_SERVERS + 1]),
            Err(SettingsError::InvalidDns)
        );
        assert_eq!(
            with(|s| s.dns_domains = vec!["a.example".into(); MAX_DNS_DOMAINS + 1]),
            Err(SettingsError::InvalidDns)
        );
        // Domains without servers have nothing to match.
        assert_eq!(with(|s| s.dns_servers.clear()), Err(SettingsError::InvalidDns));
        for bad in [[0, 0, 0, 0], [224, 0, 0, 1]] {
            assert_eq!(
                with(|s| s.dns_servers = vec![bad.into()]),
                Err(SettingsError::InvalidDns)
            );
        }
        let long_label = "a".repeat(64);
        let long_name = format!("{}.example", vec!["a".repeat(60); 5].join("."));
        for bad in [
            "", ".", "a..b", "-a.example", "a-.example", "a_b.example", "corp.example.",
            "bücher.example", long_label.as_str(), long_name.as_str(),
        ] {
            assert_eq!(
                with(|s| s.dns_domains = vec![bad.into()]),
                Err(SettingsError::InvalidDns),
                "{bad}"
            );
        }
        assert_eq!(with(|s| s.dns_domains = vec!["a-b.c1.example".into()]), Ok(()));
    }
}
