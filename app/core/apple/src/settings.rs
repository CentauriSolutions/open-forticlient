//! Representation of validated tunnel settings, as NetworkExtension wants them.
//!
//! Ports the output half of `SettingsMapper.make`. [`oftc_provider::settings`]
//! owns every rule about what a value may be; [`convert`] owns only how a valid
//! value is spelled: a `/32` interface mask, routes as destination plus mask,
//! one excluded `/32` for the outer IPv4 gateway, and the DNS match and search
//! domain shape. It re-checks no rule, but it never panics: input that could not
//! have passed validation is [`TunnelError::SettingsRejected`], so a skipped
//! validation fails closed instead of installing garbage.
//!
//! The result is a plain struct, so the conversion is testable without any Apple
//! framework; the NetworkExtension backend turns it into the framework's objects.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oftc_engine::tunnel::TunnelError;
use oftc_engine::{AddressRange, NetworkSettings};

const HOST_MASK: &str = "255.255.255.255";

/// An IPv4 route as NetworkExtension takes it: dotted destination and mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeRoute {
    pub destination: String,
    pub mask: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeDns {
    pub servers: Vec<String>,
    pub match_domains: Vec<String>,
    pub search_domains: Vec<String>,
    pub match_domains_no_search: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeSettings {
    /// `tunnelRemoteAddress`: the connected outer gateway, as text.
    pub remote_address: String,
    pub address: String,
    /// Always `/32`: the interface mask must not create an on-link route wider
    /// than the authenticated split routes.
    pub subnet_mask: String,
    pub included_routes: Vec<NeRoute>,
    pub excluded_routes: Vec<NeRoute>,
    pub dns: Option<NeDns>,
    pub mtu: u32,
}

/// IPv6 address text as Swift's `FFISettings` printed it: eight unpadded hex
/// groups, never `::`-compressed (`0:0:0:0:0:ffff:cb00:7100`). Not
/// `Ipv6Addr::to_string`, which compresses and prints mapped addresses in
/// dotted form.
pub fn ipv6_text(address: Ipv6Addr) -> String {
    let groups: Vec<String> = address
        .segments()
        .iter()
        .map(|segment| format!("{segment:x}"))
        .collect();
    groups.join(":")
}

fn host_route(address: Ipv4Addr) -> NeRoute {
    NeRoute {
        destination: address.to_string(),
        mask: HOST_MASK.to_owned(),
    }
}

/// CIDR first/last to destination and mask. `/0` is the all-zero mask; shifting
/// by 32 would overflow, and the workspace builds with overflow checks on.
fn route(range: &AddressRange) -> Result<NeRoute, TunnelError> {
    let (IpAddr::V4(first), IpAddr::V4(last)) = (range.first, range.last) else {
        return Err(TunnelError::SettingsRejected);
    };
    let (first, last) = (u32::from(first), u32::from(last));
    let size = u64::from(last)
        .checked_sub(u64::from(first))
        .map(|span| span + 1)
        .filter(|size| size.is_power_of_two() && u64::from(first) & (size - 1) == 0)
        .ok_or(TunnelError::SettingsRejected)?;
    let host_bits = size.trailing_zeros();
    let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
    Ok(NeRoute {
        destination: Ipv4Addr::from(first).to_string(),
        mask: Ipv4Addr::from(mask).to_string(),
    })
}

pub fn convert(settings: &NetworkSettings) -> Result<NeSettings, TunnelError> {
    let excluded = oftc_provider::settings::outer_ipv4(settings.outer_remote_ip)
        .map_err(|_| TunnelError::SettingsRejected)?;
    let remote_address = match settings.outer_remote_ip {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => ipv6_text(address),
    };
    let included_routes = settings
        .split_routes
        .iter()
        .map(route)
        .collect::<Result<Vec<_>, _>>()?;
    let dns = if settings.dns_servers.is_empty() {
        None
    } else {
        let servers = settings
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect();
        Some(if settings.dns_domains.is_empty() {
            // Servers without a split DNS suffix: the empty match domain is the
            // system resolver.
            NeDns {
                servers,
                match_domains: vec![String::new()],
                search_domains: Vec::new(),
                match_domains_no_search: false,
            }
        } else {
            NeDns {
                servers,
                match_domains: settings.dns_domains.clone(),
                search_domains: settings.dns_domains.clone(),
                match_domains_no_search: true,
            }
        })
    };
    Ok(NeSettings {
        remote_address,
        address: settings.assigned_ipv4.to_string(),
        subnet_mask: HOST_MASK.to_owned(),
        included_routes,
        excluded_routes: excluded.map(host_route).into_iter().collect(),
        dns,
        mtu: u32::try_from(settings.inner_mtu).map_err(|_| TunnelError::SettingsRejected)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn range(first: IpAddr, last: IpAddr) -> AddressRange {
        AddressRange { first, last }
    }

    fn base() -> NetworkSettings {
        NetworkSettings {
            outer_remote_ipv4: Ipv4Addr::new(203, 0, 113, 1),
            outer_remote_ip: v4(203, 0, 113, 1),
            assigned_ipv4: Ipv4Addr::new(10, 0, 0, 5),
            // The gateway's mask is validated elsewhere and never routed.
            netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            split_routes: vec![range(v4(10, 1, 0, 0), v4(10, 1, 255, 255))],
            dns_servers: vec![],
            dns_domains: vec![],
            inner_mtu: 1400,
        }
    }

    fn route_text(destination: &str, mask: &str) -> NeRoute {
        NeRoute {
            destination: destination.into(),
            mask: mask.into(),
        }
    }

    #[test]
    fn interface_is_a_host_address_with_the_outer_gateway_excluded() {
        let ne = convert(&base()).unwrap();
        assert_eq!(ne.remote_address, "203.0.113.1");
        assert_eq!(ne.address, "10.0.0.5");
        assert_eq!(ne.subnet_mask, "255.255.255.255");
        assert_eq!(
            ne.excluded_routes,
            [route_text("203.0.113.1", "255.255.255.255")]
        );
        assert_eq!(ne.included_routes, [route_text("10.1.0.0", "255.255.0.0")]);
        assert_eq!(ne.mtu, 1400);
        assert_eq!(ne.dns, None);
    }

    #[test]
    fn outer_gateway_spelling_and_exclusion_by_family() {
        let mut mapped = base();
        mapped.outer_remote_ip = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 1).to_ipv6_mapped());
        let ne = convert(&mapped).unwrap();
        assert_eq!(ne.remote_address, "0:0:0:0:0:ffff:cb00:7101");
        assert_eq!(
            ne.excluded_routes,
            [route_text("203.0.113.1", "255.255.255.255")]
        );

        let mut native = base();
        native.outer_remote_ip = "2001:db8::1".parse().unwrap();
        let ne = convert(&native).unwrap();
        assert_eq!(ne.remote_address, "2001:db8:0:0:0:0:0:1");
        assert!(ne.excluded_routes.is_empty());
    }

    #[test]
    fn routes_become_destination_and_mask() {
        let cases = [
            (
                (v4(192, 0, 2, 7), v4(192, 0, 2, 7)),
                ("192.0.2.7", "255.255.255.255"),
            ),
            (
                (v4(192, 0, 2, 0), v4(192, 0, 2, 255)),
                ("192.0.2.0", "255.255.255.0"),
            ),
            // /0: `u32::MAX << 32` would overflow-panic.
            (
                (v4(0, 0, 0, 0), v4(255, 255, 255, 255)),
                ("0.0.0.0", "0.0.0.0"),
            ),
        ];
        for ((first, last), (destination, mask)) in cases {
            assert_eq!(
                route(&range(first, last)),
                Ok(route_text(destination, mask)),
                "{first}-{last}"
            );
        }
    }

    #[test]
    fn input_validation_would_have_refused_is_rejected_not_panicked() {
        let mut bad_range = base();
        for (first, last) in [
            (v4(10, 0, 0, 0), v4(10, 0, 0, 2)), // not a power of two
            (v4(10, 0, 0, 1), v4(10, 0, 0, 2)), // unaligned
            (v4(10, 0, 0, 9), v4(10, 0, 0, 1)), // reversed
            (
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ), // V6 route
        ] {
            bad_range.split_routes = vec![range(first, last)];
            assert_eq!(
                convert(&bad_range),
                Err(TunnelError::SettingsRejected),
                "{first}-{last}"
            );
        }
        let mut multicast = base();
        for outer in [
            v4(224, 0, 0, 1),
            IpAddr::V6(Ipv4Addr::new(224, 0, 0, 1).to_ipv6_mapped()),
        ] {
            multicast.outer_remote_ip = outer;
            assert_eq!(
                convert(&multicast),
                Err(TunnelError::SettingsRejected),
                "{outer}"
            );
        }
    }

    #[test]
    fn dns_shapes() {
        let servers = vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)];
        let names =
            |servers: &[Ipv4Addr]| servers.iter().map(ToString::to_string).collect::<Vec<_>>();

        let mut settings = base();
        settings.dns_servers = servers.clone();
        assert_eq!(
            convert(&settings).unwrap().dns,
            Some(NeDns {
                servers: names(&servers),
                match_domains: vec![String::new()],
                search_domains: vec![],
                match_domains_no_search: false,
            })
        );

        settings.dns_domains = vec!["corp.example".into(), "example.com".into()];
        assert_eq!(
            convert(&settings).unwrap().dns,
            Some(NeDns {
                servers: names(&servers),
                match_domains: settings.dns_domains.clone(),
                search_domains: settings.dns_domains.clone(),
                match_domains_no_search: true,
            })
        );

        // Domains without servers install no DNS block (validation refuses it).
        settings.dns_servers.clear();
        assert_eq!(convert(&settings).unwrap().dns, None);
    }
}
