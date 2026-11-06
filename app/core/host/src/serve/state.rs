//! The two state rules the UI used to compute, now in the host: which row state a
//! profile shows (`MenuConnectionState.resolve`) and whether the VPN component is
//! ready (`VPNComponentState.resolve`, `canReplace`). The Swift check cases moved
//! here one for one; the Swift resolvers are gone.

use std::cmp::Ordering;

use oftc_apple::error::AppleError;
use oftc_apple::manager::VpnStatus;
use oftc_apple::sysext::{is_extension_not_found, ExtensionProperties};
use oftc_ui_edge::{ComponentState, ConnectionState, Phase};

/// The row state from the NetworkExtension status, the supervisor phase, whether the
/// profile's VPN entry exists and is enabled, and a stop in progress. A live tunnel
/// status wins over a phase; a phase wins over "disconnected".
pub fn resolve_connection(
    status: Option<VpnStatus>,
    configured: bool,
    phase: Option<Phase>,
    stopping: bool,
) -> ConnectionState {
    if stopping {
        return ConnectionState::Disconnecting;
    }
    match status {
        Some(VpnStatus::Connected) => return ConnectionState::Connected,
        Some(VpnStatus::Connecting) => return ConnectionState::Connecting,
        Some(VpnStatus::Reasserting) => return ConnectionState::Reconnecting,
        Some(VpnStatus::Disconnecting) => return ConnectionState::Disconnecting,
        _ => {}
    }
    match phase {
        Some(Phase::Acquiring) => return ConnectionState::SignIn,
        Some(Phase::Connecting) => return ConnectionState::Connecting,
        Some(Phase::Recovering) => return ConnectionState::Reconnecting,
        Some(Phase::Failed) => return ConnectionState::Attention,
        _ => {}
    }
    if !configured || status == Some(VpnStatus::Invalid) {
        return ConnectionState::Setup;
    }
    ConnectionState::Disconnected
}

/// Foundation's `compare(_, options: .numeric)`, for the ASCII builds the bundle
/// uses: runs of digits compare by value, everything else byte by byte.
pub fn numeric_cmp(a: &str, b: &str) -> Ordering {
    fn runs(text: &str) -> Vec<&str> {
        let mut runs = Vec::new();
        let mut start = 0;
        let mut digits = None;
        for (index, byte) in text.bytes().enumerate() {
            let is_digit = byte.is_ascii_digit();
            if digits.is_some_and(|d| d != is_digit) {
                runs.push(&text[start..index]);
                start = index;
            }
            digits = Some(is_digit);
        }
        if start < text.len() {
            runs.push(&text[start..]);
        }
        runs
    }
    let (left, right) = (runs(a), runs(b));
    for (x, y) in left.iter().zip(&right) {
        let both_digits = x.as_bytes()[0].is_ascii_digit() && y.as_bytes()[0].is_ascii_digit();
        let order = if both_digits {
            let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
            x.len().cmp(&y.len()).then_with(|| x.cmp(y))
        } else {
            x.cmp(y)
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

/// Whether the provider the bundle ships (`expected` build) is what the system has:
/// one enabled copy that matches, a newer one, one waiting for approval, or none.
pub fn resolve_component(expected: &str, records: &[ExtensionProperties]) -> ComponentState {
    if expected.is_empty() {
        return ComponentState::Unavailable;
    }
    let current: Vec<&ExtensionProperties> = records.iter().filter(|r| !r.uninstalling).collect();
    let enabled: Vec<&&ExtensionProperties> = current.iter().filter(|r| r.enabled).collect();
    if enabled.len() > 1 {
        return ComponentState::Unavailable;
    }
    let newer = |r: &ExtensionProperties| numeric_cmp(&r.build, expected) == Ordering::Greater;
    let awaiting = current
        .iter()
        .any(|r| r.build == expected && r.awaiting_approval);
    if let Some(active) = enabled.first() {
        if active.build == expected {
            return ComponentState::Ready;
        }
        if newer(active) {
            return ComponentState::Newer;
        }
        return if awaiting {
            ComponentState::Approval
        } else {
            ComponentState::UpdateRequired
        };
    }
    if current.iter().any(|r| newer(r)) {
        return ComponentState::Newer;
    }
    if awaiting {
        return ComponentState::Approval;
    }
    if current.is_empty() {
        ComponentState::Missing
    } else {
        ComponentState::UpdateRequired
    }
}

/// Whether installing `replacement` over `existing` is not a downgrade.
pub fn can_replace(existing: &str, replacement: &str) -> bool {
    numeric_cmp(replacement, existing) != Ordering::Less
}

/// What the properties request left: the state, and the build of the enabled copy.
pub fn component_from_request(
    expected: &str,
    result: Result<Vec<ExtensionProperties>, AppleError>,
) -> (ComponentState, Option<String>) {
    match result {
        Ok(records) => {
            let installed = records
                .iter()
                .find(|r| r.enabled && !r.uninstalling)
                .map(|r| r.build.clone());
            (resolve_component(expected, &records), installed)
        }
        // Not installed at all is "missing"; any other failure (a timeout, approval
        // pending for a read-only request) leaves the question open.
        Err(error) if is_extension_not_found(&error) => (ComponentState::Missing, None),
        Err(_) => (ComponentState::Unavailable, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oftc_apple::sysext::ERROR_DOMAIN;
    use ComponentState as C;
    use ConnectionState as S;

    fn rec(build: &str, enabled: bool, awaiting: bool, uninstalling: bool) -> ExtensionProperties {
        ExtensionProperties {
            short_version: "1.0".into(),
            build: build.into(),
            enabled,
            awaiting_approval: awaiting,
            uninstalling,
        }
    }

    /// `check-menu.swift`'s `MenuConnectionState.resolve` cases, in order, then one row
    /// for each branch they leave out (the other three live statuses, the other
    /// phases, an unconfigured profile that is nonetheless connecting).
    #[test]
    fn connection_state_cases() {
        use VpnStatus as V;
        type Row = (Option<V>, bool, Option<Phase>, bool, S);
        let cases: &[Row] = &[
            (
                Some(V::Connected),
                true,
                Some(Phase::Failed),
                false,
                S::Connected,
            ),
            (
                Some(V::Connected),
                true,
                Some(Phase::Connected),
                true,
                S::Disconnecting,
            ),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Acquiring),
                false,
                S::SignIn,
            ),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Recovering),
                false,
                S::Reconnecting,
            ),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Stopped),
                false,
                S::Disconnected,
            ),
            (None, false, None, false, S::Setup),
            (
                Some(V::Reasserting),
                true,
                Some(Phase::Connected),
                false,
                S::Reconnecting,
            ),
            (Some(V::Invalid), true, None, false, S::Setup),
            // Beyond the Swift cases.
            (Some(V::Connecting), true, None, false, S::Connecting),
            (Some(V::Disconnecting), true, None, false, S::Disconnecting),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Connecting),
                false,
                S::Connecting,
            ),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Failed),
                false,
                S::Attention,
            ),
            (
                Some(V::Disconnected),
                true,
                Some(Phase::Connected),
                false,
                S::Disconnected,
            ),
            (Some(V::Disconnected), false, None, false, S::Setup),
            (Some(V::Connecting), false, None, false, S::Connecting),
            (None, true, None, false, S::Disconnected),
        ];
        for (status, configured, phase, stopping, expected) in cases {
            assert_eq!(
                resolve_connection(*status, *configured, *phase, *stopping),
                *expected,
                "{status:?} configured={configured} {phase:?} stopping={stopping}"
            );
        }
    }

    /// `check-experience.swift`'s `VPNComponentState.resolve` and `canReplace` cases.
    #[test]
    fn component_state_cases() {
        let enabled = |build| rec(build, true, false, false);
        assert_eq!(resolve_component("23", &[]), C::Missing);
        assert_eq!(resolve_component("23", &[enabled("20")]), C::UpdateRequired);
        assert_eq!(
            resolve_component("23", &[enabled("23"), rec("20", true, false, true)]),
            C::Ready
        );
        assert_eq!(
            resolve_component("23", &[enabled("20"), rec("23", false, true, false)]),
            C::Approval
        );
        assert_ne!(
            resolve_component("23", &[rec("23", false, false, false)]),
            C::Ready
        );
        assert_eq!(resolve_component("23", &[enabled("24")]), C::Newer);
        assert_eq!(
            resolve_component("23", &[enabled("23"), enabled("20")]),
            C::Unavailable
        );
        assert_eq!(resolve_component("", &[enabled("23")]), C::Unavailable);
        // Builds compare as numbers, not text: "10" is newer than "9".
        assert_eq!(resolve_component("9", &[enabled("10")]), C::Newer);
        assert!(can_replace("20", "23"));
        assert!(can_replace("23", "23"));
        assert!(!can_replace("24", "23"));
        // Beyond the Swift cases: the branches with no enabled copy.
        assert_eq!(
            resolve_component("23", &[rec("24", false, false, false)]),
            C::Newer
        );
        assert_eq!(
            resolve_component("23", &[rec("23", false, true, false)]),
            C::Approval
        );
        assert_eq!(
            resolve_component("23", &[rec("20", false, false, false)]),
            C::UpdateRequired
        );
        assert_eq!(
            resolve_component("23", &[rec("23", true, false, true)]),
            C::Missing
        );
    }

    #[test]
    fn numeric_order() {
        for (a, b, order) in [
            ("9", "10", Ordering::Less),
            ("10", "9", Ordering::Greater),
            ("23", "23", Ordering::Equal),
            ("007", "7", Ordering::Equal),
            ("1.9", "1.10", Ordering::Less),
            ("23", "23a", Ordering::Less),
            ("a", "b", Ordering::Less),
        ] {
            assert_eq!(numeric_cmp(a, b), order, "{a} {b}");
        }
    }

    /// The properties request's failures map as `ProviderReadiness.swift` did: not
    /// installed is missing, anything else unavailable; the installed build is the
    /// enabled copy's.
    #[test]
    fn component_from_the_request_result() {
        let not_found = AppleError::from_nserror(ERROR_DOMAIN, 4, "none");
        assert_eq!(
            component_from_request("23", Err(not_found)),
            (C::Missing, None)
        );
        for error in [AppleError::TimedOut, AppleError::ApprovalRequired] {
            assert_eq!(
                component_from_request("23", Err(error)),
                (C::Unavailable, None)
            );
        }
        let records = vec![
            rec("20", false, false, false),
            rec("23", true, false, false),
        ];
        assert_eq!(
            component_from_request("23", Ok(records)),
            (C::Ready, Some("23".into()))
        );
    }
}
