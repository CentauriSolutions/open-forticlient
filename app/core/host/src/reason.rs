//! Why a connection failed, in words the user can act on.
//!
//! The provider stops with an `OFTCProvider` NSError whose code is `100 * k + n`
//! (`oftc_provider::Failure`): `k` 1 for connect, 2 send, 3 receive, 4 liveness,
//! 5 rekey probe, and `n` the engine status, which for a session error is already
//! `100 + <kind>`. So a connect failure with `Error::Socket` (status 101) is
//! **201**, not a send error; the macOS log line `OFTC provider stage 201 failed`
//! is that code. The supervisor records the code of an attempt that never came up
//! (all of these are connect codes) and [`LOST`] for a tunnel that was up and
//! could not be recovered; [`explain`] turns either into the `error` of the status
//! document (`docs/ui-edge.md` 4.5). Messages hold no hostname, address or secret.

use oftc_ui_edge::ErrorCode;

/// Recorded instead of a provider code when an established tunnel dropped and the
/// automatic recoveries are used up.
pub const LOST: i32 = 1000;

/// The error code and the one-line message for a recorded failure, or `None` when
/// the code says nothing a user can act on (the menu keeps its generic text).
pub fn explain(code: i32) -> Option<(ErrorCode, &'static str)> {
    Some(match code {
        // Resolve: no address for the gateway name.
        200 => (ErrorCode::GatewayNotFound, "The gateway's address could not be found. Check the network connection and the gateway name."),
        // Socket after the UDP attempt timed out and the TCP fallback failed too.
        201 => (ErrorCode::NetworkBlocked, "The gateway did not answer over UDP or over TCP. This network may block UDP."),
        // Timeout with no fallback left, or after the gateway had answered.
        202 => (ErrorCode::GatewayNoAnswer, "The gateway did not answer in time."),
        // SA_INIT refused, CHILD_SA refused, ESP/control/inactive during setup.
        203 | 209..=212 => (ErrorCode::GatewayRefused, "The gateway refused to set up the tunnel."),
        // The gateway's authentication did not verify: a wrong pre-shared key.
        204 => (ErrorCode::GatewayRefused, "The gateway could not be verified. Check the profile's pre-shared key."),
        // EAP challenge, rejection or verification, and the final AUTH.
        205..=208 => (ErrorCode::SignInRejected, "The gateway rejected the sign-in. It may have expired; try again."),
        LOST => (ErrorCode::ConnectionLost, "The connection was lost and could not be restored."),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every connect code the engine can produce, and what the user is told.
    #[test]
    fn codes_map_to_reasons() {
        let table = [
            (200, Some(ErrorCode::GatewayNotFound)),
            (201, Some(ErrorCode::NetworkBlocked)), // UDP unanswered, TCP 4443 fallback refused or dropped
            (202, Some(ErrorCode::GatewayNoAnswer)),
            (203, Some(ErrorCode::GatewayRefused)),
            (204, Some(ErrorCode::GatewayRefused)),
            (205, Some(ErrorCode::SignInRejected)),
            (206, Some(ErrorCode::SignInRejected)),
            (207, Some(ErrorCode::SignInRejected)),
            (208, Some(ErrorCode::SignInRejected)),
            (209, Some(ErrorCode::GatewayRefused)),
            (212, Some(ErrorCode::GatewayRefused)),
            (LOST, Some(ErrorCode::ConnectionLost)),
            // Busy, bad options, cancelled, a stop, a panic, receive/liveness codes.
            (101, None),
            (104, None),
            (213, None),
            (301, None),
            (900, None),
        ];
        for (code, want) in table {
            assert_eq!(explain(code).map(|(c, _)| c), want, "{code}");
        }
    }

    /// The UDP-blocked case reads as such, and no message names a host or a code.
    #[test]
    fn messages_are_plain() {
        let (_, blocked) = explain(201).unwrap();
        assert!(blocked.contains("UDP") && blocked.contains("TCP"));
        for code in (200..=212).chain([LOST]) {
            let (_, text) = explain(code).unwrap();
            assert!(text.ends_with('.') && !text.chars().any(|c| c.is_ascii_digit()), "{text}");
        }
    }
}
