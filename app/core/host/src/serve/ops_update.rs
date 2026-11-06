//! `check_update`: is a newer release published? The host fetches a GitHub
//! "latest release" document and offers only a final release with an https page; the
//! UI opens the page, nothing is downloaded or run.
//!
//! This is the Swift `UpdateFeed` and `AppVersion` (`Host/UpdateCheck.swift`), ported.
//! The fetch is `/usr/bin/curl` limited to https, a size and a time (the same
//! child-process edge as the certificate check), not an HTTP client in the host.

use std::path::Path;
use std::process::{Command, Stdio};

use oftc_ui_edge::{UpdateOffer, UpdateResult};
use serde::Deserialize;

use super::info;
use super::ops::{value, OpCx, OpResult};
use crate::typed::Failure;

/// A feed document larger than this is refused.
pub const MAX_BYTES: usize = 256 * 1024;
const TIMEOUT_SECS: &str = "15";

/// The feed could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedUnreachable;

/// The newest published release, if it is newer than `current`.
pub trait UpdateSource: Send + Sync {
    /// `Ok(None)`: up to date, or no feed is configured. `Err`: the feed could not be
    /// read.
    fn latest(&self, current: &str) -> Result<Option<UpdateOffer>, FeedUnreachable>;
}

/// A dotted release number such as `1.2.1` or `v1.2`; a suffix (`1.3.0-beta1`) is
/// refused, so a prerelease is never offered.
fn version_parts(text: &str) -> Option<Vec<u32>> {
    let value = text.trim();
    let value = value
        .strip_prefix('v')
        .or_else(|| value.strip_prefix('V'))
        .unwrap_or(value);
    let pieces: Vec<&str> = value.split('.').collect();
    if !(1..=4).contains(&pieces.len()) {
        return None;
    }
    pieces
        .into_iter()
        .map(|piece| {
            (!piece.is_empty() && piece.bytes().all(|b| b.is_ascii_digit()))
                .then(|| piece.parse::<u32>().ok())
                .flatten()
                .filter(|n| *n < 100_000)
        })
        .collect()
}

fn newer(latest: &[u32], installed: &[u32]) -> bool {
    let count = latest.len().max(installed.len());
    for index in 0..count {
        let a = latest.get(index).copied().unwrap_or(0);
        let b = installed.get(index).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    draft: Option<bool>,
    prerelease: Option<bool>,
}

/// The offer a feed document makes to a build at `current`, if any.
pub fn offer_from(data: &[u8], current: &str) -> Option<UpdateOffer> {
    if data.len() > MAX_BYTES {
        return None;
    }
    let release: Release = serde_json::from_slice(data).ok()?;
    if release.draft == Some(true) || release.prerelease == Some(true) {
        return None;
    }
    let latest = version_parts(&release.tag_name)?;
    if !newer(&latest, &version_parts(current)?) {
        return None;
    }
    let page = release.html_url;
    let host = page.strip_prefix("https://")?.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name)
        .to_owned();
    Some(UpdateOffer { version, page })
}

/// The feed named in the app's Info.plist (`OFTCUpdateFeedURL`), fetched with curl.
pub struct CurlUpdates {
    pub feed: Option<String>,
}

impl CurlUpdates {
    /// The feed of the bundle that holds `exe`.
    pub fn from_bundle(exe: Option<&Path>) -> CurlUpdates {
        let feed =
            info::bundle_string(exe, "OFTCUpdateFeedURL").filter(|f| f.starts_with("https://"));
        CurlUpdates { feed }
    }
}

impl UpdateSource for CurlUpdates {
    fn latest(&self, current: &str) -> Result<Option<UpdateOffer>, FeedUnreachable> {
        let Some(feed) = &self.feed else {
            return Ok(None);
        };
        let output = Command::new("/usr/bin/curl")
            .args([
                "--silent",
                "--fail",
                "--proto",
                "=https",
                "--max-time",
                TIMEOUT_SECS,
            ])
            .args(["--max-filesize", &MAX_BYTES.to_string()])
            .args(["--header", "Accept: application/vnd.github+json"])
            .args(["--user-agent", &format!("Open-Forticlient/{current}")])
            .arg(feed)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| FeedUnreachable)?;
        if !output.status.success() || output.stdout.len() > MAX_BYTES {
            return Err(FeedUnreachable);
        }
        Ok(offer_from(&output.stdout, current))
    }
}

/// The `check_update` op.
pub fn check_update(cx: &OpCx) -> OpResult {
    let current = &cx.services.host.version;
    match cx.services.ops.updates.latest(current) {
        Ok(available) => value(&UpdateResult { available }),
        Err(FeedUnreachable) => Err(Failure::internal(
            "The update check could not reach the feed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, url: &str, flags: &str) -> Vec<u8> {
        format!(r#"{{"tag_name":"{tag}","html_url":"{url}"{flags}}}"#).into_bytes()
    }

    /// The feed rules of the Swift `UpdateFeed`: only a newer final release with an
    /// https page is offered, and versions compare numerically by part.
    #[test]
    fn offers() {
        let page = "https://example.com/oftc/releases/tag/v0.10.0";
        let offer = |doc: &[u8], current: &str| offer_from(doc, current).map(|o| o.version);
        let ok = release("v0.10.0", page, "");
        for (doc, current, expect) in [
            (&ok, "0.9.0", Some("0.10.0")),
            (&ok, "0.10.0", None),
            (&ok, "0.10.1", None),
            (&ok, "1.0", None),
            (&release("0.10", page, ""), "0.9.9", Some("0.10")),
            (&release("v1.0.0-beta1", page, ""), "0.9.0", None),
            (
                &release("v0.10.0", page, r#","prerelease":true"#),
                "0.9.0",
                None,
            ),
            (&release("v0.10.0", page, r#","draft":true"#), "0.9.0", None),
            (
                &release("v0.10.0", "http://example.com/x", ""),
                "0.9.0",
                None,
            ),
            (&release("v0.10.0", "https:///x", ""), "0.9.0", None),
            (&ok, "dev", None),
            (&b"not json".to_vec(), "0.9.0", None),
            (&vec![b' '; MAX_BYTES + 1], "0.9.0", None),
        ] {
            assert_eq!(
                offer(doc, current).as_deref(),
                expect,
                "{} at {current}",
                String::from_utf8_lossy(&doc[..doc.len().min(60)])
            );
        }
    }
}
