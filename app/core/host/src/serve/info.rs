//! The bundle's version strings, for `host` in `hello` and the status document.

use std::fs;
use std::path::Path;

use oftc_ui_edge::HostBlock;

/// The value of `key` in an XML property list, when it is a `<string>`.
fn plist_string(xml: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{key}</key>");
    let after = &xml[xml.find(&marker)? + marker.len()..];
    let after = after.trim_start().strip_prefix("<string>")?;
    Some(after[..after.find("</string>")?].to_owned())
}

fn read_key(plist: &Path, key: &str) -> String {
    fs::read_to_string(plist)
        .ok()
        .and_then(|xml| plist_string(&xml, key))
        .unwrap_or_default()
}

/// A string key of the app's own Info.plist, for the bundle that holds `exe`.
pub fn bundle_string(exe: Option<&Path>, key: &str) -> Option<String> {
    let contents = exe?.parent()?.parent()?;
    Some(read_key(&contents.join("Info.plist"), key)).filter(|value| !value.is_empty())
}

/// The marketing version and build of the app, and the build of the system extension it
/// ships, read from the bundle that holds `exe` (`<app>/Contents/MacOS/<exe>`). A bundle
/// that cannot be read gives empty strings, which the component check treats as
/// "unavailable" rather than guessing.
pub fn host_block(exe: Option<&Path>, provider_id: &str) -> HostBlock {
    let Some(contents) = exe.and_then(|exe| exe.parent()?.parent()) else {
        return HostBlock {
            version: String::new(),
            build: String::new(),
            provider_build: String::new(),
        };
    };
    let app = contents.join("Info.plist");
    let provider = contents
        .join("Library/SystemExtensions")
        .join(format!("{provider_id}.systemextension/Contents/Info.plist"));
    HostBlock {
        version: read_key(&app, "CFBundleShortVersionString"),
        build: read_key(&app, "CFBundleVersion"),
        provider_build: read_key(&provider, "CFBundleVersion"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::TempDir;

    const PLIST: &str = "<plist><dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>1.2.2</string>\n\t<key>CFBundleVersion</key>\n\t<string>41</string>\n\t<key>Flag</key>\n\t<true/>\n</dict></plist>";

    /// The versions come from the two property lists in the bundle layout the build
    /// makes; a missing file, a key that is not a string, and no executable are empty.
    #[test]
    fn reads_the_bundle_layout() {
        let dir = TempDir::new("host-info");
        let contents = dir.0.join("OFTC.app/Contents");
        let extension = contents
            .join("Library/SystemExtensions/com.example.oftc.provider.systemextension/Contents");
        fs::create_dir_all(&extension).unwrap();
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        fs::write(contents.join("Info.plist"), PLIST).unwrap();
        let exe = contents.join("MacOS/OFTCAgent");
        let block = host_block(Some(&exe), "com.example.oftc.provider");
        assert_eq!(
            (block.version.as_str(), block.build.as_str()),
            ("1.2.2", "41")
        );
        assert_eq!(block.provider_build, "");
        fs::write(extension.join("Info.plist"), PLIST.replace("41", "40")).unwrap();
        assert_eq!(
            host_block(Some(&exe), "com.example.oftc.provider").provider_build,
            "40"
        );
        assert_eq!(plist_string(PLIST, "Flag"), None);
        assert_eq!(host_block(None, "x").build, "");
    }
}
