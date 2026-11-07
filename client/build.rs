// The version `oftc --version` prints and the client's hello carries come from the app's own
// Info.plist (CFBundleShortVersionString and CFBundleVersion), the single place a release number
// is edited, so the command line, About, the status document and the package cannot disagree.
// app/check-version-parity.sh compares the built binary with the packaged plist.
use std::{env, fs, path::Path};

fn plist_string(text: &str, key: &str) -> Option<String> {
    let after = &text[text.find(&format!("<key>{key}</key>"))? + key.len() + 11..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")? + start;
    Some(after[start..end].trim().to_owned())
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let plist = Path::new(&manifest).join("../app/Host/Info.plist");
    println!("cargo:rerun-if-changed={}", plist.display());
    let text = fs::read_to_string(&plist)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", plist.display()));
    for (key, variable) in [
        ("CFBundleShortVersionString", "OFTC_APP_VERSION"),
        ("CFBundleVersion", "OFTC_APP_BUILD"),
    ] {
        let value = plist_string(&text, key)
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
            .unwrap_or_else(|| panic!("{} has no numeric {key}", plist.display()));
        println!("cargo:rustc-env={variable}={value}");
    }
}
