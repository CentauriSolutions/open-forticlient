//! Stable EAP/SAML device identity derived from the Mac platform UUID.
use std::process::Command;

pub fn platform_uid() -> Option<String> {
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output().ok()?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains("IOPlatformUUID") {
            let uuid = line.split('"').nth(3)?;
            let uid: String = uuid.chars().filter(|c| *c != '-').collect();
            if !uid.is_empty() { return Some(uid.to_uppercase()); }
        }
    }
    None
}
