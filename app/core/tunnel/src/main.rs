//! The `OFTCTunnel` system extension executable: hands the process to
//! NetworkExtension with the engine-backed provider logic.

#[cfg(target_os = "macos")]
fn main() {
    oftc_apple::run(oftc_provider::link::SessionBackend)
}

/// The extension exists only on macOS; this keeps the workspace buildable
/// elsewhere.
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("OFTCTunnel runs only on macOS");
    std::process::exit(1);
}
