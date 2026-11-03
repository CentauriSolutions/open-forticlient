//! Give the dylib the install name the app bundle expects.
fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/liboftc_host_bootstrap.dylib");
}
