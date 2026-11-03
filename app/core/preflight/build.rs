//! Give the dylib the install name and rpath the app bundle expects.
fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/liboftc_preflight.dylib");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-rpath,@loader_path");
}
