//! Command-line interface for the OFTC macOS app and packet-tunnel provider.
mod commands;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        &[][..]
    } else {
        &args[..]
    };
    if let Err(error) = commands::run(args) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
