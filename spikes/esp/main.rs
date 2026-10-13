#![allow(dead_code)] // Small release caller links the full ESP codec under test.
mod esp;
use esp::{InboundSa, Keys, OutboundSa, SystemCrypto, Udp4500};

fn keys() -> Keys {
    Keys {
        encryption: [0x11; 32],
        integrity: [0x22; 20],
    }
}

fn main() {
    // Synthetic, public data. No gateway, interface, profile, or credentials.
    let mut ip = [0u8; 40];
    ip[0] = 0x60;
    let mut sender = OutboundSa::new(0x12345678, keys(), SystemCrypto).unwrap();
    let mut receiver = InboundSa::new(0x12345678, keys(), SystemCrypto).unwrap();
    let esp = sender.seal(&ip).unwrap();
    assert_eq!(esp::classify_udp4500(&esp), Ok(Udp4500::Esp(&esp)));
    assert_eq!(receiver.open(&esp).unwrap(), ip);
    println!("offline ESP release round trip passed");
}
