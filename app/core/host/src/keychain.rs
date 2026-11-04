//! PSK storage: a generic-password Keychain item per gateway.
//!
//! Existing items must keep working, so the item shape is exactly what the Swift
//! host used: class generic password, service `<bundle id>.psk`, account = the
//! gateway name, and nothing else (no label, access group or accessibility).

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::Mutex;

use zeroize::Zeroizing;

/// A PSK is 1 to 1024 bytes of UTF-8 without NUL.
pub const PSK_MAX: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainError {
    /// No item, or one whose data is not a valid PSK length.
    Unavailable,
    /// The Keychain refused the write or delete.
    Failed,
}

pub trait Keychain: Send + Sync {
    fn get(&self, gateway: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError>;
    /// Adds the item, or replaces its data when it exists.
    fn set(&self, gateway: &str, psk: &[u8]) -> Result<(), KeychainError>;
    /// Removing an item that is not there succeeds.
    fn delete(&self, gateway: &str) -> Result<(), KeychainError>;
}

/// The in-memory stand-in for tests and for other platforms.
#[derive(Default)]
pub struct MemoryKeychain(Mutex<HashMap<String, Vec<u8>>>);

impl Keychain for MemoryKeychain {
    fn get(&self, gateway: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        match self.0.lock().unwrap().get(gateway) {
            Some(psk) if (1..=PSK_MAX).contains(&psk.len()) => Ok(Zeroizing::new(psk.clone())),
            _ => Err(KeychainError::Unavailable),
        }
    }

    fn set(&self, gateway: &str, psk: &[u8]) -> Result<(), KeychainError> {
        self.0
            .lock()
            .unwrap()
            .insert(gateway.to_owned(), psk.to_vec());
        Ok(())
    }

    fn delete(&self, gateway: &str) -> Result<(), KeychainError> {
        self.0.lock().unwrap().remove(gateway);
        Ok(())
    }
}

/// Reads one PSK line: bytes up to LF, CR or end of input. The line must be 1 to
/// [`PSK_MAX`] bytes of UTF-8 with no NUL. Shared by the terminal prompt and
/// `provision-psk --stdin`, so both accept exactly the same secrets.
pub fn read_psk_line(reader: &mut dyn Read) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    while bytes.len() <= PSK_MAX {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => break,
            Ok(_) => bytes.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(KeychainError::Unavailable),
        }
    }
    if (1..=PSK_MAX).contains(&bytes.len())
        && !bytes.contains(&0)
        && std::str::from_utf8(&bytes).is_ok()
    {
        Ok(bytes)
    } else {
        Err(KeychainError::Unavailable)
    }
}

#[cfg(target_os = "macos")]
pub use sec::SecKeychain;

#[cfg(target_os = "macos")]
mod sec {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    /// `errSecItemNotFound`.
    const ITEM_NOT_FOUND: i32 = -25300;

    /// The login Keychain through Security.framework's generic-password calls,
    /// which add `(class, service, account, data)` and update only the data.
    pub struct SecKeychain {
        service: String,
    }

    impl SecKeychain {
        pub fn new(service: &str) -> SecKeychain {
            SecKeychain {
                service: service.to_owned(),
            }
        }
    }

    impl Keychain for SecKeychain {
        fn get(&self, gateway: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
            let data = Zeroizing::new(
                get_generic_password(&self.service, gateway)
                    .map_err(|_| KeychainError::Unavailable)?,
            );
            if (1..=PSK_MAX).contains(&data.len()) {
                Ok(data)
            } else {
                Err(KeychainError::Unavailable)
            }
        }

        fn set(&self, gateway: &str, psk: &[u8]) -> Result<(), KeychainError> {
            set_generic_password(&self.service, gateway, psk).map_err(|_| KeychainError::Failed)
        }

        fn delete(&self, gateway: &str) -> Result<(), KeychainError> {
            match delete_generic_password(&self.service, gateway) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(()),
                Err(_) => Err(KeychainError::Failed),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::process::Command;

        /// A throwaway service whose item is deleted when the test ends. Deleting
        /// through the backend, not `security(1)`: an item is only prompt-free for
        /// the binary that created it.
        struct Scratch(SecKeychain, &'static str);

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = self.0.delete(self.1);
            }
        }

        /// What `security` prints about an item without its data (no ACL prompt).
        fn attributes(service: &str, account: &str) -> Option<String> {
            let out = Command::new("/usr/bin/security")
                .args(["find-generic-password", "-s", service, "-a", account])
                .output()
                .unwrap();
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        }

        /// Format 11: add, update, read, delete, and the item's identity. The data is
        /// never read back through `security(1)`: reading an item another binary
        /// created needs the user to click an access prompt, which CI cannot do.
        /// The item shape is checked from its attributes instead.
        #[test]
        fn item_roundtrip_and_attributes() {
            let service = format!("com.example.oftc-test.roundtrip.{}.psk", std::process::id());
            let account = "vpn.example.com";
            let scratch = Scratch(SecKeychain::new(&service), account);
            let kc = &scratch.0;

            assert_eq!(kc.get(account), Err(KeychainError::Unavailable));
            kc.set(account, b"first-secret").unwrap();
            let shown = attributes(&service, account).expect("item is visible to security(1)");
            assert!(shown.contains("class: \"genp\""), "{shown}");
            assert!(
                shown.contains(&format!("\"svce\"<blob>=\"{service}\"")),
                "{shown}"
            );
            assert!(
                shown.contains("\"acct\"<blob>=\"vpn.example.com\""),
                "{shown}"
            );
            assert_eq!(kc.get(account).unwrap().as_slice(), b"first-secret");

            kc.set(account, b"second-secret").unwrap(); // update, not a second item
            assert_eq!(kc.get(account).unwrap().as_slice(), b"second-secret");

            // Data outside 1..=1024 bytes is not a PSK.
            kc.set(account, &vec![b'x'; PSK_MAX + 1]).unwrap();
            assert_eq!(kc.get(account), Err(KeychainError::Unavailable));

            kc.delete(account).unwrap();
            assert!(attributes(&service, account).is_none());
            kc.delete(account).unwrap(); // already gone
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(input: &[u8]) -> Result<Vec<u8>, KeychainError> {
        read_psk_line(&mut &input[..]).map(|psk| psk.to_vec())
    }

    #[test]
    fn psk_line_table() {
        assert_eq!(line(b"secret\n").unwrap(), b"secret");
        assert_eq!(line(b"secret\r\nignored").unwrap(), b"secret"); // first line only
        assert_eq!(line(b"no-newline").unwrap(), b"no-newline");
        assert_eq!(line(&[b'k'; PSK_MAX]).unwrap().len(), PSK_MAX);
        for bad in [
            &b""[..],
            b"\n",
            &vec![b'k'; PSK_MAX + 1],
            b"nul\0byte",
            &[0xff, 0xfe],
        ] {
            assert_eq!(line(bad), Err(KeychainError::Unavailable), "{bad:?}");
        }
    }
}
