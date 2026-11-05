//! The supervisor lease, the stop request and the SAML sign-in lock.
//!
//! One supervisor runs per profile. It holds an exclusive `flock` on
//! `profiles/<id>/supervisor.lock` and writes its lease id (a 36-character
//! uppercase UUID, no newline) into the file. `stop` writes that id to
//! `supervisor.stop`, which the holder honours only when it equals its own id, so a
//! stale request cannot stop a newer supervisor. Old and new builds share these
//! files while an upgrade is in progress, so the formats are the Swift ones
//! (`tests/fixtures/swift`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use crate::os;

pub(crate) const LOCK_FILE: &str = "supervisor.lock";
const STOP_FILE: &str = "supervisor.stop";

/// A fresh random version-4 UUID, uppercase and hyphenated (`UUID().uuidString`).
fn new_lease_id() -> String {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut urandom| urandom.read_exact(&mut bytes))
        .expect("/dev/urandom");
    bytes[6] = bytes[6] & 0x0F | 0x40;
    bytes[8] = bytes[8] & 0x3F | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// Whether `text` is a UUID as `UUID(uuidString:)` accepts it: 8-4-4-4-12 hex digits.
pub(crate) fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Creates `directory` (and parents) with mode 0700 if it is missing.
pub(crate) fn make_private_dir(directory: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
}

/// Replaces `directory/name` with `data` atomically, mode 0600 (what the Swift
/// `Data.write(options: .atomic)` plus `setAttributes` did).
pub(crate) fn write_private(directory: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let temporary = directory.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .and_then(|mut file| file.write_all(data))
        .and_then(|()| fs::rename(&temporary, directory.join(name)));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
        return written;
    }
    fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
}

/// Opens `path` read-write for locking, creating it 0600, never through a symlink.
pub(crate) fn open_lock_file(path: &Path, create: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Whether some process holds the lock file at `path`: it is open to us and a
/// non-blocking lock attempt fails. A free lock is released again at once.
pub(crate) fn is_held(path: &Path) -> bool {
    match open_lock_file(path, false) {
        Ok(file) => {
            if os::try_lock(&file) {
                os::unlock(&file);
                false
            } else {
                true
            }
        }
        Err(_) => false,
    }
}

/// Another supervisor holds the lease, or the files could not be used.
#[derive(Debug, PartialEq, Eq)]
pub struct LeaseUnavailable;

/// The right to supervise one profile. Dropping it releases the lock and, if the
/// lock file still holds this lease's id, removes the lock and any stop request.
pub struct SupervisorLease {
    id: String,
    lock_path: std::path::PathBuf,
    stop_path: std::path::PathBuf,
    file: Option<File>,
}

impl SupervisorLease {
    /// Takes the lease for the profile whose files are in `directory`, creating the
    /// directory if needed. Clears a stop request left for an earlier supervisor.
    pub fn acquire(directory: &Path) -> Result<SupervisorLease, LeaseUnavailable> {
        make_private_dir(directory).map_err(|_| LeaseUnavailable)?;
        let lock_path = directory.join(LOCK_FILE);
        let file = open_lock_file(&lock_path, true).map_err(|_| LeaseUnavailable)?;
        if !os::try_lock(&file) {
            return Err(LeaseUnavailable);
        }
        let mut lease = SupervisorLease {
            id: new_lease_id(),
            lock_path,
            stop_path: directory.join(STOP_FILE),
            file: Some(file),
        };
        let written = lease.file.as_mut().is_some_and(|file| {
            file.set_len(0).is_ok() && file.write_all(lease.id.as_bytes()).is_ok() && {
                file.sync_all().is_ok()
            }
        });
        if !written {
            return Err(LeaseUnavailable); // `lease` drops and releases
        }
        let _ = fs::remove_file(&lease.stop_path);
        Ok(lease)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether a `stop` named this lease.
    pub fn stop_requested(&self) -> bool {
        fs::read(&self.stop_path).is_ok_and(|bytes| bytes == self.id.as_bytes())
    }
}

impl Drop for SupervisorLease {
    fn drop(&mut self) {
        let Some(file) = self.file.take() else {
            return;
        };
        if fs::read(&self.lock_path).is_ok_and(|bytes| bytes == self.id.as_bytes()) {
            let _ = fs::remove_file(&self.lock_path);
            let _ = fs::remove_file(&self.stop_path);
        }
        os::unlock(&file);
    }
}

/// Asks the supervisor of the profile in `directory` to stop, by writing the id in
/// its lock file to the stop file. `true` when there is no lock (nothing to stop) or
/// the request was written; `false` when the lock holds something that is not a lease
/// id or the request cannot be written.
pub fn request_stop(directory: &Path) -> bool {
    let lock = directory.join(LOCK_FILE);
    if !lock.exists() {
        return true;
    }
    let Ok(bytes) = fs::read(&lock) else {
        return false;
    };
    match std::str::from_utf8(&bytes) {
        Ok(id) if is_uuid(id) => write_private(directory, STOP_FILE, id.as_bytes()).is_ok(),
        _ => false,
    }
}

/// Serialises SAML browser sign-ins across all profiles and processes: whoever holds
/// `<root>/saml.lock` is the one signing in.
pub struct SamlLock {
    file: File,
}

impl SamlLock {
    /// Waits for the lock, asking `cancelled` before each wait of `poll`. `None` when
    /// cancelled, or when the lock file cannot be opened.
    pub fn acquire(
        root: &Path,
        cancelled: &mut dyn FnMut() -> bool,
        poll: Duration,
    ) -> Option<SamlLock> {
        let _ = make_private_dir(root);
        let file = open_lock_file(&root.join("saml.lock"), true).ok()?;
        while !os::try_lock(&file) {
            if cancelled() {
                return None;
            }
            std::thread::sleep(poll);
        }
        Some(SamlLock { file })
    }
}

impl Drop for SamlLock {
    fn drop(&mut self) {
        os::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::{fixture, TempDir};
    use std::process::Command;

    /// Set in the child of [`a_lock_excludes_other_processes`]: it tries the lock on
    /// the file named by this variable and reports through its exit code.
    const HELPER: &str = "OFTC_LOCK_HELPER";

    #[test]
    fn lock_helper() {
        let Ok(path) = std::env::var(HELPER) else {
            return; // an ordinary run of the suite
        };
        let file = open_lock_file(Path::new(&path), false).unwrap();
        std::process::exit(if os::try_lock(&file) { 0 } else { 7 });
    }

    #[test]
    fn id_shape_and_uuid_check() {
        let id = new_lease_id();
        assert_eq!(id.len(), 36);
        assert!(is_uuid(&id));
        assert_eq!(id, id.to_uppercase());
        assert_eq!(&id[14..15], "4"); // version 4
        assert_ne!(id, new_lease_id());
        for (text, want) in [
            ("00000000-0000-0000-0000-000000000000", true),
            ("abcdefAB-cdef-ABCD-efab-cdefabcdefab", true),
            ("00000000-0000-0000-0000-00000000000", false),
            ("00000000-0000-0000-0000-00000000000g", false),
            ("00000000000000000000000000000000", false),
            ("00000000-0000-0000-0000-000000000000\n", false),
            ("", false),
        ] {
            assert_eq!(is_uuid(text), want, "{text:?}");
        }
    }

    /// Everything `check-supervisor.swift` asserted about the lease, plus the
    /// file shapes the Swift code writes.
    #[test]
    fn lifecycle() {
        let dir = TempDir::new("lease");
        let directory = dir.0.join("nested/profile");
        let lease = SupervisorLease::acquire(&directory).unwrap();
        let lock = directory.join(LOCK_FILE);
        // The lock holds the id, nothing else, and is private.
        assert_eq!(fs::read_to_string(&lock).unwrap(), lease.id());
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!lease.stop_requested());
        // A second supervisor is refused, and does not disturb the first.
        assert_eq!(
            SupervisorLease::acquire(&directory).err(),
            Some(LeaseUnavailable)
        );
        assert_eq!(fs::read_to_string(&lock).unwrap(), lease.id());
        // `stop` names this lease.
        assert!(request_stop(&directory));
        assert!(lease.stop_requested());
        assert_eq!(
            fs::metadata(directory.join(STOP_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Releasing removes both files; the next lease starts clean.
        let first = lease.id().to_owned();
        drop(lease);
        assert!(!lock.exists() && !directory.join(STOP_FILE).exists());
        let replacement = SupervisorLease::acquire(&directory).unwrap();
        assert_ne!(replacement.id(), first);
        assert!(!replacement.stop_requested());
        // A stop request left behind by an earlier supervisor is cleared, and one for
        // another id is not honoured.
        drop(replacement);
        fs::write(directory.join(STOP_FILE), &first).unwrap();
        let third = SupervisorLease::acquire(&directory).unwrap();
        assert!(!directory.join(STOP_FILE).exists());
        fs::write(directory.join(STOP_FILE), &first).unwrap();
        assert!(!third.stop_requested());
        // A lock another process replaced is left alone on release.
        let other = "11111111-2222-4333-8444-555555555555";
        fs::write(&lock, other).unwrap();
        drop(third);
        assert_eq!(fs::read_to_string(&lock).unwrap(), other);
    }

    #[test]
    fn request_stop_rows() {
        // (lock file contents, expected result, stop file written)
        let rows: [(Option<&[u8]>, bool, bool); 5] = [
            (None, true, false),
            (Some(b"11111111-2222-4333-8444-555555555555"), true, true),
            (Some(b"broken"), false, false),
            (
                Some(b"11111111-2222-4333-8444-555555555555\n"),
                false,
                false,
            ),
            (Some(&[0xFF, 0xFE]), false, false),
        ];
        for (lock, want, written) in rows {
            let dir = TempDir::new("stop");
            if let Some(bytes) = lock {
                fs::write(dir.0.join(LOCK_FILE), bytes).unwrap();
            }
            assert_eq!(request_stop(&dir.0), want, "{lock:?}");
            assert_eq!(dir.0.join(STOP_FILE).exists(), written, "{lock:?}");
        }
    }

    /// A lock file the Swift supervisor wrote: `request_stop` reads its id and writes
    /// the same bytes, which is what the Swift `stopRequested` compares.
    #[test]
    fn stops_a_lease_the_swift_supervisor_holds() {
        let dir = TempDir::new("swift-lock");
        let swift = fs::read(fixture("swift/supervisor/supervisor.lock")).unwrap();
        assert_eq!(swift.len(), 36);
        assert!(is_uuid(std::str::from_utf8(&swift).unwrap()));
        assert_eq!(swift, swift.to_ascii_uppercase()); // `uuidString` is uppercase
        fs::write(dir.0.join(LOCK_FILE), &swift).unwrap();
        assert!(request_stop(&dir.0));
        assert_eq!(fs::read(dir.0.join(STOP_FILE)).unwrap(), swift);
        assert_eq!(
            fs::read(fixture("swift/supervisor/supervisor.stop")).unwrap(),
            swift
        );
    }

    /// `flock` is per open file description: only another process shows that the
    /// lease excludes a supervisor started elsewhere, as the Swift one is.
    #[test]
    fn a_lock_excludes_other_processes() {
        let dir = TempDir::new("cross");
        let lease = SupervisorLease::acquire(&dir.0).unwrap();
        let run = || {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "lease::tests::lock_helper", "--nocapture"])
                .env(HELPER, dir.0.join(LOCK_FILE))
                .status()
                .unwrap()
                .code()
        };
        assert_eq!(run(), Some(7), "the helper must not get the held lock");
        assert!(is_held(&dir.0.join(LOCK_FILE)));
        drop(lease);
        fs::write(dir.0.join(LOCK_FILE), "").unwrap();
        assert_eq!(run(), Some(0), "the helper takes a free lock");
        assert!(!is_held(&dir.0.join(LOCK_FILE)));
    }

    #[test]
    fn saml_lock_queues_until_released_or_cancelled() {
        let dir = TempDir::new("saml");
        let poll = Duration::from_millis(5);
        let held = SamlLock::acquire(&dir.0, &mut || false, poll).unwrap();
        let mut polls = 0;
        let blocked = SamlLock::acquire(
            &dir.0,
            &mut || {
                polls += 1;
                polls >= 2
            },
            poll,
        );
        assert!(blocked.is_none());
        assert_eq!(polls, 2);
        drop(held);
        assert!(SamlLock::acquire(&dir.0, &mut || false, poll).is_some());
        // The shared lock file is empty and private.
        let meta = fs::metadata(dir.0.join("saml.lock")).unwrap();
        assert_eq!((meta.len(), meta.permissions().mode() & 0o777), (0, 0o600));
    }
}
