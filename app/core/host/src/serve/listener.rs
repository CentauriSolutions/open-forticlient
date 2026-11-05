//! The socket and its single-instance lock (`docs/ui-edge.md`, section 3).
//!
//! `<root>/host.lock` is held with `flock` for as long as the server runs; only the
//! holder unlinks and binds `<root>/host.sock`, so a stale socket from a crash is
//! replaced and a live server is never displaced. The directory is the host's
//! per-user directory (0700); the socket is 0600.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::lease::{make_private_dir, open_lock_file};
use crate::os;

pub const LOCK_FILE: &str = "host.lock";
pub const SOCKET_FILE: &str = "host.sock";
/// `sun_path` holds 104 bytes including its NUL.
const MAX_PATH: usize = 103;

#[derive(Debug)]
pub enum StartError {
    /// Another server holds the lock: this one has nothing to do.
    AlreadyRunning,
    /// The socket path does not fit `sun_path`; it is never truncated.
    PathTooLong,
    /// The directory, lock or socket could not be made safe or used.
    Unusable(&'static str),
}

/// The bound socket and the lock that entitles this process to it. Dropping it
/// removes the socket and releases the lock.
pub struct Bound {
    pub listener: UnixListener,
    socket: PathBuf,
    _lock: File,
}

impl Drop for Bound {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}

pub fn socket_path(root: &Path) -> PathBuf {
    root.join(SOCKET_FILE)
}

/// Takes the lock and binds a fresh non-blocking listener at `<root>/host.sock`.
pub fn bind(root: &Path) -> Result<Bound, StartError> {
    let socket = socket_path(root);
    if socket.as_os_str().len() > MAX_PATH {
        return Err(StartError::PathTooLong);
    }
    make_private_dir(root).map_err(|_| StartError::Unusable("cannot create the directory"))?;
    secure_directory(root)?;
    let lock = open_lock_file(&root.join(LOCK_FILE), true)
        .map_err(|_| StartError::Unusable("cannot open the lock file"))?;
    if !os::try_lock(&lock) {
        return Err(StartError::AlreadyRunning);
    }
    // Holding the lock: whatever sits at the socket path is a leftover.
    match fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&socket)
            .map_err(|_| StartError::Unusable("cannot remove the stale socket"))?,
        Ok(_) => return Err(StartError::Unusable("the socket path holds something else")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(StartError::Unusable("cannot inspect the socket path")),
    }
    let listener =
        UnixListener::bind(&socket).map_err(|_| StartError::Unusable("cannot bind the socket"))?;
    // The directory already keeps everyone else out; this makes the socket itself 0600.
    let bound = Bound {
        listener,
        socket: socket.clone(),
        _lock: lock,
    };
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|_| StartError::Unusable("cannot restrict the socket"))?;
    bound
        .listener
        .set_nonblocking(true)
        .map_err(|_| StartError::Unusable("cannot poll the socket"))?;
    Ok(bound)
}

/// The directory must be ours and closed to everyone else. A mode that was loosened is
/// put back; a directory of another user is refused.
fn secure_directory(root: &Path) -> Result<(), StartError> {
    let meta =
        fs::metadata(root).map_err(|_| StartError::Unusable("cannot inspect the directory"))?;
    if meta.uid() != os::euid() {
        return Err(StartError::Unusable(
            "the directory belongs to another user",
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|_| StartError::Unusable("cannot restrict the directory"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::testutil::TempDir;
    use std::os::unix::net::UnixStream;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A fresh start makes a 0600 socket in a 0700 directory, and takes both with it
    /// when it ends.
    #[test]
    fn binds_privately_and_cleans_up() {
        let dir = TempDir::new("listener");
        let root = dir.0.join("app");
        let bound = bind(&root).unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&socket_path(&root)), 0o600);
        assert_eq!(mode(&root.join(LOCK_FILE)), 0o600);
        drop(bound);
        assert!(!socket_path(&root).exists());
    }

    /// A second server does not displace the first: it is refused and the first stays
    /// connectable. After the first ends, the lock is free again.
    #[test]
    fn a_live_server_is_never_displaced() {
        let dir = TempDir::new("listener-live");
        let first = bind(&dir.0).unwrap();
        assert!(matches!(bind(&dir.0), Err(StartError::AlreadyRunning)));
        UnixStream::connect(socket_path(&dir.0)).unwrap();
        drop(first);
        assert!(bind(&dir.0).is_ok());
    }

    /// A socket left by a crashed server (its file, no listener, no lock) is replaced.
    #[test]
    fn a_stale_socket_is_taken_over() {
        let dir = TempDir::new("listener-stale");
        let socket = socket_path(&dir.0);
        let dead = UnixListener::bind(&socket).unwrap();
        // The crash: the process is gone and the file stays (closing a listener does
        // not unlink its path).
        drop(dead);
        assert!(socket.exists());
        assert_eq!(
            UnixStream::connect(&socket).unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        let bound = bind(&dir.0).unwrap();
        UnixStream::connect(&socket).unwrap();
        drop(bound);
    }

    /// Only a socket is replaced: a regular file at the path is somebody's data, and a
    /// directory more open than 0700 is closed again rather than trusted.
    #[test]
    fn refuses_what_is_not_a_leftover_socket_and_closes_a_loose_directory() {
        let dir = TempDir::new("listener-other");
        fs::write(socket_path(&dir.0), "data").unwrap();
        assert!(matches!(bind(&dir.0), Err(StartError::Unusable(_))));
        assert_eq!(fs::read_to_string(socket_path(&dir.0)).unwrap(), "data");
        fs::remove_file(socket_path(&dir.0)).unwrap();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let bound = bind(&dir.0).unwrap();
        assert_eq!(mode(&dir.0), 0o700);
        drop(bound);
    }

    /// The path limit is `sun_path`'s 104 bytes with its NUL: 103 fit, 104 fail closed
    /// before anything is created.
    #[test]
    fn path_length_fails_closed_at_104_bytes() {
        let dir = TempDir::new("listener-long");
        // A directory name that makes the socket path exactly `total` bytes.
        let with_length = |total: usize| {
            let name = total - dir.0.as_os_str().len() - 2 - SOCKET_FILE.len();
            dir.0.join("d".repeat(name))
        };
        let ok = with_length(MAX_PATH);
        let too_long = with_length(MAX_PATH + 1);
        assert_eq!(socket_path(&ok).as_os_str().len(), MAX_PATH);
        assert_eq!(socket_path(&too_long).as_os_str().len(), MAX_PATH + 1);
        assert!(bind(&ok).is_ok());
        assert!(matches!(bind(&too_long), Err(StartError::PathTooLong)));
        assert!(!too_long.exists());
    }
}
