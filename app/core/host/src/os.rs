//! The host's `unsafe` code: the terminal secret prompt, the user id, advisory file
//! locks, a liveness probe and stdio redirection. Signal handling lands here with
//! the supervisor that needs it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use zeroize::Zeroizing;

use crate::commands::SecretPrompt;
use crate::keychain::{read_psk_line, KeychainError};

/// Prompts on `/dev/tty` with echo off, so the secret never reaches the shell's
/// history, a pipe or the screen.
pub struct TtyPrompt;

/// Restores the terminal's settings when dropped.
struct EchoOff {
    fd: i32,
    original: libc::termios,
}

impl EchoOff {
    fn new(fd: i32) -> Option<EchoOff> {
        let mut original = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is an open descriptor and `original` is a valid out-pointer.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: tcgetattr succeeded, so it initialised the struct.
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        // SAFETY: `fd` is open and `hidden` is a valid termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return None;
        }
        Some(EchoOff { fd, original })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: the descriptor outlives this guard and `original` is what tcgetattr gave.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

impl SecretPrompt for TtyPrompt {
    fn read_secret(&self) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")
            .map_err(|_| KeychainError::Unavailable)?;
        let _echo = EchoOff::new(tty.as_raw_fd()).ok_or(KeychainError::Unavailable)?;
        let _ = tty.write_all(b"OFTC PSK: ");
        let psk = read_psk_line(&mut tty);
        let _ = tty.write_all(b"\n");
        psk
    }
}

/// The real user id, for `launchctl`'s `gui/<uid>` domain.
pub fn uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// Takes the exclusive advisory lock on `file` without waiting: true if this call
/// holds it. It is `flock(2)`, the lock type the Swift supervisor holds, so the two
/// exclude each other.
pub fn try_lock(file: &File) -> bool {
    // SAFETY: `file` owns an open descriptor for the whole call.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Releases a lock taken with [`try_lock`] (closing the file does too).
pub fn unlock(file: &File) {
    // SAFETY: `file` owns an open descriptor for the whole call.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

/// Whether `kill(pid, 0)` succeeds: the process exists and may be signalled. A
/// process of another user counts as gone, as the Swift status reader had it.
pub fn process_alive(pid: i32) -> bool {
    // `kill(0, 0)` and `kill(-1, 0)` address process groups and succeed.
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists; nothing is sent.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The effective user id, to check that a log file is ours.
pub fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Points this process's stdout and stderr at `file`.
pub fn redirect_stdio(file: &File) -> bool {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open for the call; `dup2` copies it onto the standard descriptors.
    unsafe { libc::dup2(fd, libc::STDOUT_FILENO) >= 0 && libc::dup2(fd, libc::STDERR_FILENO) >= 0 }
}
