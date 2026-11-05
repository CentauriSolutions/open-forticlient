//! The host's `unsafe` code: the terminal secret prompt and the user id. The
//! file-lock, signal and process calls land here with the supervisor.

use std::fs::OpenOptions;
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
