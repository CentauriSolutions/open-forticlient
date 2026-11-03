//! Timestamped stderr logging for the long-running `connect` path. Under the
//! LaunchAgent stderr is the log file, and without timestamps a drop can't be
//! lined up against fctctl.log or `log show --predicate 'process=="iked"'`.
//! Local time with offset, matching fctctl.log's "TZ=-0700" style.

use std::time::{SystemTime, UNIX_EPOCH};

/// `struct tm` from <time.h> on macOS (libSystem).
#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const u8,
}

extern "C" {
    fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
}

/// Local wall-clock time of a Unix timestamp, e.g. "2026-10-07 07:47:49 -0700".
pub fn local_time(secs: i64) -> String {
    let mut tm = Tm {
        tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
        tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: std::ptr::null(),
    };
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    if unsafe { localtime_r(&secs, &mut tm) }.is_null() {
        return format!("@{secs}");
    }
    let off = tm.tm_gmtoff / 60;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}{:02}{:02}",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        if off < 0 { '-' } else { '+' }, off.abs() / 60, off.abs() % 60,
    )
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `eprintln!` with a local timestamp prefix.
macro_rules! log {
    ($($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::log::local_time($crate::log::now_secs()), format_args!($($arg)*))
    };
}
pub(crate) use log;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_local_time() {
        let s = local_time(0);
        // "YYYY-MM-DD HH:MM:SS ±HHMM" in whatever zone the test runs in.
        assert_eq!(s.len(), 25, "{s}");
        assert!(s.starts_with("1969-12-31") || s.starts_with("1970-01-01"), "{s}");
    }
}
