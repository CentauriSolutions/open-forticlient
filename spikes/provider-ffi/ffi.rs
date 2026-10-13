//! Opaque C ABI for the provider-owned Rust UDP/TCP Session. No secrets, keys,
//! raw IKE packets, or ESP SA state are exported to Swift.
#![allow(dead_code)] // The imported session also contains offline spike APIs.
extern crate oftc_session as session;

use std::net::{IpAddr, Ipv4Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const FRESH: u8 = 0;
const CONNECTING: u8 = 1;
const CONNECTED: u8 = 2;
const CLOSED: u8 = 3;
const MAX_GATEWAY: usize = 253;
const MAX_UID: usize = 32;
const MAX_PSK: usize = 1024;
const MAX_TOKEN: usize = 16 * 1024;
const MAX_INNER_PACKET: usize = 65_535;

pub const OK: i32 = 0;
pub const BAD_ARGUMENT: i32 = 1;
pub const NOT_CONNECTED: i32 = 2;
pub const BUSY: i32 = 3;
pub const CANCELLED: i32 = 4;
pub const BUFFER_TOO_SMALL: i32 = 5;
pub const CLOSED_HANDLE: i32 = 6;
pub const INTERNAL: i32 = 7;
pub const PACKET_DROPPED: i32 = 8;
pub const RECONNECT_NEEDED: i32 = 9;
pub const SESSION_ERROR_BASE: i32 = 100;

pub const EVENT_IP_PACKET: u32 = 1;
pub const EVENT_PEER_DPD: u32 = 2;
pub const EVENT_PEER_DELETED_CHILD: u32 = 3;
pub const EVENT_PEER_DELETED_IKE: u32 = 4;
pub const EVENT_NAT_KEEPALIVE: u32 = 5;
pub const EVENT_REJECTED: u32 = 6;
pub const EVENT_TIMEOUT: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OftcSettings {
    pub version: u32,
    pub assigned_ipv4: [u8; 4],
    pub netmask: [u8; 4],
    pub outer_remote_family: u32,
    pub outer_remote: [u8; 16],
    pub inner_mtu: u32,
    pub route_count: u32,
    pub dns_server_count: u32,
    pub dns_domain_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OftcConnectMode {
    pub transport: u32,
    pub outer_family: u32,
    pub idi_v4: [u8; 4],
    pub tcp_fallback: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OftcRekeyCounts {
    pub local: u32,
    pub peer: u32,
    pub ike: u32,
}

fn connect_options(mode: OftcConnectMode) -> Result<session::transport::ConnectOptions, i32> {
    use session::transport::{ConnectOptions, OuterFamily, Wire};
    let wire = match mode.transport {
        1 => Wire::Udp4500,
        2 => Wire::Tcp4443,
        _ => return Err(BAD_ARGUMENT),
    };
    let family = match mode.outer_family {
        4 => OuterFamily::Ipv4,
        6 => OuterFamily::Ipv6,
        _ => return Err(BAD_ARGUMENT),
    };
    if mode.tcp_fallback > 1 || (wire == Wire::Tcp4443 && mode.tcp_fallback != 0) {
        return Err(BAD_ARGUMENT);
    }
    let idi_v4 = if family == OuterFamily::Ipv6 {
        Some(Ipv4Addr::from(mode.idi_v4))
    } else {
        if mode.idi_v4 != [0; 4] { return Err(BAD_ARGUMENT); }
        None
    };
    let options = ConnectOptions { wire, family, idi_v4,
        tcp_fallback: mode.tcp_fallback != 0 };
    options.validate().map_err(|_| BAD_ARGUMENT)?;
    Ok(options)
}

fn outer_address(ip: IpAddr) -> (u32, [u8; 16]) {
    match ip {
        IpAddr::V4(address) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&address.octets());
            (4, bytes)
        }
        IpAddr::V6(address) => (6, address.octets()),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OftcRoute {
    /// 4 for IPv4 or 6 for IPv6; IPv4 occupies the first four bytes.
    pub family: u32,
    pub first: [u8; 16],
    pub last: [u8; 16],
}

struct Inner {
    session: Option<session::Session>,
    pending_ip: Option<Vec<u8>>,
}

/// Every FFI call requires a live retained pointer. The Swift owner must join
/// work using the pointer before releasing its final reference.
pub struct OftcHandle {
    cancel: session::Cancellation,
    phase: AtomicU8,
    inner: Mutex<Inner>,
}

struct CloseIfConnecting<'a>(&'a AtomicU8);
impl Drop for CloseIfConnecting<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .compare_exchange(CONNECTING, CLOSED, Ordering::SeqCst, Ordering::SeqCst);
    }
}

fn mapped(error: session::Error) -> i32 {
    use session::Error;
    match error {
        Error::Cancelled => CANCELLED,
        Error::InvalidInput => BAD_ARGUMENT,
        Error::Resolve => SESSION_ERROR_BASE,
        Error::Socket => SESSION_ERROR_BASE + 1,
        Error::Timeout(_) => SESSION_ERROR_BASE + 2,
        Error::SaInit => SESSION_ERROR_BASE + 3,
        Error::ResponderAuth => SESSION_ERROR_BASE + 4,
        Error::EapChallenge => SESSION_ERROR_BASE + 5,
        Error::EapRejected => SESSION_ERROR_BASE + 6,
        Error::EapVerification => SESSION_ERROR_BASE + 7,
        Error::FinalAuth => SESSION_ERROR_BASE + 8,
        Error::ChildSa => SESSION_ERROR_BASE + 9,
        Error::Esp => SESSION_ERROR_BASE + 10,
        Error::PacketDropped => PACKET_DROPPED,
        Error::Control => SESSION_ERROR_BASE + 11,
        Error::Inactive => SESSION_ERROR_BASE + 12,
        Error::ReconnectNeeded => RECONNECT_NEEDED,
        Error::Rekey(stage) => {
            use session::RekeyStage;
            match stage {
                RekeyStage::LocalOffer => 120,
                RekeyStage::NoResponse => 121,
                RekeyStage::PeerNoProposal => 122,
                RekeyStage::PeerInvalidKe => 123,
                RekeyStage::PeerNoAdditionalSas => 124,
                RekeyStage::PeerTsUnacceptable => 125,
                RekeyStage::PeerOtherNotify => 126,
                RekeyStage::ResponseMalformed => 127,
                RekeyStage::ResponseSuite => 128,
                RekeyStage::ResponseSelectors => 129,
                RekeyStage::Keymat => 130,
                RekeyStage::Install => 131,
                RekeyStage::OldDelete => 132,
            }
        }
    }
}

fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(INTERNAL)
}

fn lock_inner(handle: &OftcHandle) -> Result<std::sync::MutexGuard<'_, Inner>, i32> {
    handle.inner.lock().map_err(|_| INTERNAL)
}

unsafe fn text_arg<'a>(ptr: *const u8, len: usize, max: usize) -> Result<&'a str, i32> {
    if ptr.is_null() || len == 0 || len > max {
        return Err(BAD_ARGUMENT);
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).map_err(|_| BAD_ARGUMENT)
}

unsafe fn byte_arg<'a>(ptr: *const u8, len: usize, max: usize) -> Result<&'a [u8], i32> {
    if ptr.is_null() || len == 0 || len > max {
        return Err(BAD_ARGUMENT);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn copy_bytes(src: &[u8], out: *mut u8, capacity: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return BAD_ARGUMENT;
    }
    unsafe {
        *out_len = src.len();
    }
    if capacity < src.len() {
        return BUFFER_TOO_SMALL;
    }
    if !src.is_empty() && out.is_null() {
        return BAD_ARGUMENT;
    }
    if !src.is_empty() {
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
        }
    }
    OK
}

/// Create one handle. A connect attempt consumes it; create a new handle for
/// another token-bearing attempt. The pointer starts with one owned reference.
#[no_mangle]
pub extern "C" fn oftc_handle_new() -> *mut OftcHandle {
    catch_unwind(|| {
        Arc::into_raw(Arc::new(OftcHandle {
            cancel: session::Cancellation::default(),
            phase: AtomicU8::new(FRESH),
            inner: Mutex::new(Inner {
                session: None,
                pending_ip: None,
            }),
        })) as *mut OftcHandle
    })
    .unwrap_or(ptr::null_mut())
}

/// Retain before passing the pointer to another queue/thread. The caller must
/// already own a live reference when calling this function.
#[no_mangle]
pub unsafe extern "C" fn oftc_handle_retain(handle: *mut OftcHandle) -> *mut OftcHandle {
    if handle.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        Arc::increment_strong_count(handle);
    }
    handle
}

/// Release one reference. Never use a pointer after releasing its last ref.
#[no_mangle]
pub unsafe extern "C" fn oftc_handle_release(handle: *mut OftcHandle) {
    if !handle.is_null() {
        unsafe {
            Arc::decrement_strong_count(handle);
        }
    }
}

/// Set the atomic cancellation flag. Safe to call while connect/receive is
/// blocked on another retained reference; receive checks it within 250 ms.
#[no_mangle]
pub unsafe extern "C" fn oftc_cancel(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        handle.cancel.cancel();
        OK
    })
}

/// Blocking one-shot connect. All inputs are length-delimited UTF-8, copied
/// into a ConnectInput; PSK and token copies are wiped by that type on drop.
/// The caller must keep its buffers alive until this function returns and
/// erase its own PSK/token buffers separately.
#[no_mangle]
pub unsafe extern "C" fn oftc_connect(
    handle: *mut OftcHandle,
    gateway: *const u8,
    gateway_len: usize,
    uid: *const u8,
    uid_len: usize,
    psk: *const u8,
    psk_len: usize,
    token: *const u8,
    token_len: usize,
) -> i32 {
    unsafe { connect_inner(handle, gateway, gateway_len, uid, uid_len,
        psk, psk_len, token, token_len, session::transport::ConnectOptions::default()) }
}

#[no_mangle]
pub unsafe extern "C" fn oftc_connect_mode(
    handle: *mut OftcHandle,
    gateway: *const u8,
    gateway_len: usize,
    uid: *const u8,
    uid_len: usize,
    psk: *const u8,
    psk_len: usize,
    token: *const u8,
    token_len: usize,
    mode: *const OftcConnectMode,
) -> i32 {
    let Some(mode) = (unsafe { mode.as_ref() }) else { return BAD_ARGUMENT; };
    let Ok(options) = connect_options(*mode) else { return BAD_ARGUMENT; };
    unsafe { connect_inner(handle, gateway, gateway_len, uid, uid_len,
        psk, psk_len, token, token_len, options) }
}

unsafe fn connect_inner(
    handle: *mut OftcHandle,
    gateway: *const u8,
    gateway_len: usize,
    uid: *const u8,
    uid_len: usize,
    psk: *const u8,
    psk_len: usize,
    token: *const u8,
    token_len: usize,
    options: session::transport::ConnectOptions,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        if handle
            .phase
            .compare_exchange(FRESH, CONNECTING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return if handle.phase.load(Ordering::SeqCst) == CLOSED {
                CLOSED_HANDLE
            } else {
                BUSY
            };
        }
        let _close_on_panic = CloseIfConnecting(&handle.phase);
        let result = (|| {
            let gateway = unsafe { text_arg(gateway, gateway_len, MAX_GATEWAY) }?;
            let uid = unsafe { text_arg(uid, uid_len, MAX_UID) }?;
            let psk = unsafe { text_arg(psk, psk_len, MAX_PSK) }?;
            let token = unsafe { text_arg(token, token_len, MAX_TOKEN) }?;
            if uid.len() != 32
                || !uid.bytes().all(|b| b.is_ascii_hexdigit())
                || gateway.as_bytes().contains(&0)
            {
                return Err(BAD_ARGUMENT);
            }
            let input = session::ConnectInput {
                gateway: gateway.to_owned(),
                uid: uid.to_owned(),
                psk: psk.to_owned(),
                tokenid: token.to_owned(),
            };
            let session = session::Session::connect_with_options(
                input, handle.cancel.clone(), options).map_err(mapped)?;
            let mut inner = lock_inner(handle)?;
            inner.session = Some(session);
            Ok(())
        })();
        handle.phase.store(
            if result.is_ok() { CONNECTED } else { CLOSED },
            Ordering::SeqCst,
        );
        result.map_or_else(|code| code, |_| OK)
    })
}

/// Copy plain network settings; keys and SA state stay inside Rust.
#[no_mangle]
pub unsafe extern "C" fn oftc_settings(handle: *mut OftcHandle, out: *mut OftcSettings) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let Some(out) = (unsafe { out.as_mut() }) else {
            return BAD_ARGUMENT;
        };
        if handle.phase.load(Ordering::SeqCst) != CONNECTED {
            return NOT_CONNECTED;
        }
        let inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_ref() else {
            return NOT_CONNECTED;
        };
        let settings = s.settings();
        let Ok(route_count) = u32::try_from(settings.split_routes.len()) else {
            return INTERNAL;
        };
        let Ok(dns_server_count) = u32::try_from(settings.dns_servers.len()) else {
            return INTERNAL;
        };
        let Ok(dns_domain_count) = u32::try_from(settings.dns_domains.len()) else {
            return INTERNAL;
        };
        let Ok(inner_mtu) = u32::try_from(settings.inner_mtu) else {
            return INTERNAL;
        };
        let (outer_remote_family, outer_remote) = outer_address(settings.outer_remote_ip);
        *out = OftcSettings {
            version: 2,
            assigned_ipv4: settings.assigned_ipv4.octets(),
            netmask: settings.interface_mask().octets(),
            outer_remote_family,
            outer_remote,
            inner_mtu,
            route_count,
            dns_server_count,
            dns_domain_count,
        };
        OK
    })
}

fn range_ip(first: IpAddr, last: IpAddr) -> Result<OftcRoute, i32> {
    let mut range = OftcRoute::default();
    match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            range.family = 4;
            range.first[..4].copy_from_slice(&a.octets());
            range.last[..4].copy_from_slice(&b.octets());
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            range.family = 6;
            range.first = a.octets();
            range.last = b.octets();
        }
        _ => return Err(INTERNAL),
    }
    Ok(range)
}

#[no_mangle]
pub unsafe extern "C" fn oftc_route(
    handle: *mut OftcHandle,
    index: usize,
    out: *mut OftcRoute,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let Some(out) = (unsafe { out.as_mut() }) else {
            return BAD_ARGUMENT;
        };
        let inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_ref() else {
            return NOT_CONNECTED;
        };
        let Some(route) = s.settings().split_routes.get(index) else {
            return BAD_ARGUMENT;
        };
        match range_ip(route.first, route.last) {
            Ok(range) => {
                *out = range;
                OK
            }
            Err(code) => code,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn oftc_dns_server(
    handle: *mut OftcHandle,
    index: usize,
    out_ipv4: *mut u8,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        if out_ipv4.is_null() {
            return BAD_ARGUMENT;
        }
        let inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_ref() else {
            return NOT_CONNECTED;
        };
        let Some(dns) = s.settings().dns_servers.get(index) else {
            return BAD_ARGUMENT;
        };
        unsafe {
            ptr::copy_nonoverlapping(dns.octets().as_ptr(), out_ipv4, 4);
        }
        OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn oftc_dns_domain(
    handle: *mut OftcHandle,
    index: usize,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_ref() else {
            return NOT_CONNECTED;
        };
        let Some(domain) = s.settings().dns_domains.get(index) else {
            return BAD_ARGUMENT;
        };
        unsafe { copy_bytes(domain.as_bytes(), out, capacity, out_len) }
    })
}

#[no_mangle]
pub unsafe extern "C" fn oftc_send_ip(
    handle: *mut OftcHandle,
    packet: *const u8,
    packet_len: usize,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let packet = match unsafe { byte_arg(packet, packet_len, MAX_INNER_PACKET) } {
            Ok(packet) => packet,
            Err(code) => return code,
        };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        s.send_ip(packet).map_or_else(mapped, |_| OK)
    })
}

/// Optional bounded authenticated DPD. Call from a worker queue, not the
/// packetFlow callback; the same Session mutex serializes send/receive.
#[no_mangle]
pub unsafe extern "C" fn oftc_probe_liveness(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        s.probe_liveness().map_or_else(mapped, |_| OK)
    })
}

/// Advance the monotonic DPD policy once. This does not read or wait for a
/// reply. Receive must continue on its own worker so a late authenticated
/// response can complete the pending exchange. RECONNECT_NEEDED means the
/// caller must stop using this SA and start a fresh one under its policy.
#[no_mangle]
pub unsafe extern "C" fn oftc_tick_liveness(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        s.tick_liveness().map_or_else(mapped, |_| OK)
    })
}

/// Refresh the outer NAT mapping without changing authenticated liveness
/// state. The session selects the UDP NAT-T or RFC 9329 TCP keepalive frame.
#[no_mangle]
pub unsafe extern "C" fn oftc_send_nat_keepalive(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        s.send_nat_keepalive().map_or_else(mapped, |_| OK)
    })
}

/// One explicit, bounded CHILD_SA rekey probe. The caller must treat any
/// failure as a failed session and arrange local tunnel cleanup.
#[no_mangle]
pub unsafe extern "C" fn oftc_rekey_child_once(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        s.rekey_child_once().map_or_else(mapped, |_| OK)
    })
}

/// Explicit IKE_SA renewal probe; keeps the existing ESP CHILD_SA installed.
#[no_mangle]
pub unsafe extern "C" fn oftc_rekey_ike_once(handle: *mut OftcHandle) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else { return BAD_ARGUMENT; };
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_mut() else { return NOT_CONNECTED; };
        s.rekey_ike_once().map_or_else(mapped, |_| OK)
    })
}

/// Copy nonsecret successful CHILD_SA rekey counts for diagnostics.
#[no_mangle]
pub unsafe extern "C" fn oftc_rekey_counts(
    handle: *mut OftcHandle, out: *mut OftcRekeyCounts,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else { return BAD_ARGUMENT; };
        let Some(out) = (unsafe { out.as_mut() }) else { return BAD_ARGUMENT; };
        let inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        let Some(s) = inner.session.as_ref() else { return NOT_CONNECTED; };
        let (local, peer) = s.rekey_counts();
        *out = OftcRekeyCounts { local, peer, ike: s.ike_rekey_count() };
        OK
    })
}

/// Polls once; `EVENT_TIMEOUT` is normal. If an IP packet exceeds capacity,
/// it is retained for the next call, and `out_len` reports the required size.
#[no_mangle]
pub unsafe extern "C" fn oftc_receive(
    handle: *mut OftcHandle,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
    out_event: *mut u32,
) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        if out_len.is_null() || out_event.is_null() {
            return BAD_ARGUMENT;
        }
        unsafe {
            *out_len = 0;
            *out_event = 0;
        }
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        if let Some(ip) = inner.pending_ip.as_ref() {
            unsafe {
                *out_event = EVENT_IP_PACKET;
            }
            let code = unsafe { copy_bytes(ip, out, capacity, out_len) };
            if code == OK {
                inner.pending_ip = None;
            }
            return code;
        }
        let Some(s) = inner.session.as_mut() else {
            return NOT_CONNECTED;
        };
        let event = match s.receive() {
            Ok(event) => event,
            Err(error) => return mapped(error),
        };
        match event {
            session::Event::IpPacket(ip) => {
                unsafe {
                    *out_event = EVENT_IP_PACKET;
                }
                let code = unsafe { copy_bytes(&ip, out, capacity, out_len) };
                if code != OK {
                    inner.pending_ip = Some(ip);
                }
                code
            }
            session::Event::PeerDpd => {
                unsafe {
                    *out_event = EVENT_PEER_DPD;
                }
                OK
            }
            session::Event::PeerDeletedChild => {
                unsafe {
                    *out_event = EVENT_PEER_DELETED_CHILD;
                }
                OK
            }
            session::Event::PeerDeletedIke => {
                unsafe {
                    *out_event = EVENT_PEER_DELETED_IKE;
                }
                OK
            }
            session::Event::NatKeepalive => {
                unsafe {
                    *out_event = EVENT_NAT_KEEPALIVE;
                }
                OK
            }
            session::Event::Rejected => {
                unsafe {
                    *out_event = EVENT_REJECTED;
                }
                OK
            }
            session::Event::Timeout => {
                unsafe {
                    *out_event = EVENT_TIMEOUT;
                }
                OK
            }
        }
    })
}

/// Consume the Rust session and clear any pending IP packet. The selected
/// teardown result is returned separately from the call status.
#[no_mangle]
pub unsafe extern "C" fn oftc_teardown(handle: *mut OftcHandle, out_result: *mut u32) -> i32 {
    guard(|| {
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            return BAD_ARGUMENT;
        };
        let Some(out_result) = (unsafe { out_result.as_mut() }) else {
            return BAD_ARGUMENT;
        };
        if handle
            .phase
            .compare_exchange(CONNECTED, CLOSED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return NOT_CONNECTED;
        }
        let mut inner = match lock_inner(handle) {
            Ok(inner) => inner,
            Err(code) => return code,
        };
        inner.pending_ip = None;
        let Some(s) = inner.session.take() else {
            return INTERNAL;
        };
        drop(inner);
        let result = s.disconnect();
        *out_result = match result {
            session::Teardown::Clean => 1,
            session::Teardown::PeerDeleted => 2,
            session::Teardown::LocalOnly => 3,
            session::Teardown::ChildDeleteUnconfirmed => 4,
            session::Teardown::IkeDeleteUnconfirmed => 5,
        };
        OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn policy_drop_is_distinct_from_fatal_esp_error() {
        assert_eq!(mapped(session::Error::PacketDropped), PACKET_DROPPED);
        assert_ne!(mapped(session::Error::Esp), PACKET_DROPPED);
        assert_eq!(mapped(session::Error::ReconnectNeeded), RECONNECT_NEEDED);
        assert_ne!(mapped(session::Error::Inactive), RECONNECT_NEEDED);
    }

    #[test]
    fn rekey_stages_are_fixed_and_distinct_from_connection_errors() {
        use session::{Error, RekeyStage};
        assert_eq!(mapped(Error::Rekey(RekeyStage::NoResponse)), 121);
        assert_eq!(mapped(Error::Rekey(RekeyStage::PeerNoAdditionalSas)), 124);
        assert_eq!(mapped(Error::Rekey(RekeyStage::ResponseSuite)), 128);
        assert_eq!(mapped(Error::Rekey(RekeyStage::OldDelete)), 132);
    }

    #[test]
    fn liveness_tick_requires_a_connected_session() {
        let h = oftc_handle_new();
        unsafe {
            assert_eq!(oftc_tick_liveness(h), NOT_CONNECTED);
            assert_eq!(oftc_tick_liveness(ptr::null_mut()), BAD_ARGUMENT);
            assert_eq!(oftc_send_nat_keepalive(h), NOT_CONNECTED);
            assert_eq!(oftc_send_nat_keepalive(ptr::null_mut()), BAD_ARGUMENT);
            assert_eq!(oftc_rekey_child_once(h), NOT_CONNECTED);
            assert_eq!(oftc_rekey_child_once(ptr::null_mut()), BAD_ARGUMENT);
            assert_eq!(oftc_rekey_ike_once(h), NOT_CONNECTED);
            assert_eq!(oftc_rekey_ike_once(ptr::null_mut()), BAD_ARGUMENT);
            let mut counts = OftcRekeyCounts::default();
            assert_eq!(oftc_rekey_counts(h, &mut counts), NOT_CONNECTED);
            assert_eq!(oftc_rekey_counts(ptr::null_mut(), &mut counts), BAD_ARGUMENT);
            assert_eq!(oftc_rekey_counts(h, ptr::null_mut()), BAD_ARGUMENT);
            oftc_handle_release(h);
        }
    }

    #[test]
    fn handle_retaining_and_cancellation_are_independent_of_session_mutex() {
        let h = oftc_handle_new();
        assert!(!h.is_null());
        unsafe {
            let retained = oftc_handle_retain(h);
            assert_eq!(retained, h);
            assert_eq!(oftc_cancel(retained), OK);
            assert_eq!(oftc_cancel(h), OK);
            oftc_handle_release(retained);
            oftc_handle_release(h);
        }
    }

    #[test]
    fn invalid_input_never_enters_network_connect() {
        let h = oftc_handle_new();
        let uid = b"AABBCCDDEEFF00112233445566778899";
        let psk = b"synthetic";
        let token = b"synthetic";
        unsafe {
            assert_eq!(
                oftc_connect(
                    h,
                    ptr::null(),
                    1,
                    uid.as_ptr(),
                    uid.len(),
                    psk.as_ptr(),
                    psk.len(),
                    token.as_ptr(),
                    token.len()
                ),
                BAD_ARGUMENT
            );
            assert_eq!(
                oftc_connect(
                    h,
                    ptr::null(),
                    1,
                    uid.as_ptr(),
                    uid.len(),
                    psk.as_ptr(),
                    psk.len(),
                    token.as_ptr(),
                    token.len()
                ),
                CLOSED_HANDLE
            );
            oftc_handle_release(h);
        }
    }

    #[test]
    fn output_copy_reports_required_length_without_partial_write() {
        let mut out = [0xAA; 2];
        let mut needed = 0;
        assert_eq!(
            unsafe { copy_bytes(b"route", out.as_mut_ptr(), out.len(), &mut needed) },
            BUFFER_TOO_SMALL
        );
        assert_eq!(needed, 5);
        assert_eq!(out, [0xAA; 2]);
        let mut big = [0; 5];
        assert_eq!(
            unsafe { copy_bytes(b"route", big.as_mut_ptr(), big.len(), &mut needed) },
            OK
        );
        assert_eq!(&big, b"route");
    }

    #[test]
    fn receive_keeps_oversize_packet_until_caller_supplies_buffer() {
        let h = oftc_handle_new();
        unsafe {
            (*h).phase.store(CONNECTED, Ordering::SeqCst);
            (*h).inner.lock().unwrap().pending_ip = Some(vec![0x45, 1, 2, 3, 4]);
            let mut small = [0xaa; 2];
            let mut length = 0;
            let mut event = 0;
            assert_eq!(
                oftc_receive(h, small.as_mut_ptr(), small.len(), &mut length, &mut event),
                BUFFER_TOO_SMALL
            );
            assert_eq!(small, [0xaa; 2]);
            assert_eq!(length, 5);
            assert_eq!(event, EVENT_IP_PACKET);
            let mut full = [0; 5];
            assert_eq!(
                oftc_receive(h, full.as_mut_ptr(), full.len(), &mut length, &mut event),
                OK
            );
            assert_eq!(full, [0x45, 1, 2, 3, 4]);
            assert!((*h).inner.lock().unwrap().pending_ip.is_none());
            oftc_handle_release(h);
        }
    }

    #[test]
    fn c_struct_layout_is_stable() {
        assert_eq!(std::mem::size_of::<OftcSettings>(), 48);
        assert_eq!(std::mem::align_of::<OftcSettings>(), 4);
        assert_eq!(std::mem::size_of::<OftcConnectMode>(), 16);
        assert_eq!(std::mem::align_of::<OftcConnectMode>(), 4);
        assert_eq!(std::mem::size_of::<OftcRoute>(), 36);
        assert_eq!(std::mem::align_of::<OftcRoute>(), 4);
    }

    #[test]
    fn connect_mode_rejects_ambiguous_and_invalid_outer_identity() {
        assert!(connect_options(OftcConnectMode { transport: 1, outer_family: 4,
            idi_v4: [0; 4], tcp_fallback: 1 }).is_ok());
        assert!(connect_options(OftcConnectMode { transport: 2, outer_family: 6,
            idi_v4: [192, 0, 0, 2], tcp_fallback: 0 }).is_ok());
        for mode in [
            OftcConnectMode { transport: 2, outer_family: 4, idi_v4: [0; 4], tcp_fallback: 1 },
            OftcConnectMode { transport: 1, outer_family: 4, idi_v4: [192, 0, 0, 2], tcp_fallback: 0 },
            OftcConnectMode { transport: 1, outer_family: 6, idi_v4: [0; 4], tcp_fallback: 0 },
            OftcConnectMode { transport: 3, outer_family: 4, idi_v4: [0; 4], tcp_fallback: 0 },
        ] {
            assert!(connect_options(mode).is_err());
        }
    }

    #[test]
    fn outer_endpoint_encoding_preserves_native_family() {
        let (family, bytes) = outer_address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(family, 4);
        assert_eq!(&bytes[..4], &[203, 0, 113, 7]);
        assert_eq!(&bytes[4..], &[0; 12]);
        let (family, bytes) = outer_address(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(family, 6);
        assert_eq!(bytes, Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn route_encoding_is_family_explicit() {
        let v4 = range_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 8, 0)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 8, 255)),
        )
        .unwrap();
        assert_eq!(v4.family, 4);
        assert_eq!(&v4.first[..4], &[10, 0, 8, 0]);
        assert_eq!(&v4.last[..4], &[10, 0, 8, 255]);
        assert_eq!(&v4.first[4..], &[0; 12]);
        let v6 = range_ip(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap();
        assert_eq!(v6.family, 6);
        assert_eq!(v6.first, Ipv6Addr::LOCALHOST.octets());
        assert!(range_ip(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        )
        .is_err());
    }

    #[test]
    fn null_and_oversize_input_pointers_are_rejected_before_dereference() {
        assert_eq!(
            unsafe { text_arg(ptr::null(), 5, 10) }.unwrap_err(),
            BAD_ARGUMENT
        );
        assert_eq!(
            unsafe { text_arg(1usize as *const u8, 11, 10) }.unwrap_err(),
            BAD_ARGUMENT
        );
        assert_eq!(
            unsafe { byte_arg(ptr::null(), 1, 10) }.unwrap_err(),
            BAD_ARGUMENT
        );
        assert_eq!(
            unsafe { byte_arg(1usize as *const u8, 11, 10) }.unwrap_err(),
            BAD_ARGUMENT
        );
    }
}
