# Offline provider FFI

`sh spikes/provider-ffi/run.sh` builds the provider-owned Session
as a Rust rlib, then builds `ffi.rs` as a C ABI dynamic library. It runs offline
synthetic Rust tests and typechecks a Swift consumer against `oftc_ffi.h`. The
script does not connect to a gateway, run SAML, sign, or install an extension.

The ABI exposes an opaque `OftcHandle`. The Rust Session retains the IKE and
ESP keys, SPIs, socket, and authenticated control state. Swift receives only
plain network settings, inner IP packets, and control event codes. The header
uses fixed C layouts and length-delimited byte buffers; no `String`, Rust
allocation, or borrowed Rust pointer crosses the boundary.

## Provider call sequence

1. Create a handle with `oftc_handle_new()`. Retain it before dispatching a
   blocking call to another queue; release each reference after that call has
   returned. The final release must follow all work using the pointer.
2. Decode and validate the one-time bootstrap in Swift. Pass gateway, 32-byte
   machine UID, PSK, and **one fresh SAML tokenid** to `oftc_connect()` on a
   worker queue. It is a one-shot blocking call. It copies bounded UTF-8 input
   into `ConnectInput`; that type wipes the Rust PSK and token copies when
   dropped. Swift must erase its own original buffers. A failed connect leaves
   the handle closed; create a new handle for another authorized attempt.
3. If connect succeeds, copy `OftcSettings`, then fetch each route, DNS server,
   and DNS domain by index. Version 2 includes assigned IPv4, interface mask,
   the family-tagged resolved outer gateway IP (IPv4 or IPv6), inner MTU, and
   item counts. Route endpoints
   use family 4 or 6; IPv4 occupies the first four bytes of each 16-byte
   address. Convert each inclusive range to exact route prefixes before
   applying `NEPacketTunnelNetworkSettings`. Exclude an outer IPv4 gateway /32
   from the tunnel; an IPv6 outer endpoint cannot recurse into an IPv4-only
   split route. Do not widen a split route when a mask is missing.
4. Feed packetFlow IPv4 packets to `oftc_send_ip()` and call `oftc_receive()`
   repeatedly on a worker queue. A timeout event is normal. On
   `OFTC_BUFFER_TOO_SMALL`, `out_len` contains the required size and the Rust
   side retains that same IP packet for the next receive call. Control events
   have no raw IKE payload; responder DPD and DELETE are authenticated inside
   Session. `oftc_probe_liveness()` can run a bounded DPD exchange on the same
   serialized session.
5. On stop, stop packet dispatch, call `oftc_teardown()` on a worker queue,
   remove tunnel settings, join all workers, and release the final handle.
   `OFTC_TEARDOWN_CLEAN` means authenticated CHILD and IKE DELETE responses
   arrived. An unconfirmed result means the local keys/socket were still
   dropped, but the peer acknowledgement was not observed. `oftc_cancel()`
   sets an atomic flag and can interrupt connect/receive from another retained
   reference; Session's teardown uses bounded cleanup even after cancellation.

All FFI pointers must be valid for their stated lengths. A null pointer with
nonzero length is rejected, but C cannot validate an arbitrary nonnull address.
Output functions never return borrowed storage. `oftc_dns_domain()` and
`oftc_receive()` report required lengths before copying. Calling release while
another thread is using the last reference is invalid; retain before starting
that work.

## Status and scope

The `oftc_ffi.h` constants distinguish ABI errors, cancellation, session
stages, events, and teardown outcomes without logging credentials or packet
bytes. The FFI deliberately has no browser, profile, or TCP fallback behavior.
The installed version 5 provider has passed one live UDP/4500 packetFlow echo
and reply over an IPv4 outer socket. TCP fallback, native IPv6 outer transport,
and sustained signed-provider lifecycle remain separate gates. The offline
tests cover handle references, bounded
inputs, copy ownership, route layouts, and short receive buffers. They do not
simulate a full authenticated gateway exchange through the C ABI.
