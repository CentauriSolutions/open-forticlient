//! [`VpnControl`] over NetworkExtension, through `objc2`.
//!
//! Every call into the generated bindings is `unsafe`; each goes through
//! [`catch`] so an Objective-C exception becomes an error instead of unwinding
//! through Rust. The SDK documents main-thread delivery for the load, remove and
//! save handlers; callers must therefore not be on the main thread (the CLI parks
//! its main thread in `dispatch_main` and runs commands on a worker), and
//! [`await_callback`] refuses otherwise. Load, save and observer behaviour, and
//! the provider-message and disconnect-error handlers, are unverified against a
//! live NetworkExtension.

use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2_foundation::{
    NSArray, NSData, NSDictionary, NSError, NSNotificationCenter, NSObject, NSObjectProtocol,
    NSString,
};
use objc2_network_extension::{
    NETunnelProviderManager, NETunnelProviderProtocol, NETunnelProviderSession, NEVPNConnection,
    NEVPNStatus, NEVPNStatusDidChangeNotification,
};

use super::{Result, StartKind, StartOptions, Subscription, VpnControl, VpnEntry, VpnStatus};
use crate::completion::{await_callback, Resolver, DEFAULT_TIMEOUT};
use crate::error::AppleError;
use crate::objc::{catch, error_from_ptr, from_ns_error, is_main, Shared, ThreadSafeObject};

// SAFETY: NETunnelProviderManager.h in the macOS SDK says "Instances of this
// class are thread safe." (line 28), and NEVPNManager.h says the same of its
// superclass (line 66).
unsafe impl ThreadSafeObject for NETunnelProviderManager {}

// SAFETY: NEVPNConnection.h says "Instances of this class are thread safe."
// (line 99). Its subclass NETunnelProviderSession adds only a message call.
unsafe impl ThreadSafeObject for NEVPNConnection {}

/// The opaque token `addObserverForName:...` returns.
struct ObserverToken(Retained<ProtocolObject<dyn NSObjectProtocol>>);

// SAFETY: the token is only ever passed to `removeObserver:`, never messaged
// otherwise, and NSNotificationCenter is documented as safe to use from any
// thread.
unsafe impl Send for ObserverToken {}

impl ObserverToken {
    fn remove(self) {
        // SAFETY: removing the token we added.
        let _ = catch(|| unsafe {
            NSNotificationCenter::defaultCenter().removeObserver(self.0.as_ref())
        });
    }
}

/// `saveToPreferences` can wait on the user approving a VPN configuration.
const SAVE_TIMEOUT: Duration = Duration::from_secs(120);

/// The `providerConfiguration` key holding the profile key.
const PROFILE_KEY: &str = "oftc.profile";

/// The option keys `startVPNTunnel` passes to the provider. They belong to the
/// provider crate (this crate does not depend on it), so the host supplies them.
pub struct StartKeys {
    pub live: String,
    pub preflight: String,
    pub mode: String,
}

pub struct NeVpnControl {
    keys: StartKeys,
}

type Manager = Shared<NETunnelProviderManager>;

impl NeVpnControl {
    pub fn new(keys: StartKeys) -> Self {
        NeVpnControl { keys }
    }
}

fn manager(entry: &VpnEntry) -> Result<&Manager> {
    entry.handle::<Manager>().ok_or(AppleError::StaleEntry)
}

fn snapshot(manager: Retained<NETunnelProviderManager>) -> Result<VpnEntry> {
    let (provider_id, profile_key, enabled) = catch(|| {
        // SAFETY: plain property reads on a thread-safe object, inside `catch`.
        unsafe {
            let protocol = manager
                .protocolConfiguration()
                .and_then(|p| p.downcast::<NETunnelProviderProtocol>().ok());
            let provider_id = protocol
                .as_ref()
                .and_then(|p| p.providerBundleIdentifier())
                .map(|s| s.to_string())
                .unwrap_or_default();
            let key = protocol
                .as_ref()
                .and_then(|p| p.providerConfiguration())
                .and_then(|d| d.objectForKey(&NSString::from_str(PROFILE_KEY)))
                .and_then(|v| v.downcast::<NSString>().ok())
                .map(|s| s.to_string());
            (provider_id, key, manager.isEnabled())
        }
    })?;
    Ok(VpnEntry::new(
        provider_id,
        profile_key,
        enabled,
        Arc::new(Shared::new(manager)),
    ))
}

fn connection(entry: &VpnEntry) -> Result<Shared<NEVPNConnection>> {
    let manager = manager(entry)?;
    // SAFETY: property read on a thread-safe object, inside `catch`.
    catch(|| Shared::new(unsafe { manager.connection() }))
}

/// Runs a call taking a `void (^)(NSError *)` handler and waits for it.
fn await_error(
    timeout: Duration,
    call: impl FnOnce(&block2::DynBlock<dyn Fn(*mut NSError)>) -> std::result::Result<(), AppleError>,
) -> Result<()> {
    let mut started = Ok(());
    let waited = await_callback(
        timeout,
        is_main,
        |resolver: Resolver<Option<AppleError>>| {
            let block = RcBlock::new(move |error: *mut NSError| {
                // SAFETY: NetworkExtension passes null or a live NSError.
                resolver.resolve(unsafe { error_from_ptr(error) });
            });
            started = call(&block);
        },
    );
    // A call that raised never fires its handler; report that, not the timeout.
    started?;
    waited?.map_or(Ok(()), Err)
}

fn map_status(status: NEVPNStatus) -> VpnStatus {
    match status {
        NEVPNStatus::Disconnected => VpnStatus::Disconnected,
        NEVPNStatus::Connecting => VpnStatus::Connecting,
        NEVPNStatus::Connected => VpnStatus::Connected,
        NEVPNStatus::Reasserting => VpnStatus::Reasserting,
        NEVPNStatus::Disconnecting => VpnStatus::Disconnecting,
        _ => VpnStatus::Invalid,
    }
}

impl VpnControl for NeVpnControl {
    fn load_all(&self) -> Result<Vec<VpnEntry>> {
        let managers = await_callback(
            DEFAULT_TIMEOUT,
            is_main,
            |resolver: Resolver<Result<Vec<Manager>>>| {
                let failed = resolver.clone();
                let block = RcBlock::new(
                    move |list: *mut NSArray<NETunnelProviderManager>, error: *mut NSError| {
                        // SAFETY: null or live for the duration of the handler; the
                        // objects are retained before it returns.
                        let result = match unsafe { error_from_ptr(error) } {
                            Some(e) => Err(e),
                            None => Ok(unsafe { list.as_ref() }
                                .map(|l| l.to_vec().into_iter().map(Shared::new).collect())
                                .unwrap_or_default()),
                        };
                        resolver.resolve(result);
                    },
                );
                if let Err(e) = catch(|| {
                    // SAFETY: handler block outlives the call (NE copies it).
                    unsafe {
                        NETunnelProviderManager::loadAllFromPreferencesWithCompletionHandler(&block)
                    }
                }) {
                    failed.resolve(Err(e));
                }
            },
        )??;
        managers
            .into_iter()
            .map(|m| snapshot(Retained::from(&*m)))
            .collect()
    }

    fn reload(&self, entry: &VpnEntry) -> Result<VpnEntry> {
        let manager = manager(entry)?;
        await_error(DEFAULT_TIMEOUT, |block| {
            // SAFETY: handler block outlives the call (NE copies it).
            catch(|| unsafe { manager.loadFromPreferencesWithCompletionHandler(block) })
        })?;
        snapshot(Retained::from(&**manager))
    }

    fn status(&self, entry: &VpnEntry) -> VpnStatus {
        let Ok(connection) = connection(entry) else {
            return VpnStatus::Invalid;
        };
        // SAFETY: property read on a thread-safe object, inside `catch`.
        catch(|| map_status(unsafe { connection.status() })).unwrap_or(VpnStatus::Invalid)
    }

    fn create(&self, provider_id: &str, profile_key: &str, name: &str) -> Result<()> {
        if is_main() {
            return Err(AppleError::MainThread);
        }
        let manager = catch(|| {
            // SAFETY: constructing and configuring objects we own, inside `catch`.
            unsafe {
                let manager = NETunnelProviderManager::new();
                let protocol = NETunnelProviderProtocol::new();
                protocol.setProviderBundleIdentifier(Some(&NSString::from_str(provider_id)));
                // Display label only, never a secret.
                protocol.setServerAddress(Some(&NSString::from_str("OFTC")));
                let key = NSString::from_str(PROFILE_KEY);
                let value: Retained<AnyObject> =
                    Retained::into_super(Retained::into_super(NSString::from_str(profile_key)));
                protocol.setProviderConfiguration(Some(&NSDictionary::from_retained_objects(
                    &[&*key],
                    &[value],
                )));
                manager.setProtocolConfiguration(Some(&protocol));
                manager.setLocalizedDescription(Some(&NSString::from_str(&format!(
                    "OFTC VPN ({name})"
                ))));
                manager.setEnabled(true);
                manager
            }
        })?;
        save(&manager)
    }

    fn set_enabled(&self, entry: &VpnEntry, enabled: bool) -> Result<()> {
        if is_main() {
            return Err(AppleError::MainThread);
        }
        let manager = manager(entry)?;
        // SAFETY: property write on a thread-safe object, inside `catch`.
        catch(|| unsafe { manager.setEnabled(enabled) })?;
        save(manager)
    }

    fn remove(&self, entry: &VpnEntry) -> Result<()> {
        let manager = manager(entry)?;
        await_error(DEFAULT_TIMEOUT, |block| {
            // SAFETY: handler block outlives the call (NE copies it).
            catch(|| unsafe { manager.removeFromPreferencesWithCompletionHandler(Some(block)) })
        })
    }

    fn start(&self, entry: &VpnEntry, options: StartOptions) -> Result<()> {
        let connection = connection(entry)?;
        let envelope_key = match options.kind {
            StartKind::Live => &self.keys.live,
            StartKind::Preflight => &self.keys.preflight,
        };
        // The envelope is copied into an NSData we cannot zeroize; the Swift
        // implementation had the same property.
        let mut keys = vec![NSString::from_str(envelope_key)];
        let mut values: Vec<Retained<NSObject>> =
            vec![Retained::into_super(NSData::with_bytes(&options.envelope))];
        if let Some(mode) = &options.mode {
            keys.push(NSString::from_str(&self.keys.mode));
            values.push(Retained::into_super(NSData::with_bytes(mode)));
        }
        let key_refs: Vec<&NSString> = keys.iter().map(|k| &**k).collect();
        let dict = NSDictionary::from_retained_objects(&key_refs, &values);
        // SAFETY: arguments are live objects; inside `catch`.
        catch(|| unsafe { connection.startVPNTunnelWithOptions_andReturnError(Some(&dict)) })?
            .map_err(|e| from_ns_error(&e))
    }

    fn stop(&self, entry: &VpnEntry) {
        if let Ok(connection) = connection(entry) {
            // SAFETY: thread-safe object, inside `catch`; failure leaves nothing
            // to report from a void call.
            let _ = catch(|| unsafe { connection.stopVPNTunnel() });
        }
    }

    fn send_provider_message(
        &self,
        entry: &VpnEntry,
        message: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let connection = connection(entry)?;
        await_callback(timeout, is_main, |resolver: Resolver<Result<Vec<u8>>>| {
            let failed = resolver.clone();
            let data = NSData::with_bytes(message);
            let block = RcBlock::new(move |reply: *mut NSData| {
                // SAFETY: null or a live NSData for the handler's duration.
                let bytes = unsafe { reply.as_ref() }
                    .map(|d| d.to_vec())
                    .unwrap_or_default();
                resolver.resolve(Ok(bytes));
            });
            let session = Retained::<NEVPNConnection>::from(&*connection)
                .downcast::<NETunnelProviderSession>();
            let Ok(session) = session else {
                failed.resolve(Err(AppleError::from_nserror(
                    "oftc.apple",
                    0,
                    "connection is not a tunnel provider session",
                )));
                return;
            };
            let mut error = None;
            // SAFETY: arguments live across the call; inside `catch`.
            let sent = catch(|| unsafe {
                session.sendProviderMessage_returnError_responseHandler(
                    &data,
                    Some(&mut error),
                    Some(&block),
                )
            });
            match sent {
                Ok(true) => {}
                Ok(false) => {
                    failed.resolve(Err(error.as_deref().map(from_ns_error).unwrap_or_else(
                        || AppleError::from_nserror("oftc.apple", 0, "provider message not sent"),
                    )))
                }
                Err(e) => failed.resolve(Err(e)),
            }
        })?
    }

    fn last_disconnect_error(
        &self,
        entry: &VpnEntry,
        timeout: Duration,
    ) -> Result<Option<AppleError>> {
        let connection = connection(entry)?;
        await_callback(
            timeout,
            is_main,
            |resolver: Resolver<Result<Option<AppleError>>>| {
                let failed = resolver.clone();
                let block = RcBlock::new(move |error: *mut NSError| {
                    // SAFETY: null or a live NSError for the handler's duration.
                    resolver.resolve(Ok(unsafe { error_from_ptr(error) }));
                });
                // SAFETY: handler block outlives the call (NE copies it).
                if let Err(e) = catch(|| unsafe {
                    connection.fetchLastDisconnectErrorWithCompletionHandler(&block)
                }) {
                    failed.resolve(Err(e));
                }
            },
        )?
    }

    fn observe_status(&self, entry: &VpnEntry, notify: Sender<()>) -> Result<Subscription> {
        let connection = connection(entry)?;
        let block = RcBlock::new(
            move |_: std::ptr::NonNull<objc2_foundation::NSNotification>| {
                let _ = notify.send(());
            },
        );
        // Queue nil: delivering on the main queue deadlocks with NE. The
        // connection is always passed as the object: `object: nil` leaks mach
        // ports.
        let token: Retained<ProtocolObject<dyn NSObjectProtocol>> = catch(|| {
            // SAFETY: notification name and object are live; block is copied.
            unsafe {
                NSNotificationCenter::defaultCenter().addObserverForName_object_queue_usingBlock(
                    Some(NEVPNStatusDidChangeNotification),
                    Some(&*connection),
                    None,
                    &block,
                )
            }
        })?;
        let token = ObserverToken(token);
        Ok(Subscription::new(move || token.remove()))
    }
}

fn save(manager: &NETunnelProviderManager) -> Result<()> {
    await_error(SAVE_TIMEOUT, |block| {
        // SAFETY: handler block outlives the call (NE copies it).
        catch(|| unsafe { manager.saveToPreferencesWithCompletionHandler(Some(block)) })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_status_and_falls_back_to_invalid() {
        for (raw, want) in [
            (NEVPNStatus::Invalid, VpnStatus::Invalid),
            (NEVPNStatus::Disconnected, VpnStatus::Disconnected),
            (NEVPNStatus::Connecting, VpnStatus::Connecting),
            (NEVPNStatus::Connected, VpnStatus::Connected),
            (NEVPNStatus::Reasserting, VpnStatus::Reasserting),
            (NEVPNStatus::Disconnecting, VpnStatus::Disconnecting),
            (NEVPNStatus(99), VpnStatus::Invalid),
        ] {
            assert_eq!(map_status(raw), want);
        }
    }
}
