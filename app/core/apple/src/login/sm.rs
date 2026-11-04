//! [`LoginItems`] over ServiceManagement's `SMAppService`, through `objc2`.
//!
//! Each call builds the service object it needs and drops it, so no object is
//! shared between threads. Every call is `unsafe` in the generated bindings and
//! goes through [`catch`]. `register` and `unregister` are the synchronous
//! variants. The statuses and errors of real registration (approval, a missing
//! plist) are unverified against a live system.

use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use super::{LoginItem, LoginItems, LoginStatus, Result};
use crate::objc::{catch, from_ns_error};

pub struct ServiceLoginItems;

fn service(item: &LoginItem) -> Result<Retained<SMAppService>> {
    // SAFETY: constructors taking a live string, inside `catch`.
    catch(|| unsafe {
        match item {
            LoginItem::MainApp => SMAppService::mainAppService(),
            LoginItem::Agent(plist) => {
                SMAppService::agentServiceWithPlistName(&NSString::from_str(plist))
            }
        }
    })
}

fn map_status(status: SMAppServiceStatus) -> LoginStatus {
    match status {
        SMAppServiceStatus::NotRegistered => LoginStatus::NotRegistered,
        SMAppServiceStatus::Enabled => LoginStatus::Enabled,
        SMAppServiceStatus::RequiresApproval => LoginStatus::RequiresApproval,
        SMAppServiceStatus::NotFound => LoginStatus::NotFound,
        _ => LoginStatus::Unknown,
    }
}

impl LoginItems for ServiceLoginItems {
    fn status(&self, item: &LoginItem) -> LoginStatus {
        let Ok(service) = service(item) else {
            return LoginStatus::Unknown;
        };
        // SAFETY: property read on a live object, inside `catch`.
        catch(|| map_status(unsafe { service.status() })).unwrap_or(LoginStatus::Unknown)
    }

    fn register(&self, item: &LoginItem) -> Result<()> {
        let service = service(item)?;
        // SAFETY: call on a live object, inside `catch`.
        catch(|| unsafe { service.registerAndReturnError() })?.map_err(|e| from_ns_error(&e))
    }

    fn unregister(&self, item: &LoginItem) -> Result<()> {
        let service = service(item)?;
        // SAFETY: call on a live object, inside `catch`.
        catch(|| unsafe { service.unregisterAndReturnError() })?.map_err(|e| from_ns_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_status_and_falls_back_to_unknown() {
        for (raw, want) in [
            (
                SMAppServiceStatus::NotRegistered,
                LoginStatus::NotRegistered,
            ),
            (SMAppServiceStatus::Enabled, LoginStatus::Enabled),
            (
                SMAppServiceStatus::RequiresApproval,
                LoginStatus::RequiresApproval,
            ),
            (SMAppServiceStatus::NotFound, LoginStatus::NotFound),
            (SMAppServiceStatus(99), LoginStatus::Unknown),
        ] {
            assert_eq!(map_status(raw), want);
        }
    }

    /// A bundled agent that is not in this test binary's bundle reads as not
    /// found: the only real `SMAppService` call that is safe to make in CI.
    #[test]
    fn an_agent_missing_from_the_bundle_is_not_found() {
        let status = ServiceLoginItems.status(&LoginItem::Agent("absent.example.plist".into()));
        assert_eq!(status, LoginStatus::NotFound);
    }
}
