use crate::filesystem::{InstallError, Installer};
use crate::ipc::authorize_system_bus_name;
use crate::model::{InstallRequest, Profile, ProfileInspection, validate_ssid};
use std::sync::{Arc, Mutex};
use zbus::fdo;
use zbus::message::Header;

pub struct InstallerService {
    installer: Arc<Mutex<Installer>>,
    activity: ServiceActivity,
}

#[derive(Clone)]
pub struct ServiceActivity {
    state: Arc<Mutex<ActivityState>>,
}

struct ActivityState {
    accepting: bool,
    active_requests: usize,
}

struct RequestGuard {
    activity: ServiceActivity,
}

impl InstallerService {
    pub fn new(installer: Installer) -> Self {
        Self {
            installer: Arc::new(Mutex::new(installer)),
            activity: ServiceActivity {
                state: Arc::new(Mutex::new(ActivityState {
                    accepting: true,
                    active_requests: 0,
                })),
            },
        }
    }

    pub fn activity(&self) -> ServiceActivity {
        self.activity.clone()
    }

    fn request_guard(&self) -> fdo::Result<RequestGuard> {
        self.activity
            .begin()
            .ok_or_else(|| fdo::Error::Failed(String::from("service is shutting down")))
    }

    fn inspect_profile_authorized(&self, ssid: &str) -> fdo::Result<ProfileInspection> {
        let installer = self
            .installer
            .lock()
            .map_err(|_| fdo::Error::Failed(String::from("installer state unavailable")))?;
        let (filename, state) = installer.inspect(ssid).map_err(map_install_error)?;
        Ok(ProfileInspection { filename, state })
    }
}

impl ServiceActivity {
    fn begin(&self) -> Option<RequestGuard> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !state.accepting {
            return None;
        }
        state.active_requests += 1;
        Some(RequestGuard {
            activity: self.clone(),
        })
    }

    pub fn stop_if_idle(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.active_requests == 0 {
            state.accepting = false;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn active_requests(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.active_requests,
            Err(poisoned) => poisoned.into_inner().active_requests,
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let mut state = match self.activity.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.active_requests > 0 {
            state.active_requests -= 1;
        }
    }
}

#[zbus::interface(name = "org.codeberg.iweap1.ProfileInstaller")]
impl InstallerService {
    async fn inspect_profile(
        &self,
        ssid: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<ProfileInspection> {
        let _request = self.request_guard()?;
        let sender = sender_from_header(&header)?;
        validate_inspection_input(ssid)?;
        authorize_system_bus_name(&sender)
            .await
            .map_err(map_authorization_error)?;
        self.inspect_profile_authorized(ssid)
    }

    async fn install_profile(
        &self,
        request: InstallRequest,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        let _request = self.request_guard()?;
        let sender = sender_from_header(&header)?;
        let (profile, expected_state, overwrite) = validate_request(request)?;
        authorize_system_bus_name(&sender)
            .await
            .map_err(map_authorization_error)?;

        let installer = self
            .installer
            .lock()
            .map_err(|_| fdo::Error::Failed(String::from("installer state unavailable")))?;
        installer
            .install(&profile, expected_state, overwrite)
            .map_err(map_install_error)
    }
}

fn sender_from_header(header: &Header<'_>) -> fdo::Result<String> {
    header
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied(String::from("missing D-Bus caller identity")))
        .map(ToString::to_string)
}

fn validate_inspection_input(ssid: &str) -> fdo::Result<()> {
    validate_ssid(ssid).map_err(map_validation_error)
}

fn map_authorization_error(error: crate::ipc::AuthorizationError) -> fdo::Error {
    match error {
        crate::ipc::AuthorizationError::Denied => {
            fdo::Error::AccessDenied(String::from("authorization denied"))
        }
        crate::ipc::AuthorizationError::Bus(error) => fdo::Error::Failed(error.to_string()),
    }
}

fn validate_request(
    request: InstallRequest,
) -> fdo::Result<(Profile, crate::model::FileState, bool)> {
    let profile = Profile::try_from(request.profile).map_err(map_validation_error)?;
    Ok((profile, request.expected_state, request.overwrite))
}

fn map_validation_error(error: crate::model::ValidationError) -> fdo::Error {
    fdo::Error::InvalidArgs(error.to_string())
}

fn map_install_error(error: InstallError) -> fdo::Error {
    match error {
        InstallError::Invalid(error) => map_validation_error(error),
        other => fdo::Error::Failed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EapMethod, Secret, WireEapLayer, WireProfile, WireTlsConfig};
    use std::fs;

    #[test]
    fn malformed_request_is_rejected_before_authorization_or_filesystem_access() {
        let request = InstallRequest {
            profile: WireProfile {
                ssid: String::from("Office Wi-Fi"),
                layers: vec![WireEapLayer {
                    method: EapMethod::Mschapv2.wire_code(),
                    identity: String::from("user"),
                    password: Secret::new("password"),
                    password_hash: Secret::new(""),
                    has_tls: false,
                    tls: WireTlsConfig::default(),
                }],
            },
            expected_state: crate::model::FileState::absent(),
            overwrite: false,
        };
        let result = validate_request(request);
        assert!(result.is_ok());

        let invalid = InstallRequest {
            profile: WireProfile {
                ssid: String::from("Office Wi-Fi"),
                layers: vec![WireEapLayer {
                    method: 255,
                    identity: String::new(),
                    password: Secret::new(""),
                    password_hash: Secret::new(""),
                    has_tls: false,
                    tls: WireTlsConfig::default(),
                }],
            },
            expected_state: crate::model::FileState::absent(),
            overwrite: false,
        };
        assert!(matches!(
            validate_request(invalid),
            Err(fdo::Error::InvalidArgs(_))
        ));
    }

    #[test]
    fn inspection_fails_closed_without_caller_identity() {
        let service = InstallerService::new(Installer::system());
        let message = zbus::message::Message::method_call("/org/codeberg/iweap", "InspectProfile")
            .expect("build inspection message")
            .build(&())
            .expect("build inspection message");

        assert!(matches!(
            zbus::block_on(service.inspect_profile("Office Wi-Fi", message.header())),
            Err(fdo::Error::AccessDenied(_))
        ));
    }

    #[test]
    fn authorization_errors_fail_closed() {
        assert!(matches!(
            map_authorization_error(crate::ipc::AuthorizationError::Denied),
            fdo::Error::AccessDenied(_)
        ));
        assert!(matches!(
            map_authorization_error(crate::ipc::AuthorizationError::Bus(
                zbus::Error::Unsupported
            )),
            fdo::Error::Failed(_)
        ));
    }

    #[test]
    fn idle_shutdown_rejects_new_requests_after_active_work_finishes() {
        let service = InstallerService::new(Installer::system());
        let activity = service.activity();
        let request = activity.begin().expect("admit request");
        assert_eq!(activity.active_requests(), 1);
        assert!(!activity.stop_if_idle());
        drop(request);
        assert_eq!(activity.active_requests(), 0);
        assert!(activity.stop_if_idle());
        assert!(activity.begin().is_none());
    }

    #[test]
    fn inspection_validates_input_and_respects_shutdown_state() {
        let parent =
            std::env::temp_dir().join(format!("iweap-service-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).expect("create service fixture");
        let service = InstallerService::new(Installer::for_test(parent.join("iwd")));

        let inspection = service
            .inspect_profile_authorized("Office Wi-Fi")
            .expect("inspect absent profile");
        assert_eq!(inspection.filename, "Office Wi-Fi.8021x");
        assert!(!inspection.state.exists);
        assert!(matches!(
            validate_inspection_input(""),
            Err(fdo::Error::InvalidArgs(_))
        ));

        let invalid_message =
            zbus::message::Message::method_call("/org/codeberg/iweap", "InspectProfile")
                .expect("build invalid inspection message")
                .sender(":1.42")
                .expect("set inspection sender")
                .build(&())
                .expect("build invalid inspection message");
        assert!(matches!(
            zbus::block_on(service.inspect_profile("", invalid_message.header())),
            Err(fdo::Error::InvalidArgs(_))
        ));

        assert!(service.activity.stop_if_idle());
        let shutdown_message =
            zbus::message::Message::method_call("/org/codeberg/iweap", "InspectProfile")
                .expect("build shutdown inspection message")
                .build(&())
                .expect("build shutdown inspection message");
        assert!(matches!(
            zbus::block_on(service.inspect_profile("Office Wi-Fi", shutdown_message.header())),
            Err(fdo::Error::Failed(_))
        ));
        fs::remove_dir_all(parent).expect("remove service fixture");
    }
}
