use crate::filesystem::{InstallError, Installer};
use crate::ipc::authorize_system_bus_name;
use crate::model::{InstallRequest, Profile, ProfileInspection};
use std::sync::{Arc, Mutex};
use zbus::fdo;
use zbus::message::Header;

pub struct InstallerService {
    installer: Arc<Mutex<Installer>>,
}

impl InstallerService {
    pub fn new(installer: Installer) -> Self {
        Self {
            installer: Arc::new(Mutex::new(installer)),
        }
    }
}

#[zbus::interface(name = "org.codeberg.iweap1.ProfileInstaller")]
impl InstallerService {
    async fn inspect_profile(&self, ssid: &str) -> fdo::Result<ProfileInspection> {
        let installer = self
            .installer
            .lock()
            .map_err(|_| fdo::Error::Failed(String::from("installer state unavailable")))?;
        let (filename, state) = installer.inspect(ssid).map_err(map_install_error)?;
        Ok(ProfileInspection { filename, state })
    }

    async fn install_profile(
        &self,
        request: InstallRequest,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<String> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied(String::from("missing D-Bus caller identity")))?
            .to_string();
        let (profile, expected_state, overwrite) = validate_request(request)?;
        authorize_system_bus_name(&sender)
            .await
            .map_err(|error| match error {
                crate::ipc::AuthorizationError::Denied => {
                    fdo::Error::AccessDenied(String::from("authorization denied"))
                }
                crate::ipc::AuthorizationError::Bus(error) => fdo::Error::Failed(error.to_string()),
            })?;

        let installer = self
            .installer
            .lock()
            .map_err(|_| fdo::Error::Failed(String::from("installer state unavailable")))?;
        installer
            .install(&profile, expected_state, overwrite)
            .map_err(map_install_error)
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
}
