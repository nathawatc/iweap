use crate::model::{InstallRequest, ProfileInspection};
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Str};

pub const SERVICE_NAME: &str = "org.codeberg.iweap";
pub const OBJECT_PATH: &str = "/org/codeberg/iweap";
pub const INTERFACE_NAME: &str = "org.codeberg.iweap1.ProfileInstaller";
pub const AUTHORIZATION_ACTION: &str = "org.codeberg.iweap.install-profile";

#[zbus::proxy(
    interface = "org.codeberg.iweap1.ProfileInstaller",
    default_service = "org.codeberg.iweap",
    default_path = "/org/codeberg/iweap"
)]
pub trait ProfileInstaller {
    #[zbus(name = "InspectProfile")]
    fn inspect_profile(&self, ssid: &str) -> zbus::Result<ProfileInspection>;

    #[zbus(name = "InstallProfile")]
    fn install_profile(&self, request: InstallRequest) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait PolicyKitAuthority {
    #[zbus(name = "CheckAuthorization")]
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        action_id: &str,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

#[derive(Debug)]
pub enum AuthorizationError {
    Bus(zbus::Error),
    Denied,
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bus(error) => write!(f, "authorization service unavailable: {error}"),
            Self::Denied => f.write_str("authorization denied"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

pub async fn authorize_system_bus_name(sender: &str) -> Result<(), AuthorizationError> {
    let connection = zbus::Connection::system()
        .await
        .map_err(AuthorizationError::Bus)?;
    let proxy = PolicyKitAuthorityProxy::new(&connection)
        .await
        .map_err(AuthorizationError::Bus)?;
    let subject = (
        String::from("system-bus-name"),
        HashMap::from([(
            String::from("name"),
            OwnedValue::from(Str::from(sender.to_owned())),
        )]),
    );
    let (authorized, _challenge, _details) = proxy
        .check_authorization(subject, AUTHORIZATION_ACTION, HashMap::new(), 1, "")
        .await
        .map_err(AuthorizationError::Bus)?;
    if authorized {
        Ok(())
    } else {
        Err(AuthorizationError::Denied)
    }
}
