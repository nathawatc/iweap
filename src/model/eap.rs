use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroize;
use zvariant::Type;

#[derive(Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl Type for Secret {
    const SIGNATURE: &'static zvariant::Signature = <String as Type>::SIGNATURE;
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EapMethod {
    Aka = 1,
    AkaPrime = 2,
    Mschapv2 = 3,
    Peap = 4,
    Pwd = 5,
    Sim = 6,
    Tls = 7,
    Ttls = 8,
    WfaTls = 9,
    Gtc = 10,
    Md5 = 11,
    TunneledPap = 12,
    TunneledChap = 13,
    TunneledMschap = 14,
    TunneledMschapv2 = 15,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodKind {
    Sim,
    Password,
    Tls,
    Tunnel,
    TunneledPassword,
}

impl EapMethod {
    pub const OUTER: &'static [Self] = &[
        Self::Aka,
        Self::AkaPrime,
        Self::Mschapv2,
        Self::Peap,
        Self::Pwd,
        Self::Sim,
        Self::Tls,
        Self::Ttls,
        Self::WfaTls,
    ];
    pub const INNER: &'static [Self] = &[
        Self::Gtc,
        Self::Md5,
        Self::Mschapv2,
        Self::Pwd,
        Self::Aka,
        Self::AkaPrime,
        Self::Peap,
        Self::Sim,
        Self::Tls,
        Self::Ttls,
        Self::WfaTls,
    ];
    pub const TTLS_TUNNELED: &'static [Self] = &[
        Self::TunneledPap,
        Self::TunneledChap,
        Self::TunneledMschap,
        Self::TunneledMschapv2,
    ];

    pub fn from_wire(value: u8) -> Option<Self> {
        Self::OUTER
            .iter()
            .chain(Self::INNER)
            .chain(Self::TTLS_TUNNELED)
            .copied()
            .find(|method| method.wire_code() == value)
    }

    pub const fn wire_code(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Aka => "AKA",
            Self::AkaPrime => "AKA'",
            Self::Mschapv2 => "MSCHAPV2",
            Self::Peap => "PEAP",
            Self::Pwd => "PWD",
            Self::Sim => "SIM",
            Self::Tls => "TLS",
            Self::Ttls => "TTLS",
            Self::WfaTls => "WFA-TLS",
            Self::Gtc => "GTC",
            Self::Md5 => "MD5",
            Self::TunneledPap => "Tunneled-PAP",
            Self::TunneledChap => "Tunneled-CHAP",
            Self::TunneledMschap => "Tunneled-MSCHAP",
            Self::TunneledMschapv2 => "Tunneled-MSCHAPv2",
        }
    }

    pub const fn kind(self) -> MethodKind {
        match self {
            Self::Aka | Self::AkaPrime | Self::Sim => MethodKind::Sim,
            Self::Gtc | Self::Md5 | Self::Mschapv2 | Self::Pwd => MethodKind::Password,
            Self::Tls | Self::WfaTls => MethodKind::Tls,
            Self::Peap | Self::Ttls => MethodKind::Tunnel,
            Self::TunneledPap
            | Self::TunneledChap
            | Self::TunneledMschap
            | Self::TunneledMschapv2 => MethodKind::TunneledPassword,
        }
    }

    pub fn is_tunneled(self) -> bool {
        Self::TTLS_TUNNELED.contains(&self)
    }

    pub const fn is_password_method(self) -> bool {
        matches!(self.kind(), MethodKind::Password)
    }

    pub const fn is_tls_method(self) -> bool {
        matches!(self.kind(), MethodKind::Tls)
    }

    pub const fn supports_tls_client_credentials(self) -> bool {
        matches!(self, Self::Tls | Self::WfaTls)
    }

    pub const fn is_tunnel_method(self) -> bool {
        matches!(self.kind(), MethodKind::Tunnel)
    }

    pub const fn is_sim_method(self) -> bool {
        matches!(self.kind(), MethodKind::Sim)
    }

    pub fn is_outer_method(self) -> bool {
        Self::OUTER.contains(&self)
    }

    pub fn is_inner_method(self) -> bool {
        Self::INNER.contains(&self)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct TlsConfig {
    pub ca_cert: Option<PathBuf>,
    pub server_domain_mask: Option<String>,
    pub fast_reauthentication: Option<bool>,
    pub client: TlsClientCredentials,
    pub client_key_passphrase: Option<Secret>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TlsClientCredentials {
    None,
    CertificateAndKey { certificate: PathBuf, key: PathBuf },
    Pkcs12 { bundle: PathBuf },
}

#[derive(Debug, Eq, PartialEq)]
pub struct EapLayer {
    pub method: EapMethod,
    pub identity: Option<String>,
    pub password: Option<Secret>,
    pub password_hash: Option<Secret>,
    pub tls: Option<TlsConfig>,
}

impl EapLayer {
    pub fn new(method: EapMethod) -> Self {
        Self {
            method,
            identity: None,
            password: None,
            password_hash: None,
            tls: None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Profile {
    pub ssid: String,
    pub layers: Vec<EapLayer>,
}

impl Profile {
    pub fn new(ssid: String, layers: Vec<EapLayer>) -> Self {
        Self { ssid, layers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_method_catalogs_and_wire_codes_are_stable() {
        assert_eq!(
            EapMethod::OUTER,
            &[
                EapMethod::Aka,
                EapMethod::AkaPrime,
                EapMethod::Mschapv2,
                EapMethod::Peap,
                EapMethod::Pwd,
                EapMethod::Sim,
                EapMethod::Tls,
                EapMethod::Ttls,
                EapMethod::WfaTls,
            ]
        );
        assert_eq!(
            EapMethod::INNER,
            &[
                EapMethod::Gtc,
                EapMethod::Md5,
                EapMethod::Mschapv2,
                EapMethod::Pwd,
                EapMethod::Aka,
                EapMethod::AkaPrime,
                EapMethod::Peap,
                EapMethod::Sim,
                EapMethod::Tls,
                EapMethod::Ttls,
                EapMethod::WfaTls,
            ]
        );
        assert_eq!(
            EapMethod::TTLS_TUNNELED,
            &[
                EapMethod::TunneledPap,
                EapMethod::TunneledChap,
                EapMethod::TunneledMschap,
                EapMethod::TunneledMschapv2,
            ]
        );

        let methods = [
            EapMethod::Aka,
            EapMethod::AkaPrime,
            EapMethod::Mschapv2,
            EapMethod::Peap,
            EapMethod::Pwd,
            EapMethod::Sim,
            EapMethod::Tls,
            EapMethod::Ttls,
            EapMethod::WfaTls,
            EapMethod::Gtc,
            EapMethod::Md5,
            EapMethod::TunneledPap,
            EapMethod::TunneledChap,
            EapMethod::TunneledMschap,
            EapMethod::TunneledMschapv2,
        ];
        for (index, method) in methods.into_iter().enumerate() {
            assert!(!method.name().is_empty());
            assert_eq!(EapMethod::from_wire(method.wire_code()), Some(method));
            assert_eq!(method.wire_code(), (index + 1) as u8);
        }
    }

    #[test]
    fn tls_client_credential_capabilities_are_modeled_correctly() {
        assert!(EapMethod::Tls.supports_tls_client_credentials());
        assert!(EapMethod::WfaTls.supports_tls_client_credentials());
        assert!(!EapMethod::Peap.supports_tls_client_credentials());
        assert!(!EapMethod::Ttls.supports_tls_client_credentials());

        for method in EapMethod::OUTER
            .iter()
            .chain(EapMethod::INNER)
            .chain(EapMethod::TTLS_TUNNELED)
        {
            let expected = matches!(method, EapMethod::Tls | EapMethod::WfaTls);
            assert_eq!(method.supports_tls_client_credentials(), expected);
        }
    }
}
