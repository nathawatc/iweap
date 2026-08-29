use super::eap::{EapLayer, EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig};
use std::fmt;
use std::path::Path;

pub const MAX_SSID_BYTES: usize = 32;
pub const MAX_EAP_IDENTITY_BYTES: usize = 253;
pub const MAX_EAP_DEPTH: usize = 4;
pub const MAX_EAP_LAYERS: usize = MAX_EAP_DEPTH + 1;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_SECRET_BYTES: usize = 4096;
pub const MAX_DOMAIN_MASK_BYTES: usize = 1024;
pub const PASSWORD_HASH_HEX_CHARS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    EmptySsid,
    SsidTooLong,
    TextTooLong,
    NulInText,
    NoEapLayers,
    TooManyEapLayers,
    InvalidOuterMethod,
    InvalidInnerMethod,
    MissingPhase2,
    UnexpectedNestedEap,
    InvalidTunneledMethod,
    MethodHasUnexpectedFields,
    MissingTlsConfiguration,
    InvalidTlsConfiguration,
    InvalidBoolean,
    InvalidPath,
    MissingCaCertificate,
    InvalidDomainMask,
    EmptySecret,
    SecretTooLong,
    PasswordHashUnsupported,
    InvalidPasswordHash,
    PasswordConflict,
    CredentialNeedsIdentity,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySsid => "SSID is required",
            Self::SsidTooLong => {
                return write!(f, "SSID must contain at most {MAX_SSID_BYTES} bytes");
            }
            Self::TextTooLong => "profile text value is too long",
            Self::NulInText => "profile text contains an unsupported NUL byte",
            Self::NoEapLayers => "an EAP method is required",
            Self::TooManyEapLayers => "nested EAP configuration is too deep",
            Self::InvalidOuterMethod => "invalid outer EAP method",
            Self::InvalidInnerMethod => "invalid inner EAP method",
            Self::MissingPhase2 => "tunneled EAP method requires a phase-2 method",
            Self::UnexpectedNestedEap => "EAP method cannot contain another method",
            Self::InvalidTunneledMethod => "invalid TTLS tunneled method",
            Self::MethodHasUnexpectedFields => "EAP method has incompatible settings",
            Self::MissingTlsConfiguration => "TLS-based EAP method requires TLS settings",
            Self::InvalidTlsConfiguration => "invalid TLS settings",
            Self::InvalidBoolean => "invalid boolean setting",
            Self::InvalidPath => "path must be absolute and name a UTF-8 file path",
            Self::MissingCaCertificate => "server domain mask requires a CA certificate",
            Self::InvalidDomainMask => "invalid server domain mask",
            Self::EmptySecret => "stored secret cannot be empty",
            Self::SecretTooLong => "stored secret is too long",
            Self::PasswordHashUnsupported => "password hash is only valid for MSCHAPV2",
            Self::InvalidPasswordHash => {
                return write!(
                    f,
                    "MSCHAPV2 password hash must be {PASSWORD_HASH_HEX_CHARS} hexadecimal characters"
                );
            }
            Self::PasswordConflict => "password and password hash cannot both be set",
            Self::CredentialNeedsIdentity => "stored credentials require an identity",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ValidationError {}

impl Profile {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_ssid(&self.ssid)?;
        if self.layers.is_empty() {
            return Err(ValidationError::NoEapLayers);
        }
        if self.layers.len() > MAX_EAP_LAYERS {
            return Err(ValidationError::TooManyEapLayers);
        }
        let consumed = self.validate_layer(0, None, 0)?;
        if consumed != self.layers.len() {
            return Err(ValidationError::UnexpectedNestedEap);
        }
        Ok(())
    }

    fn validate_layer(
        &self,
        index: usize,
        parent: Option<EapMethod>,
        depth: usize,
    ) -> Result<usize, ValidationError> {
        if depth > MAX_EAP_DEPTH {
            return Err(ValidationError::TooManyEapLayers);
        }
        let layer = self
            .layers
            .get(index)
            .ok_or(ValidationError::MissingPhase2)?;

        if parent.is_none() {
            if !layer.method.is_outer_method() {
                return Err(ValidationError::InvalidOuterMethod);
            }
        } else if layer.method.is_tunneled() {
            if parent != Some(EapMethod::Ttls) {
                return Err(ValidationError::InvalidTunneledMethod);
            }
        } else if !layer.method.is_inner_method() {
            return Err(ValidationError::InvalidInnerMethod);
        }
        self.validate_layer_fields(layer)?;

        if layer.method.is_tunnel_method() {
            let child_index = index + 1;
            let child = self
                .layers
                .get(child_index)
                .ok_or(ValidationError::MissingPhase2)?;
            if layer.method == EapMethod::Peap && child.method.is_tunneled() {
                return Err(ValidationError::InvalidTunneledMethod);
            }
            if layer.method == EapMethod::Ttls && child.method.is_tunneled() {
                self.validate_tunneled_fields(child)?;
                return Ok(child_index + 1);
            }
            return self.validate_layer(child_index, Some(layer.method), depth + 1);
        }
        if index + 1 != self.layers.len() {
            return Err(ValidationError::UnexpectedNestedEap);
        }
        Ok(index + 1)
    }

    fn validate_layer_fields(&self, layer: &EapLayer) -> Result<(), ValidationError> {
        if layer.method.is_tunneled() {
            validate_optional_text(layer.identity.as_deref())?;
        } else {
            validate_eap_identity(layer.identity.as_deref())?;
        }
        if layer.method.is_sim_method() {
            if layer.identity.is_some()
                || layer.password.is_some()
                || layer.password_hash.is_some()
                || layer.tls.is_some()
            {
                return Err(ValidationError::MethodHasUnexpectedFields);
            }
            return Ok(());
        }
        if layer.method.is_password_method() {
            if layer.tls.is_some() {
                return Err(ValidationError::MethodHasUnexpectedFields);
            }
            validate_secret_pair(layer)?;
            if layer.method != EapMethod::Mschapv2 && layer.password_hash.is_some() {
                return Err(ValidationError::PasswordHashUnsupported);
            }
            return Ok(());
        }
        if layer.method.is_tls_method() || layer.method.is_tunnel_method() {
            if layer.password.is_some() || layer.password_hash.is_some() {
                return Err(ValidationError::MethodHasUnexpectedFields);
            }
            let tls = layer
                .tls
                .as_ref()
                .ok_or(ValidationError::MissingTlsConfiguration)?;
            if !layer.method.supports_tls_client_credentials()
                && (!matches!(tls.client, TlsClientCredentials::None)
                    || tls.client_key_passphrase.is_some())
            {
                return Err(ValidationError::MethodHasUnexpectedFields);
            }
            return tls.validate();
        }
        if layer.method.is_tunneled() {
            return self.validate_tunneled_fields(layer);
        }
        Err(ValidationError::InvalidInnerMethod)
    }

    fn validate_tunneled_fields(&self, layer: &EapLayer) -> Result<(), ValidationError> {
        if !layer.method.is_tunneled() {
            return Err(ValidationError::InvalidTunneledMethod);
        }
        validate_optional_text(layer.identity.as_deref())?;
        if layer.password_hash.is_some() || layer.tls.is_some() {
            return Err(ValidationError::MethodHasUnexpectedFields);
        }
        validate_secret_pair(layer)
    }
}

impl TlsConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(path) = self.ca_cert.as_deref() {
            validate_path(path)?;
        }
        if let Some(mask) = self.server_domain_mask.as_deref() {
            validate_domain_mask(mask)?;
            if self.ca_cert.is_none() {
                return Err(ValidationError::MissingCaCertificate);
            }
        }
        match &self.client {
            TlsClientCredentials::None => {}
            TlsClientCredentials::CertificateAndKey { certificate, key } => {
                validate_path(certificate)?;
                validate_path(key)?;
            }
            TlsClientCredentials::Pkcs12 { bundle } => validate_path(bundle)?,
        }
        if let Some(passphrase) = self.client_key_passphrase.as_ref() {
            validate_secret(passphrase)?;
            if matches!(self.client, TlsClientCredentials::None) {
                return Err(ValidationError::InvalidTlsConfiguration);
            }
        }
        Ok(())
    }
}

fn validate_secret_pair(layer: &EapLayer) -> Result<(), ValidationError> {
    if let Some(password) = layer.password.as_ref() {
        validate_secret(password)?;
    }
    if let Some(password_hash) = layer.password_hash.as_ref() {
        validate_secret(password_hash)?;
        if !is_valid_password_hash(password_hash.as_str()) {
            return Err(ValidationError::InvalidPasswordHash);
        }
    }
    if layer.password.is_some() && layer.password_hash.is_some() {
        return Err(ValidationError::PasswordConflict);
    }
    if (layer.password.is_some() || layer.password_hash.is_some()) && layer.identity.is_none() {
        return Err(ValidationError::CredentialNeedsIdentity);
    }
    Ok(())
}

fn validate_secret(secret: &Secret) -> Result<(), ValidationError> {
    if secret.is_empty() {
        return Err(ValidationError::EmptySecret);
    }
    if secret.as_str().len() > MAX_SECRET_BYTES {
        return Err(ValidationError::SecretTooLong);
    }
    validate_text(secret.as_str(), MAX_SECRET_BYTES)
}

pub fn validate_ssid(ssid: &str) -> Result<(), ValidationError> {
    if ssid.is_empty() {
        return Err(ValidationError::EmptySsid);
    }
    if ssid.len() > MAX_SSID_BYTES {
        return Err(ValidationError::SsidTooLong);
    }
    validate_text(ssid, MAX_SSID_BYTES)
}

pub(super) fn validate_text(value: &str, max_bytes: usize) -> Result<(), ValidationError> {
    if value.len() > max_bytes {
        return Err(ValidationError::TextTooLong);
    }
    if value.contains('\0') {
        return Err(ValidationError::NulInText);
    }
    Ok(())
}

fn validate_optional_text(value: Option<&str>) -> Result<(), ValidationError> {
    if let Some(value) = value {
        if value.is_empty() {
            return Err(ValidationError::MethodHasUnexpectedFields);
        }
        validate_text(value, MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn validate_eap_identity(value: Option<&str>) -> Result<(), ValidationError> {
    validate_optional_text(value)?;
    if value.is_some_and(|value| value.len() > MAX_EAP_IDENTITY_BYTES) {
        return Err(ValidationError::TextTooLong);
    }
    Ok(())
}

pub(super) fn validate_path(path: &Path) -> Result<(), ValidationError> {
    let Some(value) = path.to_str() else {
        return Err(ValidationError::InvalidPath);
    };
    if !path.is_absolute() {
        return Err(ValidationError::InvalidPath);
    }
    validate_text(value, MAX_TEXT_BYTES)
}

fn validate_domain_mask(mask: &str) -> Result<(), ValidationError> {
    if mask.is_empty() || mask.len() > MAX_DOMAIN_MASK_BYTES || mask.contains('\0') {
        return Err(ValidationError::InvalidDomainMask);
    }
    for candidate in mask.split(';') {
        if candidate.is_empty() {
            return Err(ValidationError::InvalidDomainMask);
        }
        for label in candidate.split('.') {
            if label.is_empty()
                || (label != "*"
                    && !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
            {
                return Err(ValidationError::InvalidDomainMask);
            }
        }
    }
    Ok(())
}

pub fn is_valid_domain_mask(mask: &str) -> bool {
    validate_domain_mask(mask).is_ok()
}

pub fn is_valid_password_hash(value: &str) -> bool {
    value.len() == PASSWORD_HASH_HEX_CHARS && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password_layer(method: EapMethod, identity: &str, password: &str) -> EapLayer {
        let mut layer = EapLayer::new(method);
        layer.identity = Some(identity.to_owned());
        layer.password = Some(Secret::new(password));
        layer
    }

    fn empty_tls() -> TlsConfig {
        TlsConfig {
            ca_cert: None,
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        }
    }

    fn profile(layers: Vec<EapLayer>) -> Profile {
        Profile::new(String::from("Office Wi-Fi"), layers)
    }

    #[test]
    fn ssid_limits_and_validation_follow_iwd() {
        assert_eq!(validate_ssid(&"é".repeat(16)), Ok(()));
        assert_eq!(
            validate_ssid(&"é".repeat(17)),
            Err(ValidationError::SsidTooLong)
        );
    }

    #[test]
    fn domain_masks_match_conservative_input_contract() {
        assert!(is_valid_domain_mask("radius.example.com;*.backup"));
        assert!(is_valid_domain_mask("*.example"));
        assert!(!is_valid_domain_mask("radius..example"));
        assert!(!is_valid_domain_mask("radius.example;"));
        assert!(!is_valid_domain_mask("radius/example"));
    }

    #[test]
    fn validation_rejects_invalid_nesting_and_settings() {
        let mut invalid_outer = EapLayer::new(EapMethod::Gtc);
        invalid_outer.identity = Some(String::from("user"));
        assert_eq!(
            profile(vec![invalid_outer]).validate(),
            Err(ValidationError::InvalidOuterMethod)
        );

        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(empty_tls());
        assert_eq!(
            profile(vec![peap, EapLayer::new(EapMethod::TunneledPap)]).validate(),
            Err(ValidationError::InvalidTunneledMethod)
        );

        let mut tls = EapLayer::new(EapMethod::Tls);
        tls.tls = Some(TlsConfig {
            server_domain_mask: Some(String::from("radius.example.com")),
            ..empty_tls()
        });
        assert_eq!(
            profile(vec![tls]).validate(),
            Err(ValidationError::MissingCaCertificate)
        );

        let mut sim = EapLayer::new(EapMethod::Sim);
        sim.identity = Some(String::from("unexpected"));
        assert_eq!(
            profile(vec![sim]).validate(),
            Err(ValidationError::MethodHasUnexpectedFields)
        );

        let mut hash = EapLayer::new(EapMethod::Mschapv2);
        hash.identity = Some(String::from("user"));
        hash.password_hash = Some(Secret::new("not-a-hash"));
        assert_eq!(
            profile(vec![hash]).validate(),
            Err(ValidationError::InvalidPasswordHash)
        );
    }

    #[test]
    fn validation_enforces_depth_and_text_rules() {
        let mut layers = Vec::new();
        for _ in 0..5 {
            let mut layer = EapLayer::new(EapMethod::Peap);
            layer.tls = Some(empty_tls());
            layers.push(layer);
        }
        layers.push(password_layer(EapMethod::Gtc, "user", "secret"));
        assert_eq!(
            profile(layers).validate(),
            Err(ValidationError::TooManyEapLayers)
        );

        let mut layer = password_layer(EapMethod::Mschapv2, "user\0", "secret");
        assert_eq!(
            profile(vec![layer]).validate(),
            Err(ValidationError::NulInText)
        );
        layer = password_layer(EapMethod::Mschapv2, "user", "secret");
        layer.password_hash = Some(Secret::new("0123456789abcdef0123456789abcdef"));
        assert_eq!(
            profile(vec![layer]).validate(),
            Err(ValidationError::PasswordConflict)
        );

        let layer = password_layer(EapMethod::Mschapv2, &"x".repeat(254), "secret");
        assert_eq!(
            profile(vec![layer]).validate(),
            Err(ValidationError::TextTooLong)
        );
    }

    #[test]
    fn maximum_nested_profile_is_valid() {
        let mut layers = Vec::new();
        for _ in 0..4 {
            let mut layer = EapLayer::new(EapMethod::Peap);
            layer.tls = Some(empty_tls());
            layers.push(layer);
        }
        layers.push(password_layer(EapMethod::Mschapv2, "user", "secret"));
        assert_eq!(profile(layers).validate(), Ok(()));
    }

    #[test]
    fn peap_and_ttls_reject_outer_client_credentials() {
        let cert_and_key = TlsClientCredentials::CertificateAndKey {
            certificate: std::path::PathBuf::from("/etc/ssl/client.pem"),
            key: std::path::PathBuf::from("/etc/ssl/client.key"),
        };
        let pkcs12 = TlsClientCredentials::Pkcs12 {
            bundle: std::path::PathBuf::from("/etc/ssl/client.p12"),
        };

        for client in [cert_and_key, pkcs12] {
            let mut peap = EapLayer::new(EapMethod::Peap);
            peap.tls = Some(TlsConfig {
                client,
                ..empty_tls()
            });
            let peap_profile = profile(vec![
                peap,
                password_layer(EapMethod::Mschapv2, "user", "secret"),
            ]);
            assert_eq!(
                peap_profile.validate(),
                Err(ValidationError::MethodHasUnexpectedFields)
            );
        }

        let cert_and_key = TlsClientCredentials::CertificateAndKey {
            certificate: std::path::PathBuf::from("/etc/ssl/client.pem"),
            key: std::path::PathBuf::from("/etc/ssl/client.key"),
        };
        let pkcs12 = TlsClientCredentials::Pkcs12 {
            bundle: std::path::PathBuf::from("/etc/ssl/client.p12"),
        };

        for client in [cert_and_key, pkcs12] {
            let mut ttls = EapLayer::new(EapMethod::Ttls);
            ttls.tls = Some(TlsConfig {
                client,
                ..empty_tls()
            });
            let mut child = EapLayer::new(EapMethod::TunneledPap);
            child.identity = Some(String::from("user"));
            child.password = Some(Secret::new("secret"));
            let ttls_profile = profile(vec![ttls, child]);
            assert_eq!(
                ttls_profile.validate(),
                Err(ValidationError::MethodHasUnexpectedFields)
            );
        }
    }

    #[test]
    fn peap_and_ttls_reject_outer_client_key_passphrase() {
        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(TlsConfig {
            client_key_passphrase: Some(Secret::new("outer-passphrase")),
            ..empty_tls()
        });
        let peap_profile = profile(vec![
            peap,
            password_layer(EapMethod::Mschapv2, "user", "secret"),
        ]);
        assert_eq!(
            peap_profile.validate(),
            Err(ValidationError::MethodHasUnexpectedFields)
        );

        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(TlsConfig {
            client_key_passphrase: Some(Secret::new("outer-passphrase")),
            ..empty_tls()
        });
        let mut child = EapLayer::new(EapMethod::TunneledPap);
        child.identity = Some(String::from("user"));
        child.password = Some(Secret::new("secret"));
        let ttls_profile = profile(vec![ttls, child]);
        assert_eq!(
            ttls_profile.validate(),
            Err(ValidationError::MethodHasUnexpectedFields)
        );
    }

    #[test]
    fn direct_tls_and_wfa_tls_allow_client_credentials() {
        for method in [EapMethod::Tls, EapMethod::WfaTls] {
            let mut layer_cert_key = EapLayer::new(method);
            layer_cert_key.identity = Some(String::from("user"));
            layer_cert_key.tls = Some(TlsConfig {
                client: TlsClientCredentials::CertificateAndKey {
                    certificate: std::path::PathBuf::from("/etc/ssl/client.pem"),
                    key: std::path::PathBuf::from("/etc/ssl/client.key"),
                },
                client_key_passphrase: Some(Secret::new("passphrase")),
                ..empty_tls()
            });
            assert_eq!(profile(vec![layer_cert_key]).validate(), Ok(()));

            let mut layer_pkcs12 = EapLayer::new(method);
            layer_pkcs12.identity = Some(String::from("user"));
            layer_pkcs12.tls = Some(TlsConfig {
                client: TlsClientCredentials::Pkcs12 {
                    bundle: std::path::PathBuf::from("/etc/ssl/client.p12"),
                },
                client_key_passphrase: Some(Secret::new("passphrase")),
                ..empty_tls()
            });
            assert_eq!(profile(vec![layer_pkcs12]).validate(), Ok(()));
        }
    }
}
