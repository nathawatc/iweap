use super::eap::{EapLayer, EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig};
use std::fmt;
use std::path::Path;

pub const MAX_SSID_BYTES: usize = 32;
pub const MAX_EAP_IDENTITY_BYTES: usize = 253;
pub const MAX_EAP_DEPTH: usize = 4;
pub const MAX_EAP_LAYERS: usize = MAX_EAP_DEPTH + 1;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_SECRET_BYTES: usize = 4096;
const MAX_GTC_PASSWORD_BYTES: usize = 2048;
pub const MAX_DOMAIN_MASK_BYTES: usize = 1024;
pub const PASSWORD_HASH_HEX_CHARS: usize = 32;

const IWD_EAP_SETTING_BUFFER_SIZE: usize = 64;
const IWD_TLS_PREFIX_BUFFER_SIZE: usize = 32;
const IWD_SETTING_BUFFER_SIZE: usize = 72;
const IWD_TTLS_NON_EAP_SETTING_BUFFER_SIZE: usize = 128;

const IWD_EAP_PREFIX: &str = "EAP-";
const PEAP_PHASE1_SUFFIX: &str = "PEAP-";
const PEAP_PHASE2_SUFFIX: &str = "PEAP-Phase2-";
const TTLS_PHASE1_SUFFIX: &str = "TTLS-";
const TTLS_PHASE2_SUFFIX: &str = "TTLS-Phase2-";
const TLS_SUFFIX: &str = "TLS-";

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
    GtcPasswordTooLong,
    MschapPasswordNotUcs2,
    SettingPrefixTooLong,
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
            Self::GtcPasswordTooLong => {
                return write!(
                    f,
                    "GTC password exceeds IWD's {MAX_GTC_PASSWORD_BYTES}-byte limit"
                );
            }
            Self::MschapPasswordNotUcs2 => {
                "MSCHAP password contains characters not representable in UCS-2"
            }
            Self::SettingPrefixTooLong => {
                "nested EAP configuration exceeds IWD's supported setting-prefix length"
            }
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
        let consumed = self.validate_layer(0, IWD_EAP_PREFIX)?;
        if consumed != self.layers.len() {
            return Err(ValidationError::UnexpectedNestedEap);
        }
        Ok(())
    }

    fn validate_layer(&self, index: usize, prefix: &str) -> Result<usize, ValidationError> {
        let layer = self
            .layers
            .get(index)
            .ok_or(ValidationError::MissingPhase2)?;

        if index == 0 {
            if !layer.method.is_outer_method() {
                return Err(ValidationError::InvalidOuterMethod);
            }
        } else if !layer.method.is_inner_method() {
            return Err(ValidationError::InvalidInnerMethod);
        }
        self.validate_layer_fields(layer)?;
        validate_iwd_prefix_compatibility(layer, prefix)?;

        if layer.method.is_tunnel_method() {
            let child_index = index + 1;
            let child = self
                .layers
                .get(child_index)
                .ok_or(ValidationError::MissingPhase2)?;
            if layer.method == EapMethod::Peap && child.method.is_tunneled() {
                return Err(ValidationError::InvalidTunneledMethod);
            }
            let child_prefix = match layer.method {
                EapMethod::Peap => format!("{prefix}{PEAP_PHASE2_SUFFIX}"),
                EapMethod::Ttls => format!("{prefix}{TTLS_PHASE2_SUFFIX}"),
                _ => unreachable!(),
            };
            if layer.method == EapMethod::Ttls && child.method.is_tunneled() {
                self.validate_tunneled_fields(child)?;
                validate_iwd_prefix_compatibility(child, &child_prefix)?;
                return Ok(child_index + 1);
            }
            return self.validate_layer(child_index, &child_prefix);
        }
        if index + 1 != self.layers.len() {
            return Err(ValidationError::UnexpectedNestedEap);
        }
        Ok(index + 1)
    }

    fn validate_layer_fields(&self, layer: &EapLayer) -> Result<(), ValidationError> {
        validate_eap_identity(layer.identity.as_deref())?;
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

fn check_c_buffer_fit(formatted_len: usize, buffer_size: usize) -> Result<(), ValidationError> {
    match formatted_len.checked_add(1) {
        Some(required) if required <= buffer_size => Ok(()),
        _ => Err(ValidationError::SettingPrefixTooLong),
    }
}

fn validate_tls_common_iwd_compatibility(prefix_len: usize) -> Result<(), ValidationError> {
    for suffix in ["CACert", "ServerDomainMask", "FastReauthentication"] {
        check_c_buffer_fit(prefix_len + suffix.len(), IWD_SETTING_BUFFER_SIZE)?;
    }
    Ok(())
}

fn validate_iwd_prefix_compatibility(
    layer: &EapLayer,
    prefix: &str,
) -> Result<(), ValidationError> {
    validate_iwd_method_prefix(
        layer.method,
        prefix,
        layer.identity.is_some(),
        layer.password.is_some() || layer.password_hash.is_some(),
    )
}

fn validate_iwd_method_prefix(
    method: EapMethod,
    prefix: &str,
    stored_identity: bool,
    stored_password: bool,
) -> Result<(), ValidationError> {
    if method.is_tunneled() {
        check_c_buffer_fit(
            prefix.len() + "Identity".len(),
            IWD_TTLS_NON_EAP_SETTING_BUFFER_SIZE,
        )?;
        check_c_buffer_fit(
            prefix.len() + "Password".len(),
            IWD_TTLS_NON_EAP_SETTING_BUFFER_SIZE,
        )?;
        return Ok(());
    }

    check_c_buffer_fit(prefix.len() + "Method".len(), IWD_EAP_SETTING_BUFFER_SIZE)?;
    if !method.is_sim_method() {
        check_c_buffer_fit(prefix.len() + "Identity".len(), IWD_EAP_SETTING_BUFFER_SIZE)?;
    }

    match method {
        EapMethod::Peap => {
            check_c_buffer_fit(
                prefix.len() + PEAP_PHASE2_SUFFIX.len(),
                IWD_SETTING_BUFFER_SIZE,
            )?;
            let tls_prefix_len = prefix.len() + PEAP_PHASE1_SUFFIX.len();
            check_c_buffer_fit(tls_prefix_len, IWD_SETTING_BUFFER_SIZE)?;
            validate_tls_common_iwd_compatibility(tls_prefix_len)?;
        }
        EapMethod::Ttls => {
            let tls_prefix_len = prefix.len() + TTLS_PHASE1_SUFFIX.len();
            check_c_buffer_fit(tls_prefix_len, IWD_SETTING_BUFFER_SIZE)?;
            validate_tls_common_iwd_compatibility(tls_prefix_len)?;
            check_c_buffer_fit(
                prefix.len() + "TTLS-Phase2-Method".len(),
                IWD_SETTING_BUFFER_SIZE,
            )?;
            check_c_buffer_fit(
                prefix.len() + TTLS_PHASE2_SUFFIX.len(),
                IWD_SETTING_BUFFER_SIZE,
            )?;
        }
        EapMethod::Tls | EapMethod::WfaTls => {
            let tls_prefix_len = prefix.len() + TLS_SUFFIX.len();
            check_c_buffer_fit(tls_prefix_len, IWD_TLS_PREFIX_BUFFER_SIZE)?;
            validate_tls_common_iwd_compatibility(tls_prefix_len)?;
            for suffix in [
                "ClientCert",
                "ClientKey",
                "ClientKeyBundle",
                "ClientKeyPassphrase",
            ] {
                check_c_buffer_fit(tls_prefix_len + suffix.len(), IWD_SETTING_BUFFER_SIZE)?;
            }
        }
        EapMethod::Mschapv2 => {
            check_c_buffer_fit(prefix.len() + "Identity".len(), IWD_EAP_SETTING_BUFFER_SIZE)?;
            check_c_buffer_fit(prefix.len() + "Password".len(), IWD_EAP_SETTING_BUFFER_SIZE)?;
            if stored_identity {
                check_c_buffer_fit(
                    prefix.len() + "Password-Hash".len(),
                    IWD_EAP_SETTING_BUFFER_SIZE,
                )?;
            }
        }
        EapMethod::Gtc => {
            check_c_buffer_fit(prefix.len() + "Identity".len(), IWD_SETTING_BUFFER_SIZE)?;
            check_c_buffer_fit(prefix.len() + "Password".len(), IWD_SETTING_BUFFER_SIZE)?;
            if !stored_password {
                check_c_buffer_fit(prefix.len() + "GTC-Secret".len(), IWD_SETTING_BUFFER_SIZE)?;
            }
        }
        EapMethod::Pwd => {
            check_c_buffer_fit(prefix.len() + "Identity".len(), IWD_SETTING_BUFFER_SIZE)?;
            check_c_buffer_fit(prefix.len() + "Password".len(), IWD_SETTING_BUFFER_SIZE)?;
        }
        EapMethod::Md5 => {
            check_c_buffer_fit(prefix.len() + "Identity".len(), IWD_SETTING_BUFFER_SIZE)?;
            check_c_buffer_fit(prefix.len() + "Password".len(), IWD_SETTING_BUFFER_SIZE)?;
            if !stored_password {
                check_c_buffer_fit(prefix.len() + "MD5-Secret".len(), IWD_SETTING_BUFFER_SIZE)?;
            }
        }
        EapMethod::Sim | EapMethod::Aka | EapMethod::AkaPrime => {}
        _ => {}
    }

    Ok(())
}

pub fn is_eap_method_supported_for_layers(
    method: EapMethod,
    layers: &[EapLayer],
    store_credentials: bool,
) -> bool {
    is_eap_method_supported_for_layers_with_identity(method, layers, store_credentials, false)
}

pub fn is_eap_method_supported_for_layers_with_identity(
    method: EapMethod,
    layers: &[EapLayer],
    store_credentials: bool,
    identity_present: bool,
) -> bool {
    if layers.is_empty() || layers.iter().any(|layer| !layer.method.is_tunnel_method()) {
        return false;
    }
    if method.is_tunneled() {
        if layers.last().map(|layer| layer.method) != Some(EapMethod::Ttls) {
            return false;
        }
    } else if !method.is_inner_method() {
        return false;
    }

    let prefix = compute_effective_prefix_for_layers(layers);
    let stored_identity = method.is_password_method() && (identity_present || store_credentials);
    let stored_password = store_credentials && method.is_password_method();
    validate_iwd_method_prefix(method, &prefix, stored_identity, stored_password).is_ok()
}

fn compute_effective_prefix_for_layers(layers: &[EapLayer]) -> String {
    let mut prefix = String::from(IWD_EAP_PREFIX);
    for layer in layers {
        prefix.push_str(match layer.method {
            EapMethod::Peap => PEAP_PHASE2_SUFFIX,
            EapMethod::Ttls => TTLS_PHASE2_SUFFIX,
            _ => unreachable!(),
        });
    }
    prefix
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
        validate_method_password(layer.method, password)?;
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

fn validate_method_password(method: EapMethod, password: &Secret) -> Result<(), ValidationError> {
    if method.has_gtc_password_limit() && password.as_str().len() > MAX_GTC_PASSWORD_BYTES {
        return Err(ValidationError::GtcPasswordTooLong);
    }
    if method.uses_mschap_password_hashing() && !is_ucs2_representable(password.as_str()) {
        return Err(ValidationError::MschapPasswordNotUcs2);
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

fn is_ucs2_representable(value: &str) -> bool {
    value
        .chars()
        .all(|character| u32::from(character) <= 0xffff)
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
        assert_eq!(
            profile(vec![EapLayer::new(EapMethod::TunneledPap)]).validate(),
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

    fn nested_peap_layers(count: usize) -> Vec<EapLayer> {
        (0..count)
            .map(|_| {
                let mut layer = EapLayer::new(EapMethod::Peap);
                layer.tls = Some(empty_tls());
                layer
            })
            .collect()
    }

    #[test]
    fn mschap_prefix_boundaries_follow_iwd_credential_branches() {
        let stored = password_layer(EapMethod::Mschapv2, "user", "secret");
        assert_eq!(
            validate_iwd_prefix_compatibility(&stored, &"a".repeat(50)),
            Ok(())
        );
        assert_eq!(
            validate_iwd_prefix_compatibility(&stored, &"a".repeat(51)),
            Err(ValidationError::SettingPrefixTooLong)
        );

        let agent = EapLayer::new(EapMethod::Mschapv2);
        assert_eq!(
            validate_iwd_prefix_compatibility(&agent, &"a".repeat(55)),
            Ok(())
        );
        assert_eq!(
            validate_iwd_prefix_compatibility(&agent, &"a".repeat(56)),
            Err(ValidationError::SettingPrefixTooLong)
        );

        let nested = nested_peap_layers(4);
        assert!(is_eap_method_supported_for_layers(
            EapMethod::Mschapv2,
            &nested,
            false
        ));
        assert!(!is_eap_method_supported_for_layers_with_identity(
            EapMethod::Mschapv2,
            &nested,
            false,
            true
        ));
        assert!(!is_eap_method_supported_for_layers(
            EapMethod::Mschapv2,
            &nested,
            true
        ));
    }

    #[test]
    fn nested_mschap_credentials_follow_iwd_credential_branches() {
        let mut stored = nested_peap_layers(4);
        stored.push(password_layer(EapMethod::Mschapv2, "user", "secret"));
        assert_eq!(
            profile(stored).validate(),
            Err(ValidationError::SettingPrefixTooLong)
        );

        let mut agent = nested_peap_layers(4);
        agent.push(EapLayer::new(EapMethod::Mschapv2));
        assert_eq!(profile(agent).validate(), Ok(()));
    }

    #[test]
    fn nested_tls_prefixes_reject_only_iwd_unsafe_paths() {
        for method in [EapMethod::Tls, EapMethod::WfaTls] {
            let mut layers = nested_peap_layers(2);
            layers.push({
                let mut layer = EapLayer::new(method);
                layer.tls = Some(empty_tls());
                layer
            });
            assert_eq!(
                profile(layers).validate(),
                Err(ValidationError::SettingPrefixTooLong)
            );
        }

        for (outer, inner) in [EapMethod::Peap, EapMethod::Ttls]
            .into_iter()
            .map(|method| {
                let mut layer = EapLayer::new(method);
                layer.tls = Some(empty_tls());
                layer
            })
            .zip([EapMethod::Tls, EapMethod::Tls])
        {
            let mut layers = vec![outer];
            let mut inner_layer = EapLayer::new(inner);
            inner_layer.tls = Some(empty_tls());
            layers.push(inner_layer);
            assert_eq!(profile(layers).validate(), Ok(()));
        }

        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(empty_tls());
        let mut nested_ttls = EapLayer::new(EapMethod::Ttls);
        nested_ttls.tls = Some(empty_tls());
        let mut tls = EapLayer::new(EapMethod::Tls);
        tls.tls = Some(empty_tls());
        assert_eq!(
            profile(vec![ttls, nested_ttls, tls]).validate(),
            Err(ValidationError::SettingPrefixTooLong)
        );
    }

    #[test]
    fn tls_common_boundary_applies_without_optional_tls_fields() {
        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(empty_tls());
        assert_eq!(
            validate_iwd_prefix_compatibility(&peap, &"a".repeat(46)),
            Ok(())
        );
        assert_eq!(
            validate_iwd_prefix_compatibility(&peap, &"a".repeat(47)),
            Err(ValidationError::SettingPrefixTooLong)
        );
    }

    #[test]
    fn deeply_nested_72_byte_eap_methods_remain_valid() {
        for method in [EapMethod::Gtc, EapMethod::Pwd, EapMethod::Md5] {
            let mut layers = nested_peap_layers(4);
            layers.push(password_layer(method, "user", "secret"));
            assert_eq!(profile(layers).validate(), Ok(()));
        }
    }

    #[test]
    fn ttls_tunneled_methods_remain_valid() {
        for method in [
            EapMethod::TunneledPap,
            EapMethod::TunneledChap,
            EapMethod::TunneledMschap,
            EapMethod::TunneledMschapv2,
        ] {
            let mut ttls = EapLayer::new(EapMethod::Ttls);
            ttls.tls = Some(empty_tls());
            assert_eq!(
                profile(vec![ttls, password_layer(method, "user", "secret")]).validate(),
                Ok(())
            );
        }

        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(empty_tls());
        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(empty_tls());
        assert_eq!(
            profile(vec![
                peap,
                ttls,
                password_layer(EapMethod::TunneledPap, "user", "secret"),
            ])
            .validate(),
            Ok(())
        );
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

    #[test]
    fn ucs2_representability_check_identifies_boundary_characters() {
        assert!(is_ucs2_representable(""));
        assert!(is_ucs2_representable("ascii"));
        assert!(is_ucs2_representable("pässword"));
        assert!(is_ucs2_representable("密碼"));
        assert!(is_ucs2_representable("\u{ffff}"));
        assert!(!is_ucs2_representable("\u{10000}"));
        assert!(!is_ucs2_representable("abc😀def"));
    }

    #[test]
    fn gtc_password_limit_enforces_exact_utf8_byte_boundary() {
        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(empty_tls());

        // 1. 2048 ASCII bytes -> PASS
        let pass_2048 = "a".repeat(2048);
        let valid_profile = profile(vec![
            peap,
            password_layer(EapMethod::Gtc, "user", &pass_2048),
        ]);
        assert_eq!(valid_profile.validate(), Ok(()));

        // 2. 2049 ASCII bytes -> FAIL
        let mut peap2 = EapLayer::new(EapMethod::Peap);
        peap2.tls = Some(empty_tls());
        let fail_2049 = "a".repeat(2049);
        let invalid_profile = profile(vec![
            peap2,
            password_layer(EapMethod::Gtc, "user", &fail_2049),
        ]);
        assert_eq!(
            invalid_profile.validate(),
            Err(ValidationError::GtcPasswordTooLong)
        );

        // 3. UTF-8 byte boundary with multibyte characters:
        // 'é' is 2 bytes in UTF-8. 1025 characters = 1025 chars < 2048, but 2050 bytes > 2048.
        let mut peap3 = EapLayer::new(EapMethod::Peap);
        peap3.tls = Some(empty_tls());
        let multibyte_pwd = "é".repeat(1025);
        assert!(multibyte_pwd.chars().count() < 2048);
        assert!(multibyte_pwd.len() > 2048);
        let invalid_multibyte = profile(vec![
            peap3,
            password_layer(EapMethod::Gtc, "user", &multibyte_pwd),
        ]);
        assert_eq!(
            invalid_multibyte.validate(),
            Err(ValidationError::GtcPasswordTooLong)
        );

        // Multibyte characters fitting within 2048 bytes: 1024 'é' = 2048 bytes -> PASS
        let mut peap4 = EapLayer::new(EapMethod::Peap);
        peap4.tls = Some(empty_tls());
        let multibyte_2048 = "é".repeat(1024);
        assert_eq!(multibyte_2048.len(), 2048);
        let valid_multibyte = profile(vec![
            peap4,
            password_layer(EapMethod::Gtc, "user", &multibyte_2048),
        ]);
        assert_eq!(valid_multibyte.validate(), Ok(()));

        // 4. Nested GTC inside TTLS
        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(empty_tls());
        let ttls_gtc_valid = profile(vec![
            ttls,
            password_layer(EapMethod::Gtc, "user", &pass_2048),
        ]);
        assert_eq!(ttls_gtc_valid.validate(), Ok(()));

        let mut ttls2 = EapLayer::new(EapMethod::Ttls);
        ttls2.tls = Some(empty_tls());
        let ttls_gtc_invalid = profile(vec![
            ttls2,
            password_layer(EapMethod::Gtc, "user", &fail_2049),
        ]);
        assert_eq!(
            ttls_gtc_invalid.validate(),
            Err(ValidationError::GtcPasswordTooLong)
        );
    }

    #[test]
    fn mschap_family_enforces_ucs2_character_repertoire() {
        // Direct MSCHAPV2 BMP Unicode passes (accented, CJK)
        assert_eq!(
            profile(vec![password_layer(
                EapMethod::Mschapv2,
                "user",
                "pässword"
            )])
            .validate(),
            Ok(())
        );
        assert_eq!(
            profile(vec![password_layer(EapMethod::Mschapv2, "user", "密碼")]).validate(),
            Ok(())
        );

        // Direct MSCHAPV2 supplementary-plane Unicode fails
        let invalid = profile(vec![password_layer(
            EapMethod::Mschapv2,
            "user",
            "abc😀def",
        )]);
        assert_eq!(
            invalid.validate(),
            Err(ValidationError::MschapPasswordNotUcs2)
        );
        // Error message does not leak secret
        let err = invalid.validate().unwrap_err();
        let display = format!("{err}");
        assert!(!display.contains("abc"));
        assert!(!display.contains("😀"));
        assert!(!display.contains("def"));

        // Direct MSCHAPV2 with password hash is unaffected by UCS-2 rule
        let mut hash_layer = EapLayer::new(EapMethod::Mschapv2);
        hash_layer.identity = Some(String::from("user"));
        hash_layer.password_hash = Some(Secret::new("0123456789abcdef0123456789abcdef"));
        assert_eq!(profile(vec![hash_layer]).validate(), Ok(()));

        // PEAP -> MSCHAPV2
        let make_peap = || {
            let mut peap = EapLayer::new(EapMethod::Peap);
            peap.tls = Some(empty_tls());
            peap
        };
        assert_eq!(
            profile(vec![
                make_peap(),
                password_layer(EapMethod::Mschapv2, "user", "pässword")
            ])
            .validate(),
            Ok(())
        );
        assert_eq!(
            profile(vec![
                make_peap(),
                password_layer(EapMethod::Mschapv2, "user", "abc😀def")
            ])
            .validate(),
            Err(ValidationError::MschapPasswordNotUcs2)
        );

        // TTLS -> EAP-MSCHAPV2
        let make_ttls = || {
            let mut ttls = EapLayer::new(EapMethod::Ttls);
            ttls.tls = Some(empty_tls());
            ttls
        };
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::Mschapv2, "user", "pässword")
            ])
            .validate(),
            Ok(())
        );
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::Mschapv2, "user", "abc😀def")
            ])
            .validate(),
            Err(ValidationError::MschapPasswordNotUcs2)
        );

        // TTLS Tunneled-MSCHAP
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledMschap, "user", "pässword")
            ])
            .validate(),
            Ok(())
        );
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledMschap, "user", "abc😀def")
            ])
            .validate(),
            Err(ValidationError::MschapPasswordNotUcs2)
        );

        // TTLS Tunneled-MSCHAPv2
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledMschapv2, "user", "pässword")
            ])
            .validate(),
            Ok(())
        );
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledMschapv2, "user", "abc😀def")
            ])
            .validate(),
            Err(ValidationError::MschapPasswordNotUcs2)
        );
    }

    #[test]
    fn non_mschap_methods_and_omitted_credentials_are_unaffected() {
        let make_ttls = || {
            let mut ttls = EapLayer::new(EapMethod::Ttls);
            ttls.tls = Some(empty_tls());
            ttls
        };
        let make_peap = || {
            let mut peap = EapLayer::new(EapMethod::Peap);
            peap.tls = Some(empty_tls());
            peap
        };

        // Tunneled-PAP accepts supplementary-plane Unicode
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledPap, "user", "pap_secret_😀")
            ])
            .validate(),
            Ok(())
        );

        // Tunneled-CHAP accepts supplementary-plane Unicode
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledChap, "user", "chap_secret_😀")
            ])
            .validate(),
            Ok(())
        );

        // MD5 accepts supplementary-plane Unicode
        assert_eq!(
            profile(vec![
                make_peap(),
                password_layer(EapMethod::Md5, "user", "md5_secret_😀")
            ])
            .validate(),
            Ok(())
        );

        // PWD accepts supplementary-plane Unicode
        assert_eq!(
            profile(vec![
                make_peap(),
                password_layer(EapMethod::Pwd, "user", "pwd_secret_😀")
            ])
            .validate(),
            Ok(())
        );

        // Omitted credentials (agent asks later) remain valid across all methods
        let mut omitted_gtc = EapLayer::new(EapMethod::Gtc);
        omitted_gtc.identity = Some(String::from("user"));
        assert_eq!(profile(vec![make_peap(), omitted_gtc]).validate(), Ok(()));

        let mut omitted_mschap = EapLayer::new(EapMethod::Mschapv2);
        omitted_mschap.identity = Some(String::from("user"));
        assert_eq!(profile(vec![omitted_mschap]).validate(), Ok(()));

        let mut omitted_tunneled_mschap = EapLayer::new(EapMethod::TunneledMschap);
        omitted_tunneled_mschap.identity = Some(String::from("user"));
        assert_eq!(
            profile(vec![make_ttls(), omitted_tunneled_mschap]).validate(),
            Ok(())
        );

        // Generic maximum (MAX_SECRET_BYTES = 4096) remains enforced
        let oversized = "a".repeat(MAX_SECRET_BYTES + 1);
        assert_eq!(
            profile(vec![
                make_ttls(),
                password_layer(EapMethod::TunneledPap, "user", &oversized)
            ])
            .validate(),
            Err(ValidationError::SecretTooLong)
        );
        assert_eq!(
            profile(vec![password_layer(
                EapMethod::Mschapv2,
                "user",
                &oversized
            )])
            .validate(),
            Err(ValidationError::SecretTooLong)
        );
    }
}
