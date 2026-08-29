use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;
use zvariant::Type;

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

#[derive(Eq, PartialEq)]
pub struct PlaintextProfile(String);

impl PlaintextProfile {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for PlaintextProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted profile>")
    }
}

impl Drop for PlaintextProfile {
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
            return layer
                .tls
                .as_ref()
                .ok_or(ValidationError::MissingTlsConfiguration)?
                .validate();
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

    pub fn profile_filename(&self) -> Result<String, ValidationError> {
        validate_ssid(&self.ssid)?;
        Ok(profile_filename_for_ssid(&self.ssid))
    }

    pub fn redacted_config(&self) -> Result<String, ValidationError> {
        self.render(false)
    }

    pub fn serialize_plain(&self) -> Result<PlaintextProfile, ValidationError> {
        self.render(true).map(PlaintextProfile)
    }

    pub fn into_wire(self) -> Result<WireProfile, ValidationError> {
        self.validate()?;
        let layers = self
            .layers
            .into_iter()
            .map(WireEapLayer::from_layer)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WireProfile {
            ssid: self.ssid,
            layers,
        })
    }

    fn render(&self, include_secrets: bool) -> Result<String, ValidationError> {
        self.validate()?;
        let mut output = String::from("[Security]\n");
        self.render_layer(&mut output, 0, "EAP-", include_secrets)?;
        Ok(output)
    }

    fn render_layer(
        &self,
        output: &mut String,
        index: usize,
        prefix: &str,
        include_secrets: bool,
    ) -> Result<(), ValidationError> {
        let layer = &self.layers[index];
        append_setting(output, &format!("{prefix}Method"), layer.method.name())?;
        if let Some(identity) = layer.identity.as_deref() {
            append_setting(output, &format!("{prefix}Identity"), identity)?;
        }

        match layer.method {
            method if method.is_sim_method() => {}
            method if method.is_password_method() => {
                if let Some(password) = layer.password.as_ref() {
                    append_secret_setting(
                        output,
                        &format!("{prefix}Password"),
                        password,
                        include_secrets,
                    )?;
                }
                if let Some(password_hash) = layer.password_hash.as_ref() {
                    append_secret_setting(
                        output,
                        &format!("{prefix}Password-Hash"),
                        password_hash,
                        include_secrets,
                    )?;
                }
            }
            method if method.is_tls_method() => {
                let tls = layer
                    .tls
                    .as_ref()
                    .ok_or(ValidationError::MissingTlsConfiguration)?;
                render_tls(output, &format!("{prefix}TLS-"), tls, include_secrets)?;
            }
            EapMethod::Peap => {
                let tls = layer
                    .tls
                    .as_ref()
                    .ok_or(ValidationError::MissingTlsConfiguration)?;
                render_tls(output, &format!("{prefix}PEAP-"), tls, include_secrets)?;
                self.render_layer(
                    output,
                    index + 1,
                    &format!("{prefix}PEAP-Phase2-"),
                    include_secrets,
                )?;
            }
            EapMethod::Ttls => {
                let tls = layer
                    .tls
                    .as_ref()
                    .ok_or(ValidationError::MissingTlsConfiguration)?;
                render_tls(output, &format!("{prefix}TTLS-"), tls, include_secrets)?;
                let child = &self.layers[index + 1];
                if child.method.is_tunneled() {
                    append_setting(
                        output,
                        &format!("{prefix}TTLS-Phase2-Method"),
                        child.method.name(),
                    )?;
                    if let Some(identity) = child.identity.as_deref() {
                        append_setting(output, &format!("{prefix}TTLS-Phase2-Identity"), identity)?;
                    }
                    if let Some(password) = child.password.as_ref() {
                        append_secret_setting(
                            output,
                            &format!("{prefix}TTLS-Phase2-Password"),
                            password,
                            include_secrets,
                        )?;
                    }
                } else {
                    self.render_layer(
                        output,
                        index + 1,
                        &format!("{prefix}TTLS-Phase2-"),
                        include_secrets,
                    )?;
                }
            }
            method if method.is_tunneled() => {
                append_setting(output, &format!("{prefix}Method"), method.name())?;
                if let Some(password) = layer.password.as_ref() {
                    append_secret_setting(
                        output,
                        &format!("{prefix}Password"),
                        password,
                        include_secrets,
                    )?;
                }
            }
            _ => return Err(ValidationError::InvalidInnerMethod),
        }
        Ok(())
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

fn validate_text(value: &str, max_bytes: usize) -> Result<(), ValidationError> {
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

fn validate_path(path: &Path) -> Result<(), ValidationError> {
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

pub fn escape_iwd_value(value: &str) -> Result<String, ValidationError> {
    validate_text(value, MAX_TEXT_BYTES)?;
    let mut escaped = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            ' ' if index == 0 => escaped.push_str("\\s"),
            _ => escaped.push(character),
        }
    }
    Ok(escaped)
}

pub fn profile_filename_for_ssid(ssid: &str) -> String {
    if ssid
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
    {
        return format!("{ssid}.8021x");
    }

    let mut hex = String::with_capacity(ssid.len() * 2);
    for byte in ssid.as_bytes() {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("={hex}.8021x")
}

fn append_setting(output: &mut String, key: &str, value: &str) -> Result<(), ValidationError> {
    let escaped = escape_iwd_value(value)?;
    output.push_str(key);
    output.push('=');
    output.push_str(&escaped);
    output.push('\n');
    Ok(())
}

fn append_secret_setting(
    output: &mut String,
    key: &str,
    secret: &Secret,
    include_secret: bool,
) -> Result<(), ValidationError> {
    let value = if include_secret {
        secret.as_str()
    } else {
        "<redacted>"
    };
    append_setting(output, key, value)
}

fn render_tls(
    output: &mut String,
    prefix: &str,
    tls: &TlsConfig,
    include_secrets: bool,
) -> Result<(), ValidationError> {
    if let Some(ca_cert) = tls.ca_cert.as_deref() {
        append_path_setting(output, &format!("{prefix}CACert"), ca_cert)?;
    }
    if let Some(mask) = tls.server_domain_mask.as_deref() {
        append_setting(output, &format!("{prefix}ServerDomainMask"), mask)?;
    }
    if let Some(fast_reauthentication) = tls.fast_reauthentication {
        append_setting(
            output,
            &format!("{prefix}FastReauthentication"),
            if fast_reauthentication {
                "true"
            } else {
                "false"
            },
        )?;
    }
    match &tls.client {
        TlsClientCredentials::None => {}
        TlsClientCredentials::CertificateAndKey { certificate, key } => {
            append_path_setting(output, &format!("{prefix}ClientCert"), certificate)?;
            append_path_setting(output, &format!("{prefix}ClientKey"), key)?;
        }
        TlsClientCredentials::Pkcs12 { bundle } => {
            append_path_setting(output, &format!("{prefix}ClientKeyBundle"), bundle)?;
        }
    }
    if let Some(passphrase) = tls.client_key_passphrase.as_ref() {
        append_secret_setting(
            output,
            &format!("{prefix}ClientKeyPassphrase"),
            passphrase,
            include_secrets,
        )?;
    }
    Ok(())
}

fn append_path_setting(output: &mut String, key: &str, path: &Path) -> Result<(), ValidationError> {
    let value = path.to_str().ok_or(ValidationError::InvalidPath)?;
    append_setting(output, key, value)
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct WireProfile {
    pub ssid: String,
    pub layers: Vec<WireEapLayer>,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct WireEapLayer {
    pub method: u8,
    pub identity: String,
    pub password: Secret,
    pub password_hash: Secret,
    pub tls: WireTlsConfig,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct WireTlsConfig {
    pub ca_cert: String,
    pub server_domain_mask: String,
    pub fast_reauthentication: i8,
    pub client_kind: u8,
    pub client_cert: String,
    pub client_key: String,
    pub client_bundle: String,
    pub client_key_passphrase: Secret,
}

impl Default for WireTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: String::new(),
            server_domain_mask: String::new(),
            fast_reauthentication: -1,
            client_kind: 0,
            client_cert: String::new(),
            client_key: String::new(),
            client_bundle: String::new(),
            client_key_passphrase: Secret::new(""),
        }
    }
}

impl WireEapLayer {
    fn from_layer(layer: EapLayer) -> Result<Self, ValidationError> {
        let tls = layer
            .tls
            .map(WireTlsConfig::from_tls)
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            method: layer.method.wire_code(),
            identity: layer.identity.unwrap_or_default(),
            password: layer.password.unwrap_or_else(|| Secret::new("")),
            password_hash: layer.password_hash.unwrap_or_else(|| Secret::new("")),
            tls,
        })
    }
}

impl WireTlsConfig {
    fn from_tls(tls: TlsConfig) -> Result<Self, ValidationError> {
        let (client_kind, client_cert, client_key, client_bundle) = match tls.client {
            TlsClientCredentials::None => (0, String::new(), String::new(), String::new()),
            TlsClientCredentials::CertificateAndKey { certificate, key } => (
                1,
                path_to_string(certificate)?,
                path_to_string(key)?,
                String::new(),
            ),
            TlsClientCredentials::Pkcs12 { bundle } => {
                (2, String::new(), String::new(), path_to_string(bundle)?)
            }
        };
        Ok(Self {
            ca_cert: tls
                .ca_cert
                .map(path_to_string)
                .transpose()?
                .unwrap_or_default(),
            server_domain_mask: tls.server_domain_mask.unwrap_or_default(),
            fast_reauthentication: tls
                .fast_reauthentication
                .map(|value| if value { 1 } else { 0 })
                .unwrap_or(-1),
            client_kind,
            client_cert,
            client_key,
            client_bundle,
            client_key_passphrase: tls.client_key_passphrase.unwrap_or_else(|| Secret::new("")),
        })
    }

    fn into_tls(self) -> Result<TlsConfig, ValidationError> {
        let ca_cert = optional_path(self.ca_cert)?;
        let server_domain_mask = optional_text(self.server_domain_mask);
        let fast_reauthentication = match self.fast_reauthentication {
            -1 => None,
            0 => Some(false),
            1 => Some(true),
            _ => return Err(ValidationError::InvalidBoolean),
        };
        let client = match self.client_kind {
            0 => {
                if !self.client_cert.is_empty()
                    || !self.client_key.is_empty()
                    || !self.client_bundle.is_empty()
                {
                    return Err(ValidationError::InvalidTlsConfiguration);
                }
                TlsClientCredentials::None
            }
            1 => {
                let certificate = required_path(self.client_cert)?;
                let key = required_path(self.client_key)?;
                if !self.client_bundle.is_empty() {
                    return Err(ValidationError::InvalidTlsConfiguration);
                }
                TlsClientCredentials::CertificateAndKey { certificate, key }
            }
            2 => {
                let bundle = required_path(self.client_bundle)?;
                if !self.client_cert.is_empty() || !self.client_key.is_empty() {
                    return Err(ValidationError::InvalidTlsConfiguration);
                }
                TlsClientCredentials::Pkcs12 { bundle }
            }
            _ => return Err(ValidationError::InvalidTlsConfiguration),
        };
        let client_key_passphrase = optional_secret(self.client_key_passphrase);
        Ok(TlsConfig {
            ca_cert,
            server_domain_mask,
            fast_reauthentication,
            client,
            client_key_passphrase,
        })
    }
}

impl TryFrom<WireProfile> for Profile {
    type Error = ValidationError;

    fn try_from(value: WireProfile) -> Result<Self, Self::Error> {
        if value.layers.len() > MAX_EAP_LAYERS {
            return Err(ValidationError::TooManyEapLayers);
        }
        let layers = value
            .layers
            .into_iter()
            .map(EapLayer::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let profile = Self::new(value.ssid, layers);
        profile.validate()?;
        Ok(profile)
    }
}

impl TryFrom<WireEapLayer> for EapLayer {
    type Error = ValidationError;

    fn try_from(value: WireEapLayer) -> Result<Self, Self::Error> {
        let method =
            EapMethod::from_wire(value.method).ok_or(ValidationError::InvalidInnerMethod)?;
        let identity = optional_text(value.identity);
        let password = optional_secret(value.password);
        let password_hash = optional_secret(value.password_hash);
        let tls = if value.tls == WireTlsConfig::default() {
            None
        } else {
            Some(value.tls.into_tls()?)
        };
        Ok(Self {
            method,
            identity,
            password,
            password_hash,
            tls,
        })
    }
}

impl PartialEq for WireTlsConfig {
    fn eq(&self, other: &Self) -> bool {
        self.ca_cert == other.ca_cert
            && self.server_domain_mask == other.server_domain_mask
            && self.fast_reauthentication == other.fast_reauthentication
            && self.client_kind == other.client_kind
            && self.client_cert == other.client_cert
            && self.client_key == other.client_key
            && self.client_bundle == other.client_bundle
            && self.client_key_passphrase.as_str() == other.client_key_passphrase.as_str()
    }
}

impl Eq for WireTlsConfig {}

fn optional_text(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn optional_secret(value: Secret) -> Option<Secret> {
    if value.is_empty() { None } else { Some(value) }
}

fn required_path(value: String) -> Result<PathBuf, ValidationError> {
    let path = PathBuf::from(value);
    validate_path(&path)?;
    Ok(path)
}

fn optional_path(value: String) -> Result<Option<PathBuf>, ValidationError> {
    if value.is_empty() {
        Ok(None)
    } else {
        required_path(value).map(Some)
    }
}

fn path_to_string(path: PathBuf) -> Result<String, ValidationError> {
    path.into_os_string()
        .into_string()
        .map_err(|_| ValidationError::InvalidPath)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Type)]
pub struct FileState {
    pub exists: bool,
    pub device: u64,
    pub inode: u64,
    pub hard_links: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: u64,
}

impl FileState {
    pub const fn absent() -> Self {
        Self {
            exists: false,
            device: 0,
            inode: 0,
            hard_links: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct ProfileInspection {
    pub filename: String,
    pub state: FileState,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct InstallRequest {
    pub profile: WireProfile,
    pub expected_state: FileState,
    pub overwrite: bool,
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
    fn ssid_limits_and_profile_names_follow_iwd() {
        assert_eq!(validate_ssid(&"é".repeat(16)), Ok(()));
        assert_eq!(
            validate_ssid(&"é".repeat(17)),
            Err(ValidationError::SsidTooLong)
        );
        assert_eq!(
            profile_filename_for_ssid("Office Wi-Fi"),
            "Office Wi-Fi.8021x"
        );
        assert_eq!(
            profile_filename_for_ssid("Office/5"),
            "=4f66666963652f35.8021x"
        );
    }

    #[test]
    fn iwd_value_escaping_preserves_internal_spaces() {
        assert_eq!(
            escape_iwd_value(" leading\\value\tline\r\nbreak"),
            Ok(String::from("\\sleading\\\\value\\tline\\r\\nbreak"))
        );
    }

    #[test]
    fn peap_redacts_password_and_serializes_phase2() {
        let mut outer = EapLayer::new(EapMethod::Peap);
        outer.identity = Some(String::from("anonymous"));
        outer.tls = Some(empty_tls());
        let profile = profile(vec![
            outer,
            password_layer(EapMethod::Mschapv2, "user", "secret"),
        ]);

        assert_eq!(
            profile.redacted_config(),
            Ok(String::from(
                "[Security]\n\
                 EAP-Method=PEAP\n\
                 EAP-Identity=anonymous\n\
                 EAP-PEAP-Phase2-Method=MSCHAPV2\n\
                 EAP-PEAP-Phase2-Identity=user\n\
                 EAP-PEAP-Phase2-Password=<redacted>\n"
            ))
        );
        let plain = profile.serialize_plain().expect("valid test profile");
        assert!(std::str::from_utf8(plain.as_bytes()).is_ok_and(|value| value.contains("secret")));
        assert!(!format!("{:?}", plain).contains("secret"));
        assert!(!format!("{:?}", Secret::new("secret")).contains("secret"));
    }

    #[test]
    fn ttls_supports_tunneled_phase2_methods() {
        let mut outer = EapLayer::new(EapMethod::Ttls);
        outer.tls = Some(empty_tls());
        let mut child = EapLayer::new(EapMethod::TunneledMschapv2);
        child.identity = Some(String::from("user"));
        child.password = Some(Secret::new("secret"));
        let profile = profile(vec![outer, child]);

        assert_eq!(profile.validate(), Ok(()));
        assert_eq!(
            profile.redacted_config(),
            Ok(String::from(
                "[Security]\n\
                 EAP-Method=TTLS\n\
                 EAP-TTLS-Phase2-Method=Tunneled-MSCHAPv2\n\
                 EAP-TTLS-Phase2-Identity=user\n\
                 EAP-TTLS-Phase2-Password=<redacted>\n"
            ))
        );
    }

    #[test]
    fn tls_and_wfa_tls_use_current_iwd_keys() {
        let mut tls = EapLayer::new(EapMethod::WfaTls);
        tls.identity = Some(String::from("user"));
        tls.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/cert.pem")),
            server_domain_mask: Some(String::from("radius.example.com;*.backup")),
            fast_reauthentication: Some(false),
            client: TlsClientCredentials::CertificateAndKey {
                certificate: PathBuf::from("/etc/ssl/client.pem"),
                key: PathBuf::from("/etc/ssl/client.key"),
            },
            client_key_passphrase: Some(Secret::new("passphrase")),
        });
        let config = profile(vec![tls])
            .redacted_config()
            .expect("valid TLS profile");
        assert!(config.contains("EAP-Method=WFA-TLS\n"));
        assert!(config.contains("EAP-TLS-CACert=/etc/ssl/cert.pem\n"));
        assert!(config.contains("EAP-TLS-ServerDomainMask=radius.example.com;*.backup\n"));
        assert!(config.contains("EAP-TLS-FastReauthentication=false\n"));
        assert!(config.contains("EAP-TLS-ClientCert=/etc/ssl/client.pem\n"));
        assert!(config.contains("EAP-TLS-ClientKey=/etc/ssl/client.key\n"));
        assert!(config.contains("EAP-TLS-ClientKeyPassphrase=<redacted>\n"));
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
            profile(vec![peap, EapLayer::new(EapMethod::TunneledPap),]).validate(),
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
    fn domain_masks_match_conservative_input_contract() {
        assert!(is_valid_domain_mask("radius.example.com;*.backup"));
        assert!(is_valid_domain_mask("*.example"));
        assert!(!is_valid_domain_mask("radius..example"));
        assert!(!is_valid_domain_mask("radius.example;"));
        assert!(!is_valid_domain_mask("radius/example"));
    }

    #[test]
    fn wire_conversion_rejects_unknown_values() {
        let mut wire = profile(vec![password_layer(EapMethod::Mschapv2, "user", "secret")])
            .into_wire()
            .expect("valid profile");
        wire.layers[0].method = 255;
        assert_eq!(
            Profile::try_from(wire),
            Err(ValidationError::InvalidInnerMethod)
        );

        let mut wire = profile(vec![password_layer(EapMethod::Mschapv2, "user", "secret")])
            .into_wire()
            .expect("valid profile");
        wire.layers[0].tls.fast_reauthentication = 2;
        assert_eq!(
            Profile::try_from(wire),
            Err(ValidationError::InvalidBoolean)
        );
    }

    #[test]
    fn tls_wire_round_trips_and_rejects_inconsistent_client_fields() {
        fn tls_profile(client: TlsClientCredentials, fast: bool) -> Profile {
            let mut layer = EapLayer::new(EapMethod::Tls);
            layer.identity = Some(String::from("user"));
            layer.tls = Some(TlsConfig {
                ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
                server_domain_mask: Some(String::from("radius.example.com")),
                fast_reauthentication: Some(fast),
                client,
                client_key_passphrase: None,
            });
            profile(vec![layer])
        }

        for profile in [
            tls_profile(TlsClientCredentials::None, false),
            tls_profile(
                TlsClientCredentials::CertificateAndKey {
                    certificate: PathBuf::from("/etc/ssl/client.pem"),
                    key: PathBuf::from("/etc/ssl/client.key"),
                },
                true,
            ),
            tls_profile(
                TlsClientCredentials::Pkcs12 {
                    bundle: PathBuf::from("/etc/ssl/client.p12"),
                },
                false,
            ),
        ] {
            let wire = profile.into_wire().expect("encode TLS profile");
            assert!(Profile::try_from(wire).is_ok());
        }

        let invalid_tls = [
            WireTlsConfig {
                client_kind: 0,
                client_cert: String::from("/etc/ssl/client.pem"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 1,
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 1,
                client_cert: String::from("/etc/ssl/client.pem"),
                client_key: String::from("/etc/ssl/client.key"),
                client_bundle: String::from("/etc/ssl/client.p12"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 2,
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 2,
                client_cert: String::from("/etc/ssl/client.pem"),
                client_bundle: String::from("/etc/ssl/client.p12"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 3,
                ..WireTlsConfig::default()
            },
        ];
        for tls in invalid_tls {
            let wire = WireProfile {
                ssid: String::from("Office Wi-Fi"),
                layers: vec![WireEapLayer {
                    method: EapMethod::Tls.wire_code(),
                    identity: String::from("user"),
                    password: Secret::new(""),
                    password_hash: Secret::new(""),
                    tls,
                }],
            };
            assert!(matches!(
                Profile::try_from(wire),
                Err(ValidationError::InvalidPath | ValidationError::InvalidTlsConfiguration)
            ));
        }
    }

    #[test]
    fn supported_method_names_and_credential_omission_are_stable() {
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

        let mut omitted = EapLayer::new(EapMethod::Mschapv2);
        omitted.identity = Some(String::from("user"));
        let config = profile(vec![omitted])
            .redacted_config()
            .expect("valid profile");
        assert!(!config.contains("Password="));
        assert!(!config.contains("Password-Hash="));
    }

    #[test]
    fn mschap_hash_and_all_ttls_tunneled_methods_serialize() {
        let mut hash = EapLayer::new(EapMethod::Mschapv2);
        hash.identity = Some(String::from("user"));
        hash.password_hash = Some(Secret::new("0123456789abcdef0123456789abcdef"));
        let hash_config = profile(vec![hash])
            .redacted_config()
            .expect("valid hash profile");
        assert!(hash_config.contains("EAP-Password-Hash=<redacted>\n"));

        for method in [
            EapMethod::TunneledPap,
            EapMethod::TunneledChap,
            EapMethod::TunneledMschap,
            EapMethod::TunneledMschapv2,
        ] {
            let mut outer = EapLayer::new(EapMethod::Ttls);
            outer.tls = Some(empty_tls());
            let mut child = EapLayer::new(method);
            child.identity = Some(String::from("user"));
            child.password = Some(Secret::new("secret"));
            let config = profile(vec![outer, child])
                .redacted_config()
                .expect("valid tunneled profile");
            assert!(config.contains(&format!("EAP-TTLS-Phase2-Method={}\n", method.name())));
        }
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
    fn pkcs12_and_nested_tls_credentials_use_expected_keys() {
        let mut outer = EapLayer::new(EapMethod::Ttls);
        outer.tls = Some(empty_tls());
        let mut child = EapLayer::new(EapMethod::Tls);
        child.tls = Some(TlsConfig {
            client: TlsClientCredentials::Pkcs12 {
                bundle: PathBuf::from("/etc/ssl/client.p12"),
            },
            ..empty_tls()
        });
        let config = profile(vec![outer, child])
            .redacted_config()
            .expect("valid nested TLS profile");
        assert!(config.contains("EAP-TTLS-Phase2-TLS-ClientKeyBundle=/etc/ssl/client.p12\n"));
    }
}
