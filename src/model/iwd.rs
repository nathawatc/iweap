use super::eap::{EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig};
use super::validation::{MAX_TEXT_BYTES, ValidationError, validate_ssid, validate_text};
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

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

impl Profile {
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

#[cfg(test)]
mod tests {
    use super::super::eap::EapLayer;
    use super::*;
    use std::path::PathBuf;

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
    fn profile_names_follow_iwd() {
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
        assert!(!format!("{plain:?}").contains("secret"));
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
    fn credential_omission_is_stable() {
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
