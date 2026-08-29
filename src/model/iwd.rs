use super::eap::{EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig};
use super::validation::{MAX_TEXT_BYTES, ValidationError, validate_ssid, validate_text};
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Eq, PartialEq)]
pub struct PlaintextProfile(Zeroizing<String>);

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

impl Profile {
    pub fn profile_filename(&self) -> Result<String, ValidationError> {
        validate_ssid(&self.ssid)?;
        Ok(profile_filename_for_ssid(&self.ssid))
    }

    pub fn redacted_config(&self) -> Result<String, ValidationError> {
        let mut output = String::from("[Security]\n");
        self.render(&mut output, false)?;
        Ok(output)
    }

    pub fn serialize_plain(&self) -> Result<PlaintextProfile, ValidationError> {
        let mut output = Zeroizing::new(String::from("[Security]\n"));
        self.render(&mut output, true)?;
        Ok(PlaintextProfile(output))
    }

    fn render(&self, output: &mut String, include_secrets: bool) -> Result<(), ValidationError> {
        self.validate()?;
        self.render_layer(output, 0, "EAP-", include_secrets)
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
                let tls_prefix = format!("{prefix}TLS-");
                render_tls_common(output, &tls_prefix, tls)?;
                if method.supports_tls_client_credentials() {
                    render_tls_client_credentials(output, &tls_prefix, tls, include_secrets)?;
                }
            }
            EapMethod::Peap => {
                let tls = layer
                    .tls
                    .as_ref()
                    .ok_or(ValidationError::MissingTlsConfiguration)?;
                render_tls_common(output, &format!("{prefix}PEAP-"), tls)?;
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
                render_tls_common(output, &format!("{prefix}TTLS-"), tls)?;
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
            _ => return Err(ValidationError::InvalidInnerMethod),
        }
        Ok(())
    }
}

pub fn escape_iwd_value(value: &str) -> Result<String, ValidationError> {
    validate_text(value, MAX_TEXT_BYTES)?;
    let mut escaped = String::with_capacity(value.len());
    append_escaped_iwd_value(&mut escaped, value);
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
    validate_text(value, MAX_TEXT_BYTES)?;
    output.push_str(key);
    output.push('=');
    append_escaped_iwd_value(output, value);
    output.push('\n');
    Ok(())
}

fn append_escaped_iwd_value(output: &mut String, value: &str) {
    for (index, character) in value.chars().enumerate() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\t' => output.push_str("\\t"),
            '\r' => output.push_str("\\r"),
            '\n' => output.push_str("\\n"),
            ' ' if index == 0 => output.push_str("\\s"),
            _ => output.push(character),
        }
    }
}

fn render_tls_common(
    output: &mut String,
    prefix: &str,
    tls: &TlsConfig,
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
    Ok(())
}

fn render_tls_client_credentials(
    output: &mut String,
    prefix: &str,
    tls: &TlsConfig,
    include_secrets: bool,
) -> Result<(), ValidationError> {
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
    fn iwd_value_escaping_preserves_current_rules() {
        let cases = [
            ("plain ASCII", "plain ASCII"),
            (" leading and trailing ", "\\sleading and trailing "),
            ("semi;colon", "semi;colon"),
            ("back\\\\slash", "back\\\\\\\\slash"),
            ("line\nfeed", "line\\nfeed"),
            ("carriage\rreturn", "carriage\\rreturn"),
            ("tab\tvalue", "tab\\tvalue"),
            ("quotes\"'", "quotes\"'"),
            ("non-ASCII café密码", "non-ASCII café密码"),
            ("", ""),
        ];

        for (value, expected) in cases {
            assert_eq!(escape_iwd_value(value), Ok(String::from(expected)));
        }
    }

    #[test]
    fn secret_setting_escaping_matches_canonical_escaping() {
        let values = [
            "plain ASCII",
            " leading and trailing ",
            "semi;colon",
            "back\\\\slash",
            "line\nfeed",
            "carriage\rreturn",
            "tab\tvalue",
            "quotes\"'",
            "non-ASCII café密码",
            "",
        ];

        for value in values {
            let mut rendered = String::new();
            append_secret_setting(&mut rendered, "Secret", &Secret::new(value), true)
                .expect("valid secret value");
            let escaped = escape_iwd_value(value).expect("valid value");
            let mut expected = String::from("Secret=");
            expected.push_str(&escaped);
            expected.push('\n');
            assert_eq!(rendered, expected);
        }
    }

    #[test]
    fn serialized_profiles_preserve_secret_output() {
        let direct = password_layer(EapMethod::Pwd, "direct-user", "direct-password");
        assert_serialized_profile(
            profile(vec![direct]),
            "[Security]\n\
             EAP-Method=PWD\n\
             EAP-Identity=direct-user\n\
             EAP-Password=direct-password\n",
        );

        let mschap = password_layer(EapMethod::Mschapv2, "mschap-user", "mschap-password");
        assert_serialized_profile(
            profile(vec![mschap]),
            "[Security]\n\
             EAP-Method=MSCHAPV2\n\
             EAP-Identity=mschap-user\n\
             EAP-Password=mschap-password\n",
        );

        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(empty_tls());
        let ttls_child = password_layer(EapMethod::TunneledPap, "ttls-user", "ttls-password");
        assert_serialized_profile(
            profile(vec![ttls, ttls_child]),
            "[Security]\n\
             EAP-Method=TTLS\n\
             EAP-TTLS-Phase2-Method=Tunneled-PAP\n\
             EAP-TTLS-Phase2-Identity=ttls-user\n\
             EAP-TTLS-Phase2-Password=ttls-password\n",
        );

        let mut tls = EapLayer::new(EapMethod::Tls);
        tls.identity = Some(String::from("tls-user"));
        tls.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::CertificateAndKey {
                certificate: PathBuf::from("/etc/ssl/client.pem"),
                key: PathBuf::from("/etc/ssl/client.key"),
            },
            client_key_passphrase: Some(Secret::new("tls-passphrase")),
        });
        assert_serialized_profile(
            profile(vec![tls]),
            "[Security]\n\
             EAP-Method=TLS\n\
             EAP-Identity=tls-user\n\
             EAP-TLS-CACert=/etc/ssl/ca.pem\n\
             EAP-TLS-ClientCert=/etc/ssl/client.pem\n\
             EAP-TLS-ClientKey=/etc/ssl/client.key\n\
             EAP-TLS-ClientKeyPassphrase=tls-passphrase\n",
        );
    }

    fn assert_serialized_profile(profile: Profile, expected: &str) {
        let serialized = profile.serialize_plain().expect("valid profile");
        assert_eq!(
            std::str::from_utf8(serialized.as_bytes()).expect("UTF-8 profile"),
            expected
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
    fn ttls_tunneled_methods_render_once_in_phase2() {
        for (method, name) in [
            (EapMethod::TunneledPap, "Tunneled-PAP"),
            (EapMethod::TunneledChap, "Tunneled-CHAP"),
            (EapMethod::TunneledMschap, "Tunneled-MSCHAP"),
            (EapMethod::TunneledMschapv2, "Tunneled-MSCHAPv2"),
        ] {
            let mut outer = EapLayer::new(EapMethod::Ttls);
            outer.tls = Some(empty_tls());
            let child = password_layer(method, "user", "secret");
            let profile = profile(vec![outer, child]);

            assert_eq!(profile.validate(), Ok(()));
            assert_eq!(
                profile.redacted_config(),
                Ok(format!(
                    "[Security]\n\
                     EAP-Method=TTLS\n\
                     EAP-TTLS-Phase2-Method={name}\n\
                     EAP-TTLS-Phase2-Identity=user\n\
                     EAP-TTLS-Phase2-Password=<redacted>\n"
                ))
            );
            let plain = profile
                .serialize_plain()
                .expect("serialize tunneled profile");
            let plain = std::str::from_utf8(plain.as_bytes()).expect("UTF-8 profile");
            assert_eq!(plain.matches("EAP-TTLS-Phase2-Method=").count(), 1);
            assert_eq!(
                plain,
                format!(
                    "[Security]\n\
                     EAP-Method=TTLS\n\
                     EAP-TTLS-Phase2-Method={name}\n\
                     EAP-TTLS-Phase2-Identity=user\n\
                     EAP-TTLS-Phase2-Password=secret\n"
                )
            );
        }

        let mut peap = EapLayer::new(EapMethod::Peap);
        peap.tls = Some(empty_tls());
        let mut ttls = EapLayer::new(EapMethod::Ttls);
        ttls.tls = Some(empty_tls());
        let nested = profile(vec![
            peap,
            ttls,
            password_layer(EapMethod::TunneledPap, "nested-user", "nested-secret"),
        ]);

        assert_eq!(nested.validate(), Ok(()));
        assert_eq!(
            nested.redacted_config(),
            Ok(String::from(
                "[Security]\n\
                 EAP-Method=PEAP\n\
                 EAP-PEAP-Phase2-Method=TTLS\n\
                 EAP-PEAP-Phase2-TTLS-Phase2-Method=Tunneled-PAP\n\
                 EAP-PEAP-Phase2-TTLS-Phase2-Identity=nested-user\n\
                 EAP-PEAP-Phase2-TTLS-Phase2-Password=<redacted>\n"
            ))
        );
        let plain = nested.serialize_plain().expect("serialize nested profile");
        assert_eq!(
            std::str::from_utf8(plain.as_bytes()).expect("UTF-8 profile"),
            "[Security]\n\
             EAP-Method=PEAP\n\
             EAP-PEAP-Phase2-Method=TTLS\n\
             EAP-PEAP-Phase2-TTLS-Phase2-Method=Tunneled-PAP\n\
             EAP-PEAP-Phase2-TTLS-Phase2-Identity=nested-user\n\
             EAP-PEAP-Phase2-TTLS-Phase2-Password=nested-secret\n"
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

    #[test]
    fn nested_peap_and_ttls_to_inner_tls_preserves_client_credentials() {
        // PEAP -> TLS with CertificateAndKey and passphrase
        let mut peap_outer = EapLayer::new(EapMethod::Peap);
        peap_outer.identity = Some(String::from("anon-peap"));
        peap_outer.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/peap-ca.pem")),
            server_domain_mask: Some(String::from("peap.example.com")),
            fast_reauthentication: Some(true),
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });

        let mut peap_inner_tls = EapLayer::new(EapMethod::Tls);
        peap_inner_tls.identity = Some(String::from("peap-inner-user"));
        peap_inner_tls.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/inner-ca.pem")),
            server_domain_mask: Some(String::from("inner.example.com")),
            fast_reauthentication: Some(false),
            client: TlsClientCredentials::CertificateAndKey {
                certificate: PathBuf::from("/etc/ssl/inner-client.pem"),
                key: PathBuf::from("/etc/ssl/inner-client.key"),
            },
            client_key_passphrase: Some(Secret::new("inner-passphrase")),
        });

        let peap_profile = profile(vec![peap_outer, peap_inner_tls]);
        assert_eq!(peap_profile.validate(), Ok(()));

        let peap_config = peap_profile
            .redacted_config()
            .expect("valid PEAP->TLS profile");
        assert!(peap_config.contains("EAP-Method=PEAP\n"));
        assert!(peap_config.contains("EAP-Identity=anon-peap\n"));
        assert!(peap_config.contains("EAP-PEAP-CACert=/etc/ssl/peap-ca.pem\n"));
        assert!(peap_config.contains("EAP-PEAP-ServerDomainMask=peap.example.com\n"));
        assert!(peap_config.contains("EAP-PEAP-FastReauthentication=true\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-Method=TLS\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-Identity=peap-inner-user\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-CACert=/etc/ssl/inner-ca.pem\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-ServerDomainMask=inner.example.com\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-FastReauthentication=false\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-ClientCert=/etc/ssl/inner-client.pem\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-ClientKey=/etc/ssl/inner-client.key\n"));
        assert!(peap_config.contains("EAP-PEAP-Phase2-TLS-ClientKeyPassphrase=<redacted>\n"));

        let peap_plain = peap_profile
            .serialize_plain()
            .expect("serialize plain PEAP->TLS");
        let peap_plain_str =
            std::str::from_utf8(peap_plain.as_bytes()).expect("valid UTF-8 plain profile");
        assert!(
            peap_plain_str.contains("EAP-PEAP-Phase2-TLS-ClientKeyPassphrase=inner-passphrase\n")
        );

        // TTLS -> TLS with CertificateAndKey
        let mut ttls_outer = EapLayer::new(EapMethod::Ttls);
        ttls_outer.identity = Some(String::from("anon-ttls"));
        ttls_outer.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/ttls-ca.pem")),
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });

        let mut ttls_inner_tls = EapLayer::new(EapMethod::Tls);
        ttls_inner_tls.tls = Some(TlsConfig {
            ca_cert: None,
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::CertificateAndKey {
                certificate: PathBuf::from("/etc/ssl/ttls-client.pem"),
                key: PathBuf::from("/etc/ssl/ttls-client.key"),
            },
            client_key_passphrase: None,
        });

        let ttls_profile = profile(vec![ttls_outer, ttls_inner_tls]);
        assert_eq!(ttls_profile.validate(), Ok(()));
        let ttls_config = ttls_profile
            .redacted_config()
            .expect("valid TTLS->TLS profile");
        assert!(ttls_config.contains("EAP-Method=TTLS\n"));
        assert!(ttls_config.contains("EAP-Identity=anon-ttls\n"));
        assert!(ttls_config.contains("EAP-TTLS-CACert=/etc/ssl/ttls-ca.pem\n"));
        assert!(ttls_config.contains("EAP-TTLS-Phase2-Method=TLS\n"));
        assert!(ttls_config.contains("EAP-TTLS-Phase2-TLS-ClientCert=/etc/ssl/ttls-client.pem\n"));
        assert!(ttls_config.contains("EAP-TTLS-Phase2-TLS-ClientKey=/etc/ssl/ttls-client.key\n"));
    }

    #[test]
    fn outer_peap_and_ttls_profiles_never_serialize_forbidden_client_keys() {
        let forbidden_keys = [
            "EAP-PEAP-ClientCert",
            "EAP-PEAP-ClientKey",
            "EAP-PEAP-ClientKeyBundle",
            "EAP-PEAP-ClientKeyPassphrase",
            "EAP-TTLS-ClientCert",
            "EAP-TTLS-ClientKey",
            "EAP-TTLS-ClientKeyBundle",
            "EAP-TTLS-ClientKeyPassphrase",
        ];

        // PEAP with MSCHAPv2
        let mut peap_outer = EapLayer::new(EapMethod::Peap);
        peap_outer.identity = Some(String::from("anon"));
        peap_outer.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
            server_domain_mask: Some(String::from("radius.example.com")),
            fast_reauthentication: Some(true),
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });
        let peap_mschap = profile(vec![
            peap_outer,
            password_layer(EapMethod::Mschapv2, "user", "secret"),
        ]);
        let peap_mschap_config = peap_mschap.redacted_config().expect("valid config");
        for key in &forbidden_keys {
            assert!(
                !peap_mschap_config.contains(key),
                "peap config contains forbidden key {key}"
            );
        }

        // TTLS with TunneledPap
        let mut ttls_outer = EapLayer::new(EapMethod::Ttls);
        ttls_outer.identity = Some(String::from("anon"));
        ttls_outer.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
            server_domain_mask: Some(String::from("radius.example.com")),
            fast_reauthentication: Some(true),
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });
        let mut child = EapLayer::new(EapMethod::TunneledPap);
        child.identity = Some(String::from("user"));
        child.password = Some(Secret::new("secret"));
        let ttls_pap = profile(vec![ttls_outer, child]);
        let ttls_pap_config = ttls_pap.redacted_config().expect("valid config");
        for key in &forbidden_keys {
            assert!(
                !ttls_pap_config.contains(key),
                "ttls config contains forbidden key {key}"
            );
        }

        // PEAP with inner TLS
        let mut peap_outer2 = EapLayer::new(EapMethod::Peap);
        peap_outer2.identity = Some(String::from("anon"));
        peap_outer2.tls = Some(TlsConfig {
            ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });
        let mut inner_tls = EapLayer::new(EapMethod::Tls);
        inner_tls.tls = Some(TlsConfig {
            ca_cert: None,
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::CertificateAndKey {
                certificate: PathBuf::from("/etc/ssl/client.pem"),
                key: PathBuf::from("/etc/ssl/client.key"),
            },
            client_key_passphrase: Some(Secret::new("pass")),
        });
        let peap_tls = profile(vec![peap_outer2, inner_tls]);
        let peap_tls_config = peap_tls.redacted_config().expect("valid config");
        for key in &forbidden_keys {
            assert!(
                !peap_tls_config.contains(key),
                "peap->tls config contains forbidden outer key {key}"
            );
        }
    }
}
