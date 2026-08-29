use super::eap::{EapLayer, EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig};
use super::validation::{MAX_EAP_LAYERS, ValidationError, validate_path};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zvariant::Type;

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
    pub has_tls: bool,
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
        let has_tls = layer.tls.is_some();
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
            has_tls,
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

impl Profile {
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
        let tls = if value.has_tls {
            Some(value.tls.into_tls()?)
        } else {
            if value.tls != WireTlsConfig::default() {
                return Err(ValidationError::InvalidTlsConfiguration);
            }
            None
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

#[cfg(test)]
mod tests {
    use super::*;

    fn password_layer(method: EapMethod, identity: &str, password: &str) -> EapLayer {
        let mut layer = EapLayer::new(method);
        layer.identity = Some(identity.to_owned());
        layer.password = Some(Secret::new(password));
        layer
    }

    fn profile(layers: Vec<EapLayer>) -> Profile {
        Profile::new(String::from("Office Wi-Fi"), layers)
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
        wire.layers[0].has_tls = true;
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
                    has_tls: true,
                    tls,
                }],
            };
            assert!(matches!(
                Profile::try_from(wire),
                Err(ValidationError::InvalidPath | ValidationError::InvalidTlsConfiguration)
            ));
        }
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

    fn clone_tls(tls: &TlsConfig) -> TlsConfig {
        TlsConfig {
            ca_cert: tls.ca_cert.clone(),
            server_domain_mask: tls.server_domain_mask.clone(),
            fast_reauthentication: tls.fast_reauthentication,
            client: match &tls.client {
                TlsClientCredentials::None => TlsClientCredentials::None,
                TlsClientCredentials::CertificateAndKey { certificate, key } => {
                    TlsClientCredentials::CertificateAndKey {
                        certificate: certificate.clone(),
                        key: key.clone(),
                    }
                }
                TlsClientCredentials::Pkcs12 { bundle } => TlsClientCredentials::Pkcs12 {
                    bundle: bundle.clone(),
                },
            },
            client_key_passphrase: tls
                .client_key_passphrase
                .as_ref()
                .map(|s| Secret::new(s.as_str())),
        }
    }

    fn clone_layer(layer: &EapLayer) -> EapLayer {
        let mut cloned = EapLayer::new(layer.method);
        cloned.identity = layer.identity.clone();
        cloned.password = layer.password.as_ref().map(|s| Secret::new(s.as_str()));
        cloned.password_hash = layer
            .password_hash
            .as_ref()
            .map(|s| Secret::new(s.as_str()));
        cloned.tls = layer.tls.as_ref().map(clone_tls);
        cloned
    }

    fn clone_profile(p: &Profile) -> Profile {
        Profile::new(p.ssid.clone(), p.layers.iter().map(clone_layer).collect())
    }

    #[test]
    fn dbus_wire_signature_explicitly_includes_has_tls_discriminator() {
        assert_eq!(
            <WireEapLayer as Type>::SIGNATURE.to_string(),
            "(ysssb(ssnyssss))"
        );
        assert_eq!(
            <WireProfile as Type>::SIGNATURE.to_string(),
            "(sa(ysssb(ssnyssss)))"
        );
    }

    #[test]
    fn regression_p1_1_tls_none_round_trips_distinctly() {
        let original_layer = password_layer(EapMethod::Mschapv2, "user", "secret");
        assert_eq!(original_layer.tls, None);

        let wire_layer =
            WireEapLayer::from_layer(password_layer(EapMethod::Mschapv2, "user", "secret"))
                .expect("encode layer without TLS");
        assert!(!wire_layer.has_tls);
        assert_eq!(wire_layer.tls, WireTlsConfig::default());

        let decoded_layer = EapLayer::try_from(wire_layer).expect("decode layer without TLS");
        assert_eq!(decoded_layer.tls, None);
        assert_eq!(decoded_layer, original_layer);

        let original_profile = profile(vec![password_layer(EapMethod::Mschapv2, "user", "secret")]);
        let wire_profile = profile(vec![password_layer(EapMethod::Mschapv2, "user", "secret")])
            .into_wire()
            .expect("encode profile without TLS");
        assert!(!wire_profile.layers[0].has_tls);
        assert_eq!(wire_profile.layers[0].tls, WireTlsConfig::default());

        let decoded_profile = Profile::try_from(wire_profile).expect("decode profile without TLS");
        assert_eq!(decoded_profile, original_profile);
        assert_eq!(decoded_profile.layers[0].tls, None);
    }

    #[test]
    fn regression_p1_1_empty_tls_round_trips_distinctly_from_none() {
        let make_layer = || {
            let mut layer = EapLayer::new(EapMethod::Tls);
            layer.identity = Some(String::from("user"));
            layer.tls = Some(empty_tls());
            layer
        };
        let original_layer = make_layer();
        assert_eq!(original_layer.tls, Some(empty_tls()));

        let wire_layer =
            WireEapLayer::from_layer(make_layer()).expect("encode layer with empty TLS");
        assert!(wire_layer.has_tls);
        assert_eq!(wire_layer.tls, WireTlsConfig::default());

        let decoded_layer = EapLayer::try_from(wire_layer).expect("decode layer with empty TLS");
        assert_eq!(decoded_layer.tls, Some(empty_tls()));
        assert_eq!(decoded_layer, original_layer);

        let make_profile = || profile(vec![make_layer()]);
        let original_profile = make_profile();
        let wire_profile = make_profile()
            .into_wire()
            .expect("encode profile with empty TLS");
        assert!(wire_profile.layers[0].has_tls);
        assert_eq!(wire_profile.layers[0].tls, WireTlsConfig::default());

        let decoded_profile =
            Profile::try_from(wire_profile).expect("decode profile with empty TLS");
        assert_eq!(decoded_profile, original_profile);
        assert_eq!(decoded_profile.layers[0].tls, Some(empty_tls()));

        // Semantic distinction: None and Some(empty) encode with different discriminators
        let none_layer = {
            let mut layer = EapLayer::new(EapMethod::Tls);
            layer.identity = Some(String::from("user"));
            layer.tls = None;
            layer
        };
        let wire_none = WireEapLayer::from_layer(none_layer).expect("encode layer with None TLS");
        let wire_some =
            WireEapLayer::from_layer(make_layer()).expect("encode layer with Some(empty) TLS");
        assert_ne!(wire_none.has_tls, wire_some.has_tls);
        assert!(!wire_none.has_tls);
        assert!(wire_some.has_tls);
        assert_eq!(wire_none.tls, wire_some.tls);
    }

    #[test]
    fn regression_p1_1_non_empty_tls_round_trips_faithfully() {
        let test_cases = [
            TlsConfig {
                ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
                server_domain_mask: Some(String::from("radius.example.com")),
                fast_reauthentication: Some(true),
                client: TlsClientCredentials::CertificateAndKey {
                    certificate: PathBuf::from("/etc/ssl/client.pem"),
                    key: PathBuf::from("/etc/ssl/client.key"),
                },
                client_key_passphrase: Some(Secret::new("client_pass")),
            },
            TlsConfig {
                ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
                server_domain_mask: Some(String::from("auth.example.org")),
                fast_reauthentication: Some(false),
                client: TlsClientCredentials::Pkcs12 {
                    bundle: PathBuf::from("/etc/ssl/client.p12"),
                },
                client_key_passphrase: Some(Secret::new("p12_pass")),
            },
            TlsConfig {
                ca_cert: Some(PathBuf::from("/etc/ssl/ca.pem")),
                server_domain_mask: None,
                fast_reauthentication: None,
                client: TlsClientCredentials::None,
                client_key_passphrase: None,
            },
        ];

        for config in test_cases {
            let make_layer = || {
                let mut layer = EapLayer::new(EapMethod::Tls);
                layer.identity = Some(String::from("user"));
                layer.tls = Some(clone_tls(&config));
                layer
            };

            let original_layer = make_layer();
            let wire_layer = WireEapLayer::from_layer(make_layer()).expect("encode layer");
            assert!(wire_layer.has_tls);
            let decoded_layer = EapLayer::try_from(wire_layer).expect("decode layer");
            assert_eq!(decoded_layer, original_layer);

            let original_profile = profile(vec![make_layer()]);
            let wire_profile = profile(vec![make_layer()])
                .into_wire()
                .expect("encode profile");
            assert!(wire_profile.layers[0].has_tls);
            let decoded_profile = Profile::try_from(wire_profile).expect("decode profile");
            assert_eq!(decoded_profile, original_profile);
        }
    }

    #[test]
    fn regression_p1_1_tls_based_methods_with_empty_tls_round_trip() {
        let profiles = [
            // TLS
            profile(vec![{
                let mut layer = EapLayer::new(EapMethod::Tls);
                layer.identity = Some(String::from("user"));
                layer.tls = Some(empty_tls());
                layer
            }]),
            // WFA-TLS
            profile(vec![{
                let mut layer = EapLayer::new(EapMethod::WfaTls);
                layer.identity = Some(String::from("user"));
                layer.tls = Some(empty_tls());
                layer
            }]),
            // PEAP (valid phase 2)
            profile(vec![
                {
                    let mut layer = EapLayer::new(EapMethod::Peap);
                    layer.identity = Some(String::from("user"));
                    layer.tls = Some(empty_tls());
                    layer
                },
                password_layer(EapMethod::Mschapv2, "inner_user", "password"),
            ]),
            // TTLS (valid phase 2)
            profile(vec![
                {
                    let mut layer = EapLayer::new(EapMethod::Ttls);
                    layer.identity = Some(String::from("user"));
                    layer.tls = Some(empty_tls());
                    layer
                },
                password_layer(EapMethod::TunneledPap, "inner_user", "password"),
            ]),
        ];

        for original in profiles {
            assert!(original.validate().is_ok());
            let wire = clone_profile(&original)
                .into_wire()
                .expect("encode profile");

            assert!(wire.layers[0].has_tls);
            assert_eq!(wire.layers[0].tls, WireTlsConfig::default());

            let decoded = Profile::try_from(wire).expect("round trip profile");
            assert_eq!(decoded, original);
            assert_eq!(decoded.layers[0].tls, Some(empty_tls()));
            assert!(decoded.validate().is_ok());
        }
    }

    #[test]
    fn regression_p1_1_malformed_wire_state_rejects_non_default_tls_when_has_tls_false() {
        let non_default_payloads = [
            WireTlsConfig {
                fast_reauthentication: 1,
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                fast_reauthentication: 0,
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                ca_cert: String::from("/etc/ssl/ca.pem"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                server_domain_mask: String::from("radius.example.com"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 1,
                client_cert: String::from("/etc/ssl/client.pem"),
                client_key: String::from("/etc/ssl/client.key"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_kind: 2,
                client_bundle: String::from("/etc/ssl/client.p12"),
                ..WireTlsConfig::default()
            },
            WireTlsConfig {
                client_key_passphrase: Secret::new("passphrase"),
                ..WireTlsConfig::default()
            },
        ];

        for tls in non_default_payloads {
            let wire_layer = WireEapLayer {
                method: EapMethod::Tls.wire_code(),
                identity: String::from("user"),
                password: Secret::new(""),
                password_hash: Secret::new(""),
                has_tls: false,
                tls,
            };
            assert_eq!(
                EapLayer::try_from(wire_layer),
                Err(ValidationError::InvalidTlsConfiguration)
            );
        }

        let wire_profile = WireProfile {
            ssid: String::from("Office Wi-Fi"),
            layers: vec![WireEapLayer {
                method: EapMethod::Tls.wire_code(),
                identity: String::from("user"),
                password: Secret::new(""),
                password_hash: Secret::new(""),
                has_tls: false,
                tls: WireTlsConfig {
                    fast_reauthentication: 1,
                    ..WireTlsConfig::default()
                },
            }],
        };
        assert_eq!(
            Profile::try_from(wire_profile),
            Err(ValidationError::InvalidTlsConfiguration)
        );
    }

    #[test]
    fn regression_p1_1_preserves_semantic_validation_without_wire_decoder_policy() {
        // TLS-based methods with has_tls = false decode faithfully to tls: None
        for method in [
            EapMethod::Tls,
            EapMethod::WfaTls,
            EapMethod::Peap,
            EapMethod::Ttls,
        ] {
            let wire_layer = WireEapLayer {
                method: method.wire_code(),
                identity: String::from("user"),
                password: Secret::new(""),
                password_hash: Secret::new(""),
                has_tls: false,
                tls: WireTlsConfig::default(),
            };
            // Wire decoder must NOT enforce EAP semantics: decoding succeeds with tls: None
            let decoded_layer = EapLayer::try_from(wire_layer).expect("wire decoding succeeds");
            assert_eq!(decoded_layer.method, method);
            assert_eq!(decoded_layer.tls, None);

            // Normal domain validation subsequently rejects it
            let layers = if method.is_tunnel_method() {
                vec![
                    WireEapLayer {
                        method: method.wire_code(),
                        identity: String::from("user"),
                        password: Secret::new(""),
                        password_hash: Secret::new(""),
                        has_tls: false,
                        tls: WireTlsConfig::default(),
                    },
                    WireEapLayer {
                        method: EapMethod::Mschapv2.wire_code(),
                        identity: String::from("inner"),
                        password: Secret::new("password"),
                        password_hash: Secret::new(""),
                        has_tls: false,
                        tls: WireTlsConfig::default(),
                    },
                ]
            } else {
                vec![WireEapLayer {
                    method: method.wire_code(),
                    identity: String::from("user"),
                    password: Secret::new(""),
                    password_hash: Secret::new(""),
                    has_tls: false,
                    tls: WireTlsConfig::default(),
                }]
            };
            let wire_profile = WireProfile {
                ssid: String::from("Office Wi-Fi"),
                layers,
            };
            assert_eq!(
                Profile::try_from(wire_profile),
                Err(ValidationError::MissingTlsConfiguration)
            );
        }

        // Non-TLS method with has_tls = true decodes faithfully to Some(...)
        let wire_layer = WireEapLayer {
            method: EapMethod::Sim.wire_code(),
            identity: String::new(),
            password: Secret::new(""),
            password_hash: Secret::new(""),
            has_tls: true,
            tls: WireTlsConfig::default(),
        };
        let decoded_layer = EapLayer::try_from(wire_layer).expect("wire decoding succeeds");
        assert_eq!(decoded_layer.method, EapMethod::Sim);
        assert_eq!(decoded_layer.tls, Some(empty_tls()));

        // Normal domain validation determines SIM cannot have TLS
        let wire_profile = WireProfile {
            ssid: String::from("Office Wi-Fi"),
            layers: vec![WireEapLayer {
                method: EapMethod::Sim.wire_code(),
                identity: String::new(),
                password: Secret::new(""),
                password_hash: Secret::new(""),
                has_tls: true,
                tls: WireTlsConfig::default(),
            }],
        };
        assert_eq!(
            Profile::try_from(wire_profile),
            Err(ValidationError::MethodHasUnexpectedFields)
        );
    }
}
