use super::args::AppError;
use crate::input::Input;
use iweap::model::{MAX_EAP_DEPTH, MethodKind, PASSWORD_HASH_HEX_CHARS};
use iweap::{
    EapLayer, EapMethod, Profile, Secret, TlsClientCredentials, TlsConfig, ValidationError,
};
use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;

fn is_stderr_tty() -> bool {
    std::io::stderr().is_terminal()
}

pub fn configure_profile<R: BufRead>(
    input: &mut Input<R>,
    ssid: String,
) -> Result<(Profile, String, bool), AppError> {
    let filename = iweap::model::profile_filename_for_ssid(&ssid);

    let outer = select_method(
        input,
        "Outer EAP method",
        EapMethod::OUTER,
        Some(EapMethod::Peap),
    )?;
    let store_credentials = if outer.is_sim_method() {
        false
    } else {
        select_credential_handling(input)?
    };

    let mut layers = Vec::new();
    configure_layer(input, &mut layers, outer, 0, true, store_credentials)?;
    let profile = Profile::new(ssid, layers);
    profile.validate()?;
    Ok((profile, filename, store_credentials))
}

pub(crate) fn select_method<R: BufRead>(
    input: &mut Input<R>,
    title: &str,
    methods: &[EapMethod],
    default_method: Option<EapMethod>,
) -> Result<EapMethod, AppError> {
    let default_method = default_method.filter(|d| methods.contains(d));
    let tty = is_stderr_tty();
    loop {
        eprintln!("\n{title}:");
        let items: Vec<String> = methods
            .iter()
            .enumerate()
            .map(|(index, method)| {
                let is_default = Some(*method) == default_method;
                if is_default && tty {
                    format!("\x1b[1m{:>3})\x1b[0m {:<10}", index + 1, method.name())
                } else {
                    format!("{:>3}) {:<10}", index + 1, method.name())
                }
            })
            .collect();
        for chunk in items.chunks(3) {
            eprintln!("  {}", chunk.join("  "));
        }

        let prompt = format!("Select [1-{}]: ", methods.len());
        let line = input.line(&prompt)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(default) = default_method {
                return Ok(default);
            }
        }
        if let Ok(selection) = trimmed.parse::<usize>() {
            if let Some(method) = selection
                .checked_sub(1)
                .and_then(|index| methods.get(index))
            {
                return Ok(*method);
            }
        }
        if let Some(method) = methods
            .iter()
            .find(|m| m.name().eq_ignore_ascii_case(trimmed))
        {
            return Ok(*method);
        }
        eprintln!(
            "Choose a number from 1 to {} or enter a method name.",
            methods.len()
        );
    }
}

pub(crate) fn select_credential_handling<R: BufRead>(
    input: &mut Input<R>,
) -> Result<bool, AppError> {
    let tty = is_stderr_tty();
    let num_1 = if tty { "\x1b[1m  1)\x1b[0m" } else { "  1)" };
    loop {
        eprintln!(
            "\nCredential storage:\n{num_1} Prompt at connection (recommended)\n  2) Store in profile"
        );
        match input.line("Select [1-2]: ")?.trim() {
            "" | "1" => return Ok(false),
            "2" => return Ok(true),
            _ => eprintln!("Choose 1 or 2."),
        }
    }
}

pub(crate) fn select_compatible_method<R: BufRead>(
    input: &mut Input<R>,
    title: &str,
    methods: impl IntoIterator<Item = EapMethod>,
    existing_layers: &[EapLayer],
    store_credentials: bool,
    default_method: Option<EapMethod>,
) -> Result<EapMethod, AppError> {
    let methods: Vec<EapMethod> = methods
        .into_iter()
        .filter(|method| {
            iweap::model::is_eap_method_supported_for_layers(
                *method,
                existing_layers,
                store_credentials,
            )
        })
        .collect();
    if methods.is_empty() {
        return Err(ValidationError::SettingPrefixTooLong.into());
    }
    select_method(input, title, &methods, default_method)
}

pub(crate) fn select_inner_eap_method<R: BufRead>(
    input: &mut Input<R>,
    existing_layers: &[EapLayer],
    store_credentials: bool,
) -> Result<EapMethod, AppError> {
    select_compatible_method(
        input,
        "Inner EAP method",
        EapMethod::INNER.iter().copied(),
        existing_layers,
        store_credentials,
        Some(EapMethod::Mschapv2),
    )
}

pub(crate) fn select_ttls_phase2_method<R: BufRead>(
    input: &mut Input<R>,
    existing_layers: &[EapLayer],
    store_credentials: bool,
) -> Result<EapMethod, AppError> {
    select_compatible_method(
        input,
        "TTLS phase-2 method",
        EapMethod::TTLS_PHASE2.iter().copied(),
        existing_layers,
        store_credentials,
        Some(EapMethod::TunneledMschapv2),
    )
}

pub(crate) fn configure_layer<R: BufRead>(
    input: &mut Input<R>,
    layers: &mut Vec<EapLayer>,
    method: EapMethod,
    depth: usize,
    outer: bool,
    store_credentials: bool,
) -> Result<(), AppError> {
    if depth > MAX_EAP_DEPTH {
        return Err(ValidationError::TooManyEapLayers.into());
    }

    let mut layer = EapLayer::new(method);
    match method.kind() {
        MethodKind::Sim => {}
        MethodKind::Password => {
            layer.identity = prompt_identity(input, method, outer, store_credentials)?;
            if method == EapMethod::Mschapv2 && !store_credentials && !layers.is_empty() {
                loop {
                    let identity_present = layer.identity.is_some();
                    if !identity_present
                        || iweap::model::is_eap_method_supported_for_layers_with_identity(
                            method,
                            layers,
                            store_credentials,
                            identity_present,
                        )
                    {
                        break;
                    }
                    eprintln!(
                        "Identity cannot be stored for MSCHAPV2 at this nesting depth; leave it blank to use IWD agent."
                    );
                    layer.identity = prompt_identity(input, method, outer, store_credentials)?;
                }
            }
            let (password, password_hash) = configure_password(input, method, store_credentials)?;
            layer.password = password;
            layer.password_hash = password_hash;
        }
        MethodKind::Tls | MethodKind::Tunnel => {
            layer.identity = prompt_identity(input, method, outer, store_credentials)?;
            layer.tls = Some(configure_tls(input, method, store_credentials)?);
        }
        MethodKind::TunneledPassword => {
            configure_tunneled_fields(input, &mut layer, store_credentials)?;
        }
    }
    layers.push(layer);

    match method {
        EapMethod::Peap => {
            eprintln!("\n[2/3] Authentication");
            let child = select_inner_eap_method(input, layers, store_credentials)?;
            configure_layer(input, layers, child, depth + 1, false, store_credentials)?;
        }
        EapMethod::Ttls => {
            eprintln!("\n[2/3] Authentication");
            let child = select_ttls_phase2_method(input, layers, store_credentials)?;
            configure_layer(input, layers, child, depth + 1, false, store_credentials)?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn prompt_identity<R: BufRead>(
    input: &mut Input<R>,
    method: EapMethod,
    outer: bool,
    store_credentials: bool,
) -> Result<Option<String>, AppError> {
    if method.is_sim_method() {
        return Ok(None);
    }
    if outer {
        Ok(input.optional("Anonymous identity [optional]: ")?)
    } else if method.is_password_method() && store_credentials {
        Ok(Some(input.required("Username: ")?))
    } else if method.is_password_method() {
        Ok(input.optional("Username [optional]: ")?)
    } else {
        Ok(input.optional("Phase-2 anonymous identity [optional]: ")?)
    }
}

pub(crate) fn configure_password<R: BufRead>(
    input: &mut Input<R>,
    method: EapMethod,
    store_credentials: bool,
) -> Result<(Option<Secret>, Option<Secret>), AppError> {
    if !store_credentials {
        return Ok((None, None));
    }
    if method == EapMethod::Mschapv2 {
        let tty = is_stderr_tty();
        let num_1 = if tty { "\x1b[1m  1)\x1b[0m" } else { "  1)" };
        loop {
            eprintln!(
                "\nMSCHAPV2 credential format:\n{num_1} Password\n  2) MD4 password hash ({PASSWORD_HASH_HEX_CHARS} hex characters)"
            );
            match input.line("Select [1-2]: ")?.trim() {
                "" | "1" => {
                    return Ok((
                        Some(input.secret_required("Password (stored in profile): ")?),
                        None,
                    ));
                }
                "2" => loop {
                    let hash = input.secret_required("MD4 password hash (stored in profile): ")?;
                    if iweap::model::is_valid_password_hash(hash.as_str()) {
                        return Ok((None, Some(hash)));
                    }
                    eprintln!(
                        "Hash must contain exactly {PASSWORD_HASH_HEX_CHARS} hexadecimal characters."
                    );
                },
                _ => eprintln!("Choose 1 or 2."),
            }
        }
    }
    Ok((
        Some(input.secret_required("Password (stored in profile): ")?),
        None,
    ))
}

pub(crate) fn configure_tunneled_fields<R: BufRead>(
    input: &mut Input<R>,
    layer: &mut EapLayer,
    store_credentials: bool,
) -> Result<(), AppError> {
    layer.identity = if store_credentials {
        Some(input.required("Username: ")?)
    } else {
        input.optional("Username [optional]: ")?
    };
    if store_credentials {
        layer.password = Some(input.secret_required("Password (stored in profile): ")?);
    }
    Ok(())
}

pub(crate) struct TlsCommon {
    pub(crate) ca_cert: Option<PathBuf>,
    pub(crate) server_domain_mask: Option<String>,
    pub(crate) fast_reauthentication: Option<bool>,
}

pub(crate) fn configure_tls_common<R: BufRead>(
    input: &mut Input<R>,
) -> Result<TlsCommon, AppError> {
    let ca_cert = input.path("CA certificate path [optional]: ", false)?;
    if ca_cert.is_none() {
        eprintln!(
            "Warning: omitting CA certificate disables server verification (vulnerable to rogue APs)."
        );
    }
    let server_domain_mask = if ca_cert.is_some() {
        loop {
            let value = input.optional("Server domain mask [optional]: ")?;
            match value {
                None => break None,
                Some(value) if iweap::model::is_valid_domain_mask(&value) => break Some(value),
                Some(_) => eprintln!(
                    "Invalid domain mask. Use DNS labels, * labels, dots, and semicolons."
                ),
            }
        }
    } else {
        None
    };
    let fast_reauthentication =
        input.optional_bool("Fast reauthentication [y/n, blank to omit]: ")?;
    Ok(TlsCommon {
        ca_cert,
        server_domain_mask,
        fast_reauthentication,
    })
}

pub(crate) fn configure_tls_client_credentials<R: BufRead>(
    input: &mut Input<R>,
    store_credentials: bool,
) -> Result<(TlsClientCredentials, Option<Secret>), AppError> {
    let tty = is_stderr_tty();
    let num_0 = if tty { "\x1b[1m  0)\x1b[0m" } else { "  0)" };
    let client = loop {
        eprintln!(
            "\nTLS client credentials:\n{num_0} None\n  1) Certificate & private key\n  2) PKCS#12 bundle"
        );
        match input.line("Select [0-2]: ")?.trim() {
            "" | "0" => break TlsClientCredentials::None,
            "1" => {
                let certificate = input
                    .path("Client certificate path: ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                let key = input
                    .path("Private key path: ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                break TlsClientCredentials::CertificateAndKey { certificate, key };
            }
            "2" => {
                let bundle = input
                    .path("PKCS#12 bundle path: ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                break TlsClientCredentials::Pkcs12 { bundle };
            }
            _ => eprintln!("Choose 0, 1, or 2."),
        }
    };
    let client_key_passphrase =
        if store_credentials && !matches!(client, TlsClientCredentials::None) {
            let value = input.secret("Private key passphrase [optional]: ")?;
            (!value.is_empty()).then_some(value)
        } else {
            None
        };
    Ok((client, client_key_passphrase))
}

pub(crate) fn configure_tls<R: BufRead>(
    input: &mut Input<R>,
    method: EapMethod,
    store_credentials: bool,
) -> Result<TlsConfig, AppError> {
    let common = configure_tls_common(input)?;
    let (client, client_key_passphrase) = if method.supports_tls_client_credentials() {
        configure_tls_client_credentials(input, store_credentials)?
    } else {
        (TlsClientCredentials::None, None)
    };
    Ok(TlsConfig {
        ca_cert: common.ca_cert,
        server_domain_mask: common.server_domain_mask,
        fast_reauthentication: common.fast_reauthentication,
        client,
        client_key_passphrase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn method_selection_uses_model_catalog_order_and_bounds() {
        let mut input = Input::new(Cursor::new(b"0\ninvalid\n9\n"));
        assert_eq!(
            select_method(&mut input, "Outer", EapMethod::OUTER, None).expect("select method"),
            EapMethod::WfaTls
        );

        let mut input = Input::new(Cursor::new(b"15\n"));
        assert_eq!(
            select_ttls_phase2_method(&mut input, &[EapLayer::new(EapMethod::Ttls)], false,)
                .expect("select TTLS method"),
            EapMethod::WfaTls
        );
    }

    #[test]
    fn method_selection_accepts_case_insensitive_name_aliases() {
        let mut input = Input::new(Cursor::new(b"peap\n"));
        assert_eq!(
            select_method(&mut input, "Outer", EapMethod::OUTER, None)
                .expect("select PEAP by name"),
            EapMethod::Peap
        );

        let mut input = Input::new(Cursor::new(b"TLS\n"));
        assert_eq!(
            select_method(&mut input, "Outer", EapMethod::OUTER, None).expect("select TLS by name"),
            EapMethod::Tls
        );
    }

    #[test]
    fn interactive_menus_accept_enter_key_for_defaults() {
        let mut input = Input::new(Cursor::new(b"\n"));
        assert_eq!(
            select_method(&mut input, "Outer", EapMethod::OUTER, Some(EapMethod::Peap))
                .expect("default PEAP"),
            EapMethod::Peap
        );

        let mut input = Input::new(Cursor::new(b"\n"));
        assert_eq!(
            select_inner_eap_method(&mut input, &[EapLayer::new(EapMethod::Peap)], true)
                .expect("default MSCHAPV2 for inner PEAP"),
            EapMethod::Mschapv2
        );

        let mut input = Input::new(Cursor::new(b"\n"));
        assert!(!select_credential_handling(&mut input).expect("default credential handling"));

        let mut input = Input::new(Cursor::new(b"\n"));
        let (client, passphrase) =
            configure_tls_client_credentials(&mut input, false).expect("default client creds");
        assert_eq!(client, TlsClientCredentials::None);
        assert_eq!(passphrase, None);
    }

    #[test]
    fn enterprise_peap_mschapv2_flow_uses_defaults_for_outer_inner_and_format() {
        // 1. \n -> outer method: default PEAP
        // 2. \n -> credential storage: default Prompt at connection
        // 3. \n -> anonymous identity: omitted
        // 4. \n -> CA cert: omitted
        // 5. \n -> fast reauth: omitted
        // 6. \n -> inner method: default MSCHAPV2
        // 7. \n -> username: omitted (deferred to agent)
        let input_bytes = b"\n\n\n\n\n\n\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut input = Input::new(&mut cursor);

        let (profile, filename, store_credentials) =
            configure_profile(&mut input, String::from("@KMUTNB"))
                .expect("configure enterprise profile");

        assert!(!store_credentials);
        assert_eq!(filename, "=404b4d55544e42.8021x");
        assert_eq!(profile.layers.len(), 2);
        assert_eq!(profile.layers[0].method, EapMethod::Peap);
        assert_eq!(profile.layers[1].method, EapMethod::Mschapv2);
        assert_eq!(profile.layers[1].identity, None);
    }

    fn peap_layer() -> EapLayer {
        let mut layer = EapLayer::new(EapMethod::Peap);
        layer.tls = Some(TlsConfig {
            ca_cert: None,
            server_domain_mask: None,
            fast_reauthentication: None,
            client: TlsClientCredentials::None,
            client_key_passphrase: None,
        });
        layer
    }

    fn nested_peap_layers(count: usize) -> Vec<EapLayer> {
        (0..count).map(|_| peap_layer()).collect()
    }

    #[test]
    fn cli_filters_tls_methods_at_prefix_boundary() {
        let existing_layers = nested_peap_layers(2);
        let mut input = Input::new(Cursor::new(b"9\n"));
        assert_eq!(
            select_inner_eap_method(&mut input, &existing_layers, false)
                .expect("select inner method"),
            EapMethod::Ttls
        );
    }

    #[test]
    fn cli_uses_known_credential_mode_for_mschapv2_selection() {
        let existing_layers = nested_peap_layers(4);

        let mut input = Input::new(Cursor::new(b"3\n"));
        assert_eq!(
            select_inner_eap_method(&mut input, &existing_layers, false)
                .expect("agent-compatible method"),
            EapMethod::Mschapv2
        );

        let mut input = Input::new(Cursor::new(b"3\n"));
        assert_eq!(
            select_inner_eap_method(&mut input, &existing_layers, true)
                .expect("stored-compatible method"),
            EapMethod::Pwd
        );
    }

    #[test]
    fn cli_reprompts_incompatible_deep_agent_mschapv2_identity() {
        let existing_layers = nested_peap_layers(4);
        let mut selection_input = Input::new(Cursor::new(b"3\n"));
        assert_eq!(
            select_inner_eap_method(&mut selection_input, &existing_layers, false)
                .expect("agent-compatible method"),
            EapMethod::Mschapv2
        );

        let mut input = Input::new(Cursor::new(b"user\n\n"));
        let mut layers = existing_layers;
        configure_layer(
            &mut input,
            &mut layers,
            EapMethod::Mschapv2,
            4,
            false,
            false,
        )
        .expect("reprompt until identity is omitted");

        assert_eq!(
            layers.last().and_then(|layer| layer.identity.as_deref()),
            None
        );
        assert_eq!(
            Profile::new(String::from("Office Wi-Fi"), layers).validate(),
            Ok(())
        );
    }

    #[test]
    fn layer_configuration_follows_model_capabilities() {
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(Cursor::new(b"")),
            &mut layers,
            EapMethod::Sim,
            0,
            true,
            false,
        )
        .expect("configure SIM");
        assert_eq!(layers, vec![EapLayer::new(EapMethod::Sim)]);

        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(Cursor::new(b"\n\n\n1\n\n")),
            &mut layers,
            EapMethod::Peap,
            0,
            true,
            false,
        )
        .expect("configure PEAP");
        assert_eq!(
            layers.iter().map(|layer| layer.method).collect::<Vec<_>>(),
            [EapMethod::Peap, EapMethod::Gtc]
        );

        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(Cursor::new(b"\n\n\n1\n\n")),
            &mut layers,
            EapMethod::Ttls,
            0,
            true,
            false,
        )
        .expect("configure TTLS");
        assert_eq!(
            layers.iter().map(|layer| layer.method).collect::<Vec<_>>(),
            [EapMethod::Ttls, EapMethod::TunneledPap]
        );
    }

    #[test]
    fn configuration_rejects_excessive_depth_and_omits_credentials() {
        let error = configure_layer(
            &mut Input::new(Cursor::new(b"")),
            &mut Vec::new(),
            EapMethod::Sim,
            MAX_EAP_DEPTH + 1,
            false,
            false,
        )
        .expect_err("depth must be bounded");
        assert!(matches!(
            error,
            AppError::Validation(ValidationError::TooManyEapLayers)
        ));

        let mut input = Input::new(Cursor::new(b"username\n"));
        assert_eq!(
            prompt_identity(&mut input, EapMethod::Mschapv2, false, false)
                .expect("optional identity"),
            Some(String::from("username"))
        );
        assert_eq!(
            configure_password(&mut input, EapMethod::Mschapv2, false)
                .expect("credentials omitted"),
            (None, None)
        );
    }

    #[test]
    fn cli_peap_flow_prompts_tls_common_and_never_client_credentials() {
        let input_bytes = b"anon-peap\n/etc/hosts\nradius.example.com;*.corp\ny\n3\nmschap-user\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(&mut cursor),
            &mut layers,
            EapMethod::Peap,
            0,
            true,
            false,
        )
        .expect("configure PEAP");

        assert_eq!(
            cursor.position() as usize,
            input_bytes.len(),
            "all expected prompts were consumed without asking for client credentials"
        );
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].method, EapMethod::Peap);
        assert_eq!(layers[0].identity.as_deref(), Some("anon-peap"));
        let tls = layers[0].tls.as_ref().expect("peap tls config");
        assert_eq!(tls.ca_cert, Some(PathBuf::from("/etc/hosts")));
        assert_eq!(
            tls.server_domain_mask.as_deref(),
            Some("radius.example.com;*.corp")
        );
        assert_eq!(tls.fast_reauthentication, Some(true));
        assert_eq!(tls.client, TlsClientCredentials::None);
        assert_eq!(tls.client_key_passphrase, None);

        assert_eq!(layers[1].method, EapMethod::Mschapv2);
        assert_eq!(layers[1].identity.as_deref(), Some("mschap-user"));
        assert_eq!(layers[1].password, None);
        assert_eq!(layers[1].password_hash, None);
        assert_eq!(layers[1].tls, None);
    }

    #[test]
    fn cli_ttls_flow_prompts_tls_common_and_never_client_credentials() {
        let input_bytes = b"anon-ttls\n/etc/hosts\n*.example.org\nn\n1\npap-user\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(&mut cursor),
            &mut layers,
            EapMethod::Ttls,
            0,
            true,
            false,
        )
        .expect("configure TTLS");

        assert_eq!(
            cursor.position() as usize,
            input_bytes.len(),
            "all expected prompts were consumed without asking for client credentials"
        );
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].method, EapMethod::Ttls);
        assert_eq!(layers[0].identity.as_deref(), Some("anon-ttls"));
        let ttls_tls = layers[0].tls.as_ref().expect("TTLS TLS config");
        assert_eq!(
            ttls_tls.ca_cert.as_deref(),
            Some(std::path::Path::new("/etc/hosts"))
        );
        assert_eq!(
            ttls_tls.server_domain_mask.as_deref(),
            Some("*.example.org")
        );
        assert_eq!(ttls_tls.fast_reauthentication, Some(false));
        assert_eq!(ttls_tls.client, TlsClientCredentials::None);
        assert_eq!(ttls_tls.client_key_passphrase, None);

        assert_eq!(layers[1].method, EapMethod::TunneledPap);
        assert_eq!(layers[1].identity.as_deref(), Some("pap-user"));
    }

    #[test]
    fn cli_direct_tls_and_wfa_tls_flows_prompt_client_credentials() {
        let input_bytes = b"tls-user\n/etc/hosts\n\ny\n1\n/etc/hosts\n/etc/hosts\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(&mut cursor),
            &mut layers,
            EapMethod::Tls,
            0,
            true,
            false,
        )
        .expect("configure TLS");

        assert_eq!(cursor.position() as usize, input_bytes.len());
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].method, EapMethod::Tls);
        let tls = layers[0].tls.as_ref().expect("TLS config");
        assert_eq!(
            tls.client,
            TlsClientCredentials::CertificateAndKey {
                certificate: std::path::PathBuf::from("/etc/hosts"),
                key: std::path::PathBuf::from("/etc/hosts"),
            }
        );

        let input_bytes = b"wfa-user\n\n\n2\n/etc/hosts\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(&mut cursor),
            &mut layers,
            EapMethod::WfaTls,
            0,
            true,
            false,
        )
        .expect("configure WFA-TLS");

        assert_eq!(cursor.position() as usize, input_bytes.len());
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].method, EapMethod::WfaTls);
        let tls = layers[0].tls.as_ref().expect("WFA-TLS config");
        assert_eq!(
            tls.client,
            TlsClientCredentials::Pkcs12 {
                bundle: std::path::PathBuf::from("/etc/hosts"),
            }
        );

        let mut layers = Vec::new();
        let error = configure_layer(
            &mut Input::new(Cursor::new(b"tls-user\n\n\n")),
            &mut layers,
            EapMethod::Tls,
            0,
            true,
            false,
        )
        .expect_err("TLS must prompt for client credentials");
        assert!(matches!(
            error,
            AppError::Input(crate::input::InputError::EndOfInput)
        ));
    }

    #[test]
    fn cli_nested_peap_to_inner_tls_prompts_client_credentials_on_inner_tls() {
        let input_bytes = b"anon-peap\n\n\n9\ninner-tls-user\n\n\n1\n/etc/hosts\n/etc/hosts\n";
        let mut cursor = Cursor::new(&input_bytes[..]);
        let mut layers = Vec::new();
        configure_layer(
            &mut Input::new(&mut cursor),
            &mut layers,
            EapMethod::Peap,
            0,
            true,
            false,
        )
        .expect("configure PEAP->TLS");

        assert_eq!(cursor.position() as usize, input_bytes.len());
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].method, EapMethod::Peap);
        assert_eq!(
            layers[0].tls.as_ref().unwrap().client,
            TlsClientCredentials::None
        );
        assert_eq!(layers[1].method, EapMethod::Tls);
        assert_eq!(
            layers[1].tls.as_ref().unwrap().client,
            TlsClientCredentials::CertificateAndKey {
                certificate: std::path::PathBuf::from("/etc/hosts"),
                key: std::path::PathBuf::from("/etc/hosts"),
            }
        );
    }
}
