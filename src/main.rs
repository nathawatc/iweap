mod input;

use input::{Input, InputError, SignalManager};
use iweap::model::{MAX_EAP_DEPTH, MAX_SSID_BYTES, MethodKind, PASSWORD_HASH_HEX_CHARS};
use iweap::{
    EapLayer, EapMethod, IWD_DIRECTORY, InstallRequest, PROFILE_MODE, Profile, Secret,
    TlsClientCredentials, TlsConfig, ValidationError,
};
use std::io::{self, BufRead};

fn usage() -> String {
    format!(
        "Usage: iweap [--dry-run|--preview] [--help]\n\nInteractively create an IWD .8021x profile for {IWD_DIRECTORY}/.\n\nOptions:\n  --dry-run, --preview  Generate and display a redacted profile; do not install it.\n  --help                Show this help.\n\nThe unprivileged client sends typed requests over the system D-Bus. The root\nservice performs direct Polkit authorization and writes only {IWD_DIRECTORY}.\nCredentials are omitted by default so IWD can request them through its agent.\n"
    )
}

#[derive(Debug)]
enum AppError {
    Input(InputError),
    Validation(ValidationError),
    Bus(zbus::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Validation(error) => error.fmt(f),
            Self::Bus(error) => write!(f, "D-Bus request failed: {error}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<InputError> for AppError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<ValidationError> for AppError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<zbus::Error> for AppError {
    fn from(error: zbus::Error) -> Self {
        Self::Bus(error)
    }
}

#[derive(Clone, Copy)]
struct Options {
    dry_run: bool,
}

fn main() {
    if let Err(error) = run() {
        let exit_code = match &error {
            AppError::Input(InputError::Interrupted(signal)) => 128 + signal,
            _ => 1,
        };
        eprintln!("iweap: {error}");
        std::process::exit(exit_code);
    }
}

fn run() -> Result<(), AppError> {
    let Some(options) = parse_args(std::env::args().skip(1))? else {
        return Ok(());
    };
    let signals = SignalManager::install()?;
    let stdin = io::stdin();
    let mut input = Input::with_signals(stdin.lock(), signals);

    let ssid = loop {
        let value = input.required("SSID: ")?;
        if iweap::model::validate_ssid(&value).is_ok() {
            break value;
        }
        eprintln!("SSID must contain 1 to {MAX_SSID_BYTES} bytes.");
    };
    let filename = iweap::model::profile_filename_for_ssid(&ssid);
    eprintln!("IWD profile filename: {filename}");

    let outer = select_method(&mut input, "Outer EAP method", EapMethod::OUTER)?;
    let store_credentials = if outer.is_sim_method() {
        false
    } else {
        select_credential_handling(&mut input)?
    };

    let mut layers = Vec::new();
    configure_layer(&mut input, &mut layers, outer, 0, true, store_credentials)?;
    let profile = Profile::new(ssid, layers);
    profile.validate()?;
    show_preview(&profile, &filename, store_credentials)?;

    if options.dry_run {
        return Ok(());
    }

    let install_prompt = format!("Install this profile into {IWD_DIRECTORY}? [y/N]: ");
    if !input.yes_no(&install_prompt, false)? {
        return Ok(());
    }

    let connection = zbus::blocking::Connection::system()?;
    let proxy = iweap::ipc::ProfileInstallerProxyBlocking::new(&connection)?;
    let inspection = proxy.inspect_profile(&profile.ssid)?;
    let overwrite = if inspection.state.exists {
        eprintln!("Warning: {IWD_DIRECTORY}/{filename} already exists.");
        input.yes_no("Overwrite existing profile? [y/N]: ", false)?
    } else {
        false
    };
    if inspection.state.exists && !overwrite {
        return Ok(());
    }

    let request = InstallRequest {
        profile: profile.into_wire()?,
        expected_state: inspection.state,
        overwrite,
    };
    let installed_filename = proxy.install_profile(request)?;
    println!(
        "Installed {IWD_DIRECTORY}/{installed_filename} with root:root ownership and mode {PROFILE_MODE:04o}."
    );
    Ok(())
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<Option<Options>, AppError> {
    let mut dry_run = false;
    for argument in arguments {
        match argument.as_str() {
            "--dry-run" | "--preview" => dry_run = true,
            "--help" | "-h" => {
                print!("{}", usage());
                return Ok(None);
            }
            _ => {
                eprint!("{}", usage());
                return Err(AppError::Input(InputError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown option",
                ))));
            }
        }
    }
    Ok(Some(Options { dry_run }))
}

fn select_method<R: BufRead>(
    input: &mut Input<R>,
    title: &str,
    methods: &[EapMethod],
) -> Result<EapMethod, AppError> {
    loop {
        eprintln!("\n{title}:");
        for (index, method) in methods.iter().enumerate() {
            eprintln!("{:>3}) {}", index + 1, method.name());
        }
        let prompt = format!("Select method [1-{}]: ", methods.len());
        let selection = input.line(&prompt)?.parse::<usize>().ok();
        if let Some(method) = selection
            .and_then(|selection| selection.checked_sub(1))
            .and_then(|index| methods.get(index))
        {
            return Ok(*method);
        }
        eprintln!("Choose a number from 1 to {}.", methods.len());
    }
}

fn select_credential_handling<R: BufRead>(input: &mut Input<R>) -> Result<bool, AppError> {
    loop {
        eprintln!(
            "\nCredential handling:\n  1) Ask IWD agent at connection time (recommended; do not store secrets)\n  2) Store credentials in profile"
        );
        match input.line("Select credential handling [1-2]: ")?.as_str() {
            "1" => return Ok(false),
            "2" => return Ok(true),
            _ => eprintln!("Choose 1 or 2."),
        }
    }
}

fn select_ttls_phase2_method<R: BufRead>(input: &mut Input<R>) -> Result<EapMethod, AppError> {
    let methods = EapMethod::TTLS_TUNNELED
        .iter()
        .chain(EapMethod::INNER)
        .copied()
        .collect::<Vec<_>>();
    select_method(input, "TTLS phase-2 method", &methods)
}

fn configure_layer<R: BufRead>(
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
            let child = select_method(input, "Inner EAP method", EapMethod::INNER)?;
            configure_layer(input, layers, child, depth + 1, false, store_credentials)?;
        }
        EapMethod::Ttls => {
            let child = select_ttls_phase2_method(input)?;
            configure_layer(input, layers, child, depth + 1, false, store_credentials)?;
        }
        _ => {}
    }
    Ok(())
}

fn prompt_identity<R: BufRead>(
    input: &mut Input<R>,
    method: EapMethod,
    outer: bool,
    store_credentials: bool,
) -> Result<Option<String>, AppError> {
    if method.is_sim_method() {
        return Ok(None);
    }
    let scope = if outer {
        "Outer identity / anonymous identity"
    } else {
        "Phase-2 identity / username"
    };
    let password_method = method.is_password_method();
    if password_method && store_credentials {
        Ok(Some(input.required(&format!(
            "{scope} (required when storing credentials): "
        ))?))
    } else if password_method {
        Ok(input.optional(&format!("{scope} (blank to let IWD ask): "))?)
    } else {
        Ok(input.optional(&format!(
            "{scope} (blank to omit; some RADIUS servers require this): "
        ))?)
    }
}

fn configure_password<R: BufRead>(
    input: &mut Input<R>,
    method: EapMethod,
    store_credentials: bool,
) -> Result<(Option<Secret>, Option<Secret>), AppError> {
    if !store_credentials {
        return Ok((None, None));
    }
    if method == EapMethod::Mschapv2 {
        loop {
            eprintln!(
                "\nMSCHAPV2 credential format:\n  1) Password (IWD derives the NT hash)\n  2) Existing {PASSWORD_HASH_HEX_CHARS}-hex-character MD4 password hash"
            );
            match input.line("Select credential format [1-2]: ")?.as_str() {
                "1" => {
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

fn configure_tunneled_fields<R: BufRead>(
    input: &mut Input<R>,
    layer: &mut EapLayer,
    store_credentials: bool,
) -> Result<(), AppError> {
    layer.identity = if store_credentials {
        Some(input.required("Phase-2 identity / username: ")?)
    } else {
        input.optional("Phase-2 identity / username (blank to let IWD ask): ")?
    };
    if store_credentials {
        layer.password = Some(input.secret_required("Phase-2 password (stored in profile): ")?);
    }
    Ok(())
}

struct TlsCommon {
    ca_cert: Option<std::path::PathBuf>,
    server_domain_mask: Option<String>,
    fast_reauthentication: Option<bool>,
}

fn configure_tls_common<R: BufRead>(input: &mut Input<R>) -> Result<TlsCommon, AppError> {
    let ca_cert = input.path(
        "CA certificate path (absolute; blank disables CA verification): ",
        false,
    )?;
    let server_domain_mask = if ca_cert.is_some() {
        loop {
            let value =
                input.optional("Server domain mask (blank to omit; use ; between masks): ")?;
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
        input.optional_bool("Fast reauthentication [y/n/blank to omit]: ")?;
    Ok(TlsCommon {
        ca_cert,
        server_domain_mask,
        fast_reauthentication,
    })
}

fn configure_tls_client_credentials<R: BufRead>(
    input: &mut Input<R>,
    store_credentials: bool,
) -> Result<(TlsClientCredentials, Option<Secret>), AppError> {
    let client = loop {
        eprintln!(
            "\nTLS client credentials:\n  0) No client certificate\n  1) Separate client certificate and private key\n  2) PKCS#12 client key bundle"
        );
        match input
            .line("Select client credential form [0-2]: ")?
            .as_str()
        {
            "0" => break TlsClientCredentials::None,
            "1" => {
                let certificate = input
                    .path("Client certificate path (absolute): ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                let key = input
                    .path("Private key path (absolute): ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                break TlsClientCredentials::CertificateAndKey { certificate, key };
            }
            "2" => {
                let bundle = input
                    .path("PKCS#12 client key bundle path (absolute): ", true)?
                    .ok_or(ValidationError::InvalidPath)?;
                break TlsClientCredentials::Pkcs12 { bundle };
            }
            _ => eprintln!("Choose 0, 1, or 2."),
        }
    };
    let client_key_passphrase = if store_credentials
        && !matches!(client, TlsClientCredentials::None)
    {
        let value = input
            .secret("Private-key passphrase (blank to let IWD ask or for an unencrypted key): ")?;
        (!value.is_empty()).then_some(value)
    } else {
        None
    };
    Ok((client, client_key_passphrase))
}

fn configure_tls<R: BufRead>(
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

fn show_preview(
    profile: &Profile,
    filename: &str,
    store_credentials: bool,
) -> Result<(), AppError> {
    println!("\nProfile filename: {filename}");
    println!("Install path: {IWD_DIRECTORY}/{filename}\n");
    print!("{}", profile.redacted_config()?);
    if store_credentials {
        println!("\nStored secrets are shown as <redacted>.");
    } else {
        println!(
            "\nCredentials are not stored in this profile.\nIWD will obtain any required credentials at connection time."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn arguments_accept_preview_aliases_and_reject_unknown_options() {
        let options = parse_args([String::from("--preview")])
            .expect("valid arguments")
            .expect("continue");
        assert!(options.dry_run);
        assert!(
            parse_args([String::from("--help")])
                .expect("help argument")
                .is_none()
        );
        assert!(matches!(
            parse_args([String::from("--unknown")]),
            Err(AppError::Input(InputError::Io(error)))
                if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn method_selection_uses_model_catalog_order_and_bounds() {
        let mut input = Input::new(Cursor::new(b"0\ninvalid\n9\n"));
        assert_eq!(
            select_method(&mut input, "Outer", EapMethod::OUTER).expect("select method"),
            EapMethod::WfaTls
        );

        let mut input = Input::new(Cursor::new(b"15\n"));
        assert_eq!(
            select_ttls_phase2_method(&mut input).expect("select TTLS method"),
            EapMethod::WfaTls
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
        // Inputs:
        // 1. "anon-peap\n" -> PEAP outer identity
        // 2. "/etc/hosts\n" -> CA cert path (existing regular file)
        // 3. "radius.example.com;*.corp\n" -> Server domain mask (prompted because CA cert is Some)
        // 4. "y\n" -> Fast reauthentication: true
        // (NO client credential prompt!)
        // 5. "3\n" -> Inner EAP method: MSCHAPv2 (index 3 in EapMethod::INNER)
        // 6. "mschap-user\n" -> MSCHAPv2 identity
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
        let peap_tls = layers[0].tls.as_ref().expect("PEAP TLS config");
        assert_eq!(
            peap_tls.ca_cert.as_deref(),
            Some(std::path::Path::new("/etc/hosts"))
        );
        assert_eq!(
            peap_tls.server_domain_mask.as_deref(),
            Some("radius.example.com;*.corp")
        );
        assert_eq!(peap_tls.fast_reauthentication, Some(true));
        assert_eq!(peap_tls.client, TlsClientCredentials::None);
        assert_eq!(peap_tls.client_key_passphrase, None);

        assert_eq!(layers[1].method, EapMethod::Mschapv2);
        assert_eq!(layers[1].identity.as_deref(), Some("mschap-user"));
    }

    #[test]
    fn cli_ttls_flow_prompts_tls_common_and_never_client_credentials() {
        // Inputs:
        // 1. "anon-ttls\n" -> TTLS outer identity
        // 2. "/etc/hosts\n" -> CA cert path
        // 3. "*.example.org\n" -> Server domain mask
        // 4. "n\n" -> Fast reauthentication: false
        // (NO client credential prompt!)
        // 5. "1\n" -> Phase-2 method: Tunneled-PAP (index 1 in TTLS_TUNNELED + INNER)
        // 6. "pap-user\n" -> Tunneled-PAP identity
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
        // Direct TLS with CertificateAndKey:
        // 1. "tls-user\n" -> identity
        // 2. "/etc/hosts\n" -> CA cert path
        // 3. "\n" -> Server domain mask omitted
        // 4. "y\n" -> Fast reauthentication
        // 5. "1\n" -> Client credential form 1: Certificate and key
        // 6. "/etc/hosts\n" -> Client certificate path
        // 7. "/etc/hosts\n" -> Client private key path
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

        // WFA-TLS with PKCS#12:
        // 1. "wfa-user\n" -> identity
        // 2. "\n" -> CA cert omitted
        // 3. "\n" -> Fast reauthentication omitted
        // 4. "2\n" -> Client credential form 2: PKCS#12 bundle
        // 5. "/etc/hosts\n" -> Bundle path
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

        // Direct TLS must still prompt for the client credential form.
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
        assert!(matches!(error, AppError::Input(InputError::EndOfInput)));
    }

    #[test]
    fn cli_nested_peap_to_inner_tls_prompts_client_credentials_on_inner_tls() {
        // Outer PEAP:
        // 1. "anon-peap\n" -> PEAP identity
        // 2. "\n" -> PEAP CA omitted
        // 3. "\n" -> PEAP fast reauth omitted
        // (NO outer client credential prompt!)
        // 4. "9\n" -> Inner method selection: 9 = TLS
        // Inner TLS:
        // 5. "inner-tls-user\n" -> inner TLS identity
        // 6. "\n" -> inner CA omitted
        // 7. "\n" -> inner fast reauth omitted
        // 8. "1\n" -> inner client credential form 1: Certificate and key
        // 9. "/etc/hosts\n" -> inner client cert
        // 10. "/etc/hosts\n" -> inner private key
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
