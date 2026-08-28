mod input;

use input::{Input, InputError};
use iweap::model::MAX_EAP_DEPTH;
use iweap::{
    EapLayer, EapMethod, IWD_DIRECTORY, InstallRequest, Profile, Secret, TlsClientCredentials,
    TlsConfig, ValidationError,
};
use std::io::{self, BufRead};

const USAGE: &str = "Usage: iweap [--dry-run|--preview] [--help]\n\nInteractively create an IWD .8021x profile for /var/lib/iwd/.\n\nOptions:\n  --dry-run, --preview  Generate and display a redacted profile; do not install it.\n  --help                Show this help.\n\nThe unprivileged client sends typed requests over the system D-Bus. The root\nservice performs direct Polkit authorization and writes only /var/lib/iwd.\nCredentials are omitted by default so IWD can request them through its agent.\n";

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
        eprintln!("iweap: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let Some(options) = parse_args()? else {
        return Ok(());
    };
    let stdin = io::stdin();
    let mut input = Input::new(stdin.lock());

    let ssid = loop {
        let value = input.required("SSID: ")?;
        if iweap::model::validate_ssid(&value).is_ok() {
            break value;
        }
        eprintln!("SSID must contain 1 to 32 bytes.");
    };
    let filename = iweap::model::profile_filename_for_ssid(&ssid);
    eprintln!("IWD profile filename: {filename}");

    let outer = select_outer_method(&mut input)?;
    let store_credentials = match outer {
        EapMethod::Aka | EapMethod::AkaPrime | EapMethod::Sim => false,
        _ => select_credential_handling(&mut input)?,
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
        "Installed {IWD_DIRECTORY}/{installed_filename} with root:root ownership and mode 0600."
    );
    Ok(())
}

fn parse_args() -> Result<Option<Options>, AppError> {
    let mut dry_run = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--dry-run" | "--preview" => dry_run = true,
            "--help" | "-h" => {
                print!("{}", USAGE);
                return Ok(None);
            }
            _ => {
                eprint!("{}", USAGE);
                return Err(AppError::Input(InputError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown option",
                ))));
            }
        }
    }
    Ok(Some(Options { dry_run }))
}

fn select_outer_method<R: BufRead>(input: &mut Input<R>) -> Result<EapMethod, AppError> {
    loop {
        eprintln!(
            "\nOuter EAP method:\n  1) AKA\n  2) AKA'\n  3) MSCHAPV2\n  4) PEAP\n  5) PWD\n  6) SIM\n  7) TLS\n  8) TTLS\n  9) WFA-TLS (expanded TLS method supported by current IWD source)"
        );
        match input.line("Select outer EAP method [1-9]: ")?.as_str() {
            "1" => return Ok(EapMethod::Aka),
            "2" => return Ok(EapMethod::AkaPrime),
            "3" => return Ok(EapMethod::Mschapv2),
            "4" => return Ok(EapMethod::Peap),
            "5" => return Ok(EapMethod::Pwd),
            "6" => return Ok(EapMethod::Sim),
            "7" => return Ok(EapMethod::Tls),
            "8" => return Ok(EapMethod::Ttls),
            "9" => return Ok(EapMethod::WfaTls),
            _ => eprintln!("Choose a number from 1 to 9."),
        }
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

fn select_inner_method<R: BufRead>(input: &mut Input<R>) -> Result<EapMethod, AppError> {
    loop {
        eprintln!(
            "\nInner EAP method:\n  1) GTC\n  2) MD5\n  3) MSCHAPV2\n  4) PWD\n  5) AKA\n  6) AKA'\n  7) PEAP\n  8) SIM\n  9) TLS\n 10) TTLS\n 11) WFA-TLS (expanded TLS method)"
        );
        match input.line("Select inner EAP method [1-11]: ")?.as_str() {
            "1" => return Ok(EapMethod::Gtc),
            "2" => return Ok(EapMethod::Md5),
            "3" => return Ok(EapMethod::Mschapv2),
            "4" => return Ok(EapMethod::Pwd),
            "5" => return Ok(EapMethod::Aka),
            "6" => return Ok(EapMethod::AkaPrime),
            "7" => return Ok(EapMethod::Peap),
            "8" => return Ok(EapMethod::Sim),
            "9" => return Ok(EapMethod::Tls),
            "10" => return Ok(EapMethod::Ttls),
            "11" => return Ok(EapMethod::WfaTls),
            _ => eprintln!("Choose a number from 1 to 11."),
        }
    }
}

fn select_ttls_phase2_method<R: BufRead>(input: &mut Input<R>) -> Result<EapMethod, AppError> {
    loop {
        eprintln!(
            "\nTTLS phase-2 method:\n  1) Tunneled-PAP\n  2) Tunneled-CHAP\n  3) Tunneled-MSCHAP\n  4) Tunneled-MSCHAPv2\n  5) GTC\n  6) MD5\n  7) MSCHAPV2\n  8) PWD\n  9) AKA\n 10) AKA'\n 11) PEAP\n 12) SIM\n 13) TLS\n 14) TTLS\n 15) WFA-TLS (expanded TLS method)"
        );
        match input.line("Select TTLS phase-2 method [1-15]: ")?.as_str() {
            "1" => return Ok(EapMethod::TunneledPap),
            "2" => return Ok(EapMethod::TunneledChap),
            "3" => return Ok(EapMethod::TunneledMschap),
            "4" => return Ok(EapMethod::TunneledMschapv2),
            "5" => return Ok(EapMethod::Gtc),
            "6" => return Ok(EapMethod::Md5),
            "7" => return Ok(EapMethod::Mschapv2),
            "8" => return Ok(EapMethod::Pwd),
            "9" => return Ok(EapMethod::Aka),
            "10" => return Ok(EapMethod::AkaPrime),
            "11" => return Ok(EapMethod::Peap),
            "12" => return Ok(EapMethod::Sim),
            "13" => return Ok(EapMethod::Tls),
            "14" => return Ok(EapMethod::Ttls),
            "15" => return Ok(EapMethod::WfaTls),
            _ => eprintln!("Choose a number from 1 to 15."),
        }
    }
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
    match method {
        EapMethod::Aka | EapMethod::AkaPrime | EapMethod::Sim => {}
        EapMethod::Gtc | EapMethod::Md5 | EapMethod::Mschapv2 | EapMethod::Pwd => {
            layer.identity = prompt_identity(input, method, outer, store_credentials)?;
            let (password, password_hash) = configure_password(input, method, store_credentials)?;
            layer.password = password;
            layer.password_hash = password_hash;
        }
        EapMethod::Tls | EapMethod::WfaTls | EapMethod::Peap | EapMethod::Ttls => {
            layer.identity = prompt_identity(input, method, outer, store_credentials)?;
            layer.tls = Some(configure_tls(input, store_credentials)?);
        }
        EapMethod::TunneledPap
        | EapMethod::TunneledChap
        | EapMethod::TunneledMschap
        | EapMethod::TunneledMschapv2 => {
            configure_tunneled_fields(input, &mut layer, store_credentials)?;
        }
    }
    layers.push(layer);

    match method {
        EapMethod::Peap => {
            let child = select_inner_method(input)?;
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
    if matches!(
        method,
        EapMethod::Aka | EapMethod::AkaPrime | EapMethod::Sim
    ) {
        return Ok(None);
    }
    let scope = if outer {
        "Outer identity / anonymous identity"
    } else {
        "Phase-2 identity / username"
    };
    let password_method = matches!(
        method,
        EapMethod::Gtc | EapMethod::Md5 | EapMethod::Mschapv2 | EapMethod::Pwd
    );
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
                "\nMSCHAPV2 credential format:\n  1) Password (IWD derives the NT hash)\n  2) Existing 32-hex-character MD4 password hash"
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
                    if hash.as_str().len() == 32
                        && hash.as_str().bytes().all(|byte| byte.is_ascii_hexdigit())
                    {
                        return Ok((None, Some(hash)));
                    }
                    eprintln!("Hash must contain exactly 32 hexadecimal characters.");
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

fn configure_tls<R: BufRead>(
    input: &mut Input<R>,
    store_credentials: bool,
) -> Result<TlsConfig, AppError> {
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
    Ok(TlsConfig {
        ca_cert,
        server_domain_mask,
        fast_reauthentication,
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
