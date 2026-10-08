mod cli;
mod input;

use cli::{AppError, configure_profile, parse_args, show_preview};
use input::{Input, InputError, SignalManager};
use iweap::model::MAX_SSID_BYTES;
use iweap::{IWD_DIRECTORY, InstallRequest, PROFILE_MODE};
use std::io;

fn main() {
    if let Err(error) = run() {
        match &error {
            AppError::Input(InputError::Interrupted(signal)) => {
                std::process::exit(128 + signal);
            }
            AppError::UnknownOption(_) => {
                eprintln!("iweap: {error}");
                std::process::exit(2);
            }
            _ => {
                eprintln!("iweap: {error}");
                std::process::exit(1);
            }
        }
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

    let (profile, filename, store_credentials) = configure_profile(&mut input, ssid)?;
    show_preview(&profile, &filename, store_credentials)?;

    if options.dry_run {
        return Ok(());
    }

    let install_prompt = format!("Install this profile into {IWD_DIRECTORY}? [y/N]: ");
    if !input.yes_no(&install_prompt, false)? {
        eprintln!("Installation aborted.");
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
        eprintln!("Existing profile left unmodified; installation aborted.");
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
