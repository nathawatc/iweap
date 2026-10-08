use super::args::AppError;
use iweap::{IWD_DIRECTORY, Profile};

pub fn show_preview(
    profile: &Profile,
    filename: &str,
    store_credentials: bool,
) -> Result<(), AppError> {
    eprintln!("  Target: {IWD_DIRECTORY}/{filename}\n");
    print!("{}", profile.redacted_config()?);
    if store_credentials {
        eprintln!("\nStored secrets are shown as <redacted>.");
    } else {
        eprintln!(
            "\nCredentials are not stored in this profile (IWD agent will prompt at connection)."
        );
    }
    Ok(())
}
