use super::args::AppError;
use iweap::{IWD_DIRECTORY, Profile};

pub fn show_preview(
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
