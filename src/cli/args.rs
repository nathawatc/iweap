use crate::input::InputError;
use iweap::{IWD_DIRECTORY, ValidationError};

pub fn usage() -> String {
    format!(
        "Usage: iweap [--dry-run|--preview] [-h|--help] [-V|--version]\n\nInteractively create an IWD .8021x profile for {IWD_DIRECTORY}/.\n\nOptions:\n  --dry-run, --preview  Generate and display a redacted profile; do not install it.\n  -h, --help            Show this help.\n  -V, --version         Show version information.\n\nThe unprivileged client sends typed requests over the system D-Bus. The root\nservice performs direct Polkit authorization and writes only {IWD_DIRECTORY}.\nCredentials are omitted by default so IWD can request them through its agent.\n"
    )
}

#[derive(Debug)]
pub enum AppError {
    Input(InputError),
    Validation(ValidationError),
    Bus(zbus::Error),
    UnknownOption(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Validation(error) => error.fmt(f),
            Self::Bus(error) => write!(f, "D-Bus request failed: {error}"),
            Self::UnknownOption(option) => {
                write!(
                    f,
                    "unrecognized option '{option}'\nTry 'iweap --help' for more information."
                )
            }
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

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub dry_run: bool,
}

pub fn parse_args(
    arguments: impl IntoIterator<Item = String>,
) -> Result<Option<Options>, AppError> {
    let mut dry_run = false;
    for argument in arguments {
        match argument.as_str() {
            "--dry-run" | "--preview" => dry_run = true,
            "-h" | "--help" => {
                print!("{}", usage());
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("iweap {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            _ => {
                return Err(AppError::UnknownOption(argument));
            }
        }
    }
    Ok(Some(Options { dry_run }))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            parse_args([String::from("-h")])
                .expect("short help argument")
                .is_none()
        );
        assert!(
            parse_args([String::from("--version")])
                .expect("version argument")
                .is_none()
        );
        assert!(
            parse_args([String::from("-V")])
                .expect("short version argument")
                .is_none()
        );
        let err = parse_args([String::from("--unknown")]).expect_err("unknown option");
        assert!(matches!(err, AppError::UnknownOption(ref opt) if opt == "--unknown"));
        assert_eq!(
            err.to_string(),
            "unrecognized option '--unknown'\nTry 'iweap --help' for more information."
        );
        let help_text = usage();
        assert!(help_text.contains("-h, --help"));
        assert!(help_text.contains("-V, --version"));
    }
}
