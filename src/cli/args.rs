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
            Self::Bus(error) => format_bus_error(error, f),
            Self::UnknownOption(option) => {
                write!(
                    f,
                    "unrecognized option '{option}'\nTry 'iweap --help' for more information."
                )
            }
        }
    }
}

fn format_bus_error(error: &zbus::Error, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if let zbus::Error::FDO(fdo_err) = error {
        match fdo_err.as_ref() {
            zbus::fdo::Error::AccessDenied(_) => {
                return write!(f, "authorization denied or cancelled by user");
            }
            zbus::fdo::Error::ServiceUnknown(_) | zbus::fdo::Error::NameHasNoOwner(_) => {
                return write!(
                    f,
                    "installer service unavailable; verify systemd and D-Bus activation"
                );
            }
            zbus::fdo::Error::Timeout(_) => {
                return write!(
                    f,
                    "request timed out waiting for installer service or authentication"
                );
            }
            zbus::fdo::Error::InvalidArgs(detail) => {
                return write!(f, "invalid request: {detail}");
            }
            zbus::fdo::Error::Failed(detail) => {
                return write!(f, "installation failed: {detail}");
            }
            _ => {}
        }
    }
    if let zbus::Error::MethodError(name, detail, _) = error {
        match name.as_str() {
            "org.freedesktop.DBus.Error.AccessDenied" => {
                return write!(f, "authorization denied or cancelled by user");
            }
            "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner" => {
                return write!(
                    f,
                    "installer service unavailable; verify systemd and D-Bus activation"
                );
            }
            "org.freedesktop.DBus.Error.NoReply" | "org.freedesktop.DBus.Error.Timeout" => {
                return write!(
                    f,
                    "request timed out waiting for installer service or authentication"
                );
            }
            "org.freedesktop.DBus.Error.InvalidArgs" => {
                if let Some(detail) = detail {
                    return write!(f, "invalid request: {detail}");
                }
            }
            "org.freedesktop.DBus.Error.Failed" => {
                if let Some(detail) = detail {
                    return write!(f, "installation failed: {detail}");
                }
            }
            _ => {}
        }
    }
    write!(f, "D-Bus request failed: {error}")
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

    #[test]
    fn bus_error_formatting_translates_known_dbus_errors() {
        let access_denied = AppError::from(zbus::Error::from(zbus::fdo::Error::AccessDenied(
            String::new(),
        )));
        assert_eq!(
            access_denied.to_string(),
            "authorization denied or cancelled by user"
        );

        let service_unknown = AppError::from(zbus::Error::from(zbus::fdo::Error::ServiceUnknown(
            String::new(),
        )));
        assert_eq!(
            service_unknown.to_string(),
            "installer service unavailable; verify systemd and D-Bus activation"
        );

        let timeout = AppError::from(zbus::Error::from(zbus::fdo::Error::Timeout(String::new())));
        assert_eq!(
            timeout.to_string(),
            "request timed out waiting for installer service or authentication"
        );

        let invalid = AppError::from(zbus::Error::from(zbus::fdo::Error::InvalidArgs(
            String::from("bad ssid"),
        )));
        assert_eq!(invalid.to_string(), "invalid request: bad ssid");

        let failed = AppError::from(zbus::Error::from(zbus::fdo::Error::Failed(String::from(
            "disk full",
        ))));
        assert_eq!(failed.to_string(), "installation failed: disk full");
    }
}
