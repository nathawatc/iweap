mod signals;
mod terminal;

pub use signals::SignalManager;
pub use terminal::read_secret;

use iweap::Secret;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub enum InputError {
    EndOfInput,
    Io(io::Error),
    Terminal(String),
    Signal(io::Error),
    Interrupted(i32),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndOfInput => f.write_str("input ended unexpectedly"),
            Self::Io(error) => write!(f, "input failed: {error}"),
            Self::Terminal(error) => write!(f, "cannot read a secret silently: {error}"),
            Self::Signal(error) => write!(f, "cannot install signal handling: {error}"),
            Self::Interrupted(signal) => write!(f, "interrupted by signal {signal}"),
        }
    }
}

impl std::error::Error for InputError {}

pub struct Input<R> {
    reader: R,
    signals: Option<SignalManager>,
}

impl<R: BufRead> Input<R> {
    #[cfg(test)]
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            signals: None,
        }
    }

    pub fn with_signals(reader: R, signals: SignalManager) -> Self {
        Self {
            reader,
            signals: Some(signals),
        }
    }

    pub fn line(&mut self, prompt: &str) -> Result<String, InputError> {
        print_prompt(prompt)?;
        let mut line = String::new();
        let count = self.reader.read_line(&mut line).map_err(InputError::Io)?;
        if count == 0 {
            return Err(InputError::EndOfInput);
        }
        trim_line_ending(&mut line);
        Ok(line)
    }

    pub fn required(&mut self, prompt: &str) -> Result<String, InputError> {
        loop {
            let value = self.line(prompt)?;
            if !value.is_empty() {
                return Ok(value);
            }
            eprintln!("This value is required.");
        }
    }

    pub fn optional(&mut self, prompt: &str) -> Result<Option<String>, InputError> {
        let value = self.line(prompt)?;
        Ok((!value.is_empty()).then_some(value))
    }

    pub fn yes_no(&mut self, prompt: &str, default: bool) -> Result<bool, InputError> {
        loop {
            let mut value = self.line(prompt)?;
            if value.is_empty() {
                value = if default { "yes" } else { "no" }.to_owned();
            }
            match value.as_str() {
                "y" | "Y" | "yes" | "YES" | "Yes" => return Ok(true),
                "n" | "N" | "no" | "NO" | "No" => return Ok(false),
                _ => eprintln!("Answer yes or no."),
            }
        }
    }

    pub fn optional_bool(&mut self, prompt: &str) -> Result<Option<bool>, InputError> {
        loop {
            let value = self.line(prompt)?;
            match value.as_str() {
                "" => return Ok(None),
                "y" | "Y" | "yes" | "YES" | "Yes" => return Ok(Some(true)),
                "n" | "N" | "no" | "NO" | "No" => return Ok(Some(false)),
                _ => eprintln!("Enter yes, no, or leave blank."),
            }
        }
    }

    pub fn path(&mut self, prompt: &str, required: bool) -> Result<Option<PathBuf>, InputError> {
        loop {
            let raw_value = if required {
                self.required(prompt)?
            } else if let Some(value) = self.optional(prompt)? {
                value
            } else {
                return Ok(None);
            };
            let cleaned = sanitize_path_input(&raw_value);
            if cleaned.is_empty() {
                if required {
                    eprintln!("This value is required.");
                    continue;
                } else {
                    return Ok(None);
                }
            }
            let path = PathBuf::from(cleaned);
            if !path.is_absolute() {
                eprintln!("Path must be absolute (start with /).");
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        return Ok(Some(path));
                    } else if metadata.is_dir() {
                        eprintln!(
                            "Path is a directory, not a regular file: {}",
                            path.display()
                        );
                    } else {
                        eprintln!("Path is not a regular file: {}", path.display());
                    }
                }
                Err(error) => match error.kind() {
                    io::ErrorKind::NotFound => {
                        eprintln!("File not found: {}", path.display());
                    }
                    io::ErrorKind::PermissionDenied => {
                        eprintln!("Permission denied: {}", path.display());
                    }
                    _ => {
                        eprintln!("Cannot access {}: {error}", path.display());
                    }
                },
            }
        }
    }

    pub fn secret(&mut self, prompt: &str) -> Result<Secret, InputError> {
        print_prompt(prompt)?;
        let signals = self
            .signals
            .as_ref()
            .ok_or_else(|| InputError::Terminal(String::from("signal manager is not installed")))?;
        read_secret(signals)
    }

    pub fn secret_required(&mut self, prompt: &str) -> Result<Secret, InputError> {
        loop {
            let value = self.secret(prompt)?;
            if !value.is_empty() {
                return Ok(value);
            }
            eprintln!("This secret is required.");
        }
    }
}

pub(crate) fn print_prompt(prompt: &str) -> Result<(), InputError> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(InputError::Io)
}

pub(crate) fn trim_line_ending(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
}

pub(crate) fn sanitize_path_input(input: &str) -> &str {
    let mut trimmed = input.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        trimmed = trimmed[1..trimmed.len() - 1].trim();
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn line_prompts_and_required_optional_choices_are_deterministic() {
        let mut input = Input::new(Cursor::new(b"\nvalue\n\n"));
        assert!(matches!(
            input.required("required: "),
            Ok(value) if value == "value"
        ));
        assert_eq!(input.optional("optional: ").ok(), Some(None));
        assert_eq!(
            input.line("eof: ").err().map(|error| error.to_string()),
            Some(String::from("input ended unexpectedly"))
        );
    }

    #[test]
    fn yes_no_and_optional_bool_accept_shell_compatibility_forms() {
        let mut input = Input::new(Cursor::new(b"maybe\nyes\nNO\n"));
        assert_eq!(input.yes_no("yes/no: ", false).ok(), Some(true));
        assert_eq!(input.optional_bool("bool: ").ok(), Some(Some(false)));
    }

    #[test]
    fn line_reader_and_prompts_strip_crlf_and_cr_endings() {
        let mut input = Input::new(Cursor::new(
            b"first\r\n\r\nsecond\r\nthird\nrequired\r\nyes\r\nno\r\n",
        ));
        assert_eq!(input.line("first: ").unwrap(), "first");
        assert_eq!(input.line("empty: ").unwrap(), "");
        assert_eq!(input.line("second: ").unwrap(), "second");
        assert_eq!(input.line("third: ").unwrap(), "third");
        assert_eq!(input.required("required: ").unwrap(), "required");
        assert!(input.yes_no("yes: ", false).unwrap());
        assert_eq!(input.optional_bool("no: ").unwrap(), Some(false));

        let mut trailing_cr = Input::new(Cursor::new(b"trailing_cr\r"));
        assert_eq!(trailing_cr.line("prompt: ").unwrap(), "trailing_cr");
    }

    #[test]
    fn path_input_sanitizes_quotes_and_whitespace() {
        assert_eq!(sanitize_path_input("  /etc/hosts  "), "/etc/hosts");
        assert_eq!(sanitize_path_input("\"/etc/hosts\""), "/etc/hosts");
        assert_eq!(sanitize_path_input("'  /etc/hosts  '"), "/etc/hosts");
        assert_eq!(sanitize_path_input("\"\""), "");
        assert_eq!(sanitize_path_input(""), "");

        let mut input = Input::new(Cursor::new(b" \"/etc/hosts\" \n"));
        let path = input.path("path: ", true).unwrap();
        assert_eq!(path, Some(PathBuf::from("/etc/hosts")));
    }

    #[test]
    fn path_input_retries_on_relative_or_missing_paths() {
        let mut input = Input::new(Cursor::new(
            b"relative/path\n/missing/nonexistent/file.pem\n/etc/hosts\n",
        ));
        let path = input.path("path: ", true).unwrap();
        assert_eq!(path, Some(PathBuf::from("/etc/hosts")));
    }
}
