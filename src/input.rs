use iweap::Secret;
use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use zeroize::Zeroizing;

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
        if line.ends_with('\n') {
            line.pop();
        }
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
            let value = if required {
                self.required(prompt)?
            } else if let Some(value) = self.optional(prompt)? {
                value
            } else {
                return Ok(None);
            };
            let path = PathBuf::from(value);
            if path.is_absolute() && path.to_str().is_some() {
                match std::fs::metadata(&path) {
                    Ok(metadata) if metadata.is_file() => return Ok(Some(path)),
                    _ => {}
                }
            }
            eprintln!("Path must be absolute and point to an existing regular file.");
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

fn print_prompt(prompt: &str) -> Result<(), InputError> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(InputError::Io)
}

enum SecretEvent {
    Read(io::Result<Secret>),
    Signal(i32),
}

pub struct SignalManager {
    active_secret: std::sync::Arc<std::sync::Mutex<Option<mpsc::Sender<SecretEvent>>>>,
}

impl SignalManager {
    pub fn install() -> Result<Self, InputError> {
        let mut signals =
            Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM]).map_err(InputError::Signal)?;
        let active_secret =
            std::sync::Arc::new(std::sync::Mutex::new(None::<mpsc::Sender<SecretEvent>>));
        let listener_active = std::sync::Arc::clone(&active_secret);
        thread::spawn(move || {
            for signal in signals.forever() {
                let active = match listener_active.lock() {
                    Ok(active) => active,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(sender) = active.as_ref() {
                    let _ = sender.send(SecretEvent::Signal(signal));
                } else {
                    std::process::exit(128 + signal);
                }
            }
        });
        Ok(Self { active_secret })
    }

    fn begin_secret(
        &self,
        sender: mpsc::Sender<SecretEvent>,
    ) -> Result<SecretSignalScope, InputError> {
        let mut active = match self.active_secret.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        if active.is_some() {
            return Err(InputError::Terminal(String::from(
                "secret input is already active",
            )));
        }
        *active = Some(sender);
        Ok(SecretSignalScope {
            active_secret: std::sync::Arc::clone(&self.active_secret),
        })
    }
}

struct SecretSignalScope {
    active_secret: std::sync::Arc<std::sync::Mutex<Option<mpsc::Sender<SecretEvent>>>>,
}

impl Drop for SecretSignalScope {
    fn drop(&mut self) {
        let mut active = match self.active_secret.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        active.take();
    }
}

struct TerminalGuard {
    tty: File,
    original: rustix::termios::Termios,
    active: bool,
}

impl TerminalGuard {
    fn new(tty: File) -> Result<Self, InputError> {
        let original = tcgetattr(&tty).map_err(|error| InputError::Terminal(error.to_string()))?;
        let mut silent = original.clone();
        silent.local_modes.remove(LocalModes::ECHO);
        if let Err(error) = tcsetattr(&tty, OptionalActions::Now, &silent) {
            let _ = tcsetattr(&tty, OptionalActions::Now, &original);
            return Err(InputError::Terminal(error.to_string()));
        }
        Ok(Self {
            tty,
            original,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<(), InputError> {
        if self.active {
            tcsetattr(&self.tty, OptionalActions::Now, &self.original)
                .map_err(|error| InputError::Terminal(error.to_string()))?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn read_secret(signals: &SignalManager) -> Result<Secret, InputError> {
    let tty = OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|error| InputError::Terminal(error.to_string()))?;
    let (sender, receiver) = mpsc::channel();
    let signal_scope = signals.begin_secret(sender.clone())?;
    let mut guard = TerminalGuard::new(tty)?;
    let read_tty = guard
        .tty
        .try_clone()
        .map_err(|error| InputError::Terminal(error.to_string()))?;
    let reader_sender = sender.clone();
    let reader = thread::spawn(move || {
        let mut reader = io::BufReader::new(read_tty);
        let mut value = Zeroizing::new(String::new());
        let result = reader.read_line(&mut value).map(|count| {
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended unexpectedly",
                ));
            }
            if value.ends_with('\n') {
                value.pop();
            }
            Ok(Secret::new(std::mem::take(&mut *value)))
        });
        let _ = reader_sender.send(SecretEvent::Read(result.and_then(|value| value)));
    });

    let event = receiver
        .recv()
        .map_err(|_| InputError::Terminal(String::from("secret reader stopped unexpectedly")))?;

    match event {
        SecretEvent::Read(result) => {
            let _ = reader.join();
            guard.restore()?;
            drop(signal_scope);
            eprintln!();
            if let Some(SecretEvent::Signal(signal)) = receiver.try_iter().next() {
                return Err(InputError::Interrupted(signal));
            }
            result.map_err(InputError::Io)
        }
        SecretEvent::Signal(signal) => {
            guard.restore()?;
            drop(signal_scope);
            eprintln!();
            drop(reader);
            Err(InputError::Interrupted(signal))
        }
    }
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
}
