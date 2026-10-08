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
        thread::Builder::new()
            .spawn(move || {
                for signal in signals.forever() {
                    Self::dispatch_signal(&listener_active, signal, |code| {
                        std::process::exit(code)
                    });
                }
            })
            .map_err(InputError::Signal)?;
        Ok(Self { active_secret })
    }

    fn dispatch_signal<F: FnOnce(i32)>(
        active_secret: &std::sync::Arc<std::sync::Mutex<Option<mpsc::Sender<SecretEvent>>>>,
        signal: i32,
        exit_fn: F,
    ) {
        let active = match active_secret.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(sender) = active.as_ref() {
            if sender.send(SecretEvent::Signal(signal)).is_err() {
                exit_fn(128 + signal);
            }
        } else {
            exit_fn(128 + signal);
        }
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

fn pending_signal(receiver: &mpsc::Receiver<SecretEvent>) -> Option<i32> {
    receiver.try_iter().find_map(|event| match event {
        SecretEvent::Signal(signal) => Some(signal),
        SecretEvent::Read(_) => None,
    })
}

fn setup_error_or_pending_signal(
    receiver: &mpsc::Receiver<SecretEvent>,
    setup_error: InputError,
) -> InputError {
    if let Some(signal) = pending_signal(receiver) {
        InputError::Interrupted(signal)
    } else {
        setup_error
    }
}

fn trim_line_ending(line: &mut String) {
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
}

fn spawn_secret_reader(
    read_tty: File,
    sender: mpsc::Sender<SecretEvent>,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().spawn(move || {
        let mut reader = io::BufReader::new(read_tty);
        let mut value = Zeroizing::new(String::new());
        let result = reader.read_line(&mut value).map(|count| {
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended unexpectedly",
                ));
            }
            trim_line_ending(&mut value);
            Ok(Secret::new(std::mem::take(&mut *value)))
        });
        let _ = sender.send(SecretEvent::Read(result.and_then(|value| value)));
    })
}

fn read_secret(signals: &SignalManager) -> Result<Secret, InputError> {
    let tty = OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|error| InputError::Terminal(error.to_string()))?;
    read_secret_from_tty(signals, tty, spawn_secret_reader)
}

fn read_secret_from_tty<S>(
    signals: &SignalManager,
    tty: File,
    spawner: S,
) -> Result<Secret, InputError>
where
    S: FnOnce(File, mpsc::Sender<SecretEvent>) -> io::Result<thread::JoinHandle<()>>,
{
    let (sender, receiver) = mpsc::channel();
    let signal_scope = signals.begin_secret(sender.clone())?;
    let mut guard = match TerminalGuard::new(tty) {
        Ok(guard) => guard,
        Err(error) => {
            drop(signal_scope);
            return Err(setup_error_or_pending_signal(&receiver, error));
        }
    };
    let read_tty = match guard.tty.try_clone() {
        Ok(read_tty) => read_tty,
        Err(error) => {
            let _ = guard.restore();
            drop(guard);
            drop(signal_scope);
            return Err(setup_error_or_pending_signal(
                &receiver,
                InputError::Terminal(error.to_string()),
            ));
        }
    };
    let reader = match spawner(read_tty, sender.clone()) {
        Ok(reader) => reader,
        Err(error) => {
            let _ = guard.restore();
            drop(guard);
            drop(signal_scope);
            return Err(setup_error_or_pending_signal(
                &receiver,
                InputError::Io(error),
            ));
        }
    };

    let event = receiver
        .recv()
        .map_err(|_| InputError::Terminal(String::from("secret reader stopped unexpectedly")))?;

    match event {
        SecretEvent::Read(result) => {
            let _ = reader.join();
            let restore_result = guard.restore();
            drop(signal_scope);
            eprintln!();
            if let Some(signal) = pending_signal(&receiver) {
                return Err(InputError::Interrupted(signal));
            }
            restore_result?;
            result.map_err(InputError::Io)
        }
        SecretEvent::Signal(signal) => {
            let _ = guard.restore();
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
    use std::os::fd::FromRawFd;

    fn create_test_pty() -> (File, File) {
        let mut master_fd = -1;
        let mut slave_fd = -1;
        let result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(result, 0);
        let master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        (master, slave)
    }

    fn is_echo_enabled(file: &File) -> bool {
        let attrs = tcgetattr(file).unwrap();
        attrs.local_modes.contains(LocalModes::ECHO)
    }

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
    fn setup_error_with_no_pending_signal_preserves_setup_error() {
        let (_sender, receiver) = mpsc::channel::<SecretEvent>();
        let original_error = InputError::Terminal(String::from("setup failed"));
        let resolved = setup_error_or_pending_signal(&receiver, original_error);
        assert!(matches!(
            resolved,
            InputError::Terminal(ref msg) if msg == "setup failed"
        ));
    }

    #[test]
    fn pending_managed_signals_override_setup_error() {
        for signal in [SIGHUP, SIGINT, SIGQUIT, SIGTERM] {
            let (sender, receiver) = mpsc::channel::<SecretEvent>();
            sender.send(SecretEvent::Signal(signal)).unwrap();
            let original_error = InputError::Terminal(String::from("setup failed"));
            let resolved = setup_error_or_pending_signal(&receiver, original_error);
            assert!(matches!(resolved, InputError::Interrupted(s) if s == signal));
        }
    }

    #[test]
    fn non_signal_secret_events_do_not_override_setup_error() {
        let (sender, receiver) = mpsc::channel::<SecretEvent>();
        sender
            .send(SecretEvent::Read(Ok(Secret::new(String::from("ignored")))))
            .unwrap();
        let original_error = InputError::Terminal(String::from("setup failed"));
        let resolved = setup_error_or_pending_signal(&receiver, original_error);
        assert!(matches!(
            resolved,
            InputError::Terminal(ref msg) if msg == "setup failed"
        ));
    }

    #[test]
    fn signal_manager_dispatch_delivers_to_connected_receiver_without_exit() {
        let active_secret = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (sender, receiver) = mpsc::channel();
        *active_secret.lock().unwrap() = Some(sender);

        let mut exited = None;
        SignalManager::dispatch_signal(&active_secret, SIGQUIT, |code| {
            exited = Some(code);
        });

        assert_eq!(exited, None);
        assert!(matches!(
            receiver.try_recv(),
            Ok(SecretEvent::Signal(SIGQUIT))
        ));
    }

    #[test]
    fn signal_manager_dispatch_exits_on_disconnected_stale_sender() {
        let active_secret = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (sender, receiver) = mpsc::channel();
        *active_secret.lock().unwrap() = Some(sender);
        drop(receiver);

        let mut exited = None;
        SignalManager::dispatch_signal(&active_secret, SIGINT, |code| {
            exited = Some(code);
        });

        assert_eq!(exited, Some(128 + SIGINT));
    }

    #[test]
    fn signal_manager_dispatch_exits_when_no_active_secret() {
        let active_secret = std::sync::Arc::new(std::sync::Mutex::new(None));

        let mut exited = None;
        SignalManager::dispatch_signal(&active_secret, SIGTERM, |code| {
            exited = Some(code);
        });

        assert_eq!(exited, Some(128 + SIGTERM));
    }

    #[test]
    fn reader_spawn_failure_without_signal_preserves_io_error_and_restores_echo() {
        let signals = SignalManager {
            active_secret: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        let (_master, slave) = create_test_pty();
        let slave_probe = slave.try_clone().unwrap();
        assert!(is_echo_enabled(&slave_probe));

        let spawn_error = io::Error::new(io::ErrorKind::OutOfMemory, "thread limit reached");
        let result = read_secret_from_tty(&signals, slave, |_read_tty, _sender| Err(spawn_error));

        assert!(
            matches!(result, Err(InputError::Io(ref err)) if err.kind() == io::ErrorKind::OutOfMemory)
        );
        assert!(is_echo_enabled(&slave_probe));
        assert!(signals.active_secret.lock().unwrap().is_none());
    }

    #[test]
    fn reader_spawn_failure_with_pending_sigquit_returns_interrupted_and_restores_echo() {
        let signals = SignalManager {
            active_secret: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        let (_master, slave) = create_test_pty();
        let slave_probe = slave.try_clone().unwrap();
        assert!(is_echo_enabled(&slave_probe));

        let result = read_secret_from_tty(&signals, slave, |_read_tty, sender| {
            sender.send(SecretEvent::Signal(SIGQUIT)).unwrap();
            Err(io::Error::other("spawn failed"))
        });

        assert!(matches!(result, Err(InputError::Interrupted(s)) if s == SIGQUIT));
        assert!(is_echo_enabled(&slave_probe));
        assert!(signals.active_secret.lock().unwrap().is_none());
    }

    #[test]
    fn reader_spawn_failure_with_pending_sigterm_returns_interrupted_and_restores_echo() {
        let signals = SignalManager {
            active_secret: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        let (_master, slave) = create_test_pty();
        let slave_probe = slave.try_clone().unwrap();
        assert!(is_echo_enabled(&slave_probe));

        let result = read_secret_from_tty(&signals, slave, |_read_tty, sender| {
            sender.send(SecretEvent::Signal(SIGTERM)).unwrap();
            Err(io::Error::other("spawn failed"))
        });

        assert!(matches!(result, Err(InputError::Interrupted(s)) if s == SIGTERM));
        assert!(is_echo_enabled(&slave_probe));
        assert!(signals.active_secret.lock().unwrap().is_none());
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
    fn secret_reader_strips_crlf_and_cr_endings() {
        let signals = SignalManager {
            active_secret: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        let (mut master, slave) = create_test_pty();
        master.write_all(b"secret_value\r\n").unwrap();

        let secret = read_secret_from_tty(&signals, slave, spawn_secret_reader).unwrap();
        assert_eq!(secret.as_str(), "secret_value");
    }
}
