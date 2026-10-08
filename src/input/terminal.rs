use super::InputError;
use super::signals::{SecretEvent, SignalManager, pending_signal, setup_error_or_pending_signal};
use super::trim_line_ending;
use iweap::Secret;
use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead};
use std::sync::mpsc;
use std::thread;
use zeroize::Zeroizing;

pub(crate) struct TerminalGuard {
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

pub(crate) fn spawn_secret_reader(
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

pub fn read_secret(signals: &SignalManager) -> Result<Secret, InputError> {
    let tty = OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|error| InputError::Terminal(error.to_string()))?;
    read_secret_from_tty(signals, tty, spawn_secret_reader)
}

pub(crate) fn read_secret_from_tty<S>(
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
    use signal_hook::consts::signal::{SIGQUIT, SIGTERM};
    use std::io::Write;
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
