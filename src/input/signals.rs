use super::InputError;
use iweap::Secret;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::iterator::Signals;
use std::io;
use std::sync::mpsc;
use std::thread;

pub(crate) enum SecretEvent {
    Read(io::Result<Secret>),
    Signal(i32),
}

pub struct SignalManager {
    pub(crate) active_secret: std::sync::Arc<std::sync::Mutex<Option<mpsc::Sender<SecretEvent>>>>,
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

    pub(crate) fn dispatch_signal<F: FnOnce(i32)>(
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

    pub(crate) fn begin_secret(
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

pub(crate) struct SecretSignalScope {
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

pub(crate) fn pending_signal(receiver: &mpsc::Receiver<SecretEvent>) -> Option<i32> {
    receiver.try_iter().find_map(|event| match event {
        SecretEvent::Signal(signal) => Some(signal),
        SecretEvent::Read(_) => None,
    })
}

pub(crate) fn setup_error_or_pending_signal(
    receiver: &mpsc::Receiver<SecretEvent>,
    setup_error: InputError,
) -> InputError {
    if let Some(signal) = pending_signal(receiver) {
        InputError::Interrupted(signal)
    } else {
        setup_error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
