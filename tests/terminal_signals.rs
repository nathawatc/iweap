#![cfg(target_os = "linux")]

use libc::{ECHO, EINTR, EIO, POLLERR, POLLHUP, POLLIN, c_int, pollfd, termios};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);

struct Pty {
    master: Option<File>,
    slave_probe: File,
    output: Vec<u8>,
}

impl Pty {
    fn spawn() -> (Self, ChildGuard) {
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
        assert_eq!(result, 0, "openpty: {}", io::Error::last_os_error());

        let master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let slave_probe = slave.try_clone().expect("duplicate PTY slave");
        let stdin = slave.try_clone().expect("duplicate PTY stdin");
        let stdout = slave.try_clone().expect("duplicate PTY stdout");
        let stderr = slave.try_clone().expect("duplicate PTY stderr");

        let mut command = Command::new(env!("CARGO_BIN_EXE_iweap"));
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        unsafe {
            command.pre_exec(|| {
                for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
                    if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                        return Err(io::Error::last_os_error());
                    }
                }
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn iweap under PTY");
        drop(slave);

        (
            Self {
                master: Some(master),
                slave_probe,
                output: Vec::new(),
            },
            ChildGuard { child: Some(child) },
        )
    }

    fn send(&mut self, input: &[u8]) {
        self.master_mut().write_all(input).expect("write PTY input");
    }

    fn read_until(&mut self, marker: &[u8]) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if self
                .output
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return;
            }
            assert!(Instant::now() < deadline, "PTY marker not received");

            let mut descriptor = pollfd {
                fd: self.master_mut().as_raw_fd(),
                events: POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EINTR) {
                    continue;
                }
                panic!("poll PTY: {error}");
            }
            if polled == 0 {
                continue;
            }
            if descriptor.revents & (POLLIN | POLLERR | POLLHUP) == 0 {
                continue;
            }

            let mut chunk = [0_u8; 1024];
            match self.master_mut().read(&mut chunk) {
                Ok(0) => panic!("PTY closed before marker"),
                Ok(count) => self.output.extend_from_slice(&chunk[..count]),
                Err(error) if error.raw_os_error() == Some(EIO) => {
                    panic!("PTY closed before marker")
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => panic!("read PTY: {error}"),
            }
        }
    }

    fn wait_for_echo(&self, enabled: bool) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if self.echo_enabled() == enabled {
                return;
            }
            assert!(Instant::now() < deadline, "PTY echo state did not change");
            thread::yield_now();
        }
    }

    fn echo_enabled(&self) -> bool {
        let mut attributes = unsafe { std::mem::zeroed::<termios>() };
        let result = unsafe { libc::tcgetattr(self.slave_probe.as_raw_fd(), &mut attributes) };
        assert_eq!(result, 0, "tcgetattr: {}", io::Error::last_os_error());
        attributes.c_lflag & ECHO != 0
    }

    fn master_mut(&mut self) -> &mut File {
        self.master.as_mut().expect("PTY master is open")
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn id(&self) -> u32 {
        self.child.as_ref().expect("child is present").id()
    }

    fn wait_with_timeout(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("child is present")
                .try_wait()
                .expect("poll child status")
            {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not terminate");
            thread::yield_now();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child
            .try_wait()
            .expect("poll child during cleanup")
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn at_secret_prompt() -> (Pty, ChildGuard) {
    let (mut pty, child) = Pty::spawn();
    pty.read_until(b"SSID: ");
    pty.send(b"eduroam\n3\n2\nuser\n1\n");
    pty.read_until(b"Password (stored in profile): ");
    pty.wait_for_echo(false);
    (pty, child)
}

fn send_signal(child: &ChildGuard, signal: c_int) {
    let result = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    assert_eq!(result, 0, "kill({signal}): {}", io::Error::last_os_error());
}

fn assert_signal_during_secret(signal: c_int) {
    let (pty, mut child) = at_secret_prompt();
    send_signal(&child, signal);
    pty.wait_for_echo(true);
    let status = child.wait_with_timeout();
    assert_eq!(status.code(), Some(128 + signal));
}

#[test]
fn sigint_before_secret_prompt_terminates_with_signal_status() {
    let (mut pty, mut child) = Pty::spawn();
    pty.read_until(b"SSID: ");
    send_signal(&child, libc::SIGINT);
    assert!(pty.echo_enabled());
    let status = child.wait_with_timeout();
    assert!(
        status.code() == Some(128 + libc::SIGINT) || status.signal() == Some(libc::SIGINT),
        "unexpected status: {status:?}"
    );
}

#[test]
fn sigquit_before_secret_prompt_terminates_with_signal_status() {
    let (mut pty, mut child) = Pty::spawn();
    pty.read_until(b"SSID: ");
    send_signal(&child, libc::SIGQUIT);
    assert!(pty.echo_enabled());
    let status = child.wait_with_timeout();
    assert_eq!(
        status.code(),
        Some(128 + libc::SIGQUIT),
        "SIGQUIT before secret input must use the managed signal path"
    );
}

#[test]
fn sigint_during_secret_restores_echo() {
    assert_signal_during_secret(libc::SIGINT);
}

#[test]
fn sigterm_during_secret_restores_echo() {
    assert_signal_during_secret(libc::SIGTERM);
}

#[test]
fn sighup_during_secret_restores_echo() {
    assert_signal_during_secret(libc::SIGHUP);
}

#[test]
fn sigquit_during_secret_restores_echo() {
    assert_signal_during_secret(libc::SIGQUIT);
}

#[test]
fn sigint_after_secret_prompt_is_not_ignored() {
    let (mut pty, mut child) = at_secret_prompt();
    pty.send(b"secret\n");
    pty.read_until(b"Install this profile into /var/lib/iwd? [y/N]: ");
    pty.wait_for_echo(true);
    send_signal(&child, libc::SIGINT);
    assert_eq!(child.wait_with_timeout().code(), Some(128 + libc::SIGINT));
}

#[test]
fn sigterm_after_secret_prompt_is_not_ignored() {
    let (mut pty, mut child) = at_secret_prompt();
    pty.send(b"secret\n");
    pty.read_until(b"Install this profile into /var/lib/iwd? [y/N]: ");
    pty.wait_for_echo(true);
    send_signal(&child, libc::SIGTERM);
    assert_eq!(child.wait_with_timeout().code(), Some(128 + libc::SIGTERM));
}

#[test]
fn sigquit_after_secret_prompt_is_not_ignored() {
    let (mut pty, mut child) = at_secret_prompt();
    pty.send(b"secret\n");
    pty.read_until(b"Install this profile into /var/lib/iwd? [y/N]: ");
    pty.wait_for_echo(true);
    send_signal(&child, libc::SIGQUIT);
    assert_eq!(child.wait_with_timeout().code(), Some(128 + libc::SIGQUIT));
}

#[test]
fn sigquit_during_second_secret_prompt_restores_echo() {
    let (mut pty, mut child) = at_secret_prompt();
    pty.send(b"\n");
    pty.read_until(b"This secret is required.");
    pty.read_until(b"Password (stored in profile): ");
    pty.wait_for_echo(false);
    send_signal(&child, libc::SIGQUIT);
    pty.wait_for_echo(true);
    let status = child.wait_with_timeout();
    assert_eq!(status.code(), Some(128 + libc::SIGQUIT));
}

#[test]
fn eof_during_secret_restores_echo_without_panic() {
    let (mut pty, mut child) = at_secret_prompt();
    pty.send(&[4]);
    let status = child.wait_with_timeout();
    pty.wait_for_echo(true);
    assert_eq!(status.code(), Some(1));
}
