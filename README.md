# iweap

Interactive Rust generator and installer for IWD 802.1X profiles.

## Architecture

`iweap` runs as the invoking user. It builds and previews a typed EAP model,
then sends `InstallProfile` over the system D-Bus. `iweap-service` runs as
root, checks the caller with Polkit action
`org.codeberg.iweap.install-profile`, validates the request again, and writes
only `/var/lib/iwd`.

No `sudo`, `doas`, `pkexec`, `run0`, shell command, or setuid helper is used.
Read-only profile inspection does not require authorization. Installation does.

## Build

Requires Rust 1.87 or newer on Linux.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release
```

## Install

Build first, then install binaries and data as root:

```sh
install -Dm755 target/release/iweap /usr/bin/iweap
install -Dm755 target/release/iweap-service /usr/lib/iweap/iweap-service
install -Dm644 data/org.codeberg.iweap.policy \
  /usr/share/polkit-1/actions/org.codeberg.iweap.policy
install -Dm644 data/dbus/org.codeberg.iweap.conf \
  /usr/share/dbus-1/system.d/org.codeberg.iweap.conf
install -Dm644 data/dbus/org.codeberg.iweap.service \
  /usr/share/dbus-1/system-services/org.codeberg.iweap.service
install -Dm644 data/systemd/org.codeberg.iweap.service \
  /usr/lib/systemd/system/org.codeberg.iweap.service
systemctl daemon-reload
```

The system bus must have a Polkit authority and an authentication agent for
the active user session.

## Use

```sh
iweap
iweap --dry-run
```

`--dry-run` prints a redacted IWD profile and never contacts D-Bus or writes
files. Supported outer methods: AKA, AKA', MSCHAPV2, PEAP, PWD, SIM, TLS,
TTLS, and current-IWD expanded WFA-TLS. PEAP and TTLS phase-2 methods follow
current IWD profile keys. Profile names follow IWD's safe-SSID rule; unsafe
SSID bytes use lowercase hexadecimal.

Secrets are read from `/dev/tty` with terminal echo disabled. Echo is restored
on success, input failure, and handled interruption. Stored secrets never
appear in preview, command arguments, environment, or application logs.

## Storage and overwrite safety

Credentials are omitted by default so IWD can request them from its agent.
When selected, IWD-compatible profile secrets remain plaintext at rest in
`/var/lib/iwd`; the root-owned directory is mode `0700` and each profile is
root-owned mode `0600`.

Certificate and key paths are validated as absolute existing regular files and
are referenced, not copied. Installation uses descriptor-relative operations,
no-follow destination inspection, exclusive temporary files, fsync, and
atomic rename. The client sends an exact file identity/timestamp token; stale
or unexpected destinations are rejected. Overwrite confirmation is explicit.
