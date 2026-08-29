# IWEAP

Interactive generator and installer for IWD 802.1X profiles.

## Build

Requires Linux, Rust 1.87+, IWD, systemd, D-Bus, Polkit, and a Polkit
authentication agent.

```sh
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

Service is D-Bus activated; do not enable it at boot.

## Use

```sh
iweap
iweap --dry-run
```

`--dry-run` prints a redacted profile without contacting D-Bus or writing files.

Supported outer methods: AKA, AKA', MSCHAPV2, PEAP, PWD, SIM, TLS, TTLS, and
WFA-TLS. PEAP and TTLS phase-2 methods are also supported.

## Credentials

Credentials are omitted by default so IWD can request them when connecting.
Stored credentials remain plaintext in root-owned mode `0600` profiles under
`/var/lib/iwd` and never appear in previews or logs.

TLS certificate and key paths are referenced, not copied, and must remain
accessible to IWD. Existing profiles require explicit overwrite confirmation.

## Troubleshooting

- No authentication prompt: verify Polkit and desktop authentication agent run.
- Service activation fails: verify install paths, then run `systemctl daemon-reload`.
- TLS path rejected: use an absolute path to a regular file readable by IWD.
