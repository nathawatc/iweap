# IWEAP

Interactive generator and installer for IWD 802.1X profiles.

## Requirements

Building requires Linux and Rust 1.87+.

Full profile installation requires IWD, systemd, D-Bus, Polkit, and a Polkit
authentication agent.

## Install

<details>
<summary><h3>Arch Linux</h3></summary>

### Install from AUR

Using an AUR helper, for example:

```sh
paru -S iweap
```

</details>

### Build from Source

```sh
cargo build --locked --release
```

Then install the binaries and system integration files as root:

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

The service is D-Bus activated and should not be enabled at boot.

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

- No authentication prompt: verify that Polkit and a desktop authentication agent are running.
- Service activation fails: verify the installation paths, then run `systemctl daemon-reload`.
- TLS path rejected: use an absolute path to a regular file readable by IWD.
