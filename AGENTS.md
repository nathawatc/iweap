# Maintainer contract

`iweap` is Linux-only Rust CLI plus root installer for IWD 802.1X profiles.

## Boundaries

- Keep CLI unprivileged. Root service starts only through systemd/D-Bus activation.
- Authorize with Polkit before mutation. Revalidate all client data in service.
- Write only fixed `/var/lib/iwd`; preserve descriptor-relative, no-follow,
  stale-state, atomic-replace, ownership, and mode checks.
- Never add shell, `sudo`, `doas`, `pkexec`, `run0`, or setuid execution.
- Never log or expose secrets. Restore terminal echo on every exit path.
- Treat systemd namespace as authority for service visibility and writable paths.

## Ownership

- `model.rs`: EAP taxonomy, capabilities, validation, wire conversion, IWD serialization.
- `filesystem.rs`: destination inspection and durable profile installation.
- `ipc.rs`: application D-Bus and Polkit identifiers plus client authorization call.
- `service.rs`: privileged request ordering, authorization, activity lifecycle.
- `main.rs` and `input.rs`: unprivileged interaction and terminal handling.
- `data/`: required cross-format systemd, D-Bus, and Polkit projections.

Keep `EapMethod` as EAP taxonomy SSOT. Reuse pure model validators at every trust
boundary. Preserve independent security assertions in tests. Any identifier or
filesystem-policy projection change requires packaging regression coverage.

## Completion

Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all-targets --all-features`, `cargo build --release`,
`cargo llvm-cov --all-targets --all-features` (at least 80% line coverage),
`cargo audit --deny warnings`, packaging XML/systemd checks, and `git diff --check`.
