# AGENTS.md

**Effective Flow project setup:** docs/adr/effective-flow-project-setup.md

Use `pnpm agent:check` to check code changes. Do not run checks on 'git commit'.

Before changing `ssh` or `readFile` semantics, run `pnpm --filter paratix test:integration` locally against a reachable Docker daemon. The GitHub-hosted `Integration Check` also provides Docker and runs an explicit `docker info` preflight; if Docker is unavailable, the job must fail instead of silently skipping the integration suite. The suite skips dynamically only in local environments without a reachable Docker daemon.

When writing Paratix code (playbooks or custom modules), read the [agent authoring guidance](packages/paratix/llm-guide.md#agent-authoring-guidance) in the complete API reference.

Do not use cspell:ignore in the code. Write cspell findings into cspell.json

## Rust toolchain for packages/ssh-native

Building the repository requires a Rust toolchain: `pnpm build` always builds the native binding in `packages/ssh-native` (`@paratix/ssh-native`, incremental). The toolchain is pinned in `packages/ssh-native/rust-toolchain.toml`; install [rustup](https://rustup.rs) and run `rustup toolchain install` inside `packages/ssh-native` to get it.

`pnpm rust:check` runs `cargo fmt --check`, `cargo clippy` with `-D warnings`, `cargo test` and `cargo deny check licenses bans sources` in `packages/ssh-native`. It needs cargo-deny 0.20.2 (`cargo install --locked cargo-deny@0.20.2`). `pnpm agent:check` calls it, controlled by `PARATIX_RUST_CHECK`:

- `auto` (default): runs when `CI=true` or `origin/main` is not resolvable; otherwise only when `src/**`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` or `deny.toml` under `packages/ssh-native` changed since `git merge-base HEAD origin/main`, including uncommitted and untracked files. A skip is logged with its reason.
- `always`: always runs. The CI job `check` uses this.
- `skip`: never runs. `Integration Check` and the publish `validate` job use this and only build.

An explicit value takes precedence over `CI=true`; any other value aborts `agent:check`.

Before pushing changes to `packages/ssh-native`, run `pnpm --filter @paratix/ssh-native test:integration` locally against a reachable Docker daemon (the root `pnpm test:integration` includes it). It builds an OpenSSH image with every sshd profile, generates keys, CA and certificates per run and removes container and image afterwards. Without Docker it skips the sshd tests locally and still runs the in-process `ssh2` proofs; with `CI=true` it fails instead, and every hard proof (H1–H6 of ADR 0008) must pass. `pnpm --filter @paratix/ssh-native test:integration:local` runs the same suite against a non-root local `sshd` (Linux and macOS, no PAM, so password and keyboard-interactive tests skip), and `pnpm --filter @paratix/ssh-native test:smoke` checks the binary the loader picks.
