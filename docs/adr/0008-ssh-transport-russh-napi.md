# 0008 - Replace ssh2 with an Own napi-rs Binding over russh

## Status

Accepted, amended 2026-10-29 (see "Amendment (2026-10-29, #255)"). All 15 hard proofs of the spike passed in both proof runs, the prebuild matrix built all
six targets within the glibc and macOS limits, and the smoke test passed on every target. One soft
cell (ed25519 PKCS#8 through the agent) could not be tested because OpenSSH's `ssh-add` refuses
that format; it is documented as an OpenSSH limitation below. The spike also found gaps that work
package B must close; they are listed under "Known Limitations and Findings for B".

## Context

Issue: sebastian-software/paratix#254 (work package A)
Epic: sebastian-software/paratix#252
Related: sebastian-software/paratix#248 (user certificates, work package D)
Blocks: sebastian-software/paratix#255 (work package B)
Planning basis: `docs/plan/2026-10-29-ssh-transport-auf-russh-umstellen.md` (German,
authoritative), merged in sebastian-software/paratix#253

Paratix should log in with short-lived OpenSSH certificates and verify hosts through a host CA
(Epic #252). Neither is possible with `ssh2`, the SSH library behind every connection today:

- `ssh2` 1.17.0 does not know `*-cert-v01@openssh.com` keys.
- It silently skips certificate identities offered by `ssh-agent`.
- It does not negotiate host-certificate algorithms.
- The upstream pull request mscdex/ssh2#1495 is not merged and waits for the maintainer; a similar
  pull request has been open there for more than a year.

`ssh2` is used in four runtime files (`ssh.ts`, `sshHelpers.ts`, `sftp.ts` and
`create-paratix`'s `hostFingerprintBootstrap.ts`). Paratix uses key-file, agent and
password/keyboard-interactive login, opt-in agent forwarding, a host verifier backed by
`knownHosts.ts`, exec without a PTY, SFTP streams with file mode, `destroy()` in the last-resort
cleanup, and a host-key scan without login. It does not use keepalive, custom algorithm lists,
port forwarding, `shell` or exec environment variables.

The Rust crate `russh` (warp-tech/russh, 0.65.0) supports user certificates from file and agent,
host-certificate negotiation, exec, keyboard-interactive and, through `russh-sftp`, SFTP. Several
points were unverified at planning time (agent forwarding, `russh-sftp` mode and backpressure,
certificate identities from the agent, interop with `ssh2`'s `Server`, key formats, cross-builds).
A throwaway spike had to settle them before work package B starts.

## Decision

Replace `ssh2` with an own, thin napi-rs binding over `russh` 0.65 and `russh-sftp` 3.

- **Package:** `packages/ssh-native`, published as `@paratix/ssh-native`, versioned together with
  `paratix` and `create-paratix`. Prebuilt binaries ship as `@paratix/ssh-native-<triple>` through
  `optionalDependencies`, loaded by a hand-written `index.js`.
- **Hard switch:** there is no `ssh.transport` opt-in and no parallel operation for users. Until
  the switch, Paratix keeps logging in with keys.
- **Narrow, Paratix-specific API.** The binding offers only:
  - `scan`: handshake without login, with an overall timeout and protection against half-open TCP
  - `connect`: timeout, cancellation, login by agent, key file or password with
    keyboard-interactive, optional agent forwarding, and an **async** host-key callback
  - `exec` with streaming stdout/stderr, stdin, exit code and signal
  - SFTP read and write streams with a file mode
  - a disconnect event
  - `close()` and a synchronous `destroy()`
- **Keepalive is off** and not part of the API; there is no inactivity timeout either, so a long
  silent command is never cut off.
- **Server-opened channels are rejected** (`forwarded-tcpip`, `x11`, `auth-agent@openssh.com`,
  `session`, `direct-tcpip`, the streamlocal variants and unknown types). The only exception is
  `auth-agent@openssh.com` when `agentForward: true`; only then is the agent socket bridged.
- **No configuration logic in Rust.** Paths, `~`, `SSH_AUTH_SOCK` and validation stay in
  TypeScript. There is no Rust logger, `RUST_LOG` has no effect, and a silent panic hook keeps
  stderr clean.
- Certificate options arrive only with D and E.

Follow-up work packages, each with its own issue:

- **B (#255):** the production package `@paratix/ssh-native`, Rust workspace, `deny.toml`,
  toolchain pin, CI, advisory job, release matrix and publish pipeline.
- **C1:** an internal transport interface (`transport.ts`) under `SshConnectionImpl` with a
  temporary `ssh2` adapter, released on its own without behaviour change.
- **C2:** the native adapter (`transportNative.ts`), removal of `ssh2` from the runtime
  dependencies, `create-paratix` switched to `scan()`.
- **D (#248):** user certificates (agent certificate identities, `ssh.certificate`, `rsync` with
  `CertificateFile`).
- **E:** host certificates on the controller (`@cert-authority`, `@revoked` for CA keys,
  principals check, `rsync` with an `@cert-authority` anchor).

## Alternatives Rejected

- **`ssh2` fork:** would add certificate support only by maintaining a fork of a large protocol
  library whose upstream does not merge the change. The user decided against a fork and against
  any interim solution.
- **System OpenSSH as a subprocess:** gives up the process control Paratix has with `ssh2`:
  reconnect, cancellation, secret masking, typed errors, and the TypeScript trust decision in
  `knownHosts.ts`. It stays the fallback plan if a hard proof had failed without a workaround.
- **The existing npm package `russh` (0.1.38):** exposes no certificate API and is tailored to
  Tabby.
- **Own napi-rs binding (chosen):** certificates in both directions, full process control as with
  `ssh2`, and an actively maintained base (new russh releases about every two to three weeks). The
  price is a Rust toolchain for everyone who builds the repository, a prebuild matrix, a release
  pipeline and a platform boundary.

## Decision Criteria

The spike had hard and soft criteria (plan decision 11).

- **Hard:** certificate login through the agent, async host-key callback with error propagation,
  exec semantics, SFTP with mode and backpressure, `destroy`/`exit` behaviour, the prebuild
  matrix, and `agentForward`.
- **Soft:** individual key formats.

A failed hard proof without a workaround would have meant status "rejected" plus a new plan for an
OpenSSH-subprocess transport. A missing soft format is a documented limitation in this ADR and in
the changelog of C2.

## Spike Results

### Setup

- **Authoritative CI run:** https://github.com/sebastian-software/paratix/actions/runs/40903619584
  on head `ffa3be6652263f14c11b3ab8b5c25dcc6ec2aa48`, every job green. All figures below come
  from this run.
- **First green run (reference only):**
  https://github.com/sebastian-software/paratix/actions/runs/40895741197 on head
  `83b5036af52c9a313917d603a31b336b4fd8d2ba`. After an independent review the proofs were
  strengthened without Rust changes; the six binaries of both runs are byte-identical (same
  SHA-256).
- **Spike commits** on branch `firmo/build/russh-spike-adr-0008` (PR #259). The spike code was
  removed from the tree before merge and stays retrievable from these commits:
  - `8a30ee9c3b951016cc8f6ce6165e72bc146bdb27`: spike code (`packages/ssh-native`, Rust sources,
    loader, proof suite, Docker fixture)
  - `a779804b72cdc5e3afc357b3dc6d4456df21064c`: spike workflow (`ssh-native-spike.yml`)
  - `8ea7614e01c30cba7b8f6a55a1f42151ccd21464` and `83b5036af52c9a313917d603a31b336b4fd8d2ba`: CI
    fixes
  - `9d893b7b651b8c4502d2236fa2184522f10ce43a`: proofs strengthened after review
  - `ffa3be6652263f14c11b3ab8b5c25dcc6ec2aa48`: CI fix (SIGPIPE in the smoke steps)
- **Spike crate:** `russh` 0.65.0 (`rsa` feature, `aws-lc-rs` backend), `russh-sftp` 3.0.1,
  `napi` 3.15, `zeroize` 1, `panic = "unwind"`.
- **Targets of the proof suite:**
  - **Docker sshd (authoritative run):** `debian:bookworm-slim` with Debian bookworm OpenSSH,
    ed25519/ECDSA/RSA host keys, an ed25519 host certificate, a test user CA in
    `TrustedUserCAKeys`, PAM for password login, and extra profiles by port (`MaxSessions 1`,
    password only, keyboard-interactive only). Result: **43 pass, 1 skip, 0 fail**, including all
    15 hard proofs.
  - **Local non-root OpenSSH sshd on the runner:** **40 pass, 4 skip, 0 fail**, including all 15
    hard proofs. Password, keyboard-interactive and wrong-password need PAM and run in Docker
    only; the fourth skip is the same ed25519 PKCS#8 agent cell as in Docker.
  - **In-process `ssh2` `Server`:** for proofs that need a server opening channels or holding SFTP
    replies, and for interop.
- **Gate:** the proofs job requires every one of the 15 hard proof ids with status `pass` in both
  result files. A hard skip counts as a failure, and a missing or unexpected hard id is an error.
- **Scope:** the full proof suite (H1–H6 and the other and soft proofs) ran only on
  linux-x64-gnu, on `ubuntu-24.04` with Node v24.22.1, against the Docker and the local sshd. The
  other five targets are covered by the smoke test, which since this run includes key login, exec,
  the panic mapping and the `destroy()` lifecycle (see "Smoke Tests").

Figures below come from the Docker run unless stated otherwise.

### Hard Proofs

All 15 hard proofs of the suite passed in both runs; the prebuild matrix (the seventh hard
criterion) is reported separately below.

| Proof                                       | Server        | Evidence                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| H1 agent login with user certificate        | Docker sshd   | The certified key is not in `authorized_keys`; only the CA vouches for it. Agent offers `ssh-ed25519` and `ssh-ed25519-cert-v01@openssh.com`; login succeeds as `paratix` with identity kind `certificate`, algorithm `ssh-ed25519-cert-v01@openssh.com`, 2 attempts. Negative control: an agent that holds only the bare key (`ssh-ed25519`, added successfully) gives `AUTH_FAILED` with no detail.   |
| H2 async verifier                           | Docker sshd   | The callback sleeps 750 ms; `connect()` waits for it (verify start at 17 ms, end at 768 ms, accepted; total 785 ms) and exec works afterwards.                                                                                                                                                                                                                                                          |
| H2 verifier error identity and verdict rule | Docker sshd   | An async rejection (`KnownHostsMismatch`), a synchronous throw and a non-`Error` throw value each reach the caller as the identical object. The identity is preserved by the JS wrapper; only a boolean crosses napi. Verdict rule: only `true` or `undefined` accept; `false`, `1`, `"yes"`, `{}` and `null` give `HOST_KEY_REJECTED` (fail closed).                                                   |
| H3 exec streams and exit                    | Docker sshd   | `cat; echo err >&2; exit 3` with stdin `hello from stdin`: stdout echoed, stderr `err\n`, exit code 3. A command killed by TERM reports `code: null, signal: "TERM"`. Streaming: first chunk after 3 ms, done after 1004 ms. 8 MiB through stdin: SHA-256 matches.                                                                                                                                      |
| H4 SFTP mode 0600                           | Docker sshd   | 32 MiB (33554432 bytes) written with `mode: 0o600` into a pre-existing `0644` file: mode `600`, size and SHA-256 match, 141 ms (227 MiB/s). A fresh 5-byte file also gets mode `600`.                                                                                                                                                                                                                   |
| H4 SFTP backpressure (bounded in flight)    | `ssh2` Server | The server holds WRITE replies. After 1.5 s the binding has accepted 655360 bytes (bound 1 MiB, 1048576 bytes) of the 720896 produced by JS, the server received 360421, with 16 outstanding writes (max 16). After release all 32 MiB arrive; the server saw mode `600` twice. This is the backpressure evidence; `write()` returning `false` alone proves nothing, since any async Writable shows it. |
| H5 `destroy()` before `process.exit()`      | Docker sshd   | Five runs of `destroy()` + `process.exit(0)` during a running `sleep`: exit code 0, no signal, empty stderr, exit 5–6 ms after the marker. Informational: the 5 remote `sleep` processes were still running afterwards (see limitations).                                                                                                                                                               |
| H5 `destroy()` before exit while streaming  | Docker sshd   | 50 runs of `destroy()` + `process.exit(0)` while `yes` streams with a stdout listener attached, up to 1081296 bytes (about 1 MiB) received before `destroy()`: every run exit code 0, signal `null`, empty stderr; exit latency median 5 ms, max 7 ms.                                                                                                                                                  |
| H5 `destroy()` releases the event loop      | Docker sshd   | Without `process.exit()` the process ends on its own, exit code 0 after 4 ms.                                                                                                                                                                                                                                                                                                                           |
| H5 `close()` then natural exit              | Docker sshd   | The process ends after `close()`: native 4 ms, `ssh2` parity run 16 ms.                                                                                                                                                                                                                                                                                                                                 |
| H5 idle connection keeps process alive      | Docker sshd   | With an open, idle connection the process is still alive after 5 s, for both the binding and `ssh2`, with empty stderr.                                                                                                                                                                                                                                                                                 |
| H6 agent forward, remote `ssh-add`          | Docker sshd   | With `agentForward: true`, the remote `ssh-add -l` lists the forwarded ed25519 key with the expected fingerprint; one agent channel bridged.                                                                                                                                                                                                                                                            |
| H6 no agent forward by default              | Docker sshd   | An agent login with `agentForward: false` (and a key-file login) leaves the remote `SSH_AUTH_SOCK` empty; `ssh-add` exits with 2; no channel bridged.                                                                                                                                                                                                                                                   |
| H6 server-opened channels rejected          | `ssh2` Server | Server-opened `auth-agent@openssh.com`, `forwarded-tcpip` and `x11` channels are each refused with "Administratively prohibited" (reason 1); the connection stays usable.                                                                                                                                                                                                                               |
| H6 server-opened agent channel bridged      | `ssh2` Server | With `agentForward: true` the agent channel is accepted; `SSH_AGENTC_REQUEST_IDENTITIES` returns answer type 12 with one identity.                                                                                                                                                                                                                                                                      |

The local run matched the Docker run on every hard proof, for example H2 778 ms, H4 145 ms
(220.7 MiB/s) with identical in-flight counts, and the streaming `destroy()` proof with a max exit
latency of 6 ms over 50 runs.

### Other Proofs

| Proof                         | Server        | Evidence                                                                                                                                                                                                                                                                                                     |
| ----------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Agent key without certificate | Docker sshd   | Login by agent, 1 attempt, `ssh-ed25519`.                                                                                                                                                                                                                                                                    |
| Key-file login                | Docker sshd   | `publickey`, 1 attempt, `ssh-ed25519`; the caller's JS key buffer is zero-filled afterwards.                                                                                                                                                                                                                 |
| Password login                | Docker sshd   | `password`, 1 attempt (Docker only).                                                                                                                                                                                                                                                                         |
| Keyboard-interactive login    | Docker sshd   | `keyboard-interactive`, 2 attempts (Docker only).                                                                                                                                                                                                                                                            |
| Wrong password                | Docker sshd   | `AUTH_FAILED` (Docker only).                                                                                                                                                                                                                                                                                 |
| Authentication error codes    | Docker sshd   | Unauthorized key: `AUTH_FAILED`. Encrypted key: `ENCRYPTED_KEY`. Garbage key: `UNSUPPORTED_KEY`. Closed port: `CONNECT_FAILED` with `ECONNREFUSED`.                                                                                                                                                          |
| Channel open refused          | Docker sshd   | Profile `MaxSessions 1`: a second exec while the first runs fails with `CHANNEL_OPEN_FAILED` (detail `connect-failed`); the connection stays usable and the next exec succeeds on the first attempt.                                                                                                         |
| `scan()` without login        | Docker sshd   | Returns kind `key`, `ssh-ed25519`, the key blob and its SHA-256 fingerprint.                                                                                                                                                                                                                                 |
| Half-open TCP timeout         | silent peer   | A TCP peer that never speaks: `scan()` fails with `TIMEOUT` after 1503 ms, `connect()` after 1501 ms (timeout 1500 ms).                                                                                                                                                                                      |
| Host certificate              | Docker sshd   | With certificate algorithms offered: kind `certificate`, `ssh-ed25519-cert-v01@openssh.com`, type `host`, principals `localhost`, `127.0.0.1`, `sshd`, key ID `spike-host`, CA signature valid. Without: the raw `ssh-ed25519` key with the same blob. `scan()` with certificates also sees the certificate. |
| `ssh2` Server interop         | `ssh2` Server | `scan()` sees `ssh-rsa`; RSA key login negotiates `rsa-sha2-256`; exec returns output and exit code 0. This shows protocol compatibility only; signature correctness is covered by the OpenSSH runs and by the smoke login, where the `ssh2` Server verifies the signature.                                  |
| Disconnect event              | `ssh2` Server | A server-side close fires the event with reason `remote`; a follow-up call fails with `DISCONNECTED`.                                                                                                                                                                                                        |
| Panic maps to `INTERNAL`      | none          | A panic inside a guarded task resolves the promise with `INTERNAL` ("internal error in the native SSH binding") and prints nothing to stderr.                                                                                                                                                                |

### Soft Proofs: Key-Format Matrix

Each format was tested from a file and through `ssh-agent` against the Docker sshd. RSA keys
negotiate `rsa-sha2-512` through `server-sig-algs`. The agent column tests whether `ssh-add` can
parse the format, not the russh key parser: through the agent, russh only sees the public key and
the agent's signatures.

| Format                | File header                 | Algorithm             | File | Agent                                         |
| --------------------- | --------------------------- | --------------------- | ---- | --------------------------------------------- |
| ed25519, OpenSSH      | `BEGIN OPENSSH PRIVATE KEY` | `ssh-ed25519`         | pass | pass                                          |
| RSA, OpenSSH          | `BEGIN OPENSSH PRIVATE KEY` | `rsa-sha2-512`        | pass | pass                                          |
| RSA, PEM PKCS#1       | `BEGIN RSA PRIVATE KEY`     | `rsa-sha2-512`        | pass | pass                                          |
| RSA, PKCS#8           | `BEGIN PRIVATE KEY`         | `rsa-sha2-512`        | pass | pass                                          |
| ECDSA P-256, OpenSSH  | `BEGIN OPENSSH PRIVATE KEY` | `ecdsa-sha2-nistp256` | pass | pass                                          |
| ECDSA P-256, PEM SEC1 | `BEGIN EC PRIVATE KEY`      | `ecdsa-sha2-nistp256` | pass | pass                                          |
| ECDSA P-256, PKCS#8   | `BEGIN PRIVATE KEY`         | `ecdsa-sha2-nistp256` | pass | pass                                          |
| ed25519, PKCS#8       | `BEGIN PRIVATE KEY`         | `ssh-ed25519`         | pass | skip: `ssh-add` refuses it ("invalid format") |

The skipped cell is an OpenSSH limitation, not a binding limitation: the binding loads the same
file directly. ECDSA P-384/P-521 keys and encrypted keys beyond detection (`ENCRYPTED_KEY`) were
not tested; passphrases are not supported, as with `ssh2` in Paratix today.

### Prebuild Matrix

All six targets were built with Rust 1.99.1 and the `aws-lc-rs` backend, with `--locked`.

- **Linux:** on `ubuntu-24.04` with cargo-zigbuild 0.24.0 and zig 0.17.0. The gnu targets use the
  versioned triples `x86_64-unknown-linux-gnu.2.35` and `aarch64-unknown-linux-gnu.2.35`. The musl
  targets use `-C target-feature=-crt-static`, because a `cdylib` must link musl dynamically.
- **macOS:** native `cargo` on `macos-15` (arm64) and `macos-15-intel` (x64) with
  `MACOSX_DEPLOYMENT_TARGET=11.0`; the gate read `minos` from the Mach-O load commands.
- **gnu gate:** the highest `GLIBC_` symbol version must not exceed 2.35. The CI gate used
  `readelf -V`, which is stricter than the plan's `objdump -T`; `objdump -T` on both downloaded gnu artifacts confirms GLIBC_2.34.
- **musl gate:** the NEEDED check only warns. The real check is the smoke test in
  `node:24-alpine`.

| Target           | Triple                       | Size (bytes) | SHA-256                                                            | Gate                       |
| ---------------- | ---------------------------- | -----------: | ------------------------------------------------------------------ | -------------------------- |
| linux-x64-gnu    | `x86_64-unknown-linux-gnu`   |      6079464 | `723806633c86b7408d77e7c4060ea6175fb610c9932a2112182df151f671062f` | GLIBC_2.34 (limit 2.35)    |
| linux-arm64-gnu  | `aarch64-unknown-linux-gnu`  |      4806576 | `96ec4e567e772ca46361d75386cd8e33f3c986800cf36a91d2f3344b22e6d637` | GLIBC_2.34 (limit 2.35)    |
| linux-x64-musl   | `x86_64-unknown-linux-musl`  |      6074160 | `d6bade637f1b16370cd88b0c9b8e27a9bf9adf1255204b0132f0f1bc282b8c07` | NEEDED `libc.so`           |
| linux-arm64-musl | `aarch64-unknown-linux-musl` |      4803064 | `e1cbbf287a805dc8533bc21933ff1e146400610cd2142df0b72e3debbd2e9dac` | NEEDED `libc.so`           |
| darwin-x64       | `x86_64-apple-darwin`        |      8209736 | `73c354434dde5d476720017bc779e344aa2c3aea29991b15fbd2e6ea2ac303c0` | minos 11.0 (expected 11.0) |
| darwin-arm64     | `aarch64-apple-darwin`       |      6826144 | `ed6d771bba439f862663fbf59d0a04b39020465639e8288d16982060befdc471` | minos 11.0 (expected 11.0) |

### Smoke Tests

Each shipped artifact was loaded through `index.js` against an in-process `ssh2` `Server`. The
smoke test verifies that the SHA-256 of the loaded binary equals the artifact's. On every target
it checks:

- `scan()`
- ed25519 key login, with the server verifying the signature and the JS key buffer zero-filled
  afterwards
- exec with exit code 7
- a panic mapping to `INTERNAL` with empty stderr
- `destroy()` + `process.exit(0)` in child processes: 20 runs on an idle connection and 20 runs
  during a streaming exec, each with exit code 0, signal `null` and empty stderr

Every check passed on every target, and every target reported the crypto backend `aws-lc-rs`. The
lifecycle and panic evidence therefore covers all six targets, not only linux-x64-gnu.

| Target           | Runner             | Environment      | Node     | Checks   | Max exit latency, idle / streaming |
| ---------------- | ------------------ | ---------------- | -------- | -------- | ---------------------------------- |
| linux-x64-gnu    | `ubuntu-24.04`     | host             | v24.22.1 | all pass | 5 ms / 9 ms                        |
| linux-x64-gnu    | `ubuntu-24.04`     | `ubuntu:22.04`   | v24.22.2 | all pass | 5 ms / 9 ms                        |
| linux-arm64-gnu  | `ubuntu-24.04-arm` | host             | v24.22.1 | all pass | 4 ms / 7 ms                        |
| linux-arm64-gnu  | `ubuntu-24.04-arm` | `ubuntu:22.04`   | v24.22.2 | all pass | 4 ms / 8 ms                        |
| linux-x64-musl   | `ubuntu-24.04`     | `node:24-alpine` | v24.22.2 | all pass | 6 ms / 15 ms                       |
| linux-arm64-musl | `ubuntu-24.04-arm` | `node:24-alpine` | v24.22.2 | all pass | 5 ms / 10 ms                       |
| darwin-x64       | `macos-15-intel`   | host             | v24.19.0 | all pass | 9 ms / 34 ms                       |
| darwin-arm64     | `macos-15`         | host             | v24.20.0 | all pass | 6 ms / 11 ms                       |

## Platforms

- **linux-x64-gnu, linux-arm64-gnu:** glibc 2.35 or newer, which means Ubuntu 22.04 and Debian 12
  or newer. RHEL 8 and 9 are deliberately unsupported as controllers.
- **linux-x64-musl, linux-arm64-musl:** for Alpine and other musl systems.
- **darwin-x64, darwin-arm64:** macOS 13.5 or newer, which is Node 24's own floor and therefore
  the minimum supported controller OS. The native binary keeps the deployment target macOS 11.0
  (`minos 11.0`), so the binding itself never sets a stricter floor than Node.
- **No Windows**, and no other platforms such as FreeBSD.

On an unsupported platform, `import "paratix"`, `--help`, `--version`, playbook unit tests and
scaffolding keep working, because the binding loads only on demand. A run stops before the first
secret prompt with a message that names platform, architecture, libc and the supported targets,
and points at omitted optional dependencies and lockfiles created on another platform
(npm/cli#4828). `create-paratix` scaffolds without the host-key scan and prints a hint. There is
no fallback to `ssh2`.

## Crypto Backend and License Allowlist

The crypto backend is **`aws-lc-rs`**, the russh default; the spike built it on all six targets.
`ring` remains a fallback behind a cargo feature. It compiled locally but was not cross-built in
CI.

The license allowlist was derived with `cargo deny list` on the `aws-lc-rs` build:

- `MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`

The remaining dual- or multi-licensed crates are covered by choosing one `OR` branch from that
list, for example:

| Crate         | License expression                                                                                                                    |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `dunce`       | `CC0-1.0 OR MIT-0 OR Apache-2.0`                                                                                                      |
| `fiat-crypto` | `MIT OR Apache-2.0 OR BSD-1-Clause`                                                                                                   |
| `r-efi`       | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (UEFI only, never built for our targets)                                                     |
| `wasi`        | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`                                                                                 |
| `aws-lc-sys`  | `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)` |

`deny.toml` (work package B) enforces licenses, bans and sources as blocking checks.

## Error Codes

The binding rejects with a fixed set of codes and secret-free messages. Native causes pass through
the secret sink. A panic or `JoinError` becomes `INTERNAL`, so every promise settles; the spike
does this only for guarded async tasks so far (see limitations).

| Code                  | Meaning                        | Spike                                         |
| --------------------- | ------------------------------ | --------------------------------------------- |
| `AUTH_FAILED`         | login rejected                 | tested                                        |
| `HOST_KEY_REJECTED`   | host key rejected              | tested                                        |
| `TIMEOUT`             | time limit exceeded            | tested                                        |
| `ABORTED`             | cancelled through a signal     | for B                                         |
| `CONNECT_FAILED`      | TCP connect failed, with errno | tested (`ECONNREFUSED`)                       |
| `PROTOCOL`            | key exchange or protocol error | for B                                         |
| `CHANNEL_OPEN_FAILED` | channel refused                | tested                                        |
| `DISCONNECTED`        | connection closed              | tested                                        |
| `SFTP_STATUS`         | SFTP failure, with status code | for B (on write, see limitations)             |
| `UNSUPPORTED_KEY`     | key format not supported       | tested                                        |
| `ENCRYPTED_KEY`       | encrypted private key          | tested                                        |
| `INTERNAL`            | internal error or panic        | tested (panic in a guarded task, all targets) |

`CHANNEL_OPEN_FAILED` replaces the `/channel open failure/i` regex from #178: russh reports a typed
`Error::ChannelOpenFailure`.

## Host Keys and Host Certificates

The trust decision stays in TypeScript. `knownHosts.ts` and `buildHostVerifier` keep TOFU, pins,
"HOST KEY CHANGED" and R-0000204. The native side calls an async JS callback and fails with
`HOST_KEY_REJECTED` when it rejects; only a boolean crosses napi. The JS side accepts only `true`
or `undefined` as a verdict; any other value rejects (fail closed). The TypeScript adapter
remembers the exact error object the verifier threw for that connection attempt and rethrows it on
`HOST_KEY_REJECTED`; only when nothing was remembered does it throw a generic
`HostKeyVerificationError`. The messages survive and reconnects still stop (fail closed). H2
proved the identity for async rejections, synchronous throws and non-`Error` values, and the
verdict rule for `true`, `undefined`, `false`, `1`, `"yes"`, `{}` and `null`.

Until E:

- The binding offers no host-certificate algorithms.
- `Preferred.key` is pinned to `ssh2`'s order: ed25519 → ecdsa → rsa-sha2-512/256 → ssh-rsa.
- `verifiedHostPublicKey` stays the raw key in its current format.

In E the work is split:

- **Rust** checks the certificate cryptography (CA signature, type `host`, validity) through the
  `russh::keys` re-export (`ssh_key::Certificate::verify_signature`), not a separate `ssh-key`
  dependency. This is necessary because russh itself does not verify the CA
  (`russh-0.65.0/src/client/kex.rs:288-305`), and a presented certificate replaces the raw-key
  check instead of adding to it (`client/mod.rs:2063-2077`).
- **TypeScript** checks the principals against the hostname and handles `@cert-authority` and
  `@revoked`.

`Preferred.host_key_certificates` is empty by default (`negotiation.rs:74-90`), so a server only
presents a certificate when the binding asks for one. `check_server_key` runs only on the initial
key exchange; russh does not check that the host key stays the same on rekey (see limitations).

## Secrets and zeroize Limits

Private keys, the login password and sudo stdin travel from JS to Rust as Buffers. Rust copies
them into `Zeroizing` buffers, and JS zero-fills the caller's buffer in every path, success
included. This replaces the R-0000521 rationale, which kept the key buffer because `ssh2` holds a
reference to it. In the spike only the private key and the password use `Zeroizing`; exec stdin,
and with it sudo stdin, is still a plain `Vec` (see limitations).

Limits inside russh and ssh-key:

- `decode_secret_key` keeps non-zeroized copies: a base64 `String` and a DER `Vec`
  (`russh-0.65.0/src/keys/format/mod.rs:51,97`).
- The parsed key lives in an `Arc<PrivateKey>` inside `auth_method`; ssh-key zeroizes it on drop.
- Password copies are zeroized (`auth.rs:307-313`, `CryptoVec`).
- Keyboard-interactive answers (`Msg::AuthInfoResponse`, `Vec<String>`) are not zeroized.
- V8 strings cannot be wiped at all, so passwords travel as Buffers, never as strings.

## Advisory Exception: RUSTSEC-2023-0071

RUSTSEC-2023-0071 (Marvin attack on the `rsa` crate, no fix available) is pulled in as
`rsa 0.10.0-rc.18` through the `rsa` feature of russh. `deny.toml` carries a justified exception:
the client only signs and never performs RSA decryption. The exception is re-reviewed on every
russh update.

Advisories run in a separate, scheduled, non-blocking job that reports new findings. Licenses,
bans and sources stay blocking.

## Update Rule

- `Cargo.lock` is committed and CI builds with `--locked`.
- One Renovate group covers `russh` and `russh-sftp`.
- A russh security release is taken even if `russh-sftp` lags behind, through `[patch]` if
  needed.
- Actions are pinned by SHA. The repository's action allowlist permits only `actions/*`,
  `pnpm/action-setup` and release-please, and requires SHA pinning. `Swatinem/rust-cache`, for
  example, is not usable without a settings change; the spike dropped it for that reason.

## Known Limitations and Findings for B

- **Server-opened channels:** the default `client::Handler` of russh accepts server-opened
  channels (forwarded-tcpip, x11, agent, session, direct-tcpip; `client/mod.rs:2915-3080`). The
  binding must override every one of these callbacks. The spike did, and H6 proves the rejection.
- **Exec output flow control:** each stdout/stderr chunk is a non-blocking threadsafe-function
  call into an unbounded queue, and the SSH channel window always reopens. That is not `ssh2`
  parity, because `ssh2` throttles the sender through the window. It matters for Paratix
  `readFile`, which runs `cat` over exec. B must bound the queue and tie the drain of the JS stream
  to channel reads.
- **Verifier timeout:** when `readyTimeout` fires, the socket is killed, but the russh session
  task still awaits the JS promise. A verifier that never settles therefore keeps the ref'd handle
  and the process alive. B must cancel the pending callback.
- **Panic coverage:** only panics inside the guarded async tasks map to `INTERNAL`. Panics in
  synchronous `#[napi]` functions or in value conversion abort the process, because napi's
  `catch_unwind` is opt-in. A panic in the detached exec reader would leave `done` pending, and one
  in the SFTP task surfaces as `DISCONNECTED`. B must wrap every entry point.
- **Rekey:** russh calls `check_server_key` only on the first key exchange and does not check that
  the host key stays the same on rekey, which OpenSSH does. Rekey was never exercised: the largest
  transfer was 32 MiB, below the 1 GiB rekey limit of russh.
- **zeroize gaps:** exec stdin (and therefore sudo stdin) is a plain `Vec` in the spike, and
  keyboard-interactive answers are not zeroized.
- **SFTP status on write is lost:** russh-sftp flattens WRITE and CLOSE status replies into
  `io::Error::other` (`russh-sftp-3.0.1 file.rs:227`), so the numeric SFTP status does not reach
  `SFTP_STATUS` on writes. OPEN and setstat keep it.
- **SFTP pipelining:** russh-sftp keeps up to 16 writes of up to 32 KiB in flight (H4 measured 16
  outstanding writes).
- **Remote command after `destroy()`:** exec runs without a PTY, so sshd does not signal the
  command when the connection drops and it keeps running. This matches `ssh2`.
- **MaxSessions race:** sshd frees a `MaxSessions` slot only after it processed the client's
  `CHANNEL_CLOSE`, so an immediate re-open can still be refused with `CHANNEL_OPEN_FAILED`.
- **ed25519 PKCS#8 through the agent:** the binding loads the format from a file, but OpenSSH's
  `ssh-add` refuses it ("invalid format"). This is an OpenSSH limitation.
- **Not covered by the spike:**
  - SFTP streaming read
  - `AbortSignal` / `cancel()` / `ABORTED`; a pending `connect()` cannot be destroyed either
  - ECDSA P-384/P-521 keys and encrypted keys beyond detection
  - the russh key parser in the agent column of the key-format matrix: that column tests the
    parsing of `ssh-add`
  - signature correctness against the `ssh2` Server in the interop proof, which shows protocol
    compatibility only; signatures are covered by the OpenSSH runs and the smoke login
- **Gate method:** the glibc gate used `readelf -V`, which is stricter than the plan's
  `objdump -T`; `objdump -T` confirmed GLIBC_2.34 on both downloaded gnu artifacts. The musl gate
  only warns; the alpine smoke test is the real check.
- **Build toolchain:** the gnu artifacts need the zigbuild toolchain. A native build on
  `ubuntu-24.04` links GLIBC_2.38 and would break the glibc 2.35 floor.

## Amendment (2026-10-29, #255)

Stage B1 of sebastian-software/paratix#255 ships the package `@paratix/ssh-native`. The spike
tables above stay unchanged as historical findings; this section records what B1 changed or
settled.

- **Verdict:** the host-key verifier accepts only `true`. Every other value (`false`, `undefined`,
  `1`, `"yes"`, `{}`, `null`) rejects with `HOST_KEY_REJECTED`. This supersedes the "`true` or
  `undefined`" rule in "Host Keys and Host Certificates" and H2, in line with the C1 planning in
  sebastian-software/paratix#256. A value the verifier throws or rejects with still reaches the
  caller of `connect()` as the identical object. `index.d.ts` types the verifier as
  `(info: HostKeyInfo) => boolean | Promise<boolean>`.
- **Unresponsive verifier:** `check_server_key` waits with `tokio::select!` on the verifier or a
  cancel signal; the deadline comes from `readyTimeoutMs` and the `AbortSignal`. On expiry
  `connect()` rejects with `TIMEOUT`, the russh session task ends, the handler and its ref'd
  threadsafe function drop, and the process can exit. A late verdict is discarded without an
  unhandled rejection. An `AbortSignal` gives `ABORTED`; an already-aborted signal gives `ABORTED`
  without opening TCP. napi holds no strong reference to the pending verdict promise, so the
  wrapper keeps it until it settles; an error from the verdict future (for example a collected
  promise) counts as "no verdict yet", and `check_server_key` keeps waiting for the deadline or
  the abort instead of rejecting the key early (fail closed either way).
- **Exec backpressure and stderr rule:**
  - stdout uses a bounded queue, `STDOUT_QUEUE_LIMIT` = 1 MiB. The Rust exec reader reads the next
    channel message only after JS has taken stdout.
  - The russh client config is set explicitly: `window_size` 2 MiB (2097152),
    `maximum_packet_size` 32768, `channel_buffer_size` 100.
  - stderr goes unbounded into a JS buffer and never blocks stdout or the exit while stdout flows.
  - **Known limit:** paused stdout stalls the whole connection (all channels, SFTP and disconnect
    detection). russh refills the SSH window on receipt, has no per-channel window, and its session
    loop blocks when the channel queue is full. stderr flows only while stdout flows, and large
    unread stderr uses memory. `destroy()`, `AbortSignal`, `cancel()` and destroying `stdout`
    (also an early exit from `for await` or a failed pipeline) still work during such a stall; a
    destroyed `stdout` releases its outstanding credit and acknowledges later data on arrival.
    `session.close()` puts the disconnect and the wait for the end under one 5 s deadline, then
    shuts the socket down; channels still open end with `disconnected: true`. A connection that
    drops while stdout is paused (russh's loop not blocked) also ends the channel as disconnected.
  - **Rule for C2:** Paratix never pauses stdout while it waits for something else on the same
    connection.
  - **Measured** in the B1 unit test: the server sent 6,422,528 bytes against a bound of 6,488,064
    (`STDOUT_QUEUE_LIMIT` + `highWaterMark` 64 KiB + 100 × 32768 + 2 MiB); JS buffered 1,081,344
    bytes against a bound of 1,114,112.
- **Ordering:** on connection loss the session disconnect is reported before the exit of an
  affected channel. That exit reports `code: null` with `disconnected: true`, never exit 0. The
  exit comes exactly once and after all stdout and stderr data, because it travels through the same
  threadsafe-function queue as the data. Signals are raw names (`TERM`); the C2 adapter adds `SIG`.
  Exec `close()`: russh 0.65 forgets a channel as soon as the client closes it, so the server's
  `CHANNEL_CLOSE` never reaches the reader. The reader therefore sends `CHANNEL_CLOSE` itself,
  forwards the messages already queued and then reports the exit once, with `disconnected: false`
  and the exit status if one arrived (otherwise `code: null`). russh keeps the channel's sender in
  its session map until the session ends.
- **Panic coverage:** every synchronous `#[napi]` entry point uses `catch_unwind`; threadsafe-function
  callbacks build their JS values inside `catch_unwind`; the exec reader and the handler
  callbacks are guarded. The JS wrapper maps any error without a valid `CODE|detail|message` reason
  to `INTERNAL` with the fixed message "internal error in the native SSH binding". The internal
  probe `__internalPanicProbe(kind)` (`sync`, `convert`, `async`, `event`, `execReader`, `handler`)
  in the shipped binary proves this. napi 3.15 converts the value of a resolved promise
  (`settle_deferred`) outside `catch_unwind`; the binding therefore resolves only trivially
  convertible values (externals, `()`, numbers, optional Buffers and derived `#[napi(object)]`
  structs of strings, numbers and booleans). Limits: a panic during an unwind aborts the process, and
  panics in tasks that russh-sftp spawns itself surface as `DISCONNECTED`. B1 drives SFTP through
  `RawSftpSession`, so this is limited to russh-sftp's own internal tasks.
- **SFTP status:** the finding "SFTP status on write is lost" is resolved. WRITE, READ and CLOSE run
  through russh-sftp's `RawSftpSession` (pipelined, at most 16 requests of 32 KiB in flight), whose
  status replies keep the numeric code. Failures surface as `SFTP_STATUS` with `sftpStatus` (unit
  tests: WRITE 4, also for a failure in the middle of a multi-chunk write, CLOSE 3, OPEN of a
  missing file 2). The binding waits for the reply to the subsystem request; a refused SFTP
  subsystem rejects `sftp()` with `CHANNEL_OPEN_FAILED` (detail `subsystem-refused`).
- **zeroize:** the private key, the password, exec stdin (including sudo stdin) and
  keyboard-interactive answers sit in `Zeroizing` buffers in the binding; `cargo test` asserts this
  through the types. The JS wrapper zero-fills the caller's buffers in every path, success
  included; a stdin chunk is zero-filled once copied, immediately if `stdin` no longer accepts
  data, and on exit, cancel or destroy if it is still queued. russh keeps its own non-zeroized copies: key decoding (`String`/`Vec`),
  keyboard-interactive answers (`Vec<String>` in `Msg::AuthInfoResponse`) and exec/sudo stdin
  (`Bytes` in `ChannelMsg::Data`).
- **Rekey gap:** russh does not re-check the host key on rekey and offers no hook for it. This
  stays a documented gap, tracked in sebastian-software/paratix#260 (re-check through a russh hook
  or an upstream contribution).
- **Tooling:**
  - CI caches with `actions/cache`; `Swatinem/rust-cache` is not used and the action allowlist is
    unchanged.
  - `pnpm rust:check` runs fmt, clippy with `-D warnings`, `cargo test` and
    `cargo deny check licenses bans sources`. `PARATIX_RUST_CHECK` (`always`, `skip`, `auto`)
    controls it.
  - It runs with `always` only in the `check` job of `ci.yml`. `integration-check.yml` and
    `publish.yml` set `skip` and only build.

## Source

- **Issue:** https://github.com/sebastian-software/paratix/issues/254
- **Epic:** https://github.com/sebastian-software/paratix/issues/252
- **Plan:** `docs/plan/2026-10-29-ssh-transport-auf-russh-umstellen.md` (PR #253)
- **Spike CI run (authoritative):**
  https://github.com/sebastian-software/paratix/actions/runs/40903619584
- **First green spike CI run:**
  https://github.com/sebastian-software/paratix/actions/runs/40895741197
- **Spike code:** commits `8a30ee9c3b951016cc8f6ce6165e72bc146bdb27` (code),
  `a779804b72cdc5e3afc357b3dc6d4456df21064c` (workflow) and
  `9d893b7b651b8c4502d2236fa2184522f10ce43a` (strengthened proofs) on branch
  `firmo/build/russh-spike-adr-0008` (PR #259)
