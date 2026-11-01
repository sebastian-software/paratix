# @paratix/ssh-native

Native SSH transport for [Paratix](https://github.com/sebastian-software/paratix): a thin
[napi-rs](https://napi.rs) binding over [russh](https://github.com/warp-tech/russh) 0.65 and
russh-sftp 3. The design and the spike that validated it are recorded in
[ADR 0008](../../docs/adr/0008-ssh-transport-russh-napi.md).

## Status

This is an internal binding for Paratix, not a general-purpose SSH library. Its API is narrow and
shaped by what Paratix needs; it may change with any Paratix release. Both `paratix` and `create-paratix` use this binding for SSH connections
and host-key scanning respectively; `ssh2` remains a development-only test server.

## Supported targets

Prebuilt binaries ship as optional platform packages `@paratix/ssh-native-<target>`:

| Target             | Requirement                                                                 |
| ------------------ | --------------------------------------------------------------------------- |
| `linux-x64-gnu`    | glibc 2.35 or newer (Ubuntu 22.04, Debian 12 or newer)                      |
| `linux-arm64-gnu`  | glibc 2.35 or newer                                                         |
| `linux-x64-musl`   | musl (Alpine)                                                               |
| `linux-arm64-musl` | musl (Alpine)                                                               |
| `darwin-x64`       | macOS 13.5 or newer (Node 24's floor; the binary itself targets macOS 11.0) |
| `darwin-arm64`     | macOS 13.5 or newer                                                         |

Windows and other platforms (for example FreeBSD) are not supported. The loader (`loader.js`) first
loads a locally built `ssh-native.<target>.node` next to it, then the platform package. If neither
loads, it throws an error that names platform, architecture, libc and the supported targets, and
points at omitted optional dependencies (`--no-optional`, `--omit=optional`) and at lockfiles
created on another platform ([npm/cli#4828](https://github.com/npm/cli/issues/4828)).

## Building

Published packages use prebuilt binaries and need no Rust toolchain. Contributors building from
source need the Rust toolchain pinned in `rust-toolchain.toml` (install
[rustup](https://rustup.rs), then run `rustup toolchain install` in this directory).

```sh
pnpm --filter @paratix/ssh-native build   # napi build --platform --release (incremental)
pnpm --filter @paratix/ssh-native test    # Node unit tests against an in-process ssh2 server
pnpm --filter @paratix/ssh-native test:integration        # against an OpenSSH sshd in Docker
pnpm --filter @paratix/ssh-native test:integration:local  # against a non-root local sshd
pnpm --filter @paratix/ssh-native test:smoke              # smoke test of the loaded binary
```

The integration suite (`test/integration`) runs the hard proofs H1–H6 of ADR 0008 against a real
OpenSSH server. Keys, CA and certificates are generated per run. Without Docker the sshd tests
are skipped locally; with `CI=true` they fail instead.

The root `pnpm build` builds the binding as well. `pnpm build` also regenerates `index.d.ts` from
`dts-header.txt` (the declarations of the JS wrapper) and the Rust `#[napi(object)]` structs; the
output is deterministic and CI checks that it is committed unchanged. `pnpm rust:check` at the
repository root runs `cargo fmt --check`, `cargo clippy`, `cargo test` and
`cargo deny check licenses bans sources` for this crate. RustSec advisories are checked weekly
and on demand by `.github/workflows/ssh-native-advisories.yml`; no pull request check depends on
it.

## Releases

`@paratix/ssh-native` and its six platform packages are versioned together with `paratix` and
`create-paratix` (release-please `linked-versions`; the platform manifests are `extra-files` of this
package). The crate itself stays at `version = "0.0.0"`. Until the first `ssh-native-v*` tag exists,
release-please bootstraps this component from the manifest version and the top-level
`bootstrap-sha` (the 0.23.1 release commit); without it, it would scan the whole history of this
directory and pick up older `Release-As` footers. A release runs `.github/workflows/publish.yml`:

1. The reusable workflow `ssh-native.yml` builds the six binaries (gnu via `cargo-zigbuild`
   against glibc 2.35, darwin with a fixed `MACOSX_DEPLOYMENT_TARGET`) and smoke-tests exactly
   these files on every target, the gnu targets also in `ubuntu:22.04` and the musl targets in
   `node:24-alpine`.
2. `scripts/publishWorkspacePackages.mjs` stages the packages under `$RUNNER_TEMP` (the platform
   manifests plus their binary, and this package with `optionalDependencies` pinned to the exact
   version), packs all nine with `pnpm pack` and checks the tarballs: the binary SHA-256 against
   the smoke-tested artifact, the packed `optionalDependencies`, no `.node` file in this package.
3. Before the first `npm publish` it classifies every package. An already published version is
   skipped only if its npm provenance names this repository, `publish.yml` and `refs/heads/main`;
   from the same workflow run its `integrity` must match the local tarball, from an earlier run
   `packages/ssh-native` must be unchanged since that run's commit. A missing version needs a
   successful npm OIDC token exchange for that package. Any failure aborts before anything is
   published, so a rerun resumes safely: "Re-run failed jobs" in the same run, or a new release
   run on main (also after a fix commit). "Re-run all jobs" rebuilds the binaries, which are not
   bit-identical, and therefore aborts. For the native packages the earlier-run rule also compares
   `.github/workflows/ssh-native.yml`, which pins the build toolchain.
4. It publishes the platform packages, then `@paratix/ssh-native`, then `paratix`, then
   `create-paratix`.

A manual run of `publish.yml` in mode `verify` performs steps 1 and 2 without publishing and
uploads the nine tarballs as the artifact `npm-tarballs`.

Trusted publishing for the seven `@paratix/ssh-native*` packages is configured with
`scripts/configure-trust.sh` (run by an npm owner, see the script header) right before the first
release PR after #255 B3 is merged; then "Require two-factor authentication and disallow tokens"
is enabled for them. Because of `linked-versions`, every release PR from B3 on contains this
package, whichever commit triggered it; without trust the publish job aborts before publishing
anything. npm allows two days between configuring a trusted publisher and its first publish.

## API overview

```js
const { connect, scan } = require("@paratix/ssh-native")

const hostKey = await scan({ host, port, timeoutMs: 10_000 })
const session = await connect(
  { host, port, user, privateKey: keyBuffer, readyTimeoutMs: 20_000, signal },
  async (info) => info.fingerprintSha256 === expectedFingerprint // only `true` accepts
)
const channel = await session.exec("cat /etc/hostname", { stdin: sudoPassword })
channel.stdout.pipe(process.stdout)
const { code, signal: exitSignal, disconnected } = await channel.exit
const sftp = await session.sftp()
sftp.createWriteStream("/tmp/file", { mode: 0o600 }).end(data)
session.onDisconnect((event) => console.log(event.reason, event.code))
await session.close() // or session.destroy() right before process.exit()
```

- `scan(options)` performs a handshake without login and resolves with the host key
  (`HostKeyInfo`).
- `connect(options, verifyHost)` connects, verifies the host key and logs in with an agent socket
  (`agent`), a private key (`privateKey`) or a password (`password`, also used for
  keyboard-interactive). The verifier may be async. Only a verdict of exactly `true` accepts the
  key; any other value rejects with `HOST_KEY_REJECTED`. A value the verifier throws or rejects with
  reaches the caller of `connect()` as the identical object. `readyTimeoutMs` (default 20000)
  covers TCP, handshake, verification and login; a verifier that never settles ends with `TIMEOUT`.
  An `AbortSignal` ends a pending connect with `ABORTED`; an already aborted signal does so without
  opening TCP. `agentForward: true` bridges server-opened agent channels to `agent`.
- `privateKey`, `password`, the exec `stdin` option and every Buffer written to `stdin` are
  zero-filled by the binding in every path, including success. A stdin chunk is zero-filled once the
  binding copied it, immediately if `stdin` no longer accepts data, and on exit, `cancel()` or
  destroy if it is still queued.
- `Session`: `authInfo`, `closed`, `onDisconnect(listener)` (fires exactly once; late subscribers
  are notified asynchronously; returns an unsubscribe function that also cancels a pending late
  notification), `exec()`, `sftp()`, `close()` (graceful, at most about 5 s before the socket is
  shut down; open exec channels then end with `disconnected: true`), the synchronous `destroy()` (safe right before `process.exit()`, releases the event loop) and the
  diagnostics `channelStats()`. An open connection keeps the Node event loop alive.
- `ExecChannel`: `stdout` (with backpressure), `stderr`, `stdin`, `exit`, `cancel()` and
  `close()`. `exit` resolves exactly once with `{ code, signal, disconnected }` after all stdout and
  stderr data. `signal` is the raw name, for example `TERM`. When the connection is lost, the session
  disconnect is reported first and the channel exits with `disconnected: true` and `code: null`.
  `cancel()` and the `signal` option end the channel with `ABORTED`. `close()` sends
  `CHANNEL_CLOSE`; the exit follows with `disconnected: false` and the exit status if one arrived
  before (otherwise `code: null`). Destroying `stdout` (also by leaving a `for await` loop early or
  through a failed pipeline) discards the rest of the output without stalling the connection.
- `SftpSession`: `createReadStream(path)`, `createWriteStream(path, { mode })` and `end()`. Streams
  are created synchronously and open the remote file lazily; errors arrive as `error` events. `mode`
  is applied on create and through an fchmod after open, so an existing file gets it too. A server
  that refuses the SFTP subsystem makes `sftp()` reject with `CHANNEL_OPEN_FAILED` (detail
  `subsystem-refused`).
- `cryptoBackend()`, `SUPPORTED_TARGETS` and `currentTarget()` describe the binary.

Keepalive and an inactivity timeout are off. Channels the server opens are rejected, except
`auth-agent@openssh.com` with `agentForward: true`. There is no Rust logger; a silent panic hook keeps
stderr clean.

## Authentication and key formats

Private key files must be unencrypted UTF-8 text in PEM or OpenSSH format. The binding supports
Ed25519, RSA, and ECDSA (P-256, P-384, P-521). Supported encodings include OpenSSH private keys,
RSA PEM, and PKCS#8 PEM for supported algorithms.

- Encrypted private key files fail with `ENCRYPTED_KEY`; the binding has no passphrase option.
  Load a passphrase-protected key into a working SSH agent and omit Paratix's `privateKey` option.
- DSA (`ssh-dss`) files, hardware-backed security-key (`sk-*`) files, unsupported algorithms,
  binary files, and corrupt or unrecognized formats fail with `UNSUPPORTED_KEY`.
- Agent authentication delegates signing to the agent and can use user certificates. These
  file-format restrictions describe keys passed through `privateKey`, not keys held by the agent.
  Server host certificates are not supported yet.

The binding selects exactly one authentication method per connection: agent, otherwise private
key, otherwise password (also used for keyboard-interactive). Paratix connects with a configured
key file only and never falls back from that file to a password. Without a key file,
`passwordFallback: true` permits a password attempt after agent authentication fails; that attempt
does not pass the agent again. `privateKey` with `passwordFallback: true` is rejected.

Paratix requires a working agent for `agentForward: true`. Combining it with `privateKey` is a
configuration error. A missing or unusable agent, or a failed agent login, aborts before any
password prompt. `ENCRYPTED_KEY` and `UNSUPPORTED_KEY` stop Paratix after the first attempt,
including during reconnect; trying another port cannot fix the key.

## Errors

Every error of the binding is an `Error` with a `code` from this set, and messages never contain
secrets:

| Code                  | Meaning                                                                                                     |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `AUTH_FAILED`         | login refused, or no usable agent identity                                                                  |
| `HOST_KEY_REJECTED`   | the verifier did not return `true`                                                                          |
| `TIMEOUT`             | `readyTimeoutMs` / `timeoutMs` elapsed                                                                      |
| `ABORTED`             | an `AbortSignal` fired or `cancel()` was called                                                             |
| `CONNECT_FAILED`      | TCP connect failed; `errno` and `syscallCode` (e.g. `ECONNREFUSED`)                                         |
| `PROTOCOL`            | SSH or SFTP protocol error                                                                                  |
| `CHANNEL_OPEN_FAILED` | the server refused a channel, the exec request (`exec-refused`) or the SFTP subsystem (`subsystem-refused`) |
| `DISCONNECTED`        | the connection is closed or was lost                                                                        |
| `SFTP_STATUS`         | the SFTP server returned an error status; `sftpStatus` holds its code                                       |
| `UNSUPPORTED_KEY`     | the private key type or format is not supported                                                             |
| `ENCRYPTED_KEY`       | the private key is encrypted (passphrases are not supported)                                                |
| `INTERNAL`            | a bug in the binding, including a caught panic                                                              |

`INTERNAL` always carries the fixed message `internal error in the native SSH binding`; the native
text is discarded. Invalid arguments (wrong types, missing credentials) throw a `TypeError`.

## Known limitations

- **Rekey does not re-check the host key.** russh calls the host-key check only on the first key
  exchange and offers no hook for later ones; OpenSSH checks that the key stays the same. Follow-up:
  [#260](https://github.com/sebastian-software/paratix/issues/260).
- **A paused stdout stalls the whole connection.** stdout has backpressure: the binding reads the
  next channel message only while fewer than `STDOUT_QUEUE_LIMIT` (1 MiB) bytes of stdout wait in
  JS. Because russh reopens the SSH window on receipt and its session loop blocks once a channel
  buffer is full, a paused stdout stops all channels, SFTP and the detection of a lost connection.
  `destroy()`, `close()`, an `AbortSignal` and destroying `stdout` still work while stalled; a
  connection that drops while stdout is paused still ends the channel. stderr has no bound of its own: it
  flows into a JS buffer, even without a reader, but only while stdout flows, and a very large
  unread stderr uses memory.
- **russh keeps its own, non-zeroized copies of secrets.** The binding holds private keys,
  passwords, exec stdin and keyboard-interactive answers in zeroizing buffers, but russh copies
  them: the key while decoding (`String`/`Vec`), keyboard-interactive answers (`Vec<String>` in
  `Msg::AuthInfoResponse`) and stdin (`Bytes` in `ChannelMsg::Data`).
- **Panics inside tasks of russh-sftp** surface as `DISCONNECTED`, not `INTERNAL`. Panics at the
  binding's own entry points become `INTERNAL`; a panic during an unwind still aborts the process.
- **MaxSessions race.** sshd frees a `MaxSessions` slot only after it processed the client's
  `CHANNEL_CLOSE`, so an exec opened right after another ended can still fail with
  `CHANNEL_OPEN_FAILED`.
- **The remote command keeps running after `destroy()`.** Exec runs without a PTY, so sshd does not
  signal the command when the connection drops (as with `ssh2`).
- **`__internalPanicProbe(kind)` is internal, undocumented API.** It exists only so tests can prove
  that a panic at each kind of entry point ends as `INTERNAL`; do not use it.

## License

MIT
