# Paratix TypeScript API and Module Reference

This is the complete reference for writing Paratix playbooks and custom modules. It covers the
TypeScript API, built-in modules, authoring patterns, and common mistakes.

## Overview

Paratix is a CLI tool for idempotent VPS configuration via SSH using TypeScript playbooks. Each playbook exports a `server()` definition containing an ordered list of modules that are checked and applied over SSH. Modules follow a check/apply pattern: `check` determines if work is needed, `apply` enforces the desired state.

## Controller requirements

Paratix uses `@paratix/ssh-native` for SSH. Controllers need Node.js 24 or newer and Linux
x64/arm64 (glibc 2.35 or newer, or musl), or macOS x64/arm64 13.5 or newer. Windows is not
supported for playbook execution. See [supported platforms](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/README.md).
Published packages include prebuilt binaries through optional dependencies; users do not need Rust.
Contributors building the repository need the pinned Rust toolchain. The runner checks the binding
before resolving playbook secrets; imports, `--help`, and `--version` do not load it.

## Agent authoring guidance

When generating or changing Paratix playbooks or custom modules, automated coding agents should use
this document as the complete API reference. Read the relevant API and module sections before making
changes, and follow the [Do's and Don'ts](#dos-and-donts) and [testing patterns](#testing-patterns).

## Imports

Paratix has exactly two import paths:

<!-- public-api-imports:start -->

```typescript
import {
  assert,
  assertValidModuleMetaEntries,
  assertValidModuleMetaEntry,
  debug,
  diffEnvironmentToMetaEntries,
  environmentMeta,
  environmentToMetaEntries,
  fail,
  failed,
  failedCommand,
  failedCommandWithDiagnostic,
  firstRun,
  isBooleanEnvironmentMetaEntry,
  isEnvironmentMetaEntry,
  isFirstRun,
  isLazyEnvironmentMetaEntry,
  isNumberEnvironmentMetaEntry,
  isSshdPortMetaEntry,
  isStringEnvironmentMetaEntry,
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
  meta,
  NEEDS_APPLY,
  pause,
  recipe,
  resolveEnvironment,
  server,
  shellQuote,
  signals,
  sshdPortMeta,
  systemHostMeta,
  systemRebootMeta,
  when,
} from "paratix"

import type {
  Environment,
  EnvironmentMetaEntry,
  EnvironmentValue,
  AuthorizedPrincipalsOptions as RootAuthorizedPrincipalsOptions,
  DeferredSecretResolver as RootDeferredSecretResolver,
  HostCertificateOptions as RootHostCertificateOptions,
  HostCertificateRequest as RootHostCertificateRequest,
  HostCertificateSigner as RootHostCertificateSigner,
  LocalHostCertificateSignerOptions as RootLocalHostCertificateSignerOptions,
  ExecOptions,
  ExecResult,
  KnownHostsCertAuthorityOptions as RootKnownHostsCertAuthorityOptions,
  MetaEnvironmentValue,
  Module,
  ModuleMetaEntry,
  ModuleResult,
  PodmanLoginOptions as RootPodmanLoginOptions,
  PodmanOptions as RootPodmanOptions,
  ManualSecretProviderOptions as RootManualSecretProviderOptions,
  SecretHandle as RootSecretHandle,
  SecretInput as RootSecretInput,
  SecretProvider as RootSecretProvider,
  SecretResolver as RootSecretResolver,
  SecretTotpInput as RootSecretTotpInput,
  ServerDefinition,
  ShutdownSignal,
  SshConfig,
  SshConnection,
  SshdPortMetaEntry,
  SystemHostMetaEntry,
  SystemRebootMetaEntry,
  StepCaHostCertificateSignerOptions as RootStepCaHostCertificateSignerOptions,
  TrustedUserCaOptions as RootTrustedUserCaOptions,
  UnifiedDiffOptions,
} from "paratix"

import {
  apt,
  archive,
  buildKeyValueDiff,
  buildUnifiedDiff,
  command,
  compose,
  cron,
  download,
  file,
  git,
  group,
  hostname,
  mount,
  net,
  op,
  package as pkg,
  podman,
  quadlet,
  releaseUpgrade,
  restartSystemdUnit,
  rsync,
  script,
  secret,
  service,
  ssh,
  sshd,
  swap,
  sysctl,
  system,
  systemd,
  timer,
  ufw,
  user,
} from "paratix/modules"

import type {
  DeferredSecretResolver,
  HostCertificateOptions,
  HostCertificateRequest,
  HostCertificateSigner,
  KnownHostsCertAuthorityOptions,
  LocalHostCertificateSignerOptions,
  ManualSecretProviderOptions,
  PackageSpec,
  PodmanLoginOptions,
  PodmanOptions,
  SecretHandle,
  SecretInput,
  SecretProvider,
  SecretResolver,
  SecretTotpInput,
  AuthorizedPrincipalsOptions,
  UnifiedDiffOptions as ModulesUnifiedDiffOptions,
  StepCaHostCertificateSignerOptions,
  TrustedUserCaOptions,
  UpgradeOptions,
} from "paratix/modules"
```

<!-- public-api-imports:end -->

Use `paratix/modules` for built-in modules in new playbooks. The same built-in module values are also
re-exported from `paratix` for compatibility with existing playbooks, and both entry points return
the same references. Only these two package entry points are public; do not use deep imports.

## SSH authentication

With `ssh.privateKey`, Paratix uses that file only: a rejected key does not trigger a password
prompt. Both `privateKey` with `passwordFallback: true` and `privateKey` with `agentForward: true`
are rejected during validation. Omit `privateKey` to use the agent in `SSH_AUTH_SOCK`.
`passwordFallback: true` permits a password prompt after an agent login fails (or no agent is
available); the password connection does not reuse the agent. `agentForward: true` requires a
working agent and successful agent authentication: a missing/unusable socket or failed login
aborts before a password prompt.

Key files must be unencrypted PEM/OpenSSH text for Ed25519, RSA, or ECDSA (P-256/P-384/P-521).
Encrypted files (`ENCRYPTED_KEY`), DSA, hardware-backed `sk-*` key files, and unsupported or corrupt
formats (`UNSUPPORTED_KEY`) fail on the first attempt, without further ports or reconnect retries.
To use an encrypted key, load it into an agent and omit both `privateKey` and `certificate`. See the
[native binding's key requirements](https://github.com/sebastian-software/paratix/blob/main/packages/ssh-native/README.md).

For file-based OpenSSH user-certificate authentication, set `ssh.certificate` to a nonempty path
alongside the matching `ssh.privateKey`. Both paths expand `~`. A certificate without a key file is
invalid; attaching an external certificate to a raw agent key is unsupported. To use an
agent-held certificate, omit both file options and let the existing agent identity path sign.

Before TCP, Paratix checks the certificate's OpenSSH format, user type, issuer signature, key
match, and validity window against the controller clock. Signature validation does not establish
CA trust: the server's `TrustedUserCAKeys` and principal policy determine authorization. Paratix
has no local rule requiring `ssh.user` to occur in the certificate principals;
`AuthorizedPrincipalsFile` can authorize a different principal. RSA user certificates use
RSA-SHA2 without enabling legacy `ssh-rsa`. Host identity has its own
[host-certificate trust policy](#host-certificate-trust), independent of user authentication.
Separately, [`ssh.hostCertificate`](#sshhostcertificate) issues host certificates for clients
that trust a host CA.
For OpenSSH clients running on a managed target, use
[`ssh.knownHostsCertAuthority`](#target-user-host-certificate-trust); this does not change controller trust.

Local certificate failures use `AUTH_FAILED` with native `detail` equal to
`certificate-invalid`, `certificate-key-mismatch`, `certificate-expired`, or
`certificate-not-yet-valid`. These stop immediately without trying more ports or retrying,
including during reconnect. Other `AUTH_FAILED` failures keep the existing retry behavior;
a server rejection gives a generic CA/principal hint because the exact server reason is unknown.
Each reconnect reloads both files, so a renewed certificate is read and an expired one fails
validation. Private-key and certificate input buffers are zero-filled after use; errors do not
include certificate contents, key IDs, or principals.

### Host-certificate trust

The controller reads host CA anchors from its existing `~/.ssh/known_hosts`. Add an independently
verified CA public key as `@cert-authority <host-patterns> <algorithm> <base64-key>`; these are
placeholders, not a complete key. No new `SshConfig` option is required. `ssh.certificate` is
only for user authentication, not host trust.

With `strictHostKeyChecking: "yes"` (default) or `"accept-new"`, a matching CA enables supported
host-certificate algorithms ahead of the unchanged raw-key list: Ed25519, ECDSA P-256/P-384/P-521
and RSA SHA-2. CA and leaf key algorithms are independent. CA selection happens before the
initial handshake using existing host/port matching, including lists, wildcards, negation and
hashed names; nonstandard ports use `[host]:port`, including IPv6. Without a matching CA, the
algorithm offer and raw-key behavior stay unchanged. `scan()` offers raw keys only, and
`strictHostKeyChecking: "no"` adds no CA trust.

The native binding validates the signature, type `host`, integer validity interval
`valid_after <= now < valid_before` against the controller clock, and an empty critical-options
map. TypeScript requires consistent structured metadata, a matching CA and at least one
matching principal. Principals use the requested hostname or IP without its port and
case-sensitive `*`/`?` patterns; an empty list fails. There is no new `HostKeyAlias` or
DNS/reverse-DNS fallback. Uncritical extensions do not authorize trust.

Under active Known-Hosts checking, matching `@revoked` entries win over CA anchors, cache and
pins. Both the signing CA and certified raw leaf are checked. A revoked certificate is
normalized to its raw leaf, so renewing that certificate does not clear the revocation. There
is no KRL, serial-number or key-ID policy. CA anchors are never ordinary host-key entries.

`expectedHostPublicKey` and `expectedHostFingerprint` always refer to the raw public key; for a
certificate, that is the certified leaf. A certificate must pass CA validation **and every
configured pin**. Neither a CA key nor a certificate blob substitutes for a leaf pin. A raw key
presented by the server still follows the normal pin, `"yes"` or `"accept-new"` policy even if a
CA line matches; that line alone is not a raw-key mismatch. A rejected certificate causes
`HostKeyVerificationError` and stops reconnect, with no retry using a raw-key handshake.
Diagnostics do not include unfiltered key IDs, principals or certificate blobs.

A CA-only controller session can reconnect with a different leaf after the new certificate
passes all trust checks. Successful authentication replaces the verified leaf and evidence;
failed attempts preserve both. Explicit leaf pins and any raw-key binding established earlier
in the same connection instance still prevent leaf rotation. A switch to a raw-key handshake
must match the latest verified leaf and also pass the normal raw-key policy.

Certificates, certified leaves and CAs never create TOFU file or cache entries, whether accepted
or rejected. Raw-key `"accept-new"` persists only after successful authentication as before.
Successful handshakes replace the complete session verification evidence, including the
accepted CA; failed attempts leave the prior evidence unchanged. See
[`getConnectionInfo()`](#sshconnection-api) for its raw-leaf and evidence fields, and
[`rsync.sync()`](#rsync) for external SSH trust boundaries.

These checks apply to the initial key exchange. Rekey host-key validation remains open in
[#260](https://github.com/sebastian-software/paratix/issues/260); host-certificate issuance and
target-side Known-Hosts management are outside this controller trust feature.

Native errors include `[CODE]`; after other connection failures, the final message includes
`; last error on port <p>: <native message> [<CODE>]`. See
[SSH troubleshooting](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/troubleshooting.md).

### Server-side user-CA trust and principals

Use `ssh.authorizedPrincipals` to manage the per-user principals file before enabling trust, then
use `ssh.trustedUserCa` to manage the shared user-CA trust. The CA module writes the global
`TrustedUserCAKeys` and `AuthorizedPrincipalsFile` directives; it does not manage
`AuthorizedPrincipalsCommand`, which remains an independent OpenSSH policy boundary.

```typescript
import { server } from "paratix"
import { ssh, user as userModule } from "paratix/modules"

const user = "deploy"
const caPublicKeys = "ssh-ed25519 AAAA... ca-one\nssh-ed25519 AAAA... ca-two"
const principalsBeforeTrust = ssh.authorizedPrincipals(user, ["deploy", "release"])
const trust = ssh.trustedUserCa({
  publicKey: caPublicKeys, // one or more complete OpenSSH public-key lines
  principalsFile: "/etc/ssh/auth_principals/%u", // optional; must match every call
  revokedKeys: "/etc/ssh/revoked_user_keys", // optional
})

export default server({
  name: "certificate-host",
  host: "203.0.113.10",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/admin" },
  run: [userModule.present(user, { homeMode: "0700" }), principalsBeforeTrust, trust],
})
```

`publicKey` may contain multiple CA keys; Paratix validates and deterministically normalizes them.
Principal names are single, injection-safe lines and an empty principal array creates an empty
file. The default template is `/etc/ssh/auth_principals/%u`; a custom template must be an absolute,
normalized `/etc/ssh/` path ending in exactly one `%u`, and the same template must be used by the
CA and principal modules because the CA resource is global. The modules reject path/file
collisions, symlinks, unsafe ancestors, and an existing root-only `0700` ancestor that the login
user cannot traverse. Managed files are root-owned and mode `0644`; newly created directories are
`0755`.

If `revokedKeys` is set and absent, Paratix creates an empty text revocation file before enabling
the directives. Existing text lists and binary OpenSSH KRLs are preserved byte-for-byte, including
safe metadata such as mode `0600`; Paratix never creates or deletes revocation entries. Omitting
`revokedKeys` leaves `RevokedKeys` unmanaged.

Removal must be ordered explicitly: first apply `ssh.trustedUserCa({ state: "absent" })`, which
validates, deactivates, and reloads sshd before removing the CA file; then remove principal files
with `ssh.authorizedPrincipals(user, [], { state: "absent" })`. Principal files and revocation
files are retained when CA trust is removed. A second apply or dry-run is idempotent. The modules
refuse managed directives inside `Match` blocks and unresolved or conflicting `Include` layouts;
they report effective-value mismatches rather than rewriting foreign drop-ins.

`check` and `ok` describe file contents, safe metadata, and effective **on-disk** sshd settings
read by `sshd -T`; they do not attest to the running daemon's configuration. Handled update
errors trigger rollback, and rollback failures are reported. This is a bounded transaction,
without automatic recovery after an abrupt controller or target process interruption. If an
interruption occurs after configuration publication but before reload, the daemon may still use
its previous principal or revocation settings even though the files match. Rerunning Paratix
alone can return `ok` without making that pending configuration live.

Applies also share target-process locking with host-certificate writers and require Linux
`flock`. An unresolved host-certificate Pending blocks these writers until the
[host-certificate recovery owner](#pending-and-shared-sshd-writers) resolves it. This does not
replace the separate user-CA recovery procedure below.

After such an interruption, an administrator must verify that the on-disk CA, principal,
revocation, and sshd configuration files and their permissions match the intended policy. On
the **remote Linux target**, as root or with sudo, validate `/etc/ssh/sshd_config` with
`sudo sshd -t -f /etc/ssh/sshd_config`, then reload the existing SSH service that runs that
configuration: `sudo systemctl reload ssh.service`, or `sshd.service` when that is the actual
unit. Stop on syntax or reload failure and resolve it administratively. After a successful
reload, rerun Paratix from the controller and verify the intended certificate login and
rejection policy. These administrative commands run on the target, not the macOS controller;
see the [interrupted-update recovery procedure](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/README.md).

## Playbook Structure

A playbook is a TypeScript file with a default export of `server()`:

```typescript
import { server, recipe, when, shellQuote } from "paratix"
import { package as pkg, file, service, ufw, hostname } from "paratix/modules"

export default server({
  // Required fields
  name: "web-01",
  host: "10.0.0.1",
  ssh: {
    user: "root",
    ports: [22], // Array -- runner tries each port in order
    privateKey: "~/.ssh/id_ed25519", // Optional -- "~" is expanded; omit to use SSH agent
    // Optional:
    // certificate: "~/.ssh/id_ed25519-cert.pub", // Matching user certificate; requires privateKey
    // agentForward: false,          // Forward SSH agent to remote
    // passwordFallback: false,     // Only without privateKey; fallback after failed agent login
    // sudoPassword: "...",
    // reconnectTimeout: 30000,
    // strictHostKeyChecking: "yes", // default; set "accept-new" only for explicit TOFU
    // expectedHostFingerprint: "SHA256:...",
    // expectedHostPublicKey: "ssh-ed25519 AAAA...",
  },

  // Optional: env values available in templates and conditions
  env: {
    DOMAIN: "example.com",
    APP_PORT: 3000,
    SECRET: async () => fetchFromVault("secret"), // Lazy async values supported
  },

  // Required: ordered list of modules to apply
  run: [
    hostname.set("web-01"),
    pkg.update("2025-03-01"),
    pkg.installed("nginx", "curl"),
    file.template("/etc/nginx/sites-available/default", "./files/nginx.conf.tmpl"),
    service.enabled("nginx"),
    service.running("nginx"),
    ufw.enabled(),
    ufw.rule("allow", 80),
    ufw.rule("allow", 443),

    // Conditional module
    when((env) => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban")),
  ],

  // Optional: signals fire when ANY module in run reported "changed"
  signals: [service.reload("nginx")],
})
```

## Module Reference

### `apt`

| Method            | Signature                                                                                | Idempotent       |
| ----------------- | ---------------------------------------------------------------------------------------- | ---------------- |
| `apt.debconf`     | `(packageName: string, selections: Record<string, string>): Module`                      | Yes              |
| `apt.distUpgrade` | `(date: string, options?: UpgradeOptions): Module`                                       | Yes (dated flag) |
| `apt.key`         | `(name: string, url: string, options: { fingerprint: string }): Module`                  | Yes              |
| `apt.repository`  | `(nameOrPpa: string, source?: string, options?: { signedBy?: false \| string }): Module` | Yes              |

### `archive`

| Method            | Signature                                                                                       | Idempotent        |
| ----------------- | ----------------------------------------------------------------------------------------------- | ----------------- |
| `archive.extract` | `(source: string, destination: string, options?: { owner?: string; upload?: boolean }): Module` | Yes (SHA256 flag) |

`archive.extract` extracts a tar symlink or hardlink only if its target, resolved from the link's
own directory (hardlinks: from the archive root) and through the archive's own symlinks, stays
inside `destination`; absolute targets, a link in place of the destination root, members below an
archive symlink, hardlinks to or through an archive symlink, a path that occurs more than once with
a symlink among its occurrences and conflicting types or targets, and zip symlinks are rejected. A
member whose path, or whose hardlink target, has a `..` path segment is rejected in tar and zip
archives, even when the normalized path would stay inside `destination`; `.` segments, a leading
`./` and `..` in symlink targets remain allowed. The archive listing is decoded as strict UTF-8,
never with replacement characters. `tar` lists the archive under a UTF-8 C locale (`C.UTF-8` or
`C.utf8`) when the host has one and under `LC_ALL=C` otherwise (bsdtar always under `LC_ALL=C`);
for GNU tar and bsdtar the escape sequences of the
listing (`\NNN`, `\\` and the single-letter control escapes) are decoded back to the stored bytes,
so non-ASCII names are accepted whatever locale the SSH session has. A member whose decoded name is
not valid UTF-8, or whose name contains any other escape sequence, is rejected because it cannot be
mapped to the extracted name. A member whose path or link target contains a backslash or U+FFFD is
rejected in every listing, also after decoding, because another `tar` (such as BusyBox) and `unzip`
print escape sequences and real backslashes alike. Once the archive listing is validated, and before
the destination is created or validated, one command reads every containment entry of the
destination and creates the apply's own `in-progress` entry (see below); an apply that cannot create
it stops before the destination is touched. An entry directory that is a symlink or not a directory,
an entry or an old flag file that is a symlink or not a regular file, or an entry or old flag file
that cannot be read makes the apply refuse before the destination is touched; an entry without a
usable record of offending links does not (see below). Before anything is staged, it then refuses a
member whose path or parent directories are existing host symlinks (an archive symlink may replace
the link at its own path), a file, hardlink or symlink member where the host has a real directory,
and a directory, including an implied parent directory, where the host has a non-directory. Still
before copying anything, it resolves the symlinks already under `destination` together with the
archive's: an archive symlink replaces an existing symlink at the same path and existing absolute
targets inside `destination` are allowed, while any other type combination at a member path, a
member below an existing symlink, a link resolving outside `destination`, or a link whose target
passes through a path that differs from an existing symlink (of the archive or already on the host)
only by letter case (U+1E9E, the capital sharp s, counts as `ss`, like `ß`), Unicode normalization
(NFC, NFD or compatibility forms) or default-ignorable characters such as U+200D, U+200C, U+FEFF or
U+00AD refuses the extraction, because a case-insensitive or normalizing filesystem may follow that
symlink. The archive's own link rules above (except the root-link rule) compare member paths under
the same folding: symlink `x/L -> y` refuses member `x/l/f`, symlink `a/b/S -> ../../x` refuses a
hardlink `h` to `a/b/s`, and symlink `Foo -> bar` refuses a file `foo`, while duplicates without a
symlink, such as regular files `Makefile` and `makefile`, stay accepted. This comparison is purely
lexical, so it refuses the same archives on case-sensitive hosts, and it may group more spellings
than a given filesystem does, which only refuses more. An existing escaping link must then be
removed or pointed inside.

Only the links the archive can affect are judged: the archive's own symlinks and every existing
symlink whose resolution passes through a path the archive writes (a member path or one of its
parent directories, compared under the same case and normalization folding), directly or through
another such link. An existing symlink whose path differs from one of the archive's symlinks only by
letter case, Unicode normalization or default-ignorable characters (the host listing the archive's
`a/s` as `A/S`, for example) is judged like that archive link, before and after the merge: if it
escapes, it refuses the extraction, or after the merge fails the run and is recorded in the apply's
containment entry; being lexical, this may also judge an unrelated link on a case-sensitive host,
which only refuses more. Any other existing symlink, even one that points outside `destination`,
loops or has an unusual name (a virtual environment's `bin/python3 -> /usr/bin/python3`, for
example), is ignored (except by the whole-destination check described below) and never changed. An
archive without symlinks (every zip archive among them) cannot change how any path resolves, so this
check runs no command for it, and the check after the merge runs only while containment entries of
the destination record links or hold no usable list (see below). For an archive with symlinks, one
command lists every symlink under `destination`, with link paths relative to it, up to a
captured-output cap of 64 MiB; a destination with more symlinks than that fails the check with a
message saying it holds too many symlinks to check. The listing sends every name outside printable
ASCII hex-encoded and decodes it byte for byte: a valid UTF-8 name keeps its exact spelling (a
literal U+FFFD included), while a judged link whose path or target is not valid UTF-8, or that
resolves through such a link, cannot be checked and refuses the extraction until it is renamed or
removed; malformed listing output or a duplicate link path fails closed. With GNU `find` on the
host, a directory under `destination` that cannot be read or searched is reported instead of failing
the listing: a judged link that resolves into it, or an archive member at or below it, refuses the
extraction because it cannot be checked, while the links inside it are not judged (a known limit).
Without GNU `find` (busybox, the BSDs), any unreadable directory under `destination` fails the
check. A symlink under `destination` that cannot be read during the check fails it as well, with a
message that names the link when its name can be transported.

The host stops the merge with GNU `timeout` after 100 seconds (killing it 10 seconds later), before
the 120-second command timeout; without `timeout` the merge fails before copying anything. Once the
merge has started, a check of the same links (the archive's symlinks and every symlink whose
resolution passes through a path the archive writes) always runs for an archive with symlinks, and
for any archive while containment entries record links or hold no usable list (see below), also
after a failed or stopped merge that may have copied entries: it resolves the links like the
pre-merge check, without asking the host to resolve them, and counts name variants as violations
too. It then asks the kernel in one batched command (`test -e` and `test -ef`, bounded by the
kernel's symlink limit; never `realpath` or `readlink -f`) whether each judged link it placed inside
really reaches the resolved path. A link that reaches an existing object must reach exactly that
path. A link that reaches nothing is not trusted for that alone, because writing through it would
create the missing name wherever the kernel resolves the rest of its target: the check walks the
link's target path from its full length back towards the link's directory and compares the first
point that exists on the host or in the model with the model's location of the same point, and both
must exist and be the same object. A link the kernel resolves to a different object, whose nearest
existing point differs or exists on one side only (for example a target that climbs with `..` out of
a missing directory, even though nothing can be written through it yet), or of whose target path no
point exists at all is a violation. When a judged link resolves through another symlink that is
not judged itself, the same command cross-checks that link's target as well; a mismatch there is a
violation of the judged link, names the followed link, and only the judged link is recorded. A
cross-check that cannot be completed fails the run, including a judged link whose cross-check entry
would exceed 64 KiB (a target with very many segments). A
converged tree costs two commands when a judged symlink is placed inside, one otherwise, and none
for an archive without symlinks (one listing plus at most one cross-check while containment entries
record links or hold no usable list), independent of the number of members; neither a violation nor
re-verifying recorded links or the whole destination for an archive with symlinks adds one. This
check only reports: it removes, moves or changes nothing. Any violating link (resolving outside, not
resolvable within the symlink limit such as a loop, a name variant, a kernel mismatch, or a link
that cannot be checked because of an unreadable directory or a name that is not valid UTF-8) fails
the run with a message that names the first 10 offending links by path, stored target and reason,
adds `(and N more)` for the rest, and states that nothing was removed or changed. The offending
links must be removed or pointed inside manually.

Every apply records its outcome in its own containment entry, a file `run-<32 hex digits>` in the
destination's entry directory `/var/lib/paratix/flags/archive-containment-<sha256>.d/` (`<sha256>`
is the SHA-256 of the normalized destination path). It creates that entry as `in-progress` once it
holds the destination's extract lock (see below) and before it touches the destination, never
replacing an existing name, and it only ever rewrites its own entry, never another apply's. The `in-progress` entry records the SHA-256 digest of the archive's
containment scope (its symlinks and every path it writes, together with an algorithm identifier and
the Unicode version of the Node.js runtime), so its size is fixed whatever the number of members. An
apply that stops with an error after its merge started, before its post-merge check passed, rewrites
its entry as `stopped` with the same digest. When an apply fails after its merge started, its entry
records the links its post-merge check identified, relative to `destination` (at most 256); a
failure before the merge started published nothing and records an empty list, while the links other
entries record stay in those entries. A later apply of any source into that destination reads every
entry before it touches the destination and re-verifies the links all of them record in its own
post-merge check, with the same lexical resolution and kernel cross-check: each must be gone or now
resolve inside `destination`, otherwise the apply fails naming it and its own entry records it. An
entry of an earlier apply that did not finish (it was interrupted, stopped with an error after its
merge started or could not record its outcome) records only that apply's scope digest. If the
digest equals the current apply's own, the earlier apply extracted an archive with an equivalent containment scope (the same symlink paths and
written paths, compared by name variant; member contents and symlink targets are not part of the
digest) and could only have published links the current apply judges anyway: its own symlinks and
every link whose resolution passes through a path it writes. The
current apply's normal post-merge check then covers that entry, without verifying the whole
destination, and a symlink outside that scope does not affect it, even one that points outside
`destination`. If an entry holds no usable list, because its digest differs (the archive's
containment scope changed, or the digest was derived by a paratix version with another scope
derivation or under another Unicode
version), it is an `in-progress` entry of an older paratix version, its check could not identify the
links (a failed listing or an archive member in an unreadable directory, for example), there were
too many to record (more than 256 links or 64 KiB), or it is damaged (empty, truncated or malformed,
for example), and likewise when the single flag file `archive-containment-<sha256>.failed` of older
paratix versions exists or there are more than 16 entries, the apply still runs normally. Its
post-merge check then verifies the whole destination: every symlink under `destination`, not only
those the archive can affect, must resolve inside it, with the same lexical resolution and kernel
cross-check, before `owner` is applied and the marker files are written. If the check finds links
that escape or cannot be resolved, the apply fails naming them as above, removes nothing, and its
own entry records exactly those links; the entries it read stay as well, so the next apply verifies
those links and the whole destination again. If the check cannot complete (a failed listing, an
unreadable directory or too many symlinks), the apply fails with the reason, its entry holds no
usable list, and the next apply verifies the whole destination again. This check reuses the
post-merge listing and cross-check: while an entry holds no usable list, it adds at most one listing
and one cross-check for an archive without symlinks and no command for an archive with symlinks.
Reading the entries and creating the own one costs one command, and removing them after a success
one more, whatever the number of entries. A `.paratix-stage.*` directory that a killed apply left
inside `destination` is not judged by the normal post-merge check, because the archive link rules
above keep its links inside it, and it is not removed. After an interrupted apply, a successful
retry with an archive of equivalent containment scope (a matching digest) removes the entry without
a manual step. After an
upgrade, the old flag file and the entries of older paratix versions are read like entries without a
usable list, and the whole destination is verified before they are removed; an older paratix version
likewise reads an entry of this version as one without a usable list. A destination that
deliberately contains a symlink pointing outside it fails this check while an entry holds no usable
list, for example a virtualenv interpreter link into `/usr/bin` in a runner work tree when the
archive's containment scope changed after an interrupted apply. If violations persist, remove or
repoint the offending
links and run again. If the offending links are intended and outside the scope the archive can
affect, clearing the containment state can allow a retry to pass. This manual step is needed only
for entries without a usable digest or after the archive's containment scope changed. The failure
message offers this step
only after a fully readable whole-destination check when the current archive's normal scope
would pass without recorded links, including the kernel
cross-check. First stop or wait for all `archive.extract` applies to this destination to finish;
while its extract lock `/var/lib/paratix/flags/archive-extract-lock-<sha256>` exists, an apply runs
or was interrupted (see below). Prevent new applies until both your inspection and state clearing
are complete. An active apply can still publish more contents, so its entry must not be deleted through `run-*` while it is
running. Only then check the destination yourself and delete its `run-*` entries and the old flag
file with
`rm -f -- '/var/lib/paratix/flags/archive-containment-<sha256>.d'/run-* '/var/lib/paratix/flags/archive-containment-<sha256>.failed'`.
Then run again. Replace `<sha256>` with the SHA-256 of the normalized destination path before use;
the failure message names the exact command. Clearing state cannot resolve violations within the
current archive's scope. On failure no extraction marker is written and no `owner` is applied.

Only an apply that succeeds completely, including the re-verification of recorded links or of the
whole destination, `owner` and the marker files, removes entries, in one command at the end, while
it still holds the extract lock: every entry it read whose content is unchanged since it read it (it
claims each by an atomic rename and compares its SHA-256 with the one it read), the old flag file
included, and then its own. An entry that was rewritten in the meantime stays, and the next apply
reads it. A refusal while the destination is created or validated, by the checks before staging, by
the pre-merge check, by the merge, by the post-merge check, or because the apply lost its extract
lock leaves the apply's entry in place. While any entry or the old flag file exists, and while the
entry directory is a symlink, not a directory or unreadable, `check` reports `needs-apply` for every
archive extracting into that destination. An apply that crashes while removing entries leaves a
`run-…-claim-<n>` entry, which is an ordinary entry and keeps `check` at `needs-apply`.

Applies to one destination are serialized by a per-destination extract lock, the directory
`/var/lib/paratix/flags/archive-extract-lock-<sha256>` (the same `<sha256>` as the entry directory).
An apply takes it after the upload, the archive listing and the member checks, right before it
creates its containment entry, and releases it after it removed the entries or recorded its
failure, on every exit path the controller survives; the release removes the lock only while its
marker still carries this apply's token. `check` takes no lock, and applies to different
destinations still run in parallel. The lock holds a marker file `holder`: its first line is a
random token, the only value paratix compares, and the lines after it name the owner for an
operator: `controller <hostname> pid <pid>` (the controller host and its process ID),
`started <ISO 8601 time>` and `entry run-<32 hex digits>` (the apply's containment entry). Taking
and releasing the lock adds a few commands to every apply.

An apply that finds the lock held first tries to reclaim a stale lock (see below) right away, then
waits for up to 300 seconds, polling on the host in rounds of at most 60 seconds and trying to
reclaim a stale lock again after every round. If the lock is freed in time, the apply takes it and
proceeds. Otherwise it fails with a message that names the destination, the lock path, the owner
lines, the marker's age and when the lock becomes reclaimable; retry once the other apply has
finished.

While it holds the lock, an apply refreshes the marker about every 60 seconds. Each refresh, and a
guard that runs in the same command right before the merge and right before the entries are
removed, passes only while the lock directory exists, the marker's first line is the apply's token
and the marker is not older than 300 seconds. If the lock was lost anyway, the apply fails visibly
and names the lock: a refused merge is not started and publishes nothing, and a refused removal
removes no entry. Its own entry then records an empty list, so `check` reports `needs-apply` until
a later apply verifies and clears the entries.

A killed or disconnected apply cannot release its lock. A waiting or later apply reclaims a lock
whose marker is older than 540 seconds (a lock directory without a marker by the directory's age);
this lies above the guard's 300 seconds plus the host-side merge limit of 110 seconds, so a merge
the guard let start has ended before its lock can be reclaimed. An apply started shortly after an
interrupted one can therefore still fail with the wait message, which says when the lock becomes
reclaimable. Under the lock, an `in-progress` entry belongs to an apply that stopped without
finishing, so the apply that reclaimed the lock verifies the whole destination as described above,
or only its own archive's scope when the scope digests match, and, after a success, removes the
entries; `check` then converges. To inspect a held lock, read the
owner lines in its `holder` file. Remove the lock by hand with
`rm -f -- '/var/lib/paratix/flags/archive-extract-lock-<sha256>/holder' && rmdir -- '/var/lib/paratix/flags/archive-extract-lock-<sha256>'`
only when no `archive.extract` apply for that destination runs anywhere, on any controller;
otherwise the running apply loses its lock to the next one. The wait failure message names the
exact command.

Known limits remain. A forward jump of the target host's clock larger than the gap between the
guard age and the reclaim age, or a merge stuck in uninterruptible I/O beyond its `timeout`, can
make a live apply's lock look stale: another apply may then reclaim it and, after a clean
whole-destination check, remove the live apply's `in-progress` entry; if both extract the same
archive, their digests match, and the other apply removes it after its normal post-merge check
alone. The guards stop the live apply at its next guarded step, but if it is killed, links its merge published after that check are
checked by nobody. Nested destinations such as `/srv/a` and `/srv/a/b` use different locks and are
not serialized against each other. Running older and newer paratix versions at the same time on one
destination is not supported: older versions take no extract lock and still use the single flag
file.

### `command`

| Method          | Signature                                                                                                  | Idempotent        |
| --------------- | ---------------------------------------------------------------------------------------------------------- | ----------------- |
| `command.shell` | `(cmd: string, options?: { check?: string; name?: string; secrets?: string[]; timeout?: number }): Module` | Only with `check` |

`command.shell` accepts `timeout` in milliseconds to limit the runtime of the applied command. The
idempotency guard configured through `check` is not affected by this timeout.

### `cron`

| Method        | Signature                                                                                       | Idempotent |
| ------------- | ----------------------------------------------------------------------------------------------- | ---------- |
| `cron.job`    | `(user: string, name: string, options: { job: string; state?: "absent" \| "present" }): Module` | Yes        |
| `cron.absent` | `(user: string, name: string): Module`                                                          | Yes        |

`cron.absent(user, name)` is the dedicated uninstall variant: it removes a
managed cron entry without requiring a placeholder `job` argument. Use it as
the idiomatic way to ensure a previously installed cron job is gone.

### `compose`

| Method            | Signature                                                                                                            | Idempotent |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| `compose.config`  | `(options: { content?: string; projectDirectory: string; runtime?: "docker" \| "podman"; src?: string }): Module`    | Yes        |
| `compose.up`      | `(options: { projectDirectory: string; runtime?: "docker" \| "podman"; services?: string[] }): Module`               | Yes        |
| `compose.down`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman"; volumes?: boolean }): Module`                 | Yes        |
| `compose.pull`    | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | Partial    |
| `compose.restart` | `(options: { projectDirectory: string; runtime?: "docker" \| "podman" }): Module`                                    | No         |
| `compose.systemd` | `(options: { detached?: boolean; name?: string; projectDirectory: string; runtime?: "docker" \| "podman" }): Module` | Yes        |

> **`compose.pull` change detection:** `compose.pull` compares image digests before and after the pull to report `ok` (nothing new) vs `changed`. This needs `compose config --format json`. With `runtime: "podman"`, when the compose provider is the Python `podman-compose` (which does not support `--format json`), digest-based detection is unavailable: the pull still runs, but always reports `changed`. The Docker and Compose v2 paths are unaffected.

### `download`

| Method            | Signature                                                                                                                                                                                                                                                                                                                    | Idempotent |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `download.url`    | `(destination: string, url: string, options?: { allowInsecureHttp?: boolean; allowInsecureHttpHeaders?: boolean; allowUnverifiedDownload?: boolean; connectTimeout?: number; force?: boolean; headers?: Record<string, string>; sha256?: string; mode?: string; owner?: string; group?: string; timeout?: number }): Module` | Yes        |
| `download.github` | `(destination: string, options: { repo: string; tag: string; asset: string; token?: string; allowUnverifiedDownload?: boolean; connectTimeout?: number; sha256?: string; mode?: string; owner?: string; group?: string; timeout?: number }): Module`                                                                         | Yes        |
| `download.large`  | `(destination: string, url: string, options?: { allowInsecureHttp?: boolean; allowInsecureHttpHeaders?: boolean; allowUnverifiedDownload?: boolean; connectTimeout?: number; group?: string; headers?: Record<string, string>; mode?: string; owner?: string; sha256?: string; timeout?: number }): Module`                  | Yes (flag) |

Downloads require an explicit integrity decision at runtime: provide `sha256`
for verification, or set `allowUnverifiedDownload: true` when the remote
artifact is intentionally trusted without a pinned digest. `download.url` and
`download.large` allow only HTTPS by default; set `allowInsecureHttp: true`
only when an `http://` source or redirect is intentional. Sensitive headers
such as `Authorization`, `Cookie`, and `X-Api-Key` are still rejected over
plaintext HTTP unless `allowInsecureHttpHeaders: true` is also set.
Curl-based downloads use bounded transfer timing by default (`connectTimeout:
10000`, `timeout: 300000`, both in milliseconds). Override these options for
very slow artifact hosts or large downloads.

### `file`

| Method            | Signature                                                                                                           | Idempotent          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `file.absent`     | `(remotePath: string): Module`                                                                                      | Yes                 |
| `file.assemble`   | `(remotePath: string, fragments: string[], options?: { mode?: string; owner?: string }): Module`                    | Yes                 |
| `file.block`      | `(remotePath: string, options: { content: string; name: string; prefix?: string }): Module`                         | Yes                 |
| `file.chmod`      | `(remotePath: string, mode: string): Module`                                                                        | Yes                 |
| `file.chown`      | `(remotePath: string, owner: string): Module`                                                                       | Yes                 |
| `file.copy`       | `(remotePath: string, localPath: string, options?: { mode?: string; owner?: string }): Module`                      | Yes                 |
| `file.directory`  | `(remotePath: string, options?: { mode?: string; owner?: string }): Module`                                         | Yes                 |
| `file.line`       | `(remotePath: string, line: string, options?: { match?: string }): Module`                                          | Yes                 |
| `file.properties` | `(remotePath: string, options: { group?: string; mode?: string; owner?: string }): Module`                          | Yes                 |
| `file.replace`    | `(remotePath: string, pattern: string, replacement: string): Module`                                                | Yes                 |
| `file.stat`       | `(remotePath: string): Module`                                                                                      | No (always-applies) |
| `file.template`   | `(remotePath: string, templatePath: string, options?: { mode?: string; owner?: string; strict?: boolean }): Module` | Yes                 |

**Note on `owner` and `group` values:** Every ownership option accepts either a POSIX name or a
numeric id — `owner: "www-data:www-data"` and `owner: "65532:65532"` are both valid, and the two
components may be mixed (`owner: "root:65532"`). Numeric ids are the only option for accounts that
have no passwd or group entry on the target host, such as `65532` in distroless images or `70` in
the postgres image. Drift detection compares the declared value against both the name and the id
reported by the host, so a numerically declared owner converges to `status: "ok"` like a named one.
`file.properties` keeps `owner` and `group` as separate options and therefore rejects a combined
`"user:group"` spec.

**Note on `file.copy` and the default mode:** When `options.mode` is omitted, `file.copy` sets the mode to the documented default of `0644`. The mode is applied during upload (`uploadFile` with `{ mode }`) and compared with the desired value in `check`, so subsequent runs detect mode drift (for example, a manual `chmod 0600`) as `needs-apply`. Pass `{ mode: "0600" }` explicitly when more restrictive permissions are required, such as for secrets.

**Note on `file.line`:** The `line` value must be a single line without CR/LF characters. Use `file.block` for multiline content.

### `git`

| Method      | Signature                                                                 | Idempotent |
| ----------- | ------------------------------------------------------------------------- | ---------- |
| `git.clone` | `(repo: string, destination: string, options?: { ref?: string }): Module` | Yes        |

### `group`

| Method          | Signature                                            | Idempotent |
| --------------- | ---------------------------------------------------- | ---------- |
| `group.present` | `(name: string, options?: { gid?: number }): Module` | Yes        |
| `group.absent`  | `(name: string): Module`                             | Yes        |

### `hostname`

| Method         | Signature                | Idempotent |
| -------------- | ------------------------ | ---------- |
| `hostname.set` | `(name: string): Module` | Yes        |

### `mount`

| Method          | Signature                                                                                           | Idempotent             |
| --------------- | --------------------------------------------------------------------------------------------------- | ---------------------- |
| `mount.present` | `(options: { fstype: string; opts: string; path: string; persist?: boolean; src: string }): Module` | Yes (incl. bind/rbind) |
| `mount.absent`  | `(options: { path: string; persist?: boolean }): Module`                                            | Yes                    |

**Note on bind mounts:** `mount.present` is idempotent for bind mounts (`opts`
contains `bind` or `rbind`; use `fstype: "none"`). `src` must be an absolute,
normalized directory path that is not below `path`. A bind counts as converged
when the top-most mount at `path` has the `MAJ:MIN` and FSROOT of the resolved
source, so a correctly bound target is never unmounted, even while in use. Only
the VFS flags written explicitly in `opts` (`ro`/`rw`, `nosuid`/`suid`,
`nodev`/`dev`, `noexec`/`exec`, `noatime`/`relatime`/`strictatime`,
`nodiratime`, `nosymfollow`) are enforced; unnamed flags are inherited from the
source mount. Flag drift is fixed with `mount -o remount,bind,<flags>` without an
unmount; the remount names the complete resulting VFS flag state, so unnamed
flags keep their live value. `rbind` submounts are not verified. When the bind source lives on a
`_netdev` mount, add `_netdev` (and optionally `nofail`) to the bind's `opts`.

### `net`

| Method          | Signature                                                                                                                                                                                               | Idempotent |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `net.hosts`     | `(ip: string, hostnames: string[], options?: { state?: "absent" \| "present" }): Module`                                                                                                                | Yes        |
| `net.interface` | `(name: string, options: { addresses?: string[]; dhcp?: boolean; gateway?: string; nameservers?: string[] }): Module`                                                                                   | Yes        |
| `net.request`   | `(url: string, options?: { allowInsecureHttpHeaders?: boolean; body?: string; connectTimeout?: number; headers?: Record<string, string>; method?: string; status?: number; timeout?: number }): Module` | Yes        |
| `net.resolv`    | `(options: { nameservers: string[]; search?: string[] }): Module`                                                                                                                                       | Yes        |
| `net.route`     | `(destination: string, gateway: string, options?: { device?: string; state?: "absent" \| "present" }): Module`                                                                                          | Yes        |
| `net.waitFor`   | `(options: { contains?: string; file?: string; host?: string; interval?: number; port?: number; timeout?: number }): Module`                                                                            | Yes        |

`net.request` uses bounded curl timing by default (`connectTimeout: 10000`,
`timeout: 300000`, both in milliseconds). Override these values for endpoints
that are expected to respond more slowly.

### `op`

| Method       | Signature                                      | Idempotent                        |
| ------------ | ---------------------------------------------- | --------------------------------- |
| `op.resolve` | `(references: Record<string, string>): Module` | No (always-applies, runs locally) |

Inside a `runPlaybook` run, every `op.resolve` reference in the definition
is read up front, before the SSH connect: all `op read` calls (and any
provider prompt they trigger, e.g. a biometric unlock or `op signin`) happen
once, right after the command starts, instead of somewhere in the middle of
the run at the module's own position. The module still runs at its position
in `run` and emits the same meta as before -- it just serves the value from
that up-front resolution instead of invoking `op` again. A failure during
this phase aborts the whole run before any connection is opened, with exit
code 2, instead of surfacing as a failed module later on. This phase also
runs during `--dry-run`, and `--filter` prints a warning (without changing
run behavior) when it removes a module that would have resolved secrets.
References ending in `/otp` or `/one-time-password` read their seed early and emit a lazy
code resolver. After environment meta is merged, the first successful code is memoized by the
normal meta policy; later consumers reuse it. An unmarked OTP-code attribute is an ordinary
early cached string. For a new code per independent access, use [`secret.totp(...)`](#secret).
Existing playbooks need no migration.

This up-front timing does not change what `op.resolve()` can feed into
`SshConfig` -- see [Anti-Pattern 16](#dos-and-donts) below.

### `package`

Import with renaming: `import { package as pkg } from "paratix/modules"`. The word `package` is reserved in JavaScript, so you must alias it.

| Method              | Signature                                                                         | Idempotent       |
| ------------------- | --------------------------------------------------------------------------------- | ---------------- |
| `package.installed` | `(...packagesAndOptions: Array<string \| PackageSpec \| UpgradeOptions>): Module` | Yes              |
| `package.absent`    | `(...packagesAndOptions: Array<string \| PackageSpec \| AbsentOptions>): Module`  | Yes              |
| `package.update`    | `(date: string, options?: UpgradeOptions): Module`                                | Yes (dated flag) |
| `package.upgrade`   | `(date: string, options?: UpgradeOptions): Module`                                | Yes (dated flag) |

#### `UpgradeOptions`

```typescript
type UpgradeOptions = {
  timeout?: number // Override SSH command timeout (ms). Same value applies to every step
  // of multi-step pipelines (apt upgrade, apk upgrade, apt dist-upgrade).
}
```

For `package.installed` and `package.absent`, pass the options object as the **last** argument after
the package names. Existing variadic calls such as `pkg.installed("git", "curl")` continue to work
unchanged. Use a higher `timeout` for slow operations on production servers with a large update
backlog:

```typescript
pkg.upgrade("2026-05-01", { timeout: 900_000 })
pkg.installed("texlive-full", { timeout: 900_000 })
apt.distUpgrade("2026-05-01", { timeout: 1_200_000 })
```

#### `AbsentOptions` — Purge

```typescript
type AbsentOptions = UpgradeOptions & {
  purge?: boolean // apt: purge (remove incl. configuration files) instead of remove
}
```

`package.absent` accepts `AbsentOptions` as its last argument; `purge` is not available on
`package.installed`, `package.update` or `package.upgrade`.

```typescript
pkg.absent("docker-ce", "containerd.io", { purge: true })
```

With `purge: true`:

- **apt** runs `DEBIAN_FRONTEND=noninteractive apt-get purge -y -- …`, which also deletes the
  packages' configuration files. A package counts as absent only when dpkg knows no remnant of it:
  `installed`, `rc` (`config-files`) and intermediate states such as `half-installed` or `unpacked`
  are purged; `not-installed` entries and names dpkg does not know are absent. Every name is queried
  across all architectures, and exactly the dpkg-reported identifiers (bare `name` or `name:arch`)
  are passed to `apt-get purge`. Unknown names are skipped, so a package whose source was already
  removed does not fail the run, and a foreign-architecture remnant is purged too.
- **`check`** (and therefore `--dry-run`) uses the same detection: an `rc` package reports
  `needs-apply`, and a second run after the purge reports `ok`.
- **Reverse dependencies:** like `remove`, `apt-get purge` also removes packages that depend on the
  named ones and purges their configuration files, even when they are not named. Purging
  `containerd.io` removes `docker-ce`.
- **No `autoremove`:** dependencies that are no longer needed stay installed.
- **apk, dnf, yum:** `purge: true` maps to the normal remove (same command, same detection). rpm may
  still leave modified configuration files behind as `*.rpmsave`.
- **`timeout`** applies to the `apt-get purge` call only, not to the dpkg status queries.
- **Guards:** `when.packageAbsent` (and `when.packageInstalled`) treat a package in the `rc` state
  as absent, so a guard such as
  `when.packageInstalled("docker-ce", pkg.absent("docker-ce", { purge: true }))` skips the purge
  once only remnants are left. Run the purge unguarded; it is idempotent on its own.
- A non-boolean `purge` (including `null`) throws at construction:
  `package.absent: purge must be a boolean`.

Without `purge` (or with `purge: false`) the command, detection and result are unchanged.

#### `PackageSpec` — Version Pinning

```typescript
type PackageSpec = {
  name: string
  version?: string // Exact target version. Without `version`, only presence is enforced.
}
```

Pin a package to an exact version by passing a `PackageSpec` object instead of a string. A plain
`"grafana"` string is equivalent to `{ name: "grafana" }` without a pin. Package-manager-specific
syntax such as `name=version` or `name-version` is **not** accepted as a pass-through string; a
string containing `=` remains an invalid package name. Arguments are distinguished by their
**shape**, not their position: an object **with** a `name` field is a `PackageSpec` and may also be
the last argument, while a final object **without** a `name` field is `UpgradeOptions`.

```typescript
pkg.installed({ name: "grafana", version: "13.1.0" })
pkg.installed("curl", { name: "grafana", version: "13.1.0" }, { timeout: 600_000 })
```

Installation token by package manager:

| Package manager | Installation token | Example                |
| --------------- | ------------------ | ---------------------- |
| apt             | `name=version`     | `grafana=13.1.0`       |
| apk             | `name=version`     | `grafana=13.1.0-r0`    |
| dnf / yum       | `name-version`     | `grafana-13.1.0-1.el9` |

Semantics:

- **`check`** compares the installed version with the pinned version; any mismatch returns
  `needs-apply`. Without a pinned version, it remains a presence check.
- **`apply`** installs exactly the pinned version, including a **downgrade**. For apt, a pinned
  version automatically adds `--allow-downgrades`. If dnf/yum finds a newer installed version, it
  uses `dnf downgrade` or `yum downgrade` instead of `install` (apk installs the exact version in
  either direction without an extra flag). The dnf/yum direction check uses a version-aware
  comparison on the target host (`sort -V`) so multi-digit components such as `13.9.0` and
  `13.10.0` are ordered correctly.
- After installation, Paratix verifies the installed version. A partial or incorrect version
  reports `failed`, not `changed`.
- **No hold.** Paratix only installs the version; it creates no `apt-mark hold` marker or
  `preferences.d` file. A later `apt upgrade` can therefore upgrade the package again unless the
  pinned playbook runs again.

Valid versions start with an alphanumeric character and may contain `[A-Za-z0-9]` plus
`. + ~ : _ -`. This covers apt epoch/revision values such as `1:2.3-1ubuntu0.2` and RPM
`version-release` values such as `13.1.0-1.el9`. Whitespace and shell metacharacters are rejected.
`package.absent` is name-based; passing a `PackageSpec` with `version` produces a clear error.

### `podman`

Use `podman.login` to maintain persistent credentials for one direct registry entry and
`podman.logout` to remove it. `podman`, `PodmanLoginOptions`, and `PodmanOptions` are public
from both entry points.

| Method          | Signature                                             | Idempotent                                         |
| --------------- | ----------------------------------------------------- | -------------------------------------------------- |
| `podman.login`  | `(options: PodmanLoginOptions): Module`               | Yes, compares local credentials and auth-file mode |
| `podman.logout` | `(registry: string, options?: PodmanOptions): Module` | Yes, checks whether the direct entry exists        |

#### Runtime and helper image

The target must run native Linux Podman with Paratix's existing effective-root SSH execution.
Changing `authFile` does not select another user. Rootless execution is unsupported. Host Python
is not required: a short-lived file helper runs Python 3.15.0 inside the pinned upstream image.
Host Podman performs login/logout using its own registry, CA, and transport configuration.
The native fixture pins Ubuntu 24.04 package `podman=4.9.3+ds1-1ubuntu0.2` (Podman 4.9.3),
including its `--compat-auth-file` behavior. This is the tested fixture, not a compatibility
promise for every Podman version or platform. SELinux Enforcing is unsupported in V1; the
module refuses it before auth mutation. It does not change host policy or recursively relabel files.

Before using the module, explicitly preload this public image **on the target in the same
rootful Podman store**:

```bash
sudo podman pull docker.io/library/python@sha256:db3231d3fce4c59182f8364dbec08b8bad4fdfca673dfb226f3c9e77b6b48cd2
```

A rootless pull does not satisfy this prerequisite. Every helper start uses `--pull=never`;
check and apply never pull or install anything. A missing image is an error. `helperImage` may
select a trusted equivalent mirror, but must be fully qualified and pinned by SHA-256 digest.
The image needs the compatible Python standard library and `python3` entry point. Treat its
contents as trusted: it can read all credentials in the explicitly mounted directories.

#### Options and credential sources

| Option                         | Contract                                                                                                                                                                                                                             |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `registry`                     | Required for login; positional for logout. DNS hostname, IPv4, or `localhost`, optionally with port 1–65535. No scheme, path, userinfo, IPv6, or whitespace. Hostnames become lowercase; Docker Hub host aliases become `docker.io`. |
| `username` / `usernameEnv`     | Exactly one. A fixed username or a Paratix environment binding name. Username must be a nonempty string without colon, whitespace, or control characters, at most 64 KiB in UTF-8.                                                   |
| `passwordFile` / `passwordEnv` | Exactly one for login. A token file or a Paratix environment binding name. There is no plaintext `password` option. Logout needs neither source.                                                                                     |
| `passwordFileLocation`         | Only with `passwordFile`: `"controller"` (default) or `"target"`. Forbidden with `passwordEnv`.                                                                                                                                      |
| `authFile`                     | Persistent target auth JSON, default `/root/.config/containers/auth.json`. Pass the same explicit path to consumers such as `quadlet.updateImage`.                                                                                   |
| `helperImage`                  | Optional fully qualified digest-pinned replacement for the image above. Default is the exact reference in the preload command.                                                                                                       |

Username and token sources are independent: a fixed username plus a manually entered token,
or `usernameEnv` plus `passwordFile`, are supported. Binding names follow the [`secret`](#secret)
facade rules, including dotted names. They are keys, not `op://` references, resolved values, or
OS environment exports. The consumer reads them sequentially through `resolveEnvironment`;
there is no `process.env` or alternate-source fallback. Missing keys, non-string values, empty
values, and invalid credentials fail without echoing their contents.

Tokens must be nonempty single-line UTF-8 strings, at most **65,535 bytes (64 KiB − 1)**,
without control characters or leading/trailing whitespace. This is the tested
`--password-stdin` scanner limit of the supported Podman 4.9.3 fixture, within the module's
64 KiB safety ceiling. A 65,536-byte token is rejected before auth mutation for every credential
source. Provider values are used unchanged and rejected if invalid. Only the file path removes
one optional final LF or CRLF before validating the token length. A token file must be a regular
non-symlink file with mode **exactly `0400`**, owned by the effective controller UID for a
controller file or root for a target file. Target token files also require a single hard link
and must differ from the auth file by path and file identity. Check and apply each read the
selected file again; no credential value is cached in the module object.

#### Use 1Password or manual input before an image update

This example assumes the matching `app` Quadlet unit already exists. Replace the example host,
image, and vault references with your configuration. Install and authenticate the `op` CLI
on the controller for 1Password; the target and helper need no 1Password access.

```typescript
import { server } from "paratix"
import { podman, quadlet, secret } from "paratix/modules"
import type { SecretResolver } from "paratix/modules"

const secrets: SecretResolver = secret.provider("1password")
const authFile = "/root/.config/containers/auth.json"

export default server({
  name: "app-host",
  host: "server.example",
  ssh: { user: "root", ports: [22] },
  run: [
    secrets.resolve({
      REGISTRY_USERNAME: "op://prod/registry/username",
      REGISTRY_TOKEN: "op://prod/registry/token",
    }),
    podman.login({
      registry: "registry.example",
      usernameEnv: "REGISTRY_USERNAME",
      passwordEnv: "REGISTRY_TOKEN",
      authFile,
    }),
    quadlet.updateImage({ name: "app", image: "registry.example/app:latest", authFile }),
  ],
})
```

For hidden manual input, replace only the resolver above; the same bindings and consumer work:

```typescript
const secrets: SecretResolver = secret.provider("manual", {
  labels: { REGISTRY_USERNAME: "Registry username", REGISTRY_TOKEN: "Registry token" },
})
```

For a known username, replace the resolver and login pair with this `run` array:

```typescript
const run = [
  secret.provider("manual", { labels: { REGISTRY_TOKEN: "Registry token" } }).resolve({
    REGISTRY_TOKEN: "",
  }),
  podman.login({
    registry: "registry.example",
    username: "deployment",
    passwordEnv: "REGISTRY_TOKEN",
    authFile,
  }),
]
```

`SecretResolver.resolve(...)` must precede the consumer in `run`. Ordinary provider bindings
are prewarmed before SSH, including in `--dry-run`, even if login later reports `ok`. Their
values are reused across check/apply in that run; a new run reads again and detects rotation.
Filtering out the resolver can leave the consumer without its binding and causes a safe
failure. Manual input keeps the existing TTY, hidden-input, cancellation, and run-cache rules
in [`secret`](#secret). The environment path reads/writes no credential file on the controller;
credentials travel only in SSH stdin. Private transaction files still exist on the target.

#### File alternatives and logout

After provisioning a controller-owned `0400` token file, use:

```typescript
podman.login({
  registry: "registry.example",
  username: "deployment",
  passwordFile: "/private/registry/token",
  authFile,
})
```

For a root-owned `0400` token already on the target, add `passwordFileLocation: "target"`
and use its absolute target path:

```typescript
podman.login({
  registry: "registry.example",
  username: "deployment",
  passwordFile: "/root/registry-token/token",
  passwordFileLocation: "target",
  authFile,
})
```

Its token stays on the target, including during check; it is never downloaded or sent through
SSH stdin. Remove the complete direct entry without credentials using
`podman.logout("registry.example", { authFile })`.

#### Filesystem, state, and failure boundaries

- Target auth and token files must be in dedicated directories. Parent-directory bind mounts
  allow atomic replacement, so do not place unrelated sensitive files there. Broad parents
  such as `/`, `/etc`, `/root`, `/home/<user>`, and `/var/lib` are rejected. Paths are absolute,
  normalized, at most 512 characters, and contain only ASCII letters/digits, `_`, `.`, `/`,
  and `-`; no spaces, `.`/`..` segments, colons, commas, or control characters.
- Existing target ancestors must be root-owned directories without symlinks or group/other
  write permission. Existing safe modes such as `0755` remain unchanged. Apply creates missing
  auth directories as `0700` and publishes auth files as `0600`; check does not create auth
  directories. Auth leaves must be regular, root-owned, non-symlink files with one hard link.
- The helper uses no network, socket, or privileged mode; it runs as `0:0` with host user
  namespace, read-only rootfs, no writable rootfs tmpfs, all capabilities dropped,
  `no-new-privileges`, disabled container logging, and `label=disable`. Only required auth,
  target-token, and private work directories are mounted, with read-only mounts where possible.
  Host commands resolve through the existing SSH execution `PATH`; the module does not sanitize
  it or pin executable paths. Trust the target's executables, configuration, and helper image.
- Login is `ok` when the local encoded credentials and mode `0600` match. It does not contact
  the registry during check, so server-side revocation alone does not trigger another login.
  Credential or mode drift needs apply; mode-only repair does not run a network login.
  Logout is `ok` for a missing file or entry without running host logout. A missing auth file
  allows logout without the helper image, subject to the identity/path/SELinux preflight.
- Paratix owns the **whole addressed registry object**: a credential update replaces it and
  logout removes it, including unknown fields inside it. JSON values outside that object,
  including other registries and unknown top-level fields, are preserved semantically;
  formatting and key order may change. Malformed/empty JSON, duplicate keys, invalid base64,
  relevant identity-token/credential-helper settings, global credential stores, and legacy
  alias/URL entries are refused without automatic repair. Existing auth JSON and the published
  candidate are each limited to **8 MiB**. JSON serialization can expand Unicode values into
  ASCII escape sequences; any candidate that exceeds 8 MiB is refused before publication,
  preserving the original file byte for byte. Private transaction state has a separate, larger
  derived bound that accounts for the base64-encoded original plus expected credentials and
  metadata; compat results have their own bounded read. The 8 MiB auth-file read limit is not
  applied to those private files. Every published candidate remains within that auth read limit.
- Apply prepares a root-private target transaction and gives host Podman only a private compat
  file without foreign credentials or helper mappings. Login uses `--password-stdin` with TLS
  verification enabled. External credential-helper store/erase operations are excluded by the
  compat edit path; host configuration can still cause helper get operations. The checked
  result is merged and published by atomic replacement after a conflict check.
- Ensure exclusive writing to the auth file during apply. Observed content/identity/metadata
  changes cause a conflict failure; this is not a compare-and-swap guarantee against an
  uncooperative root writer in the final rename window. Privileged path/mount replacement is
  outside the trust boundary. Ordinary pre-publication failures preserve the original file.
- Normal completion cleans up owned work files and containers; abrupt host/process loss may
  leave protected files. An interrupted transport or post-publication failure reports unknown
  completion: the change may already be applied. Inspect target state before deciding to rerun.
  There is no automatic retry or snapshot rollback and no diff containing auth contents.
- Resolved usernames and tokens, including short values, are explicitly masked in module output
  and errors. Raw helper/host output is discarded on the target before SSH; only fixed exit
  statuses cross that boundary. The username is nevertheless visible in the actual host
  Podman process argv because its CLI requires `--username`. The token is never passed in argv.
  Neither value is interpolated into the controller-built SSH/helper command text. Custom logs
  and unrelated consumers retain the general masking limits documented under [`secret`](#secret).

`quadlet.updateImage` supports this auth file explicitly. A Compose provider must itself be
configured to use the matching credentials; `podman.login` makes no blanket Compose-provider
compatibility promise.

#### Native integration validation

The existing integration command is `pnpm --filter paratix test:integration`. Docker remains
required for the existing SSH/SFTP fixture. Native Podman cases additionally use an isolated
Linux SSH target, passwordless effective-root sudo, a preloaded helper, and a dedicated
root-owned test directory. Never point these tests at production auth data. The controller
needs `openssl` for the synthetic HTTPS registry and the target must permit loopback remote
SSH forwarding for it.

Set `PARATIX_PODMAN_HOST`, `PARATIX_PODMAN_PORT`, `PARATIX_PODMAN_USER`,
`PARATIX_PODMAN_PRIVATE_KEY` (controller path), `PARATIX_PODMAN_EXPECTED_VERSION`, and
`PARATIX_PODMAN_TEST_ROOT` for an explicitly provisioned local test target. Also set
`PARATIX_PODMAN_HOST_PUBLIC_KEY` to pin its SSH host key; without it the local harness disables
strict host-key checking. `PARATIX_PODMAN_HELPER_IMAGE` optionally overrides the pinned image;
`PARATIX_PODMAN_REQUIRE_NO_HOST_PYTHON=1` asserts that host Python is absent. Without a configured
target these cases skip locally; in CI missing configuration fails.

The existing Ubuntu integration and publish-validation jobs invoke
`bash scripts/runPodmanIntegration.sh pnpm agent:check:integration`. This wrapper installs the
exact Podman fixture package and SSH prerequisites, preloads the helper, starts an owned
loopback SSH fixture, verifies effective root and a real restricted helper start, and removes
its temporary user, service, keys, sudo rule, and test files after the supplied command.
It does not expand release/deployment permissions.

### `quadlet`

| Method                | Signature                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Idempotent |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `quadlet.container`   | `(options: { addCapability?: string[]; addDevice?: string[]; annotation?: Record<string, string>; autoUpdate?: "local" \| "registry"; containerName?: string; description?: string; dns?: string[]; dnsOption?: string[]; dnsSearch?: string[]; dropCapability?: string[]; entrypoint?: string[]; environment?: Record<string, string>; environmentFiles?: string[]; exec?: string[]; exposeHostPort?: string[]; groupAdd?: string[]; healthCmd?: string; healthInterval?: string; healthOnFailure?: "kill" \| "none" \| "restart" \| "stop"; healthRetries?: number; healthStartPeriod?: string; healthTimeout?: string; hostName?: string; image: string; ip?: string; ip6?: string; label?: Record<string, string>; logDriver?: string; mask?: string[]; mount?: string[]; name: string; networks?: string[]; noNewPrivileges?: boolean; notify?: boolean; podmanArgs?: string[]; publishPorts?: string[]; pull?: "always" \| "missing" \| "never" \| "newer"; readOnly?: boolean; restart?: "always" \| "no" \| "on-abnormal" \| "on-abort" \| "on-failure" \| "on-success" \| "on-watchdog"; runInit?: boolean; secret?: string[]; seccompProfile?: string; securityLabelDisable?: boolean; securityLabelType?: string; stopTimeout?: number; sysctl?: Record<string, string>; timeoutStartSec?: number; timeoutStopSec?: number; timezone?: string; tmpfs?: string[]; ulimit?: string[]; unmask?: string[]; user?: string; userNs?: string; volumes?: string[]; wantedBy?: string; workingDir?: string }): Module` | Yes        |
| `quadlet.network`     | `(options: { description?: string; disableDns?: boolean; dns?: string[]; driver?: string; gateway?: string; internal?: boolean; ipRange?: string; ipamDriver?: string; ipv6?: boolean; label?: Record<string, string>; name: string; options?: Record<string, string>; podmanArgs?: string[]; subnet?: string }): Module` — writes `/etc/containers/systemd/<name>.network`; reference it from a container via `networks: ["<name>.network"]`. When the change lands and a network with the same name is already live, `changed` carries an advisory detail that the running network is not recreated until removed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Yes        |
| `quadlet.updateImage` | `(options: { authFile?: string; containerName?: string; image: string; name: string; serviceName?: string }): Module` — returns `changed` with the new registry digest (or local image ID fallback) in parentheses when a newer image was pulled. Fails before pulling when a container of the managed name is owned by something other than this unit (see [Quadlet conflict guard](#quadlet-conflict-guard))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Partial    |

### `releaseUpgrade`

| Method                   | Signature                                                                                                                                            | Idempotent |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `releaseUpgrade.upgrade` | `(options?: { dryRun?: boolean; resolveHost?: (signal?: AbortSignal) => Promise<string>; resolveHostTimeoutMs?: number; timeout?: number }): Module` | Yes        |

### `rsync`

| Method       | Signature                                                                                                                                                                                                                                      | Idempotent |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `rsync.sync` | `(options: { src: string; dest: string; chmod?: string; delete?: boolean; exclude?: string[]; group?: string; include?: string[]; owner?: string; strictHostKeyChecking?: "accept-new" \| "no" \| "off" \| "yes"; timeout?: number }): Module` | Yes        |

`rsync.sync()` requires the active session's verified raw key **and** typed verification evidence;
it refuses an unverified or inconsistent session. Before each external SSH transfer it reads a
fresh snapshot of the controller's `~/.ssh/known_hosts` through the same asynchronous, locked
loader. For certificate sessions, a read failure or newly revoked session leaf/CA fails closed.
Matching revocations for alternative leaves are also carried into the CA path. This is a
preflight snapshot, not monitoring of later file changes.

- A raw-key session reuses its verified host key as the sole anchor.
- A certificate session **without explicit pins** uses only a host/port-scoped
  `@cert-authority` anchor for the CA accepted by the controller, plus matching revocations.
  OpenSSH validates its current certificate and may accept a different, non-revoked leaf under
  that CA. CA trust does not preserve the previous leaf's identity.
- A certificate session **with either explicit pin** uses only the verified raw leaf as anchor
  and offers only the corresponding raw-key algorithm. RSA uses `rsa-sha2-512,rsa-sha2-256`,
  without adding `ssh-rsa`. This preserves the leaf pin but checks no certificate or current CA
  validity on the new connection. A different leaf or certificate-only server fails. There is
  no automatic retry, downgrade or combined CA/raw-key anchor.

All paths use a private temporary Known-Hosts file, isolated user/global trust files and fixed
`StrictHostKeyChecking=yes`, `KnownHostsCommand=none`, `VerifyHostKeyDNS=no`. Inherited command
anchors and DNS SSHFP cannot replace the chosen anchor; `strictHostKeyChecking` on the module
cannot weaken the policy. Temporary files are cleaned up after success or failure.

After successful file-key authentication with `ssh.certificate`, rsync also passes the expanded,
shell-quoted certificate path as `-o CertificateFile=...` alongside the matching private key.
Agent and password sessions do not set `CertificateFile`, including sessions using an agent-held
certificate.

### `script`

| Method        | Signature                                                                                    | Idempotent           |
| ------------- | -------------------------------------------------------------------------------------------- | -------------------- |
| `script.once` | `(name: string, localPath: string, options?: { args?: string[]; version?: string }): Module` | Yes (versioned flag) |

### `secret`

Use this local facade to keep the same consumer bindings with manual input or 1Password.
`secret` and its public types are available from both `paratix/modules` and `paratix`.

| Method             | Signature                                                                                                                          | Behavior                                                                                                                           |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `secret.provider`  | `(name: "1password"): DeferredSecretResolver` or `(name: "manual", options?: ManualSecretProviderOptions): DeferredSecretResolver` | Creates an immutable facade without I/O or a global provider change. A `SecretProvider` variable is also accepted without options. |
| `secrets.deferred` | `(reference: string): SecretHandle`                                                                                                | Creates an opaque provider-bound signer credential without I/O or environment metadata.                                            |
| `secrets.resolve`  | `(bindings: Readonly<Record<string, SecretInput>>): Module`                                                                        | Creates a local module; `check` always returns `NEEDS_APPLY`, and `apply` emits environment meta.                                  |
| `secret.totp`      | `(reference: string): SecretTotpInput`                                                                                             | Creates a frozen `{ kind: "totp", reference }` descriptor without I/O; requests a current code at actual use.                      |

`SecretProvider` is `"1password" | "manual"`. `SecretInput` is `string | SecretTotpInput`.
`ManualSecretProviderOptions` accepts `labels?: Readonly<Record<string, string>>`.
Use `SecretResolver` to pass the configured facade into a recipe or module builder:

```typescript
import { secret } from "paratix/modules"
import type { Module } from "paratix"
import type { ManualSecretProviderOptions, SecretResolver } from "paratix/modules"

const manualOptions: ManualSecretProviderOptions = {
  labels: { DB_PASSWORD: "Database password", MFA_CODE: "Current login code" },
}
const manualSecrets = secret.provider("manual", manualOptions)
const vaultSecrets = secret.provider("1password")

function loginSecrets(secrets: SecretResolver): Module {
  return secrets.resolve({
    DB_PASSWORD: "op://prod/database/password",
    MFA_CODE: secret.totp("op://prod/login/one-time-password"),
  })
}

const manualModule = loginSecrets(manualSecrets)
const vaultModule = loginSecrets(vaultSecrets)
```

Choose one configured module for `run` before its consumers. The binding keys are environment
names; reference strings identify sources, never resolved secret values. The facade passes them
unchanged to the selected provider. Manual accepts the same `op://` strings as opaque identities,
without reading or displaying them. Its prompt uses a configured label or the environment name.
For manual-only bindings, `secrets.resolve({ DB_PASSWORD: "", MFA_CODE: secret.totp("") })`
is valid. Manual asks for the current code, never a seed. Maps, options, and descriptor fields are
copied when configuring the facade/module. Empty binding maps, invalid names, malformed inputs,
and unsupported providers/options fail synchronously before secret I/O.

**Early secrets and late codes:** In `runPlaybook`, ordinary secrets and marked 1Password seed
fields are read before SSH, including during `--dry-run`, inside recipes and signals, and in
`when(...)` branches whose condition may later be false. Prewarm fills the run cache; environment
meta becomes available only when the secret module reaches its position. A prewarm failure
aborts before SSH. Identical ordinary manual bindings share one read per facade, name, exact
reference, and run; different facades, references, or runs remain separate. Early 1Password reads
share the exact reference string as their cache key across this facade and `op.resolve`.

A marked code is never materialized by facade construction, prewarm, module `apply`, or a meta
merge. Only a consumer's `await resolveEnvironment(env, "MFA_CODE")` or a used template placeholder
resolves it. An unused key or skipped consumer does not ask for a code. Each independent access
after completion resolves again, including separate accesses in `check` and `apply`, and a
check during `--dry-run`. A fresh calculation can still produce the same digits within a TOTP
time window. Manual does not know the remaining lifetime of an entered code. Resolve immediately
before use and retain the result locally if one operation needs it more than once.

| Marked 1Password reference                                             | Resolution                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Field without an attribute, or with `?attribute=value` / `?attr=value` | Read and validate the stored `otpauth://totp/...` seed early; calculate the current code locally at use. Free field names and field IDs work.                                                                                    |
| Field with `?attribute=otp` / `?attr=otp`                              | Read the exact reference through `op read` at each independent use; bypass the run cache, even if an unmarked binding read the same reference earlier. This can trigger later 1Password authentication or biometric interaction. |

1Password requires an installed, authenticated `op` CLI on the controller. Marked references
reject competing attribute selectors and attributes other than `value` or `otp` before I/O.
The original reference is not rewritten. Base field reads remove only the CLI's final newline;
seed trimming/validation happens after cache lookup, so ordinary and seed consumers can share
a read without changing each other's value. Unmarked strings retain the legacy suffix and
memoization behavior documented under [`op`](#op); use the explicit marker for late codes.

**Environment and templates:** Marked entries carry `resolution: "per-access"`. Concurrent
accesses to the same merged environment resolver share only its pending promise; success and
failure both clear it. Separate applies/runs get separate resolvers. Meta merges, recipes,
signals, and the environment-to-meta helpers preserve this policy. Other meta entries keep the
existing successful-result memoization. Direct calls to separate raw meta resolvers have no
shared-promise guarantee. Templates with marked keys validate names/modifiers and fully process
ordinary placeholders, including fallible modifiers, before reading codes. Different marked
keys resolve sequentially, and duplicate marked placeholders share one value for that render.

**Terminal and failure boundaries:** Manual input requires TTYs on both stdin and stderr;
redirecting stdout is allowed. Typing and pasting show neither characters nor asterisks. Unicode,
backspace, whitespace, and empty input are accepted without trimming. `Ctrl+C`, EOF, or the
runner's abort signal closes the prompt. Concurrent manual prompts in one process are rejected;
there is no prompt queue. Custom consumers must await different interactive keys sequentially.
A rejected `Promise.all` does not cancel other prompts it already started: consumer-owned
parallelism must arrange cancellation and await every resolver it starts. A late code failure
stops its consumer and does not roll back earlier connections or changes.

`--filter` removes excluded secret modules before resolution. Removed early-secret carriers
produce the existing warning; code-only modules have no prewarm hook or such warning. A consumer
of a filtered-out key fails with a missing environment value unless another source supplies it.

**Masking:** Hidden input is independent of length. Provider/resolver errors explicitly mask
known values, including short codes. The global registered-secret sink accepts only strings of
at least eight characters, so typical six-digit codes and other shorter values have no general
masking guarantee in later modules, diffs, or custom logs. Never log secrets yourself.

This facade supplies downstream modules and recipes. It cannot supply initial SSH credentials
or `ssh.sudoPassword`, because `SshConfig` is constructed before prewarm; see
[Anti-Pattern 16](#dos-and-donts). Existing `op.resolve` consumers remain supported without migration.

#### Deferred signer credentials

`secret.provider(...)` returns `DeferredSecretResolver`, which extends the existing injectable
`SecretResolver` with `deferred(reference: string): SecretHandle`. Existing implementations of
`SecretResolver` need only `resolve(...)` and remain valid. A nonempty reference creates a frozen,
opaque handle bound to that exact provider instance and reference. Neither its creation nor
import starts provider I/O; no module, environment meta, or `_prewarmSecrets` hook is registered.

Use the handle as `ssh.signer.stepCa`'s password. The host-certificate module resolves it only
when a real apply reconfirms signing need. Check, dry-run, and a matching certificate use no
signer credential. Ordinary `.resolve(...)` modules retain their early-secret behavior above.
Deferred references use ordinary credential semantics, without TOTP suffix conversion or provider
inference. `secret.provider("manual")` prompts only at actual need with the safe consumer label
“SSH certificate signer”; it does not display the raw reference or use its ordinary binding labels.

Handles contain no decrypted values or resolution promises. Run-scoped deduplication and masking
end with that run; the next run cannot reuse a cached credential. Inspect/string output is
redacted and JSON serialization throws. Copies, forged handles, and reconstructed objects are
rejected without a raw-string fallback. `SecretHandle` and `DeferredSecretResolver` are exported
from both public entry points.

### `service`

| Method             | Signature                | Idempotent                                                |
| ------------------ | ------------------------ | --------------------------------------------------------- |
| `service.running`  | `(name: string): Module` | Yes                                                       |
| `service.stopped`  | `(name: string): Module` | Yes                                                       |
| `service.enabled`  | `(name: string): Module` | Yes                                                       |
| `service.disabled` | `(name: string): Module` | Yes                                                       |
| `service.restart`  | `(name: string): Module` | No (always-applies, use as signal)                        |
| `service.reload`   | `(name: string): Module` | No (always-applies, use as signal)                        |
| `service.facts`    | `(): Module`             | No (always-applies, collects facts into `service.*` meta) |

When a state probe reports a missing unit with exit code 4 (as in systemd 255),
`service.stopped` and `service.disabled` return `ok` from check and apply without
issuing a stop or disable command. This also applies to missing timer units.

`service.running` and `service.enabled` fail during apply with `unit not found`,
preserving the probe's exit code and output without attempting start or enable.
Their checks return `needs-apply`, so dry-run reports `changed` without applying.
Unexpected probe failures retain the same check=`needs-apply`, apply=`failed`
behavior; they do not satisfy a stopped or disabled target.

### `ssh`

| Method                        | Signature                                                                                                                              | Idempotent                      |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `ssh.authorizedKeys`          | `(user: string, key: string, options?: AuthorizedKeysOptions): Module`                                                                 | Yes                             |
| `ssh.authorizedPrincipals`    | `(user: string, principals: string[], options?: AuthorizedPrincipalsOptions): Module`                                                  | Yes                             |
| `ssh.hostCertificate`         | `(options: HostCertificateOptions): Module`                                                                                            | Yes                             |
| `ssh.signer.local`            | `(options: LocalHostCertificateSignerOptions): HostCertificateSigner`                                                                  | Descriptor; no construction I/O |
| `ssh.signer.stepCa`           | `(options: StepCaHostCertificateSignerOptions): HostCertificateSigner`                                                                 | Descriptor; no construction I/O |
| `ssh.knownHosts`              | `(host: string, options?: { expectedFingerprint?: string; port?: number; publicKey?: string; state?: "absent" \| "present" }): Module` | Yes                             |
| `ssh.knownHostsCertAuthority` | `(user: string, options: KnownHostsCertAuthorityOptions): Module`                                                                      | Yes                             |
| `ssh.trustedUserCa`           | `(options: TrustedUserCaOptions): Module`                                                                                              | Yes                             |

**Trust anchor requirement for `ssh.knownHosts` (`state: "present"`):** In the default `present` state, either `expectedFingerprint` or `publicKey` must be set. Without a trust anchor, the module constructor throws immediately because `check` would otherwise treat any existing `known_hosts` entry, including older and potentially compromised TOFU acceptances, as `ok` and skip the anchor comparison. No anchor is required for `state: "absent"`, because that state removes the entry.

#### `ssh.authorizedKeys`

`ssh.authorizedKeys(user, key, options?)` manages one public-key line in the target user's
`~/.ssh/authorized_keys`. `AuthorizedKeysOptions` (`{ options?: AuthorizedKeyOptions; state?:
"absent" | "present" }`) and `AuthorizedKeyOptions` are exported from both `paratix/modules` and
`paratix`. `key` is a complete public key; an options prefix in `key` is rejected, so restrictions
go through `options`. The Unix account must already exist, so place `user.present` earlier in
`run`.

The entry is identified by its key blob (algorithm plus base64 key data), not by the exact line.
`present` keeps exactly one line for the blob: the first existing line is replaced in place,
later lines of the same blob are removed, and a missing blob is appended. A changed options block
or trailing comment therefore counts as a change. `absent` removes every line of the blob
regardless of its options or comment. Comment, blank and unrelated lines keep their bytes; a
missing `.ssh` directory (0700) and `authorized_keys` (0600) are created for the user's primary
group.

Structured `options` are validated at construction and serialized deterministically: `restrict`
first, then alphabetical by lowercase OpenSSH option name; repeated options keep input order.
Only `"` is escaped inside quoted values (`\"`), as OpenSSH does. Values must not contain control
characters or end with a backslash; error messages name the field, never the value, because
`command` and `environment` may carry secrets.

| Field                                                                           | OpenSSH option                                                                           | Value                                                                             |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `restrict`                                                                      | `restrict`                                                                               | `boolean`; disables forwarding, PTY and `~/.ssh/rc`                               |
| `agentForwarding`, `portForwarding`, `pty`, `userRc`, `x11Forwarding`           | `agent-forwarding`, `port-forwarding`, `pty`, `user-rc`, `X11-forwarding`                | `boolean`; re-enable one capability after `restrict`                              |
| `noAgentForwarding`, `noPortForwarding`, `noPty`, `noUserRc`, `noX11Forwarding` | `no-agent-forwarding`, `no-port-forwarding`, `no-pty`, `no-user-rc`, `no-X11-forwarding` | `boolean`; contradicting its positive counterpart throws                          |
| `command`                                                                       | `command="…"`                                                                            | nonempty `string`; forced command                                                 |
| `environment`                                                                   | `environment="NAME=value"` per entry                                                     | plain object of `string` values; names match `[A-Za-z_][A-Za-z0-9_]*`             |
| `expiryTime`                                                                    | `expiry-time="…"`                                                                        | `string` in the format `YYYYMMDD[HHMM[SS]][Z]`, validated as a real date and time |
| `from`                                                                          | one `from="a,b"`                                                                         | nonempty `string[]`; elements contain no commas or whitespace                     |
| `permitOpen`, `permitListen`                                                    | one `permitopen="…"` / `permitlisten="…"` per element                                    | nonempty `string[]`; elements contain no commas or whitespace                     |

`environment` only takes effect when sshd's `PermitUserEnvironment` allows it. Unknown fields
and wrong types are rejected at construction, as is enabling a flag together with its
contradicting counterpart (for example `pty` and `noPty`); a flag set to `false` emits nothing.

Without `options`, the line equals the key as passed. If an existing line of the same blob
carries options, `present` returns `failed` (naming only the option names) instead of silently
dropping restrictions. Pass the intended options to replace them, or `options: {}` to remove them
deliberately; `options: {}` writes the key without options. A line that cannot be parsed but
contains the blob as a token makes both states `failed`, because sshd may still honor it; fix or
remove that line manually. The same applies to the same blob under a different key type. A line
whose options contain `cert-authority` trusts a certificate authority rather than the plain key,
so it is kept unchanged in both states, even for the same blob. Settings other than `options`
and `state` throw at construction.

Not supported: several lines for one key with different options (for example one per `from`
source), and two calls for the same user and blob in one playbook; they overwrite each other on
every run. Use one call and combine the options.

```typescript
import { server } from "paratix"
import { ssh, user } from "paratix/modules"

const publicKey = "ssh-ed25519 AAAA... ops-ro@example"

export default server({
  name: "restricted-key",
  host: "203.0.113.10",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/admin" },
  run: [
    user.present("ops-ro", { shell: "/bin/sh" }),
    ssh.authorizedKeys("ops-ro", publicKey, {
      options: { restrict: true, command: "/usr/local/bin/ops-ro-shell", from: ["10.0.0.0/8"] },
    }),
  ],
})
```

Check, dry-run and apply read the file with a no-follow read and compare the parsed lines; a
symlinked `~/.ssh` or `authorized_keys` makes dry-run and apply `failed` and check `needs-apply`.
Dry-run reports `changed` when the target user does not exist yet. A `failed` result from the
options guard or a conflict leaves `~/.ssh` untouched. Apply stages the new bytes as base64 text
through SFTP into a private directory under `/tmp`, never into `~/.ssh`, and decodes them on the
host, so `command` and `environment` values do not appear in command lines or process listings,
bytes that are not valid UTF-8 survive, and a symlinked parent such as `/home -> /data/home`
works.

Every read and write inside `~/.ssh` runs as the target user, through `setpriv` or, as a
fallback, `runuser` (both from util-linux). For a target user other than the connection's
effective user, one of them must be installed; otherwise check reports `needs-apply` and dry-run
and apply return `failed`, and Paratix never falls back to acting as root. Each step enters
`~/.ssh` by its canonical path (the resolved home directory plus `/.ssh`), refuses it when its
physical path or its device, inode and owner changed since the prepare step, and then uses only
names inside it. The home directory must exist, and the target user must be able to enter it
and, when `~/.ssh` is missing, write to it; a missing `~/.ssh` is created by the target user
with mode 0700.

A root-owned `~/.ssh`, for example from an earlier root bootstrap, is repaired only when group
and others cannot write it and it holds nothing but `authorized_keys`, `known_hosts` and
`known_hosts.old`, with `authorized_keys` a root-owned single-link regular file. Root then hands
`authorized_keys` to the target user with mode 0600 and resets mode and owner of the verified
directory. Any other root-owned `~/.ssh`, a `~/.ssh` owned by another user, and an
`authorized_keys` in the user's `~/.ssh` that another user owns (for example after
`sudo tee -a`) make check `needs-apply` and dry-run and apply `failed` without changes; fix the
ownership manually. The file content still travels as the stdout of a command run through sudo
during every check, dry-run and apply, so sudo I/O logging (`log_output`) records it. Apply refuses to publish
when the file changed between the read and the replace. For a complete restricted account, see
the [restricted-accounts recipe](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/restricted-accounts.md).

#### `ssh.hostCertificate`

A remote module for an existing Linux target host key. Only its derived public key reaches the
controller; the private host key is never created, rotated, repaired, or exported. Signing is
controller-side and renewal happens only during Paratix runs. There is no `local: true`, removal
mode, automatic scheduler, target CA installation, or native-transport trust change.

| `HostCertificateOptions` | Meaning and default                                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `signer`                 | Required `HostCertificateSigner` with an independently configured public SSH CA key.                                                |
| `principals`             | Required nonempty `readonly string[]` of explicit hostnames/IPs; deduplicated, order-independent, no wildcards or extra principals. |
| `keyType`                | `"ed25519"` (default), `"rsa"`, or `"ecdsa"`; must match the existing private host key.                                             |
| `hostKeyPath`            | Defaults to `/etc/ssh/ssh_host_<keyType>_key`. Must have exactly one effective `HostKey` mapping.                                   |
| `certificatePath`        | Defaults to `<hostKeyPath>-cert.pub`; public certificate is installed as `0644 root:root`.                                          |
| `validity`               | Maximum total signed lifetime, default `"30d"`; positive safe whole seconds or integer `s/m/h/d/w` notation.                        |
| `renewBefore`            | Renewal threshold, default `"7d"`, using the same duration format; `0 <= renewBefore < validity`.                                   |

Target path overrides must be normalized absolute file paths without spaces, with safe root-owned
ancestors and no overlap with sshd configuration, keys, other sshd resources, or reserved Paratix
state. Symlinks, hard-linked keys/certificates, unsafe permissions, missing or encrypted private
keys, ambiguous certificate mappings, and conflicting effective settings fail closed. The target
`.pub` file is not a separate source of truth. Unrelated keys, certificates, and includes remain
in place.

`validity` caps `validBefore - validAfter`, not remaining lifetime. A `30d` certificate with `10d`
left is renewed immediately after reducing the maximum to `14d`, even with `renewBefore: "7d"`.
Increasing the maximum alone does not renew an acceptable certificate. Renew when remaining
lifetime is **less than or equal to** `renewBefore`, or the key, exact principal set, CA, signature,
host type, or validity no longer matches. CA-shortened output is accepted only with positive total
lifetime within the maximum, within the requested absolute bounds, valid now, and with remaining
lifetime strictly above the threshold. Backdating consumes the same total-lifetime budget.
Controller UTC is checked again after signing and before publication; time advancing during
signing is acceptable if those conditions still hold. Invalid output fails without an issuance
loop. Successful completion persists no desired-policy history.

Controller `ssh-keygen` is required; Step additionally needs `step`. Built-in signers perform
capability preflight only on a confirmed real signing attempt, before reading the configured CA
private key or resolving a provisioner password. OpenSSH must pass an isolated temporary-CA
host-signing/derivation proof with exact principals, identity, and absolute UTC seconds, including
its `-L` listing. Step must report an identifiable `step version` and advertise every required
SSH certificate option in `step ssh certificate --help`. There is no guessed numeric minimum;
OpenSSH 10.3p1 and Step CLI 0.31.0 satisfy the respective facility checks. See the linked guide
for exact flags and the distinction from live CA/TLS proofs. The Linux target needs
`ssh-keygen`, `sshd -t/-T`, GNU-compatible file utilities, root privileges, and `flock`. Its active
systemd SSH unit must support pure reload. Full staged configuration and certificate validation
checks the actual certificate `HostKeyAlgorithms` allowance before publication; a raw-key-only
allowance fails without rewriting the algorithm policy. Changed certificate/configuration bytes
reload sshd even when the configuration text itself stays unchanged; metadata-only correction does
not reload. Host-certificate updates never fall back to restart.

`check` and dry-run inspect state without signing, provider access, recovery writes, or reload.
A converged apply returns `ok` without those effects or target changes. Pending always requires
apply. Signer constructors perform public configuration validation only; they do not start tools,
read CA private keys, or resolve passwords. The
[host-certificate guide](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/host-certificates.md)
contains tool capabilities, deployment prerequisites, and recovery procedures.

#### Controller signers

`ssh.signer.stepCa({ caUrl, provisioner, password, root, caPublicKey })` accepts an explicit HTTPS
CA URL without credentials/query/fragment, a configured JWK provisioner, a provider-bound
`SecretHandle`, an absolute controller PEM TLS-root path, and independent public SSH-CA text.
The TLS root authenticates the CA endpoint; `caPublicKey` authenticates the resulting host
certificate. Neither is discovered from the other. No bootstrap, personal Step context, token,
OIDC, or CA administration flow is inferred. Only a confirmed signing need resolves the password.

```typescript
import { readFileSync } from "node:fs"
import { secret, ssh } from "paratix/modules"

export function hostCertificateModule(input: {
  principals: string[]
  caUrl: string
  provisioner: string
  tlsRootPath: string
  hostCaPublicKeyPath: string
  provisionerSecretReference: string
}) {
  return ssh.hostCertificate({
    principals: input.principals,
    signer: ssh.signer.stepCa({
      caUrl: input.caUrl,
      provisioner: input.provisioner,
      root: input.tlsRootPath,
      caPublicKey: readFileSync(input.hostCaPublicKeyPath, "utf8"),
      password: secret.provider("1password").deferred(input.provisionerSecretReference),
    }),
  })
}
```

`ssh.signer.local({ caKey, caPublicKey })` uses an existing unencrypted controller file CA at an
absolute `caKey` path. Its derived public key must match independent `caPublicKey` text. It does
not use an agent, hardware token, PKCS#11, or interactive passphrase prompt. Both built-in signers
use shell-free noninteractive subprocesses, bounded output, a 60-second per-process timeout,
cancellation, and private per-call temporary state (`0700` directories, `0600` credentials).
Credentials never enter argv or target state; raw provider/process errors and output do not escape.
An uncertain request is reported without automatic retry; CA issuance cannot be rolled back.

Custom signers implement the exported structural `HostCertificateSigner`:

```typescript
import type { HostCertificateRequest, HostCertificateSigner } from "paratix/modules"

export function customHostSigner(input: {
  caPublicKey: string
  sign: (request: HostCertificateRequest) => Promise<string>
}): HostCertificateSigner {
  return { version: 1, caPublicKey: input.caPublicKey, sign: input.sign }
}
```

`HostCertificateRequest` contains `version: 1`, `publicKey`, a readonly exact `principals` array,
public `requestId`, `signal: AbortSignal`, and `validAfter`/`validBefore` as absolute whole UTC
seconds. Return exactly one OpenSSH host-certificate line. The module independently verifies
signature, expected CA, key, host type, principals, time bounds, and absence of critical options;
RSA CA signatures require RSA-SHA2. Public CA keys support Ed25519, RSA (at least 2048 bits), and
ECDSA P-256/P-384/P-521. Custom implementations own credential protection and must honor
cancellation; built-in subprocess controls are not automatically applied to arbitrary callbacks.

#### Pending and shared sshd writers

A protected public manifest at `/var/lib/paratix/host-certificate-pending` and immutable
certificate/configuration snapshots are published before active changes. Recovery validates
version, paths, ownership, hashes, host-key identity, and the current public desired policy.
An unchanged valid candidate resumes without signing. A changed policy or expired candidate
first restores and reloads the verified old state before a fresh convergence decision. Rollback
copies rather than consumes snapshots. Completion is recorded atomically before repeatable
cleanup; a completed cleanup retry tolerates already removed sidecars without signing or
unnecessary reload. A crash after reload but before completion may repeat that safe reload.

Malformed or unsafe state, missing active snapshots, external edits, or host-key conflicts stop
automatic recovery with evidence retained. Preserve the manifest, sidecars, and persistent OS-lock
file; do not delete them to force convergence. Recovery covers controller/process/connection
interruption, not disk loss or arbitrary administrative edits. `ok` is not continuous live-daemon
attestation after manual changes.

Host-certificate, configuration, port, user-CA, and principal writes share a lease and bounded
process-held `flock` checks. Lease changes and active commands check the shared lock; active writes
also fence stale controller identities. A living paused process keeps its OS lock after lease
expiry; the lock file is never removed or reclaimed by age. Other sshd writers refuse unresolved
host-certificate Pending; run host-certificate recovery first. This does not add automatic recovery
to the existing separate user-CA/principal transaction contract.

`ssh.knownHosts` manages only marker-free raw host-key entries. `@cert-authority` and
`@revoked` lines do not satisfy its trust-anchor checks and are preserved during replacement
or removal, including for overlapping hosts. An `absent` declaration is satisfied when only
marker lines remain.

#### Target-user host certificate trust

`ssh.knownHostsCertAuthority(user, options)` manages a host CA in the named target user's
`~/.ssh/known_hosts` for OpenSSH clients running as that user. The controller connection needs
permission to manage that user's files and ownership. This does not change how the Paratix
controller verifies its own SSH connections.

`KnownHostsCertAuthorityOptions` is exported from both `paratix/modules` and `paratix`:

```typescript
type KnownHostsCertAuthorityOptions =
  | { hosts: string[]; publicKey: string; state?: "present" }
  | { hosts?: string[]; publicKey: string; state: "absent" }
```

Read the independently verified CA public key on the controller and put the returned module in
your server's `run` list. The Unix account must already exist on the target:

```typescript
import { readFileSync } from "node:fs"
import { ssh } from "paratix/modules"
import type { KnownHostsCertAuthorityOptions } from "paratix/modules"

const publicKey = readFileSync("./host_ca.pub", "utf8")
const trust: KnownHostsCertAuthorityOptions = {
  publicKey,
  hosts: ["*.example.test", "[git.example.test]:2222", "2001:db8::1"],
}

const ensureHostCa = ssh.knownHostsCertAuthority("deploy", trust)
```

The default state is `present`. To remove this CA later, replace that declaration with:

```typescript
const removeHostCa = ssh.knownHostsCertAuthority("deploy", {
  publicKey,
  state: "absent",
})
```

`publicKey` is required in both states and must contain exactly one complete raw OpenSSH public
key with a supported algorithm and matching key blob. Outer whitespace and a final `.pub` newline
are accepted; additional key lines, private keys, certificates, and `authorized_keys` options are
rejected. The Base64 field must equal the canonical encoding of the validated bytes: missing or
extra padding and noncanonical pad bits are rejected before target mutations. An optional key
comment is ignored and omitted from the managed line.

`hosts` is required and nonempty for `present`. Positive OpenSSH patterns accept `*` and `?`,
IPv6 literals, and `[host-or-pattern]:port` with a port from 1 to 65535, including
`[2001:db8::1]:2222`. Negations, empty elements, commas within an element, whitespace,
control/format characters, and marker, comment, or hashed-host syntax are rejected. There is no
separate `port` option or DNS lookup. Exact duplicates are removed and patterns are sorted.
For `absent`, `hosts` may be omitted; if supplied it is validated but does not filter removal.

A resource is identified by the resolved target file, the `@cert-authority` marker, and the key
algorithm plus validated decoded bytes. `present` merges all recognized lines for that CA into
one canonical `@cert-authority <patterns> <algorithm> <base64>` line. Changing the patterns
updates that same resource. Once canonical, changing only the key comment or the host list's
order/duplicates causes no drift. `absent` removes all recognized lines for that CA regardless
of their previous patterns or comments.
Other CAs, raw keys (including hashed entries), `@revoked` lines, comments, blank lines, and
unrecognized or incomplete lines retain their bytes and order. Appending to a file without a
final newline adds the necessary separator.

The existing target account supplies the absolute home directory and actual primary group;
the SSH or sudo session's `$HOME` does not select this file. Missing accounts, failed group
resolution, unsafe or ambiguous home paths, symlink ancestors, symlinks, and special files at
`.ssh` or `known_hosts` fail. In `present`, `.ssh` is a real directory with mode `0700` and
`known_hosts` a regular file with mode `0600`, both owned by the target user and primary group.
Content and metadata drift are corrected without reconfiguring the home directory itself.
An already satisfied `absent` creates no missing directory/file and leaves existing metadata
unchanged. Removing an entry from an existing file publishes it with the protected modes and
ownership above.

`check` and dry-run compare content and metadata without creating a lock, directory, file,
backup, or temporary file, or changing permissions/ownership. Dry-run reports required changes
and readable unsafe-target failures. Apply stages on the target filesystem and checks target
identity, observed content, and metadata around publication; detectable conflicts or failed
post-publication checks return `failed`.

Both known-hosts writers share a lock for the same confirmed canonical target path, covering
fresh reads through publication. This serializes cooperating Paratix writers, including raw-key
and CA updates. The lock is independent of the key, patterns, and replaceable file inode.
External writers and a concurrently hostile file owner do not share that guarantee; distinct
paths through bind mounts or hard links have no general shared-lock guarantee.

For rotation, add the new CA and explicitly remove the old one when clients no longer need it.
A different key is a different resource and does not remove the old CA automatically. Two
declarations of the same CA with different desired pattern lists conflict; they do not form a
union. Existing raw-key pins can still authorize an unsigned host, and preserved revocations
can prevent OpenSSH from accepting otherwise matching trust. This module manages no system-wide
trust or revocation policy and does not require hosts to use certificates.

### `sshd`

| Method        | Signature                                                                                                          | Idempotent                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| `sshd.config` | `(settings: Record<string, string>): Module`                                                                       | Yes                                |
| `sshd.match`  | `(name: string, criteria: SshdMatchCriteria, directives: SshdMatchDirectives, options?: SshdMatchOptions): Module` | Yes                                |
| `sshd.port`   | `(targetPort: number): Module`                                                                                     | Yes (emits typed `sshd.port` meta) |

Apply requires target `flock` and shares commit locking with the SSH certificate/principal
modules. An unresolved host-certificate Pending transaction blocks these writers; resolve it
through [`ssh.hostCertificate`](#pending-and-shared-sshd-writers) first. Existing general
`sshd.config`/`sshd.port` restart/reconnect behavior is separate from the host-certificate module's
reload-only policy.

#### `sshd.match`

`sshd.match(name, criteria, directives, options?)` manages one declarative `Match` block as the
Paratix-owned drop-in `/etc/ssh/sshd_config.d/<name>.conf` (root:root, mode `0644`). `name` matches
`[a-z0-9][a-z0-9_-]{0,63}`. `SshdMatchCriteria`, `SshdMatchDirectives` and `SshdMatchOptions` are
exported from both `paratix/modules` and `paratix`. Everything is validated at construction.

```typescript
sshd.match(
  "ops-ro",
  { user: "ops-ro" },
  { DisableForwarding: "yes", PermitTTY: "no", ForceCommand: "/usr/local/bin/ops-ro-shell" }
)
```

- **Criteria:** `user` and/or `group`, each a literal name or a nonempty list without duplicates
  (`[a-z_][a-z0-9_-]*`). Patterns, negation, commas and other criteria such as `Address` or `Host`
  are rejected. With both, sshd combines them with AND. At least one criterion is required.
- **Directives:** a fixed allowlist, written with the canonical lowercase value that `sshd -T`
  prints: `AllowAgentForwarding`, `AllowStreamLocalForwarding`, `AllowTcpForwarding`,
  `AuthenticationMethods`, `DisableForwarding`, `ForceCommand`, `PasswordAuthentication`,
  `PermitTTY`, `PermitUserRC`, `PubkeyAuthentication`, `X11Forwarding`. Yes/no directives take
  `"yes"` or `"no"`; the two forwarding directives take `yes`, `no`, `local` or `remote` and
  reject `all` because `sshd -T` prints it as `yes`. `AuthenticationMethods` takes `any` or
  single-space-separated comma lists of lowercase method names. `ForceCommand` must be nonempty
  without leading or trailing whitespace. Values with control characters are rejected, and
  `present` needs at least one directive. Weakening values such as `PasswordAuthentication: "yes"`
  are allowed. The output order follows the allowlist, not the object key order.
- **Rejected directives:** `Port`, `HostCertificate`, `TrustedUserCAKeys`, `RevokedKeys` and
  `AuthorizedPrincipalsFile` belong to `sshd.port`, `ssh.hostCertificate` and `ssh.trustedUserCa`;
  the error names the owning module.
- **Options:** `state` (`"present"` by default or `"absent"`), `verifyUser` and
  `allowConnectionUser` (default `false`). `verifyUser` is the account for the effect check. It
  defaults to the first `user` criterion, must be listed in `user` when both are given, and is
  mandatory with a `group` criterion (also for `absent`). With `group`, apply fails unless the
  verify user is a member of one of the groups; check and dry-run treat a missing membership like
  a missing verify user (see Write semantics), because the same run may still add it.

**Top-level Include:** `/etc/ssh/sshd_config` must contain `Include /etc/ssh/sshd_config.d/*.conf`
before its first `Match` line (Debian and Ubuntu ship it first). Paratix never adds it, and
`present` fails without it because the drop-in would be inert. `absent` does not need the Include.

**Lockout guard:** before any change, the module refuses criteria that match the user of the
running Paratix connection (`ssh.user`, not the sudo target) and `failed`s with a message naming
that user. Set `allowConnectionUser: true` to accept this deliberately. With a `group` criterion,
the module reads that user's groups; if they cannot be determined, it also fails. The guard also
applies to `absent`: removing a block that was installed with `allowConnectionUser: true` needs
the flag again. A run that needs no change returns `ok` without this guard.

**Staged validation and effect check:** Paratix copies the complete Include tree to a temporary
directory, inserts the candidate at its sorted glob position (or omits it for `absent`) and runs
`sshd -t` on it. For `present` it then runs `sshd -T -C` for the verify user with the placeholder
connection `host=paratix-verify.invalid,addr=192.0.2.1` and compares every declared directive with
the printed value. After publishing it repeats the `sshd -T -C` check against the live
configuration, and only then reloads. If any step fails, the previous drop-in state is restored
(and the live configuration reloaded again if a reload was attempted).

The effect check proves the declared values for the verify user and that one placeholder
connection. It does not prove them for:

- `Match Address` or `Match Host` blocks, which the placeholder address and host do not match
  as a real client would;
- other accounts matched by the criteria (further `user` entries or `group` members), for
  example when they have their own earlier `Match` blocks;
- a directive that an earlier drop-in or `Match` block already set: sshd uses the first value it
  obtains, so the check fails with a message naming the directive, the expected and the printed
  value. Rename the drop-in so it sorts first, or adjust the order.

**Write semantics:** `present` and `absent` are transactional. Apply publishes the file with a
backup and a post-write verification, then performs a pure reload, never a restart. Dry-run runs
the read-only staged validation, checks that the sshd unit supports a pure reload (read-only
`systemctl show` and `systemctl is-active`) and reports `changed` without writing or reloading;
it reports `skipped` with a reason when `/run/sshd` is missing (it does not create it), and
`changed` with an "effect check pending" detail when the verify user does not exist yet or is not
yet a member of a criteria group. Apply fails in both cases, so create the user and its group
membership first. `check` does not stage: it returns `needs-apply` for a missing or drifted
drop-in, and prints a warning on stderr when a precondition (lockout guard, Include, foreign file,
live effect check) fails.

**Pending activation:** before it changes the drop-in, apply writes the state file
`/var/lib/paratix/sshd-match-pending-<name>` (root:root, `0600`) and removes it after a confirmed
reload. If the run stops in between, or a rollback does not finish, the file stays: because
`sshd -T` reads the disk and not the running daemon, `check` then reports `needs-apply`, dry-run
reports `changed`, and the next apply repeats the lockout guard and the staged validation, reloads
sshd and removes the file, even when the drop-in on disk already matches. A symlink or any other
unsafe entry at that path fails the module in every mode.

**Foreign file protection:** an existing `<name>.conf` whose first line is not
`# Managed by Paratix sshd.match: <name>` is never overwritten or removed; the module fails.
A concurrent modification of the drop-in during the run also fails. A converged `present` needs
root:root `0644` as well as identical content.

**Interplay:** the module shares the sshd writer lock with `sshd.config`, `sshd.port`,
`ssh.trustedUserCa` and `ssh.hostCertificate`, and an unresolved host-certificate Pending
transaction blocks it. `sshd.config` manages global settings in the main file and checks them with
a plain `sshd -T` that does not evaluate `Match` blocks. In that check only a global directive in
a drop-in that sshd reads earlier wins against `sshd.config`; a `sshd.match` block is not
evaluated, so `sshd.config` does not detect its override for the matched accounts. The textual
guard of `sshd.config` that rejects a contradicting `Match`-block override scans only
`/etc/ssh/sshd_config`, not drop-ins, so it does not see a `sshd.match` drop-in either. For
example, `sshd.config({ PasswordAuthentication: "no" })` together with
`sshd.match("ops", { user: "ops" }, { PasswordAuthentication: "yes" })` reports `ok` for both
modules, and `ops` may log in with a password. Because `sshd.match` rejects the directives that
`ssh.trustedUserCa` manages, the two never write the same setting. Example for a complete
read-only diagnostic account: the
[restricted-accounts recipe](https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/restricted-accounts.md).

### `swap`

| Method                  | Signature                                                                                                                      | Idempotent |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `swap.file`             | `(options: { path: string; size: number \| string; mode?: string; priority?: number; state?: "absent" \| "present" }): Module` | Yes        |
| `swap.swappiness`       | `(value: number): Module`                                                                                                      | Yes        |
| `swap.vfsCachePressure` | `(value: number): Module`                                                                                                      | Yes        |

### `sysctl`

| Method       | Signature                                                                                                | Idempotent                                                                                                                                  |
| ------------ | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `sysctl.set` | `(key: string, value: string, options?: { resetValue?: string; state?: "absent" \| "present" }): Module` | Yes for `present`. For `absent`: only the persistence file is removed by default; pass `resetValue` to also restore the live runtime value. |

### `system`

| Method          | Signature                                                                                                        | Idempotent                                          |
| --------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `system.facts`  | `(): Module`                                                                                                     | No (always-applies, emits typed `env` meta entries) |
| `system.reboot` | `(options?: { resolveHost?: (signal?: AbortSignal) => Promise<string>; resolveHostTimeoutMs?: number }): Module` | No (always-applies)                                 |
| `system.uptime` | `(): Module`                                                                                                     | No (always-applies, emits typed `env` meta entries) |

### `systemd`

| Method                 | Signature                                 | Idempotent                         |
| ---------------------- | ----------------------------------------- | ---------------------------------- |
| `systemd.unit`         | `(name: string, content: string): Module` | Yes                                |
| `systemd.daemonReload` | `(): Module`                              | No (always-applies, use as signal) |
| `systemd.masked`       | `(name: string): Module`                  | Yes                                |
| `systemd.unmasked`     | `(name: string): Module`                  | Yes                                |

### `timer`

| Method            | Signature                                                                                                                                                                                                                                                                                                                                                             | Idempotent |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `timer.scheduled` | `(name: string, options: { accuracySec?: number \| string; description?: string; environment?: Record<string, string>; exec: string; group?: string; onCalendar: string \| string[]; onFailure?: string \| string[]; persistent?: boolean; randomizedDelaySec?: number \| string; state?: "absent" \| "present"; user?: string; workingDirectory?: string }): Module` | Yes        |
| `timer.absent`    | `(name: string): Module`                                                                                                                                                                                                                                                                                                                                              | Yes        |

`timer.absent(name)` is the dedicated uninstall variant: it disables and stops
the timer, removes both unit files, and reloads systemd, without requiring
placeholder `exec`/`onCalendar` values.

`timer.scheduled` is the systemd-timer equivalent of `cron.job`. It writes
`<name>.service` (`Type=oneshot`) and `<name>.timer` to `/etc/systemd/system/`,
reloads systemd, and runs `systemctl enable --now <name>.timer`. Use it as the
default for new scheduled tasks: `Persistent=true` is on by default so missed
runs are caught up after downtime, and logs land in journald (`journalctl -u
<name>.service`). Cron remains a fit for ad-hoc per-user crontab entries.

```typescript
timer.scheduled("backup", {
  exec: "/usr/local/bin/backup",
  onCalendar: "*-*-* 03:00:00",
})

timer.scheduled("cleanup", {
  exec: "/usr/local/bin/cleanup",
  onCalendar: ["Mon..Fri 02:00", "Sat 04:00"],
  user: "deploy",
  randomizedDelaySec: 300,
})

timer.absent("legacy-task")
```

Use `onFailure` to attach a notification unit, so an unattended job that starts
failing does not stay silent until someone reads journald. Each entry becomes
one `OnFailure=` line in the `[Unit]` section of the generated `.service`, and
systemd specifiers are passed through unescaped, so `%n` resolves to the failing
unit's name:

```typescript
timer.scheduled("restic-backup", {
  exec: "/usr/local/bin/restic-backup",
  onCalendar: "*-*-* 02:30:00",
  onFailure: "notify@%n.service",
})
```

The referenced handler unit is yours to provide, for example as a
`notify@.service` template via `systemd.unit`. Entries are restricted to
systemd unit-name characters plus `%`; a value containing whitespace, `#` or a
line break is rejected. For anything the option cannot express, write the unit
yourself with `systemd.unit`.

### `ufw`

| Method         | Signature                                                        | Idempotent |
| -------------- | ---------------------------------------------------------------- | ---------- |
| `ufw.disabled` | `(): Module`                                                     | Yes        |
| `ufw.enabled`  | `(): Module`                                                     | Yes        |
| `ufw.rule`     | `(action: "allow" \| "deny", ports: number \| number[]): Module` | Yes        |

### `user`

| Method         | Signature                                                                                                                                    | Idempotent |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `user.present` | `(name: string, options?: { uid?: number; shell?: string; home?: string; homeMode?: string; groups?: string[]; password?: string }): Module` | Yes        |
| `user.absent`  | `(name: string, options?: { removeHome?: boolean }): Module`                                                                                 | Yes        |

## Custom Modules

A custom module must implement `check` and `apply`, both async:

```typescript
import type { Module, ModuleResult, SshConnection, Environment } from "paratix"
import { NEEDS_APPLY, failed, meta } from "paratix"

function myCustomModule(configPath: string, content: string): Module {
  return {
    name: `my-module: ${configPath}`,

    async check(ssh: SshConnection | null, env: Environment): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const exists = await ssh.exists(configPath)
      if (!exists) return NEEDS_APPLY
      const current = await ssh.readFile(configPath)
      return current === content ? "ok" : NEEDS_APPLY
    },

    async apply(ssh: SshConnection | null, env: Environment): Promise<ModuleResult> {
      if (!ssh) return failed(`[my-module: ${configPath}] SSH connection is required`)
      await ssh.writeFile(configPath, content, { mode: "0644" })
      return {
        meta: [meta.env("MY_MODULE_PATH", configPath)],
        status: "changed",
      }
    },
  }
}
```

### Key rules for custom modules

- Always check `if (!ssh) return NEEDS_APPLY` in check and return `failed("...")` with a useful message in apply.
- Prefer `failedCommand("...", result)` when you used `ssh.exec(..., { ignoreExitCode: true })` and want stdout/stderr preserved for central runner output. It carries the first few non-empty output lines (bounded by a line and byte budget) so multi-line diagnostics such as systemd's `See "journalctl -xeu <unit>"` hint are not dropped; the full streams stay on `CommandError.fullStderr`/`fullStdout` for `--verbose`.
- Use `failedCommandWithDiagnostic({ ... })` when a best-effort follow-up probe supplies the cause missing from a failed command's own output.
- Use `restartSystemdUnit({ ... })` from `paratix/modules` for a bounded, attempt-scoped systemd restart diagnostic.
- Return `NEEDS_APPLY` (the exported constant), never the string literal `"needs-apply"`.
- `ModuleResult.status` must be one of: `"changed"`, `"failed"`, `"ok"`, `"skipped"`.
- Optionally return `ModuleResult.detail` with a short single-line reason; the runner appends it to the step line. Use it to say what a `changed` step actually did, and leave it unset when the step did no work. See [Status Detail on Changed Steps](#status-detail-on-changed-steps).
- Use typed `meta` entries in the return value, not loose objects.
- For normal downstream environment propagation, use `meta.env(name, value)`.
- `meta.env(...)` accepts strings, numbers, booleans, sync lazy functions, and async lazy functions.
- `meta.env(...)` is normalized internally to an async resolver, so downstream code should treat propagated environment values as lazily async and resolve them via `resolveEnvironment(...)` when it needs the concrete primitive.
- Use dedicated built-in meta entries only for runner control-plane effects, for example `meta.sshdPort(...)`, `meta.systemHost(...)`, and `meta.systemReboot()`.
- Use the exported guards such as `isEnvironmentMetaEntry(...)`, `isStringEnvironmentMetaEntry(...)`, `isNumberEnvironmentMetaEntry(...)`, `isBooleanEnvironmentMetaEntry(...)`, `isLazyEnvironmentMetaEntry(...)`, `isSshdPortMetaEntry(...)`, `isSystemHostMetaEntry(...)`, and `isSystemRebootMetaEntry(...)` when you need to inspect meta entries safely.
- Set `local: true` on the module object if it runs on the local machine (ssh will be `null`).

### Failure, restart, and diff helpers

| Helper                        | Signature                                                                                                                       | Result                                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `failedCommandWithDiagnostic` | `(parameters: { diagnostic: null \| string; message: string; result: ExecResult; secrets?: string[] }): ModuleResult`           | A failed result with bounded command output and the optional, secret-masked diagnostic. |
| `restartSystemdUnit`          | `(parameters: { failureMessage: string; secrets?: string[]; ssh: SshConnection; unit: string }): Promise<ModuleResult \| null>` | `null` on success; otherwise a failed result with a best-effort journal excerpt.        |
| `buildUnifiedDiff`            | `(current: string, desired: string, options?: UnifiedDiffOptions): string`                                                      | Unified diff text, or `""` when the normalized inputs are identical.                    |
| `buildKeyValueDiff`           | `(key: string, currentValue: null \| string, desiredValue: string): string`                                                     | A compact scalar diff, or `""` when both values match.                                  |

`UnifiedDiffOptions` has three optional fields: `contextLines?: number` (default `3`, clamped to
at least `0`), `currentLabel?: string` (default `"current"`), and `desiredLabel?: string` (default
`"desired"`). The diff helpers are available from `paratix/modules` and are re-exported at the
root for compatibility; `UnifiedDiffOptions` is exported as a type from both entry points.

### Meta API

Use the `meta` object for normal module authoring. Its `env`, `sshdPort`, `systemHost`, and
`systemReboot` methods create the four public meta-entry variants. The same constructors are also
available as `environmentMeta`, `sshdPortMeta`, `systemHostMeta`, and `systemRebootMeta` for
advanced code that prefers standalone functions.

`EnvironmentMetaEntry.resolution?: "per-access"` is an additive opt-in. Omission preserves
successful-result memoization (including legacy `op.resolve` codes); `per-access` retains only
an in-flight resolution and validates the resolved type on every access. Both success and
failure release that promise. `mergeEnvironmentFromMeta`, `environmentToMetaEntries`, and
`diffEnvironmentToMetaEntries` preserve this policy without evaluating resolvers. Explicitly
marked `secret.totp` entries use it automatically.

The remaining public helpers cover validation, narrowing, and conversion:

| Purpose                      | Public helpers                                                                                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Validate entries             | `assertValidModuleMetaEntry`, `assertValidModuleMetaEntries`                                                                                            |
| Narrow environment entries   | `isEnvironmentMetaEntry`, `isBooleanEnvironmentMetaEntry`, `isLazyEnvironmentMetaEntry`, `isNumberEnvironmentMetaEntry`, `isStringEnvironmentMetaEntry` |
| Narrow control-plane entries | `isSshdPortMetaEntry`, `isSystemHostMetaEntry`, `isSystemRebootMetaEntry`                                                                               |
| Convert environments         | `environmentToMetaEntries`, `diffEnvironmentToMetaEntries`, `mergeEnvironmentFromMeta`                                                                  |

### SshConnection API

Methods available on the `ssh` parameter:

| Method                                            | Return type                                                                                                                                              | Description                                                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `ssh.addPort(port)`                               | `boolean`                                                                                                                                                | Register a reconnect candidate; return `true` when it was added.                                       |
| `ssh.disconnect()`                                | `void`                                                                                                                                                   | Close the SSH connection.                                                                              |
| `ssh.downloadFile(remotePath, localPath)`         | `Promise<void>`                                                                                                                                          | Download a remote file.                                                                                |
| `ssh.exec(command, options?)`                     | `Promise<ExecResult>`                                                                                                                                    | Run a command and return `{ code, stdout, stderr }`. Throws on non-zero unless `ignoreExitCode: true`. |
| `ssh.exists(remotePath)`                          | `Promise<boolean>`                                                                                                                                       | Check whether a remote path exists.                                                                    |
| `ssh.getConnectionInfo()`                         | `{ agentSocket?, authMethod?, certificatePath?, configuredPorts, host, hostVerificationEvidence?, port, privateKeyPath?, user, verifiedHostPublicKey? }` | Return the active connection and authentication details.                                               |
| `ssh.lines(command)`                              | `Promise<string[]>`                                                                                                                                      | Run a command and return stdout split into lines.                                                      |
| `ssh.output(command)`                             | `Promise<string>`                                                                                                                                        | Run a command and return trimmed stdout.                                                               |
| `ssh.probeSudo()`                                 | `Promise<void>`                                                                                                                                          | Probe and cache sudo access, prompting interactively if needed.                                        |
| `ssh.readFile(remotePath)`                        | `Promise<string>`                                                                                                                                        | Read the full contents of a remote file.                                                               |
| `ssh.reconnect(options?)`                         | `Promise<void>`                                                                                                                                          | Reconnect; `options.defaultTimeout` supplies a call-specific fallback in milliseconds.                 |
| `ssh.removePort(port)`                            | `void`                                                                                                                                                   | Remove a registered reconnect candidate.                                                               |
| `ssh.sha256(remotePath)`                          | `Promise<string \| null>`                                                                                                                                | Return the SHA-256 hex digest, or `null` when the file is not found.                                   |
| `ssh.test(command)`                               | `Promise<boolean>`                                                                                                                                       | Run a command and return whether its exit code is zero.                                                |
| `ssh.updateHost(host)`                            | `void`                                                                                                                                                   | Update the target host address.                                                                        |
| `ssh.uploadFile(localPath, remotePath, options?)` | `Promise<void>`                                                                                                                                          | Upload through SFTP; `options.mode` defaults to `"0600"`.                                              |
| `ssh.writeFile(remotePath, content, options?)`    | `Promise<void>`                                                                                                                                          | Create or replace a remote file; `options.mode` defaults to `"0600"`.                                  |

`getConnectionInfo().authMethod`, when present, is `"agent"`, `"password"`, or `"privateKey"`.
`certificatePath` is the expanded configured path only after successful file-key authentication
with a certificate; it is absent for agent and password authentication. Certificate-based file
authentication still reports `authMethod: "privateKey"`.

`verifiedHostPublicKey` is optional and always uses the raw OpenSSH public-key format
`<algorithm> <base64-key>`. For an accepted host certificate it contains the certified leaf,
never the certificate or CA; its algorithm comes from the raw leaf blob. Optional
`hostVerificationEvidence` records `kind: "key" | "certificate"`, `host`, `port`, raw `publicKey`,
`explicitPins` and `revocations`; certificate evidence additionally has `authorityPublicKey` for
the accepted signer. A successful authenticated handshake replaces all evidence. A failed
reconnect leaves previous evidence unchanged. Custom rsync wrappers must not infer CA trust
from `verifiedHostPublicKey` alone.

`reconnect` accepts `options?: { defaultTimeout?: number }`; `uploadFile` and `writeFile` accept
`options?: { mode?: string }`.

### ExecOptions

```typescript
{
  env?: Record<string, string>       // Extra environment variables
  ignoreExitCode?: boolean           // Don't throw on non-zero exit
  input?: string                     // Payload written to stdin before EOF
  maxOutputBytes?: number            // Cap stored stdout/stderr bytes
  secrets?: string[]                 // Strings to mask in error output
  silent?: boolean                   // Suppress stdout/stderr
  strictUtf8Stdout?: boolean         // Reject invalid UTF-8 on stdout instead of substituting U+FFFD
  timeout?: number                   // Abort after N milliseconds
}
```

With `strictUtf8Stdout: true`, stdout is decoded as strict UTF-8 and the command rejects with an
error named `InvalidUtf8OutputError` instead of substituting U+FFFD, so different host bytes cannot
decode to the same string. stderr is always decoded leniently; the default (`false`) is unchanged.

Prefer `input` for secret payloads instead of shell arguments, so values do not
leak through process lists, `/proc/<pid>/cmdline`, or SSH logs. Add the same
values to `secrets` only as an additional masking guard for error output.

## Template System

Files deployed via `file.template(remotePath, localTemplatePath)` can contain `{{KEY}}` placeholders.

- Placeholders are resolved at runtime from the `env` object of `server()` and from typed `meta.env(...)` entries returned by previous modules.
- Environment values can be strings, numbers, booleans, sync lazy functions, or async lazy functions.
- Values propagated through `meta.env(...)` are normalized to async resolution before downstream modules or templates consume them.
- Escaping: `\{{` produces a literal `{{` in the output.
- Unknown keys throw an error at runtime.
- **Modifiers:** the built-in modifiers are `shell` (applies `shellQuote()` to the value), `raw` (explicit verbatim insertion) and `b64decode` (see below).
- **Modifier chains.** Modifiers can be chained and are applied left to right: `{{KEY|b64decode|shell}}` decodes first and quotes the result. The order is yours to get right — `{{KEY|shell|b64decode}}` tries to decode the quoted string and fails.
- **`b64decode`.** Decodes a base64-encoded value into the text it represents. Use it for multi-line secrets — PEM/OpenSSH private keys, certificates — that are stored base64-encoded on a single line because the secret manager mangles embedded newlines. Whitespace is stripped and missing padding is normalized; a foreign alphabet (including base64url), a non-canonical final group, or bytes that are not valid UTF-8 throw instead of writing corrupted output. Error messages never contain the value or the decoded bytes.
- **`b64decode` is for file targets.** It fits SSH keys, certificates and kubeconfigs rendered with `file.template`. It does **not** make a multi-line value usable inside a systemd `EnvironmentFile` — those have their own quoting rules, and a decoded PEM still breaks the parser.
- **Strict mode (default: on).** Every placeholder must have at least one explicit modifier. Bare `{{KEY}}` placeholders throw at render time. Pass `strict: false` in the options to disable this check.
- **Security: No default escaping.** Values are inserted verbatim. If the template produces a shell script or shell config, **always** use `{{KEY|shell}}` for every variable — omitting `|shell` can lead to shell injection. `b64decode` is a transform, not an escape: a chain without `shell` inserts the decoded value verbatim.
- **Secrets in dry runs.** `file.template` renders its `--dry-run` diff from the final content, unmasked. A decoded private key is therefore visible in that diff.

Example template file (`nginx.conf.tmpl`):

```
server {
    listen 80;
    server_name {{DOMAIN|raw}};
    proxy_pass http://127.0.0.1:{{APP_PORT|raw}};
}
```

With `env: { DOMAIN: "example.com", APP_PORT: 3000 }` in the server definition.

## Recipes

A recipe groups modules into a named, reusable unit with optional signals:

```typescript
import { recipe } from "paratix"
import { package as pkg, file, service } from "paratix/modules"

export const nginxRecipe = recipe(
  "nginx",
  [
    pkg.installed("nginx"),
    file.template("/etc/nginx/nginx.conf", "./files/nginx.conf.tmpl"),
    service.enabled("nginx"),
    service.running("nginx"),
  ],
  {
    signals: [service.reload("nginx")],
  }
)
```

**How recipes work:**

- Modules run in order; execution stops on first `"failed"` status.
- `meta.env(...)` values propagate from one module to all subsequent ones within the recipe and resolve lazily when later modules or templates consume them.
- If any module reports `"changed"`, the `signals` array fires after all modules complete.
- Signals follow the same failure rule as modules: a failed signal stops the remaining signals of
  that list, and the recipe or run status becomes `"failed"`. There is no `continueOnError`. Put
  restarts that must all be attempted independently into separate signal lists. See
  [ADR-0006](https://github.com/sebastian-software/paratix/blob/main/docs/adr/0006-signal-lists-stop-at-the-first-failed-signal.md).
- `signals.flush()` can be used inside the same scope to execute currently pending signals early.
- Recipes can be nested: include a recipe in another recipe's module list.

**When to use recipes:**

- Group related modules that form a logical unit (e.g., "install and configure nginx").
- When you need signals to fire only if that specific group changed (not the entire server run).

## Built-in Functions

### `assert(condition, message)`

Fail the run if a condition is not met.

```typescript
assert((env) => !!env["APP_SECRET"], "APP_SECRET must be set")
```

### `when(condition, ...modules)`

Conditionally run modules. Skipped modules report `"skipped"`, not `"failed"`.
A block whose condition holds is itemized like a recipe — header, one line per
guarded module, closing line; a block whose condition is false reports a single
`skipped` line. See [Dry-Run Diff Output](#dry-run-diff-output---diff).

```typescript
when((env) => env["DEPLOY_ENV"] === "production", service.enabled("fail2ban"), ufw.enabled())
```

### `when.packageInstalled(name, ...modules)` / `when.packageAbsent(name, ...modules)`

Conditionally run modules based on package state on the remote host.

```typescript
when.packageInstalled("ufw", ufw.disabled())
when.packageAbsent("docker-ce", pkg.installed("docker-ce"))
```

### `when.commandExists(name, ...modules)` / `when.commandMissing(name, ...modules)`

Conditionally run modules based on whether a command exists on the remote host.

```typescript
when.commandExists("docker", service.running("docker"))
when.commandMissing("docker", pkg.installed("docker-ce"))
```

### Filesystem guard variants

Use explicit filesystem-type guards when a module or recipe should only run for a specific entry type:

- `when.fileExists(path, ...modules)` / `when.fileMissing(path, ...modules)` for regular files
- `when.pathExists(path, ...modules)` / `when.pathMissing(path, ...modules)` for directories
- `when.symlinkExists(path, ...modules)` / `when.symlinkMissing(path, ...modules)` for symlinks
- `when.socketExists(path, ...modules)` / `when.socketMissing(path, ...modules)` for Unix sockets

```typescript
when.fileExists("/etc/myapp/config.yml", service.reload("myapp"))
when.pathMissing("/etc/traefik", file.directory("/etc/traefik"))
when.symlinkExists("/etc/myapp/current", service.restart("myapp"))
when.socketExists("/run/docker.sock", service.running("docker"))
```

### `swap.file(options)`

Create, activate, and persist a file-backed swap area.

```typescript
swap.file({ path: "/swapfile", size: "2G" })
swap.file({ path: "/swapfile", size: "2G", priority: 10 })
swap.file({ path: "/swapfile", size: "2G", state: "absent" })
```

### `swap.swappiness(value)` / `swap.vfsCachePressure(value)`

Apply common swap-related sysctl tuning without writing the sysctl keys manually.

```typescript
swap.swappiness(10)
swap.vfsCachePressure(50)
```

### `debug(message)`

Print a debug message during apply. Always runs.

```typescript
debug("Starting database setup")
```

### `fail(message)`

Unconditionally abort the run with a failure.

```typescript
fail("This branch should be unreachable")
```

### `firstRun.stop(message?)`

Stops the current run cleanly when Paratix was started with `--first-run`. Useful as an explicit staging boundary in bootstrap playbooks.

```typescript
firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")
```

### `isFirstRun()`

Returns `true` during a `paratix apply --first-run` invocation: while the CLI imports and evaluates
the playbook, and for the entire run, including every module `check` and `apply`, recipe children,
and `when` predicates. It returns `false` in ordinary runs and after a run has finished.
Branch at import time to choose a different module list for the first run:

```typescript
import { isFirstRun, server, type Module } from "paratix"

const bootstrapModules: Module[] = []
const regularModules: Module[] = []

export default server({
  host: "10.0.0.1",
  name: "web-01",
  run: isFirstRun() ? bootstrapModules : regularModules,
  ssh: { ports: [22], user: "root" },
})
```

A custom module can also call `isFirstRun()` inside its `check` or `apply` to adapt a single step.
Use `firstRun.stop(...)` to end a first run at an explicit staging boundary.
The helper reads an async-local context; the CLI does not mutate
`process.env.PARATIX_FIRST_RUN`, and child processes spawned by modules do not see the flag.

### `signals.flush(message?)`

Immediately runs all currently pending signals in the active scope and clears their pending state.

```typescript
signals.flush("Reload services before the next bootstrap stage")
```

### `pause(message?)`

Wait for operator to press Enter. Useful for interactive confirmation.

```typescript
pause("Review changes above, then press Enter to continue")
```

### `shellQuote(value)`

Safely quote a string for shell interpolation. Use this when building shell commands with dynamic values.

```typescript
await ssh.exec(`cat ${shellQuote(filePath)}`)
```

### `NEEDS_APPLY`

Constant for the check return value indicating work is needed. Always use this instead of the string `"needs-apply"`.

```typescript
import { NEEDS_APPLY } from "paratix"

async check(ssh) {
  if (!ssh) return NEEDS_APPLY
  // ...
}
```

## Status Detail on Changed Steps

A module may return a short `detail` next to its status. The runner appends it to
the step line, both for top-level modules and for steps inside a recipe:

```
· · ↺  package.upgrade: 2026-03-01    changed  no packages upgraded  4.1s
```

The dated-flag modules use this to say **why** they ran. Their step name already
carries the date, so the detail reports the outcome instead of repeating the key.
This matters most for the upgrade modules: they report `changed` whenever their
dated marker is absent, even when the package manager upgraded nothing.

| Module            | Detail on `changed`                                                     |
| ----------------- | ----------------------------------------------------------------------- |
| `package.update`  | `marker was missing, package index refreshed`                           |
| `package.upgrade` | `12 packages upgraded`, `1 package upgraded`, or `no packages upgraded` |
| `apt.distUpgrade` | same forms as `package.upgrade`                                         |

Rules:

- The count is parsed from apt's upgrade summary. `package.upgrade` also serves
  `dnf`, `yum` and `apk`, whose summaries differ; those report
  `upgrade completed, package count unavailable`.
- The same fallback applies when the summary line is missing from the output, or
  when the captured output was truncated at `maxOutputBytes`. apt prints its
  summary last, so a truncated capture loses exactly that line, and reporting no
  count is preferred over reporting a wrong one.
- A step that did no work carries no detail: the flag-already-exists path returns
  a plain `ok`, and failures report through the normal error path.
- Dry runs keep the generic `changed (dry-run)` suffix. The detail is produced by
  `apply`, which does not run in dry-run mode.

Custom modules may return `detail` the same way; see
[Key rules for custom modules](#key-rules-for-custom-modules).

## Dry-Run Diff Output (`--diff`)

Paratix runs a playbook in dry-run mode via `paratix apply <file> --dry-run`, which
reports per-module `changed (dry-run)` or `ok` based on each module's `check()`.
A recipe is always itemized in a dry run — at any nesting depth it prints its
`[name]` header plus one line per child, and that itemization on its own says
nothing about diffs. A `when(...)` block is itemized the same way: when its
condition holds it prints its own `[name]` header, one line per guarded module
and a closing line with the aggregated status, in a dry run as well as in an
apply. When the condition is false the block reports a single `skipped` line
without a header, and the run summary counts it under `skipped`.

`--diff` enables a second, opt-in layer: modules that mark themselves as diff
producers also render a unified-diff block under their status line so the user
sees _what_ would change, not only _that_ something would change.

```
$ paratix apply server.ts --dry-run --diff
  ↺  /etc/ssh/sshd_config                            changed  (dry-run)
     │ --- /etc/ssh/sshd_config
     │ +++ /local/path/sshd_config
     │ -Port 22
     │ +Port 2222
```

Rules:

- `--diff` requires `--dry-run`. The CLI rejects `paratix apply <file> --diff`
  without `--dry-run` before any SSH connection or playbook side effect.
- Without `--diff`, the dry-run runs are byte-identical to before: no extra
  remote round-trips, no diff output.
- Modules that do not opt in keep showing only `changed (dry-run)`.
- Every diff line is masked through the registered-secret sink and a terminal
  sanitizer before printing. Only registered strings of at least eight characters are covered;
  shorter secrets, including typical six-digit TOTP codes, are outside this global masking guarantee.
- Inline status detail and multi-line diff blocks are independent output layers. A built-in module
  may emit both at once; the runner renders detail next to the status line and the diff below it.

Diff-producing built-in modules:

| Module                                      | Diff content                                                                                                                                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `file.copy`                                 | Unified diff between the remote file and the local source.                                                                                                                                                                                                               |
| `file.template`                             | Unified diff between the remote file and the rendered template.                                                                                                                                                                                                          |
| `sysctl.set`                                | `key = old → new` for the desired configuration.                                                                                                                                                                                                                         |
| `hostname.set`                              | `hostname = old → new`.                                                                                                                                                                                                                                                  |
| `swap.file`                                 | Diff of the `/etc/fstab` entry (or removal of the line for `state: "absent"`).                                                                                                                                                                                           |
| `swap.swappiness`                           | `vm.swappiness = old → new` (via `sysctl.set`).                                                                                                                                                                                                                          |
| `swap.vfsCachePressure`                     | `vm.vfs_cache_pressure = old → new` (via `sysctl.set`).                                                                                                                                                                                                                  |
| `cron.job` / `cron.absent`                  | Unified diff of the target user's crontab.                                                                                                                                                                                                                               |
| `timer.scheduled` (present)                 | Concatenated diffs of the `.service` and `.timer` unit files.                                                                                                                                                                                                            |
| `timer.scheduled` (absent) / `timer.absent` | List of unit files to remove.                                                                                                                                                                                                                                            |
| `net.hosts`                                 | Unified diff of `/etc/hosts`.                                                                                                                                                                                                                                            |
| `quadlet.container`                         | Unified diff of the `.container` unit file. If the file already matches but the `daemon-reload` flag is missing, `(dry-run, daemon-reload pending)` also appears as a detail suffix. A conflicting foreign container is reported in every dry run, `--diff` or not.      |
| `quadlet.network`                           | Unified diff of the `.network` unit file. If the file already matches but the `daemon-reload` flag is missing, `(dry-run, daemon-reload pending)` also appears as a detail suffix. When a network with the same name is already live, the advisory hint is appended too. |

### Quadlet conflict guard

`quadlet.container` and `quadlet.updateImage` inspect the container the unit
manages before doing any work, and fail with an actionable message when that
container is owned by something other than the unit. Podman refuses to replace a
foreign container, and without the guard the failure surfaced only as
`systemctl restart failed (exit code 1)` — or not at all, because an unchanged
image skips the restart entirely and the module reported `ok` while a foreign
container was the one actually running.

The managed container name is `containerName ?? systemd-<name>`, mirroring
Quadlet's own default. Set `containerName` on `quadlet.updateImage` whenever
`quadlet.container` sets it, so both inspect the same container.

The guard reports a conflict only on **positive** evidence of foreign ownership:

- a Compose project label (`com.docker.compose.project` or
  `io.podman.compose.project`), which is what a Compose-to-Quadlet migration
  leaves behind, or
- a `PODMAN_SYSTEMD_UNIT` value naming a different unit.

Anything else — no metadata, an unreadable projection, or a probe that fails —
is deliberately **not** treated as evidence and the apply proceeds unchanged. A
false positive would fail every rollout, while a false negative merely falls back
to the journal excerpt that a failed `systemctl restart` already carries. A
container that a Quadlet unit started itself is never a conflict:
`PODMAN_SYSTEMD_UNIT` holds the full unit name (`%n`), so both sides are
normalized before comparison.

The `quadlet.container` conflict guard also runs in a plain `--dry-run`; its unit-file diff still
requires `--diff`.

### Custom-module diff output

`buildUnifiedDiff` and `buildKeyValueDiff` from `paratix/modules` are public formatting helpers.
`UnifiedDiffOptions` is available as a type from either public entry point. Runner integration for a
custom diff is not a stable extension API, however: custom modules should use the documented `check`
and `apply` contract and may return a short `detail`; do not depend on internal module fields.

## Do's and Don'ts

### DO

1. Always use `export default server({...})` as the default export of a playbook.
2. Import modules from `"paratix/modules"` in new code. Root re-exports remain supported for compatibility.
3. `package` must be aliased on import: `import { package as pkg } from "paratix/modules"` -- `package` is a reserved word in JavaScript.
4. For idempotency with `command.shell()`, always provide a `check` command.
5. Use `{{KEY|shell}}`, `{{KEY|raw}}` or a chain such as `{{KEY|b64decode|shell}}` in `.tmpl` files — strict mode is on by default and bare `{{KEY}}` will throw. Provide values via `env` in `server()`.
6. Use `service.restart()` and `service.reload()` as `signals` in recipes, not directly in `run`.
7. Use `signals.flush()` only as an explicit checkpoint when staged flows require an early signal flush.
8. Always pass a date string to `package.upgrade()` and `package.update()` -- it is the idempotency key. Each distinct date keeps its own flag file, so several calls with different dates coexist; a date that was already applied stays applied and is not re-run. Read the step's [status detail](#status-detail-on-changed-steps) to tell a real upgrade from a step that only wrote its marker.
9. Specify `ssh.ports` as an array -- the runner tries each port in order.
10. Custom modules must implement both `check` and `apply`, both async.
11. Use `shellQuote()` when interpolating dynamic values into shell commands.
12. Emit downstream values via `meta.env(...)` and use dedicated built-in meta entries only for runner control-plane behavior.
13. When you need a concrete propagated value inside custom code, use `await resolveEnvironment(env, "KEY")` instead of assuming `env["KEY"]` is already a plain primitive.

### DON'T

1. Do NOT use deep imports. The only public paths are `"paratix"` and `"paratix/modules"`.
2. Do NOT use `service.restart()` directly in `run` -- it runs EVERY time. Use it as a signal in a `recipe()`.
3. Do NOT use the string literal `"needs-apply"` -- always use the exported constant `NEEDS_APPLY`.
4. Do NOT assume `ssh` is non-null in custom modules -- always check it and return `failed("...")` with context.
5. Do NOT forget that `package.upgrade("2025-01-15")` needs a date as IDEMPOTENCY KEY -- the date controls when the upgrade re-runs.
6. Do NOT interpolate `env` values directly in shell commands -- use `shellQuote()` for safe quoting.
7. Do NOT store module methods as variables and call them later -- modules are configured at creation time, not at call time.
8. Do NOT use `ssh.exec()` without `ignoreExitCode: true` when you need to inspect the exit code -- without it, a non-zero exit throws an exception.
9. Do NOT use template syntax `{{key}}` in TypeScript code -- templates are only for files rendered via `file.template()`.
10. Do NOT use `signals` on the top-level `server()` when you mean a recipe signal -- `server.signals` fire when ANY module in `run` changed.
11. Do NOT treat `signals.flush()` as a global queue flush -- it only affects the current scope.
12. `signals.flush()` always flushes only the current scope:
    - inside a recipe, that recipe's signals
    - at the top level, `server(...).signals`
13. Do NOT call `server()` without all required fields (`name`, `host`, `ssh`, `run`) -- it throws at construction time. `name` and `host` must not be empty strings.
14. Do NOT use empty arrays for `ssh.ports` or empty strings for `ssh.user`/`ssh.privateKey`/`ssh.certificate` -- validation rejects these. `ssh.certificate` requires `ssh.privateKey`; omit both to use the SSH agent instead.
15. Do NOT return loose `meta: { ... }` maps from custom modules -- always use typed meta entries.
16. Do NOT set `ssh.sudoPassword` or initial SSH credentials to values from `secret.provider(...).resolve(...)`, `op.resolve()`, or `meta.env()` -- `SshConfig` is frozen at server construction time, before any module in `run` executes. This still holds even though `op.resolve` now resolves its references up front, right after the command starts: that up-front resolution runs inside `runPlaybook`, which is already after construction time, so it is exactly as unreachable for `SshConfig` as the module's own `apply()` step always was. Use a static source like `process.env.SUDO_PASSWORD` or a variable populated before the server definition is imported.

## Testing Patterns

Tests use vitest with a `createMockSsh` helper:

```typescript
import { describe, expect, it } from "vitest"
import { NEEDS_APPLY } from "paratix"

import { createMockSsh } from "./helpers/mockSsh.js"

describe("myModule", () => {
  it("should detect needs-apply when file is missing", async () => {
    const ssh = createMockSsh({
      // Map command strings to partial ExecResult { code?, stdout?, stderr? }
      "[ -e '/etc/myconfig' ]": { code: 1 },
    })

    const mod = myCustomModule("/etc/myconfig", "desired content")
    const result = await mod.check(ssh, {})
    expect(result).toBe(NEEDS_APPLY)
  })

  it("should apply changes", async () => {
    const ssh = createMockSsh({})

    const mod = myCustomModule("/etc/myconfig", "desired content")
    const result = await mod.apply(ssh, {})
    expect(result.status).toBe("changed")
  })

  it("should track executed commands", async () => {
    const ssh = createMockSsh({})

    const mod = myCustomModule("/etc/myconfig", "content")
    await mod.apply(ssh, {})

    // ssh.calls contains all commands executed in order
    expect(ssh.calls).toContain("some-expected-command")
  })
})
```

### `createMockSsh` behavior

- Accepts `Record<string, Partial<ExecResult>>` mapping command strings to responses.
- Unknown commands fail closed with an error. Add every expected command to the
  response map, or the helper throws instead of returning a successful default.
- `ssh.test(cmd)` returns `code === 0`.
- `ssh.exists(path)` delegates to `ssh.test("[ -e '<path>' ]")`.
- `ssh.readFile(path)` delegates to `ssh.output("cat '<path>'")`.
- Returns a `{ calls: string[] } & SshConnection` object -- `calls` records all commands in execution order.
