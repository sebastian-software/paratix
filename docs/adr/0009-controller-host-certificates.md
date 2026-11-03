# Controller-issued SSH host certificates

## Status

Accepted for implementation of issue #251, 2026-11-03.

## Context

An existing target host key needs a renewable OpenSSH host certificate without placing a CA key,
CA password, CA client, or renewal timer on that target. Renewal occurs during explicit Paratix
runs. The controller's initial transport trust remains independently configured; accepting host
certificates in the native transport is separate work.

## Decision

`ssh.hostCertificate` derives only the public key of an existing, safely owned target private
host key. It never generates, repairs, exports, or rotates that private key. The module accepts
explicit principals, a maximum total signed validity (default 30 days), and a renewal threshold
(default seven days). Principal order and public-key comments have no semantic effect. A shorter
maximum validity takes effect immediately; increasing it alone does not renew an otherwise
acceptable certificate. CA-capped certificates are accepted when valid now, within the requested
absolute bounds, and strictly outside the renewal threshold. Time is checked again after signing.

A public versioned structural signer receives a public key, exact principals, absolute UTC time
bounds, a public request identity, and an abort signal. It returns one host certificate. Independent
verification checks signature, host type, key, CA public key, principals, critical options, allowed
signature algorithm, and time bounds before publication. `ssh-keygen -L` alone is not a trust anchor.
Both initial implementations execute on the controller: `ssh.signer.local` uses an explicitly
selected noninteractive file CA with `ssh-keygen`; `ssh.signer.stepCa` uses an explicit JWK
provisioner, CA URL, TLS PEM root, SSH CA public key, and the `step` CLI. TLS verification remains
mandatory. Neither signer uses personal Step contexts, SSH agents, or interactive CLI prompts.

The additive `secret.provider(...).deferred(reference)` API produces a frozen opaque `SecretHandle`
bound to the selected provider instance. The existing injectable `SecretResolver.resolve` contract
is retained. Handles do not contain credentials, expose references, produce environment metadata,
prewarm, or resolve during construction, imports, checks, or dry-runs. A private registry rejects
copies and forged handles. JSON serialization fails safely; inspect output is redacted. Only a
confirmed apply-time signing need resolves a handle, using the existing run scope for deduplication
and masking. Secret values and errors never survive in handle state between runs.

Signer processes use shell-free argv, closed stdin, bounded duration and output, cancellation and
process termination, and private temporary directories and credential files. Passwords never enter
argv or target commands. Raw process output and raw causes cannot escape the signer boundary.
Temporary controller state is removed on success, failure, or cancellation. An uncertain CA request
is reported without automatic retries.

The existing sshd transaction seam owns host configuration integration. It preserves unrelated
HostKey, HostCertificate, Include, and algorithm policies; ambiguous assignments fail closed.
The complete staged configuration and staged certificate pass `sshd -t` and `sshd -T`, including
an effective certificate HostKeyAlgorithms check, before active mutation. A pure reload mechanism
and correct service must be established first. A renewed certificate requires a reload even when
configuration text is unchanged. Restart fallback is forbidden for this module. Public certificate
files use `0644 root:root`; metadata repair alone does not reload.

All sshd writers (configuration, port, user CA, principals, host certificates) share the existing
controller lease plus a target-process OS lock for their bounded prepared commit, reload, and
rollback sections. A living process retains its OS lock even after lease expiry or SIGSTOP.
No OS lock is reclaimed by age. The sshd coordination lease refreshes every ten seconds, expires
after a bounded two-minute window, and waits at most three minutes for recovery; kernel-lock
waits are bounded to thirty seconds. Lease acquisition/reclaim/release also takes that kernel
lock, so lease expiry cannot permit a competing writer while a target process still holds it.
Lease directory creation, initial holder publication, and confirmation form one target-process
critical section. Contended controllers wait outside the OS lock between short atomic attempts;
waiting cannot block the current holder's work, heartbeat, or release. Initial holder bytes are
prepared in a protected UUID-named file, verified, then atomically published without overwriting
an existing holder. A crash never exposes a partially written active holder. After process death
and stale expiry, recovery accepts a safe empty markerless directory or one reserved preparation
file whose ownership, mode, link count, UUID name, and bytes prove an interrupted token write.
Cleanup removes that preparation file before its directory and remains repeatable after another
crash. Arbitrary malformed holders, foreign payloads, and unsafe evidence are retained. Each active mutation and marker publication checks current lease
identity under that lock; stale controllers cannot resume writes. Competing non-host writers block
on unresolved host-certificate Pending state. Signing occurs outside the target lock, followed by
fresh host-key, configuration, and convergence checks under lock.

A dedicated root-owned protected state directory contains a versioned secret-free Pending manifest
and public certificate/configuration snapshots. The manifest records transaction identity, desired
public policy, target paths, hashes, metadata, and phase. The manifest and all needed immutable
restore sources are ready before the first active mutation. Recovery validates ownership, paths,
version, hashes, policy, and current private-host-key identity. Identical still-valid policy resumes
without signing. Changed policy or expired candidate first restores and reloads the complete old
state, then evaluates the new desired state. Host-key conflicts, external edits, malformed state,
and missing active snapshots fail closed with evidence retained.

Rollback copies immutable restore sources through verified temporary files and atomic renames;
it never consumes snapshots. After effective checks, reload, and service confirmation, an atomic
manifest transition marks the transaction complete before any sidecar cleanup. Cleanup is
idempotent, tolerates already removed sidecars, verifies the confirmed end state, and removes its
manifest last. A crash before completion may repeat a safe reload; a crash during completed cleanup
requires neither signing nor reload. Pending is always change-needed, including in a read-only
dry-run. Recovery covers interrupted controllers, target processes, and connections, not disk loss
or arbitrary foreign administrative changes.

## Consequences

The controller requires OpenSSH `ssh-keygen`; Step users additionally require `step`. Supported
Linux targets require an OS-lock facility and explicit reload capability. There is no automatic
renewal outside Paratix runs. Recovery evidence blocks conflicting administrative writes rather
than overwriting them. Private host keys and CA credentials never enter public file transactions.

## References

- [Smallstep SSH certificate CLI](https://smallstep.com/docs/step-cli/reference/ssh/certificate/)
- [OpenSSH certificate signing](https://man.openbsd.org/ssh-keygen#CERTIFICATES)
- [OpenSSH HostCertificate configuration](https://man.openbsd.org/sshd_config#HostCertificate)
- [OpenSSH certificate parsing and signature verification](https://github.com/openssh/openssh-portable/blob/master/sshkey.c)
