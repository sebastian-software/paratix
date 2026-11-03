# Issue and renew SSH host certificates

Use `ssh.hostCertificate` to certify an existing Linux target host key. Paratix derives its
public key on the target, signs it on the controller, installs the public certificate, and
reloads sshd. The private host key stays on the target unchanged. The module does not create or
rotate keys, install a CA, or configure automatic renewal.

Host certificates identify servers to clients. They are separate from
[user certificates](./README.md#authenticate-with-a-user-certificate), which authenticate users
to a server. Issuing a host certificate does not configure client trust. Paratix's own connection
still needs its independently verified raw host-key pin or `known_hosts` entry; host-CA trust in
the native transport is outside this feature.

## Prepare the controller and target

On the controller, provide OpenSSH `ssh-keygen`. Compatibility is determined by required
facilities rather than a guessed minimum version. Before each real built-in signing attempt,
Paratix generates an isolated temporary probe CA with the configured CA algorithm, derives its public
key, and signs the
public subject key with explicit host type, identity, principal, and absolute UTC seconds. It
independently verifies the probe signature and exact fields and checks the `-L` listing. This
requires `-t`/`-b` for the configured CA algorithm, `-N`, `-C`, `-q`, `-f`, `-y`, `-P`, `-s`, `-h`, `-n`, `-I`, `-V`, and `-L`,
including `YYYYMMDDHHMMSSZ` UTC intervals. The probe CA is temporary and never trusted or installed
on a target. OpenSSH `ssh-keygen` has no standalone version option; passing this facility proof
is the runtime compatibility check. OpenSSH 10.3p1 passes the local proof.

For `ssh.signer.stepCa`, also provide the Smallstep `step` CLI. Before resolving the provisioner
password, Paratix requires a recognizable `step version` result and checks
`step ssh certificate --help` for `--host`, `--sign`, `--no-agent`, `--force`, `--principal`,
`--provisioner`, `--provisioner-password-file`, `--not-before`, `--not-after`, `--ca-url`, and
`--root`. No numeric version floor is inferred from these checks. Step CLI 0.31.0 passes this
version/help contract in an isolated official container; this is separate from the JWK CA
issuance and TLS integration proofs. The actual request still uses explicit RFC 3339 bounds
and independently validates the CA's returned certificate.

Capability checks use the same noninteractive, bounded, cancellable process runner and protected
per-call directory as signing. They run only after real signing need is confirmed, never during
construction, checks, or dry-run. A failed preflight reads no configured CA private key, resolves
no provisioner password, sends no CA request, and publishes no target certificate/configuration.
See the [OpenSSH signing reference](https://man.openbsd.org/ssh-keygen#CERTIFICATES),
[Step version reference](https://smallstep.com/docs/step-cli/reference/version/), and
[Step SSH certificate reference](https://smallstep.com/docs/step-cli/reference/ssh/certificate/).
Paratix does not install these tools or configure personal Step contexts.

The Linux target needs root privileges through the existing connection, OpenSSH `ssh-keygen`
and `sshd`, GNU-compatible file utilities, and `flock`. It must already have a root-owned,
unencrypted private host key accessible only to root, without symlinks or hard links. Its public
key is derived from that private key; an adjacent `.pub` file is not the authority. The selected
key must have one unambiguous effective `HostKey` mapping. Missing or unsafe keys fail before
signing or active-file publication.

The existing systemd SSH service (`ssh.service` or `sshd.service`) must be active and support a
pure reload. The module checks this before publication and uses no restart fallback. Its
`HostKeyAlgorithms` policy must permit the selected **certificate** algorithm; permitting only
the raw-key algorithm is insufficient. Paratix preserves that policy and reports a conflict
rather than broadening it. OpenSSH also requires the certificate to match a configured
[HostKey](https://man.openbsd.org/sshd_config#HostCertificate).

## Configure controller-side signing

For Step, provision the CA independently with SSH host signing enabled and an explicit JWK
provisioner. Obtain both trust anchors through a trusted channel:

- `root`: an absolute controller path to the PEM TLS root that authenticates the HTTPS CA.
- `caPublicKey`: the independently configured SSH host-CA public key in OpenSSH format,
  supplied as public text, not a path or a value inferred from the returned certificate.

The following factory returns a remote module for an existing playbook's `run` array. Supply
all inputs from your configuration; no hostnames, secret references, or private-key contents
are embedded in the example. Controller file reads in this factory load only the public CA key.

```typescript
import { readFileSync } from "node:fs"
import { secret, ssh } from "paratix/modules"

export function configureHostCertificate(input: {
  principals: string[]
  caUrl: string
  provisioner: string
  tlsRootPath: string
  hostCaPublicKeyPath: string
  provisionerSecretReference: string
}) {
  return ssh.hostCertificate({
    keyType: "ed25519",
    principals: input.principals,
    validity: "30d",
    renewBefore: "7d",
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

`caUrl` must be an explicit HTTPS URL without embedded credentials, query, or fragment. TLS
verification stays enabled. Paratix passes the configured root and provisioner explicitly and
uses an isolated per-call Step directory. It does not bootstrap trust or use personal Step
configuration. Token, OIDC, Vault, and CA administration flows are outside this signer.

`password` must be an opaque provider-bound `SecretHandle`, not a raw password, reference string,
TOTP descriptor, or environment binding. `.deferred(reference)` creates no module, environment
metadata, provider access, or early-secret registration. The handle resolves only after a real
apply reconfirms signing need. A matching certificate, check, and dry-run never invoke the signer
or its secret provider. Ordinary `secret.provider(...).resolve(...)` modules elsewhere in the
playbook keep their existing early resolution, including during dry-run.

Use `secret.provider("manual").deferred(input.provisionerSecretReference)` for an interactive
provider prompt only when signing is needed. The prompt uses the safe label “SSH certificate
signer”, not the reference. Signer subprocesses themselves stay noninteractive. Handles belong
to their creating provider instance; copies, forged objects, and deserialized replacements are
rejected. Inspect output is redacted and JSON serialization throws. Decrypted values and pending
resolution promises are not stored in the handle; deduplication and masking use the current run,
with no credential cache carried into the next run.

For tests or a small setup with an existing controller file CA, use the local signer instead:

```typescript
import { ssh } from "paratix/modules"

export function configureLocalHostCertificate(input: {
  principals: string[]
  caKeyPath: string
  caPublicKey: string
}) {
  return ssh.hostCertificate({
    principals: input.principals,
    signer: ssh.signer.local({ caKey: input.caKeyPath, caPublicKey: input.caPublicKey }),
  })
}
```

`caKey` is an absolute controller path to an existing unencrypted, noninteractive file CA key.
The signer checks that its derived public key matches the independent `caPublicKey`. It does
not use SSH agents, hardware tokens, PKCS#11, or hidden passphrase prompts. No CA private key,
provisioner password, or signer CLI is placed on the target.

Built-in signer subprocesses use shell-free arguments, closed stdin, a 60-second per-process
limit, bounded output, and termination on cancellation. Temporary controller directories use
`0700`; credential files use `0600` and are removed after the invocation. Passwords are never
arguments. Failures report safe stages without raw subprocess streams or provider errors.
An uncertain CA request is not automatically retried; a later explicit run checks target state
again. CA-side issuance cannot be rolled back.

## Choose principals, paths, and renewal limits

`principals` must be a nonempty set of explicit hostnames or IP addresses. Duplicates are removed
and order is irrelevant; wildcards and implicit extra principals are rejected. Use the exact
identities clients will verify.

The default `keyType` is `ed25519`; `rsa` and `ecdsa` select their existing standard host keys.
`hostKeyPath` defaults to `/etc/ssh/ssh_host_<keyType>_key`, and `certificatePath` defaults to
`<hostKeyPath>-cert.pub`. Overrides must be normalized absolute paths without spaces and must
not overlap sshd configuration, other managed resources, or reserved Paratix state. Parents and
files must have safe root ownership and permissions. The installed public certificate is
`0644 root:root`.

`validity` defaults to `30d` and `renewBefore` to `7d`. Both accept finite safe whole seconds
or an integer followed by `s`, `m`, `h`, `d`, or `w`. Require `validity > 0` and
`0 <= renewBefore < validity`. The controller's UTC clock owns the decision:

- `validity` limits the **total signed lifetime**, `validBefore - validAfter`.
- Renew when remaining lifetime is less than or equal to `renewBefore`, or the certificate
  is missing, invalid, not yet valid, or mismatches the current key, exact principals, or CA.
- Shortening `validity` takes effect immediately. A certificate issued for `30d` with `10d`
  remaining must be replaced when the new maximum is `14d`, even with a `7d` renewal threshold.
- Increasing `validity` alone does not replace an otherwise acceptable certificate. It applies
  when another condition next requires issuance. Successful runs retain no desired-policy history.
- A CA may return a shorter certificate if its total lifetime is positive and within the maximum,
  it respects the requested absolute bounds, and its remaining lifetime is strictly above
  `renewBefore`. Backdating counts toward total lifetime and cannot enlarge the requested window.
- Time is checked again after signing and before publication. Time advancing during the request
  is acceptable while the certificate remains valid now and strictly outside the renewal window.
  Invalid CA output fails before publication rather than starting an issuance loop.

Run Paratix regularly enough to renew before expiry and monitor failed runs. This module creates
no timer or scheduler, so a certificate can expire if no successful run occurs in time.

## Apply and verify

Run the existing playbook with `--dry-run` first, then apply it. Dry-run reads target state without
signing, credential access, recovery writes, or reload. A converged apply returns `ok` without
signing, target changes, or reload. A certificate or effective configuration change validates the
complete staged configuration with `sshd -t` and `sshd -T` before active publication, then reloads.
A safe certificate metadata repair alone does not reload. Conflicting certificate assignments
or external changes fail closed while unrelated `HostKey`, `HostCertificate`, and includes are
preserved.

Verify separately that a client trusting the intended host CA can connect with strict checking,
the intended principal, and the selected certificate algorithm. Configure that client's
`@cert-authority` trust through an independent trusted channel. A successful raw-key login alone
does not prove certificate delivery. After renewal, confirm that the running main daemon offers
the new certificate. `ok` describes validated files and effective on-disk settings; it is not
continuous attestation against later manual changes to the running service.

## Resume an interrupted update

Before active publication, Paratix records a versioned public Pending manifest at
`/var/lib/paratix/host-certificate-pending` and protected public certificate/configuration
snapshots in `/var/lib/paratix/host-certificate-state-<transaction-id>`. They contain hashes,
metadata, paths, transaction phase, and the normalized public desired policy; no private keys
or credentials. Keep these recovery files intact.

An unresolved Pending state always needs apply, even if active files look correct. Rerun the
host-certificate module in a real apply:

1. With the same policy, unchanged host key, and a still-valid candidate, Paratix revalidates
   and finishes the update without signing again. A crash after reload may cause another safe
   reload before completion is recorded.
2. With a changed CA, principals, validity policy, or expired candidate, it first restores and
   reloads the verified old state, then evaluates the new request. It never activates an obsolete
   candidate simply because its files match.
3. Rollback copies immutable snapshots, so interruption during restoration can be resumed.
   Completion is recorded atomically before cleanup. A later run verifies a completed state
   and finishes interrupted cleanup without another signature or unnecessary reload; already
   deleted sidecars are allowed in this completed phase.

Unknown versions, unsafe or malformed state, missing active snapshots, external file changes,
and host-key conflicts block automatic recovery and preserve evidence. Diagnose the reported
conflict administratively before changing recovery files. Do not delete the manifest or snapshots
to force `ok`, or rotate the private key while recovery is unresolved. Recovery covers interrupted
controllers, target processes, and connections; it cannot reconstruct data lost from disk or
arbitrary foreign edits.

Host certificates, `sshd.config`, `sshd.port`, `ssh.trustedUserCa`, and `ssh.authorizedPrincipals`
share a lease and target-process `flock` checks for active writes, reloads, and rollback. Other
writers refuse an unresolved host-certificate Pending state; run its recovery owner first,
including when it would otherwise appear later in your playbook. A living paused target process
retains its OS lock even after lease expiry. Creating the lease directory and publishing its first
holder marker happen atomically under that lock. The first marker is fully prepared before an
atomic rename publishes it. Interrupted preparation is recovered automatically after the target
process exits and the lease becomes stale; protected preparation files are validated before
cleanup. Malformed active markers and foreign or unsafe files remain untouched. Contending
controllers wait outside the OS lock,
so the current holder can continue working, refreshing its lease, and releasing it. Waiting is
bounded, and stale controllers are fenced before active writes. Do not remove `/var/lib/paratix/sshd-commit.lock` or break a living lock
because it is old. This host-certificate recovery does not add automatic crash recovery to
separate user-CA or principal updates; their [recovery procedure](./README.md#recover-after-an-interrupted-ca-trust-update)
still applies.

For all public options and custom signer types, see the
[SSH module reference](../../packages/paratix/llm-guide.md#ssh).
