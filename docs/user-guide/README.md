# Paratix User Guide

## Supported platforms

Paratix runs on Node.js 24 or newer and uses prebuilt native SSH binaries on these controller platforms:

| Platform      | Architectures | Requirement                    |
| ------------- | ------------- | ------------------------------ |
| Linux (glibc) | x64, arm64    | glibc 2.35 or newer            |
| Linux (musl)  | x64, arm64    | musl, for example Alpine Linux |
| macOS         | x64, arm64    | macOS 13.5 or newer            |

Windows and other platforms are unsupported for playbook execution. Installation, `import "paratix"`, `--help`, and `--version` still work without loading the native binding. A playbook run checks the binding before resolving its secrets.

Keep optional dependencies enabled when installing: they supply the binary for your platform. Published packages require no Rust toolchain; Rust is needed only when contributing to and building this repository.

Private key files must be unencrypted text in a supported PEM or OpenSSH format. DSA keys, hardware-backed `sk-*` key files, binary key formats, and encrypted files are unsupported. For supported algorithms and agent use, see the [native binding's key requirements](../../packages/ssh-native/README.md#authentication-and-key-formats). For recovery, see [native SSH loading failures](./troubleshooting.md#the-native-ssh-binding-cannot-be-loaded).

## Authenticate with a user certificate

For a server that authorizes OpenSSH user certificates, configure the matching unencrypted
private key and certificate on the controller. In your playbook's `server()` definition, use:

```typescript
ssh: {
  user: "deploy",
  ports: [22],
  privateKey: "~/.ssh/id_ed25519",
  certificate: "~/.ssh/id_ed25519-cert.pub",
},
```

Both paths expand `~`; `certificate` must be a nonempty path and requires `privateKey`.
The server must trust the issuing user CA through `TrustedUserCAKeys` and authorize the
certificate's principals for the login account. `AuthorizedPrincipalsFile` can allow a principal
that differs from `ssh.user`; Paratix does not require them to match locally.

Before opening TCP, Paratix checks the certificate's format, user type, issuer signature,
key match, and validity window using the controller clock. This check does not establish CA
trust or server authorization. RSA user certificates use RSA-SHA2 without enabling legacy
`ssh-rsa`. A rejected file identity never falls back to a password.

For an agent-held certificate, omit both `privateKey` and `certificate` and use the agent in
`SSH_AUTH_SOCK`. Attaching an external certificate file to a raw agent key is unsupported.
Encrypted private keys still require an agent.

Each reconnect reloads both configured files, allowing certificate renewal at the same path;
an expired or otherwise invalid certificate stops the reconnect immediately. After a successful
file-certificate login, `rsync.sync()` passes the same expanded certificate path to OpenSSH as
`CertificateFile`. Agent and password sessions do not set that option.

User certificates authenticate you to the server. Host certificates and host-CA trust are
unsupported; retain your verified host-key pin or `known_hosts` entry. See the
[authentication reference](../../packages/paratix/llm-guide.md#ssh-authentication) and
[certificate troubleshooting](./troubleshooting.md#a-user-certificate-fails).

## Configure server-side user certificates

For a server that should trust one or more user CAs, create each user's principal file before
activating the shared CA trust. The controller connection used by these modules needs permission
to manage `/etc/ssh` and reload sshd:

```typescript
import { server } from "paratix"
import { ssh, user } from "paratix/modules"

const principalsFile = "/etc/ssh/auth_principals/%u"

export default server({
  name: "certificate-host",
  host: "203.0.113.10",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/admin" },
  run: [
    user.present("deploy", { homeMode: "0700" }),
    ssh.authorizedPrincipals("deploy", ["deploy", "release"], { principalsFile }),
    ssh.trustedUserCa({
      publicKey: "ssh-ed25519 AAAA... ca-one\nssh-ed25519 AAAA... ca-two",
      principalsFile,
      revokedKeys: "/etc/ssh/revoked_user_keys",
    }),
  ],
})
```

`ssh.trustedUserCa` manages the global `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`
directives. `ssh.authorizedPrincipals` manages only the expanded file for the named Unix user.
The default template is `/etc/ssh/auth_principals/%u`; if you customize it, use the identical
normalized `/etc/ssh/` template in every call. It must end in exactly one `%u`. The CA file is a
shared global resource, so separate calls with different templates are rejected. `publicKey` may
contain multiple complete OpenSSH public-key lines. Principal names are normalized, one per line,
and unsafe names or CA options/certificates/private keys are rejected.

The modules enforce root ownership and safe permissions (`0644` for managed files and `0755` for
new directories), reject symlinks and unsafe ancestors, and ensure the login user can traverse and
read its principal file. A root-owned `0700` ancestor is rejected when that user cannot traverse
it. `revokedKeys` is optional: when configured and absent, Paratix creates an empty **text** file;
an existing text list or binary OpenSSH KRL is preserved byte-for-byte, including a safe `0600`
mode. Without `revokedKeys`, no `RevokedKeys` directive or revocation file is managed. The modules
do not manage `AuthorizedPrincipalsCommand`; that is an independent OpenSSH policy boundary.

Removal is ordered: apply `ssh.trustedUserCa({ state: "absent" })` first so the directives are
validated, disabled, and reloaded before the CA file is removed. Then remove a user's principal
file with `ssh.authorizedPrincipals("deploy", [], { principalsFile, state: "absent" })`. Removal
does not delete principal files belonging to other users or revocation data. `Match`-scoped managed
directives, unresolved includes, and effective-value conflicts are refused without rewriting
foreign configuration. Repeating apply or dry-run is idempotent.

### Recover after an interrupted CA trust update

`check` and `ok` cover file contents, safe metadata, and the effective **on-disk** sshd settings
reported by `sshd -T`. They do not attest to the running daemon's configuration. Handled update
errors trigger rollback; any rollback failure is reported. Automatic recovery after an abrupt
controller or target process interruption is outside this bounded transaction contract.

An interruption after publishing configuration but before reloading sshd can leave the desired
files on disk while the daemon still uses its previous principal or revocation settings. Merely
rerunning Paratix can then return `ok` without making that pending configuration live.

An administrator must recover deliberately:

1. On the **remote Linux target**, verify that the CA, principal and revocation files, their
   permissions, and `/etc/ssh/sshd_config` with its includes match the intended policy. Confirm
   which existing systemd SSH service runs that configuration (`ssh.service` or `sshd.service`).
2. As root or with sudo on that target, validate the configuration. Stop and correct any error
   before proceeding:

   ```sh
   sudo sshd -t -f /etc/ssh/sshd_config
   ```

3. After validation succeeds, reload the identified service. For a target using `ssh.service`:

   ```sh
   sudo systemctl reload ssh.service
   ```

   Substitute `sshd.service` only when it is the service running the intended daemon. Stop on
   reload failure and resolve it administratively; do not substitute an indiscriminate restart.
   These commands run on the target, not on a macOS controller.

4. After a successful reload, rerun Paratix from the controller and verify the intended
   certificate login and rejection policy on the target.

See the upstream [sshd test modes](https://man.openbsd.org/sshd) and
[systemctl reload reference](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html#reload%20PATTERN%E2%80%A6).

## Guides

Use these guides alongside the package READMEs:

1. [Troubleshooting](./troubleshooting.md) explains common local runtime, certificate, host-key, and reconnect failures.
2. [Choosing an automation tool](./comparison.md) compares Paratix with Ansible and pyinfra.
3. [Migration notes](./migration.md) lists upgrades that require action in an existing Paratix project.

For the complete TypeScript API and built-in module reference, see the
[TypeScript API and Module Reference](../../packages/paratix/llm-guide.md).
