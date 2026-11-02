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

## Guides

Use these guides alongside the package READMEs:

1. [Troubleshooting](./troubleshooting.md) explains common local runtime, certificate, host-key, and reconnect failures.
2. [Choosing an automation tool](./comparison.md) compares Paratix with Ansible and pyinfra.
3. [Migration notes](./migration.md) lists upgrades that require action in an existing Paratix project.

For the complete TypeScript API and built-in module reference, see the
[TypeScript API and Module Reference](../../packages/paratix/llm-guide.md).
