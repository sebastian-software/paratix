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

## Guides

Use these guides alongside the package READMEs:

1. [Troubleshooting](./troubleshooting.md) explains common local runtime, host-key, and reconnect failures.
2. [Choosing an automation tool](./comparison.md) compares Paratix with Ansible and pyinfra.
3. [Migration notes](./migration.md) lists upgrades that require action in an existing Paratix project.

For the complete TypeScript API and built-in module reference, see the
[TypeScript API and Module Reference](../../packages/paratix/llm-guide.md).
