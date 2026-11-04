# Changelog

## [0.25.0](https://github.com/sebastian-software/paratix/compare/ssh-native-v0.24.0...ssh-native-v0.25.0) (2026-11-04)


### Features

* **ssh:** support OpenSSH user certificate files ([1737002](https://github.com/sebastian-software/paratix/commit/1737002a395220b22b083a06f0444f11af486b9e))
* **ssh:** trust controller host certificates from known_hosts ([718d0de](https://github.com/sebastian-software/paratix/commit/718d0de2a466853da7526c30d673133b245aa87c))


### Bug Fixes

* **deps:** update russh to 0.65.1 ([#279](https://github.com/sebastian-software/paratix/issues/279)) ([69ae29f](https://github.com/sebastian-software/paratix/commit/69ae29f6f13b8dbbfb96fcee617882f130293ba5))

## [0.24.0](https://github.com/sebastian-software/paratix/compare/ssh-native-v0.23.1...ssh-native-v0.24.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* **paratix:** SSH operations require Linux x64/arm64 (glibc >= 2.35 or musl) or macOS x64/arm64 >= 13.5; Windows is unsupported. Private-key authentication no longer falls back to a password. Configurations combining privateKey with passwordFallback or agentForward are rejected. Agent forwarding requires agent authentication. Native SSH errors include their error code and the final port failure is appended to connection errors. Contributors building the native binding need the pinned Rust toolchain.

* Private key files must be unencrypted PEM or OpenSSH text. DSA (`ssh-dss`), security-key (`sk-*`), binary, corrupt, and unrecognized key files are unsupported. Load passphrase-protected keys into an SSH agent and omit `privateKey`.

### Features

* **paratix:** switch the default SSH transport to the native binding ([#269](https://github.com/sebastian-software/paratix/issues/269)) ([b69ffef](https://github.com/sebastian-software/paratix/commit/b69ffef982fe851f3126399cfcbaa3c5d3a48a7d))
