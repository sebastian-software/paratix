# Changelog

## [0.24.0](https://github.com/sebastian-software/paratix/compare/ssh-native-v0.23.1...ssh-native-v0.24.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* **paratix:** SSH operations require Linux x64/arm64 (glibc >= 2.35 or musl) or macOS x64/arm64 >= 13.5; Windows is unsupported. Private-key authentication no longer falls back to a password. Configurations combining privateKey with passwordFallback or agentForward are rejected. Agent forwarding requires agent authentication. Native SSH errors include their error code and the final port failure is appended to connection errors. Contributors building the native binding need the pinned Rust toolchain.

### Features

* **paratix:** switch the default SSH transport to the native binding ([#269](https://github.com/sebastian-software/paratix/issues/269)) ([b69ffef](https://github.com/sebastian-software/paratix/commit/b69ffef982fe851f3126399cfcbaa3c5d3a48a7d))
