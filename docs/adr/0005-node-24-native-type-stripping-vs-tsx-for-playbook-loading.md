# 0005 - Node 24 Native Type Stripping vs. tsx for Playbook Loading

## Status

Accepted - ADR only; no production swap in this step. The native-first loader is prepared as a
follow-up and will be enabled only after the integration suite passes.

## Context

Issue: sebastian-software/paratix#84
Epic: sebastian-software/paratix#97

`paratix` includes `tsx` (`^4.22.3`) as a **production dependency**. At runtime, `tsx` requires
`esbuild` (`~0.28.0`), including platform-specific binaries. `tsx` is used at exactly one runtime
location: `packages/paratix/src/cli.ts:569` lazily imports `tsx/esm/api` and calls `register()` to
make `.ts`/`.mts`/`.cts` playbooks loadable through a global ESM loader hook
(`loadServerDefinitionFromFile`, `registerTsxForTypeScriptEntry`).

`paratix` already requires `engines.node >= 24.0.0`. Node has enabled native type stripping for
`.ts` files by default since v22.18.0 / v23.6.0 (`--experimental-strip-types` is enabled by
default; `--no-strip-types` disables it). Native stripping is therefore available without a flag
on every runtime supported by `paratix` (>= 24). `--experimental-transform-types`, which handles
non-erasable syntax such as `enum`/`namespace`, remains opt-in.

This raises the question: Can native stripping replace `tsx` when loading scaffolded playbooks and
remove the approximately 20 MB esbuild footprint from every `paratix` installation?

## Analysis

### What `pnpm create paratix` Generates

- `packages/create-paratix/src/templates.ts` generates exactly one `server.ts` per project, in
  either the root-bootstrap or admin variant.
- The generated code uses **only erasable syntax**: bare-specifier imports
  (`import { … } from "paratix"`, `… from "paratix/modules"`), `const` declarations, object
  literals, and function calls. It contains **no** type annotations, `enum`s, `namespace`s,
  decorators, parameter properties, or relative `.ts` imports.
- The generated `tsconfig.json` (`TSCONFIG_TEMPLATE`) uses `moduleResolution: "Bundler"` but has
  **no** `paths` mapping. There is therefore no alias resolution that would be unsupported at
  runtime by either native stripping or `tsx`.
- The generated `package.json` (`scaffoldFiles.ts`) continues to list `tsx` as a devDependency of
  the target project, alongside `typescript`, `eslint`, and `prettier`, independently of the
  `paratix` production dependency.

### Practical Verification (Node 26.3.1, This Worktree)

Both rendered template variants were imported natively with a stub `paratix` package, **without
`tsx` and without flags**:

- Root variant: `import()` succeeded; `default.run` contained 11 modules.
- Admin variant: `import()` succeeded; `default.run` contained 10 modules.
- Control test with `--no-strip-types`: `.ts` produced `ERR_UNKNOWN_FILE_EXTENSION`, confirming
  that native stripping is the enabling mechanism.
- `templates.ts` itself, including union types and type annotations, was also stripped and run
  natively.

**Result: Scaffolded playbooks are fully compatible with native type stripping.**

### Verified Limits of Native Stripping

Native stripping mode rejects syntax that `tsx` (esbuild) transforms:

- `enum` -> `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` (a reliable, unambiguous discriminator).
- Extensionless relative import (`import … from "./dep"`) -> `ERR_MODULE_NOT_FOUND`.
- A `.js` specifier that points to `./dep.ts` (`import … from "./dep.js"`) ->
  `ERR_MODULE_NOT_FOUND`.

The two `ERR_MODULE_NOT_FOUND` cases are **not** unambiguously distinguishable from a genuinely
missing dependency, such as a typo or an uninstalled npm package.

### Verified Fallback Mechanics (Node 26.3.1)

The test sequence was "try native loading first; on failure, call `tsx.register()` and import the
same URL again":

- `enum.ts`: native loading failed with `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`; retrying after
  `tsx.register()` **succeeded** because Node did not cache the compilation error.
- `.js` -> `.ts` import: native loading failed with `ERR_MODULE_NOT_FOUND`; retrying after
  `tsx.register()` **succeeded**.

Mechanically, the native-first loader with a `tsx` fallback therefore works for both error classes
on Node 26.

### Footprint Measurement (This Worktree, pnpm Store)

| Artifact                                         | Size                          |
| ------------------------------------------------ | ----------------------------- |
| `tsx@4.22.4`                                     | 668 KB                        |
| `esbuild@0.28.1` (JS)                            | ~10 MB                        |
| `@esbuild/darwin-arm64@0.28.1` (platform binary) | ~10 MB                        |
| **Total `tsx` runtime closure (one platform)**   | **~20.6 MB per installation** |

This amount is currently added to **every** `paratix` installation as a production dependency.
The footprint benefit exists **only** if `tsx` is removed or moved to `optionalDependencies`. If
`tsx` remains a mandatory fallback, the benefit is zero.

## Decision

1. Feasibility is established for the default case: **native stripping fully supports scaffolded
   playbooks** (no `tsx`, no flag, Node >= 24).
2. This step makes **no production code change** to playbook loading and **no** change to the
   `paratix` dependencies.
3. The native-first loader will be prepared as a follow-up and **enabled only after the integration
   suite passes**. According to Issue #84, that suite is the actual gate and could not be run in
   this environment because Docker/Colima was unavailable.

## Rationale

Playbook loading is a security- and reliability-sensitive core function. Despite the demonstrated
feasibility, risks remain that can be covered **only** by the Docker-backed integration suite and
cannot be proven conclusively by local `pnpm agent:check`, unit tests, or dist tests:

- **Node 24 floor untested:** All measurements used Node 26.3.1, while the supported lower bound is
  Node 24. Module-cache behavior after failed loads and stripping details have historically varied
  across Node minor releases. Fallback recovery must be verified on an actual Node 24.x runtime.
- **Error masking on the `ERR_MODULE_NOT_FOUND` path:** Falling back on
  `ERR_MODULE_NOT_FOUND` can obscure a genuinely missing dependency behind a `tsx` retry. If
  `tsx`, as an optional dependency, is not installed, the user receives the misleading "install
  tsx" message (`handleTsxLoadFailure`) instead of the correct "module not found" diagnosis. A
  narrower approach that falls back only on `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` avoids this issue
  but turns extensionless and `.js` -> `.ts` imports into hard failures.
- **Duplicate top-level execution:** If a native import fails only after partially evaluating the
  module graph, the `tsx` retry executes side-effectful top-level code again. Playbooks are mostly
  declarative (`server({…})`) but can contain top-level statements such as `isFirstRun()`, so
  duplicate execution cannot be ruled out without E2E coverage.
- **The actual gate is unavailable here:** Without the integration suite, a swap in the core
  loading path cannot be verified conclusively. The conservative rule for this core path is not to
  enable the change when in doubt.

Because the footprint benefit necessarily depends on moving `tsx` to `optionalDependencies`, and
that exact change affects both the core loading path and its error path, a swap without a passing
integration suite would be irresponsible. Feasibility is established; approval is not.

## Recommended Follow-up (Enable Only with an Integration Gate)

1. In `loadServerDefinitionFromFile`/`registerTsxForTypeScriptEntry`, try native
   `import(fileUrl)` first for TypeScript entries; do **not** register `tsx` in advance.
2. Fall back conservatively only on `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`, the unambiguous
   discriminator: call `tsx.register()` and retry the same `fileUrl` once.
   `ERR_MODULE_NOT_FOUND` initially remains a hard, honest error to avoid masking the diagnosis.
   Extend support for extensionless and `.js` -> `.ts` imports only after adding explicit
   integration coverage.
3. Move `tsx` from `dependencies` to `optionalDependencies` in `packages/paratix/package.json`.
   The existing `isMissingTsxDependencyError`/`handleTsxLoadFailure` path already covers the "tsx
   not installed" message.
4. Gate: `agent:check:integration` (Docker/Colima) must pass on Node 24.x **and** Node 26.x,
   including scenarios for scaffolded playbooks, the `enum` fallback, and missing-dependency
   diagnostics. Measure and document the footprint again before and after the change.

## Source

- Issue sebastian-software/paratix#84 - replace tsx with Node 24 native type stripping (remove the
  approximately 10 MB production `esbuild` dependency).
- Epic sebastian-software/paratix#97.
- Runtime usage: `packages/paratix/src/cli.ts:569` (`import("tsx/esm/api")`),
  `loadServerDefinitionFromFile` / `registerTsxForTypeScriptEntry`.
- Scaffold: `packages/create-paratix/src/templates.ts`,
  `packages/create-paratix/src/scaffoldFiles.ts`.
