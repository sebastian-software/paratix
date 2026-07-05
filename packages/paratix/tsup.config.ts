import { execSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "tsup"

const packageJsonPath = resolve(import.meta.dirname, "package.json")
// eslint-disable-next-line security/detect-non-literal-fs-filename -- build-time config: path is statically resolved from import.meta.dirname
const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, "utf8"))
// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- build-time config: package.json always has version
const { version } = packageJson as { version: string }

function resolveGitShortHash(cwd: string): string {
  try {
    return execSync("git rev-parse --short HEAD", {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim()
  } catch {
    return ""
  }
}

const gitShortHash = resolveGitShortHash(import.meta.dirname)
const displayVersion = gitShortHash === "" ? version : `${version}-${gitShortHash}`

const sharedDefine = {
  PACKAGE_DISPLAY_VERSION: JSON.stringify(displayVersion),
  PACKAGE_VERSION: JSON.stringify(version),
}

// R-0000729: split the previous single-build config into two passes so the
// `#!/usr/bin/env node` shebang only lands on the CLI bundle. The original
// single-build configuration applied the banner globally and enabled
// `splitting: true` for ESM. Two consequences broke the postbuild dist
// tests:
//
// 1) Every library entry (`dist/index.js`, `dist/modules/index.js`) gained
//    a stray shebang. Node tolerates it on the executable, but a downstream
//    consumer importing the package via `import "paratix"` ended up with an
//    unusual first line that some bundlers and TS analyzers flagged.
// 2) `splitting: true` shared chunks between the CLI and the library
//    entries. Because `cli.ts` performs a top-level
//    `await program.parseAsync()` inside an `isDirectCliExecution` guard,
//    splitting let that side-effect surface anywhere the shared chunk was
//    imported — including the library entry under tests. Top-level await in
//    a chunk that the library re-imports also delayed dynamic import in the
//    consumer-pack test.
//
// The fix below builds the CLI as a single self-contained bundle (no
// splitting, banner applied) and emits the library entries in a second
// pass without the banner. This keeps the CLI executable as a plain
// `#!/usr/bin/env node` script and turns the library output back into
// clean ESM that consumers can dynamic-import without dragging the CLI
// lifecycle along.
export default defineConfig([
  {
    banner: { js: "#!/usr/bin/env node" },
    clean: true,
    define: sharedDefine,
    dts: false,
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    // #75: ship no source maps in the published tarball. They are useless at
    // runtime for a CLI tool and previously accounted for ~70% of the package.
    sourcemap: false,
    splitting: false,
    target: "node24",
  },
  {
    clean: false,
    define: sharedDefine,
    dts: true,
    entry: {
      index: "src/index.ts",
      "modules/index": "src/modules/index.ts",
    },
    format: ["esm"],
    // #75: ship no source maps in the published tarball. They are useless at
    // runtime for a CLI tool and previously accounted for ~70% of the package.
    sourcemap: false,
    // R-0000729: keep splitting on so the shared module surface lives in a
    // single chunk and `paratix` / `paratix/modules` re-export the very
    // same function references. The dist tests assert object identity
    // (`packageApi[name] === moduleApi[name]`), which requires the two
    // entries to share a chunk. The `cli.ts` `import.meta.url` reference
    // is no longer pulled into the library bundle because `isFirstRun`
    // now ships from the dedicated `firstRunContext` module.
    splitting: true,
    target: "node24",
  },
])
