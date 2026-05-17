import assert from "node:assert/strict"
import { mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, it } from "node:test"
import { pathToFileURL } from "node:url"

import { isDirectExecution, publishWorkspacePackages } from "./publishWorkspacePackages.mjs"

const DEFAULT_STABLE_VERSION = "1.2.3"
const CREATE_PARATIX_NAME = "create-paratix"
const PARATIX_NAME = "paratix"
const CREATE_PARATIX_SPECIFIER = `${CREATE_PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const PARATIX_SPECIFIER = `${PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const BOTH_PACKAGE_SPECIFIERS = [CREATE_PARATIX_SPECIFIER, PARATIX_SPECIFIER]
const BETA_PRERELEASE_VERSION = `${DEFAULT_STABLE_VERSION}-beta.1`
const STABLE_BUILD_METADATA_VERSION = `${DEFAULT_STABLE_VERSION}+build.5`

// R-0000661: the publish flow now reads package.json#files and verifies
// that each entry exists with an mtime newer than the src/ tree. Default
// the in-memory mock filesystem to a healthy state (dist + llm-guide.md
// for paratix, dist for create-paratix, both freshly built) so existing
// tests do not need to wire the new probes; tests that exercise the
// freshness/missing-artefact branches override these defaults via
// `createFs({ paratixFiles, createParatixFiles, mtimes })`.
const FRESH_DIST_MTIME = 2000
const STALE_SOURCE_MTIME = 1000
const DEFAULT_PARATIX_FILES = ["dist", "llm-guide.md"]
const DEFAULT_CREATE_PARATIX_FILES = ["dist"]

function createFs({
  createParatixFiles = DEFAULT_CREATE_PARATIX_FILES,
  createParatixVersion = DEFAULT_STABLE_VERSION,
  mtimes: mtimeOverrides = {},
  paratixFiles = DEFAULT_PARATIX_FILES,
  paratixVersion = DEFAULT_STABLE_VERSION,
} = {}) {
  const defaultMtimes = {
    "packages/create-paratix/dist": FRESH_DIST_MTIME,
    "packages/create-paratix/dist/index.js": FRESH_DIST_MTIME,
    "packages/create-paratix/src": STALE_SOURCE_MTIME,
    "packages/create-paratix/src/index.ts": STALE_SOURCE_MTIME,
    "packages/paratix/dist": FRESH_DIST_MTIME,
    "packages/paratix/dist/index.js": FRESH_DIST_MTIME,
    "packages/paratix/llm-guide.md": FRESH_DIST_MTIME,
    "packages/paratix/src": STALE_SOURCE_MTIME,
    "packages/paratix/src/index.ts": STALE_SOURCE_MTIME,
  }
  const mtimes = { ...defaultMtimes, ...mtimeOverrides }
  const directories = {
    "packages/create-paratix/dist": ["index.js"],
    "packages/create-paratix/src": ["index.ts"],
    "packages/paratix/dist": ["index.js"],
    "packages/paratix/src": ["index.ts"],
  }
  return {
    async readdir(path, options) {
      const entries = directories[path]
      if (!entries) {
        throw Object.assign(new Error(`ENOENT readdir ${path}`), { code: "ENOENT" })
      }
      if (options?.withFileTypes !== true) return [...entries]
      return entries.map((name) => ({
        isDirectory: () => false,
        isFile: () => true,
        isSymbolicLink: () => false,
        name,
      }))
    },
    async readFile(path) {
      if (path === "packages/paratix/package.json") {
        return JSON.stringify({
          files: paratixFiles,
          name: PARATIX_NAME,
          version: paratixVersion,
        })
      }

      if (path === "packages/create-paratix/package.json") {
        return JSON.stringify({
          files: createParatixFiles,
          name: CREATE_PARATIX_NAME,
          version: createParatixVersion,
        })
      }

      throw new Error(`Unexpected path: ${path}`)
    },
    async stat(path) {
      const mtime = mtimes[path]
      if (mtime === undefined) {
        throw Object.assign(new Error(`ENOENT stat ${path}`), { code: "ENOENT" })
      }
      const isDirectory = directories[path] !== undefined
      return {
        isDirectory: () => isDirectory,
        isFile: () => !isDirectory,
        isSymbolicLink: () => false,
        mtimeMs: mtime,
      }
    },
  }
}

function createMissingPackageError() {
  const error = new Error("missing")
  error.stderr = "npm ERR! code E404"
  return error
}

function createCommandRunner(initiallyPublished = new Set(), publishedVersions = {}) {
  const published = new Set(initiallyPublished)
  const calls = []

  return {
    calls,
    async execFile(command, commandArguments) {
      calls.push([command, ...commandArguments])

      const packageSpecifier = commandArguments[1]
      if (published.has(packageSpecifier)) {
        const version = packageSpecifier.slice(packageSpecifier.lastIndexOf("@") + 1)
        return { stdout: JSON.stringify(version) }
      }

      throw createMissingPackageError()
    },
    async spawn(command, commandArguments) {
      calls.push([command, ...commandArguments])
      const directory = commandArguments[1]
      // Use the explicit per-directory version override when provided so
      // tests can simulate publishing arbitrary prerelease/build-metadata
      // versions, falling back to the legacy 1.2.3 specifier so existing
      // tests keep working without touching the helper.
      const isCreateParatix = directory.endsWith(CREATE_PARATIX_NAME)
      const defaultSpecifier = isCreateParatix ? CREATE_PARATIX_SPECIFIER : PARATIX_SPECIFIER
      const versionOverride = isCreateParatix
        ? publishedVersions.createParatix
        : publishedVersions.paratix
      const packageSpecifier =
        versionOverride === undefined
          ? defaultSpecifier
          : `${isCreateParatix ? CREATE_PARATIX_NAME : PARATIX_NAME}@${versionOverride}`
      published.add(packageSpecifier)
    },
  }
}

function hasCommandCall(calls, command) {
  for (const call of calls) {
    if (call[0] === command) return true
  }

  return false
}

async function assertRejectsWithMessage(promise, expectedMessage) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.message.includes(expectedMessage), true)
    return
  }

  assert.fail("Expected promise to reject.")
}

describe("publishWorkspacePackages", () => {
  it("publishes paratix, waits for registry availability, then publishes create-paratix", async () => {
    const commandRunner = createCommandRunner()

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      availabilityRetries: 2,
      commandRunner,
      fs: createFs(),
    })

    assert.deepEqual(commandRunner.calls, [
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      [
        "pnpm",
        "--dir",
        "packages/paratix",
        "publish",
        "--no-git-checks",
        "--provenance",
        "--tag",
        "latest",
      ],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      [
        "pnpm",
        "--dir",
        "packages/create-paratix",
        "publish",
        "--no-git-checks",
        "--provenance",
        "--tag",
        "latest",
      ],
    ])
  })

  it("skips already published packages after verifying paratix is available", async () => {
    const commandRunner = createCommandRunner(new Set(BOTH_PACKAGE_SPECIFIERS))

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      commandRunner,
      fs: createFs(),
    })

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("fails clearly when create-paratix is published without a matching paratix runtime", async () => {
    const commandRunner = createCommandRunner(new Set([CREATE_PARATIX_SPECIFIER]))

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
      }),
      "create-paratix@1.2.3 is already published, but paratix@1.2.3 is not available"
    )
  })

  it("rejects mismatched workspace package versions before publishing", async () => {
    const commandRunner = createCommandRunner()

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        commandRunner,
        fs: createFs({ createParatixVersion: "1.2.4" }),
      }),
      "versions must match"
    )

    assert.equal(commandRunner.calls.length, 0)
  })

  // R-0000660: `pnpm publish` defaults to `--tag latest`, which would silently
  // overwrite the `latest` dist-tag with a prerelease build. Versions
  // containing a SemVer prerelease segment must publish under `next`
  // instead, while stable versions must continue to set `--tag latest`
  // explicitly so the dist-tag intent never depends on pnpm's default.
  it("R-0000660: publishes prerelease versions under --tag next", async () => {
    assertPublishCallsUseDistributionTag({
      expectedTag: "next",
      version: BETA_PRERELEASE_VERSION,
    })
  })

  it("R-0000660: keeps stable versions with build metadata on --tag latest", async () => {
    assertPublishCallsUseDistributionTag({
      expectedTag: "latest",
      version: STABLE_BUILD_METADATA_VERSION,
    })
  })

  // R-0000661: refuse to invoke pnpm publish when dist artefacts referenced
  // by package.json#files are missing. Without the guard, a skipped build
  // would publish empty or stale tarballs under --provenance, and signed
  // bad artefacts cannot easily be retracted from the registry.
  it("R-0000661: aborts when a dist artefact referenced by files is missing", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/paratix/dist": undefined,
        "packages/paratix/dist/index.js": undefined,
      },
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      "package.json#files is missing"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("R-0000661: aborts when a dist artefact mtime is older than the src tree", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/paratix/dist": 500,
        "packages/paratix/dist/index.js": 500,
        "packages/paratix/llm-guide.md": 500,
        "packages/paratix/src": 5000,
        "packages/paratix/src/index.ts": 5000,
      },
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      "is older than"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("R-0000661: aborts when package.json#files is empty", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({ paratixFiles: [] })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      'must declare a "files" allowlist'
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })
})

// R-0000662: the previous direct-execution check normalized only one side
// of the comparison, so invoking the script through a workspace symlink
// (e.g. a pnpm-managed bin shim) compared a non-realpath module URL
// against a realpath argv1 and the publish branch never fired. The test
// constructs a temporary directory tree with a symlinked script and
// verifies that the symlinked invocation still matches the canonical
// module URL.
function createSymlinkedScriptFixture() {
  // Realpath the temp directory before composing child paths so the
  // canonical script path stays stable on platforms where the OS tmpdir
  // already includes symlinks (e.g. macOS `/var/folders` → `/private/var`).
  /* eslint-disable security/detect-non-literal-fs-filename -- Paths are derived from the OS tmpdir; this fixture intentionally creates files under the controlled scratch directory. */
  const temporaryDirectory = realpathSync(mkdtempSync(join(tmpdir(), "publish-script-")))
  const scriptPath = join(temporaryDirectory, "real-script.mjs")
  writeFileSync(scriptPath, "// test fixture", "utf8")
  const symlinkScriptPath = join(temporaryDirectory, "linked-script.mjs")
  symlinkSync(scriptPath, symlinkScriptPath)
  /* eslint-enable security/detect-non-literal-fs-filename */
  return { scriptPath, symlinkScriptPath }
}

describe("isDirectExecution", () => {
  it("returns false when argv1 is null", () => {
    assert.equal(isDirectExecution("file:///some/module.js", null), false)
  })

  it("returns false when argv1 is undefined", () => {
    assert.equal(isDirectExecution("file:///some/module.js", undefined), false)
  })

  it("returns false when the module url does not match argv1", () => {
    assert.equal(isDirectExecution("file:///project/a.mjs", "/project/b.mjs"), false)
  })

  it("returns true when both sides point at the same canonical path", () => {
    const moduleUrl = pathToFileURL("/project/script.mjs").href
    assert.equal(isDirectExecution(moduleUrl, "/project/script.mjs"), true)
  })

  it("R-0000662: returns true when argv1 reaches the script via a symlink", () => {
    const { scriptPath, symlinkScriptPath } = createSymlinkedScriptFixture()
    const moduleUrl = pathToFileURL(scriptPath).href
    // argv1 reaches the script through the symlink shim; the canonical
    // module URL points at the real path. With the old asymmetric
    // implementation the two sides would diverge after realpathSync; the
    // symmetric helper must normalize both sides and still report a match.
    assert.equal(isDirectExecution(moduleUrl, symlinkScriptPath), true)
  })

  it("R-0000662: returns true when the module url uses the symlink path", () => {
    const { scriptPath, symlinkScriptPath } = createSymlinkedScriptFixture()
    const moduleUrl = pathToFileURL(symlinkScriptPath).href
    assert.equal(isDirectExecution(moduleUrl, scriptPath), true)
  })
})

async function assertPublishCallsUseDistributionTag({ expectedTag, version }) {
  const commandRunner = createCommandRunner(new Set(), {
    createParatix: version,
    paratix: version,
  })

  await publishWorkspacePackages({
    availabilityDelayMilliseconds: 0,
    availabilityRetries: 2,
    commandRunner,
    fs: createFs({ createParatixVersion: version, paratixVersion: version }),
  })

  const publishCalls = commandRunner.calls.filter((call) => call[0] === "pnpm")
  assert.equal(publishCalls.length, 2)
  const everyCallHasExpectedTag = publishCalls.every(
    (call) => call.includes("--tag") && call[call.indexOf("--tag") + 1] === expectedTag
  )
  assert.equal(everyCallHasExpectedTag, true)
}
