import assert from "node:assert/strict"
import { mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { describe, it } from "node:test"
import { pathToFileURL } from "node:url"

import { isDirectExecution, publishWorkspacePackages } from "./publishWorkspacePackages.mjs"

// Tests that exercise the local-publish path rely on `publishWorkspacePackages`
// falling back to `process.env` and not seeing any GitHub Actions environment.
// When this suite runs inside GitHub Actions itself those variables leak into
// every call site that does not pass an explicit `environment`, so clear them
// once for the whole test process.
delete process.env.GITHUB_ACTIONS
delete process.env.GITHUB_REF
delete process.env.GITHUB_SHA

const DEFAULT_STABLE_VERSION = "1.2.3"
const CREATE_PARATIX_NAME = "create-paratix"
const PARATIX_NAME = "paratix"
const REPOSITORY_ROOT = dirname(import.meta.dirname)
const CREATE_PARATIX_DIRECTORY = `packages/${CREATE_PARATIX_NAME}`
const PARATIX_DIRECTORY = `packages/${PARATIX_NAME}`
const ABSOLUTE_CREATE_PARATIX_DIRECTORY = join(REPOSITORY_ROOT, CREATE_PARATIX_DIRECTORY)
const ABSOLUTE_PARATIX_DIRECTORY = join(REPOSITORY_ROOT, PARATIX_DIRECTORY)
const ABSOLUTE_PACKAGES_DIRECTORY = join(REPOSITORY_ROOT, "packages")
const RECOVER_CREATE_PARATIX_MODE = "recover-create-paratix"
const CREATE_PARATIX_SPECIFIER = `${CREATE_PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const PARATIX_SPECIFIER = `${PARATIX_NAME}@${DEFAULT_STABLE_VERSION}`
const BOTH_PACKAGE_SPECIFIERS = [CREATE_PARATIX_SPECIFIER, PARATIX_SPECIFIER]
const GIT_HEAD_SHA = "1234567890abcdef"
const GIT_REV_PARSE_HEAD_COMMAND = "rev-parse HEAD"
const GIT_SYMBOLIC_REF_BRANCH_COMMAND = "symbolic-ref --quiet --short HEAD"
const GIT_PREFLIGHT_CALLS = [
  ["git", "rev-parse", "--show-toplevel"],
  ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
  ["git", ...GIT_SYMBOLIC_REF_BRANCH_COMMAND.split(" ")],
]
const BETA_PRERELEASE_VERSION = `${DEFAULT_STABLE_VERSION}-beta.1`
const STABLE_BUILD_METADATA_VERSION = `${DEFAULT_STABLE_VERSION}+build.5`
const PACKAGE_JSON_FILE = "package.json"
const PNPM_LOCK_FILE = "pnpm-lock.yaml"
const TSCONFIG_JSON_FILE = "tsconfig.json"
const TSCONFIG_ROOT_JSON_FILE = "tsconfig.root.json"
const TSCONFIG_TYPECHECK_JSON_FILE = "tsconfig.typecheck.json"
const TSUP_CONFIG_FILE = "tsup.config.ts"
const CREATE_PARATIX_TSCONFIG_PATH = `${CREATE_PARATIX_DIRECTORY}/${TSCONFIG_JSON_FILE}`
const CREATE_PARATIX_TSCONFIG_TYPECHECK_PATH = `${CREATE_PARATIX_DIRECTORY}/${TSCONFIG_TYPECHECK_JSON_FILE}`
const CREATE_PARATIX_TSUP_CONFIG_PATH = `${CREATE_PARATIX_DIRECTORY}/${TSUP_CONFIG_FILE}`
const PARATIX_DIST_DIRECTORY = `${PARATIX_DIRECTORY}/dist`
const PARATIX_TSCONFIG_PATH = `${PARATIX_DIRECTORY}/${TSCONFIG_JSON_FILE}`
const PARATIX_TSCONFIG_TYPECHECK_PATH = `${PARATIX_DIRECTORY}/${TSCONFIG_TYPECHECK_JSON_FILE}`
const PARATIX_TSUP_CONFIG_PATH = `${PARATIX_DIRECTORY}/${TSUP_CONFIG_FILE}`
const STALE_ARTEFACT_MESSAGE_FRAGMENT = "is older than"

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

function createFs(options) {
  const {
    createParatixFiles = DEFAULT_CREATE_PARATIX_FILES,
    createParatixVersion = DEFAULT_STABLE_VERSION,
    mtimes: mtimeOverrides = {},
    paratixFiles = DEFAULT_PARATIX_FILES,
    paratixVersion = DEFAULT_STABLE_VERSION,
    // R-0000685: callers can force `maxMtimeMillisecondsUnder` to fail with
    // an arbitrary error code for a given directory path so tests can
    // exercise the operator-friendly missing-src translation in
    // `verifyDistributionArtefacts`.
    readdirErrors = {},
    // R-0000685: callers can declare a set of paths that report
    // `isSymbolicLink() === true` from lstat so tests can model a vendored
    // source tree behind a symlink (and the matching dist symlinks) and
    // verify that the walker treats both sides identically.
    symlinks: symlinkPaths = [],
  } = options ?? {}
  const defaultMtimes = {
    [CREATE_PARATIX_TSCONFIG_PATH]: STALE_SOURCE_MTIME,
    [CREATE_PARATIX_TSCONFIG_TYPECHECK_PATH]: STALE_SOURCE_MTIME,
    [CREATE_PARATIX_TSUP_CONFIG_PATH]: STALE_SOURCE_MTIME,
    [PACKAGE_JSON_FILE]: STALE_SOURCE_MTIME,
    "packages/create-paratix/dist": FRESH_DIST_MTIME,
    "packages/create-paratix/dist/index.js": FRESH_DIST_MTIME,
    "packages/create-paratix/package.json": STALE_SOURCE_MTIME,
    "packages/create-paratix/src": STALE_SOURCE_MTIME,
    "packages/create-paratix/src/index.ts": STALE_SOURCE_MTIME,
    "packages/paratix/dist/index.js": FRESH_DIST_MTIME,
    "packages/paratix/llm-guide.md": FRESH_DIST_MTIME,
    "packages/paratix/package.json": STALE_SOURCE_MTIME,
    "packages/paratix/src": STALE_SOURCE_MTIME,
    "packages/paratix/src/index.ts": STALE_SOURCE_MTIME,
    [PARATIX_DIST_DIRECTORY]: FRESH_DIST_MTIME,
    [PARATIX_TSCONFIG_PATH]: STALE_SOURCE_MTIME,
    [PARATIX_TSCONFIG_TYPECHECK_PATH]: STALE_SOURCE_MTIME,
    [PARATIX_TSUP_CONFIG_PATH]: STALE_SOURCE_MTIME,
    [PNPM_LOCK_FILE]: STALE_SOURCE_MTIME,
    [TSCONFIG_JSON_FILE]: STALE_SOURCE_MTIME,
    [TSCONFIG_ROOT_JSON_FILE]: STALE_SOURCE_MTIME,
  }
  const mtimes = { ...defaultMtimes, ...mtimeOverrides }
  const directories = {
    "": [
      PACKAGE_JSON_FILE,
      "packages",
      PNPM_LOCK_FILE,
      TSCONFIG_JSON_FILE,
      TSCONFIG_ROOT_JSON_FILE,
    ],
    // R-0000740: the publish flow now performs a drift assertion against
    // the `packages/` directory at startup, so the mock has to surface
    // the workspace package directories alongside the per-package dist/
    // and src/ trees.
    packages: ["create-paratix", "paratix"],
    "packages/create-paratix": [
      "dist",
      PACKAGE_JSON_FILE,
      "src",
      TSCONFIG_JSON_FILE,
      TSCONFIG_TYPECHECK_JSON_FILE,
      TSUP_CONFIG_FILE,
    ],
    "packages/create-paratix/dist": ["index.js"],
    "packages/create-paratix/src": ["index.ts"],
    "packages/paratix": [
      "dist",
      "llm-guide.md",
      PACKAGE_JSON_FILE,
      "src",
      TSCONFIG_JSON_FILE,
      TSCONFIG_TYPECHECK_JSON_FILE,
      TSUP_CONFIG_FILE,
    ],
    "packages/paratix/dist": ["index.js"],
    "packages/paratix/src": ["index.ts"],
  }
  const symlinkSet = new Set(symlinkPaths)
  const calls = []
  const toMockPath = (path) => {
    if (path === REPOSITORY_ROOT) return ""
    return path.startsWith(`${REPOSITORY_ROOT}/`) ? path.slice(REPOSITORY_ROOT.length + 1) : path
  }
  // R-0000740: the drift assertion calls `readdir(path, { withFileTypes: true })`
  // for the `packages/` directory and expects entries whose
  // `isDirectory()` returns true. The default Dirent factory below
  // reports all entries as files, so callers tracking package-level
  // directories register them here.
  const directoryEntries = new Set(Object.keys(directories).filter((path) => path !== ""))
  return {
    calls,
    // R-0000685: lstat reports symbolic-link status without following the
    // link. mtimeMillisecondsForFileEntry now relies on lstat to stay
    // symmetric with maxMtimeMillisecondsUnder, which keys off
    // Dirent.isSymbolicLink() — itself derived from lstat semantics.
    async lstat(path) {
      calls.push(["lstat", path])
      const mockPath = toMockPath(path)
      const mtime = mtimes[mockPath]
      if (mtime === undefined) {
        throw Object.assign(new Error(`ENOENT lstat ${path}`), { code: "ENOENT" })
      }
      const isSymbolicLink = symlinkSet.has(mockPath)
      const isDirectory = !isSymbolicLink && directories[mockPath] !== undefined
      return {
        isDirectory: () => isDirectory,
        isFile: () => !isDirectory && !isSymbolicLink,
        isSymbolicLink: () => isSymbolicLink,
        mtimeMs: mtime,
      }
    },
    async readdir(path, options) {
      calls.push(["readdir", path])
      const mockPath = toMockPath(path)
      const errorCode = readdirErrors[mockPath]
      if (errorCode !== undefined) {
        throw Object.assign(new Error(`${errorCode} readdir ${path}`), { code: errorCode })
      }
      const entries = directories[mockPath]
      if (!entries) {
        throw Object.assign(new Error(`ENOENT readdir ${path}`), { code: "ENOENT" })
      }
      if (options?.withFileTypes !== true) return [...entries]
      return entries.map((name) => {
        const fullPath = `${mockPath}/${name}`
        const isSymbolicLink = symlinkSet.has(fullPath)
        const isDirectory = directoryEntries.has(fullPath)
        return {
          isDirectory: () => isDirectory,
          isFile: () => !isSymbolicLink && !isDirectory,
          isSymbolicLink: () => isSymbolicLink,
          name,
        }
      })
    },
    async readFile(path) {
      calls.push(["readFile", path])
      const mockPath = toMockPath(path)
      if (mockPath === "packages/paratix/package.json") {
        return JSON.stringify({
          files: paratixFiles,
          name: PARATIX_NAME,
          version: paratixVersion,
        })
      }

      if (mockPath === "packages/create-paratix/package.json") {
        return JSON.stringify({
          files: createParatixFiles,
          name: CREATE_PARATIX_NAME,
          version: createParatixVersion,
        })
      }

      throw new Error(`Unexpected path: ${path}`)
    },
    async stat(path) {
      calls.push(["stat", path])
      const mockPath = toMockPath(path)
      const mtime = mtimes[mockPath]
      if (mtime === undefined) {
        throw Object.assign(new Error(`ENOENT stat ${path}`), { code: "ENOENT" })
      }
      const isDirectory = directories[mockPath] !== undefined
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
  return Object.assign(new Error("missing"), { stderr: "npm ERR! code E404" })
}

function createGitCommandHandler({ gitBranch, gitHeadSha, gitRepositoryRoot, gitStatus }) {
  const stdoutByCommand = new Map([
    ["rev-parse --show-toplevel", `${gitRepositoryRoot}\n`],
    ["status --porcelain=v1 --untracked-files=normal", gitStatus],
    [GIT_REV_PARSE_HEAD_COMMAND, `${gitHeadSha}\n`],
    [GIT_SYMBOLIC_REF_BRANCH_COMMAND, `${gitBranch}\n`],
  ])

  return (commandArguments) => {
    const gitCommand = commandArguments.join(" ")
    const stdout = stdoutByCommand.get(gitCommand)
    if (stdout !== undefined) return { stdout }
    throw new Error(`Unexpected git command: ${gitCommand}`)
  }
}

function createCommandRunner(initiallyPublished, publishedVersions, options) {
  const published = new Set(initiallyPublished ?? [])
  const publishedVersionOverrides = publishedVersions ?? {}
  const {
    gitBranch = "main",
    gitHeadSha = GIT_HEAD_SHA,
    gitRepositoryRoot = REPOSITORY_ROOT,
    gitStatus = "",
  } = options ?? {}
  const calls = []
  const execFileOptions = []
  const spawnOptions = []
  const runGitCommand = createGitCommandHandler({
    gitBranch,
    gitHeadSha,
    gitRepositoryRoot,
    gitStatus,
  })

  return {
    calls,
    async execFile(command, commandArguments, options) {
      calls.push([command, ...commandArguments])
      execFileOptions.push({ command, options })

      if (command === "git") {
        return runGitCommand(commandArguments)
      }

      const packageSpecifier = commandArguments[1]
      if (published.has(packageSpecifier)) {
        const version = packageSpecifier.slice(packageSpecifier.lastIndexOf("@") + 1)
        return { stdout: JSON.stringify(version) }
      }

      throw createMissingPackageError()
    },
    execFileOptions,
    async spawn(command, commandArguments, options) {
      calls.push([command, ...commandArguments])
      spawnOptions.push(options)
      const directory = commandArguments[1]
      // Use the explicit per-directory version override when provided so
      // tests can simulate publishing arbitrary prerelease/build-metadata
      // versions, falling back to the legacy 1.2.3 specifier so existing
      // tests keep working without touching the helper.
      const isCreateParatix = directory.endsWith(CREATE_PARATIX_NAME)
      const defaultSpecifier = isCreateParatix ? CREATE_PARATIX_SPECIFIER : PARATIX_SPECIFIER
      const versionOverride = isCreateParatix
        ? publishedVersionOverrides.createParatix
        : publishedVersionOverrides.paratix
      const packageSpecifier =
        versionOverride === undefined
          ? defaultSpecifier
          : `${isCreateParatix ? CREATE_PARATIX_NAME : PARATIX_NAME}@${versionOverride}`
      published.add(packageSpecifier)
    },
    spawnOptions,
  }
}

function hasCommandCall(calls, command) {
  for (const call of calls) {
    if (call[0] === command) return true
  }

  return false
}

function hasGitCommandCall(calls, gitCommand) {
  return calls.some((call) => call[0] === "git" && call.slice(1).join(" ") === gitCommand)
}

function publishDirectories(calls) {
  return calls.filter((call) => call[0] === "pnpm").map((call) => call[2])
}

function npmViewOptions(commandRunner) {
  return commandRunner.execFileOptions
    .filter(({ command }) => command === "npm")
    .map(({ options }) => options)
}

function areAllFilesystemCallsRepositoryAnchored(calls) {
  return calls.every(([, path]) => path.startsWith(REPOSITORY_ROOT))
}

function hasPackagesRootDirectoryRead(calls) {
  return calls.some(
    ([method, path]) => method === "readdir" && path === ABSOLUTE_PACKAGES_DIRECTORY
  )
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
      ...GIT_PREFLIGHT_CALLS,
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["pnpm", "publish", ABSOLUTE_PARATIX_DIRECTORY, "--no-git-checks", "--tag", "latest"],
      ["npm", "view", PARATIX_SPECIFIER, "version", "--json"],
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
      ["pnpm", "publish", ABSOLUTE_CREATE_PARATIX_DIRECTORY, "--no-git-checks", "--tag", "latest"],
      ["npm", "view", CREATE_PARATIX_SPECIFIER, "version", "--json"],
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

  it("anchors filesystem reads and pnpm publish to the repository root from a foreign cwd", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs()
    const originalCwd = process.cwd()
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- Test fixture path is derived from the OS tmpdir.
    const foreignCwd = realpathSync(mkdtempSync(join(tmpdir(), "publish-foreign-cwd-")))
    try {
      process.chdir(foreignCwd)
      await publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        availabilityRetries: 2,
        commandRunner,
        fs,
      })
    } finally {
      process.chdir(originalCwd)
    }

    assert.equal(areAllFilesystemCallsRepositoryAnchored(fs.calls), true)
    assert.equal(hasPackagesRootDirectoryRead(fs.calls), true)
    assert.deepEqual(publishDirectories(commandRunner.calls), [
      ABSOLUTE_PARATIX_DIRECTORY,
      ABSOLUTE_CREATE_PARATIX_DIRECTORY,
    ])
    assert.deepEqual(commandRunner.spawnOptions, [
      { cwd: REPOSITORY_ROOT },
      { cwd: REPOSITORY_ROOT },
    ])
    assert.deepEqual(npmViewOptions(commandRunner), [
      { cwd: REPOSITORY_ROOT },
      { cwd: REPOSITORY_ROOT },
      { cwd: REPOSITORY_ROOT },
      { cwd: REPOSITORY_ROOT },
      { cwd: REPOSITORY_ROOT },
    ])
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

  it("rejects a dirty Git working tree before registry lookups", async () => {
    const commandRunner = createCommandRunner(undefined, undefined, {
      gitStatus: " M scripts/publishWorkspacePackages.mjs\n",
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
      }),
      "dirty Git working tree"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "npm"), false)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("rejects a non-main local Git branch before registry lookups", async () => {
    const commandRunner = createCommandRunner(undefined, undefined, {
      gitBranch: "release-candidate",
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
      }),
      "expected main"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "npm"), false)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("allows a GitHub Actions detached checkout when the ref and SHA match", async () => {
    const commandRunner = createCommandRunner(new Set(BOTH_PACKAGE_SPECIFIERS))

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      commandRunner,
      environment: {
        GITHUB_ACTIONS: "true",
        GITHUB_REF: "refs/heads/main",
        GITHUB_SHA: GIT_HEAD_SHA,
      },
      fs: createFs(),
    })

    assert.equal(hasGitCommandCall(commandRunner.calls, GIT_REV_PARSE_HEAD_COMMAND), true)
    assert.equal(hasGitCommandCall(commandRunner.calls, GIT_SYMBOLIC_REF_BRANCH_COMMAND), false)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("rejects a non-main GitHub Actions ref before registry lookups", async () => {
    const commandRunner = createCommandRunner()

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_REF: "refs/tags/v1.2.3",
          GITHUB_SHA: GIT_HEAD_SHA,
        },
        fs: createFs(),
      }),
      "expected refs/heads/main"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "npm"), false)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("rejects a mismatched GitHub Actions SHA before registry lookups", async () => {
    const commandRunner = createCommandRunner()

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        environment: {
          GITHUB_ACTIONS: "true",
          GITHUB_REF: "refs/heads/main",
          GITHUB_SHA: "different-sha",
        },
        fs: createFs(),
      }),
      "expected checked-out HEAD"
    )

    assert.equal(hasGitCommandCall(commandRunner.calls, GIT_REV_PARSE_HEAD_COMMAND), true)
    assert.equal(hasGitCommandCall(commandRunner.calls, GIT_SYMBOLIC_REF_BRANCH_COMMAND), false)
    assert.equal(hasCommandCall(commandRunner.calls, "npm"), false)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })
})

describe("publishWorkspacePackages recovery mode", () => {
  it("publishes only create-paratix in recovery mode when paratix is already published", async () => {
    const commandRunner = createCommandRunner(new Set([PARATIX_SPECIFIER]))

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      commandRunner,
      fs: createFs(),
      mode: RECOVER_CREATE_PARATIX_MODE,
    })

    assert.deepEqual(publishDirectories(commandRunner.calls), [ABSOLUTE_CREATE_PARATIX_DIRECTORY])
  })

  it("does not check paratix build artefacts when recovering create-paratix", async () => {
    const commandRunner = createCommandRunner(new Set([PARATIX_SPECIFIER]))

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      commandRunner,
      fs: createFs({
        mtimes: {
          "packages/paratix/dist": 500,
          "packages/paratix/dist/index.js": 500,
          "packages/paratix/llm-guide.md": 500,
          "packages/paratix/src": 5000,
          "packages/paratix/src/index.ts": 5000,
        },
      }),
      mode: RECOVER_CREATE_PARATIX_MODE,
    })

    assert.deepEqual(publishDirectories(commandRunner.calls), [ABSOLUTE_CREATE_PARATIX_DIRECTORY])
  })

  it("rejects recovery mode when paratix is not already published", async () => {
    const commandRunner = createCommandRunner()

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
        mode: RECOVER_CREATE_PARATIX_MODE,
      }),
      "Recovery mode requires paratix@1.2.3 to already be published"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("rejects recovery mode when create-paratix is already published", async () => {
    const commandRunner = createCommandRunner(new Set(BOTH_PACKAGE_SPECIFIERS))

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs: createFs(),
        mode: RECOVER_CREATE_PARATIX_MODE,
      }),
      "Recovery mode requires create-paratix@1.2.3 to be missing"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("rejects unsupported publish modes", async () => {
    await assertRejectsWithMessage(
      publishWorkspacePackages({
        fs: createFs(),
        mode: "manual",
      }),
      "Unsupported publish mode"
    )
  })
})

describe("publishWorkspacePackages release validations", () => {
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

  // R-0000861: pnpm publish can exit 0 before the registry exposes the
  // new version. The publish flow must spend the bounded propagation
  // retry budget instead of treating the first missing `npm view` as a
  // hard failure.
  it("R-0000861: retries registry propagation after pnpm publish", async () => {
    const commandRunner = createCommandRunner()
    const defaultExecFile = commandRunner.execFile
    const publishedBySpawn = new Set()
    const viewCounts = new Map()
    commandRunner.execFile = async (command, commandArguments, options) => {
      if (command === "git") return defaultExecFile(command, commandArguments, options)

      commandRunner.calls.push([command, ...commandArguments])
      const packageSpecifier = commandArguments[1]
      const viewCount = (viewCounts.get(packageSpecifier) ?? 0) + 1
      viewCounts.set(packageSpecifier, viewCount)

      const isDelayedParatixAvailability =
        packageSpecifier === PARATIX_SPECIFIER &&
        publishedBySpawn.has(packageSpecifier) &&
        viewCount >= 3
      const isImmediatelyAvailableAfterPublish =
        packageSpecifier === CREATE_PARATIX_SPECIFIER && publishedBySpawn.has(packageSpecifier)
      if (isDelayedParatixAvailability || isImmediatelyAvailableAfterPublish) {
        const version = packageSpecifier.slice(packageSpecifier.lastIndexOf("@") + 1)
        return { stdout: JSON.stringify(version) }
      }

      throw createMissingPackageError()
    }
    commandRunner.spawn = async (command, commandArguments) => {
      commandRunner.calls.push([command, ...commandArguments])
      const directory = commandArguments[1]
      publishedBySpawn.add(
        directory.endsWith(CREATE_PARATIX_NAME) ? CREATE_PARATIX_SPECIFIER : PARATIX_SPECIFIER
      )
    }

    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      availabilityRetries: 3,
      commandRunner,
      fs: createFs(),
    })

    assert.equal(viewCounts.get(PARATIX_SPECIFIER), 3)
    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), true)
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

  it("R-0000661: aborts when a create-paratix dist artefact is missing", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/create-paratix/dist/index.js": undefined,
      },
    })

    let caught
    try {
      await publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      })
    } catch (error) {
      caught = error
    }

    assert.ok(caught, "publishWorkspacePackages should reject")
    assert.equal(caught.message.includes(CREATE_PARATIX_NAME), true, caught.message)
    assert.equal(caught.message.includes("is missing"), true, caught.message)
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
      STALE_ARTEFACT_MESSAGE_FRAGMENT
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("aborts when dist output is older than a build configuration input", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/paratix/dist/index.js": 500,
        [PARATIX_DIST_DIRECTORY]: 500,
        [PARATIX_TSUP_CONFIG_PATH]: 5000,
      },
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      STALE_ARTEFACT_MESSAGE_FRAGMENT
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  it("aborts when stale dist output is masked by a fresh non-built file", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/paratix/dist": 9000,
        "packages/paratix/dist/index.js": 500,
        "packages/paratix/llm-guide.md": 9000,
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

  // R-0000862: top-level package.json#files entries must be materialised
  // artefacts. A symlinked files entry would be treated as mtime 0 by the
  // freshness walker and could let a package with no real publish
  // artefact slip through when the source side is also skipped as a
  // symlink. Reject it before any registry side effect.
  it("R-0000862: aborts when a package.json#files entry is a symlink", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      mtimes: {
        "packages/paratix/dist": 9999,
        "packages/paratix/src": STALE_SOURCE_MTIME,
        "packages/paratix/src/index.ts": 9999,
      },
      symlinks: ["packages/paratix/dist", "packages/paratix/src/index.ts"],
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        availabilityRetries: 2,
        commandRunner,
        fs,
      }),
      "referenced by package.json#files is a symbolic link"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  // R-0000685: a missing `src/` directory previously leaked the raw
  // ENOENT from `readdir` ("ENOENT readdir packages/paratix/src"). The
  // operator-friendly translation has to mention the directory and the
  // remediation ("run pnpm build") so the message is actionable.
  it("R-0000685: surfaces an operator-friendly error when src/ is missing", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      readdirErrors: {
        "packages/paratix/src": "ENOENT",
      },
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      "packages/paratix/src is missing — run pnpm build before publishing"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  // R-0000685: a non-ENOENT readdir failure (EACCES, EIO) on src/ has to
  // surface the same build-before-publishing remediation so the message
  // stays consistent regardless of the underlying filesystem error.
  it("R-0000685: maps non-ENOENT src/ failures to the same remediation", async () => {
    const commandRunner = createCommandRunner()
    const fs = createFs({
      readdirErrors: {
        "packages/paratix/src": "EACCES",
      },
    })

    await assertRejectsWithMessage(
      publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      }),
      "Run pnpm build before publishing"
    )

    assert.equal(hasCommandCall(commandRunner.calls, "pnpm"), false)
  })

  // R-0000862: the symlink rejection must happen before the freshness
  // comparison, so even a symlinked dist entry beside a newer regular
  // source tree gets a direct fail-closed diagnostic instead of a stale
  // mtime explanation.
  it("R-0000862: rejects symlinked files entries before freshness comparison", async () => {
    const commandRunner = createCommandRunner()
    const symlinkedDistributionPath = "packages/paratix/dist"
    const fs = createFs({
      mtimes: {
        "packages/paratix/src": STALE_SOURCE_MTIME,
        "packages/paratix/src/index.ts": 5000,
        // dist is a symlink → mtime 0; src has a fresh regular file so the
        // source mtime walks past 0.
        [symlinkedDistributionPath]: 9999,
      },
      symlinks: [symlinkedDistributionPath],
    })

    let caught
    try {
      await publishWorkspacePackages({
        availabilityDelayMilliseconds: 0,
        commandRunner,
        fs,
      })
    } catch (error) {
      caught = error
    }

    assert.ok(caught, "publishWorkspacePackages should reject")
    assert.equal(
      caught.message.includes("referenced by package.json#files is a symbolic link"),
      true,
      caught.message
    )
    assert.equal(caught.message.includes(symlinkedDistributionPath), true, caught.message)
    assert.equal(caught.message.includes("Materialize"), true, caught.message)
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
