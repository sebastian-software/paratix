import { execFile, spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import {
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises"
import { basename, dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { promisify } from "node:util"

import {
  assertNoWorkspaceSpecifiers,
  inspectPlatformTarball,
  inspectSshNativeTarball,
  inspectWorkspaceTarball,
  readTarGzEntries,
  tarballIntegrity,
} from "./publishArtefacts.mjs"
import {
  nativeBinaryFileName,
  platformPackageName,
  prepareStagingRoot,
  readNativeInputs,
  SSH_NATIVE_PACKAGE_NAME,
  SSH_NATIVE_TARGETS,
  stageNativePackages,
  verifyNativeArtifacts,
} from "./publishNativeStaging.mjs"
import {
  assertNativeSourcesUnchangedSince,
  assertNpmOidcSource,
  assertTrustedPublishing,
  readPublishedProvenance,
} from "./publishRegistry.mjs"

const execFileAsync = promisify(execFile)
const SCRIPT_DIRECTORY = import.meta.dirname
const REPOSITORY_ROOT = dirname(SCRIPT_DIRECTORY)

function readEnvironmentAvailabilityRetries() {
  const rawValue = process.env.PARATIX_PUBLISH_AVAILABILITY_RETRIES
  if (rawValue == null || rawValue === "") return
  const parsedValue = Number.parseInt(rawValue, 10)
  if (!Number.isFinite(parsedValue) || parsedValue <= 0) return
  return parsedValue
}

// The first native release exceeded the former ~4 min propagation budget:
// npm accepted darwin-arm64, but exposed it only after the job had stopped.
// Allow ~15 min per package before publishing its dependents. The publish
// job timeout covers all nine sequential waits. Operators can still override
// this budget with PARATIX_PUBLISH_AVAILABILITY_RETRIES.
const DEFAULT_AVAILABILITY_RETRIES = readEnvironmentAvailabilityRetries() ?? 90
const DEFAULT_AVAILABILITY_DELAY_MS = 10_000
const PACKAGE_JSON_FILE = "package.json"
const TSUP_CONFIG_FILE = "tsup.config.ts"

// R-0000740: the publish order between paratix and create-paratix is
// load-bearing (paratix must be available on the registry before
// create-paratix can resolve its peer at install time), so we keep the
// list static. To prevent silent drift when a new workspace package is
// added to packages/ without being reflected here, we cross-check the
// static list against the actual `packages/` directory listing at
// startup. An unexpected entry — or a missing one — aborts the publish
// flow before any registry side effects.
const PACKAGES_ROOT_DIRECTORY = join(REPOSITORY_ROOT, "packages")
const PACKAGES_ROOT_DISPLAY_DIRECTORY = "packages"
const SSH_NATIVE_DISPLAY_DIRECTORY = "packages/ssh-native"

const PACKAGE_KIND_LOADER = "loader"
const PACKAGE_KIND_PLATFORM = "platform"
const PACKAGE_KIND_WORKSPACE = "workspace"

// #255 B3: nine packages are released together with one linked version, in
// this fixed publish order: the six platform packages (they carry the
// smoke-tested binaries), the @paratix/ssh-native loader that references
// them as optionalDependencies, then paratix and create-paratix (R-0000740
// order). Every package is installable once all its predecessors are.
// #257: `linkedDependencyNames` are workspace packages of the same linked
// release that a source manifest may reference as exactly `workspace:*`;
// the packed manifest must then pin them to the exact release version.
const releasePackageDeclarations = [
  ...SSH_NATIVE_TARGETS.map((target) => ({
    declaredName: platformPackageName(target),
    displayDirectory: `${SSH_NATIVE_DISPLAY_DIRECTORY}/npm/${target}`,
    kind: PACKAGE_KIND_PLATFORM,
    target,
  })),
  {
    declaredName: SSH_NATIVE_PACKAGE_NAME,
    displayDirectory: SSH_NATIVE_DISPLAY_DIRECTORY,
    kind: PACKAGE_KIND_LOADER,
  },
  {
    declaredName: "paratix",
    displayDirectory: "packages/paratix",
    kind: PACKAGE_KIND_WORKSPACE,
    linkedDependencyNames: [SSH_NATIVE_PACKAGE_NAME],
  },
  {
    declaredName: "create-paratix",
    displayDirectory: "packages/create-paratix",
    kind: PACKAGE_KIND_WORKSPACE,
    linkedDependencyNames: [SSH_NATIVE_PACKAGE_NAME],
  },
]

// R-0000740 / #255 B3: the workspace package directories under packages/.
// packages/ssh-native is a published package since #255 B3 (its platform
// packages live below it in npm/<target>), so there is no longer a list of
// known but unpublished directories.
const declaredPackageDirectories = [
  "packages/paratix",
  "packages/create-paratix",
  SSH_NATIVE_DISPLAY_DIRECTORY,
]

const PUBLISH_MODE_RELEASE = "release"
const PUBLISH_MODE_VERIFY = "verify"
const REMOVED_PUBLISH_MODE_RECOVER_CREATE_PARATIX = "recover-create-paratix"
const PUBLISH_MODES = new Set([PUBLISH_MODE_RELEASE, PUBLISH_MODE_VERIFY])

function validatePublishMode(mode) {
  if (PUBLISH_MODES.has(mode)) return mode
  // #255 B3: the release mode resumes any partial release (including
  // "paratix published, create-paratix missing") with provenance and
  // trusted-publishing checks, so the dedicated recovery mode is gone.
  if (mode === REMOVED_PUBLISH_MODE_RECOVER_CREATE_PARATIX) {
    throw new Error(
      `Publish mode ${JSON.stringify(mode)} was removed. Run the "${PUBLISH_MODE_RELEASE}" mode instead: ` +
        "it skips versions already published by publish.yml (after verifying their provenance) and " +
        "publishes the missing packages in order."
    )
  }
  throw new Error(
    `Unsupported publish mode ${JSON.stringify(mode)}. Expected one of: ${[...PUBLISH_MODES].join(", ")}.`
  )
}

// R-0000830: refuse to publish when any entry in packages/ is a symbolic
// link. Symlinks under packages/ usually indicate a developer testing
// setup (e.g. linking a local checkout into the workspace) or an
// accidental include of an external tree. Publishing through a symlink
// would resolve to whatever the link currently targets, which can ship
// unintended files or expose a path outside the repository. Detect this
// before any registry side effect so the operator gets a clear
// diagnostic instead of an unexplained tarball.
function assertNoWorkspacePackageSymlinks(entries) {
  const symbolicLinkEntries = entries
    .filter((entry) => entry.isSymbolicLink())
    .map((entry) => entry.name)
  if (symbolicLinkEntries.length === 0) return
  throw new Error(
    `Refusing to publish: ${PACKAGES_ROOT_DISPLAY_DIRECTORY}/ contains symbolic links (${symbolicLinkEntries.join(", ")}). ` +
      "Remove the symlinks (e.g. unlink a development checkout) and re-run the publish script."
  )
}

function assertWorkspacePackageDirectoriesMatch(entries) {
  const filesystemDirectories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  const declaredDirectories = declaredPackageDirectories
    .map((displayDirectory) => displayDirectory.replace(/^packages\//v, ""))
    .sort()
  const filesystemSet = new Set(filesystemDirectories)
  const declaredSet = new Set(declaredDirectories)
  const missing = declaredDirectories.filter((name) => !filesystemSet.has(name))
  const unexpected = filesystemDirectories.filter((name) => !declaredSet.has(name))
  if (missing.length === 0 && unexpected.length === 0) return
  const details = []
  if (missing.length > 0) {
    details.push(`missing from filesystem: ${missing.join(", ")}`)
  }
  if (unexpected.length > 0) {
    details.push(`not declared in publishWorkspacePackages.mjs: ${unexpected.join(", ")}`)
  }
  throw new Error(
    `Workspace package drift detected (${details.join("; ")}). ` +
      "Update scripts/publishWorkspacePackages.mjs to reflect the actual packages/ contents before publishing."
  )
}

async function assertWorkspacePackagesMatchFilesystem(fs) {
  const entries = await fs.readdir(PACKAGES_ROOT_DIRECTORY, { withFileTypes: true })
  assertNoWorkspacePackageSymlinks(entries)
  assertWorkspacePackageDirectoriesMatch(entries)
}

function sleep(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds)
  })
}

async function readPackageJson(directory, fs = { readFile }) {
  const rawPackageJson = await fs.readFile(join(directory, PACKAGE_JSON_FILE), "utf8")
  const packageJson = JSON.parse(rawPackageJson)

  if (
    typeof packageJson !== "object" ||
    packageJson === null ||
    typeof packageJson.name !== "string" ||
    typeof packageJson.version !== "string"
  ) {
    throw new Error(`${directory}/package.json must contain a package name and version.`)
  }

  // R-0000661: capture the `files` allowlist so the publish prelude can
  // confirm every artefact npm would ship actually exists and is at least
  // as fresh as the source tree. The `files` field is optional in npm but
  // mandatory for our workspace packages — an empty/missing list would
  // publish a tarball without any dist artefacts at all.
  const files = Array.isArray(packageJson.files)
    ? packageJson.files.filter((value) => typeof value === "string")
    : []

  return {
    directory,
    displayDirectory: directory,
    files,
    manifest: packageJson,
    name: packageJson.name,
    version: packageJson.version,
  }
}

function normalizeNpmViewVersion(stdout) {
  const trimmedOutput = stdout.trim()
  if (trimmedOutput.startsWith('"') && trimmedOutput.endsWith('"')) {
    return JSON.parse(trimmedOutput)
  }

  return trimmedOutput
}

function isMissingPackageVersion(error) {
  const output = `${error.stdout ?? ""}\n${error.stderr ?? ""}`
  return output.includes("E404") || output.includes("No match found for version")
}

async function isPublished({ commandRunner, packageName, repositoryRoot, version }) {
  try {
    const { stdout } = await commandRunner.execFile(
      "npm",
      ["view", `${packageName}@${version}`, "version", "--json"],
      { cwd: repositoryRoot }
    )
    return normalizeNpmViewVersion(stdout) === version
  } catch (error) {
    if (isMissingPackageVersion(error)) return false
    throw error
  }
}

async function gitStdout(commandRunner, commandArguments, repositoryRoot) {
  const { stdout } = await commandRunner.execFile("git", commandArguments, {
    cwd: repositoryRoot,
  })
  return stdout.trim()
}

async function assertPublishGitRoot(commandRunner, repositoryRoot) {
  const actualRepositoryRoot = await gitStdout(
    commandRunner,
    ["rev-parse", "--show-toplevel"],
    repositoryRoot
  )
  if (normalizeExecutionPath(actualRepositoryRoot) === normalizeExecutionPath(repositoryRoot))
    return
  throw new Error(
    `Refusing to publish from ${actualRepositoryRoot}; expected repository root ${repositoryRoot}.`
  )
}

async function assertPublishGitCleanTree(commandRunner, repositoryRoot) {
  const status = await gitStdout(
    commandRunner,
    ["status", "--porcelain=v1", "--untracked-files=normal"],
    repositoryRoot
  )
  if (status === "") return
  throw new Error("Refusing to publish from a dirty Git working tree.")
}

function isGithubActions(environment) {
  return environment.GITHUB_ACTIONS === "true"
}

async function assertGithubActionsPublishReference(commandRunner, environment, repositoryRoot) {
  const expectedReference = "refs/heads/main"
  if (environment.GITHUB_REF !== expectedReference) {
    throw new Error(
      `Refusing to publish from GitHub ref ${environment.GITHUB_REF}; expected ${expectedReference}.`
    )
  }

  const headSha = await gitStdout(commandRunner, ["rev-parse", "HEAD"], repositoryRoot)
  if (environment.GITHUB_SHA === headSha) return
  throw new Error(
    `Refusing to publish from GitHub SHA ${environment.GITHUB_SHA}; expected checked-out HEAD ${headSha}.`
  )
}

async function assertLocalPublishReference(commandRunner, repositoryRoot) {
  let branchName
  try {
    branchName = await gitStdout(
      commandRunner,
      ["symbolic-ref", "--quiet", "--short", "HEAD"],
      repositoryRoot
    )
  } catch (error) {
    throw new Error("Refusing to publish from a detached HEAD outside GitHub Actions.", {
      cause: error,
    })
  }

  if (branchName === "main") return
  throw new Error(`Refusing to publish from Git branch ${branchName}; expected main.`)
}

async function assertPublishGitPreflight({ commandRunner, environment, repositoryRoot }) {
  await assertPublishGitRoot(commandRunner, repositoryRoot)
  await assertPublishGitCleanTree(commandRunner, repositoryRoot)
  if (isGithubActions(environment)) {
    await assertGithubActionsPublishReference(commandRunner, environment, repositoryRoot)
    return
  }

  await assertLocalPublishReference(commandRunner, repositoryRoot)
}

async function waitForPublishedPackage(parameters, attempt = 1) {
  const { commandRunner, packageName, repositoryRoot, version } = parameters
  const retries = parameters.retries ?? DEFAULT_AVAILABILITY_RETRIES
  const delayMilliseconds = parameters.delayMilliseconds ?? DEFAULT_AVAILABILITY_DELAY_MS

  if (await isPublished({ commandRunner, packageName, repositoryRoot, version })) return

  if (attempt >= retries) {
    throw new Error(
      `${packageName}@${version} was not visible in the npm registry after ${retries} attempts. ` +
        `Re-run the release once ${packageName}@${version} is visible on the registry; the release ` +
        "mode then verifies the provenance of the already published packages and publishes the rest. " +
        "Set PARATIX_PUBLISH_AVAILABILITY_RETRIES to extend the wait budget further if needed."
    )
  }

  console.log(
    `${packageName}@${version} is not visible in the npm registry yet; retrying in ${delayMilliseconds}ms.`
  )
  await sleep(delayMilliseconds)
  await waitForPublishedPackage(parameters, attempt + 1)
}

// R-0000660: `npm publish` defaults to the `latest` dist-tag regardless of
// any prerelease suffix on the version, so a 1.2.3-beta.1 publish would
// silently overwrite the `latest` tag and offer an unstable build to every
// `pnpm install paratix` user. Inspect the version for a SemVer prerelease
// component (the segment after the first `-`, before any `+build` metadata)
// and pin the dist-tag accordingly: prereleases publish under `next`,
// stable versions explicitly under `latest`.
//
// The split mirrors `isValidSemverVersion` in
// packages/create-paratix/src/dependencyRange.ts: SemVer 2.0.0 separates
// the prerelease (after `-`) from the build metadata (after `+`), and the
// dist-tag decision must look at the prerelease, not at the (rarely used)
// build metadata. Stripping the build segment first keeps the check
// resilient to versions like `1.2.3+build.5` or `1.2.3-rc.1+sha.abc`.
function hasPrereleaseSuffix(version) {
  const buildSeparatorIndex = version.indexOf("+")
  const withoutBuild = buildSeparatorIndex === -1 ? version : version.slice(0, buildSeparatorIndex)
  return withoutBuild.includes("-")
}

function publishDistributionTag(version) {
  return hasPrereleaseSuffix(version) ? "next" : "latest"
}

// R-0000727: format a walker error so the operator sees the failing
// path alongside the underlying error code and the standard "run pnpm
// build before publishing" remediation. The wrapper keeps the `cause`
// chain intact so the original stack stays available for debugging,
// but the message is consistent regardless of whether the failure
// surfaces from readdir, stat or lstat.
function buildWalkerErrorMessage(packageName, path, error) {
  const code = error?.code
  if (code === "ENOENT") {
    return `${packageName}: ${path} is missing — run pnpm build before publishing.`
  }
  const reason = error?.message ?? String(error)
  return `${packageName}: failed to read ${path} (${reason}). Run pnpm build before publishing.`
}

function rethrowWalkerError(packageName, path, error) {
  throw new Error(buildWalkerErrorMessage(packageName, path, error), { cause: error })
}

// R-0000661: maximum mtime captured under `directory`. Walking the tree
// (rather than stat-ing the directory itself) is necessary because
// directory mtimes only change when entries are added/removed, not when
// the contents of existing files are edited. The recursion follows
// regular files only and skips symlinks so a malicious symlink under
// the directory cannot stat its target and lift the dist freshness bar.
//
// R-0000727: translate raw readdir/stat failures into operator-friendly
// messages with the failing path and the build-before-publishing
// remediation. The caller threads `packageName` through so missing
// `src/`, missing `dist/` subtrees, and EACCES/EIO errors all surface
// with the same shape ("<package>: <path> is missing — run pnpm build").
async function maxMtimeMillisecondsUnder(packageName, directory, filesystem) {
  let entries
  try {
    entries = await filesystem.readdir(directory, { withFileTypes: true })
  } catch (error) {
    rethrowWalkerError(packageName, directory, error)
  }
  const childMtimes = await Promise.all(
    entries.map(async (entry) => {
      if (entry.isSymbolicLink()) return 0
      const entryPath = join(directory, entry.name)
      if (entry.isDirectory()) {
        // Recurse so deep edits (e.g. `src/modules/<module>.ts`) are visible.
        return maxMtimeMillisecondsUnder(packageName, entryPath, filesystem)
      }
      if (!entry.isFile()) return 0
      try {
        const stats = await filesystem.stat(entryPath)
        return stats.mtimeMs
      } catch (error) {
        rethrowWalkerError(packageName, entryPath, error)
      }
    })
  )
  return childMtimes.length > 0 ? Math.max(...childMtimes) : 0
}

async function minMtimeMillisecondsUnder(packageName, directory, filesystem) {
  let entries
  try {
    entries = await filesystem.readdir(directory, { withFileTypes: true })
  } catch (error) {
    rethrowWalkerError(packageName, directory, error)
  }
  const childResults = await Promise.all(
    entries.map(async (entry) => {
      const entryPath = join(directory, entry.name)
      if (entry.isSymbolicLink()) {
        return { minMtime: 0, regularFileCount: 0, symlinkedEntries: [entryPath] }
      }
      if (entry.isDirectory()) {
        return minMtimeMillisecondsUnder(packageName, entryPath, filesystem)
      }
      if (!entry.isFile()) return { minMtime: Infinity, regularFileCount: 0, symlinkedEntries: [] }
      try {
        const stats = await filesystem.stat(entryPath)
        return { minMtime: stats.mtimeMs, regularFileCount: 1, symlinkedEntries: [] }
      } catch (error) {
        rethrowWalkerError(packageName, entryPath, error)
      }
    })
  )
  const regularFileCount = childResults.reduce(
    (count, result) => count + result.regularFileCount,
    0
  )
  const symlinkedEntries = childResults.flatMap((result) => result.symlinkedEntries)
  const minMtime = Math.min(...childResults.map((result) => result.minMtime))
  return {
    minMtime: Number.isFinite(minMtime) ? minMtime : 0,
    regularFileCount,
    symlinkedEntries,
  }
}

function isBuildArtefactFilesEntry(fileEntry) {
  return fileEntry === "dist" || fileEntry.startsWith("dist/")
}

async function minMtimeMillisecondsForBuildArtefacts({
  directory,
  files,
  filesystem,
  packageName,
}) {
  const buildArtefactEntries = files.filter((fileEntry) => isBuildArtefactFilesEntry(fileEntry))
  const fileResults = await Promise.all(
    buildArtefactEntries.map(async (fileEntry) => {
      const absolutePath = join(directory, fileEntry)
      const linkStats = await filesystem.lstat(absolutePath)
      if (linkStats.isSymbolicLink()) {
        return { minMtime: 0, regularFileCount: 0, symlinkedEntries: [absolutePath] }
      }
      if (linkStats.isDirectory()) {
        return minMtimeMillisecondsUnder(packageName, absolutePath, filesystem)
      }
      return { minMtime: linkStats.mtimeMs, regularFileCount: 1, symlinkedEntries: [] }
    })
  )
  const regularFileCount = fileResults.reduce((count, result) => count + result.regularFileCount, 0)
  const symlinkedEntries = fileResults.flatMap((result) => result.symlinkedEntries)
  const minMtime = Math.min(...fileResults.map((result) => result.minMtime))
  return {
    minMtime: Number.isFinite(minMtime) ? minMtime : 0,
    regularFileCount,
    symlinkedEntries,
  }
}

async function assertFilesEntryIsPublishable(packageInfo, fileEntry, filesystem) {
  const absolutePath = join(packageInfo.directory, fileEntry)
  const displayPath = join(packageInfo.displayDirectory, fileEntry)
  let linkStats
  try {
    linkStats = await filesystem.lstat(absolutePath)
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${packageInfo.name}: ${fileEntry} referenced by package.json#files is missing under ${packageInfo.displayDirectory}. Run the build before publishing.`,
        { cause: error }
      )
    }
    throw error
  }
  if (linkStats.isSymbolicLink()) {
    throw new Error(
      `${packageInfo.name}: ${displayPath} referenced by package.json#files is a symbolic link. Materialize the built artefact before publishing.`
    )
  }
}

function isTypeScriptConfigFile(fileName) {
  return (
    fileName === "tsconfig.json" || (fileName.startsWith("tsconfig.") && fileName.endsWith(".json"))
  )
}

async function typeScriptConfigFilesUnder(packageName, directory, filesystem) {
  let entries
  try {
    entries = await filesystem.readdir(directory, { withFileTypes: true })
  } catch (error) {
    rethrowWalkerError(packageName, directory, error)
  }
  return entries
    .filter((entry) => entry.isFile() && isTypeScriptConfigFile(entry.name))
    .map((entry) => join(directory, entry.name))
}

async function mtimeMillisecondsForFile(packageName, path, filesystem) {
  let stats
  try {
    stats = await filesystem.lstat(path)
  } catch (error) {
    rethrowWalkerError(packageName, path, error)
  }
  if (stats.isSymbolicLink()) return 0
  if (!stats.isFile()) return 0
  return stats.mtimeMs
}

async function readBuildInputMtime(packageInfo, sourceDirectory, filesystem) {
  const packageConfigPaths = [
    join(packageInfo.directory, PACKAGE_JSON_FILE),
    join(packageInfo.directory, TSUP_CONFIG_FILE),
  ]
  const rootBuildInputPaths = [
    join(REPOSITORY_ROOT, PACKAGE_JSON_FILE),
    join(REPOSITORY_ROOT, "pnpm-lock.yaml"),
  ]
  const buildInputPaths = [
    ...packageConfigPaths,
    ...(await typeScriptConfigFilesUnder(packageInfo.name, packageInfo.directory, filesystem)),
    ...rootBuildInputPaths,
    ...(await typeScriptConfigFilesUnder(packageInfo.name, REPOSITORY_ROOT, filesystem)),
  ]
  const inputMtimes = await Promise.all(
    buildInputPaths.map((path) => mtimeMillisecondsForFile(packageInfo.name, path, filesystem))
  )
  const sourceMtime = await maxMtimeMillisecondsUnder(packageInfo.name, sourceDirectory, filesystem)
  return Math.max(sourceMtime, ...inputMtimes)
}

// R-0000661: confirm every artefact npm would ship actually exists and is
// at least as fresh as the source tree and build inputs before npm
// publish runs. Without this guard a skipped build would publish empty
// or stale dist files under `--provenance`, which cannot easily be
// retracted from the registry once the manifest is signed.
async function verifyDistributionArtefacts(packageInfo, filesystem) {
  if (packageInfo.files.length === 0) {
    throw new Error(
      `${packageInfo.displayDirectory}/package.json must declare a "files" allowlist before publish.`
    )
  }

  await Promise.all(
    packageInfo.files.map((fileEntry) =>
      assertFilesEntryIsPublishable(packageInfo, fileEntry, filesystem)
    )
  )

  const sourceDirectory = join(packageInfo.directory, "src")
  const sourceMtime = await readBuildInputMtime(packageInfo, sourceDirectory, filesystem)
  const {
    minMtime: buildArtefactsMtime,
    regularFileCount,
    symlinkedEntries,
  } = await minMtimeMillisecondsForBuildArtefacts({
    directory: packageInfo.directory,
    files: packageInfo.files,
    filesystem,
    packageName: packageInfo.name,
  })
  if (regularFileCount === 0 || buildArtefactsMtime < sourceMtime) {
    throw new Error(
      buildStaleArtefactMessage({
        buildArtefactsMtime,
        packageInfo,
        sourceMtime,
        symlinkedEntries,
      })
    )
  }
}

// R-0000728: explain a stale-freshness verdict that was triggered by a
// symlinked artefact. The freshness check skips symlinks for safety
// (an attacker-planted link could otherwise stat its target and lift
// the dist mtime bar past the source tree), so a legitimate operator
// who symlinked a top-level `files` entry would see a confusing
// "mtime older than src" verdict even when the linked artefact is
// newer. Surfacing the symlinked paths plus the materialise-before-
// publishing remediation makes the trigger obvious without weakening
// the safety guarantee.
function buildStaleArtefactMessage({
  buildArtefactsMtime,
  packageInfo,
  sourceMtime,
  symlinkedEntries,
}) {
  const baseMessage =
    `${packageInfo.name}: build artefact mtime (${new Date(buildArtefactsMtime).toISOString()}) is ` +
    `older than ${packageInfo.displayDirectory} build input mtime (${new Date(sourceMtime).toISOString()}). ` +
    `Run the build before publishing.`
  if (symlinkedEntries.length === 0) return baseMessage
  const formattedEntries = symlinkedEntries.join(", ")
  return (
    `${baseMessage} The freshness check treats symlinks as mtime 0 for safety, so the comparison ` +
    `tripped because the following package.json#files entries are symlinks rather than regular ` +
    `artefacts: ${formattedEntries}. Materialize these artefacts (replace the link with the ` +
    `built file) before publishing.`
  )
}

// #255 B3: runs `callback` for each item strictly one after another (the
// publish order is load-bearing) and collects the results.
async function mapSequentially(items, callback, results = []) {
  if (results.length === items.length) return results
  results.push(await callback(items[results.length]))
  return mapSequentially(items, callback, results)
}

function packageLabel(releasePackage) {
  return `${releasePackage.name}@${releasePackage.version}`
}

async function readReleasePackages(fs) {
  return Promise.all(
    releasePackageDeclarations.map(async (declaration) => ({
      ...(await readPackageJson(join(REPOSITORY_ROOT, declaration.displayDirectory), fs)),
      ...declaration,
    }))
  )
}

function assertPlatformManifest(releasePackage) {
  const binaryFileName = nativeBinaryFileName(releasePackage.target)
  const { files, main } = releasePackage.manifest
  const hasExactFiles = Array.isArray(files) && files.length === 1 && files[0] === binaryFileName
  if (hasExactFiles && main === binaryFileName) return
  throw new Error(
    `${releasePackage.displayDirectory}/package.json must declare "files": ["${binaryFileName}"] and "main": "${binaryFileName}".`
  )
}

// #255 B3: all nine manifests must carry their exact names, one shared
// version (release-please linked versions), exact platform `files` and no
// `workspace:` specifier before anything is staged or packed. #257: the one
// exception is `workspace:*` for a declared linked dependency.
function validateReleasePackages(releasePackages) {
  const unexpectedPackage = releasePackages.find(
    (releasePackage) => releasePackage.name !== releasePackage.declaredName
  )
  if (unexpectedPackage !== undefined) {
    throw new Error(
      `${unexpectedPackage.directory}/package.json has unexpected package name ${unexpectedPackage.name}.`
    )
  }

  const versions = new Set(releasePackages.map((releasePackage) => releasePackage.version))
  if (versions.size !== 1) {
    throw new Error(
      `Release package versions must match before publishing (${releasePackages.map((releasePackage) => packageLabel(releasePackage)).join(", ")}).`
    )
  }

  for (const releasePackage of releasePackages) {
    if (releasePackage.kind === PACKAGE_KIND_PLATFORM) assertPlatformManifest(releasePackage)
    assertNoWorkspaceSpecifiers(
      releasePackage.manifest,
      `${releasePackage.displayDirectory}/package.json`,
      { linkedDependencyNames: releasePackage.linkedDependencyNames ?? [] }
    )
  }
}

function tarballFileName({ name, version }) {
  return `${name.replace(/^@/v, "").replace("/", "-")}-${version}.tgz`
}

function inspectReleaseTarball(packedPackage, { artifacts, platformNames }) {
  const entries = readTarGzEntries(packedPackage.tarball)
  const { kind, name, target, version } = packedPackage
  if (kind === PACKAGE_KIND_PLATFORM) {
    inspectPlatformTarball(entries, {
      binaryFileName: nativeBinaryFileName(target),
      expectedSha256: artifacts.get(target).sha256,
      name,
      version,
    })
    return
  }
  if (kind === PACKAGE_KIND_LOADER) {
    inspectSshNativeTarball(entries, { name, platformNames, version })
    return
  }
  inspectWorkspaceTarball(entries, {
    linkedDependencyNames: packedPackage.linkedDependencyNames ?? [],
    name,
    sourceManifest: packedPackage.manifest,
    version,
  })
}

// #255 B3: packs with `pnpm pack --out <absolute path>` (the staged copy for
// the seven native packages, the package directory for paratix and
// create-paratix), then inspects the real tarball and records its npm
// integrity. The registry later receives exactly this file.
async function packReleasePackage({ context, packDirectory, releasePackage }) {
  const { artifacts, commandRunner, fs, platformNames, staging } = context
  const tarballPath = join(staging.tarballDirectory, tarballFileName(releasePackage))
  console.log(`Packing ${packageLabel(releasePackage)} into ${tarballPath}.`)
  await commandRunner.execFile("pnpm", ["pack", "--out", tarballPath], { cwd: packDirectory })
  const tarball = await fs.readFile(tarballPath)
  const packedPackage = {
    ...releasePackage,
    integrity: tarballIntegrity(tarball),
    tarball,
    tarballPath,
  }
  inspectReleaseTarball(packedPackage, { artifacts, platformNames })
  return packedPackage
}

async function stageReleasePackages({ artifacts, fs, releasePackages, staging }) {
  return stageNativePackages({
    artifacts,
    fs,
    loaderPackage: releasePackages.find(
      (releasePackage) => releasePackage.kind === PACKAGE_KIND_LOADER
    ),
    platformPackages: releasePackages.filter(
      (releasePackage) => releasePackage.kind === PACKAGE_KIND_PLATFORM
    ),
    staging,
  })
}

// #255 B3: common steps of both modes, all before any registry write:
// drift check, manifest validation, dist freshness, artifact checksums,
// staging outside the repository, packing and tarball inspection.
async function prepareReleaseTarballs({ commandRunner, environment, filesystem, fs }) {
  // R-0000740: assert the static package list matches the actual
  // `packages/` directory contents before reading any package.json so a
  // new workspace package added without updating this script aborts the
  // publish flow with a clear diagnostic instead of being silently
  // skipped.
  await assertWorkspacePackagesMatchFilesystem(fs)
  const releasePackages = await readReleasePackages(fs)
  validateReleasePackages(releasePackages)

  // R-0000661: verify the dist artefacts before issuing the first npm
  // publish so a missing or stale artefact never produces a half-published
  // workspace. Only paratix and create-paratix have a tsup build; the
  // native packages are checked against the CI artifact checksums instead.
  await Promise.all(
    releasePackages
      .filter((releasePackage) => releasePackage.kind === PACKAGE_KIND_WORKSPACE)
      .map((releasePackage) => verifyDistributionArtefacts(releasePackage, filesystem))
  )

  const artifacts = await verifyNativeArtifacts({ ...readNativeInputs(environment), fs })
  const staging = await prepareStagingRoot({ environment, fs, repositoryRoot: REPOSITORY_ROOT })
  console.log(`Staging release packages in ${staging.stagingRoot}.`)
  console.log(`Release tarball directory: ${staging.tarballDirectory}`)
  const stagedDirectories = await stageReleasePackages({ artifacts, fs, releasePackages, staging })
  const context = {
    artifacts,
    commandRunner,
    fs,
    platformNames: SSH_NATIVE_TARGETS.map((target) => platformPackageName(target)),
    staging,
  }
  const packedPackages = await mapSequentially(releasePackages, (releasePackage) =>
    packReleasePackage({
      context,
      packDirectory: stagedDirectories.get(releasePackage.name) ?? releasePackage.directory,
      releasePackage,
    })
  )
  return { packedPackages, staging }
}

async function classifyPackages({ commandRunner, packedPackages }) {
  return mapSequentially(packedPackages, async (packedPackage) => ({
    ...packedPackage,
    published: await isPublished({
      commandRunner,
      packageName: packedPackage.name,
      repositoryRoot: REPOSITORY_ROOT,
      version: packedPackage.version,
    }),
  }))
}

function verificationSummaryMarkdown(rows, tarballDirectory) {
  const tableRows = rows.map(
    (row) =>
      `| ${row.name} | ${row.version} | ${basename(row.tarballPath)} | \`${row.integrity}\` | ${row.published ? "already published" : "new"} |`
  )
  return [
    "### Release tarballs",
    "",
    `Tarball directory: \`${tarballDirectory}\``,
    "",
    "| Package | Version | Tarball | Integrity | npm |",
    "| --- | --- | --- | --- | --- |",
    ...tableRows,
    "",
  ].join("\n")
}

// #255 B3: verify mode packs and inspects all nine tarballs and reports
// which versions are new on npm. No Git preflight, no OIDC, no publish.
async function reportVerification({ commandRunner, environment, fs, packedPackages, staging }) {
  const rows = await classifyPackages({ commandRunner, packedPackages })
  for (const row of rows) {
    console.log(
      `${packageLabel(row)}: ${basename(row.tarballPath)} ${row.integrity} (${row.published ? "already published" : "new"})`
    )
  }
  const newCount = rows.filter((row) => !row.published).length
  console.log(
    `Verified ${rows.length} release tarballs: ${newCount} new, ${rows.length - newCount} already published. ` +
      `Tarballs: ${staging.tarballDirectory}`
  )
  const summaryPath = environment.GITHUB_STEP_SUMMARY
  if (summaryPath == null || summaryPath === "") return
  await fs.appendFile(summaryPath, verificationSummaryMarkdown(rows, staging.tarballDirectory))
}

// #255 B3: generalizes the former "create-paratix published but paratix
// missing" guard. A release only ever progresses along the fixed order, so
// a published package behind a missing one means foreign registry writes.
function assertPublishOrderConsistency(classifiedPackages) {
  const firstMissingIndex = classifiedPackages.findIndex(
    (packedPackage) => !packedPackage.published
  )
  if (firstMissingIndex === -1) return
  const laterPublished = classifiedPackages
    .slice(firstMissingIndex + 1)
    .filter((packedPackage) => packedPackage.published)
  if (laterPublished.length === 0) return
  throw new Error(
    `${laterPublished.map((packedPackage) => packageLabel(packedPackage)).join(", ")} ` +
      `${laterPublished.length === 1 ? "is" : "are"} already published, but ` +
      `${packageLabel(classifiedPackages[firstMissingIndex])} is not available although it precedes ` +
      "them in the publish order. Investigate the registry state manually before retrying."
  )
}

// #255 B3: resume rule for a version that is already on npm. Its provenance
// must name publish.yml on main of this repository. A version from this
// very workflow run must be byte-identical to the local tarball. For the
// seven native packages, a version from an earlier run is only accepted
// while the binary inputs (packages/ssh-native and the ssh-native.yml build
// matrix) are unchanged since its source commit, so already published
// binaries never mix with binaries built from different sources. paratix and
// create-paratix contain no binary; their earlier-run versions are skipped on
// valid provenance alone, as before B3.
async function assertResumablePublishedPackage(
  { commandRunner, environment, fetch },
  packedPackage
) {
  const label = packageLabel(packedPackage)
  const provenance = await readPublishedProvenance({
    commandRunner,
    fetch,
    name: packedPackage.name,
    repositoryRoot: REPOSITORY_ROOT,
    version: packedPackage.version,
  })
  const currentRunId = environment.GITHUB_RUN_ID
  if (currentRunId != null && currentRunId !== "" && provenance.runId === String(currentRunId)) {
    if (provenance.integrity !== packedPackage.integrity) {
      throw new Error(
        `${label} was published earlier in this workflow run, but its registry integrity ` +
          `${provenance.integrity} differs from the local tarball ${packedPackage.integrity}. ` +
          'A "Re-run all jobs" rebuilds the native binaries, which are not bit-identical; use ' +
          '"Re-run failed jobs" instead, or start a new release run on main (the earlier-run rule ' +
          "then applies)."
      )
    }
    console.log(`${label} was already published by this workflow run; skipping publish.`)
    return
  }
  if (packedPackage.kind === PACKAGE_KIND_WORKSPACE) {
    console.log(
      `${label} was already published by workflow run ${provenance.runId} from ${provenance.commit}; skipping publish.`
    )
    return
  }
  await assertNativeSourcesUnchangedSince({
    commandRunner,
    commit: provenance.commit,
    label,
    repositoryRoot: REPOSITORY_ROOT,
  })
  console.log(
    `${label} was already published by workflow run ${provenance.runId} from ${provenance.commit}; ` +
      "its binary inputs are unchanged since then; skipping publish."
  )
}

async function publishReleaseTarball(
  { availabilityDelayMilliseconds, availabilityRetries, commandRunner },
  packedPackage
) {
  const distributionTag = publishDistributionTag(packedPackage.version)
  console.log(`Publishing ${packageLabel(packedPackage)} under --tag ${distributionTag}.`)
  await commandRunner.spawn(
    "npm",
    [
      "publish",
      packedPackage.tarballPath,
      "--provenance",
      "--access",
      "public",
      "--tag",
      distributionTag,
    ],
    { cwd: REPOSITORY_ROOT }
  )

  // R-0000861: registry propagation can lag behind a successful
  // `npm publish`. Use the bounded availability wait after every new
  // publish instead of aborting on the first missing `npm view` result,
  // so transient propagation delays get the same retry budget that
  // protects the publish order.
  await waitForPublishedPackage({
    commandRunner,
    delayMilliseconds: availabilityDelayMilliseconds,
    packageName: packedPackage.name,
    repositoryRoot: REPOSITORY_ROOT,
    retries: availabilityRetries,
    version: packedPackage.version,
  })
}

// #255 B3: release mode. Every check (Git preflight, classification, order
// consistency, provenance of published versions, npm source check and the
// OIDC exchange for every missing package) completes before the first
// `npm publish`; only then are the missing packages published in order.
async function runRelease(context) {
  const { commandRunner, environment, fetch, fs, packedPackages, workflowCommands } = context
  await assertPublishGitPreflight({ commandRunner, environment, repositoryRoot: REPOSITORY_ROOT })
  const classifiedPackages = await classifyPackages({ commandRunner, packedPackages })
  assertPublishOrderConsistency(classifiedPackages)
  await mapSequentially(
    classifiedPackages.filter((packedPackage) => packedPackage.published),
    (packedPackage) => assertResumablePublishedPackage(context, packedPackage)
  )
  const missingPackages = classifiedPackages.filter((packedPackage) => !packedPackage.published)
  if (missingPackages.length === 0) {
    console.log(`All ${classifiedPackages.length} release packages are already published.`)
    return
  }
  await assertNpmOidcSource({ commandRunner, fs, repositoryRoot: REPOSITORY_ROOT })
  await mapSequentially(missingPackages, (packedPackage) =>
    assertTrustedPublishing({ environment, fetch, name: packedPackage.name, workflowCommands })
  )
  await mapSequentially(missingPackages, (packedPackage) =>
    publishReleaseTarball(context, packedPackage)
  )
}

function spawnInherited(command, commandArguments, spawnOptions) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArguments, {
      cwd: REPOSITORY_ROOT,
      ...spawnOptions,
      stdio: "inherit",
    })
    child.on("error", reject)
    child.on("exit", (code) => {
      if (code === 0) {
        resolve(undefined)
        return
      }

      reject(new Error(`${command} ${commandArguments.join(" ")} failed with exit code ${code}.`))
    })
  })
}

const defaultFileSystem = {
  appendFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
}

export async function publishWorkspacePackages(options) {
  const {
    availabilityDelayMilliseconds,
    availabilityRetries,
    commandRunner = { execFile: execFileAsync, spawn: spawnInherited },
    environment = process.env,
    fetch = globalThis.fetch,
    fs = defaultFileSystem,
    filesystem = fs,
    mode = PUBLISH_MODE_RELEASE,
    workflowCommands = { write: (text) => process.stdout.write(text) },
  } = options ?? {}
  const publishMode = validatePublishMode(mode)
  const { packedPackages, staging } = await prepareReleaseTarballs({
    commandRunner,
    environment,
    filesystem,
    fs,
  })

  if (publishMode === PUBLISH_MODE_VERIFY) {
    await reportVerification({ commandRunner, environment, fs, packedPackages, staging })
    return
  }

  await runRelease({
    availabilityDelayMilliseconds,
    availabilityRetries,
    commandRunner,
    environment,
    fetch,
    fs,
    packedPackages,
    workflowCommands,
  })
}

// R-0000662: resolve a filesystem path through `realpathSync` with a safe
// fallback to the lexical resolution so symlinked invocations still
// compare equal. Mirrors `normalizeExecutionPath` in
// packages/create-paratix/src/directExecution.ts so the
// direct-execution check stays symmetric between the two sides.
function normalizeExecutionPath(path) {
  const resolvedPath = resolve(path)
  try {
    return realpathSync.native(resolvedPath)
  } catch {
    return resolvedPath
  }
}

// R-0000662: the previous implementation compared `fileURLToPath(moduleUrl)`
// directly against `realpathSync(argv1)`, so a workspace symlink that
// pointed at the script (e.g. when pnpm installed it via a hoisted bin
// shim) would normalize one side but not the other and the publish
// branch would never fire. Normalize both sides through the same helper
// so symlinked and non-symlinked invocations behave identically. Exported
// so the regression test in publishWorkspacePackages.test.mjs can exercise
// the comparison without spawning the script.
export function isDirectExecution(moduleUrl, argv1) {
  if (argv1 == null) return false
  try {
    return normalizeExecutionPath(fileURLToPath(moduleUrl)) === normalizeExecutionPath(argv1)
  } catch {
    return false
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await publishWorkspacePackages({ mode: process.argv[2] ?? PUBLISH_MODE_RELEASE })
}
