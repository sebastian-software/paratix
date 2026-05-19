import { execFile, spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import { lstat, readdir, readFile, stat } from "node:fs/promises"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

function readEnvironmentAvailabilityRetries() {
  const rawValue = process.env.PARATIX_PUBLISH_AVAILABILITY_RETRIES
  if (rawValue == null || rawValue === "") return
  const parsedValue = Number.parseInt(rawValue, 10)
  if (!Number.isFinite(parsedValue) || parsedValue <= 0) return
  return parsedValue
}

// R-0000501: doubled the prior 12 × 10s (= 2 min) budget to ~4 min so the
// registry has enough time to expose paratix before we attempt to publish
// create-paratix. Operators can override the value via
// PARATIX_PUBLISH_AVAILABILITY_RETRIES when the registry is unusually slow.
const DEFAULT_AVAILABILITY_RETRIES = readEnvironmentAvailabilityRetries() ?? 24
const DEFAULT_AVAILABILITY_DELAY_MS = 10_000

// R-0000740: the publish order between paratix and create-paratix is
// load-bearing (paratix must be available on the registry before
// create-paratix can resolve its peer at install time), so we keep the
// list static. To prevent silent drift when a new workspace package is
// added to packages/ without being reflected here, we cross-check the
// static list against the actual `packages/` directory listing at
// startup. An unexpected entry — or a missing one — aborts the publish
// flow before any registry side effects.
const PACKAGES_ROOT_DIRECTORY = "packages"

const packages = [
  { directory: "packages/paratix", name: "paratix" },
  { directory: "packages/create-paratix", name: "create-paratix" },
]

const PUBLISH_MODE_RECOVER_CREATE_PARATIX = "recover-create-paratix"
const PUBLISH_MODE_RELEASE = "release"
const PUBLISH_MODES = new Set([PUBLISH_MODE_RECOVER_CREATE_PARATIX, PUBLISH_MODE_RELEASE])

function validatePublishMode(mode) {
  if (PUBLISH_MODES.has(mode)) return mode
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
    `Refusing to publish: ${PACKAGES_ROOT_DIRECTORY}/ contains symbolic links (${symbolicLinkEntries.join(", ")}). ` +
      "Remove the symlinks (e.g. unlink a development checkout) and re-run the publish script."
  )
}

function assertWorkspacePackageDirectoriesMatch(entries) {
  const filesystemDirectories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  const declaredDirectories = packages
    .map((packageInfo) => packageInfo.directory.replace(/^packages\//v, ""))
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
  // The other fs accessors in this script consume relative paths
  // (`packages/<name>/package.json`), so we keep the same convention
  // here for symmetry with the existing test mocks.
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
  const rawPackageJson = await fs.readFile(join(directory, "package.json"), "utf8")
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
    files,
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

async function isPublished(packageName, version, commandRunner) {
  try {
    const { stdout } = await commandRunner.execFile("npm", [
      "view",
      `${packageName}@${version}`,
      "version",
      "--json",
    ])
    return normalizeNpmViewVersion(stdout) === version
  } catch (error) {
    if (isMissingPackageVersion(error)) return false
    throw error
  }
}

async function waitForPublishedPackage(parameters, attempt = 1) {
  const { commandRunner, packageName, version } = parameters
  const retries = parameters.retries ?? DEFAULT_AVAILABILITY_RETRIES
  const delayMilliseconds = parameters.delayMilliseconds ?? DEFAULT_AVAILABILITY_DELAY_MS

  if (await isPublished(packageName, version, commandRunner)) return

  if (attempt >= retries) {
    throw new Error(
      `${packageName}@${version} was not visible in the npm registry after ${retries} attempts. ` +
        `Re-run this script once ${packageName}@${version} is visible on the registry; the existing ` +
        "manual-recovery branch will then resume and publish create-paratix automatically. " +
        "Set PARATIX_PUBLISH_AVAILABILITY_RETRIES to extend the wait budget further if needed."
    )
  }

  console.log(
    `${packageName}@${version} is not visible in the npm registry yet; retrying in ${delayMilliseconds}ms.`
  )
  await sleep(delayMilliseconds)
  await waitForPublishedPackage(parameters, attempt + 1)
}

// R-0000660: `pnpm publish` defaults to the `latest` dist-tag regardless of
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
  let linkStats
  try {
    linkStats = await filesystem.lstat(absolutePath)
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${packageInfo.name}: ${fileEntry} referenced by package.json#files is missing under ${packageInfo.directory}. Run the build before publishing.`,
        { cause: error }
      )
    }
    throw error
  }
  if (linkStats.isSymbolicLink()) {
    throw new Error(
      `${packageInfo.name}: ${absolutePath} referenced by package.json#files is a symbolic link. Materialize the built artefact before publishing.`
    )
  }
}

// R-0000685: translate raw filesystem failures from the source-tree
// walk into an operator-friendly hint. The pre-existing handler only
// covered the case where `files` referenced a missing path; a missing
// `src/` directory leaked the bare ENOENT from `readdir`, which is not
// obvious unless the operator already knows that the freshness check
// walks `src/`. Map every error from the source walk to the same
// build-before-publishing remediation so the message is consistent.
//
// R-0000727: the underlying walker now translates failures inline via
// `rethrowWalkerError`, so this wrapper only needs to invoke the
// recursion. Keeping the helper around documents the intent and gives
// the verifyDistributionArtefacts call site a recognisable seam.
async function readSourceMtime(packageInfo, sourceDirectory, filesystem) {
  return maxMtimeMillisecondsUnder(packageInfo.name, sourceDirectory, filesystem)
}

// R-0000661: confirm every artefact npm would ship actually exists and is
// at least as fresh as the source tree before pnpm publish runs. Without
// this guard a skipped build would publish empty or stale dist files under
// `--provenance`, which cannot easily be retracted from the registry once
// the manifest is signed.
async function verifyDistributionArtefacts(packageInfo, filesystem) {
  if (packageInfo.files.length === 0) {
    throw new Error(
      `${packageInfo.directory}/package.json must declare a "files" allowlist before publish.`
    )
  }

  await Promise.all(
    packageInfo.files.map((fileEntry) =>
      assertFilesEntryIsPublishable(packageInfo, fileEntry, filesystem)
    )
  )

  const sourceDirectory = join(packageInfo.directory, "src")
  const sourceMtime = await readSourceMtime(packageInfo, sourceDirectory, filesystem)
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
    `older than ${packageInfo.directory}/src mtime (${new Date(sourceMtime).toISOString()}). ` +
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

async function publishPackage({
  availabilityDelayMilliseconds,
  availabilityRetries,
  commandRunner,
  packageInfo,
}) {
  if (await isPublished(packageInfo.name, packageInfo.version, commandRunner)) {
    console.log(
      `${packageInfo.name}@${packageInfo.version} is already published; skipping publish.`
    )
    return
  }

  const distributionTag = publishDistributionTag(packageInfo.version)
  console.log(
    `Publishing ${packageInfo.name}@${packageInfo.version} under --tag ${distributionTag}.`
  )
  await commandRunner.spawn("pnpm", [
    "--dir",
    packageInfo.directory,
    "publish",
    "--no-git-checks",
    "--provenance",
    "--tag",
    distributionTag,
  ])

  // R-0000861: registry propagation can lag behind a successful
  // `pnpm publish`. Use the bounded availability wait after every new
  // publish instead of aborting on the first missing `npm view` result,
  // so transient propagation delays get the same retry budget that
  // protects the paratix -> create-paratix publish order.
  await waitForPublishedPackage({
    commandRunner,
    delayMilliseconds: availabilityDelayMilliseconds,
    packageName: packageInfo.name,
    retries: availabilityRetries,
    version: packageInfo.version,
  })
}

async function recoverCreateParatixPackage({
  availabilityDelayMilliseconds,
  availabilityRetries,
  commandRunner,
  createParatixPackage,
  paratixPackage,
}) {
  const paratixPublished = await isPublished(
    paratixPackage.name,
    paratixPackage.version,
    commandRunner
  )
  const createParatixPublished = await isPublished(
    createParatixPackage.name,
    createParatixPackage.version,
    commandRunner
  )

  if (!paratixPublished) {
    throw new Error(
      `Recovery mode requires ${paratixPackage.name}@${paratixPackage.version} to already be published. ` +
        "Run the normal release workflow instead."
    )
  }
  if (createParatixPublished) {
    throw new Error(
      `Recovery mode requires ${createParatixPackage.name}@${createParatixPackage.version} to be missing. ` +
        "No recovery publish is needed."
    )
  }

  await waitForPublishedPackage({
    commandRunner,
    delayMilliseconds: availabilityDelayMilliseconds,
    packageName: paratixPackage.name,
    retries: availabilityRetries,
    version: paratixPackage.version,
  })
  await publishPackage({
    availabilityDelayMilliseconds,
    availabilityRetries,
    commandRunner,
    packageInfo: createParatixPackage,
  })
}

async function readWorkspacePackages(fs) {
  return Promise.all(packages.map((packageInfo) => readPackageJson(packageInfo.directory, fs)))
}

function validateWorkspacePackages(workspacePackages) {
  const unexpectedPackage = workspacePackages.find(
    (packageInfo, index) => packageInfo.name !== packages[index].name
  )
  if (unexpectedPackage !== undefined) {
    throw new Error(
      `${unexpectedPackage.directory}/package.json has unexpected package name ${unexpectedPackage.name}.`
    )
  }

  const versions = new Set(workspacePackages.map((packageInfo) => packageInfo.version))
  if (versions.size !== 1) {
    throw new Error("paratix and create-paratix versions must match before publishing.")
  }
}

export async function publishWorkspacePackages({
  availabilityDelayMilliseconds,
  availabilityRetries,
  commandRunner = {
    execFile: execFileAsync,
    spawn: (command, commandArguments) =>
      new Promise((resolve, reject) => {
        const child = spawn(command, commandArguments, { stdio: "inherit" })
        child.on("error", reject)
        child.on("exit", (code) => {
          if (code === 0) {
            resolve()
            return
          }

          reject(
            new Error(`${command} ${commandArguments.join(" ")} failed with exit code ${code}.`)
          )
        })
      }),
  },
  fs = { lstat, readdir, readFile, stat },
  filesystem = fs,
  mode = "release",
} = {}) {
  const publishMode = validatePublishMode(mode)
  // R-0000740: assert the static `packages` list matches the actual
  // `packages/` directory contents before reading any package.json so a
  // new workspace package added without updating this script aborts the
  // publish flow with a clear diagnostic instead of being silently
  // skipped.
  await assertWorkspacePackagesMatchFilesystem(fs)
  const [paratixPackage, createParatixPackage] = await readWorkspacePackages(fs)
  validateWorkspacePackages([paratixPackage, createParatixPackage])

  // R-0000661: verify every package's dist artefacts before issuing the
  // first pnpm publish. Splitting the verification out of `publishPackage`
  // keeps the abort point well before any registry side effects so a
  // missing or stale artefact never produces a half-published workspace.
  await verifyDistributionArtefacts(paratixPackage, filesystem)
  await verifyDistributionArtefacts(createParatixPackage, filesystem)

  if (
    (await isPublished(createParatixPackage.name, createParatixPackage.version, commandRunner)) &&
    !(await isPublished(paratixPackage.name, paratixPackage.version, commandRunner))
  ) {
    throw new Error(
      `${createParatixPackage.name}@${createParatixPackage.version} is already published, but ` +
        `${paratixPackage.name}@${paratixPackage.version} is not available. Publish the runtime package manually ` +
        "before retrying."
    )
  }

  if (publishMode === PUBLISH_MODE_RECOVER_CREATE_PARATIX) {
    await recoverCreateParatixPackage({
      availabilityDelayMilliseconds,
      availabilityRetries,
      commandRunner,
      createParatixPackage,
      paratixPackage,
    })
    return
  }

  await publishPackage({
    availabilityDelayMilliseconds,
    availabilityRetries,
    commandRunner,
    packageInfo: paratixPackage,
  })
  await publishPackage({
    availabilityDelayMilliseconds,
    availabilityRetries,
    commandRunner,
    packageInfo: createParatixPackage,
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
