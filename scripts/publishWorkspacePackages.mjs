import { execFile, spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import { readdir, readFile, stat } from "node:fs/promises"
import { join } from "node:path"
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

const packages = [
  { directory: "packages/paratix", name: "paratix" },
  { directory: "packages/create-paratix", name: "create-paratix" },
]

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

// R-0000661: maximum mtime captured under `directory`. Walking the tree
// (rather than stat-ing the directory itself) is necessary because
// directory mtimes only change when entries are added/removed, not when
// the contents of existing files are edited. The recursion follows
// regular files only and skips symlinks so a malicious symlink under
// the directory cannot stat its target and lift the dist freshness bar.
async function maxMtimeMillisecondsUnder(directory, filesystem) {
  const entries = await filesystem.readdir(directory, { withFileTypes: true })
  const childMtimes = await Promise.all(
    entries.map(async (entry) => {
      if (entry.isSymbolicLink()) return 0
      const entryPath = join(directory, entry.name)
      if (entry.isDirectory()) {
        // Recurse so deep edits (e.g. `src/modules/<module>.ts`) are visible.
        return maxMtimeMillisecondsUnder(entryPath, filesystem)
      }
      if (!entry.isFile()) return 0
      const stats = await filesystem.stat(entryPath)
      return stats.mtimeMs
    })
  )
  return childMtimes.reduce((max, mtime) => (mtime > max ? mtime : max), 0)
}

async function mtimeMillisecondsForFileEntry(directory, fileEntry, filesystem) {
  const absolutePath = join(directory, fileEntry)
  const stats = await filesystem.stat(absolutePath)
  if (stats.isDirectory()) {
    return maxMtimeMillisecondsUnder(absolutePath, filesystem)
  }
  return stats.mtimeMs
}

// R-0000661: lift the most recent mtime across every entry referenced by
// `files`. Treats directories like `src/` does — walking the tree so the
// freshness signal reflects file edits, not directory churn.
async function maxMtimeMillisecondsForFiles(directory, files, filesystem) {
  const fileMtimes = await Promise.all(
    files.map((fileEntry) => mtimeMillisecondsForFileEntry(directory, fileEntry, filesystem))
  )
  return fileMtimes.reduce((max, mtime) => (mtime > max ? mtime : max), 0)
}

async function ensureFilesEntryExists(packageInfo, fileEntry, filesystem) {
  const absolutePath = join(packageInfo.directory, fileEntry)
  try {
    await filesystem.stat(absolutePath)
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(
        `${packageInfo.name}: ${fileEntry} referenced by package.json#files is missing under ${packageInfo.directory}. Run the build before publishing.`,
        { cause: error }
      )
    }
    throw error
  }
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
    packageInfo.files.map((fileEntry) => ensureFilesEntryExists(packageInfo, fileEntry, filesystem))
  )

  const sourceDirectory = join(packageInfo.directory, "src")
  const sourceMtime = await maxMtimeMillisecondsUnder(sourceDirectory, filesystem)
  const filesMtime = await maxMtimeMillisecondsForFiles(
    packageInfo.directory,
    packageInfo.files,
    filesystem
  )
  if (filesMtime < sourceMtime) {
    throw new Error(
      `${packageInfo.name}: package.json#files mtime (${new Date(filesMtime).toISOString()}) is older than ${packageInfo.directory}/src mtime (${new Date(sourceMtime).toISOString()}). Run the build before publishing.`
    )
  }
}

async function publishPackage(packageInfo, commandRunner) {
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
  fs = { readdir, readFile, stat },
  filesystem = fs,
} = {}) {
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

  await publishPackage(paratixPackage, commandRunner)
  await waitForPublishedPackage({
    commandRunner,
    delayMilliseconds: availabilityDelayMilliseconds,
    packageName: paratixPackage.name,
    retries: availabilityRetries,
    version: paratixPackage.version,
  })
  await publishPackage(createParatixPackage, commandRunner)
}

function isDirectExecution(moduleUrl, argv1) {
  if (argv1 == null) return false
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- argv1 is process.argv[1] (the invoking script path), not user input
    return fileURLToPath(moduleUrl) === realpathSync(argv1)
  } catch {
    return false
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await publishWorkspacePackages()
}
