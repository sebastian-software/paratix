import { execFile, spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { promisify } from "node:util"

const execFileAsync = promisify(execFile)

function readEnvAvailabilityRetries() {
  const rawValue = process.env.PARATIX_PUBLISH_AVAILABILITY_RETRIES
  if (rawValue == null || rawValue === "") return undefined
  const parsedValue = Number.parseInt(rawValue, 10)
  if (!Number.isFinite(parsedValue) || parsedValue <= 0) return undefined
  return parsedValue
}

// R-0000501: doubled the prior 12 × 10s (= 2 min) budget to ~4 min so the
// registry has enough time to expose paratix before we attempt to publish
// create-paratix. Operators can override the value via
// PARATIX_PUBLISH_AVAILABILITY_RETRIES when the registry is unusually slow.
const DEFAULT_AVAILABILITY_RETRIES = readEnvAvailabilityRetries() ?? 24
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

  return {
    directory,
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

async function publishPackage(packageInfo, commandRunner) {
  if (await isPublished(packageInfo.name, packageInfo.version, commandRunner)) {
    console.log(
      `${packageInfo.name}@${packageInfo.version} is already published; skipping publish.`
    )
    return
  }

  console.log(`Publishing ${packageInfo.name}@${packageInfo.version}.`)
  await commandRunner.spawn("pnpm", [
    "--dir",
    packageInfo.directory,
    "publish",
    "--no-git-checks",
    "--provenance",
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
  fs = { readFile },
} = {}) {
  const [paratixPackage, createParatixPackage] = await readWorkspacePackages(fs)
  validateWorkspacePackages([paratixPackage, createParatixPackage])

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
    return fileURLToPath(moduleUrl) === realpathSync(argv1)
  } catch {
    return false
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  await publishWorkspacePackages()
}
