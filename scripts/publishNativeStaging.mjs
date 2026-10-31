// #255 B3: inputs and staging for the seven @paratix/ssh-native packages.
// The native binaries come from the reusable workflow
// .github/workflows/ssh-native.yml: one artifact `ssh-native-<target>` per
// target with `ssh-native.<target>.node` plus its `.sha256` file, and the
// job output `sha256` (target -> hex SHA-256, set only after the smoke tests
// passed on exactly those binaries). The publish flow copies the manifests
// and binaries into a staging directory outside the repository so the
// working tree stays clean and no stray `*.node` file can leak into a
// tarball.
import { homedir, tmpdir } from "node:os"
import { dirname, isAbsolute, join, parse, relative, resolve } from "node:path"

import { sha256Hex } from "./publishArtefacts.mjs"

export const SSH_NATIVE_PACKAGE_NAME = "@paratix/ssh-native"
// Fixed order: it is also the publish order of the platform packages.
export const SSH_NATIVE_TARGETS = [
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
]
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/v
const ARTIFACT_DIRECTORY_PREFIX = "ssh-native-"
const STAGING_DIRECTORY_NAME = "paratix-publish"
const LOADER_STAGING_DIRECTORY_NAME = "ssh-native"
const TARBALL_DIRECTORY_NAME = "tarballs"
const UTF8 = "utf8"

export function platformPackageName(target) {
  return `${SSH_NATIVE_PACKAGE_NAME}-${target}`
}

export function nativeBinaryFileName(target) {
  return `ssh-native.${target}.node`
}

function parseExpectedSha256(rawValue) {
  let parsedValue
  try {
    parsedValue = JSON.parse(rawValue)
  } catch (error) {
    throw new Error("SSH_NATIVE_SHA256 must be a JSON object mapping each target to its SHA-256.", {
      cause: error,
    })
  }
  if (typeof parsedValue !== "object" || parsedValue === null || Array.isArray(parsedValue)) {
    throw new Error("SSH_NATIVE_SHA256 must be a JSON object mapping each target to its SHA-256.")
  }
  return parsedValue
}

function assertExpectedSha256Targets(expectedSha256) {
  const keys = Object.keys(expectedSha256)
  const unknownTargets = keys.filter((key) => !SSH_NATIVE_TARGETS.includes(key))
  const missingTargets = SSH_NATIVE_TARGETS.filter((target) => !keys.includes(target))
  const malformedTargets = SSH_NATIVE_TARGETS.filter(
    (target) => keys.includes(target) && !SHA256_HEX_PATTERN.test(String(expectedSha256[target]))
  )
  const problems = [
    unknownTargets.length > 0 ? `unknown targets: ${unknownTargets.join(", ")}` : "",
    missingTargets.length > 0 ? `missing targets: ${missingTargets.join(", ")}` : "",
    malformedTargets.length > 0 ? `not a hex SHA-256: ${malformedTargets.join(", ")}` : "",
  ].filter((problem) => problem !== "")
  if (problems.length === 0) return
  throw new Error(
    `SSH_NATIVE_SHA256 must list exactly the six ssh-native targets (${problems.join("; ")}).`
  )
}

// #255 B3: both inputs are required in every mode. Without them the flow
// cannot prove that the packed binaries are the smoke-tested CI artifacts.
export function readNativeInputs(environment) {
  const artifactsDirectory = environment.SSH_NATIVE_ARTIFACTS_DIR
  if (artifactsDirectory == null || artifactsDirectory === "") {
    throw new Error(
      "SSH_NATIVE_ARTIFACTS_DIR is required: point it at the downloaded ssh-native-<target> artifacts."
    )
  }
  const rawExpectedSha256 = environment.SSH_NATIVE_SHA256
  if (rawExpectedSha256 == null || rawExpectedSha256 === "") {
    throw new Error(
      "SSH_NATIVE_SHA256 is required: pass the `sha256` output of the ssh-native workflow."
    )
  }
  const expectedSha256 = parseExpectedSha256(rawExpectedSha256)
  assertExpectedSha256Targets(expectedSha256)
  return { artifactsDirectory: resolve(artifactsDirectory), expectedSha256 }
}

async function assertNoUnknownArtifactDirectories(artifactsDirectory, fs) {
  const expectedNames = new Set(
    SSH_NATIVE_TARGETS.map((target) => `${ARTIFACT_DIRECTORY_PREFIX}${target}`)
  )
  const entries = await fs.readdir(artifactsDirectory, { withFileTypes: true })
  const unknownEntries = entries
    .map((entry) => entry.name)
    .filter((name) => name.startsWith(ARTIFACT_DIRECTORY_PREFIX) && !expectedNames.has(name))
  if (unknownEntries.length === 0) return
  throw new Error(
    `${artifactsDirectory} contains artifacts for unknown targets: ${unknownEntries.join(", ")}.`
  )
}

function parseShasumLine(content, { binaryFileName, label }) {
  const groups = /^(?<digest>[0-9a-f]{64}) [ *](?<fileName>\S+)\s*$/v.exec(content.trim())?.groups
  const digest =
    groups !== undefined && groups.fileName === binaryFileName ? groups.digest : undefined
  if (digest === undefined) {
    throw new Error(`${label}.sha256 must contain "<sha256>  ${binaryFileName}".`)
  }
  return digest
}

async function readArtifactFile(fs, path, encoding) {
  try {
    return await fs.readFile(path, encoding)
  } catch (error) {
    throw new Error(`Missing or unreadable ssh-native artifact ${path}.`, { cause: error })
  }
}

async function verifyTargetArtifact({ artifactsDirectory, expectedSha256, fs, target }) {
  const binaryFileName = nativeBinaryFileName(target)
  const binaryPath = join(
    artifactsDirectory,
    `${ARTIFACT_DIRECTORY_PREFIX}${target}`,
    binaryFileName
  )
  const binary = await readArtifactFile(fs, binaryPath)
  const shasumContent = await readArtifactFile(fs, `${binaryPath}.sha256`, UTF8)
  const actualSha256 = sha256Hex(binary)
  const fileSha256 = parseShasumLine(shasumContent, { binaryFileName, label: binaryPath })
  if (actualSha256 !== fileSha256 || actualSha256 !== expectedSha256[target]) {
    throw new Error(
      `SHA-256 mismatch for ${binaryPath}: file ${actualSha256}, .sha256 file ${fileSha256}, ` +
        `SSH_NATIVE_SHA256 ${expectedSha256[target]}. Only smoke-tested binaries may be published.`
    )
  }
  return { binary, binaryFileName, sha256: actualSha256, target }
}

// #255 B3: each binary must match its `.sha256` file and the workflow
// output. Returns target -> { binary, binaryFileName, sha256 }.
export async function verifyNativeArtifacts({ artifactsDirectory, expectedSha256, fs }) {
  await assertNoUnknownArtifactDirectories(artifactsDirectory, fs)
  const artifacts = await Promise.all(
    SSH_NATIVE_TARGETS.map((target) =>
      verifyTargetArtifact({ artifactsDirectory, expectedSha256, fs, target })
    )
  )
  return new Map(artifacts.map((artifact) => [artifact.target, artifact]))
}

function isSameOrInside(parentDirectory, childPath) {
  const relativePath = relative(parentDirectory, childPath)
  return relativePath === "" || (!relativePath.startsWith("..") && !isAbsolute(relativePath))
}

async function resolveStagingRootPath(environment, fs) {
  const explicitDirectory = environment.PARATIX_PUBLISH_STAGING_DIR
  if (explicitDirectory != null && explicitDirectory !== "") return resolve(explicitDirectory)
  const runnerTemporaryDirectory = environment.RUNNER_TEMP
  if (runnerTemporaryDirectory != null && runnerTemporaryDirectory !== "") {
    return resolve(runnerTemporaryDirectory, STAGING_DIRECTORY_NAME)
  }
  return fs.mkdtemp(join(tmpdir(), `${STAGING_DIRECTORY_NAME}-`))
}

async function canonicalPath(path, fs) {
  try {
    return await fs.realpath(path)
  } catch {
    const parentDirectory = dirname(path)
    if (parentDirectory === path) return path
    return join(await canonicalPath(parentDirectory, fs), relative(parentDirectory, path))
  }
}

function assertSafeStagingRoot(stagingRoot, repositoryRoot) {
  if (isSameOrInside(repositoryRoot, stagingRoot)) {
    throw new Error(
      `Refusing to stage packages at ${stagingRoot}: the staging directory must be outside the repository ${repositoryRoot}.`
    )
  }
  const isFilesystemRoot = parse(stagingRoot).root === stagingRoot
  if (
    isFilesystemRoot ||
    stagingRoot === resolve(homedir()) ||
    isSameOrInside(stagingRoot, repositoryRoot)
  ) {
    throw new Error(
      `Refusing to use ${stagingRoot} as the staging directory: it is recreated empty, so it must be a dedicated directory.`
    )
  }
}

// #255 B3: the staging root is recreated empty on every run, so a rerun
// never picks up tarballs or binaries from an earlier attempt.
export async function prepareStagingRoot({ environment, fs, repositoryRoot }) {
  const requestedRoot = await resolveStagingRootPath(environment, fs)
  const stagingRoot = await canonicalPath(requestedRoot, fs)
  assertSafeStagingRoot(stagingRoot, await canonicalPath(repositoryRoot, fs))
  await fs.rm(stagingRoot, { force: true, recursive: true })
  await fs.mkdir(join(stagingRoot, TARBALL_DIRECTORY_NAME), { recursive: true })
  return {
    loaderDirectory: join(stagingRoot, LOADER_STAGING_DIRECTORY_NAME),
    platformDirectory: (target) => join(stagingRoot, target),
    stagingRoot,
    tarballDirectory: join(stagingRoot, TARBALL_DIRECTORY_NAME),
  }
}

function writeJson(fs, path, value) {
  return fs.writeFile(path, `${JSON.stringify(value, null, 2)}\n`, UTF8)
}

async function stagePlatformPackage({ artifact, fs, manifest, staging }) {
  const directory = staging.platformDirectory(artifact.target)
  await fs.mkdir(directory, { recursive: true })
  await writeJson(fs, join(directory, "package.json"), manifest)
  await fs.writeFile(join(directory, artifact.binaryFileName), artifact.binary)
  return directory
}

async function expandFilesEntry({ fileEntry, fs, sourceDirectory }) {
  if (!fileEntry.includes("*")) return [fileEntry]
  const match = /^(?<directory>[\w.\-]+)\/\*(?<extension>\.[\w.]+)$/v.exec(fileEntry)
  if (match?.groups === undefined) {
    throw new Error(
      `Unsupported package.json#files pattern ${JSON.stringify(fileEntry)} in ${sourceDirectory}; only "<dir>/*.<ext>" is supported.`
    )
  }
  const { directory, extension } = match.groups
  const entries = await fs.readdir(join(sourceDirectory, directory), { withFileTypes: true })
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(extension))
    .map((entry) => `${directory}/${entry.name}`)
    .sort()
}

async function copyLoaderFile({ fs, relativePath, sourceDirectory, targetDirectory }) {
  const sourcePath = join(sourceDirectory, relativePath)
  const linkStats = await fs.lstat(sourcePath)
  if (!linkStats.isFile()) {
    throw new Error(`${sourcePath} referenced by package.json#files must be a regular file.`)
  }
  const targetPath = join(targetDirectory, relativePath)
  await fs.mkdir(dirname(targetPath), { recursive: true })
  await fs.writeFile(targetPath, await fs.readFile(sourcePath))
}

async function stageLoaderPackage({ fs, loaderPackage, platformNames, staging }) {
  const { directory: sourceDirectory, files, manifest, version } = loaderPackage
  const expandedFiles = await Promise.all(
    files.map((fileEntry) => expandFilesEntry({ fileEntry, fs, sourceDirectory }))
  )
  // Never copy a native binary into the loader package, even if a local
  // build left one next to the sources.
  const relativePaths = expandedFiles.flat().filter((path) => !path.endsWith(".node"))
  const targetDirectory = staging.loaderDirectory
  await fs.mkdir(targetDirectory, { recursive: true })
  await Promise.all(
    relativePaths.map((relativePath) =>
      copyLoaderFile({ fs, relativePath, sourceDirectory, targetDirectory })
    )
  )
  const optionalDependencies = Object.fromEntries(
    platformNames.map((platformName) => [platformName, version])
  )
  await writeJson(fs, join(targetDirectory, "package.json"), {
    ...manifest,
    optionalDependencies,
  })
  return targetDirectory
}

// #255 B3: writes `<staging>/<target>/` (manifest + binary) for every
// platform package and `<staging>/ssh-native/` (the `files` entries of
// packages/ssh-native plus a manifest with the six optionalDependencies).
// Returns name -> staged directory.
export async function stageNativePackages({
  artifacts,
  fs,
  loaderPackage,
  platformPackages,
  staging,
}) {
  const platformDirectories = await Promise.all(
    platformPackages.map(async (platformPackage) => [
      platformPackage.name,
      await stagePlatformPackage({
        artifact: artifacts.get(platformPackage.target),
        fs,
        manifest: platformPackage.manifest,
        staging,
      }),
    ])
  )
  const loaderDirectory = await stageLoaderPackage({
    fs,
    loaderPackage,
    platformNames: platformPackages.map((platformPackage) => platformPackage.name),
    staging,
  })
  return new Map([...platformDirectories, [loaderPackage.name, loaderDirectory]])
}
