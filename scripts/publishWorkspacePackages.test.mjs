/* eslint-disable security/detect-non-literal-fs-filename -- Fixtures only read and write inside their own temporary directories. */
import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import * as realFs from "node:fs/promises"
import { tmpdir } from "node:os"
import { basename, dirname, join, relative } from "node:path"
import { describe, it, mock } from "node:test"
import { pathToFileURL } from "node:url"
import { gzipSync } from "node:zlib"

import { readTarGzEntries } from "./publishArtefacts.mjs"
import { isDirectExecution, publishWorkspacePackages } from "./publishWorkspacePackages.mjs"

// Tests that exercise the local-publish path rely on `publishWorkspacePackages`
// not seeing any GitHub Actions environment. Every run below passes an
// explicit environment; clear the process variables anyway so nothing leaks
// in when this suite itself runs inside GitHub Actions.
delete process.env.GITHUB_ACTIONS
delete process.env.GITHUB_REF
delete process.env.GITHUB_SHA
delete process.env.GITHUB_RUN_ID

const DEFAULT_STABLE_VERSION = "1.2.3"
const CREATE_PARATIX_NAME = "create-paratix"
const PARATIX_NAME = "paratix"
const SSH_NATIVE_NAME = "@paratix/ssh-native"
const SSH_NATIVE_DIRECTORY_NAME = "ssh-native"
const TARGETS = [
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
]
const PLATFORM_NAMES = TARGETS.map((target) => `${SSH_NATIVE_NAME}-${target}`)
const RELEASE_ORDER = [...PLATFORM_NAMES, SSH_NATIVE_NAME, PARATIX_NAME, CREATE_PARATIX_NAME]
const NATIVE_PACKAGE_COUNT = PLATFORM_NAMES.length + 1
const NATIVE_DIFF_PATHS = "packages/ssh-native .github/workflows/ssh-native.yml"
const REPOSITORY_ROOT = dirname(import.meta.dirname)
const REPOSITORY_URL = "https://github.com/sebastian-software/paratix"
const PUBLISH_WORKFLOW_PATH = ".github/workflows/publish.yml"
const MAIN_REF = "refs/heads/main"
const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
const REGISTRY_ORIGIN = "https://registry.npmjs.org"
const ATTESTATIONS_PATH = "/-/npm/v1/attestations/"
const EXCHANGE_PATH = "/-/npm/v1/oidc/token/exchange/package/"
const ID_TOKEN_REQUEST_URL = "https://token.actions.example.test/id?api-version=2.0"
const ID_TOKEN_REQUEST_ORIGIN = new URL(ID_TOKEN_REQUEST_URL).origin
const REQUEST_TOKEN = "request-token-secret-value"
const ID_TOKEN = "id-token-secret-value"
const NPM_TOKEN_PREFIX = "npm-token-secret-"
const NPM_VERSION = "11.16.0"
const HEAD_COMMIT = "a".repeat(40)
const EARLIER_COMMIT = "b".repeat(40)
const CURRENT_RUN_ID = "1000"
const EARLIER_RUN_ID = "500"
const ABSOLUTE_PACKAGES_DIRECTORY = join(REPOSITORY_ROOT, "packages")
const ABSOLUTE_SSH_NATIVE_DIRECTORY = join(ABSOLUTE_PACKAGES_DIRECTORY, SSH_NATIVE_DIRECTORY_NAME)
const CREATE_PARATIX_DIRECTORY = `packages/${CREATE_PARATIX_NAME}`
const PARATIX_DIRECTORY = `packages/${PARATIX_NAME}`
const SSH_NATIVE_DIRECTORY = `packages/${SSH_NATIVE_DIRECTORY_NAME}`
const SSH_NATIVE_MANIFEST_PATH = `${SSH_NATIVE_DIRECTORY}/package.json`
const PACKED_MANIFEST = "package/package.json"
const VERIFY_MODE = "verify"
const RELEASE_MODE = "release"
const GIT_HEAD_SHA = HEAD_COMMIT
const GIT_REV_PARSE_HEAD_COMMAND = "rev-parse HEAD"
const GIT_SYMBOLIC_REF_BRANCH_COMMAND = "symbolic-ref --quiet --short HEAD"
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
const PARATIX_DIST_INDEX_PATH = `${PARATIX_DIST_DIRECTORY}/index.js`
const PARATIX_LLM_GUIDE_PATH = `${PARATIX_DIRECTORY}/llm-guide.md`
const PARATIX_SOURCE_DIRECTORY = `${PARATIX_DIRECTORY}/src`
const PARATIX_SOURCE_INDEX_PATH = `${PARATIX_SOURCE_DIRECTORY}/index.ts`
const PARATIX_TSCONFIG_PATH = `${PARATIX_DIRECTORY}/${TSCONFIG_JSON_FILE}`
const PARATIX_TSCONFIG_TYPECHECK_PATH = `${PARATIX_DIRECTORY}/${TSCONFIG_TYPECHECK_JSON_FILE}`
const PARATIX_TSUP_CONFIG_PATH = `${PARATIX_DIRECTORY}/${TSUP_CONFIG_FILE}`
const STALE_ARTEFACT_MESSAGE_FRAGMENT = "is older than"
const DRIFT_MESSAGE_FRAGMENT = "Workspace package drift detected"
const NOT_PUBLISHABLE_FRAGMENT = "is not publishable"
const PROVENANCE_FRAGMENT = "provenance cannot be accepted"
const NPM_SOURCE_FRAGMENT = "no longer matches the verified OIDC flow"
const BINARY_COUNT_FRAGMENT = "exactly one native binary"
const SHA_MISMATCH_FRAGMENT = "SHA-256 mismatch"
const FIRST_PLATFORM_NAME = PLATFORM_NAMES[0]
const FIRST_TARGET = TARGETS[0]
const SYMLINK_FILES_FRAGMENT = "referenced by package.json#files is a symbolic link"
const ENOENT = "ENOENT"
const SIMULATED_ABORT_MESSAGE = "simulated publish abort"
const TAR_TEXT_ENTRY = "package/a.txt"

// R-0000661: the publish flow reads package.json#files and verifies that
// each entry exists with an mtime newer than the src/ tree. Default the
// in-memory mock filesystem to a healthy state (dist + llm-guide.md for
// paratix, dist for create-paratix, both freshly built) so tests only
// override what they exercise.
const FRESH_DIST_MTIME = 2000
const STALE_SOURCE_MTIME = 1000
const DEFAULT_PARATIX_FILES = ["dist", "llm-guide.md"]
const DEFAULT_CREATE_PARATIX_FILES = ["dist"]
const DEFAULT_PACKAGE_DIRECTORIES = [CREATE_PARATIX_NAME, PARATIX_NAME, SSH_NATIVE_DIRECTORY_NAME]
const SSH_NATIVE_FILES = ["index.js", "index.d.ts", "loader.js", "lib/*.js", "README.md", "LICENSE"]
const SSH_NATIVE_SOURCE_FILES = {
  [`${SSH_NATIVE_DIRECTORY}/index.d.ts`]: "export declare function connect(): void\n",
  [`${SSH_NATIVE_DIRECTORY}/index.js`]: "module.exports = require('./lib/connect.js')\n",
  [`${SSH_NATIVE_DIRECTORY}/lib/connect.js`]: "module.exports = {}\n",
  [`${SSH_NATIVE_DIRECTORY}/lib/native.js`]: "module.exports = require('../loader.js')\n",
  [`${SSH_NATIVE_DIRECTORY}/LICENSE`]: "MIT\n",
  [`${SSH_NATIVE_DIRECTORY}/loader.js`]: "module.exports = {}\n",
  [`${SSH_NATIVE_DIRECTORY}/README.md`]: "# @paratix/ssh-native\n",
}

function binaryFileName(target) {
  return `ssh-native.${target}.node`
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex")
}

function integrityOf(content) {
  return `sha512-${createHash("sha512").update(content).digest("base64")}`
}

function integrityHex(integrity) {
  return Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex")
}

function tarballFileName(name, version) {
  return `${name.replace(/^@/v, "").replace("/", "-")}-${version}.tgz`
}

function expectedTarballNames(version) {
  return RELEASE_ORDER.map((name) => tarballFileName(name, version))
}

const toMockPath = (path) => {
  if (path === REPOSITORY_ROOT) return ""
  return path.startsWith(`${REPOSITORY_ROOT}/`) ? path.slice(REPOSITORY_ROOT.length + 1) : path
}

function isRepositoryPath(path) {
  const textPath = String(path)
  return textPath === REPOSITORY_ROOT || textPath.startsWith(`${REPOSITORY_ROOT}/`)
}

// ---------------------------------------------------------------------------
// Mock repository filesystem. Repository paths are served from memory;
// every other path (artifacts, staging, tarballs, the fake npm install)
// goes to the real filesystem inside per-test temporary directories.
// ---------------------------------------------------------------------------

function platformManifest(target, version) {
  return {
    files: [binaryFileName(target)],
    main: binaryFileName(target),
    name: `${SSH_NATIVE_NAME}-${target}`,
    version,
  }
}

function createManifests(options) {
  const {
    createParatixFiles = DEFAULT_CREATE_PARATIX_FILES,
    manifestOverrides = {},
    paratixFiles = DEFAULT_PARATIX_FILES,
    version = DEFAULT_STABLE_VERSION,
  } = options
  const {
    createParatixVersion = version,
    nativeVersion = version,
    paratixVersion = version,
  } = options
  const manifests = {
    [`${CREATE_PARATIX_DIRECTORY}/package.json`]: {
      files: createParatixFiles,
      name: CREATE_PARATIX_NAME,
      version: createParatixVersion,
    },
    [`${PARATIX_DIRECTORY}/package.json`]: {
      files: paratixFiles,
      name: PARATIX_NAME,
      version: paratixVersion,
    },
    [SSH_NATIVE_MANIFEST_PATH]: {
      files: SSH_NATIVE_FILES,
      main: "index.js",
      name: SSH_NATIVE_NAME,
      version: nativeVersion,
    },
    ...Object.fromEntries(
      TARGETS.map((target) => [
        `${SSH_NATIVE_DIRECTORY}/npm/${target}/package.json`,
        platformManifest(target, nativeVersion),
      ])
    ),
  }
  for (const [path, override] of Object.entries(manifestOverrides)) {
    manifests[path] = override(manifests[path])
  }
  return manifests
}

function createDefaultMtimes() {
  return {
    [CREATE_PARATIX_TSCONFIG_PATH]: STALE_SOURCE_MTIME,
    [CREATE_PARATIX_TSCONFIG_TYPECHECK_PATH]: STALE_SOURCE_MTIME,
    [CREATE_PARATIX_TSUP_CONFIG_PATH]: STALE_SOURCE_MTIME,
    [PACKAGE_JSON_FILE]: STALE_SOURCE_MTIME,
    "packages/create-paratix/dist": FRESH_DIST_MTIME,
    "packages/create-paratix/dist/index.js": FRESH_DIST_MTIME,
    "packages/create-paratix/package.json": STALE_SOURCE_MTIME,
    "packages/create-paratix/src": STALE_SOURCE_MTIME,
    "packages/create-paratix/src/index.ts": STALE_SOURCE_MTIME,
    "packages/paratix/package.json": STALE_SOURCE_MTIME,
    [PARATIX_DIST_DIRECTORY]: FRESH_DIST_MTIME,
    [PARATIX_DIST_INDEX_PATH]: FRESH_DIST_MTIME,
    [PARATIX_LLM_GUIDE_PATH]: FRESH_DIST_MTIME,
    [PARATIX_SOURCE_DIRECTORY]: STALE_SOURCE_MTIME,
    [PARATIX_SOURCE_INDEX_PATH]: STALE_SOURCE_MTIME,
    [PARATIX_TSCONFIG_PATH]: STALE_SOURCE_MTIME,
    [PARATIX_TSCONFIG_TYPECHECK_PATH]: STALE_SOURCE_MTIME,
    [PARATIX_TSUP_CONFIG_PATH]: STALE_SOURCE_MTIME,
    [PNPM_LOCK_FILE]: STALE_SOURCE_MTIME,
    [TSCONFIG_JSON_FILE]: STALE_SOURCE_MTIME,
    [TSCONFIG_ROOT_JSON_FILE]: STALE_SOURCE_MTIME,
    ...Object.fromEntries(
      Object.keys(SSH_NATIVE_SOURCE_FILES).map((path) => [path, STALE_SOURCE_MTIME])
    ),
  }
}

function createSshNativeDirectories() {
  return {
    [`${SSH_NATIVE_DIRECTORY}/lib`]: ["connect.js", "native.js", "notes.txt"],
    [`${SSH_NATIVE_DIRECTORY}/npm`]: TARGETS,
    [SSH_NATIVE_DIRECTORY]: [
      "index.d.ts",
      "index.js",
      "lib",
      "LICENSE",
      "loader.js",
      "npm",
      PACKAGE_JSON_FILE,
      "README.md",
      // A local build artefact that must never be staged or packed.
      binaryFileName(FIRST_TARGET),
    ],
    ...Object.fromEntries(
      TARGETS.map((target) => [`${SSH_NATIVE_DIRECTORY}/npm/${target}`, [PACKAGE_JSON_FILE]])
    ),
  }
}

function createDirectories(packageDirectories) {
  return {
    "": [
      PACKAGE_JSON_FILE,
      "packages",
      PNPM_LOCK_FILE,
      TSCONFIG_JSON_FILE,
      TSCONFIG_ROOT_JSON_FILE,
    ],
    // R-0000740: the drift assertion reads the `packages/` directory.
    packages: packageDirectories,
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
    [PARATIX_DIST_DIRECTORY]: ["index.js"],
    [PARATIX_SOURCE_DIRECTORY]: ["index.ts"],
    ...(packageDirectories.includes(SSH_NATIVE_DIRECTORY_NAME) ? createSshNativeDirectories() : {}),
    ...Object.fromEntries(
      packageDirectories
        .filter((name) => !DEFAULT_PACKAGE_DIRECTORIES.includes(name))
        .map((name) => [`packages/${name}`, [PACKAGE_JSON_FILE]])
    ),
  }
}

function createDirent(name, { directoryEntries, mockPath, symlinkSet }) {
  const fullPath = mockPath === "" ? name : `${mockPath}/${name}`
  const isSymbolicLink = symlinkSet.has(fullPath)
  const isDirectory = directoryEntries.has(fullPath)
  return {
    isDirectory: () => isDirectory,
    isFile: () => !isSymbolicLink && !isDirectory,
    isSymbolicLink: () => isSymbolicLink,
    name,
  }
}

function createStats({ isDirectory, isSymbolicLink, mtime }) {
  return {
    isDirectory: () => isDirectory,
    isFile: () => !isDirectory && !isSymbolicLink,
    isSymbolicLink: () => isSymbolicLink,
    mtimeMs: mtime,
  }
}

function missingPathError(operation, path) {
  return Object.assign(new Error(`${ENOENT} ${operation} ${path}`), { code: ENOENT })
}

function rejectRepositoryWrite(path) {
  throw new Error(`Unexpected write to repository path ${path}`)
}

function createRealDelegates(calls) {
  const delegate =
    (method) =>
    async (path, ...rest) => {
      calls.push([method, String(path)])
      if (isRepositoryPath(path)) rejectRepositoryWrite(path)
      return realFs[method](path, ...rest)
    }
  return {
    appendFile: delegate("appendFile"),
    mkdir: delegate("mkdir"),
    mkdtemp: delegate("mkdtemp"),
    realpath: (path) => realFs.realpath(path),
    rm: delegate("rm"),
    writeFile: delegate("writeFile"),
  }
}

function createFs(options) {
  const {
    mtimes: mtimeOverrides = {},
    // R-0000740: the `packages/` listing seen by the drift assertion.
    packageDirectories = DEFAULT_PACKAGE_DIRECTORIES,
    // R-0000685: force `readdir` to fail with an error code for a path.
    readdirErrors = {},
    // R-0000685: paths whose lstat/Dirent report a symbolic link.
    symlinks: symlinkPaths = [],
  } = options ?? {}
  const manifests = createManifests(options ?? {})
  const mtimes = { ...createDefaultMtimes(), ...mtimeOverrides }
  const directories = createDirectories(packageDirectories)
  const symlinkSet = new Set(symlinkPaths)
  const directoryEntries = new Set(Object.keys(directories).filter((path) => path !== ""))
  const calls = []

  function statPath(operation, path) {
    calls.push([operation, path])
    const mockPath = toMockPath(path)
    const mtime = mtimes[mockPath]
    if (mtime === undefined) throw missingPathError(operation, path)
    const isSymbolicLink = operation === "lstat" && symlinkSet.has(mockPath)
    const isDirectory = !isSymbolicLink && directories[mockPath] !== undefined
    return createStats({ isDirectory, isSymbolicLink, mtime })
  }

  return {
    ...createRealDelegates(calls),
    calls,
    async lstat(path) {
      if (!isRepositoryPath(path)) return realFs.lstat(path)
      return statPath("lstat", path)
    },
    async readdir(path, readdirOptions) {
      if (!isRepositoryPath(path)) return realFs.readdir(path, readdirOptions)
      calls.push(["readdir", path])
      const mockPath = toMockPath(path)
      const errorCode = readdirErrors[mockPath]
      if (errorCode !== undefined) {
        throw Object.assign(new Error(`${errorCode} readdir ${path}`), { code: errorCode })
      }
      const entries = directories[mockPath]
      if (!entries) throw missingPathError("readdir", path)
      if (readdirOptions?.withFileTypes !== true) return [...entries]
      return entries.map((name) => createDirent(name, { directoryEntries, mockPath, symlinkSet }))
    },
    async readFile(path, encoding) {
      if (!isRepositoryPath(path)) return realFs.readFile(path, encoding)
      calls.push(["readFile", path])
      const mockPath = toMockPath(path)
      if (manifests[mockPath] !== undefined) return JSON.stringify(manifests[mockPath])
      if (SSH_NATIVE_SOURCE_FILES[mockPath] !== undefined) return SSH_NATIVE_SOURCE_FILES[mockPath]
      throw new Error(`Unexpected path: ${path}`)
    },
    async stat(path) {
      if (!isRepositoryPath(path)) return realFs.stat(path)
      return statPath("stat", path)
    },
  }
}

// ---------------------------------------------------------------------------
// Minimal ustar + gzip writer used by the fake `pnpm pack`.
// ---------------------------------------------------------------------------

const TAR_BLOCK_SIZE = 512

function writeOctal(header, { length, offset, value }) {
  header.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "ascii")
}

function tarHeader({ name, size, type }) {
  const header = Buffer.alloc(TAR_BLOCK_SIZE)
  header.write(name, 0, 100, "utf8")
  writeOctal(header, { length: 8, offset: 100, value: 0o644 })
  writeOctal(header, { length: 8, offset: 108, value: 0 })
  writeOctal(header, { length: 8, offset: 116, value: 0 })
  writeOctal(header, { length: 12, offset: 124, value: size })
  writeOctal(header, { length: 12, offset: 136, value: 0 })
  header.write("        ", 148, 8, "ascii")
  header.write(type, 156, 1, "ascii")
  header.write("ustar\u000000", 257, 8, "ascii")
  let checksum = 0
  for (const byte of header) checksum += byte
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii")
  return header
}

function createTarGzFromRecords(records) {
  const blocks = records.flatMap(({ data = "", name, type = "0" }) => {
    const content = Buffer.from(data)
    const padding = (TAR_BLOCK_SIZE - (content.length % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE
    return [tarHeader({ name, size: content.length, type }), content, Buffer.alloc(padding)]
  })
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(TAR_BLOCK_SIZE * 2)]))
}

function createTarGz(entries) {
  return createTarGzFromRecords(
    [...entries.keys()].sort().map((name) => ({ data: entries.get(name), name }))
  )
}

// ---------------------------------------------------------------------------
// Fake registry, command runner and fetch.
// ---------------------------------------------------------------------------

function splitSpecifier(specifier) {
  const versionSeparator = specifier.lastIndexOf("@")
  return {
    name: specifier.slice(0, versionSeparator),
    version: specifier.slice(versionSeparator + 1),
  }
}

function provenanceStatement(specifier, entry) {
  const { name, version } = splitSpecifier(specifier)
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: { path: PUBLISH_WORKFLOW_PATH, ref: MAIN_REF, repository: REPOSITORY_URL },
        },
        resolvedDependencies: [
          { digest: { gitCommit: entry.commit }, uri: `git+${REPOSITORY_URL}@${MAIN_REF}` },
        ],
      },
      runDetails: {
        metadata: { invocationId: `${REPOSITORY_URL}/actions/runs/${entry.runId}/attempts/1` },
      },
    },
    predicateType: SLSA_PROVENANCE_V1,
    subject: [
      {
        digest: { sha512: integrityHex(entry.integrity) },
        name: `pkg:npm/${name.replace(/^@/v, "%40")}@${version}`,
      },
    ],
  }
  return entry.tamper === undefined ? statement : entry.tamper(statement)
}

function attestationsBody(specifier, entry) {
  if (entry.attestationsBody !== undefined) return entry.attestationsBody
  const payload =
    entry.payload ??
    Buffer.from(JSON.stringify(provenanceStatement(specifier, entry))).toString("base64")
  return {
    attestations: [
      {
        bundle: { dsseEnvelope: { payload: "e30=" } },
        predicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
      },
      {
        bundle: { dsseEnvelope: { payload, payloadType: "application/vnd.in-toto+json" } },
        predicateType: SLSA_PROVENANCE_V1,
      },
    ],
  }
}

function distFor(specifier, entry) {
  if (entry.dist !== undefined) return entry.dist
  return {
    attestations: {
      provenance: { predicateType: SLSA_PROVENANCE_V1 },
      url: `${REGISTRY_ORIGIN}${ATTESTATIONS_PATH}${specifier.replace("/", "%2f")}`,
    },
    integrity: entry.integrity,
  }
}

function createMissingPackageError() {
  return Object.assign(new Error("missing"), { stderr: "npm ERR! code E404" })
}

function publishedEarlier(registry, names, options) {
  const {
    commit = EARLIER_COMMIT,
    runId = EARLIER_RUN_ID,
    version = DEFAULT_STABLE_VERSION,
  } = options ?? {}
  for (const name of names) {
    registry.set(`${name}@${version}`, {
      commit,
      integrity: integrityOf(`earlier tarball of ${name}`),
      runId,
    })
  }
}

function createGitCommandHandler(options) {
  const { diffCalls, diffExitCode, gitBranch, gitHeadSha, gitRepositoryRoot, gitStatus } = options
  const stdoutByCommand = new Map([
    ["rev-parse --show-toplevel", `${gitRepositoryRoot}\n`],
    ["status --porcelain=v1 --untracked-files=normal", gitStatus],
    [GIT_REV_PARSE_HEAD_COMMAND, `${gitHeadSha}\n`],
    [GIT_SYMBOLIC_REF_BRANCH_COMMAND, `${gitBranch}\n`],
  ])

  return (commandArguments) => {
    const gitCommand = commandArguments.join(" ")
    if (commandArguments[0] === "diff") {
      diffCalls.push(gitCommand)
      if (diffExitCode === 0) return { stdout: "" }
      throw Object.assign(new Error(`git ${gitCommand} failed`), { code: diffExitCode })
    }
    const stdout = stdoutByCommand.get(gitCommand)
    if (stdout !== undefined) return { stdout }
    throw new Error(`Unexpected git command: ${gitCommand}`)
  }
}

async function collectPackEntries(cwd, fs) {
  const entries = new Map()
  if (isRepositoryPath(cwd)) {
    entries.set(
      PACKED_MANIFEST,
      Buffer.from(await fs.readFile(join(cwd, PACKAGE_JSON_FILE), "utf8"))
    )
    entries.set("package/dist/index.js", Buffer.from("export {}\n"))
    return entries
  }
  for (const entry of readdirSync(cwd, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const absolutePath = join(entry.parentPath, entry.name)
    entries.set(`package/${relative(cwd, absolutePath)}`, readFileSync(absolutePath))
  }
  return entries
}

function createNpmHandler(state) {
  const { hiddenViews, options, registry, viewCounts } = state
  return (commandArguments) => {
    if (commandArguments[0] === "--version") return { stdout: `${options.npmVersion}\n` }
    if (commandArguments[0] === "root") return { stdout: `${options.npmRoot}\n` }
    const specifier = commandArguments[1]
    if (commandArguments[2] === "dist") {
      return { stdout: JSON.stringify(distFor(specifier, registry.get(specifier))) }
    }
    viewCounts.set(specifier, (viewCounts.get(specifier) ?? 0) + 1)
    const hidden = hiddenViews.get(specifier) ?? 0
    if (hidden > 0) {
      hiddenViews.set(specifier, hidden - 1)
      throw createMissingPackageError()
    }
    if (registry.has(specifier))
      return { stdout: JSON.stringify(splitSpecifier(specifier).version) }
    throw createMissingPackageError()
  }
}

function createPackHandler(state) {
  const { fs, options, packedSpecifiers } = state
  return async (commandArguments, runOptions) => {
    const outputPath = commandArguments[2]
    const entries = await collectPackEntries(runOptions.cwd, fs)
    const manifest = JSON.parse(entries.get(PACKED_MANIFEST).toString("utf8"))
    const specifier = `${manifest.name}@${manifest.version}`
    options.packHook?.({ entries, manifest, name: manifest.name })
    writeFileSync(outputPath, createTarGz(entries))
    packedSpecifiers.set(outputPath, specifier)
    return { stdout: `${outputPath}\n` }
  }
}

function createPublishHandler(state) {
  const { hiddenViews, options, packedSpecifiers, registry } = state
  let publishCount = 0
  return (commandArguments) => {
    publishCount += 1
    const tarballPath = commandArguments[1]
    const specifier = packedSpecifiers.get(tarballPath)
    registry.set(specifier, {
      commit: options.gitHeadSha,
      integrity: integrityOf(readFileSync(tarballPath)),
      runId: options.runId,
    })
    const { name } = splitSpecifier(specifier)
    hiddenViews.set(specifier, options.hiddenViewsAfterPublish[name] ?? 0)
    // Simulates a job that dies right after the registry accepted the
    // upload of publish step `abortAfterPublish`.
    if (publishCount === options.abortAfterPublish) throw new Error(SIMULATED_ABORT_MESSAGE)
  }
}

function createCommandRunner(runnerOptions) {
  const options = {
    diffExitCode: 0,
    gitBranch: "main",
    gitHeadSha: GIT_HEAD_SHA,
    gitRepositoryRoot: REPOSITORY_ROOT,
    gitStatus: "",
    hiddenViewsAfterPublish: {},
    npmVersion: NPM_VERSION,
    runId: CURRENT_RUN_ID,
    ...runnerOptions,
  }
  const state = {
    diffCalls: [],
    fs: options.fs,
    hiddenViews: new Map(),
    options,
    packedSpecifiers: new Map(),
    registry: options.registry,
    viewCounts: new Map(),
  }
  const runGit = createGitCommandHandler({ ...options, diffCalls: state.diffCalls })
  const runNpm = createNpmHandler(state)
  const runPack = createPackHandler(state)
  const runPublish = createPublishHandler(state)
  const calls = []
  const execFileOptions = []
  const spawnOptions = []

  return {
    calls,
    diffCalls: state.diffCalls,
    async execFile(command, commandArguments, execOptions) {
      calls.push([command, ...commandArguments])
      execFileOptions.push({ command, commandArguments, options: execOptions })
      if (command === "git") return runGit(commandArguments)
      if (command === "pnpm") return runPack(commandArguments, execOptions)
      return runNpm(commandArguments)
    },
    execFileOptions,
    async spawn(command, commandArguments, execOptions) {
      calls.push([command, ...commandArguments])
      spawnOptions.push(execOptions)
      runPublish(commandArguments)
    },
    spawnOptions,
    viewCounts: state.viewCounts,
  }
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    status,
  })
}

function idTokenResponse(url, init, options) {
  const isAuthorized = init.headers?.Authorization === `Bearer ${REQUEST_TOKEN}`
  const hasAudience = url.searchParams.get("audience") === "npm:registry.npmjs.org"
  if (!isAuthorized || !hasAudience) return jsonResponse(403, { message: "forbidden" })
  return jsonResponse(options.idTokenStatus ?? 200, { value: ID_TOKEN })
}

function exchangeResponse(url, init, options) {
  const name = decodeURIComponent(url.pathname.slice(EXCHANGE_PATH.length))
  const isAuthorized = init.headers?.Authorization === `Bearer ${ID_TOKEN}`
  if (!isAuthorized || init.method !== "POST") return jsonResponse(401, { message: "unauthorized" })
  const status = options.exchangeStatus?.[name] ?? 200
  if (status !== 200) return jsonResponse(status, { message: "no trusted publisher" })
  return jsonResponse(200, { token: `${NPM_TOKEN_PREFIX}${name}` })
}

function attestationResponse(url, registry) {
  const specifier = decodeURIComponent(url.pathname.slice(ATTESTATIONS_PATH.length))
  const entry = registry.get(specifier)
  if (entry === undefined) return jsonResponse(404, { message: "not found" })
  return jsonResponse(200, attestationsBody(specifier, entry))
}

function createFetch(options) {
  const calls = []
  async function fetch(input, init = {}) {
    const url = new URL(String(input))
    calls.push({ method: init.method ?? "GET", pathname: url.pathname, url: url.href })
    if (url.origin === ID_TOKEN_REQUEST_ORIGIN) return idTokenResponse(url, init, options)
    if (url.pathname.startsWith(EXCHANGE_PATH)) return exchangeResponse(url, init, options)
    if (url.pathname.startsWith(ATTESTATIONS_PATH)) {
      return attestationResponse(url, options.registry)
    }
    return jsonResponse(404, { message: "unexpected request" })
  }
  return Object.assign(fetch, { calls })
}

// ---------------------------------------------------------------------------
// Harness: temporary artifacts, staging directory and npm installation.
// ---------------------------------------------------------------------------

function writeArtifacts(artifactsDirectory, artifactOverrides) {
  const expectedSha256 = {}
  for (const target of TARGETS) {
    const override = artifactOverrides[target] ?? {}
    const binary = Buffer.from(`native binary for ${target}`)
    expectedSha256[target] = sha256(binary)
    if (override.missing === true) continue
    const directory = join(artifactsDirectory, `ssh-native-${target}`)
    mkdirSync(directory, { recursive: true })
    writeFileSync(join(directory, binaryFileName(target)), override.binary ?? binary)
    writeFileSync(
      join(directory, `${binaryFileName(target)}.sha256`),
      override.shasum ?? `${sha256(binary)}  ${binaryFileName(target)}\n`
    )
  }
  return expectedSha256
}

/* eslint-disable no-template-curly-in-string -- Literal excerpt of npm's lib/utils/oidc.js. */
const NPM_OIDC_SOURCE = [
  "const audience = `npm:${new URL(registry).hostname}`",
  "url.searchParams.append('audience', audience)",
  "response = await npmFetch.json(new URL(`/-/npm/v1/oidc/token/exchange/package/${escapedPackageName}`, registry), {",
].join("\n")
const NPM_OIDC_AUDIENCE_SOURCE = "npm:${new URL(registry).hostname}"
/* eslint-enable no-template-curly-in-string */

function writeNpmInstallation(globalRoot, npmOptions) {
  const npmDirectory = join(globalRoot, "npm")
  mkdirSync(join(npmDirectory, "lib/utils"), { recursive: true })
  writeFileSync(
    join(npmDirectory, PACKAGE_JSON_FILE),
    JSON.stringify({ name: "npm", version: npmOptions?.installedVersion ?? NPM_VERSION })
  )
  writeFileSync(join(npmDirectory, "lib/utils/oidc.js"), npmOptions?.oidcSource ?? NPM_OIDC_SOURCE)
  return globalRoot
}

function captureConsole(logs) {
  const record = (...values) => {
    logs.push(values.map(String).join(" "))
  }
  const logMock = mock.method(console, "log", record)
  const errorMock = mock.method(console, "error", record)
  return () => {
    logMock.mock.restore()
    errorMock.mock.restore()
  }
}

async function runPublish(harness, runOptions) {
  const { environment = {}, fetchOptions = {}, fsOptions, mode = RELEASE_MODE } = runOptions
  const runId = runOptions.runId ?? CURRENT_RUN_ID
  const fs = createFs(fsOptions)
  const commandRunner = createCommandRunner({
    fs,
    npmRoot: harness.npmRoot,
    registry: harness.registry,
    runId,
    ...runOptions.runnerOptions,
  })
  const fetch = createFetch({ registry: harness.registry, ...fetchOptions })
  /** @type {string[]} */
  const workflowCommandLines = []
  const workflowCommands = {
    lines: workflowCommandLines,
    write: (text) => workflowCommandLines.push(text),
  }
  const logs = []
  const restoreConsole = captureConsole(logs)
  let error
  try {
    await publishWorkspacePackages({
      availabilityDelayMilliseconds: 0,
      availabilityRetries: runOptions.availabilityRetries ?? 2,
      commandRunner,
      environment: { ...harness.environment, GITHUB_RUN_ID: runId, ...environment },
      fetch,
      fs,
      mode,
      workflowCommands,
    })
  } catch (caughtError) {
    error = caughtError
  } finally {
    restoreConsole()
  }
  return { commandRunner, error, fetch, fs, logs, workflowCommands }
}

function createHarness(options) {
  const { artifactOverrides = {}, npm, registry = new Map(), sha256Overrides = {} } = options ?? {}
  const root = realpathSync(mkdtempSync(join(tmpdir(), "publish-b3-")))
  const artifactsDirectory = join(root, "artifacts")
  const expectedSha256 = writeArtifacts(artifactsDirectory, artifactOverrides)
  const stagingDirectory = join(root, "staging")
  const harness = {
    environment: {
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
      ACTIONS_ID_TOKEN_REQUEST_URL: ID_TOKEN_REQUEST_URL,
      PARATIX_PUBLISH_STAGING_DIR: stagingDirectory,
      SSH_NATIVE_ARTIFACTS_DIR: artifactsDirectory,
      SSH_NATIVE_SHA256: JSON.stringify({ ...expectedSha256, ...sha256Overrides }),
    },
    expectedSha256,
    npmRoot: writeNpmInstallation(join(root, "npm-global"), npm),
    registry,
    root,
    stagingDirectory,
    tarballDirectory: join(stagingDirectory, "tarballs"),
  }
  harness.run = (runOptions) => runPublish(harness, runOptions ?? {})
  return harness
}

// ---------------------------------------------------------------------------
// Assertion helpers (kept at module level so test bodies stay flat).
// ---------------------------------------------------------------------------

function isNpmPublishCall(call) {
  return call[0] === "npm" && call[1] === "publish"
}

function isNpmVersionViewCall(call) {
  return call[0] === "npm" && call[1] === "view" && call[3] === "version"
}

function npmPublishCalls(calls) {
  return calls.filter((call) => isNpmPublishCall(call))
}

function hasNpmPublishCall(calls) {
  return calls.some((call) => isNpmPublishCall(call))
}

function hasNpmViewCall(calls) {
  return calls.some((call) => call[0] === "npm" && call[1] === "view")
}

function hasPackCall(calls) {
  return calls.some((call) => call[0] === "pnpm")
}

function hasGitCall(calls) {
  return calls.some((call) => call[0] === "git")
}

function hasGitCommandCall(calls, gitCommand) {
  return calls.some((call) => call[0] === "git" && call.slice(1).join(" ") === gitCommand)
}

function publishedTarballNames(calls) {
  return npmPublishCalls(calls).map((call) => basename(call[2]))
}

function exchangeCalls(fetch) {
  return fetch.calls.filter((call) => call.pathname.startsWith(EXCHANGE_PATH))
}

function npmViewVersionCount(calls) {
  return calls.filter((call) => isNpmVersionViewCall(call)).length
}

function hasPackagesRootDirectoryRead(calls) {
  return calls.some(
    ([method, path]) => method === "readdir" && path === ABSOLUTE_PACKAGES_DIRECTORY
  )
}

function areAllFilesystemCallsAbsolute(calls) {
  return calls.every(([, path]) => path.startsWith("/"))
}

function logsContainSecret(result) {
  const output = [...result.logs, result.error?.message ?? ""].join("\n")
  return [REQUEST_TOKEN, ID_TOKEN, NPM_TOKEN_PREFIX].some((secret) => output.includes(secret))
}

function indexOfFirstPublish(calls) {
  return calls.findIndex((call) => isNpmPublishCall(call))
}

function indexOfNpmVersionCall(calls) {
  return calls.findIndex((call) => call[0] === "npm" && call[1] === "--version")
}

function repositoryAnchoredOptions(count) {
  return Array.from({ length: count }, () => ({ cwd: REPOSITORY_ROOT }))
}

function exactOptionalDependencies(version) {
  return Object.fromEntries(PLATFORM_NAMES.map((name) => [name, version]))
}

function findLogLine(logs, prefix) {
  return logs.find((line) => line.startsWith(prefix))
}

function assertGzipRejects(gzipBuffer, pattern) {
  assert.throws(() => readTarGzEntries(gzipBuffer), pattern)
}

function assertTarRejects(records, pattern) {
  assertGzipRejects(createTarGzFromRecords(records), pattern)
}

function assertSucceeded(result) {
  if (result.error !== undefined) throw result.error
}

function assertAbortedWithoutPublish(result, expectedMessage) {
  assert.ok(result.error, "publishWorkspacePackages should reject")
  assert.equal(result.error.message.includes(expectedMessage), true, result.error.message)
  assert.equal(hasNpmPublishCall(result.commandRunner.calls), false)
  assert.equal(logsContainSecret(result), false)
}

function readTarballEntries(harness, name, version = DEFAULT_STABLE_VERSION) {
  return readTarGzEntries(
    readFileSync(join(harness.tarballDirectory, tarballFileName(name, version)))
  )
}

function readPackedManifest(harness, name) {
  return JSON.parse(readTarballEntries(harness, name).get(PACKED_MANIFEST).toString("utf8"))
}

function setPackedManifest(entries, manifest) {
  entries.set(PACKED_MANIFEST, Buffer.from(JSON.stringify(manifest)))
}

async function assertRejectsWithMessage(promise, expectedMessage) {
  try {
    await promise
  } catch (error) {
    assert.equal(error.message.includes(expectedMessage), true, error.message)
    return
  }

  assert.fail("Expected promise to reject.")
}

// ---------------------------------------------------------------------------
// Release mode: happy paths and Git preflight.
// ---------------------------------------------------------------------------

describe("publishWorkspacePackages release mode", () => {
  it("#255 B3: publishes all nine tarballs in the fixed order with provenance", async () => {
    const harness = createHarness()

    const result = await harness.run()

    assertSucceeded(result)
    assert.deepEqual(
      publishedTarballNames(result.commandRunner.calls),
      expectedTarballNames(DEFAULT_STABLE_VERSION)
    )
    assert.deepEqual(npmPublishCalls(result.commandRunner.calls)[0].slice(3), [
      "--provenance",
      "--access",
      "public",
      "--tag",
      "latest",
    ])
    assert.equal(harness.registry.size, RELEASE_ORDER.length)
  })

  it("#255 B3: completes every preflight before the first npm publish", async () => {
    const harness = createHarness()

    const result = await harness.run()

    assertSucceeded(result)
    const calls = result.commandRunner.calls
    const firstPublishIndex = indexOfFirstPublish(calls)
    const npmVersionIndex = indexOfNpmVersionCall(calls)
    assert.equal(npmVersionIndex > 0 && npmVersionIndex < firstPublishIndex, true)
    assert.equal(npmViewVersionCount(calls.slice(0, firstPublishIndex)), RELEASE_ORDER.length)
    assert.equal(exchangeCalls(result.fetch).length, RELEASE_ORDER.length)
  })

  it("#255 B3: exchanges the OIDC token with npm's escaped package name and masks it", async () => {
    const harness = createHarness()

    const result = await harness.run()

    assertSucceeded(result)
    assert.equal(
      exchangeCalls(result.fetch)[0].url,
      `${REGISTRY_ORIGIN}${EXCHANGE_PATH}${FIRST_PLATFORM_NAME.replace("/", "%2f")}`
    )
    assert.equal(result.workflowCommands.lines.includes(`::add-mask::${ID_TOKEN}\n`), true)
    assert.equal(
      result.workflowCommands.lines.includes(
        `::add-mask::${NPM_TOKEN_PREFIX}${FIRST_PLATFORM_NAME}\n`
      ),
      true
    )
    assert.equal(logsContainSecret(result), false)
  })

  it("#255 B3: logs the npm version and the tarball directory", async () => {
    const harness = createHarness()

    const result = await harness.run()

    assertSucceeded(result)
    assert.equal(result.logs.includes(`Using npm ${NPM_VERSION}.`), true)
    assert.equal(
      result.logs.includes(`Release tarball directory: ${harness.tarballDirectory}`),
      true
    )
  })

  it("skips all packages when the same workflow run already published them", async () => {
    const harness = createHarness()
    assertSucceeded(await harness.run())

    const result = await harness.run()

    assertSucceeded(result)
    assert.equal(hasNpmPublishCall(result.commandRunner.calls), false)
    assert.equal(exchangeCalls(result.fetch).length, 0)
    assert.equal(result.commandRunner.diffCalls.length, 0)
  })

  it("anchors filesystem reads and npm publish to the repository root from a foreign cwd", async () => {
    const harness = createHarness()
    const originalCwd = process.cwd()
    const foreignCwd = realpathSync(mkdtempSync(join(tmpdir(), "publish-foreign-cwd-")))
    let result
    try {
      process.chdir(foreignCwd)
      result = await harness.run()
    } finally {
      process.chdir(originalCwd)
    }

    assertSucceeded(result)
    assert.equal(areAllFilesystemCallsAbsolute(result.fs.calls), true)
    assert.equal(hasPackagesRootDirectoryRead(result.fs.calls), true)
    assert.deepEqual(
      result.commandRunner.spawnOptions,
      repositoryAnchoredOptions(RELEASE_ORDER.length)
    )
    assert.equal(existsSync(join(foreignCwd, "tarballs")), false)
  })

  it("rejects a dirty Git working tree before registry lookups", async () => {
    const result = await createHarness().run({
      runnerOptions: { gitStatus: " M scripts/publishWorkspacePackages.mjs\n" },
    })

    assertAbortedWithoutPublish(result, "dirty Git working tree")
    assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
  })

  it("rejects a non-main local Git branch before registry lookups", async () => {
    const result = await createHarness().run({ runnerOptions: { gitBranch: "release-candidate" } })

    assertAbortedWithoutPublish(result, "expected main")
    assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
  })

  it("allows a GitHub Actions detached checkout when the ref and SHA match", async () => {
    const result = await createHarness().run({
      environment: { GITHUB_ACTIONS: "true", GITHUB_REF: MAIN_REF, GITHUB_SHA: GIT_HEAD_SHA },
    })

    assertSucceeded(result)
    assert.equal(hasGitCommandCall(result.commandRunner.calls, GIT_REV_PARSE_HEAD_COMMAND), true)
    assert.equal(
      hasGitCommandCall(result.commandRunner.calls, GIT_SYMBOLIC_REF_BRANCH_COMMAND),
      false
    )
  })

  it("rejects a non-main GitHub Actions ref before registry lookups", async () => {
    const result = await createHarness().run({
      environment: {
        GITHUB_ACTIONS: "true",
        GITHUB_REF: "refs/tags/v1.2.3",
        GITHUB_SHA: GIT_HEAD_SHA,
      },
    })

    assertAbortedWithoutPublish(result, "expected refs/heads/main")
    assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
  })

  it("rejects a mismatched GitHub Actions SHA before registry lookups", async () => {
    const result = await createHarness().run({
      environment: { GITHUB_ACTIONS: "true", GITHUB_REF: MAIN_REF, GITHUB_SHA: "different-sha" },
    })

    assertAbortedWithoutPublish(result, "expected checked-out HEAD")
    assert.equal(hasGitCommandCall(result.commandRunner.calls, GIT_REV_PARSE_HEAD_COMMAND), true)
    assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
  })

  it("rejects unsupported publish modes", async () => {
    await assertRejectsWithMessage(
      publishWorkspacePackages({ fs: createFs(), mode: "manual" }),
      "Unsupported publish mode"
    )
  })

  it("#255 B3: rejects the removed recover-create-paratix mode with a pointer to release", async () => {
    await assertRejectsWithMessage(
      publishWorkspacePackages({ fs: createFs(), mode: "recover-create-paratix" }),
      'was removed. Run the "release" mode instead'
    )
  })
})

// ---------------------------------------------------------------------------
// Resume after partial releases.
// ---------------------------------------------------------------------------

async function assertSameRunResume(abortAfter) {
  const harness = createHarness()
  const abortedRun = await harness.run({ runnerOptions: { abortAfterPublish: abortAfter } })
  assert.equal(abortedRun.error?.message, SIMULATED_ABORT_MESSAGE)
  assert.equal(harness.registry.size, abortAfter)

  const resumedRun = await harness.run()

  assertSucceeded(resumedRun)
  assert.deepEqual(
    publishedTarballNames(resumedRun.commandRunner.calls),
    expectedTarballNames(DEFAULT_STABLE_VERSION).slice(abortAfter)
  )
  assert.equal(resumedRun.commandRunner.diffCalls.length, 0)
  assert.equal(harness.registry.size, RELEASE_ORDER.length)
}

async function assertNewRunResume(abortAfter) {
  const harness = createHarness()
  const abortedRun = await harness.run({ runnerOptions: { abortAfterPublish: abortAfter } })
  assert.equal(abortedRun.error?.message, SIMULATED_ABORT_MESSAGE)

  const resumedRun = await harness.run({
    runId: "2000",
    runnerOptions: { gitHeadSha: "c".repeat(40) },
  })

  assertSucceeded(resumedRun)
  assert.deepEqual(
    publishedTarballNames(resumedRun.commandRunner.calls),
    expectedTarballNames(DEFAULT_STABLE_VERSION).slice(abortAfter)
  )
  // Only the seven native packages compare their binary inputs; paratix and
  // create-paratix from an earlier run are skipped on provenance alone.
  assert.equal(
    resumedRun.commandRunner.diffCalls.length,
    Math.min(abortAfter, NATIVE_PACKAGE_COUNT)
  )
  assert.equal(
    resumedRun.commandRunner.diffCalls[0],
    `diff --quiet ${HEAD_COMMIT}..HEAD -- ${NATIVE_DIFF_PATHS}`
  )
}

describe("publishWorkspacePackages resume after an aborted release", () => {
  for (let abortAfter = 1; abortAfter <= RELEASE_ORDER.length; abortAfter += 1) {
    it(`#255 B3: resumes in the same workflow run after publish step ${abortAfter}`, async () => {
      await assertSameRunResume(abortAfter)
    })

    it(`#255 B3: resumes in a new workflow run after publish step ${abortAfter}`, async () => {
      await assertNewRunResume(abortAfter)
    })
  }

  it("#255 B3: publishes create-paratix when everything else came from an earlier run", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, RELEASE_ORDER.slice(0, -1))

    const result = await harness.run()

    assertSucceeded(result)
    assert.deepEqual(publishedTarballNames(result.commandRunner.calls), [
      tarballFileName(CREATE_PARATIX_NAME, DEFAULT_STABLE_VERSION),
    ])
    assert.equal(result.commandRunner.diffCalls.length, NATIVE_PACKAGE_COUNT)
    assert.equal(exchangeCalls(result.fetch).length, 1)
  })

  it("#255 B3: still checks paratix freshness when only create-paratix is missing", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, RELEASE_ORDER.slice(0, -1))

    const result = await harness.run({
      fsOptions: { mtimes: { [PARATIX_DIST_DIRECTORY]: 500, [PARATIX_DIST_INDEX_PATH]: 500 } },
    })

    assertAbortedWithoutPublish(result, STALE_ARTEFACT_MESSAGE_FRAGMENT)
  })

  it("fails clearly when create-paratix is published without a matching paratix runtime", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [...PLATFORM_NAMES, SSH_NATIVE_NAME, CREATE_PARATIX_NAME])

    const result = await harness.run()

    assertAbortedWithoutPublish(
      result,
      "create-paratix@1.2.3 is already published, but paratix@1.2.3 is not available"
    )
    assert.equal(exchangeCalls(result.fetch).length, 0)
  })

  it("#255 B3: aborts when a later package is published but an earlier platform package is not", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [PLATFORM_NAMES[1]])

    const result = await harness.run()

    assertAbortedWithoutPublish(result, `${FIRST_PLATFORM_NAME}@1.2.3 is not available`)
  })
})

// ---------------------------------------------------------------------------
// Release preflight aborts.
// ---------------------------------------------------------------------------

describe("publishWorkspacePackages trusted publishing preflight", () => {
  for (const status of [401, 404]) {
    it(`#255 B3: aborts when the token exchange answers ${status}`, async () => {
      const result = await createHarness().run({
        fetchOptions: { exchangeStatus: { [CREATE_PARATIX_NAME]: status } },
      })

      assertAbortedWithoutPublish(result, `create-paratix ${NOT_PUBLISHABLE_FRAGMENT}`)
      assert.equal(result.error.message.includes("scripts/configure-trust.sh"), true)
    })
  }

  for (const variable of ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"]) {
    it(`#255 B3: aborts when ${variable} is missing`, async () => {
      const result = await createHarness().run({ environment: { [variable]: "" } })

      assertAbortedWithoutPublish(result, NOT_PUBLISHABLE_FRAGMENT)
      assert.equal(exchangeCalls(result.fetch).length, 0)
    })
  }

  it("#255 B3: aborts when the ID token request fails", async () => {
    const result = await createHarness().run({ fetchOptions: { idTokenStatus: 500 } })

    assertAbortedWithoutPublish(result, NOT_PUBLISHABLE_FRAGMENT)
  })

  it("#255 B3: aborts when the npm package version differs from npm --version", async () => {
    const result = await createHarness({ npm: { installedVersion: "11.17.0" } }).run()

    assertAbortedWithoutPublish(result, NPM_SOURCE_FRAGMENT)
    assert.equal(exchangeCalls(result.fetch).length, 0)
  })

  it("#255 B3: aborts when npm's oidc.js no longer contains the verified endpoint", async () => {
    const oidcSource = NPM_OIDC_SOURCE.replace("/token/exchange/package/", "/token/exchange/v2/")
    const result = await createHarness({ npm: { oidcSource } }).run()

    assertAbortedWithoutPublish(result, NPM_SOURCE_FRAGMENT)
    assert.equal(result.error.message.includes("token exchange endpoint not found"), true)
  })

  it("#255 B3: aborts when npm's oidc.js no longer builds the verified audience", async () => {
    const oidcSource = NPM_OIDC_SOURCE.replace(NPM_OIDC_AUDIENCE_SOURCE, "npm:registry")
    const result = await createHarness({ npm: { oidcSource } }).run()

    assertAbortedWithoutPublish(result, "audience construction not found")
  })

  it("#255 B3: skips the npm source check when nothing is missing", async () => {
    const harness = createHarness({ npm: { installedVersion: "0.0.0" } })
    publishedEarlier(harness.registry, RELEASE_ORDER)

    const result = await harness.run()

    assertSucceeded(result)
    assert.equal(indexOfNpmVersionCall(result.commandRunner.calls), -1)
  })
})

function withWorkflow(statement, patch) {
  const copy = structuredClone(statement)
  const { externalParameters } = copy.predicate.buildDefinition
  externalParameters.workflow = { ...externalParameters.workflow, ...patch }
  return copy
}

function withSubject(statement, patch) {
  const copy = structuredClone(statement)
  copy.subject = [{ ...copy.subject[0], ...patch }]
  return copy
}

const tamperedProvenanceCases = [
  {
    expected: "dist.attestations.url is missing",
    name: "missing attestations",
    tamperEntry: (entry) => ({ ...entry, dist: { integrity: entry.integrity } }),
  },
  {
    expected: "foreign build workflow: repository",
    name: "a foreign repository",
    tamperStatement: (statement) =>
      withWorkflow(statement, { repository: "https://github.com/someone-else/paratix" }),
  },
  {
    expected: "foreign build workflow: path",
    name: "a foreign workflow path",
    tamperStatement: (statement) =>
      withWorkflow(statement, { path: ".github/workflows/other.yml" }),
  },
  {
    expected: "foreign build workflow: ref",
    name: "a foreign ref",
    tamperStatement: (statement) => withWorkflow(statement, { ref: "refs/heads/feature" }),
  },
  {
    expected: "the provenance payload is unreadable",
    name: "an unreadable payload",
    tamperEntry: (entry) => ({ ...entry, payload: "not-json-at-all" }),
  },
  {
    expected: "subject sha512 digest does not match",
    name: "a subject digest mismatch",
    tamperStatement: (statement) => withSubject(statement, { digest: { sha512: "0".repeat(128) } }),
  },
  {
    expected: "no subject pkg:npm/%40paratix/ssh-native-linux-x64-gnu@1.2.3",
    name: "a foreign subject name",
    tamperStatement: (statement) =>
      withSubject(statement, { name: "pkg:npm/%40paratix/other@1.2.3" }),
  },
  {
    expected: "no SLSA v1 provenance attestation",
    name: "no SLSA attestation",
    tamperEntry: (entry) => ({ ...entry, attestationsBody: { attestations: [] } }),
  },
]

function applyProvenanceTamper(registry, testCase) {
  const specifier = `${FIRST_PLATFORM_NAME}@${DEFAULT_STABLE_VERSION}`
  const entry = registry.get(specifier)
  const tamperedEntry = testCase.tamperEntry?.(entry) ?? entry
  registry.set(specifier, { ...tamperedEntry, tamper: testCase.tamperStatement })
}

describe("publishWorkspacePackages provenance of published versions", () => {
  for (const testCase of tamperedProvenanceCases) {
    it(`#255 B3: aborts on ${testCase.name}`, async () => {
      const harness = createHarness()
      publishedEarlier(harness.registry, [FIRST_PLATFORM_NAME])
      applyProvenanceTamper(harness.registry, testCase)

      const result = await harness.run()

      assertAbortedWithoutPublish(result, PROVENANCE_FRAGMENT)
      assert.equal(result.error.message.includes(testCase.expected), true, result.error.message)
      assert.equal(exchangeCalls(result.fetch).length, 0)
    })
  }

  it("#255 B3: aborts when the same run published a tarball with a different integrity", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [FIRST_PLATFORM_NAME], { runId: CURRENT_RUN_ID })

    const result = await harness.run()

    assertAbortedWithoutPublish(result, "differs from the local tarball")
  })

  it("#255 B3: aborts when packages/ssh-native changed since the earlier run", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [FIRST_PLATFORM_NAME])

    const result = await harness.run({ runnerOptions: { diffExitCode: 1 } })

    assertAbortedWithoutPublish(
      result,
      "packages/ssh-native and .github/workflows/ssh-native.yml changed since then"
    )
    assert.deepEqual(result.commandRunner.diffCalls, [
      `diff --quiet ${EARLIER_COMMIT}..HEAD -- ${NATIVE_DIFF_PATHS}`,
    ])
  })

  it("#255 B3: skips paratix from an earlier run without comparing the native sources", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, RELEASE_ORDER.slice(0, -1))

    const result = await harness.run({ runnerOptions: { diffExitCode: 0 } })

    assertSucceeded(result)
    assert.equal(result.commandRunner.diffCalls.length, NATIVE_PACKAGE_COUNT)
  })

  it("#255 B3: aborts with a fetch-depth hint when the earlier commit is unknown", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [FIRST_PLATFORM_NAME])

    const result = await harness.run({ runnerOptions: { diffExitCode: 128 } })

    assertAbortedWithoutPublish(result, "fetch-depth: 0")
  })

  it("#255 B3: aborts when the attestation is served from a foreign origin", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [FIRST_PLATFORM_NAME])
    applyProvenanceTamper(harness.registry, {
      tamperEntry: (entry) => ({
        ...entry,
        dist: {
          attestations: { url: "https://evil.example/attestation" },
          integrity: entry.integrity,
        },
      }),
    })

    const result = await harness.run()

    assertAbortedWithoutPublish(result, "attestations are served from https://evil.example")
  })
})

// ---------------------------------------------------------------------------
// Artifacts, staging and tarball inspection (both modes).
// ---------------------------------------------------------------------------

function setPackedOptionalDependencies(entries, manifest, optionalDependencies) {
  setPackedManifest(entries, { ...manifest, optionalDependencies })
}

function removeOptionalDependency({ entries, manifest, name }) {
  if (name !== SSH_NATIVE_NAME) return
  const { [PLATFORM_NAMES[2]]: _removed, ...optionalDependencies } = manifest.optionalDependencies
  setPackedOptionalDependencies(entries, manifest, optionalDependencies)
}

function mismatchOptionalDependencyVersion({ entries, manifest, name }) {
  if (name !== SSH_NATIVE_NAME) return
  setPackedOptionalDependencies(entries, manifest, {
    ...manifest.optionalDependencies,
    [PLATFORM_NAMES[3]]: "1.2.2",
  })
}

function addExtraOptionalDependency({ entries, manifest, name }) {
  if (name !== SSH_NATIVE_NAME) return
  setPackedOptionalDependencies(entries, manifest, {
    ...manifest.optionalDependencies,
    "@paratix/ssh-native-win32-x64-msvc": DEFAULT_STABLE_VERSION,
  })
}

function addBinaryToLoader({ entries, name }) {
  if (name === SSH_NATIVE_NAME) entries.set("package/lib/stray.node", Buffer.from("binary"))
}

function renamePlatformBinary({ entries, name }) {
  if (name !== FIRST_PLATFORM_NAME) return
  const binaryEntry = `package/${binaryFileName(FIRST_TARGET)}`
  entries.set("package/ssh-native.node", entries.get(binaryEntry))
  entries.delete(binaryEntry)
}

function removePlatformBinary({ entries, name }) {
  if (name === FIRST_PLATFORM_NAME) entries.delete(`package/${binaryFileName(FIRST_TARGET)}`)
}

function addExtraPlatformBinary({ entries, name }) {
  if (name === FIRST_PLATFORM_NAME) entries.set("package/extra.node", Buffer.from("extra"))
}

function replacePlatformBinary({ entries, name }) {
  if (name === FIRST_PLATFORM_NAME) {
    entries.set(`package/${binaryFileName(FIRST_TARGET)}`, Buffer.from("tampered"))
  }
}

function addPackedWorkspaceSpecifier({ entries, manifest, name }) {
  if (name !== CREATE_PARATIX_NAME) return
  setPackedManifest(entries, { ...manifest, dependencies: { paratix: "workspace:*" } })
}

function renamePackedPackage({ entries, manifest, name }) {
  if (name === PARATIX_NAME) setPackedManifest(entries, { ...manifest, name: "paratix-fork" })
}

const tarballTamperCases = [
  {
    expected: `${PLATFORM_NAMES[2]} is missing`,
    hook: removeOptionalDependency,
    name: "a missing optional dependency",
  },
  {
    expected: `${PLATFORM_NAMES[3]} is pinned to 1.2.2`,
    hook: mismatchOptionalDependencyVersion,
    name: "an optional dependency version mismatch",
  },
  {
    expected: "ssh-native-win32-x64-msvc is unexpected",
    hook: addExtraOptionalDependency,
    name: "an extra optional dependency",
  },
  {
    expected: "must not contain native binaries",
    hook: addBinaryToLoader,
    name: "a .node file in the ssh-native tarball",
  },
  {
    expected: BINARY_COUNT_FRAGMENT,
    hook: renamePlatformBinary,
    name: "a wrongly named platform binary",
  },
  {
    expected: BINARY_COUNT_FRAGMENT,
    hook: removePlatformBinary,
    name: "a missing platform binary",
  },
  {
    expected: BINARY_COUNT_FRAGMENT,
    hook: addExtraPlatformBinary,
    name: "an extra platform binary",
  },
  {
    expected: "has SHA-256",
    hook: replacePlatformBinary,
    name: "a packed binary with a different SHA-256",
  },
  {
    expected: "contains workspace: specifiers",
    hook: addPackedWorkspaceSpecifier,
    name: "a workspace: specifier in a packed manifest",
  },
  {
    expected: "packed package.json declares paratix-fork@1.2.3",
    hook: renamePackedPackage,
    name: "a packed manifest with a foreign name",
  },
]

describe("publishWorkspacePackages tarball inspection", () => {
  for (const mode of [RELEASE_MODE, VERIFY_MODE]) {
    for (const testCase of tarballTamperCases) {
      it(`#255 B3: ${mode} aborts on ${testCase.name}`, async () => {
        const result = await createHarness().run({
          mode,
          runnerOptions: { packHook: testCase.hook },
        })

        assertAbortedWithoutPublish(result, testCase.expected)
        assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
      })
    }
  }

  it("#255 B3: stages the loader without native binaries and with exact optionalDependencies", async () => {
    const harness = createHarness()

    const result = await harness.run({ mode: VERIFY_MODE })

    assertSucceeded(result)
    const loaderEntries = [...readTarballEntries(harness, SSH_NATIVE_NAME).keys()].sort()
    assert.deepEqual(loaderEntries, [
      "package/LICENSE",
      "package/README.md",
      "package/index.d.ts",
      "package/index.js",
      "package/lib/connect.js",
      "package/lib/native.js",
      "package/loader.js",
      PACKED_MANIFEST,
    ])
    assert.deepEqual(
      readPackedManifest(harness, SSH_NATIVE_NAME).optionalDependencies,
      exactOptionalDependencies(DEFAULT_STABLE_VERSION)
    )
  })

  it("#255 B3: packs each platform binary byte-identical to the CI artifact", async () => {
    const harness = createHarness()

    assertSucceeded(await harness.run({ mode: VERIFY_MODE }))

    const entries = readTarballEntries(harness, FIRST_PLATFORM_NAME)
    assert.equal(
      sha256(entries.get(`package/${binaryFileName(FIRST_TARGET)}`)),
      harness.expectedSha256[FIRST_TARGET]
    )
  })

  it("#255 B3: refuses a staging directory inside the repository", async () => {
    const result = await createHarness().run({
      environment: { PARATIX_PUBLISH_STAGING_DIR: join(REPOSITORY_ROOT, ".publish-staging") },
      mode: VERIFY_MODE,
    })

    assertAbortedWithoutPublish(result, "must be outside the repository")
    assert.equal(hasPackCall(result.commandRunner.calls), false)
  })

  it("#255 B3: refuses a staging directory that contains the repository", async () => {
    const result = await createHarness().run({
      environment: { PARATIX_PUBLISH_STAGING_DIR: dirname(REPOSITORY_ROOT) },
    })

    assertAbortedWithoutPublish(result, "must be a dedicated directory")
    assert.equal(hasPackCall(result.commandRunner.calls), false)
  })

  it("#255 B3: recreates the staging directory empty", async () => {
    const harness = createHarness()
    mkdirSync(harness.tarballDirectory, { recursive: true })
    writeFileSync(join(harness.tarballDirectory, "stale.tgz"), "stale")

    assertSucceeded(await harness.run({ mode: VERIFY_MODE }))

    assert.equal(existsSync(join(harness.tarballDirectory, "stale.tgz")), false)
  })

  it("#255 B3: defaults the staging directory to $RUNNER_TEMP/paratix-publish", async () => {
    const harness = createHarness()
    const runnerTemporaryDirectory = join(harness.root, "runner-temp")

    const result = await harness.run({
      environment: { PARATIX_PUBLISH_STAGING_DIR: "", RUNNER_TEMP: runnerTemporaryDirectory },
      mode: VERIFY_MODE,
    })

    assertSucceeded(result)
    assert.equal(
      readdirSync(join(runnerTemporaryDirectory, "paratix-publish/tarballs")).length,
      RELEASE_ORDER.length
    )
  })
})

const artifactCases = [
  {
    expected: SHA_MISMATCH_FRAGMENT,
    harnessOptions: {
      artifactOverrides: { [FIRST_TARGET]: { binary: Buffer.from("other binary") } },
    },
    name: "a binary that differs from its .sha256 file and SSH_NATIVE_SHA256",
  },
  {
    expected: SHA_MISMATCH_FRAGMENT,
    harnessOptions: {
      artifactOverrides: {
        [FIRST_TARGET]: { shasum: `${"0".repeat(64)}  ${binaryFileName(FIRST_TARGET)}\n` },
      },
    },
    name: "a .sha256 file that differs from the binary",
  },
  {
    expected: SHA_MISMATCH_FRAGMENT,
    harnessOptions: { sha256Overrides: { [FIRST_TARGET]: "1".repeat(64) } },
    name: "an SSH_NATIVE_SHA256 entry that differs from the binary",
  },
  {
    expected: `must contain "<sha256>  ${binaryFileName(FIRST_TARGET)}"`,
    harnessOptions: { artifactOverrides: { [FIRST_TARGET]: { shasum: "garbage\n" } } },
    name: "a malformed .sha256 file",
  },
  {
    expected: "Missing or unreadable ssh-native artifact",
    harnessOptions: { artifactOverrides: { [FIRST_TARGET]: { missing: true } } },
    name: "a missing artifact",
  },
  {
    expected: "unknown targets: win32-x64-msvc",
    harnessOptions: { sha256Overrides: { "win32-x64-msvc": "2".repeat(64) } },
    name: "an unknown target in SSH_NATIVE_SHA256",
  },
]

describe("publishWorkspacePackages native artifact checks", () => {
  for (const testCase of artifactCases) {
    it(`#255 B3: aborts on ${testCase.name}`, async () => {
      const result = await createHarness(testCase.harnessOptions).run({ mode: VERIFY_MODE })

      assertAbortedWithoutPublish(result, testCase.expected)
      assert.equal(hasPackCall(result.commandRunner.calls), false)
    })
  }

  it("#255 B3: aborts on an artifact directory for an unknown target", async () => {
    const harness = createHarness()
    mkdirSync(join(harness.environment.SSH_NATIVE_ARTIFACTS_DIR, "ssh-native-win32-x64-msvc"))

    const result = await harness.run({ mode: VERIFY_MODE })

    assertAbortedWithoutPublish(result, "artifacts for unknown targets: ssh-native-win32-x64-msvc")
  })

  it("#255 B3: aborts when a target is missing from SSH_NATIVE_SHA256", async () => {
    const harness = createHarness()
    const { [FIRST_TARGET]: _omitted, ...partialSha256 } = harness.expectedSha256

    const result = await harness.run({
      environment: { SSH_NATIVE_SHA256: JSON.stringify(partialSha256) },
      mode: VERIFY_MODE,
    })

    assertAbortedWithoutPublish(result, `missing targets: ${FIRST_TARGET}`)
  })

  for (const variable of ["SSH_NATIVE_ARTIFACTS_DIR", "SSH_NATIVE_SHA256"]) {
    it(`#255 B3: requires ${variable}`, async () => {
      const result = await createHarness().run({
        environment: { [variable]: "" },
        mode: VERIFY_MODE,
      })

      assertAbortedWithoutPublish(result, `${variable} is required`)
    })
  }

  it("#255 B3: rejects SSH_NATIVE_SHA256 that is not a JSON object", async () => {
    const result = await createHarness().run({
      environment: { SSH_NATIVE_SHA256: "not json" },
      mode: VERIFY_MODE,
    })

    assertAbortedWithoutPublish(result, "SSH_NATIVE_SHA256 must be a JSON object")
  })
})

// ---------------------------------------------------------------------------
// Verify mode.
// ---------------------------------------------------------------------------

describe("publishWorkspacePackages verify mode", () => {
  it("#255 B3: packs nine tarballs without Git preflight, OIDC or publish", async () => {
    const harness = createHarness()

    const result = await harness.run({
      environment: { ACTIONS_ID_TOKEN_REQUEST_URL: "" },
      mode: VERIFY_MODE,
      runnerOptions: { gitBranch: "release-candidate", gitStatus: " M scripts/x.mjs\n" },
    })

    assertSucceeded(result)
    assert.deepEqual(
      readdirSync(harness.tarballDirectory).sort(),
      expectedTarballNames(DEFAULT_STABLE_VERSION).sort()
    )
    assert.equal(hasNpmPublishCall(result.commandRunner.calls), false)
    assert.equal(hasGitCall(result.commandRunner.calls), false)
    assert.equal(result.fetch.calls.length, 0)
    assert.equal(npmViewVersionCount(result.commandRunner.calls), RELEASE_ORDER.length)
  })

  it("#255 B3: reports new and already published versions", async () => {
    const harness = createHarness()
    publishedEarlier(harness.registry, [PARATIX_NAME, CREATE_PARATIX_NAME])

    const result = await harness.run({ mode: VERIFY_MODE })

    assertSucceeded(result)
    const summaryLine = findLogLine(result.logs, "Verified 9 release tarballs")
    assert.equal(summaryLine?.includes("7 new, 2 already published"), true, summaryLine)
  })

  it("#255 B3: appends a markdown table to GITHUB_STEP_SUMMARY", async () => {
    const harness = createHarness()
    const summaryPath = join(harness.root, "step-summary.md")

    const result = await harness.run({
      environment: { GITHUB_STEP_SUMMARY: summaryPath },
      mode: VERIFY_MODE,
    })

    assertSucceeded(result)
    const summary = readFileSync(summaryPath, "utf8")
    assert.equal(summary.includes("| Package | Version | Tarball | Integrity | npm |"), true)
    assert.equal(summary.includes(`| ${FIRST_PLATFORM_NAME} | 1.2.3 |`), true)
    assert.equal(summary.split("| new |").length - 1, RELEASE_ORDER.length)
  })

  it("packs prerelease tarballs in verify mode", async () => {
    const harness = createHarness()

    const result = await harness.run({
      fsOptions: { version: BETA_PRERELEASE_VERSION },
      mode: VERIFY_MODE,
    })

    assertSucceeded(result)
    assert.deepEqual(
      readdirSync(harness.tarballDirectory).sort(),
      expectedTarballNames(BETA_PRERELEASE_VERSION).sort()
    )
  })
})

// ---------------------------------------------------------------------------
// Manifest validation and dist freshness (before anything is packed).
// ---------------------------------------------------------------------------

async function assertAbortsBeforeAnyCommand(fsOptions, expectedMessage) {
  const result = await createHarness().run({ fsOptions })
  assertAbortedWithoutPublish(result, expectedMessage)
  assert.equal(result.commandRunner.calls.length, 0)
  return result
}

describe("publishWorkspacePackages release validations", () => {
  it("rejects mismatched workspace package versions before publishing", async () => {
    await assertAbortsBeforeAnyCommand({ createParatixVersion: "1.2.4" }, "versions must match")
  })

  it("#255 B3: rejects a platform manifest with a diverging version", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        manifestOverrides: {
          [`${SSH_NATIVE_DIRECTORY}/npm/darwin-arm64/package.json`]: (manifest) => ({
            ...manifest,
            version: "1.2.4",
          }),
        },
      },
      "@paratix/ssh-native-darwin-arm64@1.2.4"
    )
  })

  it("#255 B3: rejects a platform manifest whose files differ from its binary", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        manifestOverrides: {
          [`${SSH_NATIVE_DIRECTORY}/npm/${FIRST_TARGET}/package.json`]: (manifest) => ({
            ...manifest,
            files: [binaryFileName(FIRST_TARGET), "extra.node"],
          }),
        },
      },
      `must declare "files": ["${binaryFileName(FIRST_TARGET)}"]`
    )
  })

  it("#255 B3: rejects a manifest with an unexpected package name", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        manifestOverrides: {
          [SSH_NATIVE_MANIFEST_PATH]: (manifest) => ({ ...manifest, name: "ssh-native" }),
        },
      },
      "has unexpected package name ssh-native"
    )
  })

  it("#255 B3: rejects a workspace: specifier in a source manifest", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        manifestOverrides: {
          [SSH_NATIVE_MANIFEST_PATH]: (manifest) => ({
            ...manifest,
            devDependencies: { paratix: "workspace:^" },
          }),
        },
      },
      "contains workspace: specifiers (devDependencies.paratix)"
    )
  })

  // R-0000660: `npm publish` defaults to `--tag latest`, which would silently
  // overwrite the `latest` dist-tag with a prerelease build. Versions
  // containing a SemVer prerelease segment must publish under `next`
  // instead, while stable versions must continue to set `--tag latest`
  // explicitly so the dist-tag intent never depends on npm's default.
  it("R-0000660: publishes prerelease versions under --tag next", async () => {
    await assertPublishCallsUseDistributionTag({
      expectedTag: "next",
      version: BETA_PRERELEASE_VERSION,
    })
  })

  it("R-0000660: keeps stable versions with build metadata on --tag latest", async () => {
    await assertPublishCallsUseDistributionTag({
      expectedTag: "latest",
      version: STABLE_BUILD_METADATA_VERSION,
    })
  })

  // R-0000861: npm publish can exit 0 before the registry exposes the
  // new version. The publish flow must spend the bounded propagation
  // retry budget instead of treating the first missing `npm view` as a
  // hard failure.
  it("R-0000861: retries registry propagation after npm publish", async () => {
    const harness = createHarness()

    const result = await harness.run({
      availabilityRetries: 3,
      runnerOptions: { hiddenViewsAfterPublish: { [PARATIX_NAME]: 2 } },
    })

    assertSucceeded(result)
    // One classification lookup plus three availability attempts.
    assert.equal(result.commandRunner.viewCounts.get(`${PARATIX_NAME}@1.2.3`), 4)
    assert.equal(harness.registry.size, RELEASE_ORDER.length)
  })

  it("R-0000861: stops after the availability retry budget", async () => {
    const result = await createHarness().run({
      availabilityRetries: 2,
      runnerOptions: { hiddenViewsAfterPublish: { [FIRST_PLATFORM_NAME]: 5 } },
    })

    assert.equal(
      result.error?.message.includes("was not visible in the npm registry after 2 attempts"),
      true
    )
    assert.equal(npmPublishCalls(result.commandRunner.calls).length, 1)
  })
})

describe("publishWorkspacePackages dist freshness", () => {
  // R-0000661: refuse to pack or publish when dist artefacts referenced by
  // package.json#files are missing. Without the guard, a skipped build
  // would publish empty or stale tarballs under --provenance, and signed
  // bad artefacts cannot easily be retracted from the registry.
  it("R-0000661: aborts when a dist artefact referenced by files is missing", async () => {
    await assertAbortsBeforeAnyCommand(
      { mtimes: { [PARATIX_DIST_DIRECTORY]: undefined, [PARATIX_DIST_INDEX_PATH]: undefined } },
      "package.json#files is missing"
    )
  })

  it("R-0000661: aborts when a create-paratix dist artefact is missing", async () => {
    const result = await assertAbortsBeforeAnyCommand(
      { mtimes: { "packages/create-paratix/dist/index.js": undefined } },
      "is missing"
    )

    assert.equal(result.error.message.includes(CREATE_PARATIX_NAME), true, result.error.message)
  })

  it("R-0000661: aborts when a dist artefact mtime is older than the src tree", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        mtimes: {
          [PARATIX_DIST_DIRECTORY]: 500,
          [PARATIX_DIST_INDEX_PATH]: 500,
          [PARATIX_LLM_GUIDE_PATH]: 500,
          [PARATIX_SOURCE_DIRECTORY]: 5000,
          [PARATIX_SOURCE_INDEX_PATH]: 5000,
        },
      },
      STALE_ARTEFACT_MESSAGE_FRAGMENT
    )
  })

  it("aborts when dist output is older than a build configuration input", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        mtimes: {
          [PARATIX_DIST_DIRECTORY]: 500,
          [PARATIX_DIST_INDEX_PATH]: 500,
          [PARATIX_TSUP_CONFIG_PATH]: 5000,
        },
      },
      STALE_ARTEFACT_MESSAGE_FRAGMENT
    )
  })

  it("aborts when stale dist output is masked by a fresh non-built file", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        mtimes: {
          [PARATIX_DIST_DIRECTORY]: 9000,
          [PARATIX_DIST_INDEX_PATH]: 500,
          [PARATIX_LLM_GUIDE_PATH]: 9000,
          [PARATIX_SOURCE_DIRECTORY]: 5000,
          [PARATIX_SOURCE_INDEX_PATH]: 5000,
        },
      },
      STALE_ARTEFACT_MESSAGE_FRAGMENT
    )
  })

  it("R-0000661: aborts when package.json#files is empty", async () => {
    await assertAbortsBeforeAnyCommand({ paratixFiles: [] }, 'must declare a "files" allowlist')
  })

  // R-0000862: top-level package.json#files entries must be materialised
  // artefacts. A symlinked files entry would be treated as mtime 0 by the
  // freshness walker and could let a package with no real publish
  // artefact slip through when the source side is also skipped as a
  // symlink. Reject it before any registry side effect.
  it("R-0000862: aborts when a package.json#files entry is a symlink", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        mtimes: {
          [PARATIX_DIST_DIRECTORY]: 9999,
          [PARATIX_SOURCE_DIRECTORY]: STALE_SOURCE_MTIME,
          [PARATIX_SOURCE_INDEX_PATH]: 9999,
        },
        symlinks: [PARATIX_DIST_DIRECTORY, PARATIX_SOURCE_INDEX_PATH],
      },
      SYMLINK_FILES_FRAGMENT
    )
  })

  // R-0000685: a missing `src/` directory previously leaked the raw
  // ENOENT from `readdir`. The operator-friendly translation has to
  // mention the directory and the remediation ("run pnpm build").
  it("R-0000685: surfaces an operator-friendly error when src/ is missing", async () => {
    await assertAbortsBeforeAnyCommand(
      { readdirErrors: { [PARATIX_SOURCE_DIRECTORY]: ENOENT } },
      "packages/paratix/src is missing — run pnpm build before publishing"
    )
  })

  // R-0000685: a non-ENOENT readdir failure (EACCES, EIO) on src/ has to
  // surface the same build-before-publishing remediation.
  it("R-0000685: maps non-ENOENT src/ failures to the same remediation", async () => {
    await assertAbortsBeforeAnyCommand(
      { readdirErrors: { [PARATIX_SOURCE_DIRECTORY]: "EACCES" } },
      "Run pnpm build before publishing"
    )
  })

  // R-0000862: the symlink rejection must happen before the freshness
  // comparison, so even a symlinked dist entry beside a newer regular
  // source tree gets a direct fail-closed diagnostic instead of a stale
  // mtime explanation.
  it("R-0000862: rejects symlinked files entries before freshness comparison", async () => {
    const result = await assertAbortsBeforeAnyCommand(
      {
        mtimes: {
          // dist is a symlink → mtime 0; src has a fresh regular file so the
          // source mtime walks past 0.
          [PARATIX_DIST_DIRECTORY]: 9999,
          [PARATIX_SOURCE_DIRECTORY]: STALE_SOURCE_MTIME,
          [PARATIX_SOURCE_INDEX_PATH]: 5000,
        },
        symlinks: [PARATIX_DIST_DIRECTORY],
      },
      SYMLINK_FILES_FRAGMENT
    )

    assert.equal(result.error.message.includes(PARATIX_DIST_DIRECTORY), true, result.error.message)
    assert.equal(result.error.message.includes("Materialize"), true, result.error.message)
  })
})

async function assertPublishCallsUseDistributionTag({ expectedTag, version }) {
  const result = await createHarness().run({ fsOptions: { version } })

  assertSucceeded(result)
  const publishCalls = npmPublishCalls(result.commandRunner.calls)
  assert.equal(publishCalls.length, RELEASE_ORDER.length)
  const everyCallHasExpectedTag = publishCalls.every(
    (call) => call.includes("--tag") && call[call.indexOf("--tag") + 1] === expectedTag
  )
  assert.equal(everyCallHasExpectedTag, true)
}

// ---------------------------------------------------------------------------
// #257: paratix and create-paratix may reference @paratix/ssh-native as
// exactly `workspace:*` in any dependency field. `pnpm pack` rewrites it to
// the exact release version; the packed manifest must carry exactly that
// version. Every other `workspace:` specifier stays forbidden.
// ---------------------------------------------------------------------------

const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
]
const LINKED_WORKSPACE_SPECIFIER = "workspace:*"
const LINKED_DEPENDENCY_PACKAGES = [
  { directory: PARATIX_DIRECTORY, name: PARATIX_NAME },
  { directory: CREATE_PARATIX_DIRECTORY, name: CREATE_PARATIX_NAME },
]

function withDependency(field, dependencyName, specifier) {
  return (manifest) => ({
    ...manifest,
    [field]: { ...manifest[field], [dependencyName]: specifier },
  })
}

function linkedSourceManifests(field, packages = LINKED_DEPENDENCY_PACKAGES) {
  return Object.fromEntries(
    packages.map(({ directory }) => [
      `${directory}/package.json`,
      withDependency(field, SSH_NATIVE_NAME, LINKED_WORKSPACE_SPECIFIER),
    ])
  )
}

function resolveWorkspaceSpecifiers(dependencies, version) {
  return Object.fromEntries(
    Object.entries(dependencies).map(([dependencyName, specifier]) => [
      dependencyName,
      specifier === LINKED_WORKSPACE_SPECIFIER ? version : specifier,
    ])
  )
}

// Mirrors `pnpm pack`: `workspace:*` becomes the exact version in every
// dependency field, devDependencies included.
function packLikePnpm({ entries, manifest }) {
  const resolvedFields = DEPENDENCY_FIELDS.filter((field) => manifest[field] !== undefined).map(
    (field) => [field, resolveWorkspaceSpecifiers(manifest[field], manifest.version)]
  )
  setPackedManifest(entries, { ...manifest, ...Object.fromEntries(resolvedFields) })
}

function packWithLinkedPin(field, specifier) {
  return ({ entries, manifest, name }) => {
    packLikePnpm({ entries, manifest })
    if (name !== PARATIX_NAME) return
    const packed = JSON.parse(entries.get(PACKED_MANIFEST).toString("utf8"))
    setPackedManifest(entries, withDependency(field, SSH_NATIVE_NAME, specifier)(packed))
  }
}

function packWithoutLinkedPin(field) {
  return ({ entries, manifest, name }) => {
    packLikePnpm({ entries, manifest })
    if (name !== PARATIX_NAME) return
    const packed = JSON.parse(entries.get(PACKED_MANIFEST).toString("utf8"))
    const { [SSH_NATIVE_NAME]: _removed, ...remaining } = packed[field]
    setPackedManifest(entries, { ...packed, [field]: remaining })
  }
}

function packVerbatim() {
  // Leaves the source manifest untouched, as if the packer had not resolved
  // the workspace protocol.
}

const linkedPackedTamperCases = [
  {
    expected: `devDependencies.${SSH_NATIVE_NAME} is pinned to 1.2.2`,
    field: "devDependencies",
    hook: packWithLinkedPin("devDependencies", "1.2.2"),
    name: "a packed linked dependency with a diverging version",
  },
  {
    expected: `dependencies.${SSH_NATIVE_NAME} is pinned to ^${DEFAULT_STABLE_VERSION}`,
    field: "dependencies",
    hook: packWithLinkedPin("dependencies", `^${DEFAULT_STABLE_VERSION}`),
    name: "a packed linked dependency with a range instead of the exact version",
  },
  {
    expected: `devDependencies.${SSH_NATIVE_NAME} is missing`,
    field: "devDependencies",
    hook: packWithoutLinkedPin("devDependencies"),
    name: "a packed manifest missing the linked dependency",
  },
  {
    expected: `peerDependencies.${SSH_NATIVE_NAME} is pinned to 1.2.2`,
    field: "devDependencies",
    hook: packWithLinkedPin("peerDependencies", "1.2.2"),
    name: "a packed linked dependency with a diverging version in a field the source omits",
  },
  {
    expected: `contains workspace: specifiers (devDependencies.${SSH_NATIVE_NAME})`,
    field: "devDependencies",
    hook: packVerbatim,
    name: "a packed linked dependency that still carries workspace:*",
  },
]

const forbiddenSourceSpecifierCases = [
  {
    expected: `contains workspace: specifiers (dependencies.${PARATIX_NAME})`,
    manifestOverrides: {
      [`${CREATE_PARATIX_DIRECTORY}/package.json`]: withDependency(
        "dependencies",
        PARATIX_NAME,
        LINKED_WORKSPACE_SPECIFIER
      ),
    },
    name: "workspace:* for a dependency other than @paratix/ssh-native in create-paratix",
  },
  {
    expected: "contains workspace: specifiers (devDependencies.picocolors)",
    manifestOverrides: {
      ...linkedSourceManifests("devDependencies"),
      [`${PARATIX_DIRECTORY}/package.json`]: (manifest) =>
        withDependency(
          "devDependencies",
          "picocolors",
          LINKED_WORKSPACE_SPECIFIER
        )(withDependency("devDependencies", SSH_NATIVE_NAME, LINKED_WORKSPACE_SPECIFIER)(manifest)),
    },
    name: "workspace:* for another dependency next to the allowed one in paratix",
  },
  {
    expected: `contains workspace: specifiers (dependencies.${SSH_NATIVE_NAME})`,
    manifestOverrides: {
      [`${PARATIX_DIRECTORY}/package.json`]: withDependency(
        "dependencies",
        SSH_NATIVE_NAME,
        "workspace:^"
      ),
    },
    name: "workspace:^ for @paratix/ssh-native in paratix",
  },
  {
    expected: `contains workspace: specifiers (optionalDependencies.${SSH_NATIVE_NAME})`,
    manifestOverrides: {
      [`${SSH_NATIVE_DIRECTORY}/npm/${FIRST_TARGET}/package.json`]: withDependency(
        "optionalDependencies",
        SSH_NATIVE_NAME,
        LINKED_WORKSPACE_SPECIFIER
      ),
    },
    name: "workspace:* for @paratix/ssh-native in a platform package",
  },
  {
    expected: `contains workspace: specifiers (devDependencies.${PARATIX_NAME})`,
    manifestOverrides: {
      [SSH_NATIVE_MANIFEST_PATH]: withDependency(
        "devDependencies",
        PARATIX_NAME,
        LINKED_WORKSPACE_SPECIFIER
      ),
    },
    name: "workspace:* in the ssh-native loader",
  },
]

describe("publishWorkspacePackages linked workspace dependencies", () => {
  for (const field of DEPENDENCY_FIELDS) {
    it(`#257: accepts workspace:* for @paratix/ssh-native in ${field} of paratix and create-paratix`, async () => {
      const harness = createHarness()

      const result = await harness.run({
        fsOptions: { manifestOverrides: linkedSourceManifests(field) },
        mode: VERIFY_MODE,
        runnerOptions: { packHook: packLikePnpm },
      })

      assertSucceeded(result)
      for (const { name } of LINKED_DEPENDENCY_PACKAGES) {
        assert.equal(
          readPackedManifest(harness, name)[field][SSH_NATIVE_NAME],
          DEFAULT_STABLE_VERSION
        )
      }
    })
  }

  it("#257: publishes all packages when the packed manifests pin @paratix/ssh-native exactly", async () => {
    const result = await createHarness().run({
      fsOptions: { manifestOverrides: linkedSourceManifests("devDependencies") },
      runnerOptions: { packHook: packLikePnpm },
    })

    assertSucceeded(result)
    assert.deepEqual(
      publishedTarballNames(result.commandRunner.calls),
      expectedTarballNames(DEFAULT_STABLE_VERSION)
    )
  })

  for (const mode of [RELEASE_MODE, VERIFY_MODE]) {
    for (const testCase of linkedPackedTamperCases) {
      it(`#257: ${mode} aborts on ${testCase.name}`, async () => {
        const result = await createHarness().run({
          fsOptions: { manifestOverrides: linkedSourceManifests(testCase.field) },
          mode,
          runnerOptions: { packHook: testCase.hook },
        })

        assertAbortedWithoutPublish(result, testCase.expected)
        assert.equal(hasNpmViewCall(result.commandRunner.calls), false)
      })
    }
  }

  for (const testCase of forbiddenSourceSpecifierCases) {
    it(`#257: rejects ${testCase.name} before any command`, async () => {
      await assertAbortsBeforeAnyCommand(
        { manifestOverrides: testCase.manifestOverrides },
        testCase.expected
      )
    })
  }
})

// ---------------------------------------------------------------------------
// R-0000740 / #255 B3: workspace drift. packages/ssh-native is a declared,
// published package; any other undeclared or missing directory under
// packages/ must still abort before anything is packed.
// ---------------------------------------------------------------------------

function isSshNativeSourcePath(path) {
  return (
    path === ABSOLUTE_SSH_NATIVE_DIRECTORY || path.startsWith(`${ABSOLUTE_SSH_NATIVE_DIRECTORY}/`)
  )
}

function readsSshNativeBinary(calls) {
  return calls.some(([, path]) => isSshNativeSourcePath(path) && path.endsWith(".node"))
}

describe("publishWorkspacePackages workspace drift assertion", () => {
  it("#255 B3: publishes packages/ssh-native without reading local native binaries", async () => {
    const result = await createHarness().run()

    assertSucceeded(result)
    assert.equal(hasPackagesRootDirectoryRead(result.fs.calls), true)
    assert.equal(readsSshNativeBinary(result.fs.calls), false)
    assert.equal(
      publishedTarballNames(result.commandRunner.calls).includes(
        tarballFileName(SSH_NATIVE_NAME, DEFAULT_STABLE_VERSION)
      ),
      true
    )
  })

  it("#255: still aborts on an additional undeclared package directory", async () => {
    await assertAbortsBeforeAnyCommand(
      { packageDirectories: [...DEFAULT_PACKAGE_DIRECTORIES, "unknown-package"] },
      `${DRIFT_MESSAGE_FRAGMENT} (not declared in publishWorkspacePackages.mjs: unknown-package)`
    )
  })

  it("#255: aborts when the declared packages/ssh-native directory is missing", async () => {
    await assertAbortsBeforeAnyCommand(
      { packageDirectories: [CREATE_PARATIX_NAME, PARATIX_NAME] },
      `${DRIFT_MESSAGE_FRAGMENT} (missing from filesystem: ssh-native)`
    )
  })

  it("R-0000830: aborts when packages/ contains a symbolic link", async () => {
    await assertAbortsBeforeAnyCommand(
      {
        packageDirectories: [...DEFAULT_PACKAGE_DIRECTORIES, "linked-checkout"],
        symlinks: ["packages/linked-checkout"],
      },
      "contains symbolic links (linked-checkout)"
    )
  })
})

// ---------------------------------------------------------------------------
// #255 B3: the pure-JS tar reader.
// ---------------------------------------------------------------------------

describe("readTarGzEntries", () => {
  it("reads ustar entries and skips directories", () => {
    const entries = readTarGzEntries(
      createTarGzFromRecords([
        { name: "package/", type: "5" },
        { data: "hello", name: TAR_TEXT_ENTRY },
      ])
    )

    assert.deepEqual([...entries.keys()], [TAR_TEXT_ENTRY])
    assert.equal(entries.get(TAR_TEXT_ENTRY).toString("utf8"), "hello")
  })

  it("applies pax path records and GNU long names", () => {
    const longName = `package/${"x".repeat(120)}.js`
    const paxRecord = `${longName.length + 7 + String(longName.length).length} path=${longName}\n`
    const entries = readTarGzEntries(
      createTarGzFromRecords([
        { data: paxRecord, name: "PaxHeader", type: "x" },
        { data: "pax", name: "package/short-a.js" },
        { data: `package/${"y".repeat(120)}.js\0`, name: "././@LongLink", type: "L" },
        { data: "gnu", name: "package/short-b.js" },
      ])
    )

    assert.deepEqual([...entries.keys()], [longName, `package/${"y".repeat(120)}.js`])
  })

  it("rejects symbolic links", () => {
    assertTarRejects([{ name: "package/link", type: "2" }], /only regular files are allowed/v)
  })

  it("rejects path traversal", () => {
    assertTarRejects([{ data: "x", name: "package/../evil" }], /Unsafe tar entry name/v)
  })

  it("rejects duplicate entries", () => {
    const records = [
      { data: "a", name: "package/a" },
      { data: "b", name: "package/a" },
    ]
    assertTarRejects(records, /duplicate entry/v)
  })

  it("rejects a corrupted header checksum", () => {
    const archive = Buffer.concat([
      tarHeader({ name: "package/a", size: 0, type: "0" }),
      Buffer.alloc(TAR_BLOCK_SIZE * 2),
    ])
    archive[0] = 0x71
    assertGzipRejects(gzipSync(archive), /checksum mismatch/v)
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
  const temporaryDirectory = realpathSync(mkdtempSync(join(tmpdir(), "publish-script-")))
  const scriptPath = join(temporaryDirectory, "real-script.mjs")
  writeFileSync(scriptPath, "// test fixture", "utf8")
  const symlinkScriptPath = join(temporaryDirectory, "linked-script.mjs")
  symlinkSync(scriptPath, symlinkScriptPath)
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
