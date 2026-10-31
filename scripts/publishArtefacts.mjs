// #255 B3: pure-JS helpers for the publish flow. The publish script packs
// all nine release tarballs before any registry write and inspects their
// real contents here: a minimal tar.gz reader (node:zlib + 512-byte ustar
// headers, pax `path` records and GNU long names), SHA-256 / npm integrity
// helpers and the per-package tarball assertions. No external dependency is
// involved, so the inspection cannot be skewed by a compromised tar package.
import { createHash } from "node:crypto"
import { gunzipSync } from "node:zlib"

const BLOCK_SIZE = 512
const NAME_FIELD = { length: 100, offset: 0 }
const SIZE_FIELD = { length: 12, offset: 124 }
const CHECKSUM_FIELD = { length: 8, offset: 148 }
const TYPE_FLAG_OFFSET = 156
const MAGIC_FIELD = { length: 5, offset: 257 }
const PREFIX_FIELD = { length: 155, offset: 345 }
const ASCII_SPACE = 32
const HIGH_BIT_BYTE = 0x80
const REGULAR_FILE_TYPES = new Set(["\0", "0"])
const DIRECTORY_TYPE = "5"
const PAX_HEADER_TYPE = "x"
const PAX_GLOBAL_HEADER_TYPE = "g"
const GNU_LONG_NAME_TYPE = "L"
const SHA512_BYTE_LENGTH = 64
const PACKAGE_PREFIX = "package/"
const PACKED_MANIFEST_PATH = `${PACKAGE_PREFIX}package.json`
const NODE_BINARY_SUFFIX = ".node"
const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
]

export function sha256Hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex")
}

export function tarballIntegrity(buffer) {
  return `sha512-${createHash("sha512").update(buffer).digest("base64")}`
}

// #255 B3: npm stores `dist.integrity` as `sha512-<base64>`, while the SLSA
// provenance subject carries the same digest as lowercase hex. Returns
// undefined for anything that is not a single, well-formed sha512 value.
export function integrityToHex(integrity) {
  if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) return
  const digest = Buffer.from(integrity.slice("sha512-".length), "base64")
  if (digest.length !== SHA512_BYTE_LENGTH) return
  return digest.toString("hex")
}

function readField(block, { length, offset }) {
  const slice = block.subarray(offset, offset + length)
  const end = slice.indexOf(0)
  return slice.subarray(0, end === -1 ? length : end).toString("utf8")
}

function readOctalField(block, field, label) {
  if (block[field.offset] >= HIGH_BIT_BYTE) {
    throw new Error(`Unsupported tar archive: base-256 encoded ${label} field.`)
  }
  const text = readField(block, field).trim()
  if (!/^[0-7]*$/v.test(text)) {
    throw new Error(`Malformed tar archive: invalid ${label} field ${JSON.stringify(text)}.`)
  }
  return text === "" ? 0 : Number.parseInt(text, 8)
}

function assertHeaderChecksum(header) {
  const storedChecksum = readOctalField(header, CHECKSUM_FIELD, "checksum")
  const checksumEnd = CHECKSUM_FIELD.offset + CHECKSUM_FIELD.length
  let computedChecksum = 0
  for (const [index, byte] of header.entries()) {
    const isChecksumByte = index >= CHECKSUM_FIELD.offset && index < checksumEnd
    computedChecksum += isChecksumByte ? ASCII_SPACE : byte
  }
  if (computedChecksum === storedChecksum) return
  throw new Error("Malformed tar archive: header checksum mismatch.")
}

function headerEntryName(header) {
  const name = readField(header, NAME_FIELD)
  if (readField(header, MAGIC_FIELD) !== "ustar") return name
  const prefix = readField(header, PREFIX_FIELD)
  return prefix === "" ? name : `${prefix}/${name}`
}

function parsePaxPath(data) {
  let path
  for (const record of data.toString("utf8").split("\n")) {
    const separatorIndex = record.indexOf(" ")
    const keyValue = separatorIndex === -1 ? "" : record.slice(separatorIndex + 1)
    if (keyValue.startsWith("path=")) path = keyValue.slice("path=".length)
  }
  return path
}

function normalizeEntryName(name) {
  const withoutDotPrefix = name.startsWith("./") ? name.slice(2) : name
  const segments = withoutDotPrefix.split("/")
  if (
    withoutDotPrefix === "" ||
    withoutDotPrefix.startsWith("/") ||
    withoutDotPrefix.includes("\\") ||
    segments.includes("..")
  ) {
    throw new Error(`Unsafe tar entry name ${JSON.stringify(name)}.`)
  }
  return withoutDotPrefix
}

function readRecord(archive, offset) {
  const header = archive.subarray(offset, offset + BLOCK_SIZE)
  if (header.every((byte) => byte === 0)) return
  assertHeaderChecksum(header)
  const size = readOctalField(header, SIZE_FIELD, "size")
  const dataStart = offset + BLOCK_SIZE
  if (dataStart + size > archive.length) {
    throw new Error("Malformed tar archive: entry data is truncated.")
  }
  return {
    data: archive.subarray(dataStart, dataStart + size),
    header,
    nextOffset: dataStart + Math.ceil(size / BLOCK_SIZE) * BLOCK_SIZE,
    type: String.fromCodePoint(header[TYPE_FLAG_OFFSET]),
  }
}

// Returns the name pending for the next header (pax/GNU long-name records)
// and adds regular files to `entries`.
function applyRecord(entries, { pendingName, record }) {
  if (record.type === PAX_HEADER_TYPE) return parsePaxPath(record.data) ?? pendingName
  if (record.type === GNU_LONG_NAME_TYPE) {
    return readField(record.data, { length: record.data.length, offset: 0 })
  }
  if (record.type === PAX_GLOBAL_HEADER_TYPE) return pendingName
  const name = normalizeEntryName(pendingName ?? headerEntryName(record.header))
  if (record.type === DIRECTORY_TYPE) return
  if (!REGULAR_FILE_TYPES.has(record.type)) {
    throw new Error(
      `Unsupported tar entry type ${JSON.stringify(record.type)} for ${name}; only regular files are allowed.`
    )
  }
  if (entries.has(name)) {
    throw new Error(`Malformed tar archive: duplicate entry ${name}.`)
  }
  entries.set(name, Buffer.from(record.data))
}

// #255 B3: returns a Map of normalized entry name -> file contents. Links,
// devices, base-256 sizes, unsafe paths and duplicate entries are rejected
// instead of being interpreted, so every later assertion sees exactly what
// npm would extract.
export function readTarGzEntries(gzipBuffer) {
  const archive = gunzipSync(gzipBuffer)
  const entries = new Map()
  let pendingName
  let offset = 0
  while (offset + BLOCK_SIZE <= archive.length) {
    const record = readRecord(archive, offset)
    if (record === undefined) break
    pendingName = applyRecord(entries, { pendingName, record })
    offset = record.nextOffset
  }
  return entries
}

export function findWorkspaceSpecifiers(manifest) {
  return DEPENDENCY_FIELDS.flatMap((field) => {
    const dependencies = manifest?.[field]
    if (typeof dependencies !== "object" || dependencies === null) return []
    return Object.entries(dependencies)
      .filter(
        ([, specifier]) => typeof specifier === "string" && specifier.startsWith("workspace:")
      )
      .map(([dependencyName]) => `${field}.${dependencyName}`)
  })
}

export function assertNoWorkspaceSpecifiers(manifest, label) {
  const workspaceSpecifiers = findWorkspaceSpecifiers(manifest)
  if (workspaceSpecifiers.length === 0) return
  throw new Error(
    `${label} contains workspace: specifiers (${workspaceSpecifiers.join(", ")}); they must never reach the registry.`
  )
}

function readPackedManifest(entries, label) {
  const rawManifest = entries.get(PACKED_MANIFEST_PATH)
  if (rawManifest === undefined) {
    throw new Error(`${label}: tarball does not contain ${PACKED_MANIFEST_PATH}.`)
  }
  try {
    return JSON.parse(rawManifest.toString("utf8"))
  } catch (error) {
    throw new Error(`${label}: ${PACKED_MANIFEST_PATH} in the tarball is not valid JSON.`, {
      cause: error,
    })
  }
}

function nodeBinaryEntries(entries) {
  return [...entries.keys()].filter((name) => name.endsWith(NODE_BINARY_SUFFIX))
}

function assertPackedIdentity(entries, { label, name, version }) {
  const foreignEntries = [...entries.keys()].filter((entry) => !entry.startsWith(PACKAGE_PREFIX))
  if (foreignEntries.length > 0) {
    throw new Error(`${label}: tarball entries outside package/: ${foreignEntries.join(", ")}.`)
  }
  const manifest = readPackedManifest(entries, label)
  if (manifest.name !== name || manifest.version !== version) {
    throw new Error(
      `${label}: packed package.json declares ${manifest.name}@${manifest.version}; expected ${name}@${version}.`
    )
  }
  assertNoWorkspaceSpecifiers(manifest, `${label}: packed package.json`)
  return manifest
}

function describePinnedDependency(platformName, optionalDependencies) {
  const specifier = optionalDependencies[platformName]
  return specifier === undefined
    ? `${platformName} is missing`
    : `${platformName} is pinned to ${specifier}`
}

function assertExactOptionalDependencies(manifest, { label, platformNames, version }) {
  const optionalDependencies = manifest.optionalDependencies ?? {}
  const problems = platformNames
    .filter((platformName) => optionalDependencies[platformName] !== version)
    .map((platformName) => describePinnedDependency(platformName, optionalDependencies))
  const extraNames = Object.keys(optionalDependencies).filter(
    (dependencyName) => !platformNames.includes(dependencyName)
  )
  problems.push(...extraNames.map((dependencyName) => `${dependencyName} is unexpected`))
  if (problems.length === 0) return
  throw new Error(
    `${label}: packed optionalDependencies must list exactly the six platform packages at ${version} (${problems.join("; ")}).`
  )
}

// #255 B3: the loader package must reference every platform package at the
// exact release version, ship its JS entry points and never carry a native
// binary itself (binaries only travel in the platform packages).
export function inspectSshNativeTarball(entries, { name, platformNames, version }) {
  const label = `${name}@${version}`
  const manifest = assertPackedIdentity(entries, { label, name, version })
  assertExactOptionalDependencies(manifest, { label, platformNames, version })
  const missingEntries = [`${PACKAGE_PREFIX}index.js`, `${PACKAGE_PREFIX}index.d.ts`].filter(
    (entry) => !entries.has(entry)
  )
  if (missingEntries.length > 0) {
    throw new Error(`${label}: tarball is missing ${missingEntries.join(", ")}.`)
  }
  const binaries = nodeBinaryEntries(entries)
  if (binaries.length > 0) {
    throw new Error(`${label}: tarball must not contain native binaries (${binaries.join(", ")}).`)
  }
}

// #255 B3: a platform tarball carries exactly one native binary under the
// loader's file name, byte-identical to the smoke-tested CI artifact.
export function inspectPlatformTarball(entries, { binaryFileName, expectedSha256, name, version }) {
  const label = `${name}@${version}`
  assertPackedIdentity(entries, { label, name, version })
  const expectedEntry = `${PACKAGE_PREFIX}${binaryFileName}`
  const binaries = nodeBinaryEntries(entries)
  if (binaries.length !== 1 || binaries[0] !== expectedEntry) {
    throw new Error(
      `${label}: tarball must contain exactly one native binary ${expectedEntry} (found: ${binaries.join(", ") || "none"}).`
    )
  }
  const actualSha256 = sha256Hex(entries.get(expectedEntry))
  if (actualSha256 !== expectedSha256) {
    throw new Error(
      `${label}: packed ${binaryFileName} has SHA-256 ${actualSha256}; expected ${expectedSha256}.`
    )
  }
}

export function inspectWorkspaceTarball(entries, { name, version }) {
  assertPackedIdentity(entries, { label: `${name}@${version}`, name, version })
}
