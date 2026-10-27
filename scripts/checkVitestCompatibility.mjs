import { execFileSync } from "node:child_process"
import { lstatSync, readFileSync, realpathSync } from "node:fs"
import { createRequire } from "node:module"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import semver from "semver"

const family = new Set([
  "@vitest/browser",
  "@vitest/browser-playwright",
  "@vitest/browser-preview",
  "@vitest/browser-webdriverio",
  "@vitest/coverage-istanbul",
  "@vitest/coverage-v8",
  "@vitest/ui",
  "vitest",
])
const sections = ["dependencies", "devDependencies", "optionalDependencies"]
const manifestFilename = "package.json"

function readManifest(path) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Paths come from workspace/package resolution.
  return JSON.parse(readFileSync(path, "utf8"))
}

function installedPackage(path, name) {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Follow pnpm's installed package link without loading its code.
  const manifestPath = realpathSync(path)
  const manifest = readManifest(manifestPath)
  if (manifest.name !== name || !semver.valid(manifest.version)) {
    throw new Error(`Invalid installed metadata for ${name}: ${manifestPath}`)
  }
  return { ...manifest, path: manifestPath }
}

function requireCompatible(owner, peer, range) {
  if (!semver.satisfies(peer.version, range)) {
    throw new Error(
      `${owner.name}@${owner.version} requires ${peer.name}@${range}, resolved ${peer.version}`
    )
  }
}

function directPackages(directory) {
  const manifest = readManifest(join(directory, manifestFilename))
  const direct = new Map()
  for (const section of sections) {
    for (const name of Object.keys(manifest[section] ?? {}).filter((key) => family.has(key))) {
      if (direct.has(name)) throw new Error(`Ambiguous ${name}: declared in multiple sections`)
      // An importer's own link is required; hoisted fallback cannot hide a missing install.
      const path = join(directory, "node_modules", name, manifestFilename)
      try {
        direct.set(name, installedPackage(path, name))
      } catch (error) {
        throw new Error(`Cannot read declared ${name}: ${path}: ${error.message}`, { cause: error })
      }
    }
  }
  return direct
}

function peerPackage(owner, name) {
  const paths = createRequire(owner.path).resolve.paths(name) ?? []
  for (const directory of paths) {
    const packagePath = join(directory, name)
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- Inspect Node's package search paths; only ENOENT means absent.
      lstatSync(packagePath)
    } catch (error) {
      if (error.code === "ENOENT") continue
      throw error
    }
    return installedPackage(join(packagePath, manifestFilename), name)
  }
  if (owner.peerDependenciesMeta?.[name]?.optional === true) return null
  throw new Error(`Missing ${name} peer of ${owner.name}@${owner.version}`)
}

function relevantPeers(owner) {
  const peers = Object.entries(owner.peerDependencies ?? {}).filter(([name]) => family.has(name))
  if (
    peers.length === 0 ||
    (owner.name !== "vitest" && !peers.some(([name]) => name === "vitest"))
  ) {
    throw new Error(`Missing Vitest peer metadata for ${owner.name}@${owner.version}`)
  }
  for (const [name, range] of peers) {
    if (typeof range !== "string" || !semver.validRange(range)) {
      throw new Error(`Unsupported ${name} peer range in ${owner.name}@${owner.version}`)
    }
  }
  return peers
}

function checkPeers(owner, direct) {
  const resolved = []
  for (const [name, range] of relevantPeers(owner)) {
    // Direct tools are used together by this importer. Nested peer contexts and
    // other importers are checked independently, without requiring global equality.
    if (direct.get(owner.name)?.path === owner.path && direct.has(name)) {
      requireCompatible(owner, direct.get(name), range)
    }
    const peer = peerPackage(owner, name)
    if (peer === null) continue
    requireCompatible(owner, peer, range)
    resolved.push(peer)
  }
  return resolved
}

// Check direct Vitest tools and their installed peer contexts in one importer.
export function checkImporter(directory) {
  const direct = directPackages(directory)
  const pending = [...direct.values()]
  const visited = new Set()
  while (pending.length > 0) {
    const owner = pending.pop()
    if (visited.has(owner.path)) continue
    visited.add(owner.path)
    pending.push(...checkPeers(owner, direct))
  }
  return visited.size
}

// Ask the pinned package manager for every importer, including the workspace root.
export function checkWorkspace(directory = process.cwd()) {
  const manifest = readManifest(join(directory, manifestFilename))
  if (!String(manifest.packageManager ?? "").startsWith("pnpm@12.")) {
    throw new Error("Supported input requires packageManager: pnpm@12.x and an installed workspace")
  }
  const importers = JSON.parse(
    execFileSync("pnpm", ["--recursive", "list", "--depth", "-1", "--json"], {
      cwd: directory,
      encoding: "utf8",
      timeout: 30_000,
    })
  )
  if (!Array.isArray(importers) || importers.length === 0) {
    throw new Error("pnpm did not report workspace importers")
  }
  const paths = importers.map((importer) => importer.path)
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- Canonicalize the caller workspace root.
  if (paths.some((path) => typeof path !== "string") || !paths.includes(realpathSync(directory))) {
    throw new Error(
      "pnpm importer data is incomplete: expected absolute paths including workspace root"
    )
  }
  let checked = 0
  for (const path of paths) {
    try {
      checked += checkImporter(path)
    } catch (error) {
      throw new Error(
        `${path}: ${error.message}. Update compatible companions and reinstall with pnpm.`,
        {
          cause: error,
        }
      )
    }
  }
  return checked
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const checked = checkWorkspace()
    console.log(`Vitest compatibility: checked ${checked} installed package contexts`)
  } catch (error) {
    console.error(`Vitest compatibility failed: ${error.message}`)
    process.exitCode = 1
  }
}
