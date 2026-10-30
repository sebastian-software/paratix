"use strict"

// Hand-written loader of the native binding. `resolveBinding` is pure: every
// environment input is a parameter, so a unit test can simulate other
// platforms (test/loader.test.mjs).

const fs = require("node:fs")
const path = require("node:path")

/** Targets with a prebuilt binary, as `<platform>-<arch>[-<libc>]`. */
const SUPPORTED_TARGETS = Object.freeze([
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
])

const PACKAGE_NAME = "@paratix/ssh-native"

const INSTALL_HINT =
  "If this platform is supported, the optional platform package is probably missing: " +
  "it is skipped when optional dependencies are omitted (--no-optional, --omit=optional), " +
  "and a lockfile created on another platform can leave it out (npm/cli#4828). " +
  "Reinstall with optional dependencies, or remove the lockfile and node_modules and install again."

/**
 * @typedef {object} Platform
 * @property {string} platform `process.platform`
 * @property {string} arch `process.arch`
 * @property {boolean} isMusl whether Linux runs on musl libc
 */

/**
 * @typedef {Platform & {
 *   glibcVersion?: string | null,
 *   exists: (file: string) => boolean,
 *   requireModule: (id: string) => unknown,
 *   dirname: string,
 * }} LoaderEnvironment
 */

/** Oldest glibc the gnu binaries run on. */
const MIN_GLIBC = [2, 35]

/**
 * @typedef {object} Libc
 * @property {boolean} isMusl whether the process runs on musl
 * @property {string | null} glibcVersion the glibc version, if known
 */

/** @type {Libc | null} */
let cachedLibc = null

/**
 * Reads the libc from the process report, without network information
 * (collecting it can be slow).
 *
 * @returns what the report shows, or `null` if it shows nothing
 */
function libcFromReport() {
  const reporter = /** @type {typeof process.report & { excludeNetwork?: boolean }} */ (
    process.report
  )
  const previous = reporter.excludeNetwork
  try {
    reporter.excludeNetwork = true
    const report =
      /** @type {{ header?: { glibcVersionRuntime?: string }, sharedObjects?: string[] }} */ (
        reporter.getReport()
      )
    const glibcVersion = report.header?.glibcVersionRuntime
    if (glibcVersion) return { glibcVersion, isMusl: false }
    const shared = Array.isArray(report.sharedObjects) ? report.sharedObjects : []
    if (shared.some((file) => file.includes("libc.musl-") || file.includes("ld-musl-"))) {
      return { glibcVersion: null, isMusl: true }
    }
  } catch {
    // Fall through to the ldd probe.
  } finally {
    reporter.excludeNetwork = previous
  }
  return null
}

/**
 * Detects the libc of the running Linux process (cached).
 *
 * @returns musl or glibc, with the glibc version when the report has it
 */
function detectLibc() {
  if (cachedLibc !== null) return cachedLibc
  let libc = libcFromReport()
  if (libc === null) {
    let isMusl = false
    try {
      isMusl = fs.readFileSync("/usr/bin/ldd", "utf8").includes("musl")
    } catch {
      // Assume glibc.
    }
    libc = { glibcVersion: null, isMusl }
  }
  cachedLibc = libc
  return libc
}

/**
 * Detects musl libc on Linux.
 *
 * @param [platform] defaults to `process.platform`
 * @returns `true` on musl, `false` on glibc and on every other platform
 */
function detectMusl(platform = process.platform) {
  return platform === "linux" && detectLibc().isMusl
}

/**
 * @param version a glibc version such as `2.31`
 * @returns whether it is older than the gnu binaries require
 */
function isGlibcTooOld(version) {
  const [major = 0, minor = 0] = version.split(".").map(Number)
  return major < MIN_GLIBC[0] || (major === MIN_GLIBC[0] && minor < MIN_GLIBC[1])
}

/**
 * @param target platform, libc and glibc version of the process
 * @returns a sentence about a too old glibc, or an empty string
 */
function glibcHint(target) {
  const { glibcVersion, isMusl, platform } = target
  if (platform !== "linux" || isMusl || !glibcVersion || !isGlibcTooOld(glibcVersion)) return ""
  return `This system has glibc ${glibcVersion}; the gnu targets require glibc >= ${MIN_GLIBC.join(".")}. `
}

/**
 * @param target platform, architecture and libc of the process
 * @returns e.g. `platform linux, architecture x64, libc glibc`
 */
function describePlatform(target) {
  const { arch, isMusl, platform } = target
  let libc = "n/a"
  if (platform === "linux") libc = isMusl ? "musl" : "glibc"
  return `platform ${platform}, architecture ${arch}, libc ${libc}`
}

/**
 * The target of a platform, e.g. `linux-x64-gnu` or `darwin-arm64`.
 *
 * @param platform `process.platform`
 * @param arch `process.arch`
 * @param isMusl whether Linux runs on musl libc
 * @returns `<platform>-<arch>` plus `-gnu`/`-musl` on Linux
 */
function targetFor(platform, arch, isMusl) {
  if (platform === "linux") return `linux-${arch}-${isMusl ? "musl" : "gnu"}`
  return `${platform}-${arch}`
}

/**
 * @param target the platform
 * @returns the message for a platform without a prebuilt binary
 */
function unsupportedMessage(target) {
  return (
    `${PACKAGE_NAME}: no prebuilt native binary for ${describePlatform(target)}. ` +
    `Supported targets: ${SUPPORTED_TARGETS.join(", ")}. ${INSTALL_HINT}`
  )
}

/**
 * @param target the platform
 * @param triple its target
 * @returns the message for a supported target whose binary is missing
 */
function missingMessage(target, triple) {
  return (
    `${PACKAGE_NAME}: the native binary for ${triple} could not be loaded ` +
    `(${describePlatform(target)}). ${glibcHint(target)}` +
    `Supported targets: ${SUPPORTED_TARGETS.join(", ")}. ` +
    `Expected a locally built ssh-native.${triple}.node next to the loader or the package ` +
    `${PACKAGE_NAME}-${triple}. ${INSTALL_HINT}`
  )
}

/**
 * Loads the binding: first a locally built `ssh-native.<target>.node` next to
 * the loader, then the platform package `@paratix/ssh-native-<target>`.
 *
 * @param environment platform and loader functions
 * @returns the native binding
 */
function resolveBinding(environment) {
  const { arch, dirname, exists, isMusl, platform, requireModule } = environment
  const triple = targetFor(platform, arch, isMusl)
  if (!SUPPORTED_TARGETS.includes(triple)) {
    throw new Error(unsupportedMessage(environment))
  }
  /** @type {unknown[]} */
  const causes = []
  const localFile = path.join(dirname, `ssh-native.${triple}.node`)
  if (exists(localFile)) {
    try {
      return requireModule(localFile)
    } catch (error) {
      causes.push(error)
    }
  }
  try {
    return requireModule(`${PACKAGE_NAME}-${triple}`)
  } catch (error) {
    causes.push(error)
  }
  throw new Error(missingMessage(environment, triple), {
    cause: causes.length === 1 ? causes[0] : new AggregateError(causes, "every candidate failed"),
  })
}

/**
 * @returns the target of the running process
 */
function currentTarget() {
  return targetFor(process.platform, process.arch, detectMusl())
}

/**
 * @returns the binding of the running process
 */
function loadBinding() {
  const libc = process.platform === "linux" ? detectLibc() : { glibcVersion: null, isMusl: false }
  return resolveBinding({
    arch: process.arch,
    dirname: __dirname,
    exists: fs.existsSync,
    glibcVersion: libc.glibcVersion,
    isMusl: libc.isMusl,
    platform: process.platform,
    requireModule: require,
  })
}

module.exports = {
  currentTarget,
  detectMusl,
  loadBinding,
  resolveBinding,
  SUPPORTED_TARGETS,
  targetFor,
}
