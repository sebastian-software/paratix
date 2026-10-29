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
 *   exists: (file: string) => boolean,
 *   requireModule: (id: string) => unknown,
 *   dirname: string,
 * }} LoaderEnvironment
 */

/**
 * Reads the libc from the process report.
 *
 * @returns `true` for musl, `false` for glibc, `null` if unknown
 */
function muslFromReport() {
  try {
    const report =
      /** @type {{ header?: { glibcVersionRuntime?: string }, sharedObjects?: string[] }} */ (
        process.report.getReport()
      )
    if (report.header?.glibcVersionRuntime) return false
    const shared = Array.isArray(report.sharedObjects) ? report.sharedObjects : []
    if (shared.some((file) => file.includes("libc.musl-") || file.includes("ld-musl-"))) return true
  } catch {
    // Fall through to the ldd probe.
  }
  return null
}

/**
 * Detects musl libc on Linux.
 *
 * @param [platform] defaults to `process.platform`
 * @returns `true` on musl, `false` on glibc and on every other platform
 */
function detectMusl(platform = process.platform) {
  if (platform !== "linux") return false
  const fromReport = muslFromReport()
  if (fromReport !== null) return fromReport
  try {
    return fs.readFileSync("/usr/bin/ldd", "utf8").includes("musl")
  } catch {
    return false
  }
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
    `(${describePlatform(target)}). Supported targets: ${SUPPORTED_TARGETS.join(", ")}. ` +
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
  return resolveBinding({
    arch: process.arch,
    dirname: __dirname,
    exists: fs.existsSync,
    isMusl: detectMusl(),
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
