import assert from "node:assert/strict"
import { createRequire } from "node:module"
import { join } from "node:path"
import { describe, it } from "node:test"

const require = createRequire(import.meta.url)
const { resolveBinding, SUPPORTED_TARGETS, targetFor } = require("../loader.js")

const DIRNAME = "/opt/ssh-native"
const NOT_FOUND = "module not found"

/**
 * Throws like `require` for a missing module.
 *
 * @throws {Error} always, with code MODULE_NOT_FOUND
 */
function notFound() {
  throw Object.assign(new Error(NOT_FOUND), { code: "MODULE_NOT_FOUND" })
}

/**
 * Runs `run` and returns what it threw.
 *
 * @param run expected to throw
 * @returns the thrown Error (with its cause)
 */
function thrownBy(run) {
  try {
    run()
  } catch (error) {
    return /** @type {Error & { cause: Error }} */ (error)
  }
  throw new Error("expected a throw")
}

function environment(overrides) {
  const required = []
  return {
    options: {
      arch: "x64",
      dirname: DIRNAME,
      exists: () => false,
      isMusl: false,
      platform: "linux",
      requireModule(/** @type {string} */ id) {
        required.push(id)
        return notFound()
      },
      ...overrides,
    },
    required,
  }
}

function assertHints(message) {
  for (const target of SUPPORTED_TARGETS) assert.ok(message.includes(target), target)
  assert.match(message, /--no-optional/v)
  assert.match(message, /--omit=optional/v)
  assert.match(message, /lockfile created on another platform/v)
  assert.match(message, /npm\/cli#4828/v)
}

describe("loader", () => {
  it("lists exactly the six prebuilt targets", () => {
    assert.deepEqual(SUPPORTED_TARGETS, [
      "linux-x64-gnu",
      "linux-arm64-gnu",
      "linux-x64-musl",
      "linux-arm64-musl",
      "darwin-x64",
      "darwin-arm64",
    ])
  })

  it("derives the target from platform, architecture and libc", () => {
    assert.equal(targetFor("linux", "arm64", true), "linux-arm64-musl")
    assert.equal(targetFor("linux", "x64", false), "linux-x64-gnu")
    assert.equal(targetFor("darwin", "arm64", false), "darwin-arm64")
  })

  it("prefers a locally built binary next to the loader", () => {
    const local = join(DIRNAME, "ssh-native.linux-x64-gnu.node")
    const binding = { local: true }
    const { options, required } = environment({
      exists: (file) => file === local,
      requireModule(/** @type {string} */ id) {
        required.push(id)
        return id === local ? binding : notFound()
      },
    })
    assert.equal(resolveBinding(options), binding)
    assert.deepEqual(required, [local])
  })

  it("falls back to the platform package", () => {
    const binding = { package: true }
    const { options, required } = environment({
      arch: "arm64",
      platform: "darwin",
      requireModule(/** @type {string} */ id) {
        required.push(id)
        return id === "@paratix/ssh-native-darwin-arm64" ? binding : notFound()
      },
    })
    assert.equal(resolveBinding(options), binding)
    assert.deepEqual(required, ["@paratix/ssh-native-darwin-arm64"])
  })

  it("names platform, architecture, libc and the targets on win32/x64", () => {
    const { options, required } = environment({ arch: "x64", platform: "win32" })
    const error = thrownBy(() => resolveBinding(options))
    assert.match(error.message, /platform win32, architecture x64, libc n\/a/v)
    assertHints(error.message)
    assert.deepEqual(required, [], "nothing is loaded for an unsupported target")
  })

  it("names platform, architecture, libc and the targets on freebsd", () => {
    const { options } = environment({ arch: "x64", platform: "freebsd" })
    const error = thrownBy(() => resolveBinding(options))
    assert.match(error.message, /platform freebsd, architecture x64, libc n\/a/v)
    assertHints(error.message)
  })

  it("explains a missing binary on supported linux-x64-glibc", () => {
    const { options, required } = environment({})
    const error = thrownBy(() => resolveBinding(options))
    assert.match(error.message, /linux-x64-gnu could not be loaded/v)
    assert.match(error.message, /platform linux, architecture x64, libc glibc/v)
    assert.match(error.message, /@paratix\/ssh-native-linux-x64-gnu/v)
    assertHints(error.message)
    assert.equal(error.cause.message, NOT_FOUND)
    assert.deepEqual(required, ["@paratix/ssh-native-linux-x64-gnu"])
  })

  it("reports musl as libc", () => {
    const { options } = environment({ arch: "arm64", isMusl: true })
    assert.throws(() => resolveBinding(options), /libc musl/v)
  })
})
