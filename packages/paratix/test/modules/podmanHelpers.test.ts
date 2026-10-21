import { execFileSync } from "node:child_process"
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, describe, expect, it } from "vitest"

import { podman } from "../../src/modules/podman.js"
import {
  configuration,
  normalizeRegistry,
  parsePodmanStatus,
  resolvePodmanCredentials,
  validateToken,
  validateUsername,
} from "../../src/modules/podmanHelpers.js"

const paths: string[] = []
const base = { passwordEnv: "TOKEN", registry: "registry.example", username: "fixed" } as const

describe("podman validation", () => {
  afterEach(async () => {
    await Promise.all(
      paths.splice(0).map(async (path) => rm(path, { force: true, recursive: true }))
    )
  })

  it.each([
    ["INDEX.DOCKER.IO", "docker.io"],
    ["registry-1.docker.io", "docker.io"],
    ["LOCALHOST:00443", "localhost:443"],
    ["192.168.1.1:65535", "192.168.1.1:65535"],
  ])("normalizes %s", (value, expected) => {
    expect(normalizeRegistry(value)).toBe(expected)
  })
  it.each([
    "https://docker.io",
    "docker.io/repo",
    "-host",
    "x:0",
    "x:65536",
    "a..b",
    "a.-b",
    "256.0.0.1",
    "::1",
    "u@host",
    "host\n",
    "host?x",
  ])("rejects registry %s", (value) => {
    expect(() => normalizeRegistry(value)).toThrow("podman:")
  })
  it.each(["", "x:y", " x", "x y", "x\n", "x\u0000"])(
    "rejects invalid usernames without echo",
    (value) => {
      expect(() => {
        validateUsername(value)
      }).toThrow("podman: invalid username")
    }
  )
  it.each([
    "",
    "x\n",
    " x",
    "x ",
    "x\u0000",
    "x\u007f",
    "x\u2028y",
    "x\u2029y",
    "x".repeat(65_537),
  ])("rejects invalid token", (value) => {
    expect(() => {
      validateToken(value)
    }).toThrow("podman: invalid token")
  })
  it.each([
    { usernameEnv: "USER" },
    { username: undefined },
    { passwordFile: "/private/token" },
    { passwordEnv: undefined },
    { passwordFileLocation: "target" },
    { username: undefined, usernameEnv: "__proto__" },
    { username: undefined, usernameEnv: "a..b" },
    { helperImage: "python:latest" },
    { authFile: "/root/auth.json" },
    { authFile: "/root/auth/../auth.json" },
    { authFile: "/root/auth/./auth.json" },
  ])("rejects competing, missing or unsafe options", (overrides) => {
    expect(() =>
      configuration(base.registry, { ...base, ...overrides }, { ...base, ...overrides } as never)
    ).toThrow("podman:")
  })
  it("uses exact, closed remote statuses without echoing any unexpected output", () => {
    expect(parsePodmanStatus({ code: 80, stderr: "", stdout: "" })).toBe("OK")
    for (const stdout of [
      "PARATIX_PODMAN_V1 OK",
      "PARATIX_PODMAN_V1 OK\nsecret",
      "secret",
      "PARATIX_PODMAN_V1 UNKNOWN\n\n",
    ]) {
      expect(() => parsePodmanStatus({ code: 80, stderr: "", stdout })).toThrow(
        "invalid remote status"
      )
    }
    expect(() => parsePodmanStatus({ code: 80, stderr: "hostile", stdout: "" })).toThrow(
      "invalid remote status"
    )
  })
  it.each(["\n", "\r\n", ""])(
    "reads and normalizes a descriptor-checked controller token ending %j",
    async (ending) => {
      const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
      paths.push(directory)
      const path = join(directory, "token")
      await writeFile(path, `synthetic-token${ending}`, { mode: 0o400 })
      const source = { passwordFile: path, registry: "localhost", username: "u" }
      await expect(
        resolvePodmanCredentials(configuration(source.registry, {}, source), {})
      ).resolves.toStrictEqual({ password: "synthetic-token", username: "u" })
      await chmod(path, 0o600)
      await expect(
        resolvePodmanCredentials(configuration(source.registry, {}, source), {})
      ).rejects.toThrow("credential resolution failed")
      await chmod(path, 0o400)
      await symlink(path, join(directory, "link"))
      const linked = { ...source, passwordFile: join(directory, "link") }
      await expect(
        resolvePodmanCredentials(configuration(source.registry, {}, linked), {})
      ).rejects.toThrow("credential resolution failed")
    }
  )
  it("does not read a controller file during construction", () => {
    expect(() =>
      podman.login({ passwordFile: "/does/not/exist", registry: "localhost", username: "u" })
    ).not.toThrow()
  })

  it.each([
    ["empty", Buffer.alloc(0)],
    ["invalid UTF-8", Buffer.from([0xff])],
    ["two trailing newlines", Buffer.from("synthetic-token\n\n")],
    ["leading whitespace", Buffer.from(" synthetic-token")],
    ["first rejected byte length", Buffer.alloc(65_536, "x")],
    ["oversized", Buffer.alloc(65_537, "x")],
  ])("rejects %s controller token content without leaking it", async (_description, bytes) => {
    const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
    paths.push(directory)
    const path = join(directory, "token")
    await writeFile(path, bytes, { mode: 0o400 })
    const source = { passwordFile: path, registry: "localhost", username: "u" }
    await expect(
      resolvePodmanCredentials(configuration(source.registry, {}, source), {})
    ).rejects.toThrow("podman: credential resolution failed")
  })

  it.each(["", "\n", "\r\n"])("accepts 65,535 token bytes with file ending %j", async (ending) => {
    const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
    paths.push(directory)
    const path = join(directory, "token")
    const token = "x".repeat(65_535)
    await writeFile(path, token + ending, { mode: 0o400 })
    const source = { passwordFile: path, registry: "localhost", username: "u" }
    await expect(
      resolvePodmanCredentials(configuration(source.registry, {}, source), {})
    ).resolves.toStrictEqual({ password: token, username: "u" })
  })

  it("measures the token boundary in UTF-8 bytes and preserves the separate username limit", () => {
    const maximum = `${"é".repeat(32_767)}x`
    const oversized = "é".repeat(32_768)
    expect(Buffer.byteLength(maximum)).toBe(65_535)
    expect(() => {
      validateToken(maximum)
    }).not.toThrow()
    expect(Buffer.byteLength(oversized)).toBe(65_536)
    expect(() => {
      validateToken(oversized)
    }).toThrow("invalid token")
    expect(() => {
      validateUsername("x".repeat(65_536))
    }).not.toThrow()
    expect(() => {
      validateUsername("x".repeat(65_537))
    }).toThrow("invalid username")
  })

  it.each(["", "\n", "\r\n"])(
    "rejects 65,536 controller token bytes with file ending %j",
    async (ending) => {
      const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
      paths.push(directory)
      const path = join(directory, "token")
      await writeFile(path, "x".repeat(65_536) + ending, { mode: 0o400 })
      const source = { passwordFile: path, registry: "localhost", username: "u" }
      await expect(
        resolvePodmanCredentials(configuration(source.registry, {}, source), {})
      ).rejects.toThrow("credential resolution failed")
    }
  )

  it("rejects a controller FIFO without blocking for a writer", async () => {
    const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
    paths.push(directory)
    const path = join(directory, "token")
    execFileSync("mkfifo", ["-m", "0400", path])
    const source = { passwordFile: path, registry: "localhost", username: "u" }
    await expect(
      resolvePodmanCredentials(configuration(source.registry, {}, source), {})
    ).rejects.toThrow("podman: credential resolution failed")
  })

  it.each([0o004, 0o440, 0o600, 0o1400])(
    "requires exact 0400 for a controller token instead of mode %o",
    async (mode) => {
      const directory = await mkdtemp(join(tmpdir(), "paratix-podman-"))
      paths.push(directory)
      const path = join(directory, "token")
      await writeFile(path, "synthetic-token", { mode: 0o400 })
      await chmod(path, mode)
      const source = { passwordFile: path, registry: "localhost", username: "u" }
      await expect(
        resolvePodmanCredentials(configuration(source.registry, {}, source), {})
      ).rejects.toThrow("podman: credential resolution failed")
    }
  )
})
