import { spawn } from "node:child_process"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment } from "../../src/types.js"

import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { podman } from "../../src/modules/podman.js"
import { configuration, resolvePodmanCredentials } from "../../src/modules/podmanHelpers.js"
import { secret } from "../../src/modules/secret.js"
import { withSecretPrewarmScope } from "../../src/secretPrewarm.js"
import { clearRegisteredSecrets, withRunScopedSecrets } from "../../src/secretSink.js"
import { promptTerminal } from "../../src/terminal.js"
import { createMockSsh } from "../helpers/mockSsh.js"
import { createMockSpawnChild } from "../helpers/runnerMocks.js"

vi.mock("node:child_process", () => ({ spawn: vi.fn() }))
vi.mock("../../src/terminal.js", () => ({ promptTerminal: vi.fn() }))
const source = { passwordEnv: "TOKEN", registry: "localhost", usernameEnv: "USER" } as const
const originalStdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
const originalStderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")

describe("podman provider-neutral credentials", () => {
  beforeEach(() => {
    vi.mocked(spawn).mockReset()
    vi.mocked(promptTerminal).mockReset()
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
  })
  afterEach(() => {
    if (originalStdinTty) Object.defineProperty(process.stdin, "isTTY", originalStdinTty)
    else Reflect.deleteProperty(process.stdin, "isTTY")
    if (originalStderrTty) Object.defineProperty(process.stderr, "isTTY", originalStderrTty)
    else Reflect.deleteProperty(process.stderr, "isTTY")
    vi.restoreAllMocks()
    clearRegisteredSecrets()
  })
  it.each(["manual", "1password"] as const)(
    "uses the same consumer with %s and reads once per run",
    async (provider) => {
      const values = ["synthetic-token", "OK", "rotated-token", "OK"]
      vi.mocked(promptTerminal).mockImplementation(async () => {
        await Promise.resolve()
        return String(values.shift())
      })
      vi.mocked(spawn).mockImplementation(
        () => createMockSpawnChild(`${String(values.shift())}\n`) as never
      )
      const resolver = secret.provider(provider)
      const secrets = resolver.resolve({
        TOKEN: "op://Fixture/Registry/token",
        USER: "op://Fixture/Registry/username",
      })
      const consumer = podman.login(source)
      const ssh = createMockSsh()
      const exec = vi.spyOn(ssh, "exec").mockResolvedValue({ code: 80, stderr: "", stdout: "" })
      for (const expected of ["synthetic-token", "rotated-token"]) {
        // eslint-disable-next-line no-await-in-loop -- Separate runs must rotate the fixture credentials sequentially.
        await withRunScopedSecrets(async () =>
          withSecretPrewarmScope(async () => {
            await secrets._prewarmSecrets?.()
            // eslint-disable-next-line prefer-spread -- Module.apply is the public lifecycle method.
            const result = await secrets.apply(null, {})
            const env = await mergeEnvironmentFromMeta({}, result.meta)
            await expect(consumer.check(ssh, env)).resolves.toBe("ok")
            await expect(consumer.apply(ssh, env)).resolves.toStrictEqual({ status: "ok" })
            expect(exec.mock.lastCall?.[1]?.input).toContain(expected)
          })
        )
      }
      expect(vi.mocked(promptTerminal).mock.calls.length + vi.mocked(spawn).mock.calls.length).toBe(
        4
      )
    }
  )
  it.each(["manual", "1password"] as const)(
    "rejects an oversized %s token before any SSH work",
    async (provider) => {
      const oversized = "x".repeat(65_536)
      vi.mocked(promptTerminal).mockResolvedValueOnce(oversized).mockResolvedValueOnce("u")
      vi.mocked(spawn)
        .mockImplementationOnce(() => createMockSpawnChild(`${oversized}\n`) as never)
        .mockImplementationOnce(() => createMockSpawnChild("u\n") as never)
      const producer = secret
        .provider(provider)
        .resolve({ TOKEN: "op://Fixture/Registry/token", USER: "op://Fixture/Registry/username" })
      const consumer = podman.login(source)
      const ssh = createMockSsh()
      const exec = vi.spyOn(ssh, "exec")
      await withRunScopedSecrets(async () =>
        withSecretPrewarmScope(async () => {
          const disconnected = null
          const produced = await producer.apply(disconnected, {})
          const env = await mergeEnvironmentFromMeta({}, produced.meta)
          await expect(consumer.check(ssh, env)).rejects.toThrow("credential resolution failed")
          await expect(consumer.apply(ssh, env)).resolves.toMatchObject({ status: "failed" })
          expect(exec).not.toHaveBeenCalled()
        })
      )
    }
  )

  it("accepts target token plus username binding without reading a local file", async () => {
    const mixed = {
      passwordFile: "/root/token-private/pat",
      passwordFileLocation: "target",
      registry: "localhost",
      usernameEnv: "USER",
    } as const
    await expect(
      resolvePodmanCredentials(configuration(mixed.registry, {}, mixed), { USER: "u" })
    ).resolves.toStrictEqual({ username: "u" })
  })
  it.each<Environment>([
    {},
    { TOKEN: "token", USER: 1 },
    { TOKEN: "token", USER: "" },
    { TOKEN: 1, USER: "u" },
    { TOKEN: "token\n", USER: "u" },
    {
      async TOKEN() {
        await Promise.resolve()
        throw new Error("secret-cause")
      },
      USER: "u",
    },
  ])("fails without SSH mutation for invalid or missing bindings", async (env) => {
    const ssh = createMockSsh()
    const exec = vi.spyOn(ssh, "exec")
    const result = await podman.login(source).apply(ssh, env)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe("podman: credential resolution failed")
    expect(result.error?.cause).toBeUndefined()
    expect(exec).not.toHaveBeenCalled()
  })
})
