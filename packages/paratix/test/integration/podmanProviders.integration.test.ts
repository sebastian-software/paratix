import type * as FileSystem from "node:fs/promises"

import { mkdir, open, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import { podman, secret } from "../../src/index.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { withSecretPrewarmScope } from "../../src/secretPrewarm.js"
import { promptTerminal } from "../../src/terminal.js"
import {
  createNativePodmanEnvironment,
  type NativePodmanEnvironment,
  nativePodmanTargetConfigured,
  readNativeAuthFile,
} from "./podmanHarness.js"

vi.mock("../../src/terminal.js", () => ({ promptTerminal: vi.fn() }))
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof FileSystem>()
  return { ...actual, open: vi.fn(actual.open) }
})
const shouldRun = nativePodmanTargetConfigured() || process.env.CI === "true"
const prompt = vi.mocked(promptTerminal)
const localOpen = vi.mocked(open)
let environment: NativePodmanEnvironment | undefined
function fixture(): NativePodmanEnvironment {
  if (environment === undefined) throw new Error("Native provider fixture is not initialized")
  return environment
}
const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")

const providerReadAssertions = {
  "1password": async function (f: NativePodmanEnvironment): Promise<void> {
    const log = await readFile(join(f.controllerDirectory, "op-calls"), "utf8")
    expect(log.trim().split("\n")).toHaveLength(4)
    expect(prompt).not.toHaveBeenCalled()
  },
  manual(_f: NativePodmanEnvironment): void {
    expect(prompt).toHaveBeenCalledTimes(4)
    expect(prompt.mock.calls.every((call) => call[1] === true)).toBe(true)
  },
}

describe.skipIf(!shouldRun)("native Podman provider bindings", () => {
  beforeAll(async () => {
    environment = await createNativePodmanEnvironment()
    const f = fixture()
    await mkdir(join(f.controllerDirectory, "bin"))
    // A real child process exercises the existing op CLI adapter without any vault.
    await writeFile(
      join(f.controllerDirectory, "bin/op"),
      `#!${process.execPath}\nimport {appendFileSync} from 'node:fs';\nappendFileSync(process.env.PARATIX_TEST_OP_LOG,process.argv.at(-1)+'\\n');\nprocess.stdout.write(process.argv.at(-1).endsWith('/username')?process.env.PARATIX_TEST_PROVIDER_USERNAME:process.env.PARATIX_TEST_PROVIDER_TOKEN);\n`,
      { mode: 0o700 }
    )
  })
  beforeEach(async () => {
    const f = fixture()
    await f.write(f.authFile, "{}")
    await f.write(`${f.resource}/calls`, "")
    f.trace.length = 0
    prompt.mockReset()
    localOpen.mockClear()
    vi.stubEnv("PATH", `${join(f.controllerDirectory, "bin")}:${process.env.PATH ?? ""}`)
    vi.stubEnv("PARATIX_TEST_PROVIDER_USERNAME", f.username)
    vi.stubEnv("PARATIX_TEST_PROVIDER_TOKEN", f.token)
    vi.stubEnv("PARATIX_TEST_OP_LOG", join(f.controllerDirectory, "op-calls"))
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
  })
  afterEach(() => {
    vi.unstubAllEnvs()
    if (stdinTty === undefined) Reflect.deleteProperty(process.stdin, "isTTY")
    else Object.defineProperty(process.stdin, "isTTY", stdinTty)
    if (stderrTty === undefined) Reflect.deleteProperty(process.stderr, "isTTY")
    else Object.defineProperty(process.stderr, "isTTY", stderrTty)
  })
  afterAll(async () => {
    await environment?.cleanup()
  })

  it.each(["1password", "manual"] as const)(
    "consumes %s username and token bindings with one resolution per run and fresh rotation",
    async (provider) => {
      const f = fixture()
      const facade = secret.provider(provider)
      const producer = facade.resolve({
        REGISTRY_TOKEN: "op://synthetic/registry/token",
        REGISTRY_USERNAME: "op://synthetic/registry/username",
      })
      const consumer = podman.login({
        authFile: f.authFile,
        helperImage: f.helperImage,
        passwordEnv: "REGISTRY_TOKEN",
        registry: f.registry,
        usernameEnv: "REGISTRY_USERNAME",
      })
      const run = async (token: string, status: string) => {
        vi.stubEnv("PARATIX_TEST_PROVIDER_TOKEN", token)
        // The facade preserves binding order; prompts use its existing hidden-input boundary.
        prompt.mockResolvedValueOnce(token).mockResolvedValueOnce(f.username)
        await withSecretPrewarmScope(async () => {
          await producer._prewarmSecrets?.()
          // eslint-disable-next-line prefer-spread -- apply is the public module lifecycle method.
          const produced = await producer.apply(null, {})
          expect(produced.status).toBe("ok")
          const env = await mergeEnvironmentFromMeta({}, produced.meta)
          await expect(consumer.check(f.ssh, env)).resolves.toBe("needs-apply")
          await expect(consumer.apply(f.ssh, env)).resolves.toMatchObject({ status })
          await expect(consumer.check(f.ssh, env)).resolves.toBe("ok")
          await expect(consumer.apply(f.ssh, env)).resolves.toMatchObject({ status: "ok" })
        })
      }
      await run(f.token, "changed")
      await run(`${f.token}-rotated`, "changed")
      expect(localOpen).not.toHaveBeenCalled()
      await providerReadAssertions[provider](f)
      const encoded = Buffer.from(`${f.username}:${f.token}`).toString("base64")
      for (const entry of f.trace) {
        expect(entry.command).not.toContain(f.token)
        expect(entry.command).not.toContain(encoded)
        expect(entry.result.stdout).toBe("")
        expect(entry.result.stderr).toBe("")
      }
      expect(consumer.name).toBe("podman.login")
    }
  )

  it("accepts a fixed username with a manual password binding", async () => {
    const f = fixture()
    prompt.mockResolvedValueOnce(f.token)
    const producer = secret.provider("manual").resolve({ TOKEN: "" })
    const consumer = podman.login({
      authFile: f.authFile,
      helperImage: f.helperImage,
      passwordEnv: "TOKEN",
      registry: f.registry,
      username: f.username,
    })
    // eslint-disable-next-line prefer-spread -- apply is the public module lifecycle method.
    const produced = await producer.apply(null, {})
    const env = await mergeEnvironmentFromMeta({}, produced.meta)
    await expect(consumer.apply(f.ssh, env)).resolves.toMatchObject({ status: "changed" })
    expect(prompt).toHaveBeenCalledExactlyOnceWith("TOKEN: ", true, { abortSignal: undefined })
    expect(localOpen).not.toHaveBeenCalled()
  })

  it("rejects a missing binding despite process.env and does not resolve bindings for check(null)", async () => {
    const f = fixture()
    vi.stubEnv("TOKEN", f.token)
    const resolve = vi.fn(() => f.token)
    const consumer = podman.login({
      authFile: f.authFile,
      helperImage: f.helperImage,
      passwordEnv: "TOKEN",
      registry: f.registry,
      username: f.username,
    })
    await expect(consumer.check(null, { TOKEN: resolve })).resolves.toBe("needs-apply")
    expect(resolve).not.toHaveBeenCalled()
    await expect(consumer.check(f.ssh, {})).rejects.toThrow("credential resolution failed")
    await expect(consumer.apply(f.ssh, {})).resolves.toMatchObject({ status: "failed" })
    expect(await readNativeAuthFile(f)).toBe("{}")
    expect(f.trace).toHaveLength(0)
    expect(localOpen).not.toHaveBeenCalled()
  })
})
