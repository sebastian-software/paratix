/* eslint-disable sonarjs/no-nested-template-literals -- The fixture generates a real ESM playbook with quoted target paths. */
import { spawn } from "node:child_process"
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"

import { shellQuote } from "../../src/ssh.js"
import {
  createNativePodmanEnvironment,
  type NativePodmanEnvironment,
  nativePodmanTargetConfigured,
  readNativeAuthFile,
} from "./podmanHarness.js"
import { type PodmanProcessResult, type PodmanTerminalAction, runPodmanPty } from "./podmanPty.js"

const shouldRun = nativePodmanTargetConfigured() || process.env.CI === "true"
const packageRoot = resolve(import.meta.dirname, "../..")
let environment: NativePodmanEnvironment | undefined
function fixture(): NativePodmanEnvironment {
  if (environment === undefined) throw new Error("Native runner fixture is not initialized")
  return environment
}
function eventsPath(): string {
  return join(fixture().controllerDirectory, "events.jsonl")
}
type RunnerEvent = { command?: string; kind: string; missing?: boolean; status?: string }
async function events(): Promise<RunnerEvent[]> {
  const content = await readFile(eventsPath(), "utf8")
  return content
    .split("\n")
    .filter(Boolean)
    .map((line: string) => JSON.parse(line) as RunnerEvent)
}
async function loginCalls(): Promise<number> {
  const f = fixture()
  const result = await f.baseSsh.exec(`grep -cx login ${shellQuote(`${f.resource}/calls`)} || :`, {
    silent: true,
  })
  return Number(result.stdout.trim())
}
async function playbook(provider: "1password" | "manual"): Promise<string> {
  const f = fixture()
  const path = join(f.controllerDirectory, "playbook.mjs")
  const definition = {
    host: process.env.PARATIX_PODMAN_HOST,
    name: "native-provider-lifecycle",
    ssh: {
      ports: [Number(process.env.PARATIX_PODMAN_PORT)],
      privateKey: process.env.PARATIX_PODMAN_PRIVATE_KEY,
      strictHostKeyChecking: "no",
      user: process.env.PARATIX_PODMAN_USER,
    },
  }
  const source = `
import {appendFileSync} from 'node:fs';
import {podman, secret} from ${JSON.stringify(pathToFileURL(join(packageRoot, "dist/index.js")).href)};
const record = value => appendFileSync(${JSON.stringify(eventsPath())}, JSON.stringify(value)+'\\n');
const provider = secret.provider(${JSON.stringify(provider)}, ${provider === "manual" ? '{labels:{REGISTRY_USERNAME:"Native username",REGISTRY_TOKEN:"Native token"}}' : "undefined"});
const producer = provider.resolve({REGISTRY_USERNAME:'op://synthetic/registry/username',REGISTRY_TOKEN:'op://synthetic/registry/token'});
const consumer = podman.login(${JSON.stringify({ authFile: f.authFile, helperImage: f.helperImage, passwordEnv: "REGISTRY_TOKEN", registry: f.registry, usernameEnv: "REGISTRY_USERNAME" })});
const instrument = ssh => new Proxy(ssh, {get(target,key) {
  if (key === 'exec') return async (command, options) => {
    record({kind:'exec',command});
    return target.exec(${JSON.stringify(`PATH=${shellQuote(`${f.resource}/bin`)}:$PATH `)}+command, options);
  };
  const value=Reflect.get(target,key); return typeof value === 'function' ? value.bind(target) : value;
}});
const probe = {name:'metadata-before-resolver', local:true, check:async()=> 'needs-apply', apply:async(_ssh,env)=>{
 record({kind:'metadata-before',missing:env.REGISTRY_USERNAME===undefined && env.REGISTRY_TOKEN===undefined}); return {status:'ok'};
}};
const observed = {...consumer,
 check: async(ssh,env)=>{record({kind:'consumer',missing:env.REGISTRY_USERNAME===undefined || env.REGISTRY_TOKEN===undefined}); return consumer.check(instrument(ssh),env)},
 apply: async(ssh,env)=>{const result=await consumer.apply(instrument(ssh),env);record({kind:'result',status:result.status});return result}
};
export default {...${JSON.stringify(definition)},run:[probe,producer,producer,observed]};
`
  await writeFile(path, source)
  return path
}
function childEnvironment(token: string, fail = false): NodeJS.ProcessEnv {
  const f = fixture()
  return {
    ...process.env,
    NO_COLOR: "1",
    PARATIX_TEST_OP_EVENTS: eventsPath(),
    PARATIX_TEST_OP_FAIL: fail ? "1" : "0",
    PARATIX_TEST_OP_TOKEN: token,
    PARATIX_TEST_OP_USERNAME: f.username,
    PATH: `${join(f.controllerDirectory, "bin")}:${process.env.PATH ?? ""}`,
  }
}
async function execute(
  provider: "1password" | "manual",
  options: {
    actions?: PodmanTerminalAction[]
    args?: string[]
    fail?: boolean
    token?: string
    tty?: boolean
  } = {}
): Promise<PodmanProcessResult> {
  const argv = [
    process.execPath,
    join(packageRoot, "dist/cli.js"),
    "apply",
    await playbook(provider),
    ...(options.args ?? []),
  ]
  const env = childEnvironment(options.token ?? fixture().token, options.fail)
  if (options.tty !== false)
    return runPodmanPty({ actions: options.actions ?? [], argv, cwd: packageRoot, env })
  const child = spawn(argv[0] ?? "", argv.slice(1), {
    cwd: packageRoot,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  })
  let output = ""
  child.stdout.on("data", (chunk: Buffer) => {
    output += chunk.toString()
  })
  child.stderr.on("data", (chunk: Buffer) => {
    output += chunk.toString()
  })
  return new Promise((resolveResult, reject) => {
    child.once("error", reject)
    child.once("close", (code) => {
      resolveResult({ code: code ?? -1, output, responses: 0 })
    })
  })
}
function answers(token = fixture().token): PodmanTerminalAction[] {
  return [
    { prompt: "Native username: ", response: fixture().username },
    { prompt: "Native token: ", response: token },
  ]
}
function expectNoCredentialOutput(result: PodmanProcessResult): void {
  const f = fixture()
  expect(result.output).not.toContain(f.token)
  expect(result.output).not.toContain(Buffer.from(`${f.username}:${f.token}`).toString("base64"))
  expect(result.output).not.toMatch(/\bu\b/v)
}

const providerInitialAssertions = {
  "1password": function (initial: RunnerEvent[], _first: PodmanProcessResult): void {
    expect(initial.slice(0, 2).map((entry) => entry.kind)).toStrictEqual(["op-read", "op-read"])
    expect(initial.filter((entry) => entry.kind === "op-read")).toHaveLength(2)
  },
  manual(_initial: RunnerEvent[], first: PodmanProcessResult): void {
    expect(first.responses).toBe(2)
  },
}

const providerExpectedReads = { "1password": 6, manual: 0 }
const providerExpectedResponses = { "1password": 0, manual: 2 }
function providerAnswers(
  provider: "1password" | "manual",
  token = fixture().token
): PodmanTerminalAction[] {
  return provider === "manual" ? answers(token) : []
}
function isProviderOperation(entry: RunnerEvent): boolean {
  return entry.kind === "op-read" || entry.kind === "exec"
}
function terminalAction(mode: "Ctrl+C" | "EOF" | "runner abort"): PodmanTerminalAction {
  if (mode === "runner abort") return { prompt: "Native username: ", signal: "SIGTERM" }
  return { bytes: mode === "Ctrl+C" ? "\u0003" : "\u0004", prompt: "Native username: " }
}

describe.skipIf(!shouldRun)("native Podman full runner and CLI terminal lifecycle", () => {
  beforeAll(async () => {
    environment = await createNativePodmanEnvironment()
    const f = fixture()
    await mkdir(join(f.controllerDirectory, "bin"))
    await writeFile(
      join(f.controllerDirectory, "bin/op"),
      `#!${process.execPath}\nconst {appendFileSync}=require('node:fs');\nappendFileSync(process.env.PARATIX_TEST_OP_EVENTS,JSON.stringify({kind:'op-read'})+'\\n');\nif(process.env.PARATIX_TEST_OP_FAIL==='1'){process.stderr.write(process.env.PARATIX_TEST_OP_TOKEN);process.exit(1)}\nprocess.stdout.write(process.argv.at(-1).endsWith('/username')?process.env.PARATIX_TEST_OP_USERNAME:process.env.PARATIX_TEST_OP_TOKEN);\n`,
      { mode: 0o700 }
    )
  })
  beforeEach(async () => {
    const f = fixture()
    await f.write(f.authFile, "{}")
    await f.write(`${f.resource}/calls`, "")
    await writeFile(eventsPath(), "")
  })
  afterAll(async () => {
    await environment?.cleanup()
  })

  it.each(["1password", "manual"] as const)(
    "runs %s through real CLI/SSH with per-run cache, metadata ordering, and rotation",
    async (provider) => {
      const f = fixture()
      const first = await execute(provider, { actions: providerAnswers(provider) })
      expect({ code: first.code, output: first.output }).toMatchObject({ code: 0 })
      expectNoCredentialOutput(first)
      expect(await loginCalls()).toBe(1)
      const initial = await events()
      expect(initial.find((entry) => entry.kind === "metadata-before")).toMatchObject({
        missing: true,
      })
      expect(initial.find((entry) => entry.kind === "consumer")).toMatchObject({ missing: false })
      expect(initial.filter((entry) => entry.kind === "result")).toStrictEqual([
        { kind: "result", status: "changed" },
      ])
      expect(initial.filter((entry) => entry.kind === "exec")).toHaveLength(2)
      for (const entry of initial.filter((value) => value.kind === "exec")) {
        expect(entry.command).not.toContain(f.token)
        expect(entry.command).not.toContain(
          Buffer.from(`${f.username}:${f.token}`).toString("base64")
        )
      }
      providerInitialAssertions[provider](initial, first)
      const repeated = await execute(provider, { actions: providerAnswers(provider) })
      expect({ code: repeated.code, output: repeated.output }).toMatchObject({ code: 0 })
      expectNoCredentialOutput(repeated)
      expect(await loginCalls()).toBe(1)
      const rotated = `${f.token}-rotated`
      const next = await execute(provider, {
        actions: providerAnswers(provider, rotated),
        token: rotated,
      })
      expect({ code: next.code, output: next.output }).toMatchObject({ code: 0 })
      expectNoCredentialOutput(next)
      expect(await loginCalls()).toBe(2)
      expect(
        (JSON.parse(await readNativeAuthFile(f)) as { auths: Record<string, { auth: string }> })
          .auths[f.registry].auth
      ).toBe(Buffer.from(`${f.username}:${rotated}`).toString("base64"))
      const completedEvents = await events()
      expect(completedEvents.filter((entry) => entry.kind === "op-read")).toHaveLength(
        providerExpectedReads[provider]
      )
      expect(await f.leftovers()).toStrictEqual([])
      const controllerFiles = await readdir(f.controllerDirectory)
      controllerFiles.sort()
      expect(controllerFiles).toStrictEqual([
        "bin",
        "ca.crt",
        "events.jsonl",
        "key.pem",
        "playbook.mjs",
      ])
    }
  )

  it.each(["1password", "manual"] as const)(
    "prewarms %s in dry-run and checks native state without mutation",
    async (provider) => {
      const result = await execute(provider, {
        actions: providerAnswers(provider),
        args: ["--dry-run"],
      })
      expect({ code: result.code, output: result.output }).toMatchObject({ code: 0 })
      expectNoCredentialOutput(result)
      expect(await loginCalls()).toBe(0)
      expect(await readNativeAuthFile(fixture())).toBe("{}")
      const completedEvents = await events()
      expect(completedEvents.filter((entry) => entry.kind === "exec")).toHaveLength(1)
      expect(completedEvents.some((entry) => entry.kind === "result")).toBe(false)
      expect(result.responses).toBe(providerExpectedResponses[provider])
    }
  )

  it.each(["1password", "manual"] as const)(
    "does not resolve filtered %s producer or mutate with missing metadata",
    async (provider) => {
      const result = await execute(provider, { args: ["--filter", "podman.login"] })
      expect(result.code).not.toBe(0)
      expectNoCredentialOutput(result)
      expect(result.responses).toBe(0)
      expect(result.output).toContain("credential resolution failed")
      const completedEvents = await events()
      expect(completedEvents.find((entry) => entry.kind === "consumer")).toMatchObject({
        missing: true,
      })
      expect(completedEvents.filter((entry) => isProviderOperation(entry))).toStrictEqual([])
      expect(await loginCalls()).toBe(0)
      expect(await readNativeAuthFile(fixture())).toBe("{}")
    }
  )

  it("fails safely on real op authentication failure before native mutation", async () => {
    const result = await execute("1password", { fail: true, tty: false })
    expect(result.code).not.toBe(0)
    expectNoCredentialOutput(result)
    const completedEvents = await events()
    expect(completedEvents.map((entry) => entry.kind)).toStrictEqual(["op-read"])
    expect(await loginCalls()).toBe(0)
    expect(await readNativeAuthFile(fixture())).toBe("{}")
  })

  it("requires actual stdin and stderr TTYs", async () => {
    const result = await execute("manual", { tty: false })
    expect(result.code).not.toBe(0)
    expect(result.output).toContain("TTY")
    expect(await events()).toStrictEqual([])
    expect(await loginCalls()).toBe(0)
    expect(await readNativeAuthFile(fixture())).toBe("{}")
  })

  it.each(["Ctrl+C", "EOF", "runner abort"] as const)(
    "cancels a real hidden prompt on %s before native auth mutation",
    async (mode) => {
      const action = terminalAction(mode)
      const result = await execute("manual", { actions: [action] })
      expect(result.responses).toBe(1)
      expect(result.code).not.toBe(0)
      expectNoCredentialOutput(result)
      expect(await events()).toStrictEqual([])
      expect(await loginCalls()).toBe(0)
      expect(await readNativeAuthFile(fixture())).toBe("{}")
    }
  )
})
