/* eslint-disable sonarjs/no-nested-template-literals -- Shell fixture commands interpolate quoted resource paths. */
import { randomUUID } from "node:crypto"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"

import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { podman, shellQuote } from "../../src/index.js"
import { buildPodmanCommand } from "../../src/modules/podmanContainer.js"
import { configuration } from "../../src/modules/podmanHelpers.js"
import { SshConnectionImpl } from "../../src/ssh.js"
import {
  createNativePodmanEnvironment,
  type NativePodmanEnvironment,
  nativePodmanTargetConfigured,
  readNativeAuthFile,
} from "./podmanHarness.js"
import { requiredPodmanEnvironment } from "./podmanRegistry.js"

const shouldRun = nativePodmanTargetConfigured() || process.env.CI === "true"
let environment: NativePodmanEnvironment | undefined
function fixture(): NativePodmanEnvironment {
  if (environment === undefined) throw new Error("Native security fixture is not initialized")
  return environment
}
function options(authFile = fixture().authFile) {
  const f = fixture()
  return {
    authFile,
    helperImage: f.helperImage,
    passwordEnv: "TOKEN",
    registry: f.registry,
    username: f.username,
  }
}
async function assertClean(): Promise<void> {
  expect(await fixture().leftovers()).toStrictEqual([])
}

function expectOriginalBytes(after: string, original: string): void {
  expect(after).toBe(original)
}
const afterFailureAssertions: Record<
  string,
  (after: string, original: string, registry: string) => void
> = {
  "commit-after": function (after, _original, registry) {
    expect((JSON.parse(after) as { auths: Record<string, unknown> }).auths[registry]).toBeDefined()
  },
  "commit-before": expectOriginalBytes,
  host: expectOriginalBytes,
}

const helperExitStatuses: Record<number, number> = { 0: 80, 1: 86, 125: 86, 137: 86 }
const failureMessages: Record<string, string> = {
  "commit-after": "unknown",
  "commit-before": "unknown",
  host: "before publication",
}
const helperConfigurations: Record<string, { dropIn: string; main: string }> = {
  "drop-in": {
    dropIn: 'credential-helpers = ["sentinel"]\n',
    main: 'credential-helpers = ["must-not-execute"]\n',
  },
  main: { dropIn: "", main: 'credential-helpers = ["sentinel"]\n' },
}
function failureInjection(phase: string): string {
  if (phase === "host")
    return 'if [ "$1" = login ]; then printf "untrusted output"; printf "untrusted error" >&2; exit 1; fi'
  const commit = phase === "commit-after" ? '/usr/bin/podman "$@"; [ "$?" = 12 ] || exit 1;' : ""
  return `if [ "$1" = run ]; then for argument do if [ "$argument" = commit ]; then ${commit} exit 22; fi; done; fi`
}
function rawStreamsEmpty(result: ExecResult): boolean {
  return result.stdout === "" && result.stderr === ""
}
function wrapExec(
  connection: SshConnection,
  wrapCommand: (command: string) => string
): SshConnection {
  return new Proxy(connection, {
    get(target, property) {
      if (property === "exec")
        return async (command: string, parameters: ExecOptions = {}): Promise<ExecResult> =>
          target.exec(wrapCommand(command), parameters)
      const value: unknown = Reflect.get(target, property)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return -- Preserve bound real SSH methods.
      return typeof value === "function" ? value.bind(target) : value
    },
  })
}

describe.skipIf(!shouldRun)("native Podman security and failure integration", () => {
  beforeAll(async () => {
    environment = await createNativePodmanEnvironment()
  })
  beforeEach(async () => {
    const f = fixture()
    await f.setWrapper("")
    await f.baseSsh.exec(`rm -f -- ${shellQuote(f.authFile)}`, { silent: true })
    await f.write(f.authFile, "{}")
    await f.write(f.passwordFile, f.token, "0400")
    f.trace.length = 0
  })
  afterAll(async () => {
    await environment?.cleanup()
  })

  it.each(["symlink", "ancestor", "hardlink", "fifo", "owner", "writable-parent"])(
    "rejects unsafe auth %s before publication",
    async (kind) => {
      const f = fixture()
      const directory = `${f.resource}/unsafe-${randomUUID()}`
      const file = `${directory}/auth.json`
      const sentinel = `${f.resource}/sentinel-${randomUUID()}`
      await f.baseSsh.exec(`install -d -m 0700 ${shellQuote(directory)}`, { silent: true })
      await f.write(sentinel, "sentinel-must-survive")
      await f.write(file, "{}")
      const mutations: Record<string, string> = {
        ancestor: `mv ${shellQuote(directory)} ${shellQuote(`${directory}-real`)}; ln -s ${shellQuote(`${directory}-real`)} ${shellQuote(directory)}`,
        fifo: `rm ${shellQuote(file)}; mkfifo -m 0600 ${shellQuote(file)}`,
        hardlink: `ln ${shellQuote(file)} ${shellQuote(`${directory}/second-link`)}`,
        owner: `chown 65534:65534 ${shellQuote(file)}`,
        symlink: `rm ${shellQuote(file)}; ln -s ${shellQuote(sentinel)} ${shellQuote(file)}`,
        "writable-parent": `chmod 0770 ${shellQuote(directory)}`,
      }
      await f.baseSsh.exec(mutations[kind], { silent: true })
      const module = podman.login(options(file))
      await expect(module.check(f.ssh, { TOKEN: f.token })).rejects.toThrow("podman:")
      await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
        status: "failed",
      })
      const sentinelResult = await f.baseSsh.exec(`cat ${shellQuote(sentinel)}`, { silent: true })
      expect(sentinelResult.stdout).toBe("sentinel-must-survive")
      await assertClean()
    }
  )

  it.each(["symlink", "fifo", "hardlink", "owner", "mode", "lower-mode", "same-inode"])(
    "rejects unsafe target token %s without reading it onto the controller",
    async (kind) => {
      const f = fixture()
      const directory = `${f.resource}/token-${randomUUID()}`
      const file = `${directory}/token`
      await f.baseSsh.exec(`install -d -m 0700 ${shellQuote(directory)}`, { silent: true })
      await f.write(file, f.token, "0400")
      const mutations: Record<string, string> = {
        fifo: `rm ${shellQuote(file)}; mkfifo -m 0400 ${shellQuote(file)}`,
        hardlink: `ln ${shellQuote(file)} ${shellQuote(`${directory}/second-link`)}`,
        "lower-mode": `chmod 0004 ${shellQuote(file)}`,
        mode: `chmod 0600 ${shellQuote(file)}`,
        owner: `chown 65534:65534 ${shellQuote(file)}`,
        "same-inode": `rm ${shellQuote(file)}; ln ${shellQuote(f.authFile)} ${shellQuote(file)}`,
        symlink: `rm ${shellQuote(file)}; ln -s ${shellQuote(f.passwordFile)} ${shellQuote(file)}`,
      }
      await f.baseSsh.exec(mutations[kind], { silent: true })
      const module = podman.login({
        authFile: f.authFile,
        helperImage: f.helperImage,
        passwordFile: file,
        passwordFileLocation: "target",
        registry: f.registry,
        username: f.username,
      })
      await expect(module.check(f.ssh, {})).rejects.toThrow("podman:")
      await expect(module.apply(f.ssh, {})).resolves.toMatchObject({ status: "failed" })
      expect(await readNativeAuthFile(f)).toBe("{}")
      expect(f.trace.every((entry) => !String(entry.input).includes(f.token))).toBe(true)
      await assertClean()
    }
  )

  it.each([0, 1, 125, 137])(
    "suppresses adversarial helper output before raw SSH streams for exit %i",
    async (code) => {
      const f = fixture()
      const encoded = Buffer.from(`${f.username}:${f.token}`).toString("base64")
      const leak = `${f.username} ${f.token} ${encoded} foreign-auth-secret`
      await f.setWrapper(
        `if [ "$1" = run ]; then printf '%s' ${shellQuote(leak)}; printf '%s' ${shellQuote(leak)} >&2; exit ${String(code)}; fi`
      )
      const input = `${JSON.stringify({ password: f.token, username: f.username, version: 1 })}\n`
      const command = buildPodmanCommand(configuration(f.registry, options(), options()), "apply")
      const result = await f.rawExecute(command, input)
      expect(result.stdout).toBe("")
      expect(result.stderr).toBe("")
      expect(result.code).toBe(helperExitStatuses[code])
      expect(await readNativeAuthFile(f)).toBe("{}")
      await assertClean()
    }
  )

  it("suppresses real helper and host process output before raw SSH while retaining actual login", async () => {
    const f = fixture()
    const leak = `${f.username} ${f.token} ${Buffer.from(`${f.username}:${f.token}`).toString("base64")} foreign-auth-secret`
    await f.setWrapper(
      `case "$1" in run|login|logout) printf '%s' ${shellQuote(leak)}; printf '%s' ${shellQuote(leak)} >&2 ;; esac`
    )
    const result = await f.rawExecute(
      buildPodmanCommand(configuration(f.registry, options(), options()), "apply"),
      `${JSON.stringify({ password: f.token, username: f.username, version: 1 })}\n`
    )
    expect(result).toStrictEqual({ code: 82, stderr: "", stdout: "" })
    expect(
      (JSON.parse(await readNativeAuthFile(f)) as { auths: Record<string, unknown> }).auths[
        f.registry
      ]
    ).toBeDefined()
    await assertClean()
  })

  it.each(["host", "commit-before", "commit-after"])(
    "cleans own transactions and reports %s failure without snapshot rollback",
    async (phase) => {
      const f = fixture()
      const original = '{"extension":"original bytes"}\n'
      await f.write(f.authFile, original)
      const injected = failureInjection(phase)
      await f.setWrapper(injected)
      const result = await podman.login(options()).apply(f.ssh, { TOKEN: f.token })
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain(failureMessages[phase])
      const after = await readNativeAuthFile(f)
      afterFailureAssertions[phase](after, original, f.registry)
      await assertClean()
    }
  )

  it.each(["main", "drop-in"])(
    "does not call external credential Store or Erase with %s configuration",
    async (configurationSource) => {
      const f = fixture()
      const helperLog = `${f.resource}/credential-helper-calls`
      const config = `${f.resource}/registries.conf`
      const configDirectory = `${f.resource}/registries.conf.d`
      await f.baseSsh.exec(`install -d -m 0700 ${shellQuote(configDirectory)}`, { silent: true })
      const contents = helperConfigurations[configurationSource]
      await f.write(config, contents.main)
      await f.write(`${configDirectory}/10-test.conf`, contents.dropIn)
      await f.write(
        `${f.resource}/bin/docker-credential-sentinel`,
        `#!/bin/sh\nprintf '%s\\n' "$1" >> ${shellQuote(helperLog)}\ncat >/dev/null\nif [ "$1" = get ]; then printf '%s' '{"Username":"synthetic-existing-user","Secret":"synthetic-existing-token"}'; fi\nexit 0\n`,
        "0700"
      )
      // A private mount namespace isolates the real system drop-in path from other tests.
      const isolated = `mount --bind ${shellQuote(configDirectory)} /etc/containers/registries.conf.d || exit 125; export CONTAINERS_REGISTRIES_CONF=${shellQuote(config)}; exec /usr/bin/podman "$@"`
      await f.setWrapper(
        `exec unshare --mount --propagation private sh -c ${shellQuote(isolated)} sh "$@"`
      )
      const module = podman.login(options())
      await expect(module.apply(f.ssh, { TOKEN: f.token })).resolves.toMatchObject({
        status: "changed",
      })
      await expect(
        podman
          .logout(f.registry, { authFile: f.authFile, helperImage: f.helperImage })
          .apply(f.ssh, {})
      ).resolves.toMatchObject({ status: "changed" })
      const log = await f.baseSsh.exec(
        `if [ -f ${shellQuote(helperLog)} ]; then cat ${shellQuote(helperLog)}; fi`,
        { silent: true }
      )
      expect(log.stdout).toContain("get")
      expect(
        log.stdout
          .split("\n")
          .filter(Boolean)
          .every((operation) => operation === "get")
      ).toBe(true)
      await assertClean()
    }
  )

  it("rejects an auth parent swapped to a symlink between host checks before mounting it", async () => {
    const f = fixture()
    const parent = `${f.resource}/swap-auth`
    const retained = `${f.resource}/swap-retained`
    const outside = `${f.resource}/swap-outside`
    await f.baseSsh.exec(
      `install -d -m 0700 ${[parent, outside].map((path) => shellQuote(path)).join(" ")}`,
      {
        silent: true,
      }
    )
    await f.write(`${parent}/auth.json`, "{}")
    await f.write(`${outside}/auth.json`, "outside-secret-must-not-be-read")
    await f.write(`${f.resource}/calls`, "")
    // image-exists runs after the initial guards and before the repeated pre-mount guards.
    await f.setWrapper(
      `if [ "$1" = image ]; then mv ${shellQuote(parent)} ${shellQuote(retained)}; ln -s ${shellQuote(outside)} ${shellQuote(parent)}; fi`
    )
    await expect(
      podman.login(options(`${parent}/auth.json`)).check(f.ssh, { TOKEN: f.token })
    ).rejects.toThrow("unsafe target path")
    const outsideResult = await f.baseSsh.exec(`cat ${shellQuote(`${outside}/auth.json`)}`, {
      silent: true,
    })
    const retainedResult = await f.baseSsh.exec(`cat ${shellQuote(`${retained}/auth.json`)}`, {
      silent: true,
    })
    const callsResult = await f.baseSsh.exec(`cat ${shellQuote(`${f.resource}/calls`)}`, {
      silent: true,
    })
    expect(outsideResult.stdout).toBe("outside-secret-must-not-be-read")
    expect(retainedResult.stdout).toBe("{}")
    expect(callsResult.stdout).toBe("image\n")
    expect(f.trace.every((entry) => rawStreamsEmpty(entry.result))).toBe(true)
    await assertClean()
  })

  it("refuses SELinux Enforcing before helper startup or auth mutation", async () => {
    const f = fixture()
    const fakeSys = `${f.resource}/selinux-sys`
    await f.baseSsh.exec(`install -d -m 0700 ${shellQuote(`${fakeSys}/fs/selinux`)}`, {
      silent: true,
    })
    await f.write(`${fakeSys}/fs/selinux/enforce`, "1\n")
    await f.write(`${f.resource}/calls`, "")
    const isolated = wrapExec(f.ssh, (command) => {
      const script = `mount --bind ${shellQuote(fakeSys)} /sys || exit 125; ${command}`
      return `unshare --mount --propagation private sh -c ${shellQuote(script)}`
    })
    const module = podman.login(options())
    await expect(module.check(isolated, { TOKEN: f.token })).rejects.toThrow(
      "SELinux Enforcing is unsupported"
    )
    await expect(module.apply(isolated, { TOKEN: f.token })).resolves.toMatchObject({
      status: "failed",
    })
    expect(await readNativeAuthFile(f)).toBe("{}")
    const callsResult = await f.baseSsh.exec(`cat ${shellQuote(`${f.resource}/calls`)}`, {
      silent: true,
    })
    expect(callsResult.stdout).toBe("")
    await assertClean()
  })

  it("reports unknown completion after a real SSH disconnect following publication without retry or rollback", async () => {
    const f = fixture()
    const marker = `${f.resource}/published`
    const gate = `${f.resource}/commit-gate`
    await f.write(`${f.resource}/calls`, "")
    await f.baseSsh.exec(`mkfifo -m 0600 ${shellQuote(gate)}`, { silent: true })
    await f.setWrapper(
      `if [ "$1" = run ]; then for argument do if [ "$argument" = commit ]; then /usr/bin/podman "$@"; code=$?; if [ "$code" = 12 ]; then printf ready > ${shellQuote(marker)}; read -r release < ${shellQuote(gate)}; fi; exit "$code"; fi; done; fi`
    )
    const connection = new SshConnectionImpl(requiredPodmanEnvironment("PARATIX_PODMAN_HOST"), {
      ports: [Number(requiredPodmanEnvironment("PARATIX_PODMAN_PORT"))],
      privateKey: requiredPodmanEnvironment("PARATIX_PODMAN_PRIVATE_KEY"),
      strictHostKeyChecking: "no",
      user: requiredPodmanEnvironment("PARATIX_PODMAN_USER"),
    })
    await connection.connect()
    const interrupted = wrapExec(
      connection,
      (command) => `PATH=${shellQuote(`${f.resource}/bin`)}:$PATH ${command}`
    )
    const pending = podman.login(options()).apply(interrupted, { TOKEN: f.token })
    try {
      await expect
        .poll(
          async () => {
            const markerResult = await f.baseSsh.exec(`test -f ${shellQuote(marker)}`, {
              ignoreExitCode: true,
              silent: true,
            })
            return markerResult.code
          },
          { timeout: 30_000 }
        )
        .toBe(0)
      const published = await readNativeAuthFile(f)
      expect(
        (JSON.parse(published) as { auths: Record<string, unknown> }).auths[f.registry]
      ).toBeDefined()
      connection.forceDestroy()
      const result = await pending
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("completion is unknown")
      expect(await readNativeAuthFile(f)).toBe(published)
      const callsResult = await f.baseSsh.exec(
        `grep -cx login ${shellQuote(`${f.resource}/calls`)}`,
        { silent: true }
      )
      expect(callsResult.stdout.trim()).toBe("1")
    } finally {
      connection.forceDestroy()
      // Unblock any surviving remote shell; interrupted connections have no crash-cleanup guarantee.
      await f.baseSsh.exec(
        `timeout 5 sh -c ${shellQuote(`printf release > ${shellQuote(gate)}`)} || :`,
        { silent: true }
      )
    }
  })
})
