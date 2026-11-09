import { spawnSync } from "node:child_process"
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import type { SshConnectionImpl } from "../../src/ssh.js"
import type { Module, ModuleResult } from "../../src/types.js"

import { ssh } from "../../src/modules/ssh.js"
import { sshd } from "../../src/modules/sshd.js"
import { createSshdMatchFixture, type SshdMatchFixture } from "./sshdMatchHarness.js"

const available = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!available && process.env.CI === "true")
  throw new Error("sshd.match proofs require Docker in CI")

const DROP_IN = "/etc/ssh/sshd_config.d/ops-ro.conf"
const SHELL = "/usr/local/bin/ops-ro-shell"
let fixture: SshdMatchFixture | undefined

function target(): SshdMatchFixture {
  if (fixture === undefined) throw new Error("sshd.match fixture is not initialized")
  return fixture
}

async function apply(
  module: Module,
  status: ModuleResult["status"] = "changed",
  connection: SshConnectionImpl = target().ssh
): Promise<ModuleResult> {
  const result = await module.apply(connection, {})
  expect({ message: result.error?.message, status: result.status }).toMatchObject({ status })
  return result
}

async function dryRun(module: Module, status: ModuleResult["status"]): Promise<ModuleResult> {
  if (module._applyDryRun === undefined) throw new Error("Missing module dry-run support")
  const result = await module._applyDryRun(target().ssh, {})
  expect({ message: result.error?.message, status: result.status }).toMatchObject({ status })
  return result
}

async function converged(module: Module): Promise<void> {
  expect(await module.check(target().ssh, {})).toBe("ok")
  await dryRun(module, "ok")
  await apply(module, "ok")
}

// Files, metadata, live daemon identity and confirmed reloads.
async function snapshot(): Promise<string> {
  return target().container([
    "sh",
    "-c",
    "find /etc/ssh -printf '%p %y %m %U %G\\n' | sort; find /etc/ssh -type f -exec sha256sum {} \\; | sort; cat /run/recorded-main-pid /run/main-sshd.pid; cat /run/confirmed-reloads 2>/dev/null || true",
  ])
}

async function effective(user: string, directive: string): Promise<string> {
  const output = await target().container([
    "sshd",
    "-T",
    "-C",
    `user=${user},host=paratix-verify.invalid,addr=192.0.2.1`,
  ])
  const line = output.split("\n").find((entry) => entry.startsWith(`${directive} `))
  return line?.slice(directive.length + 1) ?? "<missing>"
}

async function refuses(
  module: Module,
  message: RegExp,
  connection?: SshConnectionImpl
): Promise<void> {
  const before = await snapshot()
  const result = await apply(module, "failed", connection)
  expect(result.error?.message).toMatch(message)
  expect(await snapshot()).toBe(before)
}

function restricted(directives: Parameters<typeof sshd.match>[2] = {}): Module {
  return sshd.match(
    "ops-ro",
    { user: "ops-ro" },
    { DisableForwarding: "yes", ForceCommand: `${SHELL} match`, PermitTTY: "no", ...directives }
  )
}

describe.skipIf(!available)("sshd.match against OpenSSH", { concurrent: false }, () => {
  beforeAll(async () => {
    fixture = await createSshdMatchFixture(resolve(import.meta.dirname, "../.."))
  })
  beforeEach(async () => {
    await target().reset()
  })
  afterEach(() => {
    vi.restoreAllMocks()
    process.exitCode = 0
  })
  afterAll(async () => {
    await fixture?.cleanup()
  })

  it("ends a drop-in Match at the end of its file", async () => {
    await apply(restricted())
    expect(await target().container(["cat", DROP_IN])).toBe(
      [
        "# Managed by Paratix sshd.match: ops-ro",
        "Match User ops-ro",
        "    DisableForwarding yes",
        `    ForceCommand ${SHELL} match`,
        "    PermitTTY no",
      ].join("\n")
    )
    expect(await target().container(["stat", "-c", "%a %U %G", DROP_IN])).toBe("644 root root")
    // Port/HostKey/PidFile after the Include are invalid inside Match: sshd -t
    // only passes because the drop-in's Match ends with the file.
    await target().container(["sshd", "-t"])
    expect(await effective("other", "maxauthtries")).toBe("3")
    expect(await effective("other", "permittty")).toBe("yes")
    expect(await effective("ops-ro", "maxauthtries")).toBe("3")
    expect(await effective("ops-ro", "permittty")).toBe("no")
    expect(await target().container(["cat", "/run/confirmed-reloads"])).toMatch(/^\d+ absent$/v)
    await converged(restricted())
  })

  it("refuses criteria matching a root connection unless allowed", async () => {
    await refuses(
      sshd.match("root-lock", { user: "root" }, { PermitTTY: "no" }),
      /connection user root/v
    )
    await apply(
      sshd.match("root-lock", { user: "root" }, { PermitTTY: "no" }, { allowConnectionUser: true })
    )
    expect(await effective("root", "permittty")).toBe("no")
  })

  it("refuses group criteria matching a non-root sudo connection unless allowed", async () => {
    const deploy = await target().connectDeploy()
    const options = { verifyUser: "ops-ro" }
    await refuses(
      sshd.match("ops-group", { group: "ops" }, { PermitTTY: "no" }, options),
      /connection user deploy/v,
      deploy
    )
    const allowed = sshd.match(
      "ops-group",
      { group: "ops" },
      { PermitTTY: "no" },
      { ...options, allowConnectionUser: true }
    )
    await apply(allowed, "changed", deploy)
    expect(await effective("ops-ro", "permittty")).toBe("no")
    expect(await effective("other", "permittty")).toBe("yes")
    await apply(allowed, "ok", deploy)
  })

  it("combines authorized-key restrictions with the Match block at login", async () => {
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey, {
      options: { command: `${SHELL} key`, restrict: true },
      state: "present",
    })
    await apply(key)
    let login = await target().login("id")
    expect(login.code).toBe(0)
    expect(login.stdout).toContain("forced id via key")
    expect(login.stdout).toContain("no-tty")

    await apply(restricted())
    login = await target().login("uptime")
    expect(login.code).toBe(0)
    // ForceCommand overrides the key command; PermitTTY no refuses the PTY.
    expect(login.stdout).toContain("forced uptime via match")
    expect(login.stdout).toContain("no-tty")
    expect(login.stderr).toMatch(/PTY allocation request failed/v)
    await apply(key, "ok")
    await converged(restricted())
  })

  it("fails without changes when an earlier drop-in sets the same directive", async () => {
    await target().write(
      "/etc/ssh/sshd_config.d/00-early.conf",
      "Match User ops-ro\n    PermitTTY yes\n"
    )
    await target().container(["systemctl", "reload", "ssh"])
    await refuses(restricted(), /PermitTTY: expected no .*reports yes/v)
    await dryRun(restricted(), "failed")
    expect(await target().container(["ls", "/etc/ssh/sshd_config.d"])).toBe("00-early.conf")
  })

  it("never activates a drop-in that fails sshd -t", async () => {
    const mainPid = await target().container(["cat", "/run/recorded-main-pid"])
    await refuses(
      restricted({ AuthenticationMethods: "publickey,no-such-method" }),
      /invalid .*method list/iv
    )
    await target().container(["test", "!", "-e", DROP_IN])
    await target().container(["kill", "-0", mainPid])
    expect(await effective("ops-ro", "permittty")).toBe("yes")
  })

  it("restores the previous state for absent and leaves foreign files alone", async () => {
    const before = await snapshot()
    await apply(restricted())
    const absent = sshd.match("ops-ro", { user: "ops-ro" }, {}, { state: "absent" })
    await dryRun(absent, "changed")
    await apply(absent)
    await target().container(["test", "!", "-e", DROP_IN])
    expect(await effective("ops-ro", "permittty")).toBe("yes")
    await converged(absent)
    // Only the two confirmed reloads (apply and absent) differ from the initial snapshot.
    const initial = before.split("\n")
    const final = await snapshot()
    const after = final.split("\n")
    expect(after.slice(0, initial.length)).toStrictEqual(initial)
    expect(after.slice(initial.length)).toHaveLength(2)
    for (const line of after.slice(initial.length)) expect(line).toMatch(/^\d+ absent$/v)

    await target().write(DROP_IN, "Match User ops-ro\n    PermitTTY yes\n")
    await refuses(restricted(), /without the marker/v)
    await refuses(absent, /without the marker/v)
  })

  it("requires the drop-in Include before the first Match", async () => {
    const initial = await target().container(["cat", "/run/initial-sshd-config"])
    await target().write(
      "/etc/ssh/sshd_config",
      initial.replace("Include /etc/ssh/sshd_config.d/*.conf\n", "")
    )
    await refuses(restricted(), /Include \/etc\/ssh\/sshd_config\.d\/\*\.conf/v)
    await expect(target().container(["test", "-e", DROP_IN])).rejects.toThrow(/docker failed/v)
  })

  it("coexists with ssh.trustedUserCa in one recipe", async () => {
    const modules = [ssh.trustedUserCa({ publicKey: target().ca }), restricted()]
    for (const module of modules)
      // eslint-disable-next-line no-await-in-loop -- recipe order
      await apply(module)
    for (const module of modules) {
      // eslint-disable-next-line no-await-in-loop -- recipe order
      expect(await module.check(target().ssh, {})).toBe("ok")
      // eslint-disable-next-line no-await-in-loop -- recipe order
      await apply(module, "ok")
    }
    expect(await effective("ops-ro", "trustedusercakeys")).toBe("/etc/ssh/trusted_user_ca_keys")
  })
})
