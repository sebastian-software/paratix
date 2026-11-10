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

// A client that forces a PTY treats the refusal as fatal and exits 255.
async function expectPtyRefused(command: string): Promise<void> {
  const login = await target().login(command, { pty: true })
  expect(login.code).toBe(255)
  expect(login.stderr).toMatch(/PTY allocation request failed/v)
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
    await expectPtyRefused("id")

    await apply(restricted())
    login = await target().login("uptime")
    expect(login.code).toBe(0)
    // ForceCommand overrides the key command; PermitTTY no refuses the PTY.
    expect(login.stdout).toContain("forced uptime via match")
    expect(login.stdout).toContain("no-tty")
    await expectPtyRefused("uptime")
    await apply(key, "ok")
    await converged(restricted())
  })

  it("refuses a ~/.ssh that the user replaced by a symlink to a foreign directory", async () => {
    // A root-owned directory outside the home, with a file the key must never reach.
    await target().container([
      "sh",
      "-c",
      "mkdir -m 0755 /srv/paratix-foreign && printf 'foreign\\n' > /srv/paratix-foreign/authorized_keys && chmod 0644 /srv/paratix-foreign/authorized_keys && ln -s /srv/paratix-foreign /home/ops-ro/.ssh && chown -h ops-ro:ops-ro /home/ops-ro/.ssh",
    ])
    const foreign = async (): Promise<string> =>
      target().container([
        "sh",
        "-c",
        "stat -c '%a %U %G %h' /srv/paratix-foreign /srv/paratix-foreign/*; ls -A /srv/paratix-foreign; sha256sum /srv/paratix-foreign/*",
      ])
    const before = await foreign()
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey, {
      options: { restrict: true },
    })

    const dryRunResult = await dryRun(key, "failed")
    expect(dryRunResult.error?.message).toContain(".ssh must not be a symlink")
    const result = await apply(key, "failed")
    expect(result.error?.message).toContain(".ssh must not be a symlink")
    expect(await key.check(target().ssh, {})).toBe("needs-apply")
    expect(await foreign()).toBe(before)
    expect(await target().container(["readlink", "/home/ops-ro/.ssh"])).toBe("/srv/paratix-foreign")
  })

  it("creates ~/.ssh and authorized_keys as the login user", async () => {
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey, {
      options: { restrict: true },
    })
    await apply(key)
    expect(
      await target().container([
        "stat",
        "-c",
        "%a %U %G",
        "/home/ops-ro/.ssh",
        "/home/ops-ro/.ssh/authorized_keys",
      ])
    ).toBe("700 ops-ro ops-ro\n600 ops-ro ops-ro")
    expect(await key.check(target().ssh, {})).toBe("ok")
    await dryRun(key, "ok")
    await apply(key, "ok")
  })

  it("repairs a root-owned ~/.ssh and authorized_keys for the login user", async () => {
    // As an earlier root bootstrap would leave them.
    await target().container([
      "sh",
      "-c",
      "mkdir -m 0700 /home/ops-ro/.ssh && printf '# bootstrap\\n' > /home/ops-ro/.ssh/authorized_keys && chmod 0600 /home/ops-ro/.ssh/authorized_keys",
    ])
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey, {
      options: { restrict: true },
    })
    expect(await key.check(target().ssh, {})).toBe("needs-apply")
    await dryRun(key, "changed")

    await apply(key)

    expect(
      await target().container([
        "stat",
        "-c",
        "%a %U %G",
        "/home/ops-ro/.ssh",
        "/home/ops-ro/.ssh/authorized_keys",
      ])
    ).toBe("700 ops-ro ops-ro\n600 ops-ro ops-ro")
    expect(await target().container(["head", "-n", "1", "/home/ops-ro/.ssh/authorized_keys"])).toBe(
      "# bootstrap"
    )
    await converged(key)
  })

  it("refuses a root-owned ~/.ssh that its group may write and changes nothing", async () => {
    await target().container([
      "sh",
      "-c",
      "mkdir /home/ops-ro/.ssh && chown root:ops /home/ops-ro/.ssh && chmod 2775 /home/ops-ro/.ssh",
    ])
    const state = async (): Promise<string> =>
      target().container(["stat", "-c", "%a %U %G", "/home/ops-ro/.ssh"])
    const before = await state()
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey)

    const result = await apply(key, "failed")

    expect(result.error?.message).toContain(
      "a root-owned .ssh must not be writable by group or others"
    )
    expect(await state()).toBe(before)
    expect(await target().container(["ls", "-A", "/home/ops-ro/.ssh"])).toBe("")
  })

  it.each([
    {
      label: "holding another entry",
      message: "a root-owned .ssh may only contain authorized_keys and known_hosts",
      setup:
        "mkdir -m 0700 /home/ops-ro/.ssh && printf '# bootstrap\\n' > /home/ops-ro/.ssh/authorized_keys && chmod 0600 /home/ops-ro/.ssh/authorized_keys && printf 'x\\n' > /home/ops-ro/.ssh/cache",
    },
    {
      label: "whose authorized_keys has a second hard link",
      message: "authorized_keys in a root-owned .ssh must be a root-owned single-link regular file",
      setup:
        "mkdir -m 0700 /home/ops-ro/.ssh && printf '# bootstrap\\n' > /home/ops-ro/.ssh/authorized_keys && chmod 0600 /home/ops-ro/.ssh/authorized_keys && ln /home/ops-ro/.ssh/authorized_keys /root/paratix-second-link",
    },
  ])("refuses a root-owned ~/.ssh $label and changes nothing", async ({ message, setup }) => {
    await target().container(["sh", "-c", setup])
    const state = async (): Promise<string> =>
      target().container([
        "sh",
        "-c",
        "stat -c '%n %a %U %G %h' /home/ops-ro/.ssh /home/ops-ro/.ssh/*; sha256sum /home/ops-ro/.ssh/*",
      ])
    const before = await state()
    const key = ssh.authorizedKeys("ops-ro", target().opsPublicKey)

    const dryRunResult = await dryRun(key, "failed")
    expect(dryRunResult.error?.message).toContain(message)
    const result = await apply(key, "failed")
    expect(result.error?.message).toContain(message)
    expect(await key.check(target().ssh, {})).toBe("needs-apply")
    expect(await state()).toBe(before)
  })

  it("lets a sudo connection user manage its own key with options", async () => {
    const deploy = await target().connectDeploy()
    const key = ssh.authorizedKeys("deploy", target().opsPublicKey, {
      options: { command: `${SHELL} key`, restrict: true },
    })
    const removal = ssh.authorizedKeys("deploy", target().opsPublicKey, { state: "absent" })
    try {
      await apply(key, "changed", deploy)
      expect(await key.check(deploy, {})).toBe("ok")
      await apply(key, "ok", deploy)
      expect(
        await target().container([
          "stat",
          "-c",
          "%a %U %G",
          "/home/deploy/.ssh",
          "/home/deploy/.ssh/authorized_keys",
        ])
      ).toBe("700 deploy deploy\n600 deploy deploy")
      // The connection's own login key is still there: a new login succeeds.
      await target().connectDeploy()
    } finally {
      await apply(removal, "changed", deploy)
    }
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
