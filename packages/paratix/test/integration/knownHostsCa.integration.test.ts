/* eslint-disable no-await-in-loop -- shared remote trust state must be exercised sequentially */
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import { ssh } from "../../src/modules/ssh.js"
import { type ExecOptions, type Module, NEEDS_APPLY } from "../../src/types.js"
import { trustCommand } from "./certificateTrustHarness.js"
import {
  CLIENT_HOME,
  CLIENT_KNOWN_HOSTS,
  CLIENT_USER,
  createHostCaFixture,
  HOST_ALIAS,
  type HostCaFixture,
  type HostProbe,
} from "./knownHostsCaHarness.js"

let fixture: HostCaFixture | undefined
function target(): HostCaFixture {
  if (fixture === undefined) throw new Error("Host CA fixture is not initialized")
  return fixture
}

function ca(options: { hosts?: string[]; publicKey?: string; state?: "absent" | "present" } = {}) {
  const publicKey = options.publicKey ?? target().hostCa1
  if (options.state === "absent")
    return ssh.knownHostsCertAuthority(CLIENT_USER, {
      hosts: options.hosts,
      publicKey,
      state: "absent",
    })
  return ssh.knownHostsCertAuthority(CLIENT_USER, {
    hosts: options.hosts ?? ["*.example.test"],
    publicKey,
  })
}

async function apply(module: Module, status = "changed") {
  const result = await module.apply(target().ssh, {})
  expect(result.error?.message ?? result.status).toBe(status)
}

async function dryRun(module: Module) {
  if (module._applyDryRun === undefined) throw new Error("Missing host CA dry-run support")
  return module._applyDryRun(target().ssh, {})
}

async function clientSnapshot(): Promise<string> {
  return target().container([
    "sh",
    "-c",
    `find ${CLIENT_HOME} -printf '%p %y %m %U %G %i %T@ %C@ %l\\n' | sort; find ${CLIENT_HOME} -type f -exec sha256sum {} \\; | sort; find /tmp -maxdepth 1 -name '*paratix*' -printf '%p %y %m %T@\\n' | sort`,
  ])
}

function accepted(probe: HostProbe): void {
  expect(probe.stderr).not.toContain("Host key verification failed")
  expect(probe).toMatchObject({ code: 0 })
  expect(probe.stdout).toBe("target")
  expect(probe.stderr).toContain("Authenticated to 127.0.0.1")
}

function rejected(probe: HostProbe): void {
  expect(probe).toMatchObject({ code: 255 })
  expect(probe.stdout).toBe("")
  expect(probe.stderr).toContain("Connection established")
  expect(probe.stderr).toContain("Host key verification failed")
  expect(probe.stderr).not.toContain("Permission denied")
  expect(probe.stderr).not.toContain("Authenticated to")
}

function publicationReplacement(foreign: string) {
  const originalExec = target().ssh.exec.bind(target().ssh)
  let injected = false
  return {
    async exec(command: string, options?: ExecOptions) {
      if (!injected && command.includes("if ! mv -T --")) {
        injected = true
        await target().write(`${CLIENT_HOME}/replacement`, foreign, "0600")
        await target().container(["mv", `${CLIENT_HOME}/replacement`, CLIENT_KNOWN_HOSTS])
      }
      return originalExec(command, options)
    },
    injected: () => injected,
  }
}

function rawRemovalFailure(mode: "interrupt" | "publication") {
  const originalExec = target().ssh.exec.bind(target().ssh)
  let injected = false
  return {
    async exec(command: string, options?: ExecOptions) {
      const backupStep =
        /(?:mv -T|ln -P) -- '\/root\/\.ssh\/known_hosts' "\$known_hosts_backup" \|\| exit \$\?;/v
      if (!injected && backupStep.test(command)) {
        injected = true
        const faulty =
          mode === "interrupt"
            ? command.replace(backupStep, (step) => `${step} kill -KILL $$;`)
            : command.replace(
                /mv -T -- '\/root\/\.ssh\/\.paratix-known-hosts\.[^']+' '\/root\/\.ssh\/known_hosts'/v,
                "(exit 73)"
              )
        return originalExec(faulty, options)
      }
      return originalExec(command, options)
    },
    injected: () => injected,
  }
}

// These are mandatory #249 proofs: Docker absence fails setup even outside CI.
describe("target-system OpenSSH host CA trust", { concurrent: false }, () => {
  beforeAll(async () => {
    await trustCommand("docker", ["info"])
    fixture = await createHostCaFixture(resolve(import.meta.dirname, "../.."))
  })
  beforeEach(async () => {
    await target().resetClients()
  })
  afterEach(() => {
    vi.restoreAllMocks()
    process.exitCode = 0
  })
  afterAll(async () => {
    await fixture?.cleanup()
  })

  it("uses the explicit user's home and primary group, converges, and preserves dry-run state", async () => {
    expect(await target().container(["id", "-gn", CLIENT_USER])).toBe("client")
    expect(await target().ssh.output("id -un")).toBe("root")
    const module = ca()
    const before = await clientSnapshot()
    expect(await module.check(target().ssh, {})).toBe(NEEDS_APPLY)
    const initialDryRun = await dryRun(module)
    expect(initialDryRun.status).toBe("changed")
    expect(await clientSnapshot()).toBe(before)
    await apply(module)
    expect(
      await target().container([
        "stat",
        "-c",
        "%a %U %G",
        CLIENT_HOME,
        `${CLIENT_HOME}/.ssh`,
        CLIENT_KNOWN_HOSTS,
      ])
    ).toBe("751 hostclient client\n700 hostclient client\n600 hostclient client")
    expect(await target().ssh.readFile(CLIENT_KNOWN_HOSTS)).toBe(
      `@cert-authority *.example.test ${target().hostCa1.split(" ").slice(0, 2).join(" ")}\n`
    )
    expect(await target().ssh.exists("/root/.ssh/known_hosts")).toBe(false)
    accepted(await target().probeHost())
    await apply(module, "ok")
    expect(await module.check(target().ssh, {})).toBe("ok")
    const converged = await clientSnapshot()
    const convergedDryRun = await dryRun(module)
    expect(convergedDryRun.status).toBe("ok")
    expect(await clientSnapshot()).toBe(converged)
    await target().container(["chmod", "0644", CLIENT_KNOWN_HOSTS])
    await target().container(["chown", "root:root", CLIENT_KNOWN_HOSTS])
    expect(await module.check(target().ssh, {})).toBe(NEEDS_APPLY)
    const drifted = await clientSnapshot()
    const driftedDryRun = await dryRun(module)
    expect(driftedDryRun.status).toBe("changed")
    expect(await clientSnapshot()).toBe(drifted)
    await apply(module)
    expect(await target().container(["stat", "-c", "%a %U %G", CLIENT_KNOWN_HOSTS])).toBe(
      "600 hostclient client"
    )
  })

  it("separates successful authentication from wrong CA, principal, host pattern, and unsigned rejection", async () => {
    await apply(ca())
    const file = await target().ssh.readFile(CLIENT_KNOWN_HOSTS)
    expect(file.split("\n").filter(Boolean)).toHaveLength(1)
    expect(file).toMatch(/^@cert-authority /v)
    // Every daemon has the same functioning authorized-key login. Trust is the only variable.
    for (const port of [2221, 2222, 2223, 2224]) {
      await target().write(CLIENT_KNOWN_HOSTS, `${HOST_ALIAS} ${target().hostKey}\n`, "0600")
      await target().container(["chown", `${CLIENT_USER}:client`, CLIENT_KNOWN_HOSTS])
      accepted(await target().probeHost(port))
    }
    // Remove every control pin before negative probes; only module-managed CA trust remains.
    await target().write(CLIENT_KNOWN_HOSTS, "", "0600")
    await apply(ca())
    expect(await target().ssh.readFile(CLIENT_KNOWN_HOSTS)).toBe(file)
    const trusted = await target().probeHost()
    accepted(trusted)
    expect(trusted.stderr).toContain("Server host certificate:")
    expect(trusted.stderr).toContain(`Found CA key in ${CLIENT_KNOWN_HOSTS}:1`)
    rejected(await target().probeHost(2222))
    const wrongPrincipal = await target().probeHost(2223)
    rejected(wrongPrincipal)
    expect(wrongPrincipal.stderr).toContain("Certificate invalid: name is not a listed principal")
    rejected(await target().probeHost(2224))
    await apply(ca({ hosts: ["*.elsewhere.test"] }))
    rejected(await target().probeHost())
    await apply(ca())
    accepted(await target().probeHost())
  })

  it("preserves independent raw pins, other CAs, revocations, comments, and incomplete lines", async () => {
    await target().container(["install", "-d", "-m", "0700", `${CLIENT_HOME}/.ssh`])
    const preserved = [
      "# unmanaged trust",
      `${HOST_ALIAS} ${target().hostKey}`,
      `@cert-authority other.example.test ${target().hostCa2}`,
      `@revoked never.example.test ${target().hostCa1}`,
      "unfinished foreign entry",
      "",
    ].join("\n")
    await target().write(CLIENT_KNOWN_HOSTS, preserved)
    await apply(ca())
    const preservedContent = await target().ssh.readFile(CLIENT_KNOWN_HOSTS)
    expect(preservedContent.startsWith(preserved)).toBe(true)
    // Existing raw trust intentionally still permits the unsigned host.
    accepted(await target().probeHost(2224))
    const absent = ca({ hosts: undefined, state: "absent" })
    await apply(absent)
    expect(await target().ssh.readFile(CLIENT_KNOWN_HOSTS)).toBe(preserved)
    await apply(absent, "ok")
    accepted(await target().probeHost(2224))
  })

  it("does not create missing resources for absent and rejects symlink and special-file targets", async () => {
    await apply(ca({ hosts: undefined, state: "absent" }), "ok")
    expect(await target().ssh.exists(`${CLIENT_HOME}/.ssh`)).toBe(false)
    await target().write(`${CLIENT_HOME}/sentinel`, "untouched\n")
    const cases = [
      `ln -s ${CLIENT_HOME} ${CLIENT_HOME}/.ssh`,
      `mkdir ${CLIENT_HOME}/.ssh; ln -s ${CLIENT_HOME}/sentinel ${CLIENT_KNOWN_HOSTS}`,
      `mkdir ${CLIENT_HOME}/.ssh; mkfifo ${CLIENT_KNOWN_HOSTS}`,
      `mkfifo ${CLIENT_HOME}/.ssh`,
    ]
    for (const setup of cases) {
      await target().container(["sh", "-c", `rm -rf ${CLIENT_HOME}/.ssh; ${setup}`])
      const before = await clientSnapshot()
      const module = ca()
      expect(await module.check(target().ssh, {})).toBe(NEEDS_APPLY)
      const dryRunResult = await dryRun(module)
      expect(dryRunResult.status).toBe("failed")
      const applyResult = await module.apply(target().ssh, {})
      expect(applyResult.status).toBe("failed")
      expect(await target().ssh.readFile(`${CLIENT_HOME}/sentinel`)).toBe("untouched\n")
      expect(await clientSnapshot()).toBe(before)
    }
  })

  it("rejects home aliases and missing accounts without creating client resources", async () => {
    const missing = ssh.knownHostsCertAuthority("missing-user", {
      hosts: [HOST_ALIAS],
      publicKey: target().hostCa1,
    })
    const missingDryRun = await dryRun(missing)
    expect(missingDryRun.status).toBe("failed")
    const missingApply = await missing.apply(target().ssh, {})
    expect(missingApply.status).toBe("failed")
    await target().container(["ln", "-s", CLIENT_HOME, "/srv/client-alias"])
    await target().container(["usermod", "-d", "/srv/client-alias", CLIENT_USER])
    try {
      const before = await clientSnapshot()
      const module = ca()
      const dryRunResult = await dryRun(module)
      expect(dryRunResult.status).toBe("failed")
      const applyResult = await module.apply(target().ssh, {})
      expect(applyResult.status).toBe("failed")
      expect(await clientSnapshot()).toBe(before)
      expect(await target().ssh.exists(`${CLIENT_HOME}/.ssh`)).toBe(false)
    } finally {
      await target().container(["usermod", "-d", CLIENT_HOME, CLIENT_USER])
      await target().container(["rm", "/srv/client-alias"])
    }
  })

  it("detects a real external file replacement before publication and preserves the replacement", async () => {
    await apply(ca())
    const foreign = "# external writer replaced this file\n"
    const replacement = publicationReplacement(foreign)
    vi.spyOn(target().ssh, "exec").mockImplementation(replacement.exec)
    const result = await ca({ hosts: ["changed.example.test"] }).apply(target().ssh, {})
    expect(replacement.injected()).toBe(true)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("known_hosts changed before publication")
    expect(await target().ssh.readFile(CLIENT_KNOWN_HOSTS)).toBe(foreign)
    expect(
      await target().container(["find", `${CLIENT_HOME}/.ssh`, "-name", ".paratix-known-hosts*"])
    ).toBe("")
  })

  it.each(["interrupt", "publication"] as const)(
    "retains all trust after a raw removal %s failure and converges on retry",
    async (mode) => {
      const path = "/root/.ssh/known_hosts"
      const rawLine = `[127.0.0.1]:2224 ${target().hostKey}\n`
      const retained = [
        "# unrelated trust with trailing spaces  ",
        `other.example.test ${target().hostKey}`,
        `@cert-authority elsewhere.example.test ${target().hostCa1}`,
        `@revoked revoked.example.test ${target().hostCa2}`,
        "# retained UTF-8: café",
        "",
      ].join("\n")
      const original = `${rawLine}${retained}`
      await target().write(path, original, "0600")
      const failure = rawRemovalFailure(mode)
      vi.spyOn(target().ssh, "exec").mockImplementation(failure.exec)
      const absent = ssh.knownHosts("127.0.0.1", { port: 2224, state: "absent" })
      try {
        const interrupted = await absent.apply(target().ssh, {})
        expect(failure.injected()).toBe(true)
        expect(interrupted.status).toBe("failed")
        expect(await target().ssh.exists(path)).toBe(true)
        expect(await target().ssh.readFile(path)).toBe(original)
        await apply(absent)
        expect(await target().ssh.readFile(path)).toBe(retained)
        await apply(absent, "ok")
      } finally {
        await target().container(["sh", "-c", "rm -f /root/.ssh/known_hosts.paratix-backup.*"])
      }
    }
  )

  it("retains both CAs and hashed port-qualified raw pins across parallel writers and replacement", async () => {
    const host = "127.0.0.1"
    const pattern = "[127.0.0.1]:2224"
    const first = ssh.knownHostsCertAuthority("root", {
      hosts: [pattern],
      publicKey: target().hostCa1,
    })
    const second = ssh.knownHostsCertAuthority("root", {
      hosts: [pattern],
      publicKey: target().hostCa2,
    })
    const raw = ssh.knownHosts(host, { port: 2224, publicKey: target().hostKey })
    for (let iteration = 0; iteration < 3; iteration += 1) {
      await target().container(["rm", "-f", "/root/.ssh/known_hosts"])
      await Promise.all([apply(first), apply(second), apply(raw)])
      for (const module of [first, second, raw]) {
        expect(await module.check(target().ssh, {})).toBe("ok")
        await apply(module, "ok")
      }
      const initial = await target().ssh.readFile("/root/.ssh/known_hosts")
      expect(initial).toContain("|1|")
      const markers = initial.split("\n").filter((line) => line.startsWith("@cert-authority"))
      expect(markers).toHaveLength(2)
      // Force an atomic publication and confirm the next writer still uses the same resource lock.
      await target().container([
        "sh",
        "-c",
        "cp -p /root/.ssh/known_hosts /root/.ssh/replacement; mv /root/.ssh/replacement /root/.ssh/known_hosts",
      ])
      const revoke = `@revoked ${pattern} ${target().hostCa2}\n`
      await target().write("/root/.ssh/known_hosts", `${initial}${revoke}`, "0600")
      await apply(raw, "ok")
      const key = target().hostKey.split(" ").slice(0, 2).join(" ")
      const staleKey = target().hostCa2.split(" ").slice(0, 2).join(" ")
      const current = await target().ssh.readFile("/root/.ssh/known_hosts")
      const drifted = current.replace(key, staleKey)
      await target().write("/root/.ssh/known_hosts", drifted, "0600")
      await apply(raw)
      for (const marker of [...markers, revoke.trimEnd()])
        expect(await target().ssh.readFile("/root/.ssh/known_hosts")).toContain(marker)
      await apply(ssh.knownHosts(host, { port: 2224, state: "absent" }))
      const remaining = await target().ssh.readFile("/root/.ssh/known_hosts")
      expect(remaining).toBe(`${markers.join("\n")}\n${revoke}`)
      await apply(ssh.knownHosts(host, { port: 2224, state: "absent" }), "ok")
      await Promise.all([apply(raw), apply(first, "ok"), apply(second, "ok")])
      expect(await target().ssh.readFile("/root/.ssh/known_hosts")).toContain(revoke)
    }
  })
})
