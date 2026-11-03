import { spawnSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import { ssh } from "../../src/modules/ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY } from "../../src/types.js"
import { createTrustFixture, trustCommand, type TrustFixture } from "./certificateTrustHarness.js"

const available = spawnSync("docker", ["info"], { stdio: "ignore", timeout: 30_000 }).status === 0
if (!available && process.env.CI === "true")
  throw new Error("Certificate trust proofs require Docker in CI")
let fixture: TrustFixture | undefined

function target(): TrustFixture {
  if (fixture === undefined) throw new Error("Certificate trust fixture is not initialized")
  return fixture
}

async function apply(module: Module, status = "changed"): Promise<ModuleResult> {
  const result = await module.apply(target().ssh, {})
  expect(result.status).toBe(status)
  return result
}

async function dryRun(module: Module, status = "changed"): Promise<void> {
  if (module._applyDryRun === undefined) throw new Error("Missing module dry-run support")
  const result = await module._applyDryRun(target().ssh, {})
  expect(result.status).toBe(status)
}

async function snapshot(): Promise<string> {
  return target().container([
    "sh",
    "-c",
    "find /etc/ssh -printf '%p %y %m %U %G\\n' | sort; find /etc/ssh -type f -exec sha256sum {} \\; | sort; cat /run/confirmed-reloads 2>/dev/null || true",
  ])
}

async function principals(template?: string): Promise<void> {
  await apply(ssh.authorizedPrincipals("deploy", ["release-team"], { principalsFile: template }))
}

async function certificateLogin(
  allowed: boolean,
  identity = target().identities.first
): Promise<void> {
  const result = await target().probe(identity)
  expect(result.code).toBe(allowed ? 0 : 255)
  expect(result.stdout).toBe(allowed ? "deploy" : "")
  expect(result.stderr.includes("Permission denied")).toBe(!allowed)
}

function injectCommandFault(command: RegExp, stderr: string): () => boolean {
  const originalExec = target().ssh.exec.bind(target().ssh)
  let injected = false
  vi.spyOn(target().ssh, "exec").mockImplementation(async (value, options) => {
    if (!injected && command.test(value)) {
      injected = true
      return { code: 1, stderr, stdout: "" }
    }
    return originalExec(value, options)
  })
  return () => injected
}

async function managedTrustMetadata(): Promise<string> {
  return target().container([
    "stat",
    "-c",
    "%n %i %a %u %g %z",
    "/etc/ssh/trusted_user_ca_keys",
    "/etc/ssh/sshd_config",
    "/etc/ssh/custom/deploy",
  ])
}

function observeCandidatePreflight() {
  const observations: Array<{
    firstLogin: number
    metadata: string
    revokedKeysExists: boolean
    secondLogin: number
    snapshot: string
  }> = []
  const validations: Array<{ code: number; command: string; stdout: string }> = []
  const mutations: string[] = []
  const originalExec = target().ssh.exec.bind(target().ssh)
  const writes = vi.spyOn(target().ssh, "writeFile")
  vi.spyOn(target().ssh, "exec").mockImplementation(async (command, options) => {
    if (
      /^(?:mv|cp|rm|mkdir|rmdir|chown|chmod|umask|mktemp -d) /v.test(command) &&
      command.includes("/etc/ssh")
    )
      mutations.push(command)
    const candidate = /^sshd -[tT] -f /v.test(command)
    if (candidate) {
      // Observe the live daemon before forwarding each real candidate check.
      // A later rollback cannot hide even a temporary trust-file replacement.
      const first = await target().probe(target().identities.first)
      const second = await target().probe(target().identities.second)
      observations.push({
        firstLogin: first.code,
        metadata: await managedTrustMetadata(),
        revokedKeysExists: await target().ssh.exists("/etc/ssh/revoked_keys"),
        secondLogin: second.code,
        snapshot: await snapshot(),
      })
    }
    const response = await originalExec(command, options)
    if (candidate) validations.push({ code: response.code, command, stdout: response.stdout })
    return response
  })
  return { mutations, observations, validations, writes }
}

async function failure(module: Module, message: RegExp): Promise<void> {
  const before = await snapshot()
  const result = await apply(module, "failed")
  expect(result.error?.message).toMatch(message)
  expect(await snapshot()).toBe(before)
}

async function configWithPrefix(prefix: string): Promise<void> {
  const initial = await target().container(["cat", "/run/initial-sshd-config"])
  await target().write("/etc/ssh/sshd_config", `${prefix}\n${initial}\n`)
}

describe.skipIf(!available)("declarative OpenSSH user CA trust", { concurrent: false }, () => {
  beforeAll(async () => {
    fixture = await createTrustFixture(resolve(import.meta.dirname, "../.."))
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

  it("activates only module-created trust on the main daemon, isolates auth, rotates CAs and converges", async () => {
    const mainPid = await target().container(["cat", "/run/recorded-main-pid"])
    await certificateLogin(false)
    await principals()
    const ca = ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/revoked_keys" })
    const before = await snapshot()
    await dryRun(ca)
    expect(await snapshot()).toBe(before)
    await apply(ca)
    expect(await target().container(["cat", "/run/main-sshd.pid"])).toBe(mainPid)
    expect(await target().container(["cat", "/run/confirmed-reloads"])).toBe(`${mainPid} present`)
    expect(await target().container(["cat", "/etc/ssh/revoked_keys"])).toBe("")
    const effective = await target().container([
      "/usr/sbin/sshd",
      "-T",
      "-C",
      "user=deploy,host=localhost,addr=127.0.0.1",
    ])
    for (const setting of [
      "passwordauthentication no",
      "kbdinteractiveauthentication no",
      "authorizedkeysfile none",
      "authorizedkeyscommand none",
      "authorizedprincipalscommand none",
      "allowagentforwarding no",
      "trustedusercakeys /etc/ssh/trusted_user_ca_keys",
      "authorizedprincipalsfile /etc/ssh/auth_principals/%u",
    ]) {
      expect(effective).toContain(setting)
    }
    await certificateLogin(true)
    await certificateLogin(false, target().identities.wrong)
    await certificateLogin(false, target().identities.untrusted)
    const bare = await target().probe(target().identities.first, true)
    expect(bare.code).toBe(255)
    expect(bare.stderr).toContain("Permission denied")
    await apply(ca, "ok")
    await dryRun(ca, "ok")
    await apply(ssh.authorizedPrincipals("deploy", ["release-team"]), "ok")
    await dryRun(ssh.authorizedPrincipals("deploy", ["release-team"]), "ok")
    const reloads = await target().container(["cat", "/run/confirmed-reloads"])
    await target().container(["chmod", "0600", "/etc/ssh/trusted_user_ca_keys"])
    expect(await ca.check(target().ssh, {})).toBe(NEEDS_APPLY)
    await apply(ca)
    expect(await target().container(["cat", "/run/confirmed-reloads"])).toBe(reloads)
    const unknownAction = await target().ssh.exec("systemctl restart ssh", { ignoreExitCode: true })
    const unknownUnit = await target().ssh.exec("systemctl cat foreign.service", {
      ignoreExitCode: true,
    })
    expect(unknownAction.code).toBe(64)
    expect(unknownUnit.code).toBe(64)
    expect(
      await target().container([
        "su",
        "-s",
        "/bin/sh",
        "-c",
        "test -r /etc/ssh/auth_principals/deploy && test -x /etc/ssh/auth_principals && test ! -w /etc/ssh/auth_principals && test ! -w /etc/ssh/auth_principals/deploy && cat /etc/ssh/auth_principals/deploy",
        "deploy",
      ])
    ).toBe("release-team")
    expect(
      await target().container([
        "stat",
        "-c",
        "%a %u %g",
        "/etc/ssh/auth_principals",
        "/etc/ssh/auth_principals/deploy",
        "/etc/ssh/trusted_user_ca_keys",
        "/etc/ssh/revoked_keys",
      ])
    ).toBe("755 0 0\n644 0 0\n644 0 0\n644 0 0")
    await apply(
      ssh.trustedUserCa({
        publicKey: target().ca1 + target().ca2,
        revokedKeys: "/etc/ssh/revoked_keys",
      })
    )
    await certificateLogin(true)
    await certificateLogin(true, target().identities.second)
    await apply(
      ssh.trustedUserCa({ publicKey: target().ca2, revokedKeys: "/etc/ssh/revoked_keys" })
    )
    await certificateLogin(false)
    await certificateLogin(true, target().identities.second)
  })

  it("preserves a real binary KRL and 0600 metadata while enforcing certificate revocation", async () => {
    await principals()
    await trustCommand("docker", [
      "cp",
      target().krl,
      `${await target().container(["hostname"])}:/etc/ssh/revoked_keys`,
    ])
    await target().container(["chmod", "0600", "/etc/ssh/revoked_keys"])
    await target().container(["chown", "0:0", "/etc/ssh/revoked_keys"])
    const before = await target().container([
      "sh",
      "-c",
      "sha256sum /etc/ssh/revoked_keys; stat -c '%a %u %g' /etc/ssh/revoked_keys; base64 -w0 /etc/ssh/revoked_keys",
    ])
    expect(
      Buffer.from(await readFile(target().krl))
        .subarray(0, 7)
        .toString()
    ).toBe("SSHKRL\n")
    await apply(
      ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/revoked_keys" })
    )
    expect(
      await target().container([
        "sh",
        "-c",
        "sha256sum /etc/ssh/revoked_keys; stat -c '%a %u %g' /etc/ssh/revoked_keys; base64 -w0 /etc/ssh/revoked_keys",
      ])
    ).toBe(before)
    await certificateLogin(true)
    await certificateLogin(false, target().identities.revoked)
  })

  it("preserves nonempty text revocations and rejects unsafe files before mutation", async () => {
    await principals()
    await target().write(
      "/etc/ssh/revoked_keys",
      await readFile(`${target().identities.untrusted.privateKey}.pub`, "utf8"),
      "0600"
    )
    const original = await target().ssh.readFile("/etc/ssh/revoked_keys")
    const ca = ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/revoked_keys" })
    await apply(ca)
    expect(await target().ssh.readFile("/etc/ssh/revoked_keys")).toBe(original)
    expect(await target().container(["stat", "-c", "%a %u %g", "/etc/ssh/revoked_keys"])).toBe(
      "600 0 0"
    )
    await certificateLogin(true)
    await target().container(["chmod", "0666", "/etc/ssh/revoked_keys"])
    await failure(ca, /Revocation file.*root-owned/v)
    await target().container(["rm", "/etc/ssh/revoked_keys"])
    await target().container(["ln", "-s", "/etc/passwd", "/etc/ssh/revoked_keys"])
    await failure(ca, /Symlink file rejected/v)
  })

  it("leaves RevokedKeys unmanaged when omitted and treats an empty principal set as no authorization", async () => {
    await principals()
    await target().write("/etc/ssh/revoked_keys", "# retained text list\n", "0600")
    await configWithPrefix("RevokedKeys /etc/ssh/revoked_keys")
    await apply(ssh.trustedUserCa({ publicKey: target().ca1 }))
    expect(await target().ssh.readFile("/etc/ssh/revoked_keys")).toBe("# retained text list\n")
    await certificateLogin(true)
    await apply(ssh.authorizedPrincipals("deploy", []))
    await certificateLogin(false)
    await apply(ssh.trustedUserCa({ state: "absent" }))
    expect(await target().container(["/usr/sbin/sshd", "-T"])).toContain(
      "revokedkeys /etc/ssh/revoked_keys"
    )
    expect(await target().ssh.readFile("/etc/ssh/revoked_keys")).toBe("# retained text list\n")
  })

  it("rejects an untraversable root parent, handles principal drift and isolates principal removal", async () => {
    await failure(
      ssh.authorizedPrincipals("missinguser", ["release-team"]),
      /Unix user does not exist/v
    )
    await target().container(["mkdir", "-m", "0700", "/etc/ssh/custom"])
    const module = ssh.authorizedPrincipals("deploy", ["release-team"], {
      principalsFile: "/etc/ssh/custom/%u",
    })
    await failure(module, /not traversable.*deploy/v)
    await target().container(["chmod", "0755", "/etc/ssh/custom"])
    await apply(module)
    await apply(
      ssh.trustedUserCa({ principalsFile: "/etc/ssh/custom/%u", publicKey: target().ca1 })
    )
    await certificateLogin(true)
    await target().container([
      "sh",
      "-c",
      "chmod 0600 /etc/ssh/custom/deploy; chown 1:1 /etc/ssh/custom/deploy",
    ])
    expect(await module.check(target().ssh, {})).toBe(NEEDS_APPLY)
    const before = await snapshot()
    await dryRun(module)
    expect(await snapshot()).toBe(before)
    await apply(module)
    await target().write("/etc/ssh/custom/other", "other-team\n")
    const config = await target().ssh.readFile("/etc/ssh/sshd_config")
    await apply(
      ssh.authorizedPrincipals("deploy", [], {
        principalsFile: "/etc/ssh/custom/%u",
        state: "absent",
      })
    )
    expect(await target().ssh.readFile("/etc/ssh/custom/other")).toBe("other-team\n")
    expect(await target().ssh.readFile("/etc/ssh/sshd_config")).toBe(config)
    await apply(
      ssh.authorizedPrincipals("deploy", [], {
        principalsFile: "/etc/ssh/custom/%u",
        state: "absent",
      }),
      "ok"
    )
    await target().write("/etc/ssh/custom/goneuser", "old-team\n")
    await apply(
      ssh.authorizedPrincipals("goneuser", [], {
        principalsFile: "/etc/ssh/custom/%u",
        state: "absent",
      })
    )
    expect(await target().ssh.exists("/etc/ssh/custom/goneuser")).toBe(false)
    await target().container(["ln", "-s", "/etc/ssh/custom", "/etc/ssh/auth_principals"])
    await failure(ssh.authorizedPrincipals("deploy", ["release-team"]), /Symlink parent rejected/v)
  })

  it("restores a principal file and its ownership when post-publication readability fails", async () => {
    await target().container(["mkdir", "-m", "0755", "/etc/ssh/auth_principals"])
    await target().write("/etc/ssh/auth_principals/deploy", "old-team\n", "0600")
    await target().container(["chown", "1:1", "/etc/ssh/auth_principals/deploy"])
    const before = await snapshot()
    const injected = injectCommandFault(
      /^su -s \/bin\/sh -c .*test -r /v,
      "Injected principal readability failure"
    )
    const result = await apply(ssh.authorizedPrincipals("deploy", ["release-team"]), "failed")
    expect(injected()).toBe(true)
    expect(result.error?.message).toMatch(/not readable.*previous file and metadata restored/v)
    expect(await snapshot()).toBe(before)
  })

  it("rejects first-wins Includes even with unchanged main content, Match includes and active path collisions", async () => {
    await principals()
    await target().container(["mkdir", "/etc/ssh/conf.d"])
    await target().write("/etc/ssh/conf.d/first.conf", "TrustedUserCAKeys /etc/ssh/foreign-ca\n")
    await configWithPrefix("Include /etc/ssh/conf.d/*.conf")
    await failure(
      ssh.trustedUserCa({ publicKey: target().ca1 }),
      /TrustedUserCAKeys: expected.*actual.*foreign-ca.*Include/v
    )
    await target().write("/etc/ssh/conf.d/first.conf", "# initially empty\n")
    const ca = ssh.trustedUserCa({ publicKey: target().ca1 })
    await apply(ca)
    await target().write("/etc/ssh/conf.d/first.conf", "TrustedUserCAKeys /etc/ssh/foreign-ca\n")
    // The main file is already converged; effective configuration still differs.
    await failure(ca, /TrustedUserCAKeys: expected.*actual.*foreign-ca/v)
    await target().write(
      "/etc/ssh/conf.d/first.conf",
      "AuthorizedPrincipalsFile /etc/ssh/foreign/%u\n"
    )
    await configWithPrefix("Match User deploy\nInclude /etc/ssh/conf.d/*.conf\nMatch all")
    await failure(ca, /Match block.*first.conf.*manually/v)
    await configWithPrefix(
      "Match User deploy\nAuthorizedPrincipalsFile /etc/ssh/foreign/%u\nMatch all"
    )
    await failure(ca, /Match block.*sshd_config.*manually/v)
    await configWithPrefix("Include /etc/ssh/conf.d/*.conf")
    await failure(
      ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/conf.d/first.conf" }),
      /collision/v
    )
    await target().container(["rm", "/etc/ssh/conf.d/first.conf"])
    await target().container(["ln", "-s", "/etc/ssh/missing", "/etc/ssh/conf.d/first.conf"])
    await failure(ca, /Cannot read active sshd Include/v)
    expect(await target().ssh.readFile("/etc/ssh/sshd_config")).toContain(
      "Include /etc/ssh/conf.d/*.conf"
    )
  })

  it("rejects prospective Include conflicts before exposing a replacement CA or creating revocations", async () => {
    await principals()
    await apply(ssh.trustedUserCa({ publicKey: target().ca1 }))
    await apply(ssh.authorizedPrincipals("deploy", [], { principalsFile: "/etc/ssh/custom/%u" }))
    await target().container(["mkdir", "/etc/ssh/conf.d"])
    await target().write(
      "/etc/ssh/conf.d/first.conf",
      "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u\n"
    )
    const activeConfig = await target().ssh.readFile("/etc/ssh/sshd_config")
    await target().write("/etc/ssh/sshd_config", `Include /etc/ssh/conf.d/*.conf\n${activeConfig}`)
    await target().container(["systemctl", "reload", "ssh"])
    await certificateLogin(true)
    await certificateLogin(false, target().identities.second)
    const before = await snapshot()
    const beforeMetadata = await managedTrustMetadata()
    const { mutations, observations, validations, writes } = observeCandidatePreflight()
    const result = await apply(
      ssh.trustedUserCa({
        principalsFile: "/etc/ssh/custom/%u",
        publicKey: target().ca2,
        revokedKeys: "/etc/ssh/revoked_keys",
      }),
      "failed"
    )
    expect(result.error?.message).toMatch(
      /AuthorizedPrincipalsFile: expected.*custom.*actual.*auth_principals.*Include/v
    )
    expect(
      observations.map(({ firstLogin, secondLogin }) => ({ firstLogin, secondLogin }))
    ).toStrictEqual([
      { firstLogin: 0, secondLogin: 255 },
      { firstLogin: 0, secondLogin: 255 },
    ])
    for (const observation of observations) {
      expect(observation.snapshot).toBe(before)
      expect(observation.metadata).toBe(beforeMetadata)
      expect(observation.revokedKeysExists).toBe(false)
    }
    expect(validations.map(({ code }) => code)).toStrictEqual([0, 0])
    expect(validations[0]?.command).toMatch(/^sshd -t -f /v)
    expect(validations[1]?.command).toMatch(/^sshd -T -f /v)
    expect(validations[1]?.stdout).toContain("authorizedprincipalsfile /etc/ssh/auth_principals/%u")
    expect(mutations).toStrictEqual([])
    expect(writes.mock.calls.map(([path]) => path)).toHaveLength(1)
    expect(writes.mock.calls[0]?.[0]).toMatch(/^\/tmp\/paratix-sshd-dry-run\./v)
    expect(await snapshot()).toBe(before)
    expect(await managedTrustMetadata()).toBe(beforeMetadata)
    await certificateLogin(true)
    await certificateLogin(false, target().identities.second)
  })

  it.each([
    { command: /^sshd -t -f /v, name: "candidate syntax validation" },
    { command: /^sshd -T$/v, name: "live effective validation" },
    { command: /^mv -T .* '\/etc\/ssh\/sshd_config'$/v, name: "atomic config publication" },
  ])("restores referenced files and metadata after a fault in $name", async ({ command }) => {
    await principals()
    await target().write("/etc/ssh/trusted_user_ca_keys", target().ca2, "0600")
    const before = await snapshot()
    const injected = injectCommandFault(command, "Injected transaction fault")
    const result = await apply(
      ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/revoked_keys" }),
      "failed"
    )
    expect(injected()).toBe(true)
    expect(result.error?.message).toMatch(
      /Injected transaction fault.*previous files and metadata restored/v
    )
    expect(await snapshot()).toBe(before)
    expect(
      await target().container([
        "find",
        "/tmp",
        "-maxdepth",
        "1",
        "-name",
        "paratix-sshd-dry-run.*",
      ])
    ).toBe("")
  })

  it("deactivates and confirms reload before deleting the CA, retains data and repeats removal", async () => {
    await principals()
    const revokedKeys = "/etc/ssh/revoked_keys"
    await apply(ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys }))
    const module = ssh.trustedUserCa({ revokedKeys, state: "absent" })
    const before = await snapshot()
    await dryRun(module)
    expect(await snapshot()).toBe(before)
    await apply(module)
    expect(await target().container(["sh", "-c", "tail -n1 /run/confirmed-reloads"])).toMatch(
      / present$/v
    )
    expect(await target().ssh.exists("/etc/ssh/trusted_user_ca_keys")).toBe(false)
    expect(await target().ssh.readFile("/etc/ssh/auth_principals/deploy")).toBe("release-team\n")
    expect(await target().ssh.exists(revokedKeys)).toBe(true)
    const effective = await target().container(["/usr/sbin/sshd", "-T"])
    const atReload = await target().container(["cat", "/run/last-confirmed-configuration"])
    for (const key of ["trustedusercakeys", "authorizedprincipalsfile", "revokedkeys"]) {
      expect(effective).toContain(`${key} none`)
      expect(atReload).toContain(`${key} none`)
    }
    await certificateLogin(false)
    await apply(module, "ok")
    await dryRun(module, "ok")
    await configWithPrefix("TrustedUserCAKeys /etc/ssh/foreign-ca")
    await failure(module, /foreign TrustedUserCAKeys/v)
    await target().container(["mkdir", "/etc/ssh/conf.d"])
    await target().write(
      "/etc/ssh/conf.d/first.conf",
      "TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n"
    )
    await configWithPrefix("Include /etc/ssh/conf.d/*.conf")
    await failure(module, /TrustedUserCAKeys: expected none, actual/v)
  })

  it("restores files and metadata on reload failure and exposes restoration failures", async () => {
    await principals()
    await target().write("/etc/ssh/trusted_user_ca_keys", target().ca2, "0600")
    await target().container(["touch", "/run/fail-reload-once"])
    const before = await snapshot()
    const result = await apply(
      ssh.trustedUserCa({ publicKey: target().ca1, revokedKeys: "/etc/ssh/revoked_keys" }),
      "failed"
    )
    expect(result.error?.message).toMatch(
      /Injected reload failure.*previous files and metadata restored/v
    )
    // Rollback's confirmed restoration reload is the only allowed state change.
    const afterRollback = await snapshot()
    expect(afterRollback.replace(/\n\d+ present$/v, "")).toBe(before)
    expect(await target().ssh.exists("/etc/ssh/revoked_keys")).toBe(false)
    expect(await target().ssh.readFile("/etc/ssh/trusted_user_ca_keys")).toBe(target().ca2)
    expect(await target().container(["stat", "-c", "%a", "/etc/ssh/trusted_user_ca_keys"])).toBe(
      "600"
    )
    await target().container(["touch", "/run/fail-all-reloads"])
    const restoration = await apply(ssh.trustedUserCa({ publicKey: target().ca1 }), "failed")
    expect(restoration.error?.message).toMatch(/rollback also failed:.*live sshd configuration/v)
    expect(await target().container(["find", "/etc/ssh", "-name", ".paratix-certificate.*"])).toBe(
      ""
    )
  })
})
