import { execFile } from "node:child_process"
import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { rsync } from "../../src/modules/rsync.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createMockSsh } from "../helpers/mockSsh.js"

vi.mock("node:crypto", () => ({
  randomUUID: vi.fn().mockReturnValue("known-hosts-test"),
}))

vi.mock("node:child_process", () => ({
  execFile: vi.fn(),
}))

vi.mock("node:fs", () => ({
  unlinkSync: vi.fn(),
  writeFileSync: vi.fn(),
}))

const emptyEnv = {}
const mockExecFile = vi.mocked(execFile)
const mockRandomUUID = vi.mocked(randomUUID)
const mockUnlinkSync = vi.mocked(unlinkSync)
const mockWriteFileSync = vi.mocked(writeFileSync)

// ---------------------------------------------------------------------------
// Helpers — centralize mock setup to avoid repetitive eslint-disable lines
// ---------------------------------------------------------------------------

function mockSuccess(stdout = ""): void {
  mockExecFile.mockImplementation((...args: unknown[]) => {
    const callback = args.at(-1) as (error: null, stdout: string, stderr: string) => void
    callback(null, stdout, "")
    return undefined as never
  })
}

function mockFailureWithStderr(
  parameters: { code?: number | string; stderr?: string; stdout?: string } = {}
): void {
  mockExecFile.mockImplementation((...args: unknown[]) => {
    const callback = args.at(-1) as (error: Error, stdout: string, stderr: string) => void
    const error = Object.assign(new Error("rsync failed"), {
      code: parameters.code,
      stderr: parameters.stderr ?? "",
      stdout: parameters.stdout ?? "",
    })
    callback(error, parameters.stdout ?? "", parameters.stderr ?? "")
    return undefined as never
  })
}

function getArgs(): string[] {
  return mockExecFile.mock.calls[0][1] as string[]
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("rsync.sync — check", () => {
  beforeEach(() => {
    mockExecFile.mockReset()
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when dry-run shows changes (stdout not empty)", async () => {
    mockSuccess(">f+++++++++ file.txt\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when dry-run shows no changes (stdout empty)", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("throws a descriptive error when the rsync dry-run command fails", async () => {
    mockFailureWithStderr({ code: 23, stderr: "Permission denied (publickey)." })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(
      "[rsync.sync] check failed for /local/src -> /remote/dest (exit code 23)\nPermission denied (publickey)."
    )
  })

  it("passes correct args to rsync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.check(mockSsh, emptyEnv)

    expect(mockExecFile).toHaveBeenCalledOnce()
    const [cmd] = mockExecFile.mock.calls[0]
    expect(cmd).toBe("rsync")
    const args = getArgs()
    expect(args).toContain("/local/src")
    expect(args).toContain("root@1.2.3.4:/remote/dest")
  })

  it("includes --dry-run flag", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.check(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--dry-run")
  })
})

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

describe("rsync.sync — apply", () => {
  beforeEach(() => {
    mockExecFile.mockReset()
  })

  it("returns failed when ssh is null", async () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when rsync transfers files", async () => {
    mockSuccess(">f+++++++++ file.txt\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok when destination is already in sync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns failed when rsync command fails", async () => {
    mockFailureWithStderr({ code: 12, stderr: "rsync: connection unexpectedly closed" })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain(
      "[rsync.sync] apply failed for /local/src -> /remote/dest (exit code 12)"
    )
    expect(result.error).toMatchObject({
      fullStderr: "rsync: connection unexpectedly closed",
      fullStdout: "",
    })
  })

  it("does NOT include --dry-run flag", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--dry-run")
  })

  it("passes correct args to rsync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(mockExecFile).toHaveBeenCalledOnce()
    const [cmd] = mockExecFile.mock.calls[0]
    expect(cmd).toBe("rsync")
    const args = getArgs()
    expect(args).toContain("/local/src")
    expect(args).toContain("root@1.2.3.4:/remote/dest")
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("rsync.sync — name", () => {
  it("has correct name format: rsync.sync: <src> -> <dest>", () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    expect(mod.name).toBe("rsync.sync: /local/src -> /remote/dest")
  })
})

// ---------------------------------------------------------------------------
// Argument building
// ---------------------------------------------------------------------------

describe("rsync.sync — argument building", () => {
  beforeEach(() => {
    mockExecFile.mockReset()
    mockSuccess()
    mockRandomUUID.mockReturnValue("known-hosts-test")
    mockUnlinkSync.mockReset()
    mockWriteFileSync.mockReset()
  })

  it("includes -az and --itemize-changes as base flags", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    expect(args).toContain("-az")
    expect(args).toContain("--itemize-changes")
  })

  it("includes SSH transport with correct port, key, and StrictHostKeyChecking=yes", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("ssh")
    expect(transportArg).toContain("-p 22")
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
  })

  it("uses a temporary verified known_hosts file for a pinned session host key", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
      verifiedHostPublicKey: "ssh-ed25519 AAAAPINNEDKEY",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", strictHostKeyChecking: "no" })

    await mod.apply(mockSsh, emptyEnv)

    expect(mockWriteFileSync).toHaveBeenCalledWith(
      expect.stringContaining("/paratix-rsync-known-hosts-known-hosts-test"),
      "1.2.3.4 ssh-ed25519 AAAAPINNEDKEY\n",
      { mode: 0o600 }
    )
    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("UserKnownHostsFile='")
    expect(transportArg).toContain("paratix-rsync-known-hosts-known-hosts-test")
    expect(transportArg).toContain("-o GlobalKnownHostsFile=/dev/null")
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
    expect(mockUnlinkSync).toHaveBeenCalledWith(
      expect.stringContaining("/paratix-rsync-known-hosts-known-hosts-test")
    )
  })

  it("wraps privateKeyPath with single quotes to prevent shell expansion of special characters", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "$HOME/.ssh/deploy key",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '$HOME/.ssh/deploy key'")
    expect(transportArg).not.toContain('-i "$HOME/.ssh/deploy key"')
  })

  it("uses custom StrictHostKeyChecking value when provided", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", strictHostKeyChecking: "no" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o StrictHostKeyChecking=no")
  })

  it("does not rely on a local known_hosts entry when the session exports a verified host key", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "fresh-host.example",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
      verifiedHostPublicKey: "ssh-ed25519 AAAAFRESHKEY",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })

    await mod.check(mockSsh, emptyEnv)

    expect(mockWriteFileSync).toHaveBeenCalledWith(
      expect.stringContaining("/paratix-rsync-known-hosts-known-hosts-test"),
      "fresh-host.example ssh-ed25519 AAAAFRESHKEY\n",
      { mode: 0o600 }
    )
    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("UserKnownHostsFile='")
    expect(transportArg).toContain("paratix-rsync-known-hosts-known-hosts-test")
    expect(transportArg).toContain("-o GlobalKnownHostsFile=/dev/null")
  })

  it("passes StrictHostKeyChecking=yes to ssh transport when set to yes", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      src: "/local/src",
      strictHostKeyChecking: "yes",
    })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
  })

  it("adds --include before --exclude patterns", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      exclude: ["*.log"],
      include: ["*.conf"],
      src: "/local/src",
    })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const includeIdx = args.indexOf("--include")
    const excludeIdx = args.indexOf("--exclude")
    expect(includeIdx).toBeGreaterThanOrEqual(0)
    expect(excludeIdx).toBeGreaterThanOrEqual(0)
    expect(args[includeIdx + 1]).toBe("*.conf")
    expect(args[excludeIdx + 1]).toBe("*.log")
    expect(includeIdx).toBeLessThan(excludeIdx)
  })

  it("adds --delete when delete option is true", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ delete: true, dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--delete")
  })

  it("does not add --delete when delete option is false", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ delete: false, dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--delete")
  })

  it("does not add --delete when delete option is undefined", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--delete")
  })

  it("adds --chown=owner:owner when only owner is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", owner: "deploy", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=deploy:deploy")
  })

  it("adds --chown=:group when only group is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", group: "www-data", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=:www-data")
  })

  it("adds --chown=owner:group when both are set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      group: "www-data",
      owner: "deploy",
      src: "/local/src",
    })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=deploy:www-data")
  })

  it("adds --chmod when chmod option is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ chmod: "644", dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chmod=644")
  })

  it("builds correct remote destination as user@host:dest", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/var/www/html", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@1.2.3.4:/var/www/html")
  })

  it("builds IPv6 remote destination in bracketed form", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "2001:db8::10",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/var/www/html", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@[2001:db8::10]:/var/www/html")
  })
})

// ---------------------------------------------------------------------------
// SSH auth — agent socket vs private key vs none
// ---------------------------------------------------------------------------

describe("rsync.sync — SSH auth method in transport flag", () => {
  beforeEach(() => {
    mockExecFile.mockReset()
    mockSuccess()
  })

  it("sets -o IdentityAgent=<socket> when agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/gnupg/S.gpg-agent.ssh",
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o IdentityAgent='/run/user/1000/gnupg/S.gpg-agent.ssh'")
    expect(transportArg).not.toContain("-i ")
  })

  it("wraps agentSocket with single quotes to prevent shell expansion", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/tmp/ssh-agent $USER.sock",
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o IdentityAgent='/tmp/ssh-agent $USER.sock'")
    expect(transportArg).not.toContain('-o IdentityAgent="/tmp/ssh-agent $USER.sock"')
  })

  it("prefers privateKeyPath over agentSocket when both are present", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/gnupg/S.gpg-agent.ssh",
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/deploy_key",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '~/.ssh/deploy_key'")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("sets -i <keypath> when only privateKeyPath is provided (backwards compatibility)", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("regression: appends -o IdentitiesOnly=yes whenever privateKeyPath is set", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    // Both the -i flag and IdentitiesOnly=yes must be present, so rsync only
    // ever uses the configured key and never silently picks an agent identity.
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).toContain("-o IdentitiesOnly=yes")
  })

  it("regression: does not append IdentitiesOnly=yes when only agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/ssh-agent.sock",
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    // IdentitiesOnly=yes is only meaningful in combination with -i; with an
    // agent-only fallback the option would over-restrict identity selection.
    expect(transportArg).toContain("-o IdentityAgent='/run/user/1000/ssh-agent.sock'")
    expect(transportArg).not.toContain("-o IdentitiesOnly=yes")
  })

  it("includes no identity flag when neither privateKeyPath nor agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).not.toContain("-i ")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("throws a clear error for password-authenticated sessions", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      authMethod: "password",
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })

    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(
      "[rsync.sync] check requires agent or private-key SSH authentication; password fallback sessions are not supported"
    )

    expect(mockExecFile).not.toHaveBeenCalled()
  })
})
