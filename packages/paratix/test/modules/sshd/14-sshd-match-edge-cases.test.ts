import { afterEach, describe, expect, it, vi } from "vitest"

import type { SshdMatchOptions } from "../../../src/modules/sshd.js"

import { sshd } from "../../../src/modules/sshd.js"
import { buildSshdMatchSpec } from "../../../src/modules/sshdMatchSpec.js"
import {
  createFakeSshdHost,
  DROP_IN_DIRECTORY,
  type FakeSshdHostOptions,
} from "./sshdMatchFakeHost.js"

const DIRECTIVES = { ForceCommand: "/usr/local/bin/ops-ro-shell", PermitTTY: "no" } as const
const CRITERIA = { user: "ops-ro" }
const spec = buildSshdMatchSpec("ops-ro", CRITERIA, { directives: DIRECTIVES, options: {} })
const DROP_IN = spec.path
const DESIRED = Object.entries(spec.settings)
  .map(([key, value]) => `${key.toLowerCase()} ${value}\n`)
  .join("")
const GROUPS = { "ops-ro": ["ops-ro"], root: ["root"] }
const GROUP_OPTIONS: SshdMatchOptions = { verifyUser: "ops-ro" }

function host(overrides: Partial<FakeSshdHostOptions> = {}) {
  const fake = createFakeSshdHost({
    desired: DESIRED,
    dropInPath: DROP_IN,
    groups: GROUPS,
    marker: spec.marker,
    ...overrides,
  })
  fake.install()
  return fake
}

function present(
  options: SshdMatchOptions = {},
  criteria: Parameters<typeof sshd.match>[1] = CRITERIA
) {
  return sshd.match("ops-ro", criteria, DIRECTIVES, options)
}

function liveMutations(commands: string[]): string[] {
  return commands.filter(
    (command) =>
      /^(?:mv|cp|chown) /v.test(command) ||
      command.startsWith("rm -- ") ||
      command.includes(".paratix-certificate")
  )
}

function failingWith(prefix: string): (command: string) => string | undefined {
  return (command) => (command.startsWith(prefix) ? "rm: busy" : undefined)
}

const STAGING_REMOVAL = failingWith("rm -rf -- '/tmp/paratix-sshd-match.")

function stagingLeftovers(files: Map<string, unknown>): string[] {
  return [...files.keys()].filter((path) => path.startsWith("/tmp/"))
}

describe("sshd.match Include check variants", () => {
  afterEach(() => vi.restoreAllMocks())

  it.each([
    ["a relative pattern", "Include sshd_config.d/*.conf"],
    ["a double-quoted pattern", `Include "${DROP_IN_DIRECTORY}/*.conf"`],
    ["a single-quoted pattern", `Include '${DROP_IN_DIRECTORY}/*.conf'`],
    ["several patterns on one line", `Include /etc/ssh/extra.conf ${DROP_IN_DIRECTORY}/*.conf`],
    ["the Include= form", `Include=${DROP_IN_DIRECTORY}/*.conf`],
    ["the Include = form", `Include = ${DROP_IN_DIRECTORY}/*.conf`],
    ["a lower-case keyword", `include ${DROP_IN_DIRECTORY}/*.conf`],
    ["a doubled slash", "Include /etc/ssh//sshd_config.d/*.conf"],
    ["a trailing comment", `Include ${DROP_IN_DIRECTORY}/*.conf # distro default`],
  ])("accepts %s and publishes the drop-in", async (_label, include) => {
    const fake = host({ mainConfig: `${include}\nPort 22\n` })
    await expect(present().apply(fake.connection, {})).resolves.toMatchObject({
      status: "changed",
    })
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.validatedTrees[0]).toContain(spec.content)
  })

  it("rejects an Include of a different directory", async () => {
    const fake = host({ mainConfig: "Include /etc/ssh/other.d/*.conf\nPort 22\n" })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Paratix never adds it")
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("places the candidate at its sorted position behind a doubled-slash Include", async () => {
    const fake = host({
      liveFiles: {
        [`${DROP_IN_DIRECTORY}/10-early.conf`]: "# early\n",
        [`${DROP_IN_DIRECTORY}/zz-late.conf`]: "# late\n",
      },
      mainConfig: "Include /etc/ssh//sshd_config.d/*.conf\nPort 22\n",
    })
    const result = await present()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("changed")
    const tree = fake.validatedTrees.join("")
    expect(tree.indexOf("# early")).toBeLessThan(tree.indexOf(spec.marker))
    expect(tree.indexOf(spec.marker)).toBeLessThan(tree.indexOf("# late"))
  })
})

describe("sshd.match lockout guard in check and dry-run", () => {
  afterEach(() => vi.restoreAllMocks())

  it("check needs apply and warns without staging", async () => {
    const fake = host()
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
    const module = present({}, { user: ["ops-ro", "root"] })
    await expect(module.check(fake.connection, {})).resolves.toBe("needs-apply")
    expect(write).toHaveBeenCalledWith(
      expect.stringContaining("match the Paratix connection user root")
    )
    expect(fake.validatedTrees).toStrictEqual([])
    expect(fake.commands.some((command) => command.startsWith("mktemp"))).toBe(false)
  })

  it("dry-run fails without staging or touching the live files", async () => {
    const fake = host()
    const result = await present({}, { user: ["ops-ro", "root"] })._applyDryRun?.(
      fake.connection,
      {}
    )
    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("match the Paratix connection user root")
    expect(fake.validatedTrees).toStrictEqual([])
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("also guards absent: removing a block that matches the connection user needs the flag", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    const criteria = { user: ["ops-ro", "root"] }
    const refused = await sshd
      .match("ops-ro", criteria, DIRECTIVES, { state: "absent" })
      .apply(fake.connection, {})
    expect(refused.status).toBe("failed")
    expect(refused.error?.message).toContain("allowConnectionUser: true")
    expect(fake.live(DROP_IN)).toBe(spec.content)

    const allowed = await sshd
      .match("ops-ro", criteria, DIRECTIVES, { allowConnectionUser: true, state: "absent" })
      .apply(fake.connection, {})
    expect(allowed).toMatchObject({ status: "changed" })
    expect(fake.live(DROP_IN)).toBeUndefined()
  })
})

describe("sshd.match verify user outside the criteria group", () => {
  afterEach(() => vi.restoreAllMocks())

  const groups = { "ops-ro": ["ops-ro"], root: ["root"] }

  it("dry-run reports changed with a pending detail and skips the -C effect check", async () => {
    const fake = host({ groups })
    const result = await present(GROUP_OPTIONS, { group: "ops" })._applyDryRun?.(
      fake.connection,
      {}
    )
    expect(result?.status).toBe("changed")
    expect(result?._dryRunDetail).toContain("pending")
    expect(result?._dryRunDetail).toContain("verify user ops-ro is not a member of ops")
    expect(fake.commands.some((command) => command.includes(" -C "))).toBe(false)
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("dry-run of a converged drop-in reports changed with a pending detail", async () => {
    const groupSpec = buildSshdMatchSpec(
      "ops-ro",
      { group: "ops" },
      { directives: DIRECTIVES, options: GROUP_OPTIONS }
    )
    const fake = host({ groups, liveFiles: { [DROP_IN]: groupSpec.content } })
    const result = await present(GROUP_OPTIONS, { group: "ops" })._applyDryRun?.(
      fake.connection,
      {}
    )
    expect(result).toMatchObject({ status: "changed" })
    expect(result?._dryRunDetail).toContain("is not a member of ops")
  })

  it("check needs apply without a warning", async () => {
    const fake = host({ groups })
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
    await expect(present(GROUP_OPTIONS, { group: "ops" }).check(fake.connection, {})).resolves.toBe(
      "needs-apply"
    )
    expect(write).not.toHaveBeenCalled()
  })

  it("apply fails before publishing", async () => {
    const fake = host({ groups })
    const result = await present(GROUP_OPTIONS, { group: "ops" }).apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("verify user ops-ro is not a member of ops")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual([])
  })
})

describe("sshd.match dry-run reload capability", () => {
  afterEach(() => vi.restoreAllMocks())

  it("checks the pure reload capability before reporting changed", async () => {
    const fake = host()
    const result = await present()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("changed")
    expect(fake.reloadChecks.value).toBe(1)
    expect(fake.reloads).toStrictEqual([])
  })

  it("fails when the unit has no pure reload capability", async () => {
    const fake = host()
    fake.behavior.reloadOnlyUnavailable = "Unit ssh.service has no pure reload capability"
    const result = await present()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("no pure reload capability")
    expect(liveMutations(fake.commands)).toStrictEqual([])
    expect(fake.reloads).toStrictEqual([])
  })
})

describe("sshd.match cleanup and rollback failures", () => {
  afterEach(() => vi.restoreAllMocks())

  it("keeps the staged validation error when the staging cleanup also fails", async () => {
    const fake = host()
    fake.behavior.stagedTestFailure = "bad configuration option"
    fake.behavior.failCommand = STAGING_REMOVAL
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("bad configuration option")
    expect(result.error?.message).toContain("staging cleanup also failed")
    expect(result.error?.message).toContain("rm: busy")
    expect(fake.live(DROP_IN)).toBeUndefined()
  })

  it("surfaces a staging cleanup failure after a successful validation", async () => {
    const fake = host()
    fake.behavior.failCommand = STAGING_REMOVAL
    const result = await present()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("staging cleanup failed")
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("publishes nothing when the staging cleanup fails after a successful validation in apply", async () => {
    const fake = host()
    fake.behavior.failCommand = STAGING_REMOVAL
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("staging cleanup failed")
    expect(result.error?.message).toContain("rm: busy")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual([])
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("reports a temporary-file cleanup failure after a successful reload as live", async () => {
    const fake = host()
    fake.behavior.failCommand = failingWith(`rm -rf -- '${DROP_IN_DIRECTORY}/.paratix-certificate.`)
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      `wrote ${DROP_IN} and reloaded sshd; temporary-file cleanup failed`
    )
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.reloads).toStrictEqual(["reload"])
  })

  it("reports a temporary-file cleanup failure after removing the drop-in as live", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    fake.behavior.failCommand = failingWith(`rm -rf -- '${DROP_IN_DIRECTORY}/.paratix-certificate.`)
    const result = await sshd
      .match("ops-ro", CRITERIA, DIRECTIVES, { state: "absent" })
      .apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      `removed ${DROP_IN} and reloaded sshd; temporary-file cleanup failed`
    )
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual(["reload"])
  })

  it("reports that the rollback also failed when the restore reload fails", async () => {
    const fake = host()
    fake.behavior.reloadError = "reload exploded"
    fake.behavior.restoreError = "Unit ssh.service has no ExecReload"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("reload exploded")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("live sshd configuration")
    expect(result.error?.message).toContain("no ExecReload")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })
})

describe("sshd.match file-type guards", () => {
  afterEach(() => vi.restoreAllMocks())

  it("refuses a symlinked drop-in without touching it", async () => {
    const fake = host({ symlinks: [DROP_IN] })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`sshd.match drop-in must not be a symlink: ${DROP_IN}`)
    expect(liveMutations(fake.commands)).toStrictEqual([])
    expect(fake.validatedTrees).toStrictEqual([])
  })

  it("names a symlinked unrelated drop-in as an sshd Include file", async () => {
    const foreign = `${DROP_IN_DIRECTORY}/10-foreign.conf`
    const fake = host({ symlinks: [foreign] })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`sshd Include file must not be a symlink: ${foreign}`)
    expect(result.error?.message).not.toContain("Revocation")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(stagingLeftovers(fake.files)).toStrictEqual([])
  })

  it("names a non-regular unrelated drop-in as an sshd Include file", async () => {
    const directory = `${DROP_IN_DIRECTORY}/20-directory.conf`
    const fake = host({ liveDirectories: [directory] })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      `sshd Include file must be a regular file: ${directory}`
    )
    expect(fake.live(DROP_IN)).toBeUndefined()
  })

  it("names a group-writable unrelated drop-in as an sshd Include file", async () => {
    const writable = `${DROP_IN_DIRECTORY}/30-writable.conf`
    const fake = host({ liveFiles: { [writable]: "# writable\n" } })
    fake.files.set(writable, { content: "# writable\n", metadata: "664 0 0" })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      `sshd Include file must be root-owned, root-readable and not group/other-writable: ${writable}`
    )
  })
})
