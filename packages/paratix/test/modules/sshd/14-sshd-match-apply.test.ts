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
const STALE = `${spec.marker}\nMatch User ops-ro\n    PermitTTY yes\n`

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

function absent() {
  return sshd.match("ops-ro", CRITERIA, DIRECTIVES, { state: "absent" })
}

function mutatingCommands(commands: string[]): string[] {
  return commands.filter(
    (command) => /^(?:mv|rm|cp|chown) /v.test(command) || command.includes("mktemp")
  )
}

describe("sshd.match apply", () => {
  afterEach(() => vi.restoreAllMocks())

  it("publishes the drop-in once and converges idempotently", async () => {
    const fake = host()
    const module = present()

    const first = await module.apply(fake.connection, {})
    expect(first).toMatchObject({ detail: `wrote ${DROP_IN}`, status: "changed" })
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.files.get(DROP_IN)?.metadata).toBe("644 0 0")
    expect(fake.reloads).toStrictEqual(["reload"])
    expect([...fake.files.keys()].filter((path) => path.startsWith("/tmp/"))).toStrictEqual([])
    expect(fake.validatedTrees[0]).toContain(spec.content)

    await expect(module.apply(fake.connection, {})).resolves.toStrictEqual({ status: "ok" })
    await expect(module.check(fake.connection, {})).resolves.toBe("ok")
    await expect(module._applyDryRun?.(fake.connection, {})).resolves.toStrictEqual({
      status: "ok",
    })
    expect(fake.reloads).toStrictEqual(["reload"])
  })

  it("replaces a drifted drop-in that carries the marker", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: STALE } })
    await expect(present().apply(fake.connection, {})).resolves.toMatchObject({ status: "changed" })
    expect(fake.live(DROP_IN)).toBe(spec.content)
  })

  it("fails when the verify user does not exist", async () => {
    const fake = host({ groups: {} })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "verify user ops-ro does not exist or cannot be resolved"
    )
    expect(fake.live(DROP_IN)).toBeUndefined()
  })
})

describe("sshd.match lockout guard", () => {
  afterEach(() => vi.restoreAllMocks())

  it("refuses criteria that match the connection user by user name", async () => {
    const fake = host()
    const result = await present({}, { user: ["ops-ro", "root"] }).apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("match the Paratix connection user root")
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
    expect(fake.reloads).toStrictEqual([])
    expect(fake.live(DROP_IN)).toBeUndefined()
  })

  it("refuses criteria that match the connection user by group via id -Gn", async () => {
    const fake = host({ groups: { "ops-ro": ["ops-ro", "wheel"], root: ["root", "wheel"] } })
    const result = await present({ verifyUser: "ops-ro" }, { group: "wheel" }).apply(
      fake.connection,
      {}
    )
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("match the Paratix connection user root")
    expect(fake.commands).toContain("id -Gn -- 'root'")
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
  })

  it("refuses when the groups of the connection user cannot be determined", async () => {
    const fake = host({ groups: { "ops-ro": ["ops-ro", "wheel"] } })
    const result = await present({ verifyUser: "ops-ro" }, { group: "wheel" }).apply(
      fake.connection,
      {}
    )
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("cannot determine the groups")
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
  })

  it("proceeds with allowConnectionUser: true", async () => {
    const fake = host({ groups: { "ops-ro": ["ops-ro", "wheel"], root: ["root", "wheel"] } })
    const module = present({ allowConnectionUser: true, verifyUser: "ops-ro" }, { group: "wheel" })
    await expect(module.apply(fake.connection, {})).resolves.toMatchObject({ status: "changed" })
    expect(fake.reloads).toStrictEqual(["reload"])
  })
})

describe("sshd.match preconditions", () => {
  afterEach(() => vi.restoreAllMocks())

  it.each([
    ["no Include at all", "Port 22\n"],
    [
      "an Include after the first Match",
      `Port 22\nMatch User root\n    PermitTTY yes\nInclude ${DROP_IN_DIRECTORY}/*.conf\n`,
    ],
  ])("fails with %s and writes nothing", async (_label, mainConfig) => {
    const fake = host({ mainConfig })
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`Include ${DROP_IN_DIRECTORY}/*.conf`)
    expect(result.error?.message).toContain("Paratix never adds it")
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
    expect(fake.live(DROP_IN)).toBeUndefined()
  })

  it.each([
    ["present", present],
    ["absent", absent],
  ])("neither overwrites nor removes a foreign file (%s)", async (_label, create) => {
    const foreign = "Match User someone\n    PermitTTY yes\n"
    const fake = host({ liveFiles: { [DROP_IN]: foreign } })
    const result = await create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("without the marker")
    expect(fake.live(DROP_IN)).toBe(foreign)
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
    expect(fake.reloads).toStrictEqual([])
  })
})

describe("sshd.match staged validation", () => {
  afterEach(() => vi.restoreAllMocks())

  it("fails without publishing or reloading when staged sshd -t fails", async () => {
    const fake = host()
    fake.behavior.stagedTestFailure = "bad configuration option"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("bad configuration option")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.commands.some((command) => command.startsWith("mv "))).toBe(false)
    expect(fake.reloads).toStrictEqual([])
    expect([...fake.files.keys()].filter((path) => path.startsWith("/tmp/"))).toStrictEqual([])
  })

  it("names the directive when staged sshd -T -C does not show the desired value", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: STALE } })
    fake.behavior.stagedEffective = () =>
      "forcecommand /usr/local/bin/ops-ro-shell\npermittty yes\n"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("PermitTTY: expected no")
    expect(result.error?.message).toContain("staged sshd -T -C")
    expect(fake.live(DROP_IN)).toBe(STALE)
    expect(fake.reloads).toStrictEqual([])
  })
})

describe("sshd.match rollback", () => {
  afterEach(() => vi.restoreAllMocks())

  it("removes a new file when the live sshd -T -C check mismatches, without a restore reload", async () => {
    const fake = host()
    fake.behavior.liveEffective = () => "permittty yes\nforcecommand /usr/local/bin/ops-ro-shell\n"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("PermitTTY: expected no")
    expect(result.error?.message).toContain("previous drop-in state restored")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual([])
  })

  it("restores the previous file when the live check mismatches", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: STALE } })
    fake.behavior.liveEffective = () => ""
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.live(DROP_IN)).toBe(STALE)
    expect(fake.files.get(DROP_IN)?.metadata).toBe("644 0 0")
    expect(fake.reloads).toStrictEqual([])
  })

  it("restores the file and the live daemon when the reload fails", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: STALE } })
    fake.behavior.reloadError = "reload exploded"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("reload exploded")
    expect(fake.live(DROP_IN)).toBe(STALE)
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })

  it("removes a new file and attempts a restore reload when the reload fails", async () => {
    const fake = host()
    fake.behavior.reloadError = "reload exploded"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })
})

describe("sshd.match absent", () => {
  afterEach(() => vi.restoreAllMocks())

  it("reports ok for a missing file in every mode", async () => {
    const fake = host()
    await expect(absent().apply(fake.connection, {})).resolves.toStrictEqual({ status: "ok" })
    await expect(absent().check(fake.connection, {})).resolves.toBe("ok")
    await expect(absent()._applyDryRun?.(fake.connection, {})).resolves.toStrictEqual({
      status: "ok",
    })
    expect(mutatingCommands(fake.commands)).toStrictEqual([])
  })

  it("validates the tree without the drop-in before removing it", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    const result = await absent().apply(fake.connection, {})
    expect(result).toMatchObject({ detail: `removed ${DROP_IN}`, status: "changed" })
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.validatedTrees).toHaveLength(1)
    expect(fake.validatedTrees[0]).not.toContain(spec.marker)
    expect(fake.reloads).toStrictEqual(["reload"])
    const validated = fake.commands.findIndex((command) => command.startsWith("sshd -t -f"))
    const removed = fake.commands.indexOf(`rm -- '${DROP_IN}'`)
    expect(validated).toBeGreaterThanOrEqual(0)
    expect(removed).toBeGreaterThan(validated)
    await expect(absent().apply(fake.connection, {})).resolves.toStrictEqual({ status: "ok" })
  })

  it("keeps the file when the staged validation fails", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    fake.behavior.stagedTestFailure = "tree without the drop-in is invalid"
    const result = await absent().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.commands).not.toContain(`rm -- '${DROP_IN}'`)
    expect(fake.reloads).toStrictEqual([])
  })

  it("restores the previous file when the live check after removal fails", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    fake.behavior.liveEffective = () => {
      throw new Error("sshd -T failed")
    }
    const result = await absent().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.reloads).toStrictEqual([])
  })

  it("restores the file and attempts a restore reload when the reload fails", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    fake.behavior.reloadError = "reload exploded"
    const result = await absent().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })
})
