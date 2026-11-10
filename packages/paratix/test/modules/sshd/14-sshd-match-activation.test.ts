import { afterEach, describe, expect, it, vi } from "vitest"

import type { SshdMatchOptions } from "../../../src/modules/sshd.js"

import { sshd } from "../../../src/modules/sshd.js"
import { buildSshdMatchSpec } from "../../../src/modules/sshdMatchSpec.js"
import { createFakeSshdHost, type FakeSshdHostOptions } from "./sshdMatchFakeHost.js"

const DIRECTIVES = { ForceCommand: "/usr/local/bin/ops-ro-shell", PermitTTY: "no" } as const
const CRITERIA = { user: "ops-ro" }
const spec = buildSshdMatchSpec("ops-ro", CRITERIA, { directives: DIRECTIVES, options: {} })
const DROP_IN = spec.path
const PENDING = "/var/lib/paratix/sshd-match-pending-ops-ro"
const DESIRED = Object.entries(spec.settings)
  .map(([key, value]) => `${key.toLowerCase()} ${value}\n`)
  .join("")
const GROUPS = { "ops-ro": ["ops-ro"], root: ["root"] }
const STALE = `${spec.marker}\nMatch User ops-ro\n    PermitTTY yes\n`
const PENDING_REMOVAL = `rm -f -- '${PENDING}'`

type Fake = ReturnType<typeof createFakeSshdHost>

function host(overrides: Partial<FakeSshdHostOptions> = {}): Fake {
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

type Criteria = Parameters<typeof sshd.match>[1]

function present(options: SshdMatchOptions = {}, criteria: Criteria = CRITERIA) {
  return sshd.match("ops-ro", criteria, DIRECTIVES, options)
}

function absent(options: SshdMatchOptions = {}, criteria: Criteria = CRITERIA) {
  return sshd.match("ops-ro", criteria, DIRECTIVES, { ...options, state: "absent" })
}

function markPending(fake: Fake): void {
  fake.files.set(PENDING, { content: "pending\n", metadata: "600 0 0" })
}

function failPendingRemoval(command: string): string | undefined {
  return command === PENDING_REMOVAL ? "rm: busy" : undefined
}

// Records whether the marker already exists when the first matching command runs.
function markerObserver(fake: Fake, fragment: string) {
  const seen: { value?: boolean } = {}
  const observe = (command: string): undefined => {
    if (command.includes(fragment) && !command.startsWith("stat"))
      seen.value ??= fake.files.has(PENDING)
  }
  return { observe, seen }
}

const WITH_DROP_IN = { liveFiles: { [DROP_IN]: spec.content } }

// `start` and `undone` describe the drop-in before the change, `settled` after it.
const MODES = [
  {
    create: present,
    detail: `wrote ${DROP_IN}`,
    label: "present",
    mutation: `'${DROP_IN}'`,
    settled: spec.content,
    settledHost: WITH_DROP_IN,
    start: {},
    undone: undefined,
  },
  {
    create: absent,
    detail: `removed ${DROP_IN}`,
    label: "absent",
    mutation: `rm -- '${DROP_IN}'`,
    settled: undefined,
    settledHost: {},
    start: WITH_DROP_IN,
    undone: spec.content,
  },
] as const

describe.each(MODES)("sshd.match pending activation ($label)", (mode) => {
  afterEach(() => vi.restoreAllMocks())

  it("writes the marker before the drop-in changes and removes it after the reload", async () => {
    const fake = host(mode.start)
    const { observe, seen } = markerObserver(fake, mode.mutation)
    fake.behavior.failCommand = observe
    const result = await mode.create().apply(fake.connection, {})
    expect(result).toMatchObject({ detail: mode.detail, status: "changed" })
    expect(seen.value).toBe(true)
    expect(fake.files.has(PENDING)).toBe(false)
    expect(fake.reloads).toStrictEqual(["reload"])
    expect(fake.live(DROP_IN)).toBe(mode.settled)
  })

  it("keeps the marker when the connection drops at the reload", async () => {
    const fake = host(mode.start)
    fake.behavior.loseConnectionAtReload = true
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("stays pending for the next apply")
    expect(fake.files.get(PENDING)?.metadata).toBe("600 0 0")
    expect(fake.reloads).toStrictEqual([])
    expect(fake.live(DROP_IN)).toBe(mode.settled)
  })

  it("keeps the marker when reload and restore both fail", async () => {
    const fake = host(mode.start)
    fake.behavior.reloadError = "reload exploded"
    fake.behavior.restoreError = "restore exploded"
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })

  it("recovers an interrupted change: check, dry-run, then apply", async () => {
    const fake = host(mode.start)
    fake.behavior.loseConnectionAtReload = true
    await mode.create().apply(fake.connection, {})
    fake.behavior.loseConnectionAtReload = false
    fake.behavior.connectionLost = false

    await expect(mode.create().check(fake.connection, {})).resolves.toBe("needs-apply")
    const preview = await mode.create()._applyDryRun?.(fake.connection, {})
    expect(preview?.status).toBe("changed")
    expect(preview?._dryRunDetail).toContain("activation pending from an earlier run")
    expect(fake.reloads).toStrictEqual([])
    expect(fake.files.has(PENDING)).toBe(true)

    await expect(mode.create().apply(fake.connection, {})).resolves.toStrictEqual({
      detail: `activated pending change for ${DROP_IN}`,
      status: "changed",
    })
    expect(fake.reloads).toStrictEqual(["reload"])
    expect(fake.files.has(PENDING)).toBe(false)

    await expect(mode.create().apply(fake.connection, {})).resolves.toStrictEqual({ status: "ok" })
    await expect(mode.create().check(fake.connection, {})).resolves.toBe("ok")
    expect(fake.reloads).toStrictEqual(["reload"])
  })

  it("keeps the marker when the recovery reload fails", async () => {
    const fake = host(mode.settledHost)
    markPending(fake)
    fake.behavior.reloadError = "reload exploded"
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("stays pending for the next apply")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual(["reload", "restore"])
  })

  it("clears the marker after a clean rollback of a fresh run", async () => {
    const fake = host(mode.start)
    fake.behavior.reloadError = "reload exploded"
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("previous drop-in state restored")
    expect(result.error?.message).not.toContain("stays pending")
    expect(fake.files.has(PENDING)).toBe(false)
    expect(fake.live(DROP_IN)).toBe(mode.undone)
  })

  it("keeps a pre-existing marker through a clean rollback", async () => {
    const fake = host(mode.start)
    markPending(fake)
    fake.behavior.reloadError = "reload exploded"
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("previous drop-in state restored")
    expect(result.error?.message).toContain("stays pending for the next apply")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.live(DROP_IN)).toBe(mode.undone)
  })

  it("reports a marker that cannot be cleared after the reload", async () => {
    const fake = host(mode.start)
    fake.behavior.failCommand = failPendingRemoval
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("and reloaded sshd")
    expect(result.error?.message).toContain(`${PENDING} remains and a later run reloads once more`)
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.live(DROP_IN)).toBe(mode.settled)

    fake.behavior.failCommand = undefined
    await expect(mode.create().apply(fake.connection, {})).resolves.toMatchObject({
      status: "changed",
    })
    expect(fake.reloads).toStrictEqual(["reload", "reload"])
    expect(fake.files.has(PENDING)).toBe(false)
  })

  it("reports a marker that a clean rollback cannot clear", async () => {
    const fake = host(mode.start)
    fake.behavior.reloadError = "reload exploded"
    fake.behavior.failCommand = failPendingRemoval
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`rollback also failed: ${PENDING}: rm: busy`)
    expect(fake.files.has(PENDING)).toBe(true)
  })

  it("does not change the drop-in when the marker cannot be written", async () => {
    const fake = host({ ...mode.start, withoutStateDirectory: true })
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("cannot record the pending activation")
    expect(result.error?.message).toContain("drop-in left unchanged")
    expect(fake.reloads).toStrictEqual([])
    expect(fake.live(DROP_IN)).toBe(mode.undone)
  })

  it("fails closed on a symlinked marker in every mode", async () => {
    const fake = host({ ...mode.start, symlinks: [PENDING] })
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
    const applied = await mode.create().apply(fake.connection, {})
    expect(applied.status).toBe("failed")
    expect(applied.error?.message).toContain(
      `sshd.match pending-activation file must not be a symlink: ${PENDING}`
    )
    const preview = await mode.create()._applyDryRun?.(fake.connection, {})
    expect(preview?.status).toBe("failed")
    await expect(mode.create().check(fake.connection, {})).resolves.toBe("needs-apply")
    expect(write).toHaveBeenCalledWith(expect.stringContaining("must not be a symlink"))
    expect(fake.reloads).toStrictEqual([])
    expect(fake.live(DROP_IN)).toBe(mode.undone)
  })

  it("fails closed on a marker that is not a regular file", async () => {
    const fake = host({ ...mode.start, liveDirectories: [PENDING] })
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("must be a regular file")
    expect(fake.reloads).toStrictEqual([])
  })

  it("fails closed on a marker that others can write", async () => {
    const fake = host(mode.start)
    fake.files.set(PENDING, { content: "pending\n", metadata: "666 0 0" })
    const result = await mode.create().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("must be root-owned")
    expect(fake.reloads).toStrictEqual([])
  })
})

describe("sshd.match pending activation guards", () => {
  afterEach(() => vi.restoreAllMocks())

  const lockoutCriteria = { user: ["ops-ro", "root"] }
  const lockoutSpec = buildSshdMatchSpec("ops-ro", lockoutCriteria, {
    directives: DIRECTIVES,
    options: {},
  })

  it("still applies the lockout guard to a present recovery", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: lockoutSpec.content } })
    markPending(fake)
    const result = await present({}, lockoutCriteria).apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("match the Paratix connection user root")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual([])
  })

  it("still applies the lockout guard to an absent recovery", async () => {
    const fake = host()
    markPending(fake)
    const refused = await absent({}, lockoutCriteria).apply(fake.connection, {})
    expect(refused.status).toBe("failed")
    expect(refused.error?.message).toContain("allowConnectionUser: true")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual([])

    await expect(
      absent({ allowConnectionUser: true }, lockoutCriteria).apply(fake.connection, {})
    ).resolves.toMatchObject({ status: "changed" })
    expect(fake.files.has(PENDING)).toBe(false)
  })

  it("does not reload for a recovery while the verify user is missing", async () => {
    const fake = host({ groups: { root: ["root"] }, liveFiles: { [DROP_IN]: spec.content } })
    markPending(fake)
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("verify user ops-ro does not exist")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual([])
  })

  it("validates the tree again before a recovery reload", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: spec.content } })
    markPending(fake)
    fake.behavior.stagedTestFailure = "bad configuration option"
    const result = await present().apply(fake.connection, {})
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("bad configuration option")
    expect(fake.files.has(PENDING)).toBe(true)
    expect(fake.reloads).toStrictEqual([])
  })

  it("converges a drifted file and a marker from a run with the other state", async () => {
    const fake = host({ liveFiles: { [DROP_IN]: STALE } })
    markPending(fake)
    await expect(absent().apply(fake.connection, {})).resolves.toStrictEqual({
      detail: `removed ${DROP_IN}`,
      status: "changed",
    })
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(fake.files.has(PENDING)).toBe(false)
  })
})

describe("sshd.match without a pending activation", () => {
  afterEach(() => vi.restoreAllMocks())

  it.each([
    ["present", present, { liveFiles: { [DROP_IN]: spec.content } }],
    ["absent", absent, {}],
  ] as const)(
    "reads a missing state directory without creating it (%s)",
    async (_, create, base) => {
      const fake = host({ ...base, withoutStateDirectory: true })
      await expect(create().check(fake.connection, {})).resolves.toBe("ok")
      await expect(create()._applyDryRun?.(fake.connection, {})).resolves.toStrictEqual({
        status: "ok",
      })
      expect(fake.files.has(PENDING)).toBe(false)
      expect(fake.commands.some((command) => command.startsWith("mkdir"))).toBe(false)
    }
  )

  it("never writes the marker from check or dry-run", async () => {
    const fake = host()
    await present().check(fake.connection, {})
    await present()._applyDryRun?.(fake.connection, {})
    expect(fake.files.has(PENDING)).toBe(false)
  })

  it("does not write the marker when staged validation fails", async () => {
    const fake = host()
    fake.behavior.stagedTestFailure = "bad configuration option"
    await present().apply(fake.connection, {})
    expect(fake.files.has(PENDING)).toBe(false)
  })
})
