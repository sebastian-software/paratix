import { afterEach, describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { buildSshdMatchSpec } from "../../../src/modules/sshdMatchSpec.js"
import { createFakeSshdHost } from "./sshdMatchFakeHost.js"

const DIRECTIVES = { ForceCommand: "/usr/local/bin/ops-ro-shell", PermitTTY: "no" } as const
const spec = buildSshdMatchSpec(
  "ops-ro",
  { user: "ops-ro" },
  { directives: DIRECTIVES, options: {} }
)
const DROP_IN = spec.path
const DESIRED = Object.entries(spec.settings)
  .map(([key, value]) => `${key.toLowerCase()} ${value}\n`)
  .join("")

function host(
  liveFiles: Record<string, string> = {},
  groups: Record<string, string[]> | undefined = { "ops-ro": ["ops-ro"], root: ["root"] }
) {
  const fake = createFakeSshdHost({
    desired: DESIRED,
    dropInPath: DROP_IN,
    groups,
    liveFiles,
    marker: spec.marker,
  })
  fake.install()
  return fake
}

function module() {
  return sshd.match("ops-ro", { user: "ops-ro" }, DIRECTIVES)
}

function liveMutations(commands: string[]): string[] {
  return commands.filter(
    (command) => /^(?:mv|cp|chown) /v.test(command) || command.startsWith("rm -- ")
  )
}

describe("sshd.match check", () => {
  afterEach(() => vi.restoreAllMocks())

  it("is ok only for the byte-identical file confirmed by sshd -T -C", async () => {
    const fake = host({ [DROP_IN]: spec.content })
    await expect(module().check(fake.connection, {})).resolves.toBe("ok")
    expect(fake.commands.some((command) => command.startsWith("mv "))).toBe(false)
    expect(fake.reloads).toStrictEqual([])
  })

  it("needs apply for a missing file", async () => {
    const fake = host()
    await expect(module().check(fake.connection, {})).resolves.toBe("needs-apply")
  })

  it("needs apply for drifted content", async () => {
    const fake = host({ [DROP_IN]: `${spec.content}# drift\n` })
    await expect(module().check(fake.connection, {})).resolves.toBe("needs-apply")
  })

  it("needs apply for drifted metadata", async () => {
    const fake = host({ [DROP_IN]: spec.content })
    fake.files.set(DROP_IN, { content: spec.content, metadata: "600 0 0" })
    await expect(module().check(fake.connection, {})).resolves.toBe("needs-apply")
  })

  it("needs apply, with a warning, when sshd -T -C does not confirm the value", async () => {
    const fake = host({ [DROP_IN]: spec.content })
    fake.behavior.liveEffective = () => "permittty yes\nforcecommand /usr/local/bin/ops-ro-shell\n"
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
    await expect(module().check(fake.connection, {})).resolves.toBe("needs-apply")
    expect(write).toHaveBeenCalledWith(expect.stringContaining("PermitTTY: expected no"))
  })

  it("checks absent as ok for a missing file and needs-apply for an existing one", async () => {
    const absent = sshd.match("ops-ro", { user: "ops-ro" }, DIRECTIVES, { state: "absent" })
    await expect(absent.check(host().connection, {})).resolves.toBe("ok")
    await expect(absent.check(host({ [DROP_IN]: spec.content }).connection, {})).resolves.toBe(
      "needs-apply"
    )
  })
})

describe("sshd.match dry-run", () => {
  afterEach(() => vi.restoreAllMocks())

  it("validates the staged tree without writing the drop-in or reloading", async () => {
    const fake = host()
    const result = await module()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("changed")
    expect(result?._dryRunDetail).toContain("drop-in not written, reload not executed")
    expect(fake.live(DROP_IN)).toBeUndefined()
    expect(liveMutations(fake.commands)).toStrictEqual([])
    expect(fake.reloads).toStrictEqual([])
    expect(fake.validatedTrees[0]).toContain(spec.content)
    expect([...fake.files.keys()].filter((path) => path.startsWith("/tmp/"))).toStrictEqual([])
  })

  it("is skipped with a detail when /run/sshd is missing", async () => {
    const fake = host()
    fake.behavior.privilegeSeparation = false
    const result = await module()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("skipped")
    expect(result?._dryRunDetail).toContain("/run/sshd")
    expect(fake.validatedTrees).toStrictEqual([])
  })

  it("reports changed with a pending detail while the verify user does not exist", async () => {
    const fake = host({}, {})
    const result = await module()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("changed")
    expect(result?._dryRunDetail).toContain("pending")
    expect(result?._dryRunDetail).toContain("ops-ro")
    expect(fake.validatedTrees).toHaveLength(1)
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("fails when the staged effective value is wrong", async () => {
    const fake = host()
    fake.behavior.stagedEffective = () => ""
    const result = await module()._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("failed")
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("is idempotent once the drop-in is converged", async () => {
    const fake = host({ [DROP_IN]: spec.content })
    await expect(module()._applyDryRun?.(fake.connection, {})).resolves.toStrictEqual({
      status: "ok",
    })
    await expect(module()._applyDryRun?.(fake.connection, {})).resolves.toStrictEqual({
      status: "ok",
    })
    expect(liveMutations(fake.commands)).toStrictEqual([])
  })

  it("reports changed for absent with an existing drop-in and keeps it", async () => {
    const fake = host({ [DROP_IN]: spec.content })
    const absent = sshd.match("ops-ro", { user: "ops-ro" }, DIRECTIVES, { state: "absent" })
    const result = await absent._applyDryRun?.(fake.connection, {})
    expect(result?.status).toBe("changed")
    expect(fake.live(DROP_IN)).toBe(spec.content)
    expect(fake.validatedTrees[0]).not.toContain(spec.marker)
    expect(fake.reloads).toStrictEqual([])
  })
})
