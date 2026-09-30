import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { runSymlinkContainmentBackstop } from "../../src/modules/archiveContainmentBackstop.js"
import {
  CONTAINMENT_FLAG_BODY_LIMIT_BYTES,
  CONTAINMENT_FLAG_LINK_LIMIT,
  containmentFlagBody,
  establishContainmentFlag,
  parseContainmentFlag,
  readContainmentFlag,
  recordWithoutVerification,
  TOO_MANY_OFFENDING_LINKS,
  UNVERIFIED_DESTINATION,
} from "../../src/modules/archiveContainmentFlag.js"
import { buildKernelCrossCheckScript } from "../../src/modules/archiveKernelCrossCheck.js"
import { buildSymlinkListingProbeScript } from "../../src/modules/archiveProbe.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../../src/sshHelpers.js"

const destination = "/opt/app"
const source = "/tmp/app.tar.gz"
const flag = "/var/lib/paratix/flags/archive-containment-0123.failed"
const listingCommand = buildSymlinkListingProbeScript()
const crossCheckCommand = buildKernelCrossCheckScript()

/**
 * Issue #219: a flag body written as JSON with a trailing newline.
 *
 * @param value - The body object.
 * @returns The body text.
 */
function body(value: unknown): string {
  return `${JSON.stringify(value)}\n`
}

describe("containment flag body (Issue #219)", () => {
  it("round-trips a failed record, including a key with a segment that is not valid UTF-8", () => {
    const links = ["a/esc", "b/\u0000ff/l", "c d/l\nx"]

    const text = containmentFlagBody({ links, state: "failed" })

    expect(text).toBe(`{"links":${JSON.stringify(links)},"state":"failed","version":1}\n`)
    expect(text).toContain(String.raw`\u0000ff`)
    expect(parseContainmentFlag(text)).toStrictEqual({ kind: "recorded", links })
  })

  it("records an empty list as a usable list", () => {
    expect(parseContainmentFlag(containmentFlagBody({ links: [], state: "failed" }))).toStrictEqual(
      { kind: "recorded", links: [] }
    )
  })

  it("drops duplicate links when it serializes a body", () => {
    expect(containmentFlagBody({ links: ["a", "a", "b"], state: "failed" })).toBe(
      body({ links: ["a", "b"], state: "failed", version: 1 })
    )
  })

  it("records unknown when more links than the limit offend", () => {
    const links = Array.from({ length: CONTAINMENT_FLAG_LINK_LIMIT + 1 }, (_value, index) =>
      String(index)
    )

    const text = containmentFlagBody({ links, state: "failed" })

    expect(text).toBe(body({ reason: TOO_MANY_OFFENDING_LINKS, state: "unknown", version: 1 }))
    expect(parseContainmentFlag(text).kind).toBe("unknown")
    expect(
      parseContainmentFlag(containmentFlagBody({ links: links.slice(1), state: "failed" }))
    ).toStrictEqual({ kind: "recorded", links: links.slice(1) })
  })

  it("records unknown when the links do not fit the body limit", () => {
    const long = "x".repeat(Math.ceil(CONTAINMENT_FLAG_BODY_LIMIT_BYTES / 200))
    const links = Array.from({ length: 200 }, (_value, index) => `${long}/${String(index)}`)

    expect(containmentFlagBody({ links, state: "failed" })).toBe(
      body({ reason: TOO_MANY_OFFENDING_LINKS, state: "unknown", version: 1 })
    )
  })

  it.each([
    { name: "an empty file", text: "" },
    {
      name: "the fixed text of older versions",
      text: "archive apply in progress or symlink containment check failed\n",
    },
    { name: "garbled JSON", text: '{"version":1,"state":"failed","links":["a"' },
    { name: "JSON null", text: "null" },
    { name: "a JSON array", text: '["a"]' },
    { name: "another version", text: body({ links: [], state: "failed", version: 2 }) },
    { name: "a string version", text: body({ links: [], state: "failed", version: "1" }) },
    { name: "an extra key", text: body({ extra: true, links: [], state: "failed", version: 1 }) },
    { name: "a missing links key", text: body({ state: "failed", version: 1 }) },
    { name: "another state", text: body({ links: [], state: "ok", version: 1 }) },
    {
      name: "links that are not an array",
      text: body({ links: "a", state: "failed", version: 1 }),
    },
    { name: "a non-string link", text: body({ links: [1], state: "failed", version: 1 }) },
    { name: "an empty link", text: body({ links: [""], state: "failed", version: 1 }) },
    { name: "an absolute link", text: body({ links: ["/etc/l"], state: "failed", version: 1 }) },
    { name: "a link with ..", text: body({ links: ["a/../l"], state: "failed", version: 1 }) },
    { name: "a link with .", text: body({ links: ["./l"], state: "failed", version: 1 }) },
    { name: "a trailing slash", text: body({ links: ["a/"], state: "failed", version: 1 }) },
    { name: "a duplicate link", text: body({ links: ["a", "a"], state: "failed", version: 1 }) },
    {
      name: "more links than the limit",
      text: body({
        links: Array.from({ length: CONTAINMENT_FLAG_LINK_LIMIT + 1 }, (_value, index) =>
          String(index)
        ),
        state: "failed",
        version: 1,
      }),
    },
    {
      name: "a body above the limit",
      text: `${body({ links: ["a"], state: "failed", version: 1 })}${" ".repeat(CONTAINMENT_FLAG_BODY_LIMIT_BYTES)}`,
    },
    { name: "a record without a reason", text: body({ state: "unknown", version: 1 }) },
    { name: "a non-string reason", text: body({ reason: 1, state: "unknown", version: 1 }) },
  ])("holds no usable list with $name", ({ text }) => {
    expect(parseContainmentFlag(text)).toStrictEqual({
      kind: "unknown",
      why: "holds no usable list of offending links (it was written by an older paratix version or is damaged)",
    })
  })

  it("reads an in-progress body as an apply that did not finish, whatever links it carries", () => {
    expect(
      parseContainmentFlag(containmentFlagBody({ links: ["a/esc"], state: "in-progress" }))
    ).toStrictEqual({
      kind: "unknown",
      why: "records an apply that did not finish (it stopped after it started, possibly after its merge had begun, or another apply to this destination is still running)",
    })
  })

  it("reads an unknown body with its reason", () => {
    expect(
      parseContainmentFlag(
        containmentFlagBody({ reason: TOO_MANY_OFFENDING_LINKS, state: "unknown" })
      )
    ).toStrictEqual({
      kind: "unknown",
      why: "records a failed apply whose offending links are not known (too many offending links)",
    })
  })
})

/**
 * Issue #219: a connection whose only exec answers with a fixed result or
 * rejects with an error.
 *
 * @param answer - The result, or the error to reject with.
 * @returns The connection and its recorded execs.
 */
function singleExecConnection(answer: Error | Partial<ExecResult>): {
  conn: SshConnection
  execs: Array<{ command: string; options: ExecOptions | undefined }>
} {
  const execs: Array<{ command: string; options: ExecOptions | undefined }> = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      execs.push({ command, options })
      if (answer instanceof Error) throw answer
      return { code: 0, stderr: "", stdout: "", ...answer }
    },
  } as unknown as SshConnection
  return { conn, execs }
}

describe("readContainmentFlag (Issue #219)", () => {
  const paths = { directory: "/var/lib/paratix/flags", flag }

  it("reads in one exec with a capture cap just above the body limit and strict UTF-8", async () => {
    const { conn, execs } = singleExecConnection({ stdout: "" })

    await expect(readContainmentFlag(conn, paths)).resolves.toStrictEqual({ kind: "absent" })

    expect(execs).toHaveLength(1)
    expect(execs[0]?.options).toStrictEqual({
      ignoreExitCode: true,
      maxOutputBytes: CONTAINMENT_FLAG_BODY_LIMIT_BYTES + 1024,
      silent: true,
      strictUtf8Stdout: true,
    })
  })

  it.each([
    {
      answer: { stdout: "present\n" },
      expected: { kind: "unknown", why: expect.stringContaining("holds no usable list") },
      name: "an empty flag",
    },
    {
      answer: { stdout: `present\n${containmentFlagBody({ links: ["a/l"], state: "failed" })}` },
      expected: { kind: "recorded", links: ["a/l"] },
      name: "a recorded list",
    },
    {
      answer: { stdout: `present\n{"links":["a/l"${CAPTURE_TRUNCATION_MARKER}` },
      expected: {
        kind: "unknown",
        why: `is larger than ${String(CONTAINMENT_FLAG_BODY_LIMIT_BYTES)} bytes and holds no usable list of offending links (it was written by an older paratix version or is damaged)`,
      },
      name: "a truncated capture",
    },
    {
      answer: new InvalidUtf8OutputError("Command stdout is not valid UTF-8 (exit code 0): cat"),
      expected: { kind: "unknown", why: expect.stringContaining("is not valid UTF-8") },
      name: "stdout that is not valid UTF-8",
    },
    {
      answer: { code: 3 },
      expected: { kind: "unreadable", reason: `containment-failure flag ${flag} is a symlink` },
      name: "a symlink at the flag path",
    },
    {
      answer: { code: 4 },
      expected: {
        kind: "unreadable",
        reason: `containment-failure flag ${flag} exists but is not a regular file`,
      },
      name: "a directory at the flag path",
    },
    {
      answer: { code: 2, stderr: "mkdir: Read-only file system\n" },
      expected: {
        kind: "unreadable",
        reason: `failed to create archive marker directory for containment-failure flag ${flag}: mkdir: Read-only file system`,
      },
      name: "a flags directory that cannot be created",
    },
    {
      answer: { code: 1, stderr: "cat: Permission denied" },
      expected: {
        kind: "unreadable",
        reason: `failed to read containment-failure flag ${flag}: cat: Permission denied`,
      },
      name: "a failed cat",
    },
    {
      answer: { stdout: "garbage" },
      expected: {
        kind: "unreadable",
        reason: `failed to read containment-failure flag ${flag}: unexpected output`,
      },
      name: "output without the presence line",
    },
    {
      answer: new Error("channel closed"),
      expected: {
        kind: "unreadable",
        reason: `failed to read containment-failure flag ${flag}: channel closed`,
      },
      name: "a thrown exec",
    },
  ])("reads $name", async ({ answer, expected }) => {
    const { conn } = singleExecConnection(answer)

    await expect(readContainmentFlag(conn, paths)).resolves.toStrictEqual(expected)
  })
})

/**
 * Issue #219: a symlink archive member.
 *
 * @param path - Destination-relative member path.
 * @param target - The link target.
 * @returns A tar symlink member with that target.
 */
function symlinkMember(path: string, target: string): ArchiveMember {
  return { format: "tar", kind: "symlink", linkTarget: target, mode: "lrwxrwxrwx", path }
}

/**
 * Issue #219: a regular file archive member.
 *
 * @param path - Destination-relative member path.
 * @returns A tar regular file member.
 */
function fileMember(path: string): ArchiveMember {
  return { format: "tar", kind: "file", linkTarget: null, mode: "-rw-r--r--", path }
}

/**
 * Issue #219: a connection that answers the backstop listing with fixed
 * records and gives every link the kernel cross-check carries one verdict.
 *
 * @param listing - The listing's NUL-framed records.
 * @param verdict - The cross-check verdict for every link: `same` confirms
 *   the resolver, `differ` (at level 0) contradicts it.
 * @returns The connection and the commands it ran.
 */
function backstopConnection(
  listing: string,
  verdict: "differ" | "same" = "same"
): { commands: string[]; conn: SshConnection } {
  const commands: string[] = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      commands.push(command)
      if (command === listingCommand) return { code: 0, stderr: "", stdout: listing }
      if (command !== crossCheckCommand) throw new Error(`unexpected exec: ${command}`)
      const stdout = (options?.input ?? "")
        .split("\u0000")
        .filter((entry) => entry !== "")
        .map((entry) => `${entry.slice(0, entry.indexOf("//"))}\u0000${verdict}\u00000\u0000`)
        .join("")
      return { code: 0, stderr: "", stdout }
    },
  } as unknown as SshConnection
  return { commands, conn }
}

describe("runSymlinkContainmentBackstop recorded links (Issue #219)", () => {
  it("runs no exec for an archive without symlinks when nothing is recorded", async () => {
    const { commands, conn } = backstopConnection("")

    await expect(
      runSymlinkContainmentBackstop(conn, { destination, members: [fileMember("f")], source })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })
    expect(commands).toStrictEqual([])
  })

  it("passes a recorded link the listing no longer reports with the listing alone", async () => {
    const { commands, conn } = backstopConnection("")

    await expect(
      runSymlinkContainmentBackstop(conn, {
        destination,
        members: [fileMember("f")],
        recordedLinks: ["a/esc"],
        source,
      })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })
    expect(commands).toStrictEqual([listingCommand])
  })

  it("confirms a recorded link now inside with the kernel cross-check", async () => {
    const { commands, conn } = backstopConnection("l\u0000a/esc\u0000f\u0000")

    await expect(
      runSymlinkContainmentBackstop(conn, {
        destination,
        members: [fileMember("f")],
        recordedLinks: ["a/esc"],
        source,
      })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })
    expect(commands).toStrictEqual([listingCommand, crossCheckCommand])
  })

  it("does not judge unrelated links for an archive without symlinks", async () => {
    // Issue #219: `b/esc` escapes but was never recorded; an archive without
    // symlink members cannot change where it resolves.
    const { conn } = backstopConnection("l\u0000b/esc\u0000../..\u0000")

    await expect(
      runSymlinkContainmentBackstop(conn, {
        destination,
        members: [fileMember("b/f")],
        recordedLinks: ["a/esc"],
        source,
      })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })
  })

  it("names a recorded link that still escapes and reports its key", async () => {
    const { conn } = backstopConnection("l\u0000a/esc\u0000../..\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      members: [fileMember("b/f")],
      recordedLinks: ["a/esc"],
      source,
    })

    expect(outcome.offendingLinks).toStrictEqual(["a/esc"])
    expect(outcome.failure?.error?.message).toContain(
      `[archive.extract] refusing to complete extraction of ${source}: symlink "/opt/app/a/esc" -> "../..", recorded by an earlier failed apply, resolves outside destination "/opt/app"`
    )
  })

  it("reports a recorded link below an unreadable directory as unverifiable, not as gone", async () => {
    const { conn } = backstopConnection("u\u0000a\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      members: [fileMember("b/f")],
      recordedLinks: ["a/esc"],
      source,
    })

    expect(outcome.offendingLinks).toStrictEqual(["a/esc"])
    expect(outcome.failure?.error?.message).toContain(
      'symlink "/opt/app/a/esc", recorded by an earlier failed apply, cannot be checked: directory "/opt/app/a" is not readable'
    )
  })

  it("identifies no links when an archive member lies below an unreadable directory", async () => {
    const { conn } = backstopConnection("u\u0000locked\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      members: [symlinkMember("a/l", "f"), fileMember("locked/f")],
      source,
    })

    expect(outcome.failure?.status).toBe("failed")
    expect(outcome.offendingLinks).toBe("unidentified")
  })

  it("identifies no links when the listing cannot be trusted", async () => {
    const { conn } = backstopConnection("x\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      members: [fileMember("f")],
      recordedLinks: ["a/esc"],
      source,
    })

    expect(outcome.failure?.error?.message).toContain("symlink containment check failed")
    expect(outcome.offendingLinks).toBe("unidentified")
  })
})

/**
 * Issue #219: a connection whose flag read answers with a fixed result and
 * whose `writeFile` records every write.
 *
 * @param read - The flag read's result.
 * @returns The connection and the bodies written, by path.
 */
function flagConnection(read: Partial<ExecResult>): {
  conn: SshConnection
  writes: Array<[string, string]>
} {
  const writes: Array<[string, string]> = []
  const conn = {
    async exec(): Promise<ExecResult> {
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "", ...read }
    },
    async writeFile(path: string, content: string): Promise<void> {
      await Promise.resolve()
      writes.push([path, content])
    },
  } as unknown as SshConnection
  return { conn, writes }
}

describe("establishContainmentFlag (Issue #219)", () => {
  const paths = { directory: "/var/lib/paratix/flags", flag, source }

  it.each([
    { name: "the fixed text of older versions", stdout: "present\narchive apply in progress\n" },
    { name: "an empty flag", stdout: "present\n" },
    {
      name: "an in-progress body",
      stdout: `present\n${containmentFlagBody({ links: ["a/esc"], state: "in-progress" })}`,
    },
    {
      name: "an unknown record",
      stdout: `present\n${containmentFlagBody({ reason: TOO_MANY_OFFENDING_LINKS, state: "unknown" })}`,
    },
  ])(
    "runs the apply after $name and asks for a destination-wide verification",
    async ({ stdout }) => {
      const { conn, writes } = flagConnection({ stdout })

      await expect(establishContainmentFlag(conn, paths)).resolves.toStrictEqual({
        carried: [],
        verifyWholeDestination: true,
      })
      expect(writes).toStrictEqual([
        [flag, containmentFlagBody({ links: [], state: "in-progress" })],
      ])
    }
  )

  it("carries a recorded list without a destination-wide verification", async () => {
    const { conn, writes } = flagConnection({
      stdout: `present\n${containmentFlagBody({ links: ["a/esc"], state: "failed" })}`,
    })

    await expect(establishContainmentFlag(conn, paths)).resolves.toStrictEqual({
      carried: ["a/esc"],
      verifyWholeDestination: false,
    })
    expect(writes).toStrictEqual([
      [flag, containmentFlagBody({ links: ["a/esc"], state: "in-progress" })],
    ])
  })

  it("still refuses a symlink at the flag path and writes nothing", async () => {
    const { conn, writes } = flagConnection({ code: 3 })

    const outcome = await establishContainmentFlag(conn, paths)

    expect(outcome).toMatchObject({ status: "failed" })
    expect(writes).toStrictEqual([])
  })
})

describe("recordWithoutVerification (Issue #219)", () => {
  it("keeps the carried links when the replaced flag recorded them", () => {
    expect(
      recordWithoutVerification({ carried: ["a/esc"], verifyWholeDestination: false })
    ).toStrictEqual({ links: ["a/esc"], state: "failed" })
  })

  it("stays unknown, never an empty failed record, when the replaced flag held no usable list", () => {
    const record = recordWithoutVerification({ carried: [], verifyWholeDestination: true })

    expect(record).toStrictEqual({ reason: UNVERIFIED_DESTINATION, state: "unknown" })
    expect(parseContainmentFlag(containmentFlagBody(record)).kind).toBe("unknown")
  })
})

describe("runSymlinkContainmentBackstop destination-wide verification (Issue #219)", () => {
  const whole = { destination, source, verifyWholeDestination: true } as const

  it("runs the listing alone for an archive without symlinks on a destination without links", async () => {
    const { commands, conn } = backstopConnection("")

    await expect(
      runSymlinkContainmentBackstop(conn, { ...whole, members: [fileMember("f")] })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })
    expect(commands).toStrictEqual([listingCommand])
  })

  it("judges an escaping link the archive cannot affect and says the whole destination was checked", async () => {
    // Issue #219: the same link passes the archive-scoped backstop, see
    // "does not judge unrelated links for an archive without symlinks".
    const { conn } = backstopConnection("l\u0000b/esc\u0000../..\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...whole,
      members: [fileMember("a/f")],
    })

    expect(outcome.offendingLinks).toStrictEqual(["b/esc"])
    expect(outcome.failure?.error?.message).toContain(
      'symlink "/opt/app/b/esc" -> "../.." resolves outside destination "/opt/app"; after the merge, every symlink under the destination is checked'
    )
  })

  it("carries every link judged inside, unrelated ones included, in one cross-check", async () => {
    const execs: Array<{ command: string; input: string | undefined }> = []
    const { conn: inner } = backstopConnection(
      "l\u0000a/l\u0000f\u0000l\u0000x/in\u0000f\u0000l\u0000y/in\u0000../a/f\u0000"
    )
    const conn = {
      async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
        execs.push({ command, input: options?.input })
        return inner.exec(command, options)
      },
    } as unknown as SshConnection

    await expect(
      runSymlinkContainmentBackstop(conn, { ...whole, members: [symlinkMember("a/l", "f")] })
    ).resolves.toStrictEqual({ failure: null, offendingLinks: [] })

    expect(execs.map(({ command }) => command)).toStrictEqual([listingCommand, crossCheckCommand])
    const carried = String(execs[1]?.input)
    for (const link of ["/opt/app/a/l", "/opt/app/x/in", "/opt/app/y/in"]) {
      expect(carried).toContain(link)
    }
  })

  it("identifies no links when any directory is unreadable, even with no member below it", async () => {
    const { conn } = backstopConnection("u\u0000locked\u0000l\u0000b/esc\u0000../..\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...whole,
      members: [fileMember("a/f")],
    })

    expect(outcome.offendingLinks).toBe("unidentified")
    expect(outcome.failure?.error?.message).toContain(
      'directory "/opt/app/locked" is not readable, so the symlinks below it cannot be checked'
    )
  })

  it("reports the offending links in listing order, kernel mismatches included", async () => {
    // Issue #219: the kernel disagrees about `m/in`, which the listing reports
    // between two escaping links; the resolver finds those first.
    const listing =
      "l\u0000z/esc\u0000../..\u0000l\u0000m/in\u0000f\u0000l\u0000a/esc\u0000/etc\u0000"
    const { conn } = backstopConnection(listing, "differ")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...whole,
      members: [fileMember("f")],
    })

    expect(outcome.offendingLinks).toStrictEqual(["z/esc", "m/in", "a/esc"])
  })

  it("identifies no links when the listing cannot be trusted", async () => {
    const { conn } = backstopConnection("x\u0000")

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...whole,
      members: [fileMember("f")],
    })

    expect(outcome.failure?.error?.message).toContain("symlink containment check failed")
    expect(outcome.offendingLinks).toBe("unidentified")
  })
})
