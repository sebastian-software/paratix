import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { runSymlinkContainmentBackstop } from "../../src/modules/archiveContainmentBackstop.js"
import {
  CONTAINMENT_FLAG_BODY_LIMIT_BYTES,
  CONTAINMENT_FLAG_LINK_LIMIT,
  containmentFlagBody,
  parseContainmentFlag,
  readContainmentFlag,
  TOO_MANY_OFFENDING_LINKS,
  unknownContainmentStateRefusal,
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

  it("names the destination, the flag and the manual steps in the refusal", () => {
    expect(
      unknownContainmentStateRefusal({ destination, flag, source, why: "holds nothing usable" })
    ).toBe(
      `[archive.extract] refusing to extract ${source}: the symlink containment state of ${destination} is unknown: containment flag ${flag} holds nothing usable; check the symlinks under ${destination} manually, remove any that resolve outside it or point them inside, then remove the flag with rm -f -- '${flag}' and run the apply again`
    )
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
 * records and confirms every link the kernel cross-check carries.
 *
 * @param listing - The listing's NUL-framed records.
 * @returns The connection and the commands it ran.
 */
function backstopConnection(listing: string): { commands: string[]; conn: SshConnection } {
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
        .map((entry) => `${entry.slice(0, entry.indexOf("//"))}\u0000same\u00000\u0000`)
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
