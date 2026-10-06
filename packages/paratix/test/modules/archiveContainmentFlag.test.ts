import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { runSymlinkContainmentBackstop } from "../../src/modules/archiveContainmentBackstop.js"
import {
  buildContainmentCheckScript,
  buildContainmentClearScript,
  clearContainmentEntries,
  noContainmentEntriesCommand,
  recordContainmentFailure,
} from "../../src/modules/archiveContainmentEntries.js"
import {
  buildContainmentEstablishCommand,
  buildContainmentEstablishScript,
  CONTAINMENT_ENTRY_READ_LIMIT,
  CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES,
  containmentEstablishFailure,
  establishContainmentEntry,
  parseContainmentEstablishOutput,
} from "../../src/modules/archiveContainmentEstablish.js"
import {
  CONTAINMENT_FLAG_BODY_LIMIT_BYTES,
  CONTAINMENT_FLAG_LINK_LIMIT,
  containmentFlagBody,
  type ContainmentPaths,
  parseContainmentEntryBytes,
  parseContainmentFlag,
  TOO_MANY_OFFENDING_LINKS,
} from "../../src/modules/archiveContainmentFlag.js"
import {
  archiveContainmentScope,
  CONTAINMENT_SCOPE_DIGEST_ALGORITHM,
  containmentScopeDigest,
} from "../../src/modules/archiveContainmentScope.js"
import { buildKernelCrossCheckScript } from "../../src/modules/archiveKernelCrossCheck.js"
import { buildSymlinkListingProbeScript } from "../../src/modules/archiveProbe.js"
import { shellQuote } from "../../src/ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../../src/sshHelpers.js"

const destination = "/opt/app"
const source = "/tmp/app.tar.gz"
const flagBase = "/var/lib/paratix/flags/archive-containment-0123"
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
      parseContainmentFlag(body({ links: ["a/esc"], state: "in-progress", version: 1 }))
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
 * @returns The connection, its recorded execs and its recorded writes.
 */
function singleExecConnection(answer: Error | Partial<ExecResult>): {
  conn: SshConnection
  execs: Array<{ command: string; options: ExecOptions | undefined }>
  writes: Array<[string, string, unknown]>
} {
  const execs: Array<{ command: string; options: ExecOptions | undefined }> = []
  const writes: Array<[string, string, unknown]> = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      execs.push({ command, options })
      if (answer instanceof Error) throw answer
      return { code: 0, stderr: "", stdout: "", ...answer }
    },
    async writeFile(path: string, content: string, options: unknown): Promise<void> {
      await Promise.resolve()
      writes.push([path, content, options])
    },
  } as unknown as SshConnection
  return { conn, execs, writes }
}

const paths: ContainmentPaths = {
  directory: "/var/lib/paratix/flags",
  entryDirectory: `${flagBase}.d`,
  legacyFlag: `${flagBase}.failed`,
}
const ownName = `run-${"1".repeat(32)}`
const ownEntry = `${paths.entryDirectory}/${ownName}`
const otherName = `run-${"a".repeat(32)}`
const otherEntry = `${paths.entryDirectory}/${otherName}`
const hashA = "a".repeat(64)
const hashB = "b".repeat(64)
/** Issue #227: the scope digest of the apply under test. */
const scopeDigest = "c".repeat(64)

/**
 * Issue #219: one read line of the establish output.
 *
 * @param label - `entry <name>` or `legacy`.
 * @param sha256 - The printed hash.
 * @param content - The body, printed as hex.
 * @returns The line with its newline.
 */
function readLine(label: string, sha256: string, content: Buffer | string): string {
  return `${label} ${sha256} ${Buffer.from(content).toString("hex")}\n`
}

describe("parseContainmentEntryBytes (Issue #219)", () => {
  it("reads a recorded list", () => {
    expect(
      parseContainmentEntryBytes(
        Buffer.from(containmentFlagBody({ links: ["a/l"], state: "failed" }))
      )
    ).toStrictEqual({ kind: "recorded", links: ["a/l"] })
  })

  it("reads bytes that are not valid UTF-8 as unknown", () => {
    expect(parseContainmentEntryBytes(Buffer.from([0x7b, 0xff, 0x7d]))).toStrictEqual({
      kind: "unknown",
      why: expect.stringContaining("is not valid UTF-8"),
    })
  })

  it("reads one byte past the limit as unknown", () => {
    expect(
      parseContainmentEntryBytes(Buffer.alloc(CONTAINMENT_FLAG_BODY_LIMIT_BYTES + 1, 0x20))
    ).toStrictEqual({
      kind: "unknown",
      why: expect.stringContaining(
        `is larger than ${String(CONTAINMENT_FLAG_BODY_LIMIT_BYTES)} bytes`
      ),
    })
  })
})

describe("parseContainmentEstablishOutput (Issue #219)", () => {
  const inputs = { ...paths, ownEntry, scopeDigest }

  it("reads an empty entry directory as nothing to verify or remove", () => {
    expect(parseContainmentEstablishOutput("done\n", inputs)).toStrictEqual({
      carried: [],
      ownEntry,
      removable: [],
      verifyWholeDestination: false,
    })
  })

  it("carries the deduplicated links of recorded entries and makes every entry removable", () => {
    const stdout = [
      readLine(
        `entry ${otherName}`,
        hashA,
        containmentFlagBody({ links: ["a/l", "b/l"], state: "failed" })
      ),
      readLine("entry run-b", hashB, containmentFlagBody({ links: ["b/l"], state: "failed" })),
      "done\n",
    ].join("")

    expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
      carried: ["a/l", "b/l"],
      ownEntry,
      removable: [
        { path: otherEntry, sha256: hashA },
        { path: `${paths.entryDirectory}/run-b`, sha256: hashB },
      ],
      verifyWholeDestination: false,
    })
  })

  it.each([
    {
      name: "an in-progress entry of version 1",
      stdout: readLine(
        `entry ${otherName}`,
        hashA,
        body({ links: [], state: "in-progress", version: 1 })
      ),
    },
    { name: "an empty entry", stdout: readLine(`entry ${otherName}`, hashA, "") },
    {
      name: "an entry that is not valid UTF-8",
      stdout: readLine(`entry ${otherName}`, hashA, Buffer.from([0xff])),
    },
  ])("verifies the whole destination after $name and still lets it be removed", ({ stdout }) => {
    expect(parseContainmentEstablishOutput(`${stdout}done\n`, inputs)).toStrictEqual({
      carried: [],
      ownEntry,
      removable: [{ path: otherEntry, sha256: hashA }],
      verifyWholeDestination: true,
    })
  })

  it("verifies the whole destination for the old flag file, whatever it records, and claims it", () => {
    const stdout = `${readLine("legacy", hashA, containmentFlagBody({ links: ["a/l"], state: "failed" }))}done\n`

    expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
      carried: ["a/l"],
      ownEntry,
      removable: [{ path: paths.legacyFlag, sha256: hashA }],
      verifyWholeDestination: true,
    })
  })

  it("verifies the whole destination when there are more entries than it read", () => {
    expect(parseContainmentEstablishOutput("more\ndone\n", inputs)).toMatchObject({
      removable: [],
      verifyWholeDestination: true,
    })
  })

  it("verifies the whole destination and removes nothing else for a truncated capture", () => {
    const stdout = `entry ${otherName} ${hashA} 7b${CAPTURE_TRUNCATION_MARKER}`

    expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
      carried: [],
      ownEntry,
      removable: [],
      verifyWholeDestination: true,
    })
  })

  it.each([
    { name: "no output", stdout: "" },
    { name: "a missing done line", stdout: readLine(`entry ${otherName}`, hashA, "") },
    { name: "a line after done", stdout: "done\nmore\n" },
    { name: "a done line without its newline", stdout: "done" },
    { name: "an unknown line", stdout: "present\ndone\n" },
    { name: "a short hash", stdout: `entry ${otherName} abc 7b\ndone\n` },
    { name: "an odd hex body", stdout: `entry ${otherName} ${hashA} 7\ndone\n` },
    { name: "an upper-case hex body", stdout: `entry ${otherName} ${hashA} 7B\ndone\n` },
    { name: "a name outside the run charset", stdout: `entry run-a.b ${hashA} 7b\ndone\n` },
    { name: "a name without the run prefix", stdout: `entry x-a ${hashA} 7b\ndone\n` },
    { name: "a missing field", stdout: `entry ${otherName} ${hashA}\ndone\n` },
    { name: "the own entry", stdout: `entry ${ownName} ${hashA} 7b\ndone\n` },
  ])("cannot trust $name", ({ stdout }) => {
    expect(parseContainmentEstablishOutput(stdout, inputs)).toBeNull()
  })
})

/**
 * Issue #227: an archive of many members, a directory, a file and a symlink
 * each, so its scope holds thousands of keys.
 *
 * @param count - How many directories the archive ships.
 * @returns The archive members.
 */
function manyMembers(count: number): ArchiveMember[] {
  return Array.from({ length: count }, (_value, index) => [
    { ...fileMember(`d${String(index)}/`), kind: "directory" as const, mode: "drwxr-xr-x" },
    fileMember(`d${String(index)}/f`),
    symlinkMember(`d${String(index)}/l`, "f"),
  ]).flat()
}

/**
 * Issue #227: the digest encoding of `containmentScopeDigest`, rebuilt here
 * so a changed algorithm ID, Unicode version or set separation is caught.
 *
 * @param scope - The scope's key sets.
 * @param scope.archiveLinks - The archive link keys.
 * @param scope.written - The written keys.
 * @param prefix - The algorithm ID and Unicode version the encoding starts with.
 * @returns The lowercase hex SHA-256 of the encoding.
 */
function digestOfEncoding(
  scope: { archiveLinks: readonly string[]; written: readonly string[] },
  prefix: readonly [string, string | undefined]
): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        ...prefix,
        sortedByCodeUnit(scope.archiveLinks),
        sortedByCodeUnit(scope.written),
      ]),
      "utf8"
    )
    .digest("hex")
}

/**
 * Issue #227: sort keys by UTF-16 code unit, independent of the locale.
 *
 * @param keys - Scope keys in any order.
 * @returns A sorted copy.
 */
function sortedByCodeUnit(keys: readonly string[]): string[] {
  return [...keys].toSorted((left, right) => {
    if (left === right) return 0
    return left < right ? -1 : 1
  })
}

describe("containmentScopeDigest (Issue #227)", () => {
  const members = [
    { ...fileMember("a/"), kind: "directory" as const, mode: "drwxr-xr-x" },
    fileMember("a/f"),
    symlinkMember("a/l", "f"),
  ]

  it("is 64 lowercase hex digits", () => {
    expect(containmentScopeDigest(archiveContainmentScope(members))).toMatch(/^[\da-f]{64}$/v)
  })

  it("hashes the algorithm ID, the Unicode version and both sorted key sets", () => {
    const scope = { archiveLinks: ["a/l"], written: ["a/l", "a", "a/f"] }
    const digest = containmentScopeDigest({
      archiveLinks: new Set(scope.archiveLinks),
      written: new Set(scope.written),
    })

    expect(CONTAINMENT_SCOPE_DIGEST_ALGORITHM).toBe("paratix-archive-containment-scope/1")
    expect(digest).toBe(
      digestOfEncoding(scope, [CONTAINMENT_SCOPE_DIGEST_ALGORITHM, process.versions.unicode])
    )
    // Issue #227: a digest derived by another algorithm or under other
    // Unicode tables never matches.
    expect(digest).not.toBe(
      digestOfEncoding(scope, ["paratix-archive-containment-scope/2", process.versions.unicode])
    )
    expect(digest).not.toBe(digestOfEncoding(scope, [CONTAINMENT_SCOPE_DIGEST_ALGORITHM, "0.0"]))
  })

  it("is deterministic and independent of the member order", () => {
    const digest = containmentScopeDigest(archiveContainmentScope(members))

    expect(containmentScopeDigest(archiveContainmentScope(members))).toBe(digest)
    expect(containmentScopeDigest(archiveContainmentScope(members.toReversed()))).toBe(digest)
    expect(
      containmentScopeDigest({
        archiveLinks: new Set(["a/l"]),
        written: new Set(["a", "a/f", "a/l"].toReversed()),
      })
    ).toBe(digest)
  })

  it("changes when a key moves from the archive links to the written paths", () => {
    // Issue #227: the union of both sets stays the same; only the separate
    // encoding of the two sets tells them apart.
    expect(
      containmentScopeDigest({ archiveLinks: new Set(["x"]), written: new Set(["y"]) })
    ).not.toBe(containmentScopeDigest({ archiveLinks: new Set(), written: new Set(["x", "y"]) }))
  })

  it.each([
    { changed: [fileMember("a/f"), fileMember("a/l")], name: "a symlink becomes a file" },
    { changed: [...members, fileMember("a/g")], name: "a member is added" },
    { changed: members.slice(0, 2), name: "a member is removed" },
    {
      changed: [members[0], fileMember("a/f"), symlinkMember("b/l", "f")],
      name: "a member moves",
    },
  ])("changes when $name", ({ changed }) => {
    expect(containmentScopeDigest(archiveContainmentScope(changed))).not.toBe(
      containmentScopeDigest(archiveContainmentScope(members))
    )
  })

  // Issue #227: a golden vector. Any change to how the scope keys are derived
  // or encoded changes this digest, which forces a decision about
  // CONTAINMENT_SCOPE_DIGEST_ALGORITHM. The digest includes the Unicode
  // version; the value was derived under Unicode 17.0 (Node.js 24).
  const goldenUnicode = "17.0"
  const goldenDigest = "7ecd1e83b4ed928d89695f3c8d2dc78ef7094b9f95246d94a3c5eb42a466161e"
  const goldenMembers = [
    { ...fileMember("app/"), kind: "directory" as const, mode: "drwxr-xr-x" },
    fileMember("app/bin/tool"),
    symlinkMember("app/current", "bin"),
    fileMember("app/Straße.txt"),
    symlinkMember("app/STRASSE/\u1E9E", "../Straße.txt"),
  ]
  const goldenArchiveLinks = ["app/current", "app/strasse/ss"]
  const goldenWritten = [
    "app",
    "app/bin",
    "app/bin/tool",
    "app/current",
    "app/strasse",
    "app/strasse.txt",
    "app/strasse/ss",
  ]

  it("derives the golden vector's scope keys, folding name variants", () => {
    expect(archiveContainmentScope(goldenMembers)).toStrictEqual({
      archiveLinks: new Set(goldenArchiveLinks),
      written: new Set(goldenWritten),
    })
  })

  it.runIf(process.versions.unicode === goldenUnicode)(
    "pins the digest of the golden vector under Unicode 17.0",
    () => {
      expect(containmentScopeDigest(archiveContainmentScope(goldenMembers))).toBe(goldenDigest)
    }
  )

  it.skipIf(process.versions.unicode === goldenUnicode)(
    "derives the golden vector's digest from its encoding under another Unicode version",
    () => {
      expect(containmentScopeDigest(archiveContainmentScope(goldenMembers))).toBe(
        digestOfEncoding({ archiveLinks: goldenArchiveLinks, written: goldenWritten }, [
          CONTAINMENT_SCOPE_DIGEST_ALGORITHM,
          process.versions.unicode,
        ])
      )
    }
  )

  it("ignores symlink targets, which the scope does not hold", () => {
    expect(
      containmentScopeDigest(
        archiveContainmentScope([members[0], fileMember("a/f"), symlinkMember("a/l", "../a/f")])
      )
    ).toBe(containmentScopeDigest(archiveContainmentScope(members)))
  })
})

describe("containment flag body with a scope digest (Issue #227)", () => {
  const digest = "0123456789abcdef".repeat(4)

  it.each(["in-progress", "stopped"] as const)(
    "serializes and parses a version 2 %s body with its scope digest",
    (state) => {
      const text = containmentFlagBody({ scope: digest, state })

      expect(text).toBe(`{"scope":"${digest}","state":"${state}","version":2}\n`)
      expect(parseContainmentFlag(text)).toStrictEqual({ kind: "scoped", scope: digest })
    }
  )

  it.each(["in-progress", "stopped"] as const)(
    "keeps the %s body at a fixed size whatever the member count",
    (state) => {
      const one = containmentScopeDigest(archiveContainmentScope([fileMember("f")]))
      const many = containmentScopeDigest(archiveContainmentScope(manyMembers(5000)))
      expect(archiveContainmentScope(manyMembers(5000)).written.size).toBe(15_000)
      const oneBody = containmentFlagBody({ scope: one, state })
      const manyBody = containmentFlagBody({ scope: many, state })

      expect(one).not.toBe(many)
      expect(Buffer.byteLength(manyBody)).toBe(Buffer.byteLength(oneBody))
      expect(Buffer.byteLength(manyBody)).toBeLessThan(128)
      expect(Buffer.byteLength(manyBody)).toBeLessThan(CONTAINMENT_FLAG_BODY_LIMIT_BYTES / 256)
    }
  )

  it.each([
    {
      name: "a digest of 63 hex digits",
      text: body({ scope: digest.slice(1), state: "in-progress", version: 2 }),
    },
    {
      name: "a digest of 65 hex digits",
      text: body({ scope: `${digest}0`, state: "in-progress", version: 2 }),
    },
    {
      name: "an upper-case digest",
      text: body({ scope: digest.toUpperCase(), state: "in-progress", version: 2 }),
    },
    {
      name: "a digest that is not hex",
      text: body({ scope: `${digest.slice(1)}g`, state: "stopped", version: 2 }),
    },
    { name: "an empty digest", text: body({ scope: "", state: "in-progress", version: 2 }) },
    { name: "a numeric digest", text: body({ scope: 1, state: "in-progress", version: 2 }) },
    { name: "a null digest", text: body({ scope: null, state: "stopped", version: 2 }) },
    { name: "a digest list", text: body({ scope: [digest], state: "in-progress", version: 2 }) },
    { name: "a failed state", text: body({ scope: digest, state: "failed", version: 2 }) },
    { name: "an unknown state", text: body({ scope: digest, state: "unknown", version: 2 }) },
    { name: "another state", text: body({ scope: digest, state: "done", version: 2 }) },
    {
      name: "an extra key",
      text: body({ extra: true, scope: digest, state: "in-progress", version: 2 }),
    },
    { name: "a missing scope key", text: body({ state: "in-progress", version: 2 }) },
    { name: "a missing state key", text: body({ links: [], scope: digest, version: 2 }) },
    {
      name: "links instead of a scope",
      text: body({ links: [], state: "in-progress", version: 2 }),
    },
    { name: "a string version", text: body({ scope: digest, state: "in-progress", version: "2" }) },
    {
      name: "a scope in a version 1 body",
      text: body({ scope: digest, state: "in-progress", version: 1 }),
    },
    {
      name: "a scope in a version 3 body",
      text: body({ scope: digest, state: "in-progress", version: 3 }),
    },
    {
      name: "a truncated body",
      text: containmentFlagBody({ scope: digest, state: "in-progress" }).slice(0, -10),
    },
  ])("holds no usable list with $name", ({ text }) => {
    expect(parseContainmentFlag(text)).toStrictEqual({
      kind: "unknown",
      why: "holds no usable list of offending links (it was written by an older paratix version or is damaged)",
    })
  })

  it("still reads a version 1 in-progress body without links as an apply that did not finish", () => {
    expect(
      parseContainmentFlag(body({ links: [], state: "in-progress", version: 1 }))
    ).toStrictEqual({
      kind: "unknown",
      why: "records an apply that did not finish (it stopped after it started, possibly after its merge had begun, or another apply to this destination is still running)",
    })
  })
})

describe("parseContainmentEstablishOutput with scope digests (Issue #227)", () => {
  const inputs = { ...paths, ownEntry, scopeDigest }
  const otherDigest = "d".repeat(64)
  const secondName = `run-${"b".repeat(32)}`
  const secondEntry = `${paths.entryDirectory}/${secondName}`
  const otherLabel = `entry ${otherName}`

  it.each(["in-progress", "stopped"] as const)(
    "lets a %s entry with this apply's digest be removed without a destination-wide verification",
    (state) => {
      const stdout = `${readLine(otherLabel, hashA, containmentFlagBody({ scope: scopeDigest, state }))}done\n`

      expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
        carried: [],
        ownEntry,
        removable: [{ path: otherEntry, sha256: hashA }],
        verifyWholeDestination: false,
      })
    }
  )

  it.each(["in-progress", "stopped"] as const)(
    "verifies the whole destination after a %s entry with another digest and still lets it be removed",
    (state) => {
      const stdout = `${readLine(otherLabel, hashA, containmentFlagBody({ scope: otherDigest, state }))}done\n`

      expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
        carried: [],
        ownEntry,
        removable: [{ path: otherEntry, sha256: hashA }],
        verifyWholeDestination: true,
      })
    }
  )

  it("verifies the whole destination when one entry matches and another does not, and lets both be removed", () => {
    const stdout = [
      readLine(
        `entry ${otherName}`,
        hashA,
        containmentFlagBody({ scope: scopeDigest, state: "in-progress" })
      ),
      readLine(
        `entry ${secondName}`,
        hashB,
        containmentFlagBody({ scope: otherDigest, state: "stopped" })
      ),
      "done\n",
    ].join("")

    expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
      carried: [],
      ownEntry,
      removable: [
        { path: otherEntry, sha256: hashA },
        { path: secondEntry, sha256: hashB },
      ],
      verifyWholeDestination: true,
    })
  })

  it("carries the links of a recorded entry next to a matching scoped entry", () => {
    const stdout = [
      readLine(
        `entry ${otherName}`,
        hashA,
        containmentFlagBody({ scope: scopeDigest, state: "stopped" })
      ),
      readLine(
        `entry ${secondName}`,
        hashB,
        containmentFlagBody({ links: ["x/esc"], state: "failed" })
      ),
      "done\n",
    ].join("")

    expect(parseContainmentEstablishOutput(stdout, inputs)).toStrictEqual({
      carried: ["x/esc"],
      ownEntry,
      removable: [
        { path: otherEntry, sha256: hashA },
        { path: secondEntry, sha256: hashB },
      ],
      verifyWholeDestination: false,
    })
  })

  it("verifies the whole destination for the old flag file even when it records this apply's digest", () => {
    const stdout = `${readLine("legacy", hashA, containmentFlagBody({ scope: scopeDigest, state: "in-progress" }))}done\n`

    expect(parseContainmentEstablishOutput(stdout, inputs)).toMatchObject({
      removable: [{ path: paths.legacyFlag, sha256: hashA }],
      verifyWholeDestination: true,
    })
  })

  it("verifies the whole destination after a matching entry when there are more entries than it read", () => {
    const stdout = `${readLine(otherLabel, hashA, containmentFlagBody({ scope: scopeDigest, state: "in-progress" }))}more\ndone\n`

    expect(parseContainmentEstablishOutput(stdout, inputs)).toMatchObject({
      removable: [{ path: otherEntry, sha256: hashA }],
      verifyWholeDestination: true,
    })
  })

  it("passes the version 2 in-progress body with this apply's digest to the establish exec", () => {
    const expectedBody = `{"scope":"${scopeDigest}","state":"in-progress","version":2}\n`
    const command = buildContainmentEstablishCommand(inputs)

    expect(command.endsWith(` ${shellQuote(expectedBody)}`)).toBe(true)
  })
})

describe("containmentEstablishFailure (Issue #219)", () => {
  it.each([
    {
      code: 2,
      expected: `failed to create archive marker directory for containment entries ${paths.entryDirectory}: mkdir: denied`,
      stderr: "mkdir: denied\n",
    },
    { code: 3, expected: `containment-failure flag ${paths.legacyFlag} is a symlink; remove it` },
    {
      code: 4,
      expected: `containment-failure flag ${paths.legacyFlag} exists but is not a regular file; remove it`,
    },
    {
      code: 5,
      expected: `containment entry directory ${paths.entryDirectory} is a symlink; remove it`,
    },
    {
      code: 8,
      expected: `containment entry ${otherEntry} is a symlink; remove it`,
      stderr: `${otherName}\n`,
    },
    {
      code: 9,
      expected: `containment entry an entry in ${paths.entryDirectory} exists but is not a regular file; remove it`,
      stderr: "run-a/../x\n",
    },
    {
      code: 11,
      expected: `failed to read containment entry ${otherEntry}`,
      stderr: `sha256sum: Input/output error\n${otherName}\n`,
    },
    {
      code: 13,
      expected: `failed to create containment entry in ${paths.entryDirectory}: exit code 13`,
    },
    {
      code: 127,
      expected: `failed to read containment entries in ${paths.entryDirectory}: sh: sha256sum: not found`,
      stderr: "sh: sha256sum: not found",
    },
  ])("names exit code $code", ({ code, expected, stderr = "" }) => {
    expect(containmentEstablishFailure(paths, { code, stderr })).toBe(expected)
  })
})

/**
 * Issue #219: the message of an establish refusal.
 *
 * @param outcome - The establish outcome.
 * @returns The message, or an empty string for a ledger.
 */
function refusalMessage(outcome: Awaited<ReturnType<typeof establishContainmentEntry>>): string {
  return "status" in outcome ? String(outcome.error?.message) : ""
}

describe("establishContainmentEntry (Issue #219)", () => {
  const parameters = { ownEntryName: ownName, paths, scopeDigest, source }

  it("reads and creates in one explicit sh -c exec with a capture cap from the bounds", async () => {
    const { conn, execs, writes } = singleExecConnection({ stdout: "done\n" })

    await expect(establishContainmentEntry(conn, parameters)).resolves.toStrictEqual({
      carried: [],
      ownEntry,
      removable: [],
      verifyWholeDestination: false,
    })

    expect(execs).toStrictEqual([
      {
        command: buildContainmentEstablishCommand({ ...paths, ownEntry, scopeDigest }),
        options: {
          ignoreExitCode: true,
          maxOutputBytes: CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES,
          silent: true,
        },
      },
    ])
    expect(execs[0]?.command.startsWith(`sh -c '`)).toBe(true)
    expect(writes).toStrictEqual([])
    // Issue #219: every read entry fits the capture, one past the body limit
    // as hex, with room for the name, the hash and the other lines.
    expect(CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES).toBeGreaterThan(
      (CONTAINMENT_ENTRY_READ_LIMIT + 1) * 2 * (CONTAINMENT_FLAG_BODY_LIMIT_BYTES + 1)
    )
  })

  it("passes the paths, the own entry and its in-progress body as positional parameters", () => {
    const command = buildContainmentEstablishCommand({ ...paths, ownEntry, scopeDigest })

    expect(command).toBe(
      [
        "sh -c",
        shellQuote(buildContainmentEstablishScript()),
        "sh",
        `'${paths.directory}'`,
        `'${paths.legacyFlag}'`,
        `'${paths.entryDirectory}'`,
        `'${ownEntry}'`,
        shellQuote(containmentFlagBody({ scope: scopeDigest, state: "in-progress" })),
      ].join(" ")
    )
  })

  it.each([
    { answer: { code: 8, stderr: `${otherName}\n` }, reason: "is a symlink" },
    { answer: new Error("channel closed"), reason: "channel closed" },
    { answer: { stdout: "garbage\n" }, reason: "unexpected output" },
  ])("refuses before the destination is touched: $reason", async ({ answer, reason }) => {
    const { conn, writes } = singleExecConnection(answer)

    const outcome = await establishContainmentEntry(conn, parameters)

    expect(outcome).toMatchObject({ status: "failed" })
    expect(refusalMessage(outcome)).toContain(reason)
    expect(refusalMessage(outcome)).toContain(
      "; the containment entry must be in place before the destination is touched"
    )
    expect(writes).toStrictEqual([])
  })
})

describe("clearContainmentEntries (Issue #219)", () => {
  it("claims every removable entry and removes the own entry in one exec, whatever their number", async () => {
    const removable = Array.from({ length: CONTAINMENT_ENTRY_READ_LIMIT + 1 }, (_value, index) => ({
      path: `${paths.entryDirectory}/run-${String(index)}`,
      sha256: hashA,
    }))
    const { conn, execs } = singleExecConnection({})

    await expect(clearContainmentEntries(conn, { ownEntry, removable })).resolves.toBeNull()

    expect(execs).toHaveLength(1)
    expect(execs[0]?.command).toBe(
      [
        "sh -c",
        shellQuote(buildContainmentClearScript()),
        "sh",
        `'${ownEntry}'`,
        ...removable.flatMap(({ path, sha256 }) => [`'${path}'`, sha256]),
      ].join(" ")
    )
    expect(execs[0]?.options).toStrictEqual({ ignoreExitCode: true, silent: true })
  })

  it("fails with the exec's output when the clear exec fails", async () => {
    const { conn } = singleExecConnection({ code: 5, stderr: `cannot claim ${otherEntry}\n` })

    const failure = await clearContainmentEntries(conn, {
      ownEntry,
      removable: [{ path: otherEntry, sha256: hashA }],
    })

    expect(failure?.error?.message).toBe(
      `[archive.extract] failed to remove containment entry ${ownEntry} and the entries it verified (exit code 5)\ncannot claim ${otherEntry}`
    )
  })
})

describe("noContainmentEntriesCommand (Issue #219)", () => {
  it("tests the old flag file and runs the check script on the entry directory", () => {
    expect(noContainmentEntriesCommand(paths)).toBe(
      `test ! -e '${paths.legacyFlag}' && test ! -L '${paths.legacyFlag}' && sh -c ${shellQuote(buildContainmentCheckScript())} sh '${paths.entryDirectory}'`
    )
  })
})

describe("recordContainmentFailure (Issue #219)", () => {
  it("rewrites only the own entry through writeFile with the marker mode", async () => {
    const { conn, execs, writes } = singleExecConnection({})
    const failure = { error: new Error("[archive.extract] boom"), status: "failed" } as const

    await expect(
      recordContainmentFailure(conn, {
        failure,
        ownEntry,
        record: { links: ["a/l"], state: "failed" },
      })
    ).resolves.toBe(failure)

    expect(execs).toStrictEqual([])
    expect(writes).toStrictEqual([
      [ownEntry, containmentFlagBody({ links: ["a/l"], state: "failed" }), { mode: "0644" }],
    ])
  })

  it("appends a write failure without claiming the entry certainly survives", async () => {
    const conn = {
      async writeFile(): Promise<void> {
        await Promise.resolve()
        throw new Error("No space left on device")
      },
    } as unknown as SshConnection
    const failure = { error: new Error("[archive.extract] boom"), status: "failed" } as const

    const outcome = await recordContainmentFailure(conn, {
      failure,
      ownEntry,
      record: { links: [], state: "failed" },
    })

    // Issue #219: a concurrent apply may have verified the destination and
    // removed the entry meanwhile (race 1). Issue #227: an apply of the same
    // archive verifies only what that archive can affect.
    expect(outcome.error?.message).toBe(
      `[archive.extract] boom; [archive.extract] failed to write containment entry ${ownEntry}: No space left on device; the entry still marks the apply as unfinished, so the next apply verifies the whole destination, or every link this archive can affect when it extracts the same archive, unless another apply removed it after verifying the destination`
    )
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
