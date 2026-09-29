import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"

import {
  type PreMergeContainmentVerdict,
  preMergeContainmentVerdict,
  symlinkListingEntries,
} from "../../src/modules/archiveContainmentEnforcement.js"
import {
  archiveLinkUnsafeReason,
  archiveSymlinkTargetPrefixes,
  mergedArchiveSymlinks,
  type MergedSymlink,
  mergedSymlinkResolutions,
  mergedSymlinkViolations,
  type MergeHostState,
  pathNameVariantKey,
  type SymlinkWalkTarget,
} from "../../src/modules/archiveLinkValidation.js"

/**
 * Issue #219: a host link as the pre-merge listing produces it.
 *
 * @param stored - The raw stored target.
 * @param target - How the resolver walks it; a relative walk from the parent by default.
 * @returns The merged-set entry.
 */
function hostLink(
  stored: string,
  target: SymlinkWalkTarget = { anchor: "parent", path: stored }
): MergedSymlink {
  return { stored, target }
}

/**
 * Issue #219: the host state the pre-merge listing produces, without any
 * directory hits unless given.
 *
 * @param links - The host links by destination-relative path.
 * @param directories - Non-directory member paths that are host directories.
 * @returns The host state for {@link mergedArchiveSymlinks}.
 */
function hostState(
  links: ReadonlyMap<string, MergedSymlink>,
  directories: readonly string[] = []
): MergeHostState {
  return { directories: new Set(directories), links }
}

/**
 * Issue #219: merge and return the combined link set, failing the test on a
 * conflict.
 *
 * @param host - Symlinks already on the host, keyed by relative path.
 * @param members - What the archive ships, in listing order.
 * @returns The merged link set as entries.
 */
function mergedLinks(
  host: ReadonlyMap<string, MergedSymlink>,
  members: readonly ArchiveMember[]
): Array<[string, MergedSymlink]> {
  const merged = mergedArchiveSymlinks(hostState(host), members)
  if (merged.kind !== "merged") throw new Error(`unexpected merge conflict at ${merged.key}`)
  return [...merged.links]
}

function member(path: string, kind: ArchiveMember["kind"], linkTarget: null | string = null) {
  const modes: Record<ArchiveMember["kind"], string> = {
    directory: "drwxr-xr-x",
    file: "-rw-r--r--",
    hardlink: "hrw-r--r--",
    special: "prw-r--r--",
    symlink: "lrwxrwxrwx",
  }
  return { format: "tar", kind, linkTarget, mode: modes[kind], path } satisfies ArchiveMember
}

/**
 * Issue #219: the combined link set of an `ok` verdict.
 *
 * @param verdict - The verdict, which must be `ok`.
 * @returns The combined link set.
 * @throws {Error} When the verdict is not `ok`.
 */
function okLinks(verdict: PreMergeContainmentVerdict): ReadonlyMap<string, MergedSymlink> {
  if (verdict.kind !== "ok") throw new Error(`unexpected verdict ${JSON.stringify(verdict)}`)
  return verdict.links
}

/**
 * Issue #219: a hex-encoded listing field, as the listing probe emits it for
 * a name outside printable ASCII.
 *
 * @param parts - Text (as UTF-8) and single raw bytes, concatenated.
 * @returns The marker byte 0x01 followed by the hex of the bytes.
 */
function hexField(...parts: Array<number | string>): string {
  const bytes = parts.map((part) =>
    typeof part === "number" ? Buffer.from([part]) : Buffer.from(part, "utf8")
  )
  return `\u0001${Buffer.concat(bytes).toString("hex")}`
}

/**
 * Build a merged link set from relative `(path, target)` pairs, each walked
 * from its parent directory.
 *
 * @param links - The links in iteration order.
 * @returns The combined link set.
 */
function relativeLinks(
  links: ReadonlyArray<readonly [string, string]>
): Map<string, MergedSymlink> {
  return new Map(links.map(([path, target]) => [path, hostLink(target)]))
}

/**
 * A chain `l0 -> l1 -> … -> l<links-1> -> end`.
 *
 * @param links - Number of symlinks in the chain.
 * @returns The chain as a merged link set, in link order.
 */
function chain(links: number): Map<string, MergedSymlink> {
  const pairs = Array.from(
    { length: links - 1 },
    (_value, index) => [`l${String(index)}`, `l${String(index + 1)}`] as const
  )
  return relativeLinks([...pairs, [`l${String(links - 1)}`, "end"]])
}

describe("mergedArchiveSymlinks (Issue #219)", () => {
  it("replaces a host link with an archive symlink at the same path, taking the archive target", () => {
    const host = new Map([["a/up", hostLink("..")]])

    const merged = mergedLinks(host, [member("a/", "directory"), member("a/up", "symlink", "b")])

    expect(merged).toStrictEqual([["a/up", hostLink("b")]])
  })

  it("replaces a host link whose absolute target was root-anchored with a relative archive target", () => {
    const host = new Map([["l", hostLink("/opt/app/x", { anchor: "root", path: "x" })]])

    const merged = mergedLinks(host, [member("./l", "symlink", "y")])

    expect(merged).toStrictEqual([["l", hostLink("y")]])
  })

  // Issue #219: the merge guard refuses a non-symlink member at a host
  // symlink, so the model reports a conflict instead of a replacement.
  it.each([
    { kind: "file", linkTarget: null, path: "a/up" },
    { kind: "directory", linkTarget: null, path: "a/up/" },
    { kind: "hardlink", linkTarget: "f", path: "a/up" },
  ] as const)(
    "reports a conflict where the archive ships a $kind at the path of a host link",
    ({ kind, linkTarget, path }) => {
      const host = new Map([
        ["a/esc", hostLink("up/..")],
        ["a/up", hostLink("..")],
      ])
      const shipped = member(path, kind, linkTarget)

      const merged = mergedArchiveSymlinks(hostState(host), [shipped])

      expect(merged).toStrictEqual({
        key: "a/up",
        kind: "conflict",
        member: shipped,
        reason: "host-symlink",
      })
    }
  )

  it("matches archive members to host links by normalized path", () => {
    const host = new Map([["a/b/l", hostLink("..")]])

    const merged = mergedLinks(host, [member("./a//b/l", "symlink", "c")])

    expect(merged).toStrictEqual([["a/b/l", hostLink("c")]])
  })

  it("keeps host links below an archive member path and links the archive does not touch", () => {
    const host = new Map([
      ["a/deep/l", hostLink("../x")],
      ["other", hostLink("a")],
    ])

    const merged = mergedLinks(host, [
      member("a/", "directory"),
      member("a/deep/", "directory"),
      member("a/new", "symlink", "deep"),
    ])

    expect(merged).toStrictEqual([
      ["a/deep/l", hostLink("../x")],
      ["other", hostLink("a")],
      ["a/new", hostLink("deep")],
    ])
  })

  it("applies members in listing order, so a later entry for the same path wins", () => {
    const merged = mergedLinks(new Map(), [
      member("l", "symlink", "first"),
      member("l", "file"),
      member("m", "file"),
      member("m", "symlink", "second"),
    ])

    expect(merged).toStrictEqual([["m", hostLink("second")]])
  })

  it("leaves the host link map untouched", () => {
    const host = new Map([["a/up", hostLink("..")]])

    mergedArchiveSymlinks(hostState(host), [member("a/up", "symlink", "b")])

    expect([...host]).toStrictEqual([["a/up", hostLink("..")]])
  })
})

describe("mergedArchiveSymlinks conflicts (Issue #219)", () => {
  // Issue #219: `cp -aT --remove-destination` cannot replace a real directory
  // with a non-directory; it copies the rest of the top-level entry and fails,
  // so paths through the member would really run through the host directory.
  it.each([
    { kind: "file", linkTarget: null },
    { kind: "hardlink", linkTarget: "a/f" },
    { kind: "symlink", linkTarget: "q" },
  ] as const)(
    "reports a host-directory conflict for a $kind member at a host directory",
    ({ kind, linkTarget }) => {
      const shipped = member("a/b", kind, linkTarget)

      const merged = mergedArchiveSymlinks(hostState(new Map(), ["a/b"]), [
        member("a/", "directory"),
        shipped,
      ])

      expect(merged).toStrictEqual({
        key: "a/b",
        kind: "conflict",
        member: shipped,
        reason: "host-directory",
      })
    }
  )

  it("merges a directory member into a host directory and keeps the host links below it", () => {
    const host = hostState(new Map([["a/b/hl", hostLink("../..")]]), ["a/b"])

    const merged = mergedArchiveSymlinks(host, [
      member("a/", "directory"),
      member("a/b/", "directory"),
    ])

    expect(merged).toStrictEqual({
      kind: "merged",
      links: new Map([["a/b/hl", hostLink("../..")]]),
    })
  })

  it("matches a host directory to a member by normalized path", () => {
    const shipped = member("./a//b", "symlink", "q")

    const merged = mergedArchiveSymlinks(hostState(new Map(), ["a/b"]), [shipped])

    expect(merged).toMatchObject({ key: "a/b", kind: "conflict", reason: "host-directory" })
  })

  it.each([
    { kind: "file", linkTarget: null, path: "a/s/f" },
    { kind: "directory", linkTarget: null, path: "a/s/d/" },
    { kind: "hardlink", linkTarget: "a/f", path: "a/s/h" },
    { kind: "symlink", linkTarget: "x", path: "a/s/deeper/l" },
  ] as const)(
    "reports a below-host-symlink conflict keyed by the host link for a $kind at $path",
    ({ kind, linkTarget, path }) => {
      const shipped = member(path, kind, linkTarget)

      const merged = mergedArchiveSymlinks(hostState(new Map([["a/s", hostLink("../t")]])), [
        member("a/", "directory"),
        shipped,
      ])

      expect(merged).toStrictEqual({
        key: "a/s",
        kind: "conflict",
        member: shipped,
        reason: "below-host-symlink",
      })
    }
  )

  it("still merges an archive symlink over a host symlink, even with host links next to it", () => {
    const host = hostState(
      new Map([
        ["a/esc", hostLink("up/..")],
        ["a/up", hostLink("..")],
      ])
    )

    const merged = mergedArchiveSymlinks(host, [
      member("a/", "directory"),
      member("a/up", "symlink", "b"),
    ])

    expect(merged).toStrictEqual({
      kind: "merged",
      links: new Map([
        ["a/esc", hostLink("up/..")],
        ["a/up", hostLink("b")],
      ]),
    })
  })

  it("reports the first conflicting member in listing order", () => {
    const host = hostState(new Map([["s", hostLink("t")]]), ["d"])
    const overDirectory = member("d", "file")
    const belowLink = member("s/f", "file")

    expect(
      mergedArchiveSymlinks(host, [member("ok", "file"), overDirectory, belowLink])
    ).toMatchObject({ key: "d", member: overDirectory, reason: "host-directory" })
    expect(
      mergedArchiveSymlinks(host, [member("ok", "file"), belowLink, overDirectory])
    ).toMatchObject({ key: "s", member: belowLink, reason: "below-host-symlink" })
  })
})

describe("symlinkListingEntries (Issue #219)", () => {
  it("lists the destination as r entry first, then every non-directory member path as n entry", () => {
    const entries = symlinkListingEntries("/opt/app", [
      member("a/", "directory"),
      member("a/f", "file"),
      member("./a//l", "symlink", "f"),
      member("a/h", "hardlink", "a/f"),
      member("a/p", "special"),
      member("a/f", "file"),
      member("a/n:c", "file"),
    ])

    expect(entries).toStrictEqual([
      "r:/opt/app",
      "n:/opt/app/a/f",
      "n:/opt/app/a/l",
      "n:/opt/app/a/h",
      "n:/opt/app/a/n:c",
    ])
  })
})

describe("preMergeContainmentVerdict (Issue #219)", () => {
  const destination = "/opt/app"
  const members = [member("a/", "directory"), member("a/b", "symlink", "q")]

  it("reports a host-directory conflict from a directory hit for a requested member path", () => {
    const verdict = preMergeContainmentVerdict(destination, ["n", "/opt/app/a/b"], members)

    expect(verdict).toMatchObject({ key: "a/b", kind: "conflict", reason: "host-directory" })
  })

  it.each([
    {
      fields: ["n", "/opt/app/a"],
      name: "a directory hit for a path that was not requested",
      reason:
        'probe reported directory "/opt/app/a", which is not a requested member path below the destination',
    },
    {
      fields: ["n", "/opt/app/a/b/"],
      name: "a directory hit spelled differently from the request",
      reason:
        'probe reported directory "/opt/app/a/b/", which is not a requested member path below the destination',
    },
    {
      fields: ["l", "a/x"],
      name: "a link record cut off at the end",
      reason: 'probe output ends inside a "l" record',
    },
    {
      fields: ["", "/opt/app/a/b"],
      name: "a record of the former pair format",
      reason: 'probe reported unknown record kind ""',
    },
    {
      fields: ["x", "a/b"],
      name: "an unknown record kind",
      reason: 'probe reported unknown record kind "x"',
    },
    {
      fields: ["l", "/opt/app/a/x", "."],
      name: "an absolute link path",
      reason:
        'probe reported symlink "/opt/app/a/x", which is not a normalized path below the destination',
    },
    {
      fields: ["l", "a//x", "."],
      name: "a link path with an empty segment",
      reason: 'probe reported symlink "a//x", which is not a normalized path below the destination',
    },
    {
      fields: ["l", "a/../x", "."],
      name: "a link path with a .. segment",
      reason:
        'probe reported symlink "a/../x", which is not a normalized path below the destination',
    },
    {
      fields: ["l", "a/x", "t�"],
      name: "a non-ASCII field that was not hex-encoded",
      reason:
        'probe reported field "t�" with characters outside printable ASCII that were not hex-encoded',
    },
    {
      fields: ["l", "a/x", "\u0001abc"],
      name: "a hex field of odd length",
      reason: 'probe reported hex field "abc" that is not well-formed hex',
    },
    {
      fields: ["l", "a/x", "\u0001"],
      name: "an empty hex field",
      reason: 'probe reported hex field "" that is not well-formed hex',
    },
    {
      fields: ["u", "a", "u", "a"],
      name: "an unreadable directory listed twice",
      reason:
        'probe reported unreadable directory "a", which is not a normalized path below the destination or was reported more than once',
    },
  ])("is invalid for $name", ({ fields, reason }) => {
    expect(preMergeContainmentVerdict(destination, fields, members)).toStrictEqual({
      kind: "invalid",
      reason,
    })
  })

  // Issue #219: two host links whose names differ only in bytes that are not
  // UTF-8 stay two links: each is decoded to its own token, so neither can
  // hide the other, in either listing order.
  it.each([
    { name: "escaping first", targets: ["..", "."] },
    { name: "escaping last", targets: [".", ".."] },
  ])("keeps two links whose names differ only in invalid bytes apart ($name)", ({ targets }) => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", hexField("a/", 0xfe), targets[0], "l", hexField("a/", 0xff), targets[1]],
      [member("a/", "directory"), member("a/c", "symlink", "x")]
    )

    expect([...okLinks(verdict).keys()]).toStrictEqual(["a/\u0000fe", "a/\u0000ff", "a/c"])
  })

  it("judges an archive symlink that replaces a host link whose target is not UTF-8 by its own target", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "a/c", hexField(0xff, "/..")],
      [member("a/", "directory"), member("a/c", "symlink", "x")]
    )

    expect([...okLinks(verdict)]).toStrictEqual([
      ["a/c", { stored: "x", target: { anchor: "parent", path: "x" } }],
    ])
  })

  it.each([
    { fields: ["l", "a/up", "..", "l", "a/up", "."], name: "the same link twice" },
    { fields: ["l", "a/up", ".", "l", "a/up", ".."], name: "the same link twice, reversed" },
  ])("is invalid for $name", ({ fields }) => {
    expect(preMergeContainmentVerdict(destination, fields, members)).toStrictEqual({
      kind: "invalid",
      reason: 'probe reported symlink "a/up" more than once',
    })
  })

  it("decodes hex fields exactly, a literal U+FFFD in a valid name included", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "\u0001c39e666f6f", "\u000174efbfbd", "l", "a/nl", "\u000175700a2f2e2e"],
      members
    )

    expect([...okLinks(verdict)]).toStrictEqual([
      ["Þfoo", { stored: "t�", target: { anchor: "parent", path: "t�" } }],
      ["a/nl", { stored: "up\n/..", target: { anchor: "parent", path: "up\n/.." } }],
      ["a/b", { stored: "q", target: { anchor: "parent", path: "q" } }],
    ])
  })

  it("combines host links and archive links and reports the escaping host link", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "a/esc", "up/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "a/esc", kind: "escape" }],
    })
  })

  it("accepts a combined link set that stays inside", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "a/esc", "up/.."],
      [member("a/", "directory"), member("a/b/", "directory"), member("a/up", "symlink", "b")]
    )

    expect(verdict.kind).toBe("ok")
  })
})

describe("scope of the pre-merge verdict (Issue #219)", () => {
  const destination = "/home/runner/actions-runner"
  const venvLink = ["l", "_work/proj/.venv/bin/python3", "/usr/bin/python3"]
  const runnerMembers = [member("./bin/", "directory"), member("./bin/Runner.Listener", "file")]

  it("accepts an archive without symlinks next to an unrelated host link that points outside", () => {
    expect(preMergeContainmentVerdict(destination, venvLink, runnerMembers)).toMatchObject({
      kind: "ok",
    })
  })

  it("accepts an archive with symlinks next to an unrelated host link that points outside", () => {
    const verdict = preMergeContainmentVerdict(destination, venvLink, [
      member("bin/", "directory"),
      member("lib/node_modules/npm/bin/npm-cli.js", "file"),
      member("bin/node", "symlink", "../lib/node_modules/npm/bin/npm-cli.js"),
    ])

    expect(verdict).toMatchObject({ kind: "ok" })
  })

  it.each([
    { fields: ["l", "x/loop", "loop"], name: "a loop" },
    { fields: ["l", "x/v", "UP/f", "l", "x/up", "."], name: "a name variant" },
    { fields: ["l", hexField("x/", 0xff), "/etc"], name: "a name that is not UTF-8" },
    { fields: ["u", "locked"], name: "an unreadable directory" },
    {
      fields: ["l", "x/in", "../locked/f", "u", "locked"],
      name: "a walk into an unreadable directory",
    },
  ])("ignores an unrelated host link with $name", ({ fields }) => {
    const verdict = preMergeContainmentVerdict("/opt/app", fields, [
      member("a/", "directory"),
      member("a/l", "symlink", "f"),
    ])

    expect(verdict).toMatchObject({ kind: "ok" })
  })

  it("refuses host a/esc -> up/.. next to archive a/up -> .. with the host link as violation", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "a/esc", "up/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "a/esc", kind: "escape" }],
    })
  })

  it("refuses the reverse order in the model: host a/up -> .. next to archive a/esc -> up/..", () => {
    // The pre-staging probe already refuses this archive, because the target
    // walk of `a/esc` passes through the host symlink `a/up`; the model still
    // follows that host link and reports the archive link.
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "a/up", ".."],
      [member("a/", "directory"), member("a/esc", "symlink", "up/..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "a/esc", kind: "escape" }],
    })
  })

  it("refuses a host link elsewhere that walks through an archive link: x/esc -> ../a/up/..", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "x/esc", "../a/up/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "x/esc", kind: "escape" }],
    })
  })

  it("refuses a host link that follows an affected host link: y/l -> ../x/esc/f", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "y/l", "../x/esc/f", "l", "x/esc", "../a/up/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [
        { key: "y/l", kind: "escape" },
        { key: "x/esc", kind: "escape" },
      ],
    })
  })

  it("refuses an absolute host target inside the destination that walks through an archive link", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "x/abs", "/opt/app/a/up/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "x/abs", kind: "escape" }],
    })
  })

  it("refuses a host link that walks through a differently spelled archive path", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "x/esc", "../A/UP/.."],
      [member("a/", "directory"), member("a/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({ kind: "violations", violations: [{ key: "x/esc" }] })
  })

  it("refuses a relevant host link whose name is not UTF-8", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", hexField("x/", 0xff), "../a/f"],
      [member("a/", "directory"), member("a/f", "file"), member("a/l", "symlink", "f")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "x/\u0000ff", kind: "unmappable", link: "x/\u0000ff" }],
    })
  })

  it("refuses an archive link that follows a host link whose target is not UTF-8", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "h", hexField(0xff)],
      [member("a/", "directory"), member("a/l", "symlink", "../h/f")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "a/l", kind: "unmappable", link: "h" }],
    })
  })

  it("refuses a relevant walk into an unreadable directory", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["u", "locked"],
      [member("a/", "directory"), member("a/l", "symlink", "../locked/f")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ directory: "locked", key: "a/l", kind: "unreadable" }],
    })
  })

  it("refuses an archive member at or below an unreadable directory as a conflict", () => {
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["u", "a/locked"],
      [member("a/", "directory"), member("a/locked/f", "file"), member("a/l", "symlink", ".")]
    )

    expect(verdict).toMatchObject({
      key: "a/locked",
      kind: "conflict",
      reason: "unreadable-directory",
    })
  })
})

describe("mergedSymlinkViolations (Issue #219)", () => {
  it("reports nothing for an empty link set", () => {
    expect(mergedSymlinkViolations(new Map())).toStrictEqual([])
  })

  it("accepts links that stay inside, including dangling targets and the destination root", () => {
    const links = relativeLinks([
      ["a/up", ".."],
      ["a/bin/x", "../lib/y"],
      ["a/dangling", "missing/deeper/z"],
      ["self", "."],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([])
  })

  it("reports a relative target whose .. climbs above the destination root", () => {
    const links = relativeLinks([
      ["x", "../y"],
      ["a/b/deep", "../../../y"],
      ["a/ok", "../y"],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([
      { key: "x", kind: "escape" },
      { key: "a/b/deep", kind: "escape" },
    ])
  })

  it("reports a link that escapes only through another link of the set", () => {
    const links = relativeLinks([
      ["a/esc", "up/.."],
      ["a/up", ".."],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([{ key: "a/esc", kind: "escape" }])
  })

  it("walks a root-anchored target from the destination root, not from the link's parent", () => {
    const links = new Map([
      ["a/b/l", hostLink("/opt/app/c", { anchor: "root", path: "c" })],
      ["a/b/root", hostLink("/opt/app", { anchor: "root", path: "" })],
      // From the parent `a/b`, `..` would stay inside at `a`; from the root it
      // climbs above the destination.
      ["a/b/up", hostLink("/opt/app/..", { anchor: "root", path: ".." })],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([{ key: "a/b/up", kind: "escape" }])
  })

  it("follows a symlinked prefix physically before applying .. in a root-anchored target", () => {
    // `s` points to `a/b`, so `/opt/app/s/../..` is `/opt/app/a/b/../..`, which
    // is the destination root. A lexical reading of `s/../..` would climb out.
    const links = new Map([
      ["s", hostLink("a/b")],
      ["t", hostLink("/opt/app/s/../..", { anchor: "root", path: "s/../.." })],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([])
  })

  it("reports a root-anchored target that escapes through a relative link", () => {
    const links = new Map([
      ["a/up", hostLink("..")],
      ["x", hostLink("/opt/app/a/up/..", { anchor: "root", path: "a/up/.." })],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([{ key: "x", kind: "escape" }])
  })

  it("reports an outside target and every link that passes through it", () => {
    const links = new Map([
      ["a/etc", hostLink("/etc", { anchor: "outside" })],
      ["b/passwd", hostLink("../a/etc/passwd")],
      ["b/unrelated", hostLink("../a/other")],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([
      { key: "a/etc", kind: "escape" },
      { key: "b/passwd", kind: "escape" },
    ])
  })

  it("reports a symlink loop as exceeding the resolution limit", () => {
    const links = relativeLinks([
      ["a", "b"],
      ["b", "a"],
      ["self", "self"],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([
      { key: "a", kind: "limit" },
      { key: "b", kind: "limit" },
      { key: "self", kind: "limit" },
    ])
  })

  it("reports self-extending links that GNU realpath never finishes as exceeding the limit", () => {
    // Issue #219: the post-merge backstop judges host links with this
    // resolver instead of `realpath`, which loops forever on these; a link
    // that walks through one of them cannot be shown to stay inside either.
    const links = relativeLinks([
      ["b", "b/.."],
      ["x", "y/.."],
      ["y", "x"],
      ["via", "b/f"],
      ["plain", "f"],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([
      { key: "b", kind: "limit" },
      { key: "x", kind: "limit" },
      { key: "y", kind: "limit" },
      { key: "via", kind: "limit" },
    ])
  })

  it("reports a chain of more than 40 hops as exceeding the resolution limit", () => {
    expect(mergedSymlinkViolations(chain(40))).toStrictEqual([])
    expect(mergedSymlinkViolations(chain(41))).toStrictEqual([{ key: "l0", kind: "limit" }])
  })

  it("resolves link names and targets with spaces and newlines faithfully", () => {
    const links = relativeLinks([
      ["dir with space/up", ".."],
      ["dir with space/two\nlines", "up/.."],
      ["dir with space/inside", "sub dir/file\nname"],
      ["dir with space/sub dir/back", "../../dir with space"],
    ])

    expect(mergedSymlinkViolations(links)).toStrictEqual([
      { key: "dir with space/two\nlines", kind: "escape" },
    ])
  })
})

/** Issue #219: the first code point outside the Basic Multilingual Plane. */
const FIRST_ASTRAL_CODE_POINT = 0x1_00_00
/** Issue #219: the step between the sampled astral code points. */
const ASTRAL_SAMPLE_STEP = 0x3_f1
/** Issue #219: astral letters with case mappings, sampled on top of the step. */
const CASED_ASTRAL_CODE_POINTS = [0x1_04_00, 0x1_04_28, 0x1_d4_00, 0x1_e9_00, 0x1_e9_22]

/**
 * Issue #219: every BMP code point except the surrogates, and a sample of the
 * astral ones.
 *
 * @returns The BMP code points in order, then the astral sample.
 */
function variantKeySampleCodePoints(): number[] {
  const codePoints = [...CASED_ASTRAL_CODE_POINTS]
  for (let codePoint = 0; codePoint < FIRST_ASTRAL_CODE_POINT; codePoint += 1) {
    const surrogate = codePoint >= 0xd8_00 && codePoint <= 0xdf_ff
    if (!surrogate) codePoints.push(codePoint)
  }
  for (
    let codePoint = FIRST_ASTRAL_CODE_POINT;
    codePoint <= 0x10_ff_ff;
    codePoint += ASTRAL_SAMPLE_STEP
  ) {
    codePoints.push(codePoint)
  }
  return codePoints
}

/**
 * Issue #219: the sampled code points whose variant key is not a fixpoint.
 *
 * @returns Their hexadecimal values.
 */
function nonFixpointCodePoints(): string[] {
  return variantKeySampleCodePoints()
    .filter((codePoint) => {
      const key = pathNameVariantKey(String.fromCodePoint(codePoint))
      return pathNameVariantKey(key) !== key
    })
    .map((codePoint) => codePoint.toString(16))
}

/** Issue #219: the wording every name-variant refusal shares. */
const VARIANT_WORDING = "only by letter case or Unicode normalization"

describe("pathNameVariantKey (Issue #219)", () => {
  it.each([
    ["d/UP", "d/up"],
    ["\u00e9", "e\u0301"],
    ["STRASSE", "stra\u00dfe"],
    ["\u212a", "k"],
    ["\ufb01le", "file"],
  ])("gives %j and %j the same key", (left, right) => {
    expect(pathNameVariantKey(left)).toBe(pathNameVariantKey(right))
  })

  it("keeps names apart that differ by more than case or normalization", () => {
    expect(pathNameVariantKey("d/up")).not.toBe(pathNameVariantKey("d/uq"))
  })

  it("gives capital sharp s the key of sharp s and of every spelling of ss", () => {
    const keys = ["\u1e9e", "\u00df", "ss", "SS", "Ss", "sS"].map((name) =>
      pathNameVariantKey(name)
    )

    expect(new Set(keys)).toStrictEqual(new Set(["ss"]))
    expect(pathNameVariantKey("x/\u1e9e")).toBe(pathNameVariantKey("x/ss"))
  })

  it.each([
    ["zero width joiner", "\u200d"],
    ["zero width non-joiner", "\u200c"],
    ["byte order mark", "\ufeff"],
    ["soft hyphen", "\u00ad"],
  ])("ignores a %s", (_name, ignorable) => {
    expect(pathNameVariantKey(`d/u${ignorable}p`)).toBe(pathNameVariantKey("d/up"))
    expect(pathNameVariantKey(`${ignorable}d/UP${ignorable}`)).toBe(pathNameVariantKey("d/up"))
  })

  it("is a fixpoint for every BMP code point and a sample of astral ones", () => {
    expect(nonFixpointCodePoints()).toStrictEqual([])
  })

  it.each([
    "x/\u1e9e/\u03a3",
    "\u039f\u0394\u039f\u03a3/\u1e9e\u1e9e",
    "a\u200d\u1e9e.\u03a3\u00ad",
    "\ufb03/\u212b\u0301",
  ])("is a fixpoint for the composed name %j", (name) => {
    const key = pathNameVariantKey(name)

    expect(pathNameVariantKey(key)).toBe(key)
  })
})

describe("name variants in the archive-level check (Issue #219)", () => {
  it("refuses a link whose target passes through a case variant of an archive symlink", () => {
    const reason = archiveLinkUnsafeReason([
      member("d/", "directory"),
      member("d/up", "symlink", ".."),
      member("d/esc", "symlink", "UP/.."),
    ])

    expect(reason).toBe(
      `member "d/esc" -> "UP/.." passes through "d/UP", a name that differs from existing symlink "d/up" ${VARIANT_WORDING}; a case-insensitive or normalizing filesystem may follow that symlink instead`
    )
  })

  it("refuses a link whose target passes through an NFD spelling of an NFC symlink name", () => {
    const reason = archiveLinkUnsafeReason([
      member("d/", "directory"),
      member("d/\u00e9", "symlink", ".."),
      member("d/esc", "symlink", "e\u0301/.."),
    ])

    expect(reason).toContain(VARIANT_WORDING)
    expect(reason).toContain('member "d/esc"')
  })

  it("refuses a walk through a differently cased parent directory of a symlink", () => {
    const reason = archiveLinkUnsafeReason([
      member("d/", "directory"),
      member("x/", "directory"),
      member("d/up", "symlink", ".."),
      member("x/esc", "symlink", "../D/up/.."),
    ])

    expect(reason).toContain('passes through "D/up"')
    expect(reason).toContain('existing symlink "d/up"')
  })

  it("refuses a walk through a symlink when another symlink differs from it only by case", () => {
    const reason = archiveLinkUnsafeReason([
      member("d/", "directory"),
      member("d/up", "symlink", "."),
      member("d/UP", "symlink", ".."),
      member("d/esc", "symlink", "up/x"),
    ])

    expect(reason).toContain('member "d/esc"')
    expect(reason).toContain('existing symlink "d/UP"')
  })

  it("refuses a symlink whose own parent path is a case variant of a symlink", () => {
    const reason = archiveLinkUnsafeReason([
      member("d", "symlink", "sub"),
      member("sub/", "directory"),
      member("D/esc", "symlink", "x"),
    ])

    expect(reason).toContain('member "D/esc"')
    expect(reason).toContain('passes through "D"')
  })

  it("accepts an ordinary archive whose names differ by case only where no symlink is involved", () => {
    expect(
      archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/up", "symlink", ".."),
        member("a/x", "symlink", "up/b"),
        member("B/c", "file"),
        member("b/c", "file"),
        member("b/link", "symlink", "../B/c"),
      ])
    ).toBeNull()
  })

  it("refuses a walk through ss next to a symlink named with capital sharp s, on any filesystem", () => {
    // Issue #219: the rule is lexical, so it fires on case-sensitive hosts too.
    const reason = archiveLinkUnsafeReason([
      member("x/", "directory"),
      member("x/\u1e9e", "symlink", ".."),
      member("x/esc", "symlink", "ss/../../n"),
    ])

    expect(reason).toBe(
      `member "x/esc" -> "ss/../../n" passes through "x/ss", a name that differs from existing symlink "x/\u1e9e" ${VARIANT_WORDING}; a case-insensitive or normalizing filesystem may follow that symlink instead`
    )
  })

  it("contributes no probe prefixes for a variant link", () => {
    expect(
      archiveSymlinkTargetPrefixes([
        member("d/", "directory"),
        member("d/up", "symlink", ".."),
        member("d/esc", "symlink", "UP/x"),
      ])
    ).toStrictEqual([])
  })
})

describe("name variants in the merged link set (Issue #219)", () => {
  const destination = "/opt/app"
  const variant = { key: "d/esc", kind: "variant", link: "d/up", prefix: "d/UP" }

  it("refuses a host link d/up -> .. combined with an archive link d/esc -> UP/..", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "d/up", ".."],
      [member("d/", "directory"), member("d/esc", "symlink", "UP/..")]
    )

    expect(verdict).toMatchObject({ kind: "violations", violations: [variant] })
  })

  it("refuses the reverse: a host link d/esc -> UP/.. combined with an archive link d/up -> ..", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["l", "d/esc", "UP/.."],
      [member("d/", "directory"), member("d/up", "symlink", "..")]
    )

    expect(verdict).toMatchObject({ kind: "violations", violations: [variant] })
  })

  it("refuses a walk through ss next to a symlink named with capital sharp s in the merged model", () => {
    const { inside, violations } = mergedSymlinkResolutions(
      relativeLinks([
        ["x/\u1e9e", ".."],
        ["x/esc", "ss/../../n"],
      ])
    )

    expect(violations).toStrictEqual([
      { key: "x/esc", kind: "variant", link: "x/\u1e9e", prefix: "x/ss" },
    ])
    expect(inside).toStrictEqual(new Map([["x/\u1e9e", ""]]))
  })

  it("reports the variant link as a violation and every other link with its resolved path", () => {
    const { inside, violations } = mergedSymlinkResolutions(
      relativeLinks([
        ["d/up", ".."],
        ["d/esc", "UP/.."],
        ["d/bin", "../lib"],
      ])
    )

    expect(violations).toStrictEqual([variant])
    expect(inside).toStrictEqual(
      new Map([
        ["d/bin", "lib"],
        ["d/up", ""],
      ])
    )
  })
})

describe("symlink trails for the kernel cross-check (Issue #219)", () => {
  it("lists the kept target segments and the resolver's location after each of them", () => {
    const { trail } = mergedSymlinkResolutions(
      relativeLinks([
        ["a/up", ".."],
        ["a/esc", "./up//a/../b/"],
        ["top", "a/up"],
      ])
    )

    expect(trail("a/esc", Number.POSITIVE_INFINITY)).toStrictEqual({
      base: "a",
      locations: ["a", "", "a", "", "b"],
      segments: ["up", "a", "..", "b"],
    })
    // A top-level link walks from the destination root, and a link as the
    // final component is followed like any other.
    expect(trail("top", Number.POSITIVE_INFINITY)).toStrictEqual({
      base: "",
      locations: ["", "a", ""],
      segments: ["a", "up"],
    })
  })

  it("follows a final component that is itself a dangling link to its resolution", () => {
    const { trail } = mergedSymlinkResolutions(
      relativeLinks([
        ["a/l", "b"],
        ["a/b", "missing/q"],
      ])
    )

    expect(trail("a/l", Number.POSITIVE_INFINITY)).toStrictEqual({
      base: "a",
      locations: ["a", "a/missing/q"],
      segments: ["b"],
    })
  })

  it("starts an absolute target inside the destination at the destination root", () => {
    const links = new Map([["a/abs", hostLink("/opt/app/lib", { anchor: "root", path: "lib" })]])

    expect(mergedSymlinkResolutions(links).trail("a/abs", 100)).toStrictEqual({
      base: "",
      locations: ["", "lib"],
      segments: ["lib"],
    })
  })

  it("refuses a trail whose locations exceed the given length", () => {
    const { trail } = mergedSymlinkResolutions(relativeLinks([["a/l", "bb/cc"]]))

    expect(trail("a/l", 12)).toStrictEqual({
      base: "a",
      locations: ["a", "a/bb", "a/bb/cc"],
      segments: ["bb", "cc"],
    })
    expect(trail("a/l", 11)).toBe("oversized")
  })

  it("has no trail for a link that does not resolve inside or is unknown", () => {
    const { trail } = mergedSymlinkResolutions(
      relativeLinks([
        ["x", "../y"],
        ["b", "b/.."],
      ])
    )

    expect(trail("x", Number.POSITIVE_INFINITY)).toBeNull()
    expect(trail("b", Number.POSITIVE_INFINITY)).toBeNull()
    expect(trail("unknown", Number.POSITIVE_INFINITY)).toBeNull()
  })
})
