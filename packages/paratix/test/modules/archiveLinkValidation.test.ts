import { describe, expect, it, vi } from "vitest"

import type * as SymlinkResolverModule from "../../src/modules/archiveSymlinkResolver.js"

import {
  type PreMergeContainmentVerdict,
  preMergeContainmentVerdict,
  symlinkListingEntries,
} from "../../src/modules/archiveContainmentEnforcement.js"
import { archiveContainmentScope } from "../../src/modules/archiveContainmentScope.js"
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
import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
} from "../../src/modules/archiveMemberValidation.js"

/**
 * Issue #219: how many symlink resolvers were built. A transparent subclass
 * counts them, so a test can show that the archive-level rules and the
 * pre-staging prefix model share one resolver per member list.
 */
const resolverInstances = vi.hoisted(() => ({ built: 0 }))

vi.mock("../../src/modules/archiveSymlinkResolver.js", async (importOriginal) => {
  const original = await importOriginal<typeof SymlinkResolverModule>()
  class CountedSymlinkResolver extends original.ArchiveSymlinkResolver {
    public constructor(
      ...parameters: ConstructorParameters<typeof original.ArchiveSymlinkResolver>
    ) {
      super(...parameters)
      resolverInstances.built += 1
    }
  }
  return { ...original, ArchiveSymlinkResolver: CountedSymlinkResolver }
})

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
      fields: ["y", "a/b"],
      name: "an unknown record kind",
      reason: 'probe reported unknown record kind "y"',
    },
    {
      fields: ["l", "a/k", ".", "x", "a/l"],
      name: "an entry the probe could not read or encode",
      reason:
        'probe could not read or encode entry "a/l" below the destination (readlink or od failed on the host)',
    },
    {
      fields: ["x", "", "l", "a/k", "."],
      name: "an entry whose name the probe could not encode",
      reason:
        "probe could not encode the name of an entry below the destination (od failed on the host)",
    },
    {
      fields: ["x", "\u0001abc"],
      name: "an entry the probe could not read, with a malformed path",
      reason:
        'probe could not read or encode an entry below the destination and reported it with an unusable path: probe reported hex field "abc" that is not well-formed hex',
    },
    {
      fields: ["x"],
      name: "an entry record cut off at the end",
      reason: 'probe output ends inside a "x" record',
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

  // Issue #219: an absolute target is inside only when it is the destination
  // or continues it with `/`; a newline or a glob character right after the
  // destination's name is a different directory.
  it.each([
    { field: hexField("/opt/app\n/x"), name: "a newline", stored: "/opt/app\n/x" },
    { field: "/opt/app*", name: "a glob character", stored: "/opt/app*" },
  ])(
    "classifies an absolute target that continues the destination name with $name as outside",
    ({ field, stored }) => {
      const verdict = preMergeContainmentVerdict(destination, ["l", "x/l", field], members)

      expect(okLinks(verdict).get("x/l")).toStrictEqual({ stored, target: { anchor: "outside" } })
    }
  )

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

    // Issue #219: the duplicate rule groups by `pathNameVariantKey`, so the two
    // spellings with different targets are refused before any walk.
    expect(reason).toBe(
      'member "d/up" occurs more than once with conflicting link types or targets (also spelled "d/UP")'
    )
  })

  it("refuses a symlink whose own parent path is a case variant of a symlink", () => {
    const reason = archiveLinkUnsafeReason([
      member("d", "symlink", "sub"),
      member("sub/", "directory"),
      member("D/esc", "symlink", "x"),
    ])

    // Issue #219: the ancestor rule compares by `pathNameVariantKey`, so
    // `D/esc` is refused as a member below the symlink `d` before any walk.
    expect(reason).toBe('member "D/esc" is below archive symlink "d"')
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

/** Issue #219: the wording of every conflicting-duplicate refusal. */
const CONFLICTING_DUPLICATE_WORDING = "occurs more than once with conflicting link types or targets"

/**
 * Issue #219: the members of a Node.js binary distribution as `tar -t` lists
 * them, with its launcher symlinks into `lib/node_modules`.
 *
 * @returns The members in listing order.
 */
function nodeDistributionMembers(): ArchiveMember[] {
  return [
    member("node-v22/", "directory"),
    member("node-v22/bin/", "directory"),
    member("node-v22/bin/node", "file"),
    member("node-v22/bin/corepack", "symlink", "../lib/node_modules/corepack/dist/corepack.js"),
    member("node-v22/bin/npm", "symlink", "../lib/node_modules/npm/bin/npm-cli.js"),
    member("node-v22/bin/npx", "symlink", "../lib/node_modules/npm/bin/npx-cli.js"),
    member("node-v22/include/", "directory"),
    member("node-v22/include/node/", "directory"),
    member("node-v22/include/node/node.h", "file"),
    member("node-v22/lib/", "directory"),
    member("node-v22/lib/node_modules/", "directory"),
    member("node-v22/lib/node_modules/corepack/", "directory"),
    member("node-v22/lib/node_modules/corepack/dist/", "directory"),
    member("node-v22/lib/node_modules/corepack/dist/corepack.js", "file"),
    member("node-v22/lib/node_modules/npm/", "directory"),
    member("node-v22/lib/node_modules/npm/bin/", "directory"),
    member("node-v22/lib/node_modules/npm/bin/npm-cli.js", "file"),
    member("node-v22/lib/node_modules/npm/bin/npx-cli.js", "file"),
    member("node-v22/share/", "directory"),
    member("node-v22/share/man/", "directory"),
    member("node-v22/share/man/man1/", "directory"),
    member("node-v22/share/man/man1/node.1", "file"),
    member("node-v22/CHANGELOG.md", "file"),
    member("node-v22/LICENSE", "file"),
    member("node-v22/README.md", "file"),
  ]
}

/**
 * Issue #219: the members of a JDK image with its `legal/` symlinks between
 * modules and the `man/ja` locale alias.
 *
 * @returns The members in listing order.
 */
function jdkImageMembers(): ArchiveMember[] {
  return [
    member("jdk/", "directory"),
    member("jdk/bin/", "directory"),
    member("jdk/bin/java", "file"),
    member("jdk/legal/", "directory"),
    member("jdk/legal/java.base/", "directory"),
    member("jdk/legal/java.base/ADDITIONAL_LICENSE_INFO", "file"),
    member("jdk/legal/java.base/LICENSE", "file"),
    member("jdk/legal/java.desktop/", "directory"),
    member(
      "jdk/legal/java.desktop/ADDITIONAL_LICENSE_INFO",
      "symlink",
      "../java.base/ADDITIONAL_LICENSE_INFO"
    ),
    member("jdk/legal/java.desktop/LICENSE", "symlink", "../java.base/LICENSE"),
    member("jdk/man/", "directory"),
    member("jdk/man/ja", "symlink", "ja_JP.UTF-8"),
    member("jdk/man/ja_JP.UTF-8/", "directory"),
    member("jdk/man/ja_JP.UTF-8/man1/", "directory"),
    member("jdk/man/ja_JP.UTF-8/man1/java.1", "file"),
    member("jdk/man/man1/", "directory"),
    member("jdk/man/man1/java.1", "file"),
  ]
}

/**
 * Issue #219: the members of a packed Python virtual environment with its
 * `lib64` and interpreter symlinks.
 *
 * @returns The members in listing order.
 */
function pythonVenvMembers(): ArchiveMember[] {
  return [
    member("venv/", "directory"),
    member("venv/bin/", "directory"),
    member("venv/bin/activate", "file"),
    member("venv/bin/python", "symlink", "python3.12"),
    member("venv/bin/python3", "symlink", "python3.12"),
    member("venv/bin/python3.12", "file"),
    member("venv/include/", "directory"),
    member("venv/lib/", "directory"),
    member("venv/lib/python3.12/", "directory"),
    member("venv/lib/python3.12/site-packages/", "directory"),
    member("venv/lib/python3.12/site-packages/x.py", "file"),
    member("venv/lib64", "symlink", "lib"),
    member("venv/pyvenv.cfg", "file"),
  ]
}

/**
 * Issue #219: the members of a Go distribution, whose `src/` holds names that
 * start with differently cased prefixes (`Make.dist`, `make.bash`).
 *
 * @returns The members in listing order.
 */
function goDistributionMembers(): ArchiveMember[] {
  return [
    member("go/", "directory"),
    member("go/bin/", "directory"),
    member("go/bin/go", "file"),
    member("go/bin/gofmt", "file"),
    member("go/misc/", "directory"),
    member("go/misc/wasm/", "directory"),
    member("go/misc/wasm/wasm_exec.js", "file"),
    member("go/src/", "directory"),
    member("go/src/Make.dist", "file"),
    member("go/src/make.bash", "file"),
    member("go/src/make.bat", "file"),
    member("go/src/make.rc", "file"),
    member("go/VERSION", "file"),
  ]
}

// Issue #219: the relationship rules (duplicate, ancestor, hardlink through a
// symlink, hardlink to a symlink) compare member paths under
// `pathNameVariantKey`, like the resolution rule, because a case-folding or
// normalizing filesystem stores both spellings as one entry. The rules are
// lexical, so they refuse on case-sensitive hosts too.
describe("name variants in the archive relationship rules (Issue #219)", () => {
  describe("ancestor rule", () => {
    it("refuses a member below a case variant of an archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/L", "symlink", "y"),
        member("y/", "directory"),
        member("x/l/f", "file"),
      ])

      expect(reason).toBe('member "x/l/f" is below archive symlink "x/L"')
    })

    it("refuses a member below the NFD spelling of an NFC archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/é", "symlink", "y"),
        member("y/", "directory"),
        member("x/é/f", "file"),
      ])

      expect(reason).toBe('member "x/é/f" is below archive symlink "x/é"')
    })

    it("refuses a member below the NFC spelling of an NFD archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/é", "symlink", "y"),
        member("y/", "directory"),
        member("x/é/f", "file"),
      ])

      expect(reason).toBe('member "x/é/f" is below archive symlink "x/é"')
    })

    it("refuses a member below a spelling of an archive symlink with a default-ignorable character", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/L", "symlink", "y"),
        member("y/", "directory"),
        member("x/L‍/f", "file"),
      ])

      expect(reason).toBe('member "x/L‍/f" is below archive symlink "x/L"')
    })

    it("refuses a directory member below a case variant of an archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/L", "symlink", "y"),
        member("y/", "directory"),
        member("X/L/sub/", "directory"),
      ])

      expect(reason).toBe('member "X/L/sub/" is below archive symlink "x/L"')
    })

    it("refuses a hardlink member below a case variant of an archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("x/", "directory"),
        member("x/L", "symlink", "y"),
        member("y/", "directory"),
        member("y/f", "file"),
        member("x/l/h", "hardlink", "y/f"),
      ])

      expect(reason).toBe('member "x/l/h" is below archive symlink "x/L"')
    })

    it.each([
      ["x/L", "x/l"],
      ["x/l", "x/L"],
    ])(
      "reports the first listed spelling when symlinks %j and %j collide with the same target",
      (first, second) => {
        // Issue #219: identical targets pass the duplicate rule, so the ancestor
        // rule reports the spelling listed first, even though the member's own
        // parent matches the second spelling byte for byte.
        const reason = archiveLinkUnsafeReason([
          member("x/", "directory"),
          member(first, "symlink", "../y"),
          member(second, "symlink", "../y"),
          member("y/", "directory"),
          member(`${second}/f`, "file"),
        ])

        expect(reason).toBe(`member "${second}/f" is below archive symlink "${first}"`)
      }
    )

    it("leaves no member path with a .. segment to the ancestor rule", () => {
      // The ancestor rule compares normalized paths; a raw `x/L/../f` passes
      // through the archive symlink `x/L` although it normalizes to `x/f`, so
      // the member rule refuses it first.
      expect(archiveMemberUnsafeReason(member("x/L/../f", "file"))).toBe(
        'member "x/L/../f" contains a ".." path segment'
      )
    })

    it("accepts a member below an unrelated name next to an archive symlink", () => {
      expect(
        archiveLinkUnsafeReason([
          member("x/", "directory"),
          member("x/L", "symlink", "y"),
          member("y/", "directory"),
          member("x/M/", "directory"),
          member("x/M/f", "file"),
        ])
      ).toBeNull()
    })

    it("accepts a member below a longer name that starts with an archive symlink's name", () => {
      expect(
        archiveLinkUnsafeReason([
          member("x/", "directory"),
          member("x/L", "symlink", "y"),
          member("y/", "directory"),
          member("x/Lx/", "directory"),
          member("x/Lx/f", "file"),
        ])
      ).toBeNull()
    })
  })

  describe("hardlink through a symlink", () => {
    it("refuses a hardlink whose target passes through a case variant of an archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/b/", "directory"),
        member("a/b/S", "symlink", "../../x"),
        member("x/", "directory"),
        member("x/f", "file"),
        member("h", "hardlink", "a/b/s/f"),
      ])

      expect(reason).toBe('member "h" hardlinks to archive symlink "a/b/S"')
    })

    it("refuses a hardlink whose target passes through the NFD spelling of an NFC archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/é", "symlink", "../x"),
        member("x/", "directory"),
        member("x/f", "file"),
        member("h", "hardlink", "a/é/f"),
      ])

      expect(reason).toBe('member "h" hardlinks to archive symlink "a/é"')
    })
  })

  it("leaves no hardlink target with a .. segment to the hardlink rules", () => {
    // Hardlink targets are archive-root-relative member names, so a `..` in
    // one is refused like in a member path, even when it normalizes inside.
    expect(archiveMemberUnsafeReason(member("h", "hardlink", "a/s/../f"))).toBe(
      'member "h" -> "a/s/../f" hardlink target contains a ".." path segment'
    )
    // A symlink target keeps its `..`: the link resolver judges where it leads.
    expect(archiveMemberUnsafeReason(member("a/up", "symlink", ".."))).toBeNull()
  })

  describe("hardlink to a symlink", () => {
    it("refuses a hardlink to a case variant of an archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/b/", "directory"),
        member("a/b/S", "symlink", "../../x"),
        member("x", "file"),
        member("h", "hardlink", "a/b/s"),
      ])

      expect(reason).toBe('member "h" hardlinks to archive symlink "a/b/S"')
    })

    it("refuses a hardlink to the NFD spelling of an NFC archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/é", "symlink", "../x"),
        member("x", "file"),
        member("h", "hardlink", "a/é"),
      ])

      expect(reason).toBe('member "h" hardlinks to archive symlink "a/é"')
    })

    it("refuses a hardlink to the NFC spelling of an NFD archive symlink", () => {
      const reason = archiveLinkUnsafeReason([
        member("a/", "directory"),
        member("a/é", "symlink", "../x"),
        member("x", "file"),
        member("h", "hardlink", "a/é"),
      ])

      expect(reason).toBe('member "h" hardlinks to archive symlink "a/é"')
    })

    it("accepts a hardlink to a regular file whose name matches an unrelated symlink elsewhere only by case", () => {
      expect(
        archiveLinkUnsafeReason([
          member("a/", "directory"),
          member("a/Readme", "symlink", "../b/Readme"),
          member("b/", "directory"),
          member("b/Readme", "file"),
          member("b/readme", "file"),
          member("h", "hardlink", "b/readme"),
        ])
      ).toBeNull()
    })
  })

  describe("duplicates", () => {
    it("refuses a symlink and a regular file whose names differ only by case", () => {
      const reason = archiveLinkUnsafeReason([
        member("Foo", "symlink", "bar"),
        member("foo", "file"),
        member("bar", "file"),
      ])

      expect(reason).toStrictEqual(expect.stringContaining(CONFLICTING_DUPLICATE_WORDING))
      expect(reason).toStrictEqual(expect.stringContaining('member "Foo"'))
    })

    it("refuses a directory and a symlink whose names differ only by case", () => {
      const reason = archiveLinkUnsafeReason([
        member("D/", "directory"),
        member("d", "symlink", "x"),
        member("x", "file"),
      ])

      expect(reason).toStrictEqual(expect.stringContaining(CONFLICTING_DUPLICATE_WORDING))
      expect(reason).toStrictEqual(expect.stringContaining('member "D/"'))
    })

    it("refuses NFC and NFD spellings of a symlink with different targets", () => {
      const reason = archiveLinkUnsafeReason([
        member("é", "symlink", "a"),
        member("é", "symlink", "b"),
        member("a", "file"),
        member("b", "file"),
      ])

      expect(reason).toStrictEqual(expect.stringContaining(CONFLICTING_DUPLICATE_WORDING))
      expect(reason).toStrictEqual(expect.stringContaining('member "é"'))
    })

    it("accepts plain files whose names differ only by case (Makefile, makefile)", () => {
      expect(
        archiveLinkUnsafeReason([member("Makefile", "file"), member("makefile", "file")])
      ).toBeNull()
    })

    it("accepts Linux headers whose names differ only by case (xt_DSCP.h, xt_dscp.h)", () => {
      expect(
        archiveLinkUnsafeReason([
          member("include/", "directory"),
          member("include/xt_DSCP.h", "file"),
          member("include/xt_dscp.h", "file"),
        ])
      ).toBeNull()
    })

    it("accepts identical duplicate symlinks", () => {
      expect(
        archiveLinkUnsafeReason([
          member("l", "symlink", "t"),
          member("l", "symlink", "t"),
          member("t", "file"),
        ])
      ).toBeNull()
    })
  })

  describe("root link rule", () => {
    it.each([
      ["symlink", "x"],
      ["hardlink", "x"],
    ] as const)(
      "does not treat a %s named only with a default-ignorable character as a link at the destination root",
      (kind, linkTarget) => {
        // Issue #219: the name folds to "" but is not the destination root; the
        // root-link rule stays literal. Another rule may still refuse it.
        const reason = archiveLinkUnsafeReason([member("x", "file"), member("‍", kind, linkTarget)])

        expect(reason).not.toStrictEqual(expect.stringContaining("destination root"))
      }
    )
  })

  describe("realistic archives", () => {
    it.each([
      ["a Node.js distribution", nodeDistributionMembers],
      ["a JDK image", jdkImageMembers],
      ["a Python virtual environment", pythonVenvMembers],
      ["a Go distribution", goDistributionMembers],
    ] as const)("accepts %s", (_name, members) => {
      expect(archiveLinkUnsafeReason(members())).toBeNull()
    })
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

describe("archive links listed under another spelling (Issue #219)", () => {
  // Issue #219: a case-preserving or normalizing filesystem can list the
  // archive's own link under the spelling it keeps on disk, e.g. `A/S` for the
  // member `a/s`, or NFD for an NFC member. Such a link is the archive's link
  // and is judged even when its walk touches no written path.
  const nfcE = "é"
  const nfdE = "é"

  it.each([
    { listed: "a/s", name: "the literal member path", parent: "a" },
    { listed: "A/S", name: "a different letter case", parent: "a" },
    { listed: `${nfdE}/s`, name: "NFD for an NFC member path", parent: nfcE },
  ])("judges the archive link a/s listed as $name", ({ listed, parent }) => {
    const members = [member(`${parent}/`, "directory"), member(`${parent}/s`, "symlink", "t")]
    // Walking `../../x` from the listed parent reaches the destination root,
    // which the archive does not write, and then escapes.
    const links = relativeLinks([
      [listed, "../../x"],
      // Issue #219: unrelated to the archive, so ignored although it escapes.
      ["x/up", "../../y"],
    ])

    expect(mergedSymlinkViolations(links, archiveContainmentScope(members))).toStrictEqual([
      { key: listed, kind: "escape" },
    ])
  })

  it("refuses a host link A/S that escapes before an archive ships a/s", () => {
    // Issue #219: on a case-insensitive host the listing shows the name the
    // host keeps, so the model cannot tell whether `A/S` is the path the
    // archive link replaces; the escaping link is judged, not ignored.
    const verdict = preMergeContainmentVerdict(
      "/opt/app",
      ["l", "A/S", "../../x"],
      [member("a/", "directory"), member("a/s", "symlink", "t")]
    )

    expect(verdict).toMatchObject({
      kind: "violations",
      violations: [{ key: "A/S", kind: "escape" }],
    })
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

describe("links followed by judged links for the kernel cross-check (Issue #219)", () => {
  // Issue #219: the archive ships `d/j -> f` and `d/k -> f`; the host
  // links `d/f -> e` and `d/e -> missing/q` touch no path the archive writes,
  // so they are not judged, but both archive links resolve through them.
  const members = [
    member("d/", "directory"),
    member("d/j", "symlink", "f"),
    member("d/k", "symlink", "f"),
  ]
  const links = relativeLinks([
    ["d/j", "f"],
    ["d/k", "f"],
    ["d/f", "e"],
    ["d/e", "missing/q"],
    ["d/sub", "../other"],
    ["d/mid", "sub/x"],
  ])

  it("lists the unjudged links a judged link follows, directly and transitively, each once", () => {
    const { followed, inside, trail } = mergedSymlinkResolutions(
      links,
      archiveContainmentScope(members)
    )

    expect(inside).toStrictEqual(
      new Map([
        ["d/j", "d/missing/q"],
        ["d/k", "d/missing/q"],
      ])
    )
    expect(followed("d/j")).toStrictEqual(["d/f", "d/e"])
    expect(followed("d/k")).toStrictEqual(["d/f", "d/e"])
    // The followed links have trails of their own, from the same source.
    expect(trail("d/f", Number.POSITIVE_INFINITY)).toStrictEqual({
      base: "d",
      locations: ["d", "d/missing/q"],
      segments: ["e"],
    })
    expect(trail("d/e", Number.POSITIVE_INFINITY)).toStrictEqual({
      base: "d",
      locations: ["d", "d/missing", "d/missing/q"],
      segments: ["missing", "q"],
    })
  })

  it("has no followed links for a link that is not judged inside", () => {
    const { followed } = mergedSymlinkResolutions(links, archiveContainmentScope(members))

    expect(followed("d/f")).toStrictEqual([])
    expect(followed("d/mid")).toStrictEqual([])
    expect(followed("unknown")).toStrictEqual([])
  })

  it("lists a link followed in the middle of a target path", () => {
    const { followed, inside } = mergedSymlinkResolutions(
      links,
      archiveContainmentScope([member("d/", "directory"), member("d/mid", "symlink", "sub/x")])
    )

    expect(inside).toStrictEqual(new Map([["d/mid", "other/x"]]))
    expect(followed("d/mid")).toStrictEqual(["d/sub"])
  })

  it("leaves out a followed link that is judged itself", () => {
    // Without a scope every link is judged, so every followed link is
    // cross-checked as its own entry.
    const all = mergedSymlinkResolutions(links)
    const scoped = mergedSymlinkResolutions(
      links,
      archiveContainmentScope([...members, member("d/f", "symlink", "e")])
    )

    expect(all.followed("d/j")).toStrictEqual([])
    expect(scoped.followed("d/j")).toStrictEqual(["d/e"])
  })

  it("follows nothing for a link that does not resolve inside", () => {
    const { followed, violations } = mergedSymlinkResolutions(
      relativeLinks([
        ["d/j", "f/../../../.."],
        ["d/f", "e"],
        ["d/e", "missing/q"],
      ]),
      archiveContainmentScope([
        member("d/", "directory"),
        member("d/j", "symlink", "f/../../../.."),
      ])
    )

    expect(violations).toStrictEqual([{ key: "d/j", kind: "escape" }])
    expect(followed("d/j")).toStrictEqual([])
  })
})

describe("one symlink resolver per member list (Issue #219)", () => {
  it("resolves the archive's links once for the link rules and the prefix model", () => {
    const members = [
      member("a/", "directory"),
      member("a/lib/", "directory"),
      member("a/up", "symlink", ".."),
      member("a/bin", "symlink", "up/b/c"),
    ]
    const before = resolverInstances.built

    expect(archiveLinkUnsafeReason(members)).toBeNull()
    expect(archiveSymlinkTargetPrefixes(members)).toStrictEqual([
      { path: "b", symlink: "a/bin" },
      { path: "b/c", symlink: "a/bin" },
    ])
    expect(archiveLinkUnsafeReason(members)).toBeNull()
    expect(resolverInstances.built - before).toBe(1)

    // A different member list, even with equal content, gets its own resolver.
    expect(archiveSymlinkTargetPrefixes([...members])).toHaveLength(2)
    expect(resolverInstances.built - before).toBe(2)
  })
})
