import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"

import {
  preMergeContainmentVerdict,
  symlinkListingEntries,
} from "../../src/modules/archiveContainmentEnforcement.js"
import {
  mergedArchiveSymlinks,
  type MergedSymlink,
  mergedSymlinkViolations,
  type MergeHostState,
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
    const verdict = preMergeContainmentVerdict(destination, ["", "/opt/app/a/b"], members)

    expect(verdict).toMatchObject({ key: "a/b", kind: "conflict", reason: "host-directory" })
  })

  it.each([
    {
      fields: ["", "/opt/app/a"],
      name: "a directory hit for a path that was not requested",
      reason:
        'probe reported directory "/opt/app/a", which is not a requested member path below the destination',
    },
    {
      fields: ["", "/opt/app/a/b/"],
      name: "a directory hit spelled differently from the request",
      reason:
        'probe reported directory "/opt/app/a/b/", which is not a requested member path below the destination',
    },
    {
      fields: ["", "/opt/app/a/b", "/opt/app/x"],
      name: "an odd field count",
      reason: 'probe returned 3 fields, expected (link, target) or ("", directory) pairs',
    },
  ])("is invalid for $name", ({ fields, reason }) => {
    expect(preMergeContainmentVerdict(destination, fields, members)).toStrictEqual({
      kind: "invalid",
      reason,
    })
  })

  it("combines host links and archive links and reports the escaping host link", () => {
    const verdict = preMergeContainmentVerdict(
      destination,
      ["/opt/app/a/esc", "up/.."],
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
      ["/opt/app/a/esc", "up/.."],
      [member("a/", "directory"), member("a/b/", "directory"), member("a/up", "symlink", "b")]
    )

    expect(verdict.kind).toBe("ok")
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
