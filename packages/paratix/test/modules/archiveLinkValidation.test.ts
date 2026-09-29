import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"

import {
  mergedArchiveSymlinks,
  type MergedSymlink,
  mergedSymlinkViolations,
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

    const merged = mergedArchiveSymlinks(host, [
      member("a/", "directory"),
      member("a/up", "symlink", "b"),
    ])

    expect([...merged]).toStrictEqual([["a/up", hostLink("b")]])
  })

  it("replaces a host link whose absolute target was root-anchored with a relative archive target", () => {
    const host = new Map([["l", hostLink("/opt/app/x", { anchor: "root", path: "x" })]])

    const merged = mergedArchiveSymlinks(host, [member("./l", "symlink", "y")])

    expect([...merged]).toStrictEqual([["l", hostLink("y")]])
  })

  it.each([
    { kind: "file", linkTarget: null, path: "a/up" },
    { kind: "directory", linkTarget: null, path: "a/up/" },
    { kind: "hardlink", linkTarget: "f", path: "a/up" },
  ] as const)(
    "removes the host link where the archive ships a $kind at the same path",
    ({ kind, linkTarget, path }) => {
      const host = new Map([
        ["a/esc", hostLink("up/..")],
        ["a/up", hostLink("..")],
      ])

      const merged = mergedArchiveSymlinks(host, [member(path, kind, linkTarget)])

      expect([...merged]).toStrictEqual([["a/esc", hostLink("up/..")]])
    }
  )

  it("matches archive members to host links by normalized path", () => {
    const host = new Map([["a/b/l", hostLink("..")]])

    const merged = mergedArchiveSymlinks(host, [member("./a//b/l", "symlink", "c")])

    expect([...merged]).toStrictEqual([["a/b/l", hostLink("c")]])
  })

  it("keeps host links below an archive member path and links the archive does not touch", () => {
    const host = new Map([
      ["a/deep/l", hostLink("../x")],
      ["other", hostLink("a")],
    ])

    const merged = mergedArchiveSymlinks(host, [
      member("a/", "directory"),
      member("a/deep/", "directory"),
      member("a/new", "symlink", "deep"),
    ])

    expect([...merged]).toStrictEqual([
      ["a/deep/l", hostLink("../x")],
      ["other", hostLink("a")],
      ["a/new", hostLink("deep")],
    ])
  })

  it("applies members in listing order, so a later entry for the same path wins", () => {
    const merged = mergedArchiveSymlinks(new Map(), [
      member("l", "symlink", "first"),
      member("l", "file"),
      member("m", "file"),
      member("m", "symlink", "second"),
    ])

    expect([...merged]).toStrictEqual([["m", hostLink("second")]])
  })

  it("leaves the host link map untouched", () => {
    const host = new Map([["a/up", hostLink("..")]])

    mergedArchiveSymlinks(host, [member("a/up", "file")])

    expect([...host]).toStrictEqual([["a/up", hostLink("..")]])
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
