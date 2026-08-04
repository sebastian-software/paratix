/**
 * Shell-level smoke tests for the batched `archive.extract` probes.
 *
 * Issue #180 replaced one exec per path with three remote scripts. Issue #178
 * is why they are executed here rather than asserted as strings: a guard that
 * reads correctly can still be inert at run time, and only running it proves
 * otherwise. Same approach as `archive.shell.smoke.test.ts` and
 * `flagLock.shell.smoke.test.ts`.
 */
import { spawnSync } from "node:child_process"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  buildSymlinkProbeScript,
  encodeMemberTypeEntry,
  encodeNulPayload,
} from "../../src/modules/archiveProbe.js"
import { renderBatchedChownSymlinkCommand } from "../../src/modules/fileMetadataHelpers.js"

type ProbeResult = { code: number; fields: string[]; stderr: string }

/**
 * Run a probe script the way `runBatchedProbe` does: entries NUL-terminated on
 * stdin, violations NUL-terminated on stdout.
 *
 * @param script - The probe script under test.
 * @param entries - The entries to transport.
 * @returns Exit code, decoded output fields and stderr.
 */
function runProbe(script: string, entries: string[]): ProbeResult {
  const result = spawnSync("/bin/sh", ["-c", script], {
    encoding: "utf8",
    input: encodeNulPayload(entries),
    timeout: 10_000,
  })
  const fields = (result.stdout || "").split("\0")
  if (fields.at(-1) === "") fields.pop()
  return { code: result.status ?? -1, fields, stderr: result.stderr || "" }
}

function makeWorkspace(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), "paratix-probe-smoke-")))
}

/**
 * Whether `chown` is the GNU coreutils build.
 *
 * @returns True when `chown --version` succeeds.
 */
function hasGnuChown(): boolean {
  return spawnSync("chown", ["--version"], { encoding: "utf8", timeout: 2000 }).status === 0
}

function hasGnuStat(): boolean {
  const probe = spawnSync("stat", ["-c", "%U", "."], { encoding: "utf8", timeout: 2000 })
  return probe.status === 0
}

/**
 * Read the current owner of the working directory.
 *
 * @returns User and group, by name and numeric id.
 */
function currentOwner(): { group: string; groupId: string; user: string; userId: string } {
  const out = spawnSync("stat", ["-c", "%U %G %u %g", "."], {
    encoding: "utf8",
    timeout: 2000,
  }).stdout.trim()
  const [user = "", group = "", userId = "", groupId = ""] = out.split(/\s+/v)
  return { group, groupId, user, userId }
}

/**
 * Run the batched chown with its paths NUL-delimited on stdin.
 *
 * @param spec - The chown owner spec.
 * @param paths - The target paths.
 * @returns Exit code and stderr.
 */
function runChown(spec: string, paths: string[]): { code: number; stderr: string } {
  const result = spawnSync("/bin/sh", ["-c", renderBatchedChownSymlinkCommand(spec)], {
    encoding: "utf8",
    input: encodeNulPayload(paths),
    timeout: 10_000,
  })
  return { code: result.status ?? -1, stderr: result.stderr || "" }
}

/** Own uid:gid — the one spec an unprivileged process may chown to. */
const ownSpec = `${String(process.getuid?.() ?? 0)}:${String(process.getgid?.() ?? 0)}`

const SKIP_PLATFORM = process.platform === "win32"
const SKIP_NO_GNU_STAT = !hasGnuStat()
const SKIP_NO_GNU_CHOWN = !hasGnuChown()

describe.skipIf(SKIP_PLATFORM)("archive.extract batched probes", () => {
  describe("symlink probe", () => {
    it("reports nothing for a clean set", () => {
      const root = makeWorkspace()
      try {
        const file = join(root, "plain.txt")
        writeFileSync(file, "x")
        const result = runProbe(buildSymlinkProbeScript(), [root, file])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a symlink and leaves the plain paths out", () => {
      const root = makeWorkspace()
      try {
        const plain = join(root, "plain.txt")
        const link = join(root, "link")
        writeFileSync(plain, "x")
        symlinkSync(plain, link)

        const result = runProbe(buildSymlinkProbeScript(), [plain, link])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([link])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("does not treat a non-existent path as a violation", () => {
      // `test ! -L /missing` exits 0, so a missing ancestor passed the previous
      // per-path guard. The batched probe must keep that, or a legitimately
      // absent path starts failing extraction.
      const root = makeWorkspace()
      try {
        const result = runProbe(buildSymlinkProbeScript(), [join(root, "does-not-exist")])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("handles a path containing a literal newline", () => {
      const root = makeWorkspace()
      try {
        const target = join(root, "target")
        const link = join(root, "two\nlines")
        writeFileSync(target, "x")
        symlinkSync(target, link)

        const result = runProbe(buildSymlinkProbeScript(), [link])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([link])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("succeeds on empty input", () => {
      const result = runProbe(buildSymlinkProbeScript(), [])

      expect(result.code).toBe(0)
      expect(result.fields).toStrictEqual([])
    })
  })

  describe("member type probe", () => {
    it("reports nothing when every member matches its recorded kind", () => {
      const root = makeWorkspace()
      try {
        const directory = join(root, "dir")
        const file = join(root, "file.txt")
        const link = join(root, "link")
        mkdirSync(directory)
        writeFileSync(file, "x")
        symlinkSync(file, link)

        const result = runProbe(buildMemberTypeProbeScript(), [
          encodeMemberTypeEntry("d", directory),
          encodeMemberTypeEntry("f", file),
          encodeMemberTypeEntry("l", link),
        ])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a missing member", () => {
      const root = makeWorkspace()
      try {
        const missing = join(root, "gone.txt")
        const result = runProbe(buildMemberTypeProbeScript(), [encodeMemberTypeEntry("f", missing)])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([missing])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a member whose kind changed", () => {
      const root = makeWorkspace()
      try {
        const path = join(root, "was-a-directory")
        writeFileSync(path, "now a file")

        const result = runProbe(buildMemberTypeProbeScript(), [encodeMemberTypeEntry("d", path)])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([path])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a regular file recorded as a file but replaced by a symlink", () => {
      const root = makeWorkspace()
      try {
        const target = join(root, "target.txt")
        const path = join(root, "member.txt")
        writeFileSync(target, "x")
        symlinkSync(target, path)

        const result = runProbe(buildMemberTypeProbeScript(), [encodeMemberTypeEntry("f", path)])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([path])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("keeps kind and path paired for a path containing a colon and a newline", () => {
      // Kind and path share one argument precisely so `xargs` cannot split them
      // apart. A path containing the delimiter must still resolve correctly,
      // because only the first colon separates.
      const root = makeWorkspace()
      try {
        const path = join(root, "od:d\nname.txt")
        writeFileSync(path, "x")

        const result = runProbe(buildMemberTypeProbeScript(), [encodeMemberTypeEntry("f", path)])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  describe("batched chown", () => {
    it("chowns every supplied path, including one containing a newline", () => {
      const root = makeWorkspace()
      try {
        const plain = join(root, "plain.txt")
        const awkward = join(root, "two\nlines.txt")
        writeFileSync(plain, "x")
        writeFileSync(awkward, "x")

        const result = runChown(ownSpec, [plain, awkward])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(SKIP_NO_GNU_CHOWN)("keeps -h in effect, proven by a dangling symlink", () => {
      // A dangling symlink is the unprivileged way to prove the flag: GNU
      // `chown -h` changes the link itself and succeeds, while a dereferencing
      // `chown` cannot resolve the target and fails. Without `-h` this command
      // would follow a planted symlink and rewrite an unrelated target's
      // ownership. BSD `chown` does not fail on a dangling target, so the
      // discriminator only holds on GNU coreutils — which is what paratix
      // targets and what CI runs.
      const root = makeWorkspace()
      try {
        const dangling = join(root, "dangling")
        symlinkSync(join(root, "no-such-target"), dangling)

        const batched = runChown(ownSpec, [dangling])
        const dereferencing = spawnSync("/bin/sh", ["-c", `xargs -0 chown -- '${ownSpec}'`], {
          encoding: "utf8",
          input: encodeNulPayload([dangling]),
          timeout: 10_000,
        })

        expect(batched.code).toBe(0)
        expect(dereferencing.status).not.toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("exits non-zero and names the offending path when a target is missing", () => {
      const root = makeWorkspace()
      try {
        const missing = join(root, "gone.txt")

        const result = runChown(ownSpec, [missing])

        expect(result.code).not.toBe(0)
        expect(result.stderr).toContain("gone.txt")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  describe.skipIf(SKIP_NO_GNU_STAT)("ownership probe (requires GNU stat)", () => {
    it("reports nothing when the owner matches by name", () => {
      const root = makeWorkspace()
      try {
        const owner = currentOwner()
        const file = join(root, "f.txt")
        writeFileSync(file, "x")

        const result = runProbe(buildOwnershipProbeScript(owner.user, owner.group), [file])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports nothing when the owner matches by numeric id", () => {
      const root = makeWorkspace()
      try {
        const owner = currentOwner()
        const file = join(root, "f.txt")
        writeFileSync(file, "x")

        const result = runProbe(buildOwnershipProbeScript(owner.userId, owner.groupId), [file])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a mismatch with all five fields", () => {
      const root = makeWorkspace()
      try {
        const owner = currentOwner()
        const file = join(root, "f.txt")
        writeFileSync(file, "x")

        const result = runProbe(buildOwnershipProbeScript("definitely-not-the-owner", ""), [file])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([
          file,
          owner.user,
          owner.group,
          owner.userId,
          owner.groupId,
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a path it cannot stat, with empty fields", () => {
      const root = makeWorkspace()
      try {
        const missing = join(root, "gone.txt")

        const result = runProbe(buildOwnershipProbeScript("anyone", ""), [missing])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([missing, "", "", "", ""])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("ignores the group when none is declared", () => {
      const root = makeWorkspace()
      try {
        const owner = currentOwner()
        const file = join(root, "f.txt")
        writeFileSync(file, "x")

        const result = runProbe(buildOwnershipProbeScript(owner.user, ""), [file])

        expect(result.code).toBe(0)
        expect(result.fields).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })
})
