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
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { removeEscapingSymlinks } from "../../src/modules/archiveContainmentEnforcement.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  buildPreStagingProbeScript,
  buildSymlinkProbeScript,
  buildSymlinkRemovalScript,
  encodeMemberTypeEntry,
  encodeNulPayload,
  encodePreStagingEntry,
  runBatchedProbe,
  SYMLINK_QUARANTINED_OUTCOME_PREFIX,
  SYMLINK_REMOVED_OUTCOME,
  SYMLINK_RESTORED_OUTCOME,
} from "../../src/modules/archiveProbe.js"
import { renderBatchedChownSymlinkCommand } from "../../src/modules/fileMetadataHelpers.js"
import { localShellConnection } from "../helpers/localShell.js"

type ProbeResult = { code: number; fields: string[]; stderr: string }

/**
 * Run a probe script the way `runBatchedProbe` does: entries NUL-terminated on
 * stdin, violations NUL-terminated on stdout.
 *
 * @param script - The probe script under test.
 * @param entries - The entries to transport.
 * @param env - Issue #219: the environment of the remote shell; the test
 *   runner's environment when omitted.
 * @returns Exit code, decoded output fields and stderr.
 */
function runProbe(script: string, entries: string[], env?: NodeJS.ProcessEnv): ProbeResult {
  const result = spawnSync("/bin/sh", ["-c", script], {
    encoding: "utf8",
    env,
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
 * Issue #219: pair up NUL-decoded probe fields.
 *
 * @param fields - The decoded fields; an odd count leaves `<missing>` in the last pair.
 * @returns The `(first, second)` pairs in output order.
 */
function fieldPairs(fields: readonly string[]): Array<[string, string]> {
  const pairs: Array<[string, string]> = []
  for (let index = 0; index < fields.length; index += 2) {
    pairs.push([fields[index] ?? "", fields[index + 1] ?? "<missing>"])
  }
  return pairs
}

/**
 * Issue #219: the workspace for the removal cases: a destination plus an
 * `outside` directory and file next to it that escaping links point at.
 *
 * @returns The workspace root, the destination and the outside targets.
 */
function makeRemovalWorkspace(): {
  destination: string
  outsideDirectory: string
  outsideFile: string
  root: string
} {
  const root = makeWorkspace()
  const destination = join(root, "destination")
  const outsideDirectory = join(root, "outside")
  const outsideFile = join(root, "outside.txt")
  mkdirSync(destination)
  mkdirSync(outsideDirectory)
  writeFileSync(join(outsideDirectory, "keep.txt"), "keep\n")
  writeFileSync(outsideFile, "outside\n")
  return { destination, outsideDirectory, outsideFile, root }
}

/**
 * Issue #219: whether a path exists as a symlink, without following it.
 *
 * @param path - The path to inspect.
 * @returns True when `lstat` reports a symlink.
 */
function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink()
  } catch {
    return false
  }
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

/**
 * Issue #219: whether an `mv` renames onto a free name with `-n -T` without
 * ever moving into an existing directory, the capability the removal script
 * needs before it moves an entry back out of quarantine.
 *
 * @param mv - The `mv` executable to test.
 * @returns True when `mv -n -T` behaves like GNU coreutils.
 */
function renamesWithoutTargetDirectory(mv: string): boolean {
  const scratch = mkdtempSync(join(tmpdir(), "paratix-mv-probe-"))
  try {
    const script = [
      'mkdir t && : > f && "$0" -n -T f t 2>/dev/null; "$0" -n -T f g 2>/dev/null;',
      "[ -e g ] && [ ! -e f ] && [ ! -e t/f ]",
    ].join(" ")
    return spawnSync("/bin/sh", ["-c", script, mv], { cwd: scratch, timeout: 5000 }).status === 0
  } finally {
    rmSync(scratch, { force: true, recursive: true })
  }
}

/**
 * Issue #219: the absolute path of a command on the test runner's PATH.
 *
 * @param name - The command to look up with `command -v`.
 * @returns The path, or undefined when the command is missing.
 */
function commandPath(name: string): string | undefined {
  const found = spawnSync("/bin/sh", ["-c", 'command -v "$0"', name], { encoding: "utf8" })
  const path = found.stdout.trim()
  return found.status === 0 && path.startsWith("/") ? path : undefined
}

/** Issue #219: the system `mv`, which the removal script runs by default. */
const SYSTEM_MV = commandPath("mv") ?? "/bin/mv"
/** Issue #219: whether the system `mv` supports `-n -T` (GNU coreutils). */
const SYSTEM_MV_HAS_NO_TARGET_DIRECTORY = renamesWithoutTargetDirectory(SYSTEM_MV)
/**
 * Issue #219: an `mv` that supports `-n -T`: the system one where it does
 * (GNU coreutils), else GNU `gmv` when installed, else none.
 */
const NO_TARGET_DIRECTORY_MV = [SYSTEM_MV, commandPath("gmv")]
  .filter((mv): mv is string => mv !== undefined)
  .find((mv) => renamesWithoutTargetDirectory(mv))

/**
 * Issue #219: put an `mv` wrapper first on the removal script's PATH. The
 * wrapper runs `body` with the original arguments and then the real `mv`
 * (`$PARATIX_REAL_MV`), unless `body` exits itself. It stands in for another
 * writer acting at the exact moment the script renames an entry, which no
 * real concurrency could hit deterministically.
 *
 * @param root - A scratch directory for the wrapper.
 * @param body - Shell code run before the real `mv`.
 * @param realMv - The real `mv` the wrapper delegates to.
 * @returns The environment for the local shell.
 */
function interposedMvEnvironment(
  root: string,
  body: string,
  realMv: string = SYSTEM_MV
): NodeJS.ProcessEnv {
  const bin = join(root, "bin")
  mkdirSync(bin, { recursive: true })
  writeFileSync(join(bin, "mv"), `#!/bin/sh\n${body}\nexec "$PARATIX_REAL_MV" "$@"\n`, {
    mode: 0o755,
  })
  return { ...process.env, PARATIX_REAL_MV: realMv, PATH: `${bin}:${process.env.PATH ?? ""}` }
}

/**
 * Issue #219: wrapper body that swaps the link named `$PARATIX_SWAP_NAME` for
 * a regular file just before the script renames it into quarantine, and with
 * `$PARATIX_RETAKE` set creates the name again right after the rename.
 */
const SWAP_ON_QUARANTINE = [
  'if [ "$1" = "--" ] && [ "$2" = "./$PARATIX_SWAP_NAME" ]; then',
  '  rm -f -- "$2" && printf "swapped\\n" > "$2" || exit 1',
  '  "$PARATIX_REAL_MV" "$@" || exit $?',
  '  if [ -n "$PARATIX_RETAKE" ]; then printf "retaken\\n" > "$2"; fi',
  "  exit 0",
  "fi",
].join("\n")

/**
 * Issue #219: the quarantine directories left in a directory.
 *
 * @param directory - The directory to list.
 * @returns The names that start with `.paratix-quarantine.`, sorted.
 */
function quarantineEntries(directory: string): string[] {
  return readdirSync(directory)
    .filter((name) => name.startsWith(".paratix-quarantine."))
    .toSorted()
}

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

  describe("pre-staging probe (Issue #219)", () => {
    const probe = buildPreStagingProbeScript()

    it("reports a symlink for l, a real directory for n and a non-directory for d", () => {
      const root = makeWorkspace()
      try {
        const directory = join(root, "dir")
        const file = join(root, "file")
        const link = join(root, "link")
        mkdirSync(directory)
        writeFileSync(file, "x")
        symlinkSync(directory, link)

        const result = runProbe(probe, [
          encodePreStagingEntry("l", directory),
          encodePreStagingEntry("l", link),
          encodePreStagingEntry("n", file),
          encodePreStagingEntry("n", directory),
          encodePreStagingEntry("d", directory),
          encodePreStagingEntry("d", file),
        ])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          ["l", link],
          ["n", directory],
          ["d", file],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("never reports a symlink for n or d, even when it points at the conflicting type", () => {
      // A symlink at a member path is the `l` check's business; `n` and `d`
      // look at the entry itself, so `[ -d ]` must not follow the link.
      const root = makeWorkspace()
      try {
        const directory = join(root, "dir")
        const file = join(root, "file")
        mkdirSync(directory)
        writeFileSync(file, "x")
        symlinkSync(directory, join(root, "to-dir"))
        symlinkSync(file, join(root, "to-file"))
        symlinkSync(join(root, "missing"), join(root, "dangling"))

        const result = runProbe(probe, [
          encodePreStagingEntry("n", join(root, "to-dir")),
          encodePreStagingEntry("d", join(root, "to-file")),
          encodePreStagingEntry("d", join(root, "dangling")),
          encodePreStagingEntry("n", join(root, "dangling")),
        ])

        expect(result).toStrictEqual({ code: 0, fields: [], stderr: "" })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("treats nonexistent paths as clean for every check", () => {
      const root = makeWorkspace()
      try {
        const missing = join(root, "missing/deeper")

        const result = runProbe(probe, [
          encodePreStagingEntry("l", missing),
          encodePreStagingEntry("n", missing),
          encodePreStagingEntry("d", missing),
        ])

        expect(result).toStrictEqual({ code: 0, fields: [], stderr: "" })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("keeps check and path paired for paths with colons, spaces and newlines", () => {
      const root = makeWorkspace()
      try {
        const directory = join(root, "d:n: with space\nline")
        const file = join(root, "l:d:file")
        mkdirSync(directory)
        writeFileSync(file, "x")

        const result = runProbe(probe, [
          encodePreStagingEntry("d", file),
          encodePreStagingEntry("n", directory),
          encodePreStagingEntry("d", directory),
          encodePreStagingEntry("n", file),
        ])

        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          ["d", file],
          ["n", directory],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports an unknown check code with the kind ? instead of skipping the entry", () => {
      const root = makeWorkspace()
      try {
        const result = runProbe(probe, [`x:${root}`, "no-colon"])

        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          ["?", root],
          ["?", "no-colon"],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  describe("strict UTF-8 transport (Issue #219)", () => {
    it("fails a probe closed when its output is not valid UTF-8, and decodes valid output exactly", async () => {
      // Two paths that differ only in bytes that are not UTF-8 would both
      // decode to U+FFFD leniently; the strict decode refuses the output.
      const invalid = "xargs -0 sh -c 'printf \"d/\\376\\0d/\\377\\0\"' sh"
      const valid = "xargs -0 sh -c 'printf \"d/\\303\\251\\0\"' sh"
      const { conn } = localShellConnection()

      const refused = await runBatchedProbe(conn, { entries: ["x"], script: invalid })
      const accepted = await runBatchedProbe(conn, { entries: ["x"], script: valid })

      expect(refused).toStrictEqual({
        detail: `Command stdout is not valid UTF-8 (exit code 0): ${invalid}`,
        kind: "failed",
      })
      expect(accepted).toStrictEqual({ fields: ["d/\u00e9"], kind: "ok" })
    })
  })

  describe("symlink removal script (Issue #219)", () => {
    it("removes exactly the given symlinks without following them", () => {
      const { destination, outsideDirectory, outsideFile, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        const toDirectory = join(destination, "a/to-dir")
        const toFile = join(destination, "to-file")
        const kept = join(destination, "a/kept")
        symlinkSync("../../outside", toDirectory)
        symlinkSync(outsideFile, toFile)
        symlinkSync("../../outside", kept)

        const result = runProbe(buildSymlinkRemovalScript(destination), [toDirectory, toFile])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          [toDirectory, SYMLINK_REMOVED_OUTCOME],
          [toFile, SYMLINK_REMOVED_OUTCOME],
        ])
        expect(isSymlink(toDirectory)).toBe(false)
        expect(existsSync(toDirectory)).toBe(false)
        expect(isSymlink(toFile)).toBe(false)
        expect(readlinkSync(kept)).toBe("../../outside")
        expect(readdirSync(outsideDirectory)).toStrictEqual(["keep.txt"])
        expect(readFileSync(join(outsideDirectory, "keep.txt"), "utf8")).toBe("keep\n")
        expect(readFileSync(outsideFile, "utf8")).toBe("outside\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses a link whose ancestor is a symlink, so rm is never redirected", () => {
      // `a` points outside; the path `destination/a/l` names `outside/l`.
      const { destination, outsideDirectory, root } = makeRemovalWorkspace()
      try {
        symlinkSync(outsideDirectory, join(destination, "a"))
        symlinkSync("keep.txt", join(outsideDirectory, "l"))
        const throughLink = join(destination, "a/l")

        const result = runProbe(buildSymlinkRemovalScript(destination), [throughLink])

        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          [throughLink, "an ancestor directory is missing or a symlink"],
        ])
        expect(readlinkSync(join(outsideDirectory, "l"))).toBe("keep.txt")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses a link whose parent is a symlink to a directory inside the destination", () => {
      // Issue #219: the parent `a -> c` stays inside, yet `rm` would still act
      // on `c/l` through it. `pwd -P` after `cd -P ./a` reports `<d>/c`, not
      // `<d>/a`, so the link is refused before any path operation on it.
      const { destination, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "c"))
        symlinkSync("..", join(destination, "c/l"))
        symlinkSync("c", join(destination, "a"))
        const throughLink = join(destination, "a/l")

        const result = runProbe(buildSymlinkRemovalScript(destination), [throughLink])

        expect(result).toStrictEqual({
          code: 0,
          fields: [throughLink, "an ancestor directory is missing or a symlink"],
          stderr: "",
        })
        expect(readlinkSync(join(destination, "c/l"))).toBe("..")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses a link below a deeper ancestor that is a symlink and leaves the outside link", () => {
      const { destination, outsideDirectory, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        symlinkSync(outsideDirectory, join(destination, "a/b"))
        symlinkSync("keep.txt", join(outsideDirectory, "l"))
        const throughLink = join(destination, "a/b/l")

        const result = runProbe(buildSymlinkRemovalScript(destination), [throughLink])

        expect(fieldPairs(result.fields)).toStrictEqual([
          [throughLink, "an ancestor directory is missing or a symlink"],
        ])
        expect(readlinkSync(join(outsideDirectory, "l"))).toBe("keep.txt")
        expect(readlinkSync(join(destination, "a/b"))).toBe(outsideDirectory)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("is neither redirected nor corrupted by a hostile CDPATH", () => {
      // Issue #219: with `CDPATH` set, `cd a` may pick `<outside>/a` and print
      // it to stdout. The script unsets `CDPATH` and only ever changes into
      // absolute or `./`-prefixed paths.
      const { destination, outsideDirectory, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(outsideDirectory, "a"))
        symlinkSync("../keep.txt", join(outsideDirectory, "a/l"))
        mkdirSync(join(destination, "a"))
        const link = join(destination, "a/l")
        symlinkSync("../..", link)

        const result = runProbe(buildSymlinkRemovalScript(destination), [link], {
          ...process.env,
          CDPATH: outsideDirectory,
        })

        expect(result).toStrictEqual({
          code: 0,
          fields: [link, SYMLINK_REMOVED_OUTCOME],
          stderr: "",
        })
        expect(isSymlink(link)).toBe(false)
        expect(readlinkSync(join(outsideDirectory, "a/l"))).toBe("../keep.txt")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("unlinks nested and top-level links in their own directory and leaves same-named links elsewhere", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "a/b/c"), { recursive: true })
        const topLevel = join(destination, "l")
        const nested = join(destination, "a/b/c/l")
        const untouched = join(destination, "a/l")
        for (const link of [topLevel, nested, untouched]) symlinkSync("/etc", link)

        const result = runProbe(buildSymlinkRemovalScript(destination), [nested, topLevel])

        expect(result).toStrictEqual({
          code: 0,
          fields: [nested, SYMLINK_REMOVED_OUTCOME, topLevel, SYMLINK_REMOVED_OUTCOME],
          stderr: "",
        })
        expect([isSymlink(topLevel), isSymlink(nested), isSymlink(untouched)]).toStrictEqual([
          false,
          false,
          true,
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("removes a link below a directory whose name ends in a newline, not its namesake without one", () => {
      // Issue #219: command substitution strips trailing newlines; the
      // sentinel keeps `pwd -P` equal to `<d>/dir<newline>`.
      const { destination, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "dir\n"))
        mkdirSync(join(destination, "dir"))
        const link = join(destination, "dir\n/l")
        const namesake = join(destination, "dir/l")
        symlinkSync("../..", link)
        symlinkSync("../..", namesake)

        const result = runProbe(buildSymlinkRemovalScript(destination), [link])

        expect(result).toStrictEqual({
          code: 0,
          fields: [link, SYMLINK_REMOVED_OUTCOME],
          stderr: "",
        })
        expect(isSymlink(link)).toBe(false)
        expect(readlinkSync(namesake)).toBe("../..")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("removes links whose names and parent names start with a dash", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "-a"))
        writeFileSync(join(destination, "-f"), "file\n")
        const topLevel = join(destination, "-rf")
        const nested = join(destination, "-a/-l")
        symlinkSync("..", topLevel)
        symlinkSync("../..", nested)

        const result = runProbe(buildSymlinkRemovalScript(destination), [topLevel, nested])

        expect(result).toStrictEqual({
          code: 0,
          fields: [topLevel, SYMLINK_REMOVED_OUTCOME, nested, SYMLINK_REMOVED_OUTCOME],
          stderr: "",
        })
        expect(readdirSync(destination).toSorted()).toStrictEqual(["-a", "-f"])
        expect(readdirSync(join(destination, "-a"))).toStrictEqual([])
        expect(readFileSync(join(destination, "-f"), "utf8")).toBe("file\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses a link below a missing directory", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        const missing = join(destination, "missing/l")

        const result = runProbe(buildSymlinkRemovalScript(destination), [missing])

        expect(fieldPairs(result.fields)).toStrictEqual([
          [missing, "an ancestor directory is missing or a symlink"],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a regular file or directory at the path as no longer a symlink and keeps it", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        const file = join(destination, "f")
        const directory = join(destination, "d")
        writeFileSync(file, "file\n")
        mkdirSync(directory)
        writeFileSync(join(directory, "inner"), "inner\n")
        const gone = join(destination, "gone")

        const result = runProbe(buildSymlinkRemovalScript(destination), [file, directory, gone])

        expect(fieldPairs(result.fields)).toStrictEqual([
          [file, "no longer a symlink"],
          [directory, "no longer a symlink"],
          [gone, "no longer a symlink"],
        ])
        expect(readFileSync(file, "utf8")).toBe("file\n")
        expect(readFileSync(join(directory, "inner"), "utf8")).toBe("inner\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses paths that are not strictly below the destination", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        const outsideLink = join(root, "outside-link")
        const siblingLink = `${destination}-sibling/l`
        mkdirSync(`${destination}-sibling`)
        symlinkSync("outside", outsideLink)
        symlinkSync("..", siblingLink)

        const result = runProbe(buildSymlinkRemovalScript(destination), [
          outsideLink,
          siblingLink,
          destination,
          `${destination}/`,
        ])

        expect(fieldPairs(result.fields)).toStrictEqual([
          [outsideLink, "not below the destination"],
          [siblingLink, "not below the destination"],
          [destination, "not below the destination"],
          [`${destination}/`, "not below the destination"],
        ])
        expect(readlinkSync(outsideLink)).toBe("outside")
        expect(readlinkSync(siblingLink)).toBe("..")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("removes links whose names contain spaces and newlines", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        const directory = join(destination, "dir with space")
        mkdirSync(directory)
        const newline = join(directory, "two\nlines")
        const trailing = join(directory, "trailing space ")
        const keptSibling = join(directory, "two")
        symlinkSync("../..", newline)
        symlinkSync("../..", trailing)
        symlinkSync("../..", keptSibling)

        const result = runProbe(buildSymlinkRemovalScript(destination), [newline, trailing])

        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          [newline, SYMLINK_REMOVED_OUTCOME],
          [trailing, SYMLINK_REMOVED_OUTCOME],
        ])
        expect(readdirSync(directory)).toStrictEqual(["two"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("keeps a destination whose name contains a quote as a fixed argument", () => {
      const root = makeWorkspace()
      try {
        const destination = join(root, "it's here")
        mkdirSync(destination)
        const link = join(destination, "l")
        symlinkSync("..", link)

        const result = runProbe(buildSymlinkRemovalScript(destination), [link])

        expect(fieldPairs(result.fields)).toStrictEqual([[link, SYMLINK_REMOVED_OUTCOME]])
        expect(isSymlink(link)).toBe(false)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("refuses non-normalized paths on its own and removes nothing inside or outside", () => {
      // The script is hardened independently of the TypeScript vetting: a
      // lexical `<destination>/` prefix must not let `..`, `.` or an empty
      // segment reach `rm`.
      const { destination, root } = makeRemovalWorkspace()
      try {
        const outsideLink = join(root, "outside-link")
        symlinkSync("outside", outsideLink)
        mkdirSync(join(destination, "a"))
        const insideLink = join(destination, "a/l")
        symlinkSync("../..", insideLink)
        const parentSegment = `${destination}/../outside-link`
        const dotSegment = `${destination}/./a/l`
        const emptySegment = `${destination}//a/l`
        const innerDot = `${destination}/a/./l`
        const trailingSlash = `${destination}/a/l/`

        const result = runProbe(buildSymlinkRemovalScript(destination), [
          parentSegment,
          dotSegment,
          emptySegment,
          innerDot,
          trailingSlash,
        ])

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(fieldPairs(result.fields)).toStrictEqual([
          [parentSegment, "not normalized"],
          [dotSegment, "not normalized"],
          [emptySegment, "not normalized"],
          [innerDot, "not normalized"],
          [trailingSlash, "not normalized"],
        ])
        expect(readlinkSync(outsideLink)).toBe("outside")
        expect(readlinkSync(insideLink)).toBe("../..")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("never hands a non-normalized path to the script when driven by removeEscapingSymlinks", async () => {
      // The script refuses `<destination>/../x` itself as well; the TypeScript
      // vetting in front of it must refuse such a path first, so it never
      // reaches the script at all.
      const { destination, root } = makeRemovalWorkspace()
      try {
        const outsideLink = join(root, "outside-link")
        symlinkSync("outside", outsideLink)
        const escaping = join(destination, "esc")
        symlinkSync("..", escaping)
        const dotted = `${destination}/../outside-link`
        const { commands, conn } = localShellConnection()

        const report = await removeEscapingSymlinks(conn, destination, [dotted, escaping, escaping])

        expect(report).toStrictEqual({
          kept: [[dotted, "path is not normalized"]],
          notes: [],
          removed: [escaping],
        })
        expect(commands).toStrictEqual([buildSymlinkRemovalScript(destination)])
        expect(readlinkSync(outsideLink)).toBe("outside")
        expect(isSymlink(escaping)).toBe(false)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("removes a link through quarantine and leaves no quarantine directory behind", () => {
      const { destination, outsideDirectory, root } = makeRemovalWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        const nested = join(destination, "a/esc")
        const top = join(destination, "top")
        symlinkSync("../../outside", nested)
        symlinkSync("..", top)

        const result = runProbe(buildSymlinkRemovalScript(destination), [nested, top])

        expect(fieldPairs(result.fields)).toStrictEqual([
          [nested, SYMLINK_REMOVED_OUTCOME],
          [top, SYMLINK_REMOVED_OUTCOME],
        ])
        expect(readdirSync(join(destination, "a"))).toStrictEqual([])
        expect(readdirSync(destination)).toStrictEqual(["a"])
        expect(readdirSync(outsideDirectory)).toStrictEqual(["keep.txt"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("keeps a regular file that replaced the listed link before the removal ran", async () => {
      // The backstop listed `esc` as a symlink; by the time the removal runs, it
      // is a regular file. The quick `[ -L ]` check reports it and nothing is
      // renamed or deleted.
      const { destination, root } = makeRemovalWorkspace()
      try {
        const listed = join(destination, "esc")
        symlinkSync("..", listed)
        rmSync(listed)
        writeFileSync(listed, "replacement\n")
        const { conn } = localShellConnection()

        const report = await removeEscapingSymlinks(conn, destination, [listed])

        expect(report).toStrictEqual({
          kept: [[listed, "no longer a symlink"]],
          notes: [],
          removed: [],
        })
        expect(readFileSync(listed, "utf8")).toBe("replacement\n")
        expect(quarantineEntries(destination)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(!SYSTEM_MV_HAS_NO_TARGET_DIRECTORY)(
      "never deletes a regular file swapped in at the moment of the rename, and restores it",
      async () => {
        // An `mv` wrapper swaps the link for a regular file right before the
        // script renames it into quarantine, after the `[ -L ]` check passed.
        const { destination, root } = makeRemovalWorkspace()
        try {
          mkdirSync(join(destination, "d"))
          const listed = join(destination, "d/esc")
          symlinkSync("../..", listed)
          const env = {
            ...interposedMvEnvironment(root, SWAP_ON_QUARANTINE),
            PARATIX_SWAP_NAME: "esc",
          }
          const { conn } = localShellConnection({ env })

          const report = await removeEscapingSymlinks(conn, destination, [listed])

          expect(report).toStrictEqual({
            kept: [[listed, "no longer a symlink; restored at its path"]],
            notes: [],
            removed: [],
          })
          expect(readFileSync(listed, "utf8")).toBe("swapped\n")
          expect(quarantineEntries(join(destination, "d"))).toStrictEqual([])
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it.skipIf(SYSTEM_MV_HAS_NO_TARGET_DIRECTORY)(
      "never deletes a regular file swapped in at the moment of the rename, and keeps it in quarantine without mv -T",
      async () => {
        // Without `mv -T` the entry cannot be moved back safely and stays in
        // quarantine, intact.
        const { destination, root } = makeRemovalWorkspace()
        try {
          mkdirSync(join(destination, "d"))
          const listed = join(destination, "d/esc")
          symlinkSync("../..", listed)
          const env = {
            ...interposedMvEnvironment(root, SWAP_ON_QUARANTINE),
            PARATIX_SWAP_NAME: "esc",
          }
          const { conn } = localShellConnection({ env })

          const report = await removeEscapingSymlinks(conn, destination, [listed])

          const [quarantine] = quarantineEntries(join(destination, "d"))
          const quarantined = JSON.stringify(`d/${quarantine}/entry`)
          expect(report).toStrictEqual({
            kept: [
              [
                listed,
                `no longer a symlink; left in quarantine as ${quarantined} below the destination`,
              ],
            ],
            notes: [],
            removed: [],
          })
          expect(readFileSync(join(destination, "d", quarantine, "entry"), "utf8")).toBe(
            "swapped\n"
          )
          expect(existsSync(listed)).toBe(false)
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it.skipIf(NO_TARGET_DIRECTORY_MV === undefined)(
      "restores a swapped-in entry at its free path with its content and removes the quarantine",
      () => {
        const { destination, root } = makeRemovalWorkspace()
        try {
          const listed = join(destination, "esc")
          symlinkSync("..", listed)
          const env = {
            ...interposedMvEnvironment(root, SWAP_ON_QUARANTINE, NO_TARGET_DIRECTORY_MV),
            PARATIX_SWAP_NAME: "esc",
          }

          const result = runProbe(buildSymlinkRemovalScript(destination), [listed], env)

          expect(fieldPairs(result.fields)).toStrictEqual([[listed, SYMLINK_RESTORED_OUTCOME]])
          expect(lstatSync(listed).isFile()).toBe(true)
          expect(readFileSync(listed, "utf8")).toBe("swapped\n")
          expect(quarantineEntries(destination)).toStrictEqual([])
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("leaves the entry in quarantine when its name was taken again, and keeps both intact", () => {
      const { destination, root } = makeRemovalWorkspace()
      try {
        const listed = join(destination, "esc")
        symlinkSync("..", listed)
        const env = {
          ...interposedMvEnvironment(root, SWAP_ON_QUARANTINE, NO_TARGET_DIRECTORY_MV),
          PARATIX_RETAKE: "1",
          PARATIX_SWAP_NAME: "esc",
        }

        const result = runProbe(buildSymlinkRemovalScript(destination), [listed], env)

        const [quarantine] = quarantineEntries(destination)
        expect(fieldPairs(result.fields)).toStrictEqual([
          [listed, `${SYMLINK_QUARANTINED_OUTCOME_PREFIX}${quarantine}/entry`],
        ])
        expect(readFileSync(listed, "utf8")).toBe("retaken\n")
        expect(readFileSync(join(destination, quarantine, "entry"), "utf8")).toBe("swapped\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("leaves quarantine entries from earlier runs untouched", () => {
      const { destination, outsideDirectory, root } = makeRemovalWorkspace()
      try {
        const earlierFile = join(destination, ".paratix-quarantine.AAAAAAAA")
        const earlierDirectory = join(destination, ".paratix-quarantine.BBBBBBBB")
        const earlierLink = join(destination, ".paratix-quarantine.CCCCCCCC")
        writeFileSync(earlierFile, "file\n")
        mkdirSync(earlierDirectory)
        writeFileSync(join(earlierDirectory, "entry"), "entry\n")
        symlinkSync("../outside", earlierLink)
        const escaping = join(destination, "esc")
        symlinkSync("..", escaping)

        const result = runProbe(buildSymlinkRemovalScript(destination), [escaping])

        expect(fieldPairs(result.fields)).toStrictEqual([[escaping, SYMLINK_REMOVED_OUTCOME]])
        expect(quarantineEntries(destination)).toStrictEqual([
          ".paratix-quarantine.AAAAAAAA",
          ".paratix-quarantine.BBBBBBBB",
          ".paratix-quarantine.CCCCCCCC",
        ])
        expect(readFileSync(earlierFile, "utf8")).toBe("file\n")
        expect(readFileSync(join(earlierDirectory, "entry"), "utf8")).toBe("entry\n")
        expect(readlinkSync(earlierLink)).toBe("../outside")
        expect(readdirSync(outsideDirectory)).toStrictEqual(["keep.txt"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("fails closed and keeps the link when mv -n replaces an existing entry", () => {
      // The wrapper drops `-n`, so the no-clobber check in the private
      // quarantine directory sees an entry being replaced.
      const { destination, root } = makeRemovalWorkspace()
      try {
        const escaping = join(destination, "esc")
        symlinkSync("..", escaping)
        const env = interposedMvEnvironment(root, 'if [ "$1" = "-n" ]; then shift; fi')

        const result = runProbe(buildSymlinkRemovalScript(destination), [escaping], env)

        expect(fieldPairs(result.fields)).toStrictEqual([[escaping, "mv -n is unavailable"]])
        expect(readlinkSync(escaping)).toBe("..")
        expect(quarantineEntries(destination)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(process.getuid?.() === 0)(
      "fails closed and keeps the link when no quarantine directory can be created",
      () => {
        const { destination, root } = makeRemovalWorkspace()
        const parent = join(destination, "ro")
        try {
          mkdirSync(parent)
          const escaping = join(parent, "esc")
          symlinkSync("../..", escaping)
          chmodSync(parent, 0o555)

          const result = runProbe(buildSymlinkRemovalScript(destination), [escaping])

          expect(fieldPairs(result.fields)).toStrictEqual([
            [escaping, "quarantine directory could not be created"],
          ])
          expect(readlinkSync(escaping)).toBe("../..")
        } finally {
          chmodSync(parent, 0o755)
          rmSync(root, { force: true, recursive: true })
        }
      }
    )
  })
})
