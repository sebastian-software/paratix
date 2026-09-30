/**
 * Shell-level smoke tests for the `archive.extract` staging merge.
 *
 * Issue #178 showed why these are needed: the newline guard read correctly in
 * TypeScript but was inert on a real shell. `$(printf '\n')` looks like it
 * yields a newline, yet command substitution strips all trailing newlines, so
 * it expanded to the empty string, the `case` pattern degraded to `*`, and
 * every extraction was refused with exit 64. No mock-pattern test could catch
 * that — asserting on the emitted string only proves the string is what we
 * wrote, not what the shell does with it.
 *
 * The tests below therefore execute the production-generated merge script
 * against a real `/bin/sh` and a temporary directory, and assert on the
 * observed filesystem state and exit codes. Same approach as
 * `flagLock.shell.smoke.test.ts`.
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process"
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
import { dirname, join } from "node:path"
import { describe, expect, it } from "vitest"

import type {
  MergedSymlink,
  MergedSymlinkViolation,
} from "../../src/modules/archiveLinkValidation.js"
import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"

import {
  boundedStagingMergeCommand,
  buildStagingMergeExec,
  buildStagingMergeScript,
  type StagingMergeTimeLimits,
} from "../../src/modules/archive.js"
import {
  enforceSymlinkContainment,
  type PreMergeContainmentVerdict,
  preMergeContainmentVerdict,
  symlinkListingEntries,
} from "../../src/modules/archiveContainmentEnforcement.js"
import {
  containmentFlagBody,
  readContainmentFlag,
} from "../../src/modules/archiveContainmentFlag.js"
import { archiveContainmentScope } from "../../src/modules/archiveContainmentScope.js"
import {
  archiveMemberGuardPaths,
  destinationPathWithAncestors,
  preStagingProbeEntries,
} from "../../src/modules/archiveDestinationValidation.js"
import {
  buildKernelCrossCheckScript,
  kernelCrossCheckEntry,
  type KernelCrossCheckPoint,
  runKernelCrossCheck,
} from "../../src/modules/archiveKernelCrossCheck.js"
import { mergedSymlinkResolutions } from "../../src/modules/archiveLinkValidation.js"
import {
  buildPreStagingProbeScript,
  buildSymlinkListingProbeScript,
  encodeNulPayload,
  encodeSymlinkListingEntry,
  symlinkListingBatchScript,
} from "../../src/modules/archiveProbe.js"
import {
  decodeListingField,
  hostStateFromListing,
} from "../../src/modules/archiveSymlinkListing.js"
import { shellQuote } from "../../src/ssh.js"
import { localShellConnection } from "../helpers/localShell.js"

type ShellResult = { code: number; stderr: string; stdout: string }

/**
 * Run the production merge script the way the remote `find -exec sh -c` does.
 *
 * Issue #219: `$3` names a file with the NUL-terminated guard paths, as the
 * outer script of `buildStagingMergeExec` writes it on the host; this helper
 * writes it into its own scratch directory.
 *
 * @param parameters - Invocation inputs.
 * @param parameters.destination - Value for `$1` and `$2` (destination and its expected resolution).
 * @param parameters.guardPaths - Guard paths for the file named by `$3`.
 * @param parameters.sourcePaths - Staging entries passed as the trailing arguments.
 * @returns Exit code and captured output.
 */
function runMergeScript(parameters: {
  destination: string
  guardPaths?: string[]
  sourcePaths: string[]
}): ShellResult {
  const { destination, sourcePaths } = parameters
  const scratch = mkdtempSync(join(tmpdir(), "paratix-merge-guards-"))
  try {
    const guardFile = join(scratch, "guards")
    writeFileSync(guardFile, encodeNulPayload(parameters.guardPaths ?? []))
    const result = spawnSync(
      "/bin/sh",
      ["-c", buildStagingMergeScript(), "sh", destination, destination, guardFile, ...sourcePaths],
      { encoding: "utf8", timeout: 5000 }
    )
    return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
  } finally {
    rmSync(scratch, { force: true, recursive: true })
  }
}

function makeWorkspace(): { destination: string; root: string; staging: string } {
  // `realpathSync` because the script re-resolves the destination with
  // `readlink -f` and refuses a mismatch. On macOS the OS tempdir sits behind
  // the `/var` -> `/private/var` symlink, so an unresolved path would trip that
  // guard in the fixture rather than in the code under test. Production always
  // passes an already-validated, resolved destination.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "paratix-archive-merge-smoke-")))
  const destination = join(root, "destination")
  const staging = join(root, "staging")
  mkdirSync(destination)
  mkdirSync(staging)
  return { destination, root, staging }
}

/**
 * Whether `cp` understands the GNU flags the merge uses (`-T`,
 * `--no-dereference`, `--remove-destination`).
 *
 * paratix targets Linux hosts and CI runs on Linux, so the copy path is covered
 * there. macOS ships BSD `cp`, which rejects those flags — the copy-success
 * cases are skipped on such a host rather than asserting a portability the
 * production code never claimed. Every guard case exits before `cp` is reached
 * and therefore runs everywhere, including the issue #178 newline regression.
 *
 * @returns True when GNU coreutils `cp` is on PATH.
 */
function hasGnuCp(): boolean {
  const result = spawnSync("cp", ["--version"], { encoding: "utf8", timeout: 2000 })
  return result.status === 0 && result.stdout.includes("coreutils")
}

/**
 * Issue #219: an archive member as the tar listing parser produces it, for the
 * product guard-set functions.
 *
 * @param path - Destination-relative member path.
 * @param linkTarget - Symlink target, or null for a regular file.
 * @returns The archive member.
 */
function tarMember(path: string, linkTarget: null | string = null): ArchiveMember {
  return linkTarget === null
    ? { format: "tar", kind: "file", linkTarget, mode: "-rw-r--r--", path }
    : { format: "tar", kind: "symlink", linkTarget, mode: "lrwxrwxrwx", path }
}

/**
 * Issue #219: the guard set `archive.extract` passes to the merge, built with
 * the product functions exactly as `extractViaStagingDirectory` does — the
 * destination with its ancestors plus `archiveMemberGuardPaths`, deduplicated
 * like `moveExtractedContentsIntoDestination`.
 *
 * @param destination - The resolved destination directory.
 * @param members - The archive members.
 * @returns Absolute guard paths.
 */
function productGuardPaths(destination: string, members: ArchiveMember[]): string[] {
  return [
    ...new Set([
      ...destinationPathWithAncestors(destination),
      ...archiveMemberGuardPaths(destination, members),
    ]),
  ]
}

/**
 * Describe a directory tree by entry type, symlink target and file content so
 * two merges can be compared for idempotence.
 *
 * @param root - The directory to describe.
 * @param prefix - Path prefix for the recursion.
 * @returns One sorted line per entry.
 */
function describeTree(root: string, prefix = ""): string[] {
  const lines: string[] = []
  for (const name of readdirSync(join(root, prefix)).toSorted()) {
    const relative = prefix === "" ? name : `${prefix}/${name}`
    const absolute = join(root, relative)
    const stat = lstatSync(absolute)
    if (stat.isSymbolicLink()) lines.push(`l ${relative} -> ${readlinkSync(absolute)}`)
    else if (stat.isDirectory()) lines.push(`d ${relative}`, ...describeTree(root, relative))
    else lines.push(`f ${relative} ${readFileSync(absolute, "utf8")}`)
  }
  return lines
}

type ListingProbeResult = {
  code: number
  /** The `l` records as decoded `(link, target)` pairs, sorted by link. */
  pairs: Array<[string, string]>
  stderr: string
  /** The `u` records, decoded and sorted. */
  unreadable: string[]
}

/**
 * Issue #219: decode one listing field for an assertion.
 *
 * @param field - The raw field.
 * @returns The decoded text, or `<invalid: …>` when it cannot be decoded.
 */
function decodedField(field: string | undefined): string {
  const decoded = decodeListingField(field ?? "<missing>")
  return typeof decoded === "string" ? `<invalid: ${decoded}>` : decoded.text
}

/**
 * Issue #219: run the production listing probe the way `runBatchedProbe`
 * does, with the destination as `r` entry NUL-terminated on stdin. The output
 * must be valid UTF-8, as `strictUtf8Stdout` demands.
 *
 * @param destination - The canonical destination directory.
 * @returns Exit code, the decoded `l` and `u` records, and stderr.
 */
function runListingProbe(destination: string): ListingProbeResult {
  const result = spawnSync("/bin/sh", ["-c", buildSymlinkListingProbeScript()], {
    input: encodeNulPayload([encodeSymlinkListingEntry("r", destination)]),
    timeout: 10_000,
  })
  const stdout = new TextDecoder("utf-8", { fatal: true }).decode(result.stdout)
  const fields = stdout.split("\0")
  if (fields.at(-1) === "") fields.pop()
  const pairs: Array<[string, string]> = []
  const unreadable: string[] = []
  for (let index = 0; index < fields.length;) {
    if (fields[index] === "u") {
      unreadable.push(decodedField(fields[index + 1]))
      index += 2
    } else {
      pairs.push([decodedField(fields[index + 1]), decodedField(fields[index + 2])])
      index += 3
    }
  }
  pairs.sort(([left], [right]) => left.localeCompare(right))
  return {
    code: result.status ?? -1,
    pairs,
    stderr: result.stderr.toString("utf8"),
    unreadable: unreadable.toSorted(),
  }
}

/**
 * Issue #219: whether `find` is GNU find, which the listing probe detects the
 * same way (`-readable`) to report unreadable directories instead of failing.
 *
 * @returns True when `find . -maxdepth 0 -readable` succeeds.
 */
function hasGnuFind(): boolean {
  const result = spawnSync("/bin/sh", ["-c", "find . -maxdepth 0 -readable"], {
    encoding: "utf8",
    timeout: 2000,
  })
  return result.status === 0
}

/**
 * Issue #219: whether the system `readlink` always appends one newline, even
 * to a target that already ends in one. GNU coreutils and busybox do, so the
 * listing probe strips exactly that newline and keeps the target intact. The
 * BSD `readlink` on macOS omits its newline when the target already ends in
 * one, so the probe cannot tell `x\n` from `x` there.
 *
 * @returns True when `readlink` prints `x\n\n` for the target `x\n`.
 */
function readlinkAlwaysAppendsNewline(): boolean {
  const root = mkdtempSync(join(tmpdir(), "paratix-readlink-probe-"))
  try {
    const link = join(root, "link")
    symlinkSync("x\n", link)
    const result = spawnSync("/bin/sh", ["-c", 'command -p readlink -- "$1"', "sh", link], {
      encoding: "utf8",
      timeout: 2000,
    })
    return result.status === 0 && result.stdout === "x\n\n"
  } finally {
    rmSync(root, { force: true, recursive: true })
  }
}

/**
 * Issue #219: whether `command -p timeout` runs, which
 * `boundedStagingMergeCommand` relies on. Linux hosts ship it with GNU
 * coreutils on the default system PATH; macOS has no `timeout` there (only
 * Homebrew's, which `command -p` does not see), so the bounded merge cases are
 * skipped on such a host.
 *
 * @returns True when `command -p timeout --version` succeeds.
 */
function hasCommandPTimeout(): boolean {
  const result = spawnSync("/bin/sh", ["-c", "command -p timeout --version"], {
    encoding: "utf8",
    timeout: 2000,
  })
  return result.status === 0
}

const SKIP_PLATFORM = process.platform === "win32"
const HAS_GNU_FIND = !SKIP_PLATFORM && hasGnuFind()
const SKIP_NO_GNU_CP = !hasGnuCp()
const HAS_COMMAND_P_TIMEOUT = !SKIP_PLATFORM && hasCommandPTimeout()
const SKIP_NO_TRAILING_NEWLINE_READLINK = SKIP_PLATFORM || !readlinkAlwaysAppendsNewline()
// A privileged user reads directories regardless of their mode.
const SKIP_AS_ROOT = process.getuid?.() === 0
// Issue #219: GNU find reports unreadable directories; other finds fail closed.
const SKIP_UNLESS_UNREADABLE_FAILS = SKIP_AS_ROOT || HAS_GNU_FIND
const SKIP_UNLESS_UNREADABLE_REPORTED = SKIP_AS_ROOT || !HAS_GNU_FIND

/**
 * Issue #219: the message tail of every post-merge violation: the backstop
 * only reports and says so.
 */
const BACKSTOP_REPORT_TAIL =
  "after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship; nothing was removed or changed; remove the offending symlinks under the destination or point them inside it manually before the next run; the containment flag records them and keeps check at needs-apply, and a later apply of any source clears it only after re-verifying them"

describe.skipIf(SKIP_PLATFORM)("archive.extract staging merge shell smoke tests", () => {
  it("refuses a staging entry whose name contains a literal newline", () => {
    const { destination, root, staging } = makeWorkspace()
    try {
      const sourceFile = join(staging, "two\nlines")
      writeFileSync(sourceFile, "payload\n")

      const result = runMergeScript({ destination, sourcePaths: [sourceFile] })

      expect(result.code).toBe(64)
      expect(result.stderr).toContain("extracted path contains a newline")
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("accepts an ordinary path instead of refusing every entry (issue #178 regression)", () => {
    // The defect: the guard matched `*""*` and refused unconditionally, so
    // `archive.extract` could not complete against any archive. Reaching the
    // `cp` stage at all is the regression signal, which is why this assertion
    // is on the refusal message and not on the copy result — the copy needs
    // GNU `cp` and is covered separately below.
    const { destination, root, staging } = makeWorkspace()
    try {
      const sourceFile = join(staging, "harmless-path")
      writeFileSync(sourceFile, "payload\n")

      const result = runMergeScript({ destination, sourcePaths: [sourceFile] })

      expect(result.stderr).not.toContain("extracted path contains a newline")
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("refuses the merge when a guarded destination path is a symlink", () => {
    const { destination, root, staging } = makeWorkspace()
    try {
      const sourceFile = join(staging, "payload.txt")
      writeFileSync(sourceFile, "payload\n")
      const guarded = join(destination, "guarded")
      symlinkSync(join(root, "elsewhere"), guarded)

      const result = runMergeScript({
        destination,
        guardPaths: [guarded],
        sourcePaths: [sourceFile],
      })

      expect(result.code).toBe(64)
      expect(result.stderr).toContain("is a symlink")
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("refuses the merge when the target path in the destination is a symlink", () => {
    const { destination, root, staging } = makeWorkspace()
    try {
      const sourceFile = join(staging, "payload.txt")
      writeFileSync(sourceFile, "payload\n")
      symlinkSync(join(root, "elsewhere"), join(destination, "payload.txt"))

      const result = runMergeScript({ destination, sourcePaths: [sourceFile] })

      expect(result.code).toBe(64)
      expect(result.stderr).toContain("is a symlink")
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("still refuses a destination symlink where the staged entry is a directory (Issue #219)", () => {
    const { destination, root, staging } = makeWorkspace()
    try {
      const incoming = join(staging, "shared")
      mkdirSync(incoming)
      writeFileSync(join(incoming, "added.txt"), "added\n")
      const elsewhere = join(root, "elsewhere")
      mkdirSync(elsewhere)
      symlinkSync(elsewhere, join(destination, "shared"))

      const result = runMergeScript({ destination, sourcePaths: [incoming] })

      expect(result.code).toBe(64)
      expect(result.stderr).toContain("is a symlink")
      expect(readdirSync(elsewhere)).toStrictEqual([])
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("lets a staged symlink reach cp when the destination entry is already a symlink (Issue #219)", () => {
    // Only a staged symlink may replace a destination symlink: `cp -aT
    // --no-dereference --remove-destination` swaps the link and never writes
    // through it. Reaching `cp` is the signal here, so this runs without GNU cp.
    const { destination, root, staging } = makeWorkspace()
    try {
      const incoming = join(staging, "current")
      symlinkSync("releases/new", incoming)
      symlinkSync("releases/old", join(destination, "current"))

      const result = runMergeScript({ destination, sourcePaths: [incoming] })

      expect(result.stderr).not.toContain("refusing staging merge")
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  it("succeeds with no staging entries at all", () => {
    // `find -mindepth 1 -maxdepth 1 -exec … {} +` runs the script zero times on
    // an empty staging directory, but an explicit no-entry invocation must not
    // fail either.
    const { destination, root } = makeWorkspace()
    try {
      const result = runMergeScript({ destination, sourcePaths: [] })

      expect(result.stderr).toBe("")
      expect(result.code).toBe(0)
    } finally {
      rmSync(root, { force: true, recursive: true })
    }
  })

  describe.skipIf(SKIP_NO_GNU_CP)("copy behavior (requires GNU cp)", () => {
    it("copies an ordinary staging entry into the destination", () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        const sourceFile = join(staging, "config.yml")
        writeFileSync(sourceFile, "hello: world\n")

        const result = runMergeScript({ destination, sourcePaths: [sourceFile] })

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(readFileSync(join(destination, "config.yml"), "utf8")).toBe("hello: world\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("copies an entry whose path contains spaces and quotes but no newline", () => {
      // The guard must reject newlines only. A path with other awkward bytes is
      // legitimate and has to survive the merge untouched.
      const { destination, root, staging } = makeWorkspace()
      try {
        const sourceFile = join(staging, `a file'with "quotes`)
        writeFileSync(sourceFile, "payload\n")

        const result = runMergeScript({ destination, sourcePaths: [sourceFile] })

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(readFileSync(join(destination, `a file'with "quotes`), "utf8")).toBe("payload\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("merges into a pre-existing destination directory of the same name (R-0000221)", () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        const existing = join(destination, "shared")
        mkdirSync(existing)
        writeFileSync(join(existing, "keep.txt"), "keep\n")

        const incoming = join(staging, "shared")
        mkdirSync(incoming)
        writeFileSync(join(incoming, "added.txt"), "added\n")

        const result = runMergeScript({ destination, sourcePaths: [incoming] })

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(readFileSync(join(existing, "added.txt"), "utf8")).toBe("added\n")
        expect(readFileSync(join(existing, "keep.txt"), "utf8")).toBe("keep\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("merges a second top-level entry after one that ships sibling symlinks (Issue #219)", () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        const corepackTarget = "../lib/node_modules/corepack/dist/corepack.js"
        mkdirSync(join(staging, "externals/node20/bin"), { recursive: true })
        mkdirSync(join(staging, "externals/node20/lib/node_modules/corepack/dist"), {
          recursive: true,
        })
        writeFileSync(
          join(staging, "externals/node20/lib/node_modules/corepack/dist/corepack.js"),
          "corepack\n"
        )
        symlinkSync(corepackTarget, join(staging, "externals/node20/bin/corepack"))
        writeFileSync(join(staging, "run.sh"), "#!/bin/sh\n")
        const members = [
          tarMember("externals/node20/lib/node_modules/corepack/dist/corepack.js"),
          tarMember("externals/node20/bin/corepack", corepackTarget),
          tarMember("run.sh"),
        ]

        const guardPaths = productGuardPaths(destination, members)
        // The product guard set keeps the symlink's ancestors and drops its leaf.
        expect(guardPaths).toContain(join(destination, "externals/node20/bin"))
        expect(guardPaths).not.toContain(join(destination, "externals/node20/bin/corepack"))

        const result = runMergeScript({
          destination,
          guardPaths,
          sourcePaths: [join(staging, "externals"), join(staging, "run.sh")],
        })

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        const corepack = join(destination, "externals/node20/bin/corepack")
        expect(readlinkSync(corepack)).toBe(corepackTarget)
        expect(readFileSync(corepack, "utf8")).toBe("corepack\n")
        expect(readFileSync(join(destination, "run.sh"), "utf8")).toBe("#!/bin/sh\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("re-merges over the archive's own symlinks from an earlier run idempotently (Issue #219)", () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        mkdirSync(join(staging, "releases/x/bin"), { recursive: true })
        mkdirSync(join(staging, "releases/x/lib"))
        writeFileSync(join(staging, "releases/x/lib/tool.js"), "tool\n")
        symlinkSync("../lib/tool.js", join(staging, "releases/x/bin/tool"))
        symlinkSync("releases/x", join(staging, "current"))
        const members = [
          tarMember("releases/x/lib/tool.js"),
          tarMember("releases/x/bin/tool", "../lib/tool.js"),
          tarMember("current", "releases/x"),
        ]
        const merge = (): ShellResult =>
          runMergeScript({
            destination,
            guardPaths: productGuardPaths(destination, members),
            sourcePaths: [join(staging, "releases"), join(staging, "current")],
          })

        const first = merge()
        expect(first.stderr).toBe("")
        expect(first.code).toBe(0)
        const afterFirstRun = describeTree(destination)

        const second = merge()

        expect(second.stderr).toBe("")
        expect(second.code).toBe(0)
        expect(describeTree(destination)).toStrictEqual(afterFirstRun)
        expect(readlinkSync(join(destination, "current"))).toBe("releases/x")
        expect(readFileSync(join(destination, "current/bin/tool"), "utf8")).toBe("tool\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("replaces a destination symlink with a staged symlink without writing through it (Issue #219)", () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        const elsewhere = join(root, "elsewhere")
        mkdirSync(elsewhere)
        writeFileSync(join(elsewhere, "keep.txt"), "keep\n")
        symlinkSync(elsewhere, join(destination, "current"))
        symlinkSync("releases/new", join(staging, "current"))

        const result = runMergeScript({ destination, sourcePaths: [join(staging, "current")] })

        expect(result.stderr).toBe("")
        expect(result.code).toBe(0)
        expect(readlinkSync(join(destination, "current"))).toBe("releases/new")
        expect(readdirSync(elsewhere)).toStrictEqual(["keep.txt"])
        expect(readFileSync(join(elsewhere, "keep.txt"), "utf8")).toBe("keep\n")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })
})

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract symlink listing probe shell smoke tests (Issue #219)",
  () => {
    it("lists every symlink with its raw target as NUL-framed pairs and nothing else", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a/lib"), { recursive: true })
        writeFileSync(join(destination, "a/lib/f"), "f\n")
        writeFileSync(join(destination, "plain"), "plain\n")
        symlinkSync("lib/f", join(destination, "a/inside"))
        symlinkSync("..", join(destination, "a/up"))
        symlinkSync("up/..", join(destination, "a/esc"))
        symlinkSync("missing/y/z", join(destination, "a/dangling"))
        symlinkSync("/etc", join(destination, "etc"))
        symlinkSync(`${destination}/a/lib`, join(destination, "absolute-inside"))

        const result = runListingProbe(destination)

        expect(result).toStrictEqual({
          code: 0,
          pairs: [
            ["a/dangling", "missing/y/z"],
            ["a/esc", "up/.."],
            ["a/inside", "lib/f"],
            ["a/up", ".."],
            ["absolute-inside", `${destination}/a/lib`],
            ["etc", "/etc"],
          ].toSorted(([left = ""], [right = ""]) => left.localeCompare(right)),
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports nothing and succeeds for a destination without symlinks", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        writeFileSync(join(destination, "a/f"), "f\n")

        expect(runListingProbe(destination)).toStrictEqual({
          code: 0,
          pairs: [],
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("does not follow a symlinked directory out of the destination", () => {
      const { destination, root } = makeWorkspace()
      try {
        const elsewhere = join(root, "elsewhere")
        mkdirSync(elsewhere)
        symlinkSync("/etc", join(elsewhere, "outside-link"))
        symlinkSync(elsewhere, join(destination, "to-elsewhere"))

        expect(runListingProbe(destination)).toStrictEqual({
          code: 0,
          pairs: [["to-elsewhere", elsewhere]],
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("transports link names with newlines and spaces and targets with spaces faithfully", () => {
      const { destination, root } = makeWorkspace()
      try {
        const directory = join(destination, "dir with space")
        mkdirSync(directory)
        symlinkSync("..", join(directory, "two\nlines"))
        symlinkSync("target with space", join(directory, "link with space"))
        symlinkSync("../other dir/f", join(directory, "trailing space "))

        expect(runListingProbe(destination)).toStrictEqual({
          code: 0,
          pairs: [
            ["dir with space/link with space", "target with space"],
            ["dir with space/trailing space ", "../other dir/f"],
            ["dir with space/two\nlines", ".."],
          ],
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("keeps a newline inside a target and a target that starts with a newline", () => {
      const { destination, root } = makeWorkspace()
      try {
        symlinkSync("up\n/..", join(destination, "embedded"))
        symlinkSync("\nleading", join(destination, "leading"))

        expect(runListingProbe(destination)).toStrictEqual({
          code: 0,
          pairs: [
            ["embedded", "up\n/.."],
            ["leading", "\nleading"],
          ],
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    // BSD `readlink` (macOS) prints no newline of its own after a target that
    // already ends in one, so the probe's single-newline strip eats the
    // target's own newline there. Linux hosts use GNU or busybox `readlink`.
    it.skipIf(SKIP_NO_TRAILING_NEWLINE_READLINK)(
      "keeps trailing newlines of a target (requires a readlink that always appends one)",
      () => {
        const { destination, root } = makeWorkspace()
        try {
          symlinkSync("up\n", join(destination, "one"))
          symlinkSync("up\n\n", join(destination, "two"))

          expect(runListingProbe(destination)).toStrictEqual({
            code: 0,
            pairs: [
              ["one", "up\n"],
              ["two", "up\n\n"],
            ],
            stderr: "",
            unreadable: [],
          })
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("fails closed with a non-zero exit when the destination does not exist", () => {
      const { destination, root } = makeWorkspace()
      try {
        const result = runListingProbe(join(destination, "missing"))

        expect(result.code).not.toBe(0)
        expect(result.pairs).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    // Issue #219: without GNU find (busybox, the BSDs, macOS) the probe cannot
    // tell an unreadable directory from any other traversal error.
    it.skipIf(SKIP_UNLESS_UNREADABLE_FAILS)(
      "fails closed with a non-zero exit when find cannot read a subdirectory (without GNU find)",
      () => {
        const { destination, root } = makeWorkspace()
        const locked = join(destination, "locked")
        try {
          symlinkSync("..", join(destination, "visible"))
          mkdirSync(locked)
          symlinkSync("../..", join(locked, "hidden"))
          chmodSync(locked, 0o000)

          const result = runListingProbe(destination)

          // A partial listing must not look complete: `visible` may be
          // reported, but the exit status makes the caller refuse it.
          expect(result.code).not.toBe(0)
          expect(result.stderr).not.toBe("")
        } finally {
          chmodSync(locked, 0o755)
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it.skipIf(SKIP_UNLESS_UNREADABLE_REPORTED)(
      "reports an unreadable or unsearchable directory as a u record and lists the rest (GNU find)",
      () => {
        const { destination, root } = makeWorkspace()
        const locked = join(destination, "locked")
        const unsearchable = join(destination, "unsearchable")
        try {
          symlinkSync("..", join(destination, "visible"))
          mkdirSync(join(locked, "sub"), { recursive: true })
          symlinkSync("../..", join(locked, "sub/hidden"))
          mkdirSync(unsearchable)
          symlinkSync("x", join(unsearchable, "hidden"))
          chmodSync(locked, 0o000)
          chmodSync(unsearchable, 0o600)

          expect(runListingProbe(destination)).toStrictEqual({
            code: 0,
            pairs: [["visible", ".."]],
            stderr: "",
            unreadable: ["locked", "unsearchable"],
          })
        } finally {
          chmodSync(locked, 0o755)
          chmodSync(unsearchable, 0o755)
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("hex-encodes names outside printable ASCII so they round-trip exactly", () => {
      const { destination, root } = makeWorkspace()
      try {
        symlinkSync("Þfoo/ü", join(destination, "Þfoo"))
        symlinkSync("x\u0001y", join(destination, "ctl\u007f"))
        symlinkSync("t\ufffd", join(destination, "literal-fffd"))

        const result = spawnSync("/bin/sh", ["-c", buildSymlinkListingProbeScript()], {
          input: encodeNulPayload([encodeSymlinkListingEntry("r", destination)]),
          timeout: 10_000,
        })

        // Only printable ASCII, the hex marker and NUL reach stdout.
        expect([...result.stdout].every((byte) => byte <= 0x7e)).toBe(true)
        expect(runListingProbe(destination)).toStrictEqual({
          code: 0,
          pairs: [
            ["ctl\u007f", "x\u0001y"],
            ["literal-fffd", "t\ufffd"],
            ["Þfoo", "Þfoo/ü"],
          ].toSorted(([left = ""], [right = ""]) => left.localeCompare(right)),
          stderr: "",
          unreadable: [],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("skips a link that vanished between find and readlink", () => {
      const { destination, root } = makeWorkspace()
      try {
        symlinkSync("..", join(destination, "kept"))
        const result = spawnSync(
          "/bin/sh",
          [
            "-c",
            symlinkListingBatchScript(),
            "sh",
            "l",
            destination,
            join(destination, "gone"),
            join(destination, "kept"),
          ],
          { encoding: "utf8", timeout: 10_000 }
        )

        expect({ code: result.status, stderr: result.stderr, stdout: result.stdout }).toStrictEqual(
          {
            code: 0,
            stderr: "",
            stdout: "l\u0000kept\u0000..\u0000",
          }
        )
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("fails a batch whose link still exists but cannot be read", () => {
      const { destination, root } = makeWorkspace()
      try {
        symlinkSync("..", join(destination, "kept"))
        // `command -p` ignores PATH, so a missing `readlink` is simulated by
        // shadowing `command` with a function that fails like `command -p`
        // does without `readlink` (127): the batch still sees the link through
        // `[ -L ]` and must exit 1 instead of skipping it.
        const result = spawnSync(
          "/bin/sh",
          [
            "-c",
            `command() { return 127; }; ${symlinkListingBatchScript()}`,
            "sh",
            "l",
            destination,
            join(destination, "kept"),
          ],
          { encoding: "utf8", timeout: 10_000 }
        )

        expect({ code: result.status, stdout: result.stdout }).toStrictEqual({
          code: 1,
          stdout: "",
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

/**
 * Issue #219: split a compact tree spec entry: `x/` is a directory, `x -> t` a
 * symlink to `t`, anything else a regular file.
 *
 * @param entry - One `path`, `path/` or `path -> target` line of a tree spec.
 * @returns The path, and the link target for a symlink entry, otherwise null.
 */
function parseSpecEntry(entry: string): { path: string; target: null | string } {
  const separator = entry.indexOf(" -> ")
  if (separator === -1) return { path: entry, target: null }
  return { path: entry.slice(0, separator), target: entry.slice(separator + " -> ".length) }
}

/**
 * Issue #219: an archive member built from a tree spec entry (see
 * {@link parseSpecEntry}).
 *
 * @param entry - One `path`, `path/` or `path -> target` line of a tree spec.
 * @returns The archive member as the tar listing parser produces it.
 */
function specMember(entry: string): ArchiveMember {
  const { path, target } = parseSpecEntry(entry)
  if (target !== null) return tarMember(path, target)
  if (path.endsWith("/")) {
    return { format: "tar", kind: "directory", linkTarget: null, mode: "drwxr-xr-x", path }
  }
  return tarMember(path)
}

/**
 * Issue #219: create a tree from spec entries (see {@link specMember}) below
 * `root`, creating missing parent directories on the way. `$DEST` in a link
 * target is replaced with `destination`.
 *
 * @param root - The directory to build in.
 * @param spec - The tree spec entries, parents before children.
 * @param destination - The value of `$DEST` in link targets.
 */
function buildTree(root: string, spec: readonly string[], destination: string): void {
  for (const entry of spec) {
    const { path, target } = parseSpecEntry(entry)
    const absolute = join(root, path)
    mkdirSync(dirname(absolute), { recursive: true })
    if (target !== null) symlinkSync(target.replaceAll("$DEST", destination), absolute)
    else if (path.endsWith("/")) mkdirSync(absolute, { recursive: true })
    else writeFileSync(absolute, `${path}\n`)
  }
}

type ProbeFields = { code: number; fields: string[]; stderr: string }

/**
 * Issue #219: run a production probe script the way `runBatchedProbe` does.
 *
 * @param script - The production script to run under `/bin/sh -c`.
 * @param entries - The NUL-transported entries.
 * @returns Exit code, the decoded fields in output order, and stderr.
 */
function runProbeScript(script: string, entries: readonly string[]): ProbeFields {
  const result = spawnSync("/bin/sh", ["-c", script], {
    encoding: "utf8",
    input: encodeNulPayload([...entries]),
    timeout: 10_000,
  })
  const fields = result.stdout.split("\0")
  if (fields.at(-1) === "") fields.pop()
  return { code: result.status ?? -1, fields, stderr: result.stderr }
}

/**
 * Issue #219: run the production pre-staging probe for an archive.
 *
 * @param destination - The canonical destination directory.
 * @param members - The archive members.
 * @returns The `(check, path)` pairs it reported, in output order.
 */
function runPreStagingProbe(
  destination: string,
  members: ArchiveMember[]
): Array<readonly [string, string]> {
  const entries = [...preStagingProbeEntries(destination, members).keys()]
  const { code, fields, stderr } = runProbeScript(buildPreStagingProbeScript(), entries)
  expect({ code, stderr }).toStrictEqual({ code: 0, stderr: "" })
  const pairs: Array<readonly [string, string]> = []
  for (let index = 0; index < fields.length; index += 2) {
    pairs.push([fields[index] ?? "", fields[index + 1] ?? "<missing>"])
  }
  return pairs
}

/**
 * Issue #219: the pre-merge model verdict, computed the production way: the
 * real listing probe over the real destination, judged by
 * `preMergeContainmentVerdict`.
 *
 * @param destination - The canonical destination directory.
 * @param members - The archive members.
 * @returns What `preMergeContainmentVerdict` decides for the archive on this host.
 */
function modelVerdict(destination: string, members: ArchiveMember[]): PreMergeContainmentVerdict {
  const { code, fields, stderr } = runProbeScript(
    buildSymlinkListingProbeScript(),
    symlinkListingEntries(destination, members)
  )
  expect({ code, stderr }).toStrictEqual({ code: 0, stderr: "" })
  return preMergeContainmentVerdict(destination, fields, members)
}

/**
 * Issue #219: run the staging merge exactly as `archive.extract` issues it:
 * the command and stdin of `buildStagingMergeExec`, with the product guard
 * set, bounded by `boundedStagingMergeCommand` where `command -p timeout` exists.
 * Without it (e.g. macOS with GNU `cp` from Homebrew on PATH) the bare merge
 * runs; the wrapper only passes the exit status through, so the merge outcome
 * is the same.
 *
 * @param parameters - Merge inputs.
 * @param parameters.destination - The canonical destination directory.
 * @param parameters.members - The archive members, for the guard set.
 * @param parameters.staging - The staging directory holding the extracted archive.
 * @returns Exit code and captured output.
 */
function runProductionMerge(parameters: {
  destination: string
  members: ArchiveMember[]
  staging: string
}): ShellResult {
  const { destination, members, staging } = parameters
  const { command, input } = buildStagingMergeExec({
    destination,
    guardPaths: productGuardPaths(destination, members),
    staging,
  })
  const bounded = HAS_COMMAND_P_TIMEOUT ? boundedStagingMergeCommand(command) : command
  const result = spawnSync("/bin/sh", ["-c", bounded], {
    encoding: "utf8",
    input,
    timeout: 10_000,
  })
  return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
}

/** Issue #219: one violation of the post-merge backstop: the link's key and why. */
type BackstopViolation = readonly [key: string, kind: MergedSymlinkViolation["kind"]]

/**
 * Issue #219: every symlink below `destination` as an archive symlink member,
 * so a backstop judged with these members judges every link in the tree, as
 * if the archive had shipped all of them.
 *
 * @param destination - The canonical destination directory.
 * @param prefix - Path prefix for the recursion.
 * @returns One symlink member per link, with its stored target.
 */
function treeLinksAsMembers(destination: string, prefix = ""): ArchiveMember[] {
  const members: ArchiveMember[] = []
  for (const name of readdirSync(join(destination, prefix)).toSorted()) {
    const relative = prefix === "" ? name : `${prefix}/${name}`
    const stat = lstatSync(join(destination, relative))
    if (stat.isDirectory()) members.push(...treeLinksAsMembers(destination, relative))
    else if (stat.isSymbolicLink()) {
      members.push(tarMember(relative, readlinkSync(join(destination, relative))))
    }
  }
  return members
}

/**
 * Issue #219: the post-merge backstop's verdict on the real tree, computed the
 * production way: the real listing probe with the destination as its only `r`
 * entry, decoded by `hostStateFromListing` without requested member paths and
 * judged by `mergedSymlinkResolutions` with the archive's scope, as
 * `enforceSymlinkContainment` does; nothing on the host resolves a link. An
 * archive without symlink members is not judged at all, like in production.
 *
 * @param destination - The canonical destination directory.
 * @param members - The archive members; every link in the tree by default
 *   (see {@link treeLinksAsMembers}).
 * @returns The violations, sorted by key.
 */
function backstopViolations(
  destination: string,
  members: readonly ArchiveMember[] = treeLinksAsMembers(destination)
): BackstopViolation[] {
  if (!members.some(({ kind }) => kind === "symlink")) return []
  const { code, fields, stderr } = runProbeScript(buildSymlinkListingProbeScript(), [
    encodeSymlinkListingEntry("r", destination),
  ])
  expect({ code, stderr }).toStrictEqual({ code: 0, stderr: "" })
  const host = hostStateFromListing(destination, fields, new Map())
  if (typeof host === "string") throw new Error(`unexpected post-merge listing: ${host}`)
  const { violations } = mergedSymlinkResolutions(host.links, {
    ...archiveContainmentScope(members),
    unreadable: host.unreadable,
  })
  return violations
    .map(({ key, kind }): BackstopViolation => [key, kind])
    .toSorted(([left], [right]) => left.localeCompare(right))
}

/**
 * Issue #219: the destination-relative paths of the links the backstop
 * reports for an archive, escaping or beyond the resolution limit.
 *
 * @param destination - The canonical destination directory.
 * @param members - The archive members.
 * @returns The violating links, sorted.
 */
function escapingLinks(destination: string, members: readonly ArchiveMember[]): string[] {
  return backstopViolations(destination, members).map(([key]) => key)
}

/**
 * Issue #219: every symlink below `destination` that the kernel resolves to a
 * path outside it, found with `realpathSync.native` (the OS `realpath(3)`) —
 * independent of the listing probe and the TypeScript resolver. The plain
 * `realpathSync` is no oracle here: it joins a link target onto the link's
 * directory with `path.resolve`, which folds `x/..` lexically instead of
 * walking through `x`. A link that does not resolve
 * (ENOENT for a dangling link, ELOOP for a loop) is not provably contained and
 * is left out; the backstop may report it or not.
 *
 * @param destination - The canonical destination directory.
 * @param prefix - Path prefix for the recursion.
 * @returns The destination-relative paths of the physically escaping links.
 */
function physicallyEscapingLinks(destination: string, prefix = ""): string[] {
  const escaping: string[] = []
  for (const name of readdirSync(join(destination, prefix)).toSorted()) {
    const relative = prefix === "" ? name : `${prefix}/${name}`
    const absolute = join(destination, relative)
    const stat = lstatSync(absolute)
    if (stat.isDirectory()) escaping.push(...physicallyEscapingLinks(destination, relative))
    else if (stat.isSymbolicLink() && physicalTargetIsOutside(destination, absolute)) {
      escaping.push(relative)
    }
  }
  return escaping
}

/**
 * Issue #219: whether the kernel resolves a link to a path outside the
 * destination.
 *
 * @param destination - The canonical destination directory.
 * @param link - The absolute link path.
 * @returns True when the link resolves and lands outside; false when it lands
 *   inside or does not resolve at all.
 */
function physicalTargetIsOutside(destination: string, link: string): boolean {
  let resolved: string
  try {
    resolved = realpathSync.native(link)
  } catch {
    return false
  }
  return resolved !== destination && !resolved.startsWith(`${destination}/`)
}

/**
 * Issue #219: whether the kernel fails to resolve a path with ELOOP.
 *
 * @param path - The path to resolve.
 * @returns True when `realpathSync.native` throws ELOOP.
 */
function physicallyLoops(path: string): boolean {
  try {
    realpathSync.native(path)
    return false
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ELOOP"
  }
}

/**
 * Issue #219: condense a model verdict for table comparison.
 *
 * @param verdict - What `preMergeContainmentVerdict` returned.
 * @returns `ok`, `violations`, `invalid` or `conflict:<reason>@<key>`.
 */
function verdictLabel(verdict: PreMergeContainmentVerdict): string {
  if (verdict.kind === "conflict") return `conflict:${verdict.reason}@${verdict.key}`
  return verdict.kind
}

// Issue #219: the two-run case the pre-merge model used to get wrong. Run 1
// leaves `a/b/` as a real directory with `a/b/hl -> ../..` (inside: it
// resolves to the destination). Run 2 ships `a/b -> q` plus `a/c/l ->
// ../b/hl/..`. The old model let `a/b -> q` replace the directory, so `a/c/l`
// resolved via `a/q/hl/..` inside; `cp` cannot replace a directory with a
// symlink, copies `a/c` anyway and fails, and `a/c/l` then walks the host
// directory `a/b` and its link `hl` to the destination's parent.
const twoRunFirstHost = ["a/", "a/b/", "a/b/hl -> ../.."]
const twoRunSecondArchive = ["a/", "a/b -> q", "a/c/", "a/c/l -> ../b/hl/.."]

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract two-run directory conflict, pre-merge (Issue #219)",
  () => {
    it("refuses run 2 in the pre-staging probe and the pre-merge model without touching the tree", () => {
      // Run 1's result is built directly with fs, so no GNU cp is needed here.
      const { destination, root } = makeWorkspace()
      try {
        buildTree(destination, twoRunFirstHost, destination)
        const before = describeTree(destination)
        const members = twoRunSecondArchive.map((entry) => specMember(entry))

        const preStaging = runPreStagingProbe(destination, members)
        const verdict = modelVerdict(destination, members)

        expect(preStaging).toStrictEqual([["n", join(destination, "a/b")]])
        expect(verdict).toStrictEqual({
          key: "a/b",
          kind: "conflict",
          member: specMember("a/b -> q"),
          reason: "host-directory",
        })
        expect(describeTree(destination)).toStrictEqual(before)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract pre-merge listing of non-ASCII member paths (Issue #219)",
  () => {
    it("round-trips a directory hit for a non-ASCII member path into a conflict", () => {
      const { destination, root } = makeWorkspace()
      try {
        buildTree(destination, ["Ümlaut/", "Ümlaut/l/", "Ümlaut/l/f"], destination)
        const members = ["Ümlaut/", "Ümlaut/l -> f"].map((entry) => specMember(entry))

        expect(modelVerdict(destination, members)).toStrictEqual({
          key: "Ümlaut/l",
          kind: "conflict",
          member: specMember("Ümlaut/l -> f"),
          reason: "host-directory",
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

describe.skipIf(SKIP_PLATFORM || SKIP_NO_GNU_CP)(
  "archive.extract two-run directory conflict after a real merge (Issue #219, requires GNU cp)",
  () => {
    it("shows the escape the refusal prevents, and the backstop reports the escaping link without removing it", async () => {
      const { destination, root, staging } = makeWorkspace()
      try {
        const firstStaging = join(root, "staging-1")
        buildTree(firstStaging, twoRunFirstHost, destination)
        const first = runProductionMerge({
          destination,
          members: twoRunFirstHost.map((entry) => specMember(entry)),
          staging: firstStaging,
        })
        expect(first).toMatchObject({ code: 0, stderr: "" })
        expect(
          escapingLinks(
            destination,
            twoRunFirstHost.map((entry) => specMember(entry))
          )
        ).toStrictEqual([])
        const outsideBefore = readdirSync(root).toSorted()

        // Run 2 merged anyway, as it would have been without the refusal.
        buildTree(staging, twoRunSecondArchive, destination)
        const second = runProductionMerge({
          destination,
          members: twoRunSecondArchive.map((entry) => specMember(entry)),
          staging,
        })
        expect(second.code).not.toBe(0)
        expect(lstatSync(join(destination, "a/b")).isDirectory()).toBe(true)
        expect(readlinkSync(join(destination, "a/c/l"))).toBe("../b/hl/..")
        const secondMembers = twoRunSecondArchive.map((entry) => specMember(entry))
        expect(backstopViolations(destination, secondMembers)).toStrictEqual([["a/c/l", "escape"]])
        // The kernel agrees: `a/c/l` really resolves to the destination's parent.
        expect(realpathSync.native(join(destination, "a/c/l"))).toBe(root)
        expect(physicallyEscapingLinks(destination)).toStrictEqual(["a/c/l"])

        const { commands, conn } = localShellConnection()
        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: secondMembers,
          source: "run-2.tar",
        })

        expect(failure?.status).toBe("failed")
        expect(failure?.error?.message).toBe(
          `[archive.extract] refusing to complete extraction of run-2.tar: symlink ${JSON.stringify(join(destination, "a/c/l"))} -> "../b/hl/.." resolves outside destination ${JSON.stringify(destination)}; ${BACKSTOP_REPORT_TAIL}`
        )
        // Issue #219: one listing and nothing else: the backstop only reports.
        // `a/b/hl` resolves to the destination root without passing through a
        // path run 2 writes, so it is not judged and needs no cross-check.
        expect(commands).toStrictEqual([buildSymlinkListingProbeScript()])
        expect(describeTree(destination)).toStrictEqual([
          "d a",
          "d a/b",
          "l a/b/hl -> ../..",
          "d a/c",
          "l a/c/l -> ../b/hl/..",
        ])
        expect(readdirSync(root).toSorted()).toStrictEqual(outsideBefore)
        expect(physicallyEscapingLinks(destination)).toStrictEqual(["a/c/l"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

type DifferentialCase = {
  /** The archive as extracted into staging, in listing order. */
  archive: string[]
  /**
   * Destination-relative links the backstop reports after the real merge: the
   * TypeScript resolver's verdict on the real post-merge listing.
   */
  escapes: string[]
  /** The host tree below the destination before the merge. */
  host: string[]
  /**
   * Issue #219: host links that escape physically but that this archive
   * cannot affect, so neither check judges them.
   */
  ignored: string[]
  /** Whether the real merge exits zero. */
  merge: "failed" | "ok"
  name: string
  /** The first check the real pre-staging probe reports, or `clean`. */
  preStaging: "clean" | "d" | "l" | "n"
  /** The model verdict, see {@link verdictLabel}. */
  verdict: string
}

// Issue #219: host tree / archive combinations for the differential test. The
// production path refuses a case when the pre-staging probe reports anything
// or the model verdict is not `ok`; only the remaining cases reach the merge.
const differentialCases: DifferentialCase[] = [
  {
    archive: ["a/", "a/b -> q"],
    escapes: [],
    host: ["a/", "a/b/", "a/b/f"],
    ignored: [],
    merge: "failed",
    name: "archive symlink over a host directory without links below",
    preStaging: "n",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: twoRunSecondArchive,
    escapes: ["a/c/l"],
    host: twoRunFirstHost,
    ignored: [],
    merge: "failed",
    name: "archive symlink over a host directory with a link below (two-run case)",
    preStaging: "n",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: ["b -> a"],
    escapes: [],
    host: ["a/", "b/", "b/f"],
    ignored: [],
    merge: "failed",
    name: "top-level archive symlink over a host directory",
    preStaging: "n",
    verdict: "conflict:host-directory@b",
  },
  {
    archive: ["a/", "a/b", "a/c/", "a/c/l -> ../b/l/.."],
    escapes: ["a/c/l"],
    host: ["a/", "a/b/", "a/b/l -> ../.."],
    ignored: [],
    merge: "failed",
    name: "archive file over a host directory whose link the archive walks through",
    preStaging: "l",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: ["a/", "a/b/", "a/b/f"],
    escapes: [],
    host: ["a/", "a/b"],
    ignored: [],
    merge: "failed",
    name: "archive directory over a host file",
    preStaging: "d",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/b/", "a/up -> b"],
    escapes: [],
    host: ["a/", "a/b/", "a/esc -> up/..", "a/up -> .."],
    ignored: [],
    merge: "ok",
    name: "archive symlink over a host symlink that makes the combination safe",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/up -> .."],
    escapes: ["a/esc"],
    host: ["a/", "a/b/", "a/esc -> up/..", "a/up -> b"],
    ignored: [],
    merge: "ok",
    name: "archive symlink over a host symlink that makes a host link escape",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/x -> y"],
    escapes: [],
    host: ["a/", "a/x"],
    ignored: [],
    merge: "ok",
    name: "archive symlink over a host file",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/f"],
    escapes: [],
    host: ["a/", "a/f"],
    ignored: [],
    merge: "ok",
    name: "archive file over a host file",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/up"],
    escapes: [],
    host: ["a/", "a/up -> .."],
    ignored: [],
    merge: "failed",
    name: "archive file over a host symlink",
    preStaging: "l",
    verdict: "conflict:host-symlink@a/up",
  },
  {
    archive: ["a/", "a/s/f"],
    escapes: [],
    host: ["a/", "t/", "a/s -> ../t"],
    ignored: [],
    merge: "failed",
    name: "archive file below a host symlink",
    preStaging: "l",
    verdict: "conflict:below-host-symlink@a/s",
  },
  {
    archive: ["a/", "a/d/", "a/d/new -> ../x/f"],
    escapes: [],
    host: ["a/", "a/d/", "a/d/keep -> ../x"],
    ignored: [],
    merge: "ok",
    name: "nested directory with a symlink merged into a host directory with links",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/d/", "a/d/s -> h/.."],
    escapes: ["a/d/s"],
    host: ["a/", "a/d/", "a/d/h -> ../.."],
    ignored: [],
    merge: "ok",
    name: "nested archive symlink that escapes through a host link in the same directory",
    preStaging: "l",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/up -> .."],
    escapes: ["a/esc"],
    host: ["a/", "a/esc -> up/.."],
    ignored: [],
    merge: "ok",
    name: "sibling archive link that makes an earlier host link escape",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/lib/", "a/lib/f", "a/lib64 -> lib", "a/bin/", "a/bin/f -> ../lib64/f"],
    escapes: [],
    host: [],
    ignored: [],
    merge: "ok",
    name: "contained archive links on an empty host",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["f"],
    escapes: [],
    host: ["etc -> /etc"],
    ignored: ["etc"],
    merge: "ok",
    name: "unrelated host link with an absolute target outside, next to an archive without symlinks",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/f", "a/l -> f"],
    escapes: [],
    host: ["x/", "x/py -> /etc", "x/up -> ../.."],
    ignored: ["x/py", "x/up"],
    merge: "ok",
    name: "unrelated escaping host links next to an archive with symlinks",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/up -> .."],
    escapes: ["x/esc"],
    host: ["a/", "x/", "x/esc -> ../a/up/.."],
    ignored: [],
    merge: "ok",
    name: "host link elsewhere that walks through an archive link",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/f"],
    escapes: [],
    host: ["a/", "abs -> $DEST/a"],
    ignored: [],
    merge: "ok",
    name: "host link with an absolute target inside the destination",
    preStaging: "clean",
    verdict: "ok",
  },
]

/**
 * Issue #219: condense one differential run into the shape of its table row.
 *
 * @param run - The raw outcomes of one differential run.
 * @param run.escapes - Destination-relative links the real backstop reported.
 * @param run.merge - The real merge's exit status and output.
 * @param run.preStaging - The `(check, path)` pairs of the real pre-staging probe.
 * @param run.verdict - What `preMergeContainmentVerdict` returned.
 * @returns The observed row, with the spec fields left for the caller to fill.
 */
function differentialObservation(run: {
  escapes: string[]
  merge: ShellResult
  preStaging: ReadonlyArray<readonly [string, string]>
  verdict: PreMergeContainmentVerdict
}): Omit<DifferentialCase, "archive" | "host" | "ignored" | "name"> {
  const firstCheck = run.preStaging.map(([check]) => check).at(0) ?? "clean"
  return {
    escapes: run.escapes,
    merge: run.merge.code === 0 ? "ok" : "failed",
    preStaging: firstCheck as DifferentialCase["preStaging"],
    verdict: verdictLabel(run.verdict),
  }
}

/**
 * Issue #219: the properties that must hold between the model and the real
 * merge for every differential row.
 *
 * - `escapeWasRefused` (model soundness): production merges only when the
 *   pre-staging probe is clean and the verdict is `ok`, so an escape the real
 *   backstop sees must never come out of such a case.
 * - `mergedCaseIsClean`: a case production would merge merges successfully
 *   and leaves nothing for the backstop.
 * - `conflictMergeFails`: a conflict is a merge the model does not predict;
 *   the real merge fails on it.
 * - `publishedViolationsMatch`: when a merge the model refuses succeeds
 *   anyway, the backstop finds exactly the escaping links the model named.
 *
 * @param observed - The observed row (see {@link differentialObservation}).
 * @param verdict - What `preMergeContainmentVerdict` returned.
 * @returns Each property with whether it holds.
 */
function differentialInvariants(
  observed: Omit<DifferentialCase, "archive" | "host" | "ignored" | "name">,
  verdict: PreMergeContainmentVerdict
): Record<string, boolean> {
  const refusedBeforeMerge = observed.preStaging !== "clean" || verdict.kind !== "ok"
  const modelledEscapes =
    verdict.kind === "violations"
      ? verdict.violations
          .filter(({ kind }) => kind === "escape")
          .map(({ key }) => key)
          .toSorted()
      : []
  return {
    conflictMergeFails: verdict.kind !== "conflict" || observed.merge === "failed",
    escapeWasRefused: observed.escapes.length === 0 || refusedBeforeMerge,
    mergedCaseIsClean:
      refusedBeforeMerge || (observed.merge === "ok" && observed.escapes.length === 0),
    publishedViolationsMatch:
      verdict.kind !== "violations" ||
      observed.merge !== "ok" ||
      JSON.stringify(observed.escapes) === JSON.stringify(modelledEscapes),
  }
}

describe.skipIf(SKIP_PLATFORM || SKIP_NO_GNU_CP)(
  "archive.extract pre-merge model versus real merge (Issue #219, requires GNU cp)",
  () => {
    it.each(differentialCases)("$name", (testCase) => {
      const { destination, root, staging } = makeWorkspace()
      try {
        buildTree(destination, testCase.host, destination)
        buildTree(staging, testCase.archive, destination)
        const members = testCase.archive.map((entry) => specMember(entry))

        const preStaging = runPreStagingProbe(destination, members)
        const verdict = modelVerdict(destination, members)
        const merge = runProductionMerge({ destination, members, staging })
        const escapes = escapingLinks(destination, members)
        // Independent of the listing and the resolver: every link the kernel
        // resolves outside the destination is one the backstop reports, or
        // one the case lists as unrelated to the archive (Issue #219).
        expect([...escapes, ...testCase.ignored]).toStrictEqual(
          expect.arrayContaining(physicallyEscapingLinks(destination))
        )

        const observed = differentialObservation({ escapes, merge, preStaging, verdict })
        expect(observed).toStrictEqual({
          escapes: testCase.escapes,
          merge: testCase.merge,
          preStaging: testCase.preStaging,
          verdict: testCase.verdict,
        })
        expect(differentialInvariants(observed, verdict)).toStrictEqual({
          conflictMergeFails: true,
          escapeWasRefused: true,
          mergedCaseIsClean: true,
          publishedViolationsMatch: true,
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

/**
 * Issue #219: a workspace whose destination is `<root>/app`, next to an
 * `<root>/other/q/r` directory outside it, for links that leave the
 * destination and come back into it.
 *
 * @returns The workspace root and the destination.
 */
function makeAppWorkspace(): { destination: string; root: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "paratix-archive-backstop-smoke-")))
  const destination = join(root, "app")
  mkdirSync(destination)
  mkdirSync(join(root, "other/q/r"), { recursive: true })
  return { destination, root }
}

/**
 * Issue #219: the links a backstop failure message names, each as
 * `symlink "<absolute link path>" -> "<stored target>"`.
 *
 * @param message - The failure message of `enforceSymlinkContainment`.
 * @returns The reported link paths, sorted.
 */
function reportedLinks(message: string | undefined): string[] {
  return [...(message ?? "").matchAll(/symlink (?<link>"(?:[^"\\]|\\.)*") -> /gv)]
    .map((match) => JSON.parse(match.groups?.link ?? '""') as string)
    .toSorted()
}

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract post-merge backstop shell smoke tests (Issue #219)",
  () => {
    it("judges contained, dangling-inside, absolute-inside and self links as contained", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a/lib"), { recursive: true })
        writeFileSync(join(destination, "a/lib/f"), "f\n")
        symlinkSync("lib/f", join(destination, "a/inside"))
        symlinkSync("..", join(destination, "a/up"))
        symlinkSync("up/a/lib", join(destination, "a/via-up"))
        symlinkSync("missing/y/z", join(destination, "a/dangling"))
        symlinkSync(".", join(destination, "self"))
        symlinkSync(join(destination, "a/lib"), join(destination, "absolute-inside"))

        expect(backstopViolations(destination)).toStrictEqual([])
        expect(physicallyEscapingLinks(destination)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports an absolute link outside and a relative link into a prefix sibling", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        mkdirSync(`${destination}-sibling`)
        symlinkSync("/etc", join(destination, "a/etc"))
        // `<root>/destination-sibling` shares the destination's string prefix
        // but is a sibling, so a bare prefix comparison would accept it.
        symlinkSync("../destination-sibling", join(destination, "sibling"))

        expect(backstopViolations(destination)).toStrictEqual([
          ["a/etc", "escape"],
          ["sibling", "escape"],
        ])
        expect(physicallyEscapingLinks(destination)).toStrictEqual(["a/etc", "sibling"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a link whose name contains a newline under its exact key", () => {
      const { destination, root } = makeWorkspace()
      try {
        // Issue #219: archive member paths never contain control characters,
        // so a host link with a newline is judged through the archive path
        // `a` its target walks through.
        mkdirSync(join(destination, "a"))
        symlinkSync("a/../..", join(destination, "two\nlines"))

        expect(
          backstopViolations(destination, [specMember("a/"), tarMember("a/l", "f")])
        ).toStrictEqual([["two\nlines", "escape"]])
        expect(physicallyEscapingLinks(destination)).toStrictEqual(["two\nlines"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports cycles and self-extending links as beyond the resolution limit, and finishes quickly", () => {
      // GNU `realpath` never returns on `b -> b/..` or on `x -> y/..` with
      // `y -> x`; the listing only reads stored targets and the TypeScript
      // resolver stops at its hop limit or on the cycle.
      const { destination, root } = makeWorkspace()
      try {
        symlinkSync("loop-b", join(destination, "loop-a"))
        symlinkSync("loop-a", join(destination, "loop-b"))
        symlinkSync("b/..", join(destination, "b"))
        symlinkSync("y/..", join(destination, "x"))
        symlinkSync("x", join(destination, "y"))
        symlinkSync(".", join(destination, "self"))
        const started = Date.now()

        const violations = backstopViolations(destination)

        expect(Date.now() - started).toBeLessThan(5000)
        expect(violations).toStrictEqual([
          ["b", "limit"],
          ["loop-a", "limit"],
          ["loop-b", "limit"],
          ["x", "limit"],
          ["y", "limit"],
        ])
        // The kernel cannot resolve them either.
        const loops = violations.map(([key]) => physicallyLoops(join(destination, key)))
        expect(loops).toStrictEqual([true, true, true, true, true])
        expect(physicallyEscapingLinks(destination)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    }, 10_000)

    it("reports those links and changes nothing, in exactly two execs", async () => {
      const { destination, root } = makeWorkspace()
      try {
        writeFileSync(join(destination, "w"), "w\n")
        symlinkSync("w", join(destination, "in"))
        symlinkSync("b/..", join(destination, "b"))
        symlinkSync("y/..", join(destination, "x"))
        symlinkSync("x", join(destination, "y"))
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: treeLinksAsMembers(destination),
          source: "loop.tar",
        })

        const message = failure?.error?.message
        expect(
          message?.startsWith(
            "[archive.extract] refusing to complete extraction of loop.tar: symlink "
          )
        ).toBe(true)
        expect(
          message?.match(/cannot be resolved within the symlink resolution limit; /gv)
        ).toHaveLength(3)
        expect(message?.endsWith(`; ${BACKSTOP_REPORT_TAIL}`)).toBe(true)
        expect(reportedLinks(message)).toStrictEqual(
          ["b", "x", "y"].map((key) => join(destination, key))
        )
        // Issue #219: one listing and one kernel cross-check of `in`, and
        // nothing else: every link is still in place.
        expect(commands).toStrictEqual([
          buildSymlinkListingProbeScript(),
          buildKernelCrossCheckScript(),
        ])
        expect(describeTree(destination)).toStrictEqual([
          "l b -> b/..",
          "l in -> w",
          "f w w\n",
          "l x -> y/..",
          "l y -> x",
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    }, 10_000)

    it("reports a link that stays inside only through an escaping link, together with that link", async () => {
      // `x` leaves the destination; `z` walks through `x` and comes back into
      // it. Physically `z` lands inside, but only because `x` points outside,
      // so the backstop reports both and removes neither.
      const { destination, root } = makeAppWorkspace()
      try {
        writeFileSync(join(destination, "w"), "w\n")
        symlinkSync("../other/q/r", join(destination, "x"))
        symlinkSync("x/../../../app/w", join(destination, "z"))
        expect(realpathSync.native(join(destination, "x"))).toBe(join(root, "other/q/r"))
        expect(realpathSync.native(join(destination, "z"))).toBe(join(destination, "w"))
        expect(backstopViolations(destination)).toStrictEqual([
          ["x", "escape"],
          ["z", "escape"],
        ])
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: treeLinksAsMembers(destination),
          source: "q2.tar",
        })

        const message = failure?.error?.message
        expect(message?.endsWith(`; ${BACKSTOP_REPORT_TAIL}`)).toBe(true)
        expect(message).not.toContain("more)")
        expect(reportedLinks(message)).toStrictEqual([
          join(destination, "x"),
          join(destination, "z"),
        ])
        // No link is judged inside, so the listing is the only exec.
        expect(commands).toStrictEqual([buildSymlinkListingProbeScript()])
        expect(describeTree(destination)).toStrictEqual([
          "f w w\n",
          "l x -> ../other/q/r",
          "l z -> x/../../../app/w",
        ])
        expect(readdirSync(join(root, "other/q/r"))).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("fails closed in one exec when find cannot walk the destination", async () => {
      const { destination, root } = makeWorkspace()
      try {
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination: join(destination, "missing"),
          members: [tarMember("l", "f")],
          source: "gone.tar",
        })

        expect(failure?.error?.message).toMatch(
          /^\[archive\.extract\] refusing to complete extraction of gone\.tar: symlink containment check failed: .+/sv
        )
        expect(commands).toStrictEqual([buildSymlinkListingProbeScript()])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(SKIP_UNLESS_UNREADABLE_FAILS)(
      "fails closed and removes nothing, not even a visible escaping link, when a subdirectory is unreadable (without GNU find)",
      async () => {
        const { destination, root } = makeWorkspace()
        const locked = join(destination, "locked")
        try {
          symlinkSync("..", join(destination, "visible"))
          mkdirSync(locked)
          symlinkSync("../..", join(locked, "hidden"))
          const members = treeLinksAsMembers(destination)
          chmodSync(locked, 0o000)
          const { commands, conn } = localShellConnection()

          const failure = await enforceSymlinkContainment(conn, {
            destination,
            members,
            source: "locked.tar",
          })

          expect(failure?.error?.message).toContain("symlink containment check failed: ")
          expect(commands).toStrictEqual([buildSymlinkListingProbeScript()])
          expect(readlinkSync(join(destination, "visible"))).toBe("..")
        } finally {
          chmodSync(locked, 0o755)
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it.skipIf(SKIP_UNLESS_UNREADABLE_REPORTED)(
      "ignores an unrelated unreadable directory and refuses a judged walk into one (GNU find)",
      async () => {
        const { destination, root } = makeWorkspace()
        const locked = join(destination, "locked")
        const other = join(destination, "other")
        try {
          mkdirSync(join(destination, "a"))
          writeFileSync(join(destination, "a/f"), "f\n")
          symlinkSync("f", join(destination, "a/l"))
          symlinkSync("../locked/f", join(destination, "a/in"))
          mkdirSync(locked)
          mkdirSync(other)
          symlinkSync("../..", join(other, "hidden"))
          chmodSync(locked, 0o000)
          chmodSync(other, 0o000)
          const { conn } = localShellConnection()

          const unrelated = await enforceSymlinkContainment(conn, {
            destination,
            members: [tarMember("a/l", "f")],
            source: "ok.tar",
          })
          const judged = await enforceSymlinkContainment(conn, {
            destination,
            members: [tarMember("a/l", "f"), tarMember("a/in", "../locked/f")],
            source: "into-locked.tar",
          })

          expect(unrelated).toBeNull()
          expect(judged?.error?.message).toBe(
            `[archive.extract] refusing to complete extraction of into-locked.tar: symlink ${JSON.stringify(join(destination, "a/in"))} -> "../locked/f" cannot be checked: directory ${JSON.stringify(locked)} is not readable; ${BACKSTOP_REPORT_TAIL}`
          )
        } finally {
          chmodSync(locked, 0o755)
          chmodSync(other, 0o755)
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    describe.skipIf(SKIP_NO_GNU_CP)("after real merges (requires GNU cp)", () => {
      it("reports the earlier run's link once a later run ships the link it walks through", () => {
        // Run 1 ships `a/esc -> up/..`, run 2 ships `a/up -> ..`. Each merge
        // succeeds with the product guard set and each tree is contained on its
        // own; after run 2, `a/esc` resolves via `a/up/..` to the destination's
        // parent.
        const { destination, root, staging } = makeWorkspace()
        try {
          const secondStaging = join(root, "staging-2")
          buildTree(staging, ["a/", "a/esc -> up/.."], destination)
          buildTree(secondStaging, ["a/", "a/up -> .."], destination)
          const mergeRun = (stagingRoot: string, spec: string[]): ShellResult =>
            runProductionMerge({
              destination,
              members: spec.map((entry) => specMember(entry)),
              staging: stagingRoot,
            })

          expect(mergeRun(staging, ["a/", "a/esc -> up/.."])).toMatchObject({
            code: 0,
            stderr: "",
          })
          expect(backstopViolations(destination)).toStrictEqual([])

          expect(mergeRun(secondStaging, ["a/", "a/up -> .."])).toMatchObject({
            code: 0,
            stderr: "",
          })

          expect(readlinkSync(join(destination, "a/esc"))).toBe("up/..")
          expect(readlinkSync(join(destination, "a/up"))).toBe("..")
          expect(backstopViolations(destination)).toStrictEqual([["a/esc", "escape"]])
          expect(realpathSync.native(join(destination, "a/esc"))).toBe(root)
          expect(physicallyEscapingLinks(destination)).toStrictEqual(["a/esc"])
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      })
    })
  }
)

/**
 * Issue #219: small limits for the bounded merge cases, so a stopped merge
 * shows within seconds.
 */
const smallMergeLimits: StagingMergeTimeLimits = {
  clientTimeoutMs: 10_000,
  killAfterSeconds: 1,
  timeoutSeconds: 1,
}

/**
 * Issue #219: run a merge command bounded by `boundedStagingMergeCommand`
 * under a real `/bin/sh`, with a client-side timeout as a safety net.
 *
 * @param command - The merge command to bound.
 * @param limits - The time limits; the production defaults when omitted.
 * @returns Exit code, elapsed wall-clock time and stderr.
 */
function runBoundedMerge(
  command: string,
  limits?: StagingMergeTimeLimits
): { code: number; elapsedMs: number; stderr: string } {
  const started = Date.now()
  const result = spawnSync("/bin/sh", ["-c", boundedStagingMergeCommand(command, limits)], {
    encoding: "utf8",
    timeout: 10_000,
  })
  return { code: result.status ?? -1, elapsedMs: Date.now() - started, stderr: result.stderr }
}

/**
 * Issue #219: the processes whose command line contains a marker.
 *
 * @param marker - A string unique to the processes of one case.
 * @returns `pid args` lines of the matching processes.
 */
function processesMatching(marker: string): string[] {
  const result = spawnSync("ps", ["-A", "-o", "pid=,args="], { encoding: "utf8", timeout: 2000 })
  return result.stdout
    .split("\n")
    .filter((line) => line.includes(marker) && !line.includes("ps -A"))
}

/**
 * Issue #219: wait until no process with the marker is left, or give up.
 *
 * @param marker - A string unique to the processes of one case.
 * @returns The processes still running after the wait.
 */
async function survivorsAfterWait(marker: string): Promise<string[]> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (processesMatching(marker).length === 0) return []
    // eslint-disable-next-line no-await-in-loop -- polling with a delay by design
    await new Promise((resolve) => {
      setTimeout(resolve, 100)
    })
  }
  return processesMatching(marker)
}

/**
 * Issue #219: kill every process with the marker, so a failing case leaves
 * nothing behind.
 *
 * @param marker - A string unique to the processes of one case.
 */
function killMatching(marker: string): void {
  for (const line of processesMatching(marker)) {
    const pid = Number.parseInt(line.trim(), 10)
    try {
      process.kill(pid, "SIGKILL")
    } catch {
      // Already gone.
    }
  }
}

describe.skipIf(SKIP_PLATFORM || !HAS_COMMAND_P_TIMEOUT)(
  "archive.extract bounded staging merge shell smoke tests (Issue #219, requires command -p timeout)",
  () => {
    it("passes the exit status of a merge that finishes in time through", () => {
      expect(runBoundedMerge("true").code).toBe(0)
      expect(runBoundedMerge("false").code).toBe(1)
      expect(runBoundedMerge("sh -c 'exit 3'").code).toBe(3)
    })

    it("stops a merge that runs too long with SIGTERM to its whole process group: exit 124", async () => {
      // The production shape: `find … -exec sh -c … {} +`, whose batches
      // are grandchildren of `timeout`.
      const marker = `29.${String(process.pid)}1`
      const batch = ["sleep", marker].join(" ")
      const { root } = makeWorkspace()
      try {
        const result = runBoundedMerge(
          `find ${shellQuote(root)} -maxdepth 0 -exec sh -c ${shellQuote(batch)} sh {} +`,
          smallMergeLimits
        )

        expect(result.code).toBe(124)
        expect(result.elapsedMs).toBeLessThan(5000)
        await expect(survivorsAfterWait(marker)).resolves.toStrictEqual([])
      } finally {
        killMatching(marker)
        rmSync(root, { force: true, recursive: true })
      }
    }, 15_000)

    it("kills a merge that ignores SIGTERM after the grace period: exit 137, nothing left", async () => {
      const marker = `29.${String(process.pid)}2`
      const ignoresTerm = ['trap "" TERM;', "sleep", marker].join(" ")
      try {
        const result = runBoundedMerge(`sh -c ${shellQuote(ignoresTerm)}`, smallMergeLimits)

        expect(result.code).toBe(137)
        expect(result.elapsedMs).toBeGreaterThanOrEqual(1500)
        expect(result.elapsedMs).toBeLessThan(6000)
        await expect(survivorsAfterWait(marker)).resolves.toStrictEqual([])
      } finally {
        killMatching(marker)
      }
    }, 15_000)
  }
)

/** Issue #219: Linux's limit for a single argument (`MAX_ARG_STRLEN`). */
const LINUX_MAX_ARG_STRLEN = 128 * 1024

/**
 * Issue #219: a merge workspace with its own `TMPDIR`, so a case can see
 * whether the merge left its guard file behind.
 *
 * @returns The workspace paths.
 */
function makeGuardTransportWorkspace(): {
  destination: string
  root: string
  staging: string
  tmp: string
} {
  const workspace = makeWorkspace()
  const tmp = join(workspace.root, "tmp")
  mkdirSync(tmp)
  writeFileSync(join(workspace.staging, "payload.txt"), "payload\n")
  return { ...workspace, tmp }
}

/**
 * Issue #219: guard paths shaped like those of a Node.js tarball, whose
 * roughly 6,000 members yield about 750 KB of guard paths.
 *
 * @param destination - The destination directory.
 * @param count - The number of guard paths.
 * @returns Absolute guard paths below the destination; none of them exists.
 */
function syntheticGuardPaths(destination: string, count: number): string[] {
  return Array.from({ length: count }, (_, index) =>
    join(
      destination,
      `node-v24.21.0-linux-x64/lib/node_modules/npm/node_modules/package-${String(index)}/lib/index.js`
    )
  )
}

/**
 * Issue #219: run the command and stdin of `buildStagingMergeExec` under a
 * real `/bin/sh`, unbounded; the bounded shape is covered separately.
 *
 * @param parameters - Merge inputs.
 * @param parameters.env - Extra environment entries, e.g. a different `TMPDIR`.
 * @param parameters.guardPaths - Destination paths the merge must find free of symlinks.
 * @param parameters.input - Optional replacement of the stdin payload.
 * @param parameters.workspace - The workspace from {@link makeGuardTransportWorkspace}.
 * @returns Exit code and captured output.
 */
function runMergeExec(parameters: {
  env?: NodeJS.ProcessEnv
  guardPaths: string[]
  input?: (payload: string) => string
  workspace: ReturnType<typeof makeGuardTransportWorkspace>
}): ShellResult {
  const { destination, staging, tmp } = parameters.workspace
  const { command, input } = buildStagingMergeExec({
    destination,
    guardPaths: parameters.guardPaths,
    staging,
  })
  const result = spawnSync("/bin/sh", ["-c", command], {
    encoding: "utf8",
    env: { ...process.env, TMPDIR: tmp, ...parameters.env },
    input: parameters.input === undefined ? input : parameters.input(input),
    timeout: 10_000,
  })
  return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
}

/**
 * Issue #219: a `find` stand-in that records its start and then sleeps, so a
 * case can stop the merge while `find` runs.
 *
 * @param workspace - The workspace from {@link makeGuardTransportWorkspace}.
 * @param sleepSeconds - How long the stand-in sleeps before it exits with 0.
 * @returns The environment that puts the stand-in first on PATH and uses the
 *   workspace `TMPDIR`, and the start marker file.
 */
function sleepingFindShim(
  workspace: ReturnType<typeof makeGuardTransportWorkspace>,
  sleepSeconds = 30
): {
  env: NodeJS.ProcessEnv
  started: string
} {
  const bin = join(workspace.root, "bin")
  const started = join(workspace.root, "find-started")
  mkdirSync(bin)
  writeFileSync(
    join(bin, "find"),
    `#!/bin/sh\n: > ${shellQuote(started)}\nexec sleep ${String(sleepSeconds)}\n`
  )
  chmodSync(join(bin, "find"), 0o755)
  const path = [bin, process.env.PATH].filter((entry) => entry !== undefined).join(":")
  return { env: { ...process.env, PATH: path, TMPDIR: workspace.tmp }, started }
}

/**
 * Issue #219: send a signal to the process group of a detached child,
 * tolerating a group that is already gone.
 *
 * @param child - The detached child, leader of its process group.
 * @param signal - The signal to send.
 */
function signalProcessGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return
  try {
    process.kill(-child.pid, signal)
  } catch {
    // Already gone.
  }
}

/** Issue #219: how a stopped merge shell exited. */
type MergeExit = {
  code: null | number
  signal: NodeJS.Signals | null
}

/**
 * Issue #219: start the command and stdin of `buildStagingMergeExec` in its
 * own process group, like the one GNU `timeout` creates, with the `find`
 * stand-in from {@link sleepingFindShim}, so a case can stop the merge while
 * `find` runs.
 *
 * Issue #219: the child runs `exec` + the command, so the detached child is
 * the merge shell itself. dash (Ubuntu's `/bin/sh`) keeps a trap-less wrapper
 * shell for `sh -c` with a single command, where bash replaces itself with
 * that command; a signal then stops the wrapper at once, and the case would
 * observe its exit while the merge shell still runs its `TERM`/`EXIT` traps.
 * Production runs the merge shell directly under `timeout`, which execs `sh`.
 *
 * @param workspace - The workspace from {@link makeGuardTransportWorkspace}.
 * @param findSeconds - How long the `find` stand-in sleeps.
 * @returns The detached child, a promise of its exit, and the stand-in's start
 *   marker file.
 */
function spawnDetachedMerge(
  workspace: ReturnType<typeof makeGuardTransportWorkspace>,
  findSeconds?: number
): { child: ChildProcess; exited: Promise<MergeExit>; started: string } {
  const { env, started } = sleepingFindShim(workspace, findSeconds)
  const { command, input } = buildStagingMergeExec({
    destination: workspace.destination,
    guardPaths: syntheticGuardPaths(workspace.destination, 10),
    staging: workspace.staging,
  })
  const child = spawn("/bin/sh", ["-c", `exec ${command}`], {
    detached: true,
    env,
    stdio: ["pipe", "ignore", "ignore"],
  })
  const exited = new Promise<MergeExit>((resolve) => {
    child.on("exit", (code, signal) => {
      resolve({ code, signal })
    })
  })
  child.stdin.end(input)
  return { child, exited, started }
}

/**
 * Issue #219: wait until a file exists, or give up.
 *
 * @param path - The file to wait for.
 * @returns True when the file appeared in time.
 */
async function appeared(path: string): Promise<boolean> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (existsSync(path)) return true
    // eslint-disable-next-line no-await-in-loop -- polling with a delay by design
    await new Promise((resolve) => {
      setTimeout(resolve, 100)
    })
  }
  return existsSync(path)
}

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract staging merge guard transport shell smoke tests (Issue #219)",
  () => {
    // The guard paths used to travel as one newline-separated argument, which
    // fails with E2BIG on Linux once it exceeds 128 KiB. macOS has no
    // per-argument limit, so these cases cannot reproduce E2BIG there; they
    // assert the argument sizes instead, and the Linux CI runs the same cases
    // against the real limit.
    it("keeps every argument far below 128 KiB for a guard list above it", () => {
      const workspace = makeGuardTransportWorkspace()
      try {
        const guardPaths = syntheticGuardPaths(workspace.destination, 6000)
        const { command, input } = buildStagingMergeExec({
          destination: workspace.destination,
          guardPaths,
          staging: workspace.staging,
        })

        expect(Buffer.byteLength(guardPaths.join("\n"))).toBeGreaterThan(LINUX_MAX_ARG_STRLEN)
        expect(Buffer.byteLength(input)).toBeGreaterThan(LINUX_MAX_ARG_STRLEN)
        expect(Buffer.byteLength(boundedStagingMergeCommand(command))).toBeLessThan(16 * 1024)

        const result = runMergeExec({ guardPaths, workspace })

        expect(result.stderr).not.toContain("refusing staging merge")
        expect(readdirSync(workspace.tmp)).toStrictEqual([])
      } finally {
        rmSync(workspace.root, { force: true, recursive: true })
      }
    })

    it("still refuses a symlinked guard path at the end of a guard list above 128 KiB", () => {
      const workspace = makeGuardTransportWorkspace()
      try {
        const guarded = join(workspace.destination, "guarded")
        symlinkSync(join(workspace.root, "elsewhere"), guarded)

        const result = runMergeExec({
          guardPaths: [...syntheticGuardPaths(workspace.destination, 6000), guarded],
          workspace,
        })

        // The merge script exits 64; `find -exec … {} +` reports it as 1.
        expect(result.code).not.toBe(0)
        expect(result.stderr).toContain(
          `refusing staging merge: destination path ${guarded} is a symlink`
        )
        expect(result.stderr).toContain("refusing staging merge: the guard path check failed")
        expect(readdirSync(workspace.destination)).toStrictEqual(["guarded"])
        expect(readdirSync(workspace.tmp)).toStrictEqual([])
      } finally {
        rmSync(workspace.root, { force: true, recursive: true })
      }
    })

    it("refuses a guard list that arrives truncated", () => {
      const workspace = makeGuardTransportWorkspace()
      try {
        const result = runMergeExec({
          guardPaths: syntheticGuardPaths(workspace.destination, 6000),
          input: (payload) => payload.slice(0, 1000),
          workspace,
        })

        expect(result.code).toBe(64)
        expect(result.stderr).toMatch(/refusing staging merge: received \d+ of 6000 guard paths/v)
        expect(readdirSync(workspace.destination)).toStrictEqual([])
        expect(readdirSync(workspace.tmp)).toStrictEqual([])
      } finally {
        rmSync(workspace.root, { force: true, recursive: true })
      }
    })

    it("refuses the merge when the guard file cannot be created", () => {
      const workspace = makeGuardTransportWorkspace()
      try {
        const result = runMergeExec({
          env: { TMPDIR: join(workspace.root, "missing") },
          guardPaths: [workspace.destination],
          workspace,
        })

        expect(result.code).toBe(64)
        expect(result.stderr).toContain(
          "refusing staging merge: failed to create the guard path file"
        )
        expect(readdirSync(workspace.destination)).toStrictEqual([])
      } finally {
        rmSync(workspace.root, { force: true, recursive: true })
      }
    })

    // The signal reaches the merge shell and `find` together, as the host
    // timeout sends it, so `find` returns at once and the trap runs.
    it.each<[NodeJS.Signals, number]>([
      ["SIGHUP", 129],
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ])(
      "removes the guard file when the merge is stopped with %s: exit %i",
      async (signal, code) => {
        const workspace = makeGuardTransportWorkspace()
        const { child, exited, started } = spawnDetachedMerge(workspace)
        try {
          expect(await appeared(started)).toBe(true)
          expect(readdirSync(workspace.tmp)).toHaveLength(1)

          signalProcessGroup(child, signal)

          expect(await exited).toStrictEqual({ code, signal: null })
          expect(readdirSync(workspace.tmp)).toStrictEqual([])
        } finally {
          signalProcessGroup(child, "SIGKILL")
          rmSync(workspace.root, { force: true, recursive: true })
        }
      },
      15_000
    )

    it("removes the guard file once find returns when only the merge shell gets SIGTERM: exit 143", async () => {
      const workspace = makeGuardTransportWorkspace()
      // Issue #219: the shell defers the trap until the foreground `find`
      // returns. The stand-in sleeps 3 s, long enough that the signal
      // arrives while it runs even on a loaded runner, so the merge cannot
      // finish with exit 0 first, and the shell visibly waits at least 1 s.
      const { child, exited, started } = spawnDetachedMerge(workspace, 3)
      try {
        expect(await appeared(started)).toBe(true)
        expect(readdirSync(workspace.tmp)).toHaveLength(1)

        // `kill` signals the merge shell alone, not its process group.
        const signalled = Date.now()
        child.kill("SIGTERM")

        expect(await exited).toStrictEqual({ code: 143, signal: null })
        expect(Date.now() - signalled).toBeGreaterThanOrEqual(1000)
        expect(readdirSync(workspace.tmp)).toStrictEqual([])
      } finally {
        signalProcessGroup(child, "SIGKILL")
        rmSync(workspace.root, { force: true, recursive: true })
      }
    }, 15_000)

    it.skipIf(!HAS_COMMAND_P_TIMEOUT)(
      "removes the guard file when the host timeout stops the merge: exit 124",
      () => {
        const workspace = makeGuardTransportWorkspace()
        try {
          const { env } = sleepingFindShim(workspace)
          const { command, input } = buildStagingMergeExec({
            destination: workspace.destination,
            guardPaths: syntheticGuardPaths(workspace.destination, 10),
            staging: workspace.staging,
          })

          const result = spawnSync(
            "/bin/sh",
            ["-c", boundedStagingMergeCommand(command, smallMergeLimits)],
            { encoding: "utf8", env, input, timeout: 10_000 }
          )

          expect(result.status).toBe(124)
          expect(readdirSync(workspace.tmp)).toStrictEqual([])
        } finally {
          rmSync(workspace.root, { force: true, recursive: true })
        }
      },
      15_000
    )

    describe.skipIf(SKIP_NO_GNU_CP)("copy behavior (requires GNU cp)", () => {
      it("merges with a guard list above 128 KiB", () => {
        const workspace = makeGuardTransportWorkspace()
        try {
          const result = runMergeExec({
            guardPaths: syntheticGuardPaths(workspace.destination, 6000),
            workspace,
          })

          expect(result.stderr).toBe("")
          expect(result.code).toBe(0)
          expect(readFileSync(join(workspace.destination, "payload.txt"), "utf8")).toBe("payload\n")
          expect(readdirSync(workspace.tmp)).toStrictEqual([])
        } finally {
          rmSync(workspace.root, { force: true, recursive: true })
        }
      })

      it("merges with an empty guard list", () => {
        const workspace = makeGuardTransportWorkspace()
        try {
          const result = runMergeExec({ guardPaths: [], workspace })

          expect(result.stderr).toBe("")
          expect(result.code).toBe(0)
          expect(readFileSync(join(workspace.destination, "payload.txt"), "utf8")).toBe("payload\n")
          expect(readdirSync(workspace.tmp)).toStrictEqual([])
        } finally {
          rmSync(workspace.root, { force: true, recursive: true })
        }
      })
    })
  }
)

/**
 * Issue #219: whether the filesystem of the test workspaces folds letter case,
 * found by creating `x` and looking for `X` in a scratch directory next to
 * them.
 *
 * @returns True on a case-insensitive filesystem such as default APFS.
 */
function workspaceFoldsLetterCase(): boolean {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "paratix-case-probe-")))
  try {
    writeFileSync(join(scratch, "x"), "")
    return existsSync(join(scratch, "X"))
  } finally {
    rmSync(scratch, { force: true, recursive: true })
  }
}

/**
 * Issue #219: whether the filesystem of the test workspaces stores names that
 * are not valid UTF-8, found by trying to create one (APFS refuses them).
 *
 * @returns True when such a name could be created.
 */
function workspaceAcceptsNonUtf8Names(): boolean {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "paratix-bytes-probe-")))
  try {
    writeFileSync(Buffer.concat([Buffer.from(`${scratch}/`), Buffer.from([0x70, 0xff])]), "")
    return true
  } catch {
    return false
  } finally {
    rmSync(scratch, { force: true, recursive: true })
  }
}

/**
 * Issue #219: whether the filesystem of the test workspaces resolves `ss` to
 * an entry named with U+1E9E (capital sharp s), as APFS and Linux casefolding
 * do.
 *
 * @returns True when `ss` names the U+1E9E entry.
 */
function workspaceFoldsCapitalSharpS(): boolean {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "paratix-sharp-s-probe-")))
  try {
    writeFileSync(join(scratch, "\u1e9e"), "")
    return existsSync(join(scratch, "ss"))
  } finally {
    rmSync(scratch, { force: true, recursive: true })
  }
}

const FOLDS_LETTER_CASE = !SKIP_PLATFORM && workspaceFoldsLetterCase()
const FOLDS_CAPITAL_SHARP_S = !SKIP_PLATFORM && workspaceFoldsCapitalSharpS()
const ACCEPTS_NON_UTF8_NAMES = !SKIP_PLATFORM && workspaceAcceptsNonUtf8Names()

/**
 * Issue #219: the trail points of a link whose target walks no symlink, as the
 * resolver would compute them: each host path `K_j` keeps the target's `..`
 * segments, each expected location `E_j` is normalized.
 *
 * @param link - The absolute link path.
 * @param target - The relative target.
 * @returns The points `j = 0..n`.
 */
function plainTrailPoints(link: string, target: string): KernelCrossCheckPoint[] {
  let host = dirname(link)
  let expected = host
  const points = [{ expected, host }]
  for (const segment of target.split("/").filter((part) => part !== "" && part !== ".")) {
    host = `${host}/${segment}`
    expected = segment === ".." ? dirname(expected) : `${expected}/${segment}`
    points.push({ expected, host })
  }
  return points
}

/**
 * Issue #219: run the real kernel cross-check script for links with their
 * trail points and return its `(link, verdict, level)` triples.
 *
 * @param checks - Absolute link paths with their trail points `j = 0..n`.
 * @returns The exit code and the report per link, in output order.
 */
function runKernelCrossCheckScript(
  checks: ReadonlyArray<readonly [string, readonly KernelCrossCheckPoint[]]>
): { code: number; verdicts: Array<[string, string, string]> } {
  const entries = checks.map(([link, points]) => {
    const encoded = kernelCrossCheckEntry(link, points)
    if (encoded.kind !== "entry") throw new Error(`cannot encode ${link}: ${encoded.kind}`)
    return encoded.entry
  })
  const { code, fields } = runProbeScript(buildKernelCrossCheckScript(), entries)
  const verdicts: Array<[string, string, string]> = []
  for (let index = 0; index < fields.length; index += 3) {
    verdicts.push([
      fields[index] ?? "",
      fields[index + 1] ?? "<missing>",
      fields[index + 2] ?? "<missing>",
    ])
  }
  return { code, verdicts }
}

/**
 * Issue #219: trail points from explicit `(host, expected)` pairs.
 *
 * @param pairs - `(K_j, E_j)` for `j = 0..n`.
 * @returns One point per pair, in the same order.
 */
function trailPoints(...pairs: ReadonlyArray<readonly [string, string]>): KernelCrossCheckPoint[] {
  return pairs.map(([host, expected]) => ({ expected, host }))
}

/**
 * Issue #219: a workspace whose destination is `<root>/w/app`, with an empty
 * directory `<root>/outside` beside the destination's parent.
 *
 * @returns The workspace root, the destination and the outside directory.
 */
function makeSharpSWorkspace(): { destination: string; outside: string; root: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "paratix-archive-sharp-s-smoke-")))
  const destination = join(root, "w/app")
  const outside = join(root, "outside")
  mkdirSync(destination, { recursive: true })
  mkdirSync(outside)
  return { destination, outside, root }
}

/**
 * Issue #219: every link below `destination` as the backstop's model sees it,
 * read with the real listing probe.
 *
 * @param destination - The canonical destination directory.
 * @returns The listed links.
 */
function hostLinksOf(destination: string): ReadonlyMap<string, MergedSymlink> {
  const { fields } = runProbeScript(buildSymlinkListingProbeScript(), [
    encodeSymlinkListingEntry("r", destination),
  ])
  const host = hostStateFromListing(destination, fields, new Map())
  if (typeof host === "string") throw new Error(`unexpected listing: ${host}`)
  return host.links
}

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract kernel cross-check shell smoke tests (Issue #219)",
  () => {
    it("reports same, differ and dangling from the kernel's view of each link", () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "d"))
        writeFileSync(join(destination, "d/f"), "f\n")
        symlinkSync("f", join(destination, "d/right"))
        symlinkSync("f", join(destination, "d/wrong"))
        symlinkSync("missing/x", join(destination, "d/dangling"))
        symlinkSync("gone", join(destination, "d/half"))
        const link = (name: string): string => join(destination, "d", name)

        const d = join(destination, "d")

        const { code, verdicts } = runKernelCrossCheckScript([
          [link("right"), plainTrailPoints(link("right"), "f")],
          [link("wrong"), trailPoints([d, d], [link("f"), d])],
          [link("dangling"), plainTrailPoints(link("dangling"), "missing/x")],
          [link("half"), trailPoints([d, d], [link("gone"), link("f")])],
        ])

        expect(code).toBe(0)
        expect(verdicts).toStrictEqual([
          [link("right"), "same", "0"],
          [link("wrong"), "differ", "0"],
          // `d/missing/x` and `d/missing` exist on neither side; `d` does on both.
          [link("dangling"), "dangling", "3"],
          [link("half"), "differ", "1"],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("lets the backstop confirm contained links with the real cross-check and accept the tree", async () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "a/lib"), { recursive: true })
        writeFileSync(join(destination, "a/lib/f"), "f\n")
        symlinkSync("lib/f", join(destination, "a/inside"))
        symlinkSync("..", join(destination, "a/up"))
        symlinkSync("missing/y", join(destination, "a/dangling"))
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: treeLinksAsMembers(destination),
          source: "ok.tar",
        })

        expect(failure).toBeNull()
        expect(commands).toStrictEqual([
          buildSymlinkListingProbeScript(),
          buildKernelCrossCheckScript(),
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(!FOLDS_LETTER_CASE)(
      "sees d/esc -> UP/.. resolve through d/up in the kernel on a case-folding filesystem",
      () => {
        const { destination, root } = makeAppWorkspace()
        try {
          mkdirSync(join(destination, "d"))
          symlinkSync("..", join(destination, "d/up"))
          symlinkSync("UP/..", join(destination, "d/esc"))
          const esc = join(destination, "d/esc")

          // The kernel follows `d/up` for `d/UP`, so the cross-check alone
          // already disagrees with the plain lexical expectation `d`.
          expect(
            runKernelCrossCheckScript([[esc, plainTrailPoints(esc, "UP/..")]]).verdicts
          ).toStrictEqual([[esc, "differ", "0"]])
          expect(realpathSync.native(esc)).toBe(root)
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("compares the nearest existing point of a dangling link's target path with the model", () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "d/sub"), { recursive: true })
        const d = join(destination, "d")
        const link = (name: string, target: string): string => {
          symlinkSync(target, join(d, name))
          return join(d, name)
        }
        const inside = link("inside", "sub/n")
        const afterMissing = link("after-missing", "missing/../sub/n")
        // Hand-made: the model claims `outside` below the destination, while
        // the kernel walks out of it to the existing `<root>/other`.
        const claimed = link("claimed", "../../other/n")

        const { code, verdicts } = runKernelCrossCheckScript([
          [inside, plainTrailPoints(inside, "sub/n")],
          [afterMissing, plainTrailPoints(afterMissing, "missing/../sub/n")],
          [
            claimed,
            trailPoints(
              [d, d],
              [`${d}/..`, destination],
              [`${d}/../..`, destination],
              [`${d}/../../other`, `${destination}/other`],
              [`${d}/../../other/n`, `${destination}/other/n`]
            ),
          ],
        ])

        expect(code).toBe(0)
        expect(verdicts).toStrictEqual([
          // `d/sub` is the nearest existing point on both sides.
          [inside, "dangling", "2"],
          // The kernel cannot walk `..` out of the missing `d/missing`, while
          // the model's `d/sub` exists: refused, although nothing can be
          // written through the link today (a deliberate false positive).
          [afterMissing, "differ", "2"],
          // `<root>/other` exists on the host, `<destination>/other` does not.
          [claimed, "differ", "2"],
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("does not report a link whose final component is a dangling link resolving elsewhere inside", async () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "d"))
        mkdirSync(join(destination, "sub"))
        symlinkSync("b", join(destination, "d/l"))
        symlinkSync("../sub/q", join(destination, "d/b"))
        symlinkSync("c", join(destination, "d/m"))
        symlinkSync("missing/q", join(destination, "d/c"))
        const { commands, conn } = localShellConnection()
        const resolutions = mergedSymlinkResolutions(hostLinksOf(destination))

        const result = await runKernelCrossCheck(conn, {
          destination,
          links: resolutions.inside.keys(),
          trail: resolutions.trail,
        })

        expect([...resolutions.inside.keys()].toSorted()).toStrictEqual([
          "d/b",
          "d/c",
          "d/l",
          "d/m",
        ])
        expect(result).toStrictEqual({ kind: "ok", mismatches: [] })
        expect(commands).toStrictEqual([buildKernelCrossCheckScript()])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("names the trail point where the kernel and a hand-made model disagree for a dangling link", async () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "d"))
        mkdirSync(join(destination, "sub"))
        symlinkSync("missing/n", join(destination, "d/l"))
        const { conn } = localShellConnection()
        // Hand-made trail source: the model claims `d/missing` is the existing
        // `sub`, while the kernel finds no `d/missing`.
        const d = join(destination, "d")

        const result = await runKernelCrossCheck(conn, {
          destination,
          links: ["d/l"],
          trail: () => ({
            base: "d",
            locations: ["d", "sub", "sub/n"],
            segments: ["missing", "n"],
          }),
        })

        expect(result).toStrictEqual({
          kind: "ok",
          mismatches: [
            {
              at: { host: `${d}/missing`, kind: "point", location: `${destination}/sub` },
              expected: `${destination}/sub/n`,
              key: "d/l",
            },
          ],
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports x/esc -> ss/../../outside/n next to x/\u1e9e -> .. lexically on every filesystem", async () => {
      const { destination, outside, root } = makeSharpSWorkspace()
      try {
        mkdirSync(join(destination, "x"))
        symlinkSync("..", join(destination, "x/\u1e9e"))
        symlinkSync("ss/../../outside/n", join(destination, "x/esc"))
        expect(backstopViolations(destination)).toStrictEqual([["x/esc", "variant"]])
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: treeLinksAsMembers(destination),
          source: "sharp.tar",
        })

        expect(failure?.error?.message).toContain(
          'passes through "x/ss", a name that differs from existing symlink "x/\u1e9e" only by letter case or Unicode normalization'
        )
        expect(reportedLinks(failure?.error?.message)).toStrictEqual([join(destination, "x/esc")])
        expect(commands).toStrictEqual([
          buildSymlinkListingProbeScript(),
          buildKernelCrossCheckScript(),
        ])
        expect(readdirSync(outside)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it.skipIf(!FOLDS_CAPITAL_SHARP_S)(
      "sees the kernel disagree with the former inside expectation of x/esc -> ss/../../outside/n on a folding filesystem",
      async () => {
        const { destination, outside, root } = makeSharpSWorkspace()
        try {
          mkdirSync(join(destination, "x"))
          symlinkSync("..", join(destination, "x/\u1e9e"))
          symlinkSync("ss/../../outside/n", join(destination, "x/esc"))
          const { conn } = localShellConnection()
          const x = join(destination, "x")

          // The trail the model computed before `x/ss` counted as a name
          // variant of `x/\u1e9e`: a plain walk that stays inside.
          const result = await runKernelCrossCheck(conn, {
            destination,
            links: ["x/esc"],
            trail: () => ({
              base: "x",
              locations: ["x", "x/ss", "x", "", "outside", "outside/n"],
              segments: ["ss", "..", "..", "outside", "n"],
            }),
          })

          // Neither the link nor `<destination>/outside/n` exists, which the
          // former check accepted as dangling; the nearest existing point of
          // the kernel's walk is the `outside` directory beside the tree.
          expect(result).toStrictEqual({
            kind: "ok",
            mismatches: [
              {
                at: {
                  host: `${x}/ss/../../outside`,
                  kind: "point",
                  location: `${destination}/outside`,
                },
                expected: `${destination}/outside/n`,
                key: "x/esc",
              },
            ],
          })
          expect(realpathSync.native(`${x}/ss/../../outside`)).toBe(outside)
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("reports d/esc -> UP/.. next to d/up -> .. on every filesystem and removes nothing", async () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "d"))
        symlinkSync("..", join(destination, "d/up"))
        symlinkSync("UP/..", join(destination, "d/esc"))
        const esc = join(destination, "d/esc")
        // The name-variant rule reports the link lexically, whether or not the
        // filesystem folds case.
        expect(backstopViolations(destination)).toStrictEqual([["d/esc", "variant"]])
        const { conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: treeLinksAsMembers(destination),
          source: "case.tar",
        })

        expect(failure?.error?.message).toContain(
          'passes through "d/UP", a name that differs from existing symlink "d/up" only by letter case or Unicode normalization'
        )
        expect(reportedLinks(failure?.error?.message)).toStrictEqual([esc])
        expect(failure?.error?.message.endsWith(`; ${BACKSTOP_REPORT_TAIL}`)).toBe(true)
        expect(describeTree(destination)).toStrictEqual(["d d", "l d/esc -> UP/..", "l d/up -> .."])
        expect(readdirSync(root).toSorted()).toStrictEqual(["app", "other"])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

describe.skipIf(SKIP_PLATFORM || !ACCEPTS_NON_UTF8_NAMES)(
  "archive.extract listing decoding shell smoke tests (Issue #219, requires names that are not UTF-8)",
  () => {
    // `find` lists the two names in directory order, which the test cannot
    // choose, so the escaping target is put on each name in turn: whichever
    // name comes first, both the escaping-first and the escaping-last listing
    // occur across the two cases. The filesystem-independent variant with a
    // fixed listing order is in `archive.test.ts`.
    it.each([
      { name: "escaping link on <fe>", targets: { fe: "../a/l/../..", ff: "../a/l" } },
      { name: "escaping link on <ff>", targets: { fe: "../a/l", ff: "../a/l/../.." } },
    ])(
      "keeps two host links whose names differ only in bytes that are not UTF-8 apart and reports both when judged ($name)",
      async ({ targets }) => {
        const { destination, root } = makeAppWorkspace()
        try {
          mkdirSync(join(destination, "a"))
          writeFileSync(join(destination, "a/f"), "f\n")
          symlinkSync("f", join(destination, "a/l"))
          mkdirSync(join(destination, "d"))
          const base = Buffer.from(`${destination}/d/`)
          // Both targets walk through the archive link `a/l`, so both links
          // are judged; a lossy decode would have read both names as
          // `d/U+FFFD`, so one could hide the other.
          symlinkSync(targets.fe, Buffer.concat([base, Buffer.from([0xfe])]))
          symlinkSync(targets.ff, Buffer.concat([base, Buffer.from([0xff])]))
          const { commands, conn } = localShellConnection()

          const failure = await enforceSymlinkContainment(conn, {
            destination,
            members: [tarMember("a/l", "f")],
            source: "bytes.tar",
          })

          const message = String(failure?.error?.message)
          const spelled = ["fe", "ff"].map((byte) => join(destination, "d", `\\x${byte}`))
          for (const link of spelled)
            expect(message).toContain(`symlink ${JSON.stringify(link)} -> `)
          expect(message.match(/its path or target is not valid UTF-8/gv)).toHaveLength(2)
          // The listing, and the kernel cross-check of the archive link `a/l`.
          expect(commands).toStrictEqual([
            buildSymlinkListingProbeScript(),
            buildKernelCrossCheckScript(),
          ])
          expect(readdirSync(Buffer.from(join(destination, "d")))).toHaveLength(2)
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      }
    )

    it("ignores an unrelated host link whose name is not UTF-8", async () => {
      const { destination, root } = makeAppWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        writeFileSync(join(destination, "a/f"), "f\n")
        symlinkSync("f", join(destination, "a/l"))
        symlinkSync("/etc", Buffer.concat([Buffer.from(`${destination}/`), Buffer.from([0xff])]))
        const { commands, conn } = localShellConnection()

        const failure = await enforceSymlinkContainment(conn, {
          destination,
          members: [tarMember("a/l", "f")],
          source: "bytes.tar",
        })

        expect(failure).toBeNull()
        expect(commands).toStrictEqual([
          buildSymlinkListingProbeScript(),
          buildKernelCrossCheckScript(),
        ])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

/**
 * Issue #219: run the production flag read against a scratch flags
 * directory whose path needs quoting.
 *
 * @param prepare - Sets up the flag before the read; receives the flags
 *   directory (not yet created) and the flag path.
 * @returns What the read reports, and whether the flags directory exists.
 */
async function readPreparedFlag(
  prepare?: (paths: { directory: string; flag: string }) => void
): Promise<{
  directoryExists: boolean
  state: Awaited<ReturnType<typeof readContainmentFlag>>
}> {
  const root = mkdtempSync(join(tmpdir(), "paratix-flag-read-"))
  try {
    const directory = join(root, "it's flags")
    const flag = join(directory, "archive-containment-0123.failed")
    prepare?.({ directory, flag })
    const { conn } = localShellConnection()
    const state = await readContainmentFlag(conn, { directory, flag })
    return { directoryExists: existsSync(directory), state }
  } finally {
    rmSync(root, { force: true, recursive: true })
  }
}

describe.skipIf(SKIP_PLATFORM)(
  "archive.extract containment flag read shell smoke tests (Issue #219)",
  () => {
    it("creates the flags directory and reports an absent flag", async () => {
      await expect(readPreparedFlag()).resolves.toStrictEqual({
        directoryExists: true,
        state: { kind: "absent" },
      })
    })

    it("tells an empty flag apart from an absent one", async () => {
      const { state } = await readPreparedFlag(({ directory, flag }) => {
        mkdirSync(directory)
        writeFileSync(flag, "")
      })

      expect(state).toStrictEqual({
        kind: "unknown",
        why: expect.stringContaining("no usable list"),
      })
    })

    it("reads a recorded list, including a key with an unmappable-segment token", async () => {
      const links = ["a/esc", "b/\u0000ff/l"]
      const { state } = await readPreparedFlag(({ directory, flag }) => {
        mkdirSync(directory)
        writeFileSync(flag, containmentFlagBody({ links, state: "failed" }))
      })

      expect(state).toStrictEqual({ kind: "recorded", links })
    })

    it("reads a flag that is not valid UTF-8 as unknown", async () => {
      const { state } = await readPreparedFlag(({ directory, flag }) => {
        mkdirSync(directory)
        writeFileSync(flag, Buffer.from([0x7b, 0xff, 0x7d]))
      })

      expect(state).toStrictEqual({
        kind: "unknown",
        why: expect.stringContaining("not valid UTF-8"),
      })
    })

    it.each([
      {
        name: "a symlink to a recorded flag",
        prepare({ directory, flag }: { directory: string; flag: string }): void {
          mkdirSync(directory)
          writeFileSync(
            join(directory, "real"),
            containmentFlagBody({ links: [], state: "failed" })
          )
          symlinkSync("real", flag)
        },
        reason: "is a symlink",
      },
      {
        name: "a dangling symlink",
        prepare({ directory, flag }: { directory: string; flag: string }): void {
          mkdirSync(directory)
          symlinkSync("missing", flag)
        },
        reason: "is a symlink",
      },
      {
        name: "a directory",
        prepare({ flag }: { directory: string; flag: string }): void {
          mkdirSync(flag, { recursive: true })
        },
        reason: "exists but is not a regular file",
      },
      {
        name: "a flags directory path that is a regular file",
        prepare({ directory }: { directory: string; flag: string }): void {
          writeFileSync(directory, "")
        },
        reason: "failed to create archive marker directory for containment-failure flag",
      },
    ])("refuses to read $name", async ({ prepare, reason }) => {
      const { state } = await readPreparedFlag(prepare)

      expect(state).toStrictEqual({ kind: "unreadable", reason: expect.stringContaining(reason) })
    })
  }
)
