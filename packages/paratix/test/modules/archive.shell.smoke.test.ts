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
import { spawnSync } from "node:child_process"
import {
  chmodSync,
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

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import { buildStagingMergeScript } from "../../src/modules/archive.js"
import {
  enforceSymlinkContainment,
  type PreMergeContainmentVerdict,
  preMergeContainmentVerdict,
  symlinkListingEntries,
} from "../../src/modules/archiveContainmentEnforcement.js"
import {
  archiveMemberGuardPaths,
  destinationPathWithAncestors,
  preStagingProbeEntries,
} from "../../src/modules/archiveDestinationValidation.js"
import {
  buildPreStagingProbeScript,
  buildSymlinkContainmentProbeScript,
  buildSymlinkListingProbeScript,
  encodeNulPayload,
  encodeSymlinkListingEntry,
} from "../../src/modules/archiveProbe.js"
import { shellQuote } from "../../src/ssh.js"

type ShellResult = { code: number; stderr: string; stdout: string }

/**
 * Run the production merge script the way the remote `find -exec sh -c` does.
 *
 * @param parameters - Invocation inputs.
 * @param parameters.destination - Value for `$1` and `$2` (destination and its expected resolution).
 * @param parameters.guardPaths - Newline-separated guard paths for `$3`.
 * @param parameters.sourcePaths - Staging entries passed as the trailing arguments.
 * @returns Exit code and captured output.
 */
function runMergeScript(parameters: {
  destination: string
  guardPaths?: string[]
  sourcePaths: string[]
}): ShellResult {
  const { destination, sourcePaths } = parameters
  const guardPaths = (parameters.guardPaths ?? []).join("\n")
  const result = spawnSync(
    "/bin/sh",
    ["-c", buildStagingMergeScript(), "sh", destination, destination, guardPaths, ...sourcePaths],
    { encoding: "utf8", timeout: 5000 }
  )
  return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
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

/**
 * Issue #219: whether `command -p realpath -m` works, which the containment
 * probe relies on. GNU coreutils has it; the BSD `realpath` on macOS rejects
 * `-m`, so the probe cases are skipped there and run on Linux.
 *
 * @returns True when the system `realpath` resolves missing components.
 */
function hasRealpathMissingMode(): boolean {
  const result = spawnSync("/bin/sh", ["-c", "command -p realpath -m -- /nonexistent/a/b"], {
    encoding: "utf8",
    timeout: 2000,
  })
  return result.status === 0
}

type ContainmentProbeResult = { code: number; pairs: Array<[string, string]>; stderr: string }

/**
 * Issue #219: run the production containment probe the way `runBatchedProbe`
 * does, with the destination NUL-terminated on stdin.
 *
 * @param destination - The canonical destination directory.
 * @returns Exit code, the reported `(link, resolved)` pairs sorted by link, and stderr.
 */
function runContainmentProbe(destination: string): ContainmentProbeResult {
  const result = spawnSync("/bin/sh", ["-c", buildSymlinkContainmentProbeScript()], {
    encoding: "utf8",
    input: encodeNulPayload([destination]),
    timeout: 10_000,
  })
  const fields = result.stdout.split("\0")
  if (fields.at(-1) === "") fields.pop()
  const pairs: Array<[string, string]> = []
  for (let index = 0; index < fields.length; index += 2) {
    pairs.push([fields[index] ?? "", fields[index + 1] ?? "<missing>"])
  }
  pairs.sort(([left], [right]) => left.localeCompare(right))
  return { code: result.status ?? -1, pairs, stderr: result.stderr }
}

/**
 * Issue #219: run the production listing probe the way `runBatchedProbe`
 * does, with the destination as `r` entry NUL-terminated on stdin.
 *
 * @param destination - The canonical destination directory.
 * @returns Exit code, the reported `(link, target)` pairs sorted by link, and stderr.
 */
function runListingProbe(destination: string): ContainmentProbeResult {
  const result = spawnSync("/bin/sh", ["-c", buildSymlinkListingProbeScript()], {
    encoding: "utf8",
    input: encodeNulPayload([encodeSymlinkListingEntry("r", destination)]),
    timeout: 10_000,
  })
  const fields = result.stdout.split("\0")
  if (fields.at(-1) === "") fields.pop()
  const pairs: Array<[string, string]> = []
  for (let index = 0; index < fields.length; index += 2) {
    pairs.push([fields[index] ?? "", fields[index + 1] ?? "<missing>"])
  }
  pairs.sort(([left], [right]) => left.localeCompare(right))
  return { code: result.status ?? -1, pairs, stderr: result.stderr }
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

const SKIP_PLATFORM = process.platform === "win32"
const SKIP_NO_GNU_CP = !hasGnuCp()
const SKIP_NO_REALPATH_MISSING_MODE = !hasRealpathMissingMode()
const SKIP_NO_TRAILING_NEWLINE_READLINK = SKIP_PLATFORM || !readlinkAlwaysAppendsNewline()
// A privileged user reads directories regardless of their mode.
const SKIP_AS_ROOT = process.getuid?.() === 0

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

describe.skipIf(SKIP_PLATFORM || SKIP_NO_REALPATH_MISSING_MODE)(
  "archive.extract symlink containment probe shell smoke tests (Issue #219)",
  () => {
    it("reports nothing for contained, dangling-inside, looping and self links", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a/lib"), { recursive: true })
        writeFileSync(join(destination, "a/lib/f"), "f\n")
        symlinkSync("lib/f", join(destination, "a/inside"))
        symlinkSync("..", join(destination, "a/up"))
        symlinkSync("missing/y/z", join(destination, "a/dangling"))
        symlinkSync("loop-b", join(destination, "loop-a"))
        symlinkSync("loop-a", join(destination, "loop-b"))
        symlinkSync(".", join(destination, "self"))
        symlinkSync(join(destination, "a/lib"), join(destination, "absolute-inside"))

        const result = runContainmentProbe(destination)

        expect(result).toStrictEqual({ code: 0, pairs: [], stderr: "" })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports an absolute link outside and a relative link into a prefix sibling", () => {
      const { destination, root } = makeWorkspace()
      try {
        mkdirSync(join(destination, "a"))
        symlinkSync("/etc", join(destination, "a/etc"))
        // `<root>/destination-sibling` shares the destination's string prefix
        // but is a sibling, so a bare prefix comparison would accept it.
        symlinkSync("../destination-sibling", join(destination, "sibling"))

        const result = runContainmentProbe(destination)

        expect(result).toStrictEqual({
          code: 0,
          pairs: [
            [join(destination, "a/etc"), "/etc"],
            [join(destination, "sibling"), `${destination}-sibling`],
          ],
          stderr: "",
        })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("reports a link whose name contains a newline with its exact name", () => {
      const { destination, root } = makeWorkspace()
      try {
        const link = join(destination, "two\nlines")
        symlinkSync("..", link)

        const result = runContainmentProbe(destination)

        expect(result).toStrictEqual({ code: 0, pairs: [[link, root]], stderr: "" })
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("fails closed with a non-zero exit when find cannot walk the destination", () => {
      const { destination, root } = makeWorkspace()
      try {
        const result = runContainmentProbe(join(destination, "missing"))

        expect(result.code).not.toBe(0)
        expect(result.pairs).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    describe.skipIf(SKIP_NO_GNU_CP)("after real merges (requires GNU cp)", () => {
      it("reports the earlier run's link once a later run ships the link it walks through", () => {
        // Run 1 ships `a/esc -> up/..`, run 2 ships `a/up -> ..`. Each merge
        // succeeds with the product guard set and each tree is contained on its
        // own; after run 2, `a/esc` resolves via `a/up/..` to the destination's
        // parent.
        const { destination, root, staging } = makeWorkspace()
        try {
          const secondStaging = join(root, "staging-2")
          mkdirSync(join(staging, "a"))
          symlinkSync("up/..", join(staging, "a/esc"))
          mkdirSync(join(secondStaging, "a"), { recursive: true })
          symlinkSync("..", join(secondStaging, "a/up"))
          const mergeRun = (stagingRoot: string, link: [string, string]): ShellResult =>
            runMergeScript({
              destination,
              guardPaths: productGuardPaths(destination, [tarMember(...link)]),
              sourcePaths: [join(stagingRoot, "a")],
            })

          const first = mergeRun(staging, ["a/esc", "up/.."])
          expect(first).toMatchObject({ code: 0, stderr: "" })
          expect(runContainmentProbe(destination)).toStrictEqual({
            code: 0,
            pairs: [],
            stderr: "",
          })

          const second = mergeRun(secondStaging, ["a/up", ".."])
          expect(second).toMatchObject({ code: 0, stderr: "" })

          expect(readlinkSync(join(destination, "a/esc"))).toBe("up/..")
          expect(readlinkSync(join(destination, "a/up"))).toBe("..")
          expect(runContainmentProbe(destination)).toStrictEqual({
            code: 0,
            pairs: [[join(destination, "a/esc"), root]],
            stderr: "",
          })
        } finally {
          rmSync(root, { force: true, recursive: true })
        }
      })
    })
  }
)

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
            [join(destination, "a/dangling"), "missing/y/z"],
            [join(destination, "a/esc"), "up/.."],
            [join(destination, "a/inside"), "lib/f"],
            [join(destination, "a/up"), ".."],
            [join(destination, "absolute-inside"), `${destination}/a/lib`],
            [join(destination, "etc"), "/etc"],
          ].toSorted(([left = ""], [right = ""]) => left.localeCompare(right)),
          stderr: "",
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

        expect(runListingProbe(destination)).toStrictEqual({ code: 0, pairs: [], stderr: "" })
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
          pairs: [[join(destination, "to-elsewhere"), elsewhere]],
          stderr: "",
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
            [join(directory, "link with space"), "target with space"],
            [join(directory, "trailing space "), "../other dir/f"],
            [join(directory, "two\nlines"), ".."],
          ],
          stderr: "",
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
            [join(destination, "embedded"), "up\n/.."],
            [join(destination, "leading"), "\nleading"],
          ],
          stderr: "",
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
              [join(destination, "one"), "up\n"],
              [join(destination, "two"), "up\n\n"],
            ],
            stderr: "",
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

    it.skipIf(SKIP_AS_ROOT)(
      "fails closed with a non-zero exit when find cannot read a subdirectory",
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
 * `find <staging> -mindepth 1 -maxdepth 1 -exec sh -c <merge script> sh
 * <destination> <destination> <guard paths> {} +`, with the product guard set.
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
  const command = [
    `find ${shellQuote(staging)} -mindepth 1 -maxdepth 1 -exec sh -c`,
    shellQuote(buildStagingMergeScript()),
    "sh",
    shellQuote(destination),
    shellQuote(destination),
    shellQuote(productGuardPaths(destination, members).join("\n")),
    "{} +",
  ].join(" ")
  const result = spawnSync("/bin/sh", ["-c", command], { encoding: "utf8", timeout: 10_000 })
  return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
}

/**
 * Issue #219: an `SshConnection` whose `exec` runs the command on the local
 * `/bin/sh` with `input` on stdin, so the production backstop drives its real
 * probe and removal scripts against a temporary directory.
 *
 * @returns The connection and the commands it executed.
 */
function localShellConnection(): { commands: string[]; conn: SshConnection } {
  const commands: string[] = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      commands.push(command)
      const result = spawnSync("/bin/sh", ["-c", command], {
        encoding: "utf8",
        input: options?.input ?? "",
        timeout: 10_000,
      })
      return { code: result.status ?? -1, stderr: result.stderr, stdout: result.stdout }
    },
  } as unknown as SshConnection
  return { commands, conn }
}

/**
 * Issue #219: the destination-relative paths of the links the real
 * containment probe reports as escaping.
 *
 * @param destination - The canonical destination directory.
 * @returns The escaping links, sorted, relative to the destination.
 */
function escapingLinks(destination: string): string[] {
  const probe = runContainmentProbe(destination)
  expect({ code: probe.code, stderr: probe.stderr }).toStrictEqual({ code: 0, stderr: "" })
  return probe.pairs.map(([link]) => link.slice(destination.length + 1))
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

describe.skipIf(SKIP_PLATFORM || SKIP_NO_GNU_CP || SKIP_NO_REALPATH_MISSING_MODE)(
  "archive.extract two-run directory conflict after a real merge (Issue #219, requires GNU cp and realpath -m)",
  () => {
    it("shows the escape the refusal prevents, and the backstop removes only the escaping link", async () => {
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
        expect(escapingLinks(destination)).toStrictEqual([])
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
        expect(runContainmentProbe(destination).pairs).toStrictEqual([
          [join(destination, "a/c/l"), root],
        ])

        const { commands, conn } = localShellConnection()
        const failure = await enforceSymlinkContainment(conn, { destination, source: "run-2.tar" })

        expect(failure?.status).toBe("failed")
        expect(failure?.error?.message).toBe(
          `[archive.extract] refusing to complete extraction of run-2.tar: symlink ${JSON.stringify(join(destination, "a/c/l"))} resolves to ${JSON.stringify(root)}, outside destination ${JSON.stringify(destination)}; every symlink under the destination is checked after the merge, including links this archive did not ship; removed escaping symlinks: ${JSON.stringify(join(destination, "a/c/l"))}; re-check found no escaping symlinks`
        )
        // One probe, one batched removal, one re-probe.
        expect(commands).toHaveLength(3)
        expect(describeTree(destination)).toStrictEqual([
          "d a",
          "d a/b",
          "l a/b/hl -> ../..",
          "d a/c",
        ])
        expect(readdirSync(root).toSorted()).toStrictEqual(outsideBefore)
        expect(escapingLinks(destination)).toStrictEqual([])
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  }
)

type DifferentialCase = {
  /** The archive as extracted into staging, in listing order. */
  archive: string[]
  /** Destination-relative links the real backstop reports after the real merge. */
  escapes: string[]
  /** The host tree below the destination before the merge. */
  host: string[]
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
    merge: "failed",
    name: "archive symlink over a host directory without links below",
    preStaging: "n",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: twoRunSecondArchive,
    escapes: ["a/c/l"],
    host: twoRunFirstHost,
    merge: "failed",
    name: "archive symlink over a host directory with a link below (two-run case)",
    preStaging: "n",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: ["b -> a"],
    escapes: [],
    host: ["a/", "b/", "b/f"],
    merge: "failed",
    name: "top-level archive symlink over a host directory",
    preStaging: "n",
    verdict: "conflict:host-directory@b",
  },
  {
    archive: ["a/", "a/b", "a/c/", "a/c/l -> ../b/l/.."],
    escapes: ["a/c/l"],
    host: ["a/", "a/b/", "a/b/l -> ../.."],
    merge: "failed",
    name: "archive file over a host directory whose link the archive walks through",
    preStaging: "l",
    verdict: "conflict:host-directory@a/b",
  },
  {
    archive: ["a/", "a/b/", "a/b/f"],
    escapes: [],
    host: ["a/", "a/b"],
    merge: "failed",
    name: "archive directory over a host file",
    preStaging: "d",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/b/", "a/up -> b"],
    escapes: [],
    host: ["a/", "a/b/", "a/esc -> up/..", "a/up -> .."],
    merge: "ok",
    name: "archive symlink over a host symlink that makes the combination safe",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/up -> .."],
    escapes: ["a/esc"],
    host: ["a/", "a/b/", "a/esc -> up/..", "a/up -> b"],
    merge: "ok",
    name: "archive symlink over a host symlink that makes a host link escape",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/x -> y"],
    escapes: [],
    host: ["a/", "a/x"],
    merge: "ok",
    name: "archive symlink over a host file",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/f"],
    escapes: [],
    host: ["a/", "a/f"],
    merge: "ok",
    name: "archive file over a host file",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/up"],
    escapes: [],
    host: ["a/", "a/up -> .."],
    merge: "failed",
    name: "archive file over a host symlink",
    preStaging: "l",
    verdict: "conflict:host-symlink@a/up",
  },
  {
    archive: ["a/", "a/s/f"],
    escapes: [],
    host: ["a/", "t/", "a/s -> ../t"],
    merge: "failed",
    name: "archive file below a host symlink",
    preStaging: "l",
    verdict: "conflict:below-host-symlink@a/s",
  },
  {
    archive: ["a/", "a/d/", "a/d/new -> ../x/f"],
    escapes: [],
    host: ["a/", "a/d/", "a/d/keep -> ../x"],
    merge: "ok",
    name: "nested directory with a symlink merged into a host directory with links",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["a/", "a/d/", "a/d/s -> h/.."],
    escapes: ["a/d/s"],
    host: ["a/", "a/d/", "a/d/h -> ../.."],
    merge: "ok",
    name: "nested archive symlink that escapes through a host link in the same directory",
    preStaging: "l",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/up -> .."],
    escapes: ["a/esc"],
    host: ["a/", "a/esc -> up/.."],
    merge: "ok",
    name: "sibling archive link that makes an earlier host link escape",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/lib/", "a/lib/f", "a/lib64 -> lib", "a/bin/", "a/bin/f -> ../lib64/f"],
    escapes: [],
    host: [],
    merge: "ok",
    name: "contained archive links on an empty host",
    preStaging: "clean",
    verdict: "ok",
  },
  {
    archive: ["f"],
    escapes: ["etc"],
    host: ["etc -> /etc"],
    merge: "ok",
    name: "host link with an absolute target outside the destination",
    preStaging: "clean",
    verdict: "violations",
  },
  {
    archive: ["a/", "a/f"],
    escapes: [],
    host: ["a/", "abs -> $DEST/a"],
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
}): Omit<DifferentialCase, "archive" | "host" | "name"> {
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
  observed: Omit<DifferentialCase, "archive" | "host" | "name">,
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

describe.skipIf(SKIP_PLATFORM || SKIP_NO_GNU_CP || SKIP_NO_REALPATH_MISSING_MODE)(
  "archive.extract pre-merge model versus real merge (Issue #219, requires GNU cp and realpath -m)",
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
        const escapes = escapingLinks(destination)

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
