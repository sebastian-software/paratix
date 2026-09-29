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
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import type { ArchiveMember } from "../../src/modules/archiveMemberValidation.js"

import { buildStagingMergeScript } from "../../src/modules/archive.js"
import {
  archiveMemberGuardPaths,
  destinationPathWithAncestors,
} from "../../src/modules/archiveDestinationValidation.js"
import {
  buildSymlinkContainmentProbeScript,
  buildSymlinkListingProbeScript,
  encodeNulPayload,
} from "../../src/modules/archiveProbe.js"

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
 * does, with the destination NUL-terminated on stdin.
 *
 * @param destination - The canonical destination directory.
 * @returns Exit code, the reported `(link, target)` pairs sorted by link, and stderr.
 */
function runListingProbe(destination: string): ContainmentProbeResult {
  const result = spawnSync("/bin/sh", ["-c", buildSymlinkListingProbeScript()], {
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
