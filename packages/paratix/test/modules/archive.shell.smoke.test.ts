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
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { buildStagingMergeScript } from "../../src/modules/archive.js"

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

const SKIP_PLATFORM = process.platform === "win32"
const SKIP_NO_GNU_CP = !hasGnuCp()

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
  })
})
