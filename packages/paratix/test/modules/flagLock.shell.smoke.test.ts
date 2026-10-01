/**
 * Shell-level smoke tests for the flag-lock layer.
 *
 * Plan 0092 introduced these tests after issue #35 showed that the
 * mock-pattern tests in moduleHelpers/mockSshFlagLock match exactly the
 * same string the production code emits — so a Production-side typo
 * (`awk … --`) is reflected verbatim in every assertion, and the suite
 * stays green even though the command fails on any real Linux box.
 *
 * The tests below run the production command strings through a real
 * `/bin/sh` against a temporary directory and assert on the observed
 * filesystem state. They cannot prevent every shell bug, but they catch
 * the entire class of "the command we generate does not actually do
 * what the comment claims" defects: bad quoting, missing escapes, awk
 * end-of-options confusion, and similar.
 */
import { execFileSync, spawnSync } from "node:child_process"
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import {
  buildFlagLockDiagnosticsCommand,
  parseFlagLockHolderDiagnostics,
} from "../../src/modules/flagLockRefresh.js"
import {
  buildFlagLockHolderMarkerWrite,
  buildFlagLockRefreshGuard,
  buildStaleFlagLockReclaimCommand,
} from "../../src/modules/flagLockScripts.js"
import { shellQuote } from "../../src/ssh.js"

type ShellResult = { code: number; stderr: string; stdout: string }

function runShell(
  commandLine: string,
  options: { args?: string[]; input?: string } = {}
): ShellResult {
  const result = spawnSync("/bin/sh", ["-c", commandLine, "sh", ...(options.args ?? [])], {
    encoding: "utf8",
    input: options.input,
    timeout: 5000,
  })
  return {
    code: result.status ?? -1,
    stderr: result.stderr,
    stdout: result.stdout,
  }
}

function makeFlagsRoot(): string {
  // mkdtemp returns an OS-tempdir path. The production code roots every
  // marker at `/var/lib/paratix/flags/`; for the smoke tests we substitute
  // the OS tempdir so we can run unprivileged.
  return mkdtempSync(join(tmpdir(), "paratix-flag-lock-smoke-"))
}

function isAwkAvailable(): boolean {
  try {
    execFileSync("awk", ["--version"], { stdio: "ignore", timeout: 2000 })
    return true
  } catch {
    return false
  }
}

/**
 * Issue #224: move a file's mtime `ageSeconds` into the past (portable,
 * instead of GNU-only `touch -d`).
 *
 * @param path - The file or directory to backdate.
 * @param ageSeconds - The age to set, in seconds.
 * @returns The resulting mtime in milliseconds.
 */
function backdate(path: string, ageSeconds: number): number {
  const seconds = Math.floor(Date.now() / 1000) - ageSeconds
  utimesSync(path, seconds, seconds)
  return statSync(path).mtimeMs
}

const SKIP_PLATFORM = process.platform === "win32"
const SKIP_NO_AWK = !isAwkAvailable()

describe.skipIf(SKIP_PLATFORM || SKIP_NO_AWK)("flagLock shell-level smoke tests", () => {
  describe("writeFlagLockHolderMarker", () => {
    it("printf statement creates a marker with the expected pid@hostname format", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        // Mirror the production sequence: mkdir lock dir, then printf the
        // marker contents.
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        const printfResult = runShell(
          `printf '%s@%s %s\\n' "$$" "test-host" "$(date +%s)" > '${markerPath}'`
        )
        expect(printfResult.code).toBe(0)
        // Read the marker back the way the production awk does it.
        const readbackResult = runShell(`awk 'NR==1{print $1}' '${markerPath}'`)
        expect(readbackResult.code).toBe(0)
        expect(readbackResult.stderr).toBe("")
        // Token format is `<pid>@<hostname>`. The pid is whatever sh -c
        // had, so just match the shape.
        expect(readbackResult.stdout.trim()).toMatch(/^\d+@test-host$/v)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("regression guard for issue #35: awk does not accept the -- end-of-options sentinel", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        writeFileSync(markerPath, "1234@host-x 1700000000\n")
        // Bare form (what production uses post-issue #35): works.
        const ok = runShell(`awk 'NR==1{print $1}' '${markerPath}'`)
        expect(ok.code).toBe(0)
        expect(ok.stdout.trim()).toBe("1234@host-x")
        // Faulty form (what production used pre-issue #35): awk treats
        // `--` as a literal filename and exits non-zero. If this test
        // ever turns green it means an awk implementation started
        // honouring `--`, at which point the production simplification
        // could be revisited.
        const broken = runShell(`awk 'NR==1{print $1}' -- '${markerPath}'`)
        expect(broken.code).not.toBe(0)
        expect(broken.stderr.toLowerCase()).toContain("--")
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  describe("releaseFlagLock", () => {
    it("ownership-checked release removes the marker and lock directory when tokens match", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        const token = "9999@test-host"
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        writeFileSync(markerPath, `${token} 1700000000\n`)

        // Mirror the production release command verbatim, with the
        // quoting layout the script actually uses.
        const expectedToken = `x${token}`
        const command =
          `awk_token=$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null); awk_status=$?; ` +
          `[ "$awk_status" = 0 ] && ` +
          `[ "x$awk_token" = '${expectedToken}' ] && ` +
          `rm -f -- '${markerPath}' && ` +
          `rmdir -- '${lockDir}'`
        const result = runShell(command)
        expect(result.code).toBe(0)
        // Both the marker and lock directory should be gone.
        expect(runShell(`[ -e '${markerPath}' ]`).code).not.toBe(0)
        expect(runShell(`[ -e '${lockDir}' ]`).code).not.toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("ownership-checked release leaves the lock untouched when tokens disagree", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        writeFileSync(markerPath, `7777@other-host 1700000000\n`)

        const expectedToken = "x9999@test-host"
        const command =
          `awk_token=$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null); awk_status=$?; ` +
          `[ "$awk_status" = 0 ] && ` +
          `[ "x$awk_token" = '${expectedToken}' ] && ` +
          `rm -f -- '${markerPath}' && ` +
          `rmdir -- '${lockDir}'`
        const result = runShell(command)
        // The conjunction short-circuits on the token mismatch — overall
        // exit is non-zero and the filesystem is preserved.
        expect(result.code).not.toBe(0)
        expect(runShell(`[ -f '${markerPath}' ]`).code).toBe(0)
        expect(runShell(`[ -d '${lockDir}' ]`).code).toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  describe("tryReclaimStaleFlagLock", () => {
    it("removes an old lock + marker pair when both predate the mmin threshold", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        writeFileSync(markerPath, "0000@stale-host 1500000000\n")
        // Backdate both the marker and the directory by ~1 day so the
        // `-mmin +0` check fires.
        expect(runShell(`touch -t 202401010000 '${markerPath}' '${lockDir}'`).code).toBe(0)

        const command =
          `if [ -d '${lockDir}' ]; then ` +
          `if [ -f '${markerPath}' ]; then ` +
          `STALE_TOKEN="$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null)"; ` +
          `if find '${markerPath}' -maxdepth 0 -mmin +0 -print -quit | grep -q .; then ` +
          `[ "$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null)" = "$STALE_TOKEN" ] && ` +
          `rm -f -- '${markerPath}' && rmdir -- '${lockDir}'; ` +
          `else exit 1; fi; ` +
          `else if find '${lockDir}' -maxdepth 0 -mmin +0 -print -quit | grep -q .; then ` +
          `find '${lockDir}' -maxdepth 0 -mmin +0 -print -quit | grep -q . && ` +
          `rm -f -- '${markerPath}' && rmdir -- '${lockDir}'; ` +
          `else exit 1; fi; fi; else exit 1; fi`
        const result = runShell(command)
        expect(result.code).toBe(0)
        expect(runShell(`[ -e '${lockDir}' ]`).code).not.toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })

    it("leaves a fresh lock untouched even when the same statement is replayed", () => {
      const root = makeFlagsRoot()
      try {
        const lockDir = join(root, "etc-fstab-mutex")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir '${lockDir}'`).code).toBe(0)
        writeFileSync(markerPath, "1111@fresh-host 1700000000\n")
        // No backdate — both the dir and marker are brand new.

        const command =
          `if [ -d '${lockDir}' ]; then ` +
          `if [ -f '${markerPath}' ]; then ` +
          `STALE_TOKEN="$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null)"; ` +
          `if find '${markerPath}' -maxdepth 0 -mmin +60 -print -quit | grep -q .; then ` +
          `[ "$(awk 'NR==1{print $1}' '${markerPath}' 2>/dev/null)" = "$STALE_TOKEN" ] && ` +
          `rm -f -- '${markerPath}' && rmdir -- '${lockDir}'; ` +
          `else exit 1; fi; ` +
          `else if find '${lockDir}' -maxdepth 0 -mmin +60 -print -quit | grep -q .; then ` +
          `find '${lockDir}' -maxdepth 0 -mmin +60 -print -quit | grep -q . && ` +
          `rm -f -- '${markerPath}' && rmdir -- '${lockDir}'; ` +
          `else exit 1; fi; fi; else exit 1; fi`
        const result = runShell(command)
        expect(result.code).not.toBe(0)
        expect(runShell(`[ -d '${lockDir}' ]`).code).toBe(0)
        expect(runShell(`[ -f '${markerPath}' ]`).code).toBe(0)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    })
  })

  // Issue #224: the refresh guard, the shared reclaim statement, the
  // caller-supplied holder marker and the diagnostics read, all run from the
  // production builders against a temporary lock directory.
  describe("refresh guard (issue #224)", () => {
    const token = "0123456789abcdef0123456789abcdef"
    // `-mmin +5`: the guard refuses markers older than 300 s.
    const guardSeconds = 360
    // `-mmin +9`: the reclaim removes markers older than 540 s.
    const staleSeconds = 600

    function createLock(
      root: string,
      markerToken = token
    ): { lockDir: string; markerPath: string } {
      const lockDir = join(root, "archive-extract-lock-0123456789abcdef")
      const markerPath = join(lockDir, "holder")
      expect(runShell(`mkdir ${shellQuote(lockDir)}`).code).toBe(0)
      const write = buildFlagLockHolderMarkerWrite(shellQuote(markerPath), {
        ownerLines: ["host=controller pid=42", "entry=run-abc"],
        token: markerToken,
      })
      expect(runShell(write).code).toBe(0)
      return { lockDir, markerPath }
    }

    function guardFor(lockDir: string, guardToken = token): string {
      return buildFlagLockRefreshGuard({
        guardSeconds,
        lockDirectory: { kind: "literal", value: lockDir },
        token: { kind: "literal", value: guardToken },
      })
    }

    function reclaimFor(lockDir: string, markerPath: string): string {
      return buildStaleFlagLockReclaimCommand({
        awkMarkerWord: shellQuote(markerPath),
        lockWord: shellQuote(lockDir),
        markerWord: shellQuote(markerPath),
        staleSeconds,
      })
    }

    function withRoot(body: (root: string) => void): void {
      const root = makeFlagsRoot()
      try {
        body(root)
      } finally {
        rmSync(root, { force: true, recursive: true })
      }
    }

    it("writes the caller-supplied token on line 1 and the owner lines after it", () => {
      withRoot((root) => {
        const { markerPath } = createLock(root)
        expect(readFileSync(markerPath, "utf8")).toBe(
          `${token}\nhost=controller pid=42\nentry=run-abc\n`
        )
        expect(runShell(`awk 'NR==1{print $1}' ${shellQuote(markerPath)}`).stdout.trim()).toBe(
          token
        )
      })
    })

    it("refreshes a fresh marker that carries the token", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 120)
        const result = runShell(guardFor(lockDir))
        expect(result).toStrictEqual({ code: 0, stderr: "", stdout: "" })
        expect(statSync(markerPath).mtimeMs).toBeGreaterThan(before)
      })
    })

    it("refuses a token mismatch and touches nothing", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 120)
        expect(runShell(guardFor(lockDir, "fedcba9876543210fedcba9876543210")).code).not.toBe(0)
        expect(statSync(markerPath).mtimeMs).toBe(before)
      })
    })

    it("refuses a missing lock directory and creates nothing", () => {
      withRoot((root) => {
        const lockDir = join(root, "archive-extract-lock-missing")
        expect(runShell(guardFor(lockDir)).code).not.toBe(0)
        expect(existsSync(lockDir)).toBe(false)
      })
    })

    it("refuses a lock directory without a marker and creates no marker", () => {
      withRoot((root) => {
        const lockDir = join(root, "archive-extract-lock-0123456789abcdef")
        expect(runShell(`mkdir ${shellQuote(lockDir)}`).code).toBe(0)
        expect(runShell(guardFor(lockDir)).code).not.toBe(0)
        expect(existsSync(join(lockDir, "holder"))).toBe(false)
      })
    })

    it("refuses a marker older than the guard threshold and touches nothing", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 400)
        expect(runShell(guardFor(lockDir)).code).not.toBe(0)
        expect(statSync(markerPath).mtimeMs).toBe(before)
      })
    })

    it("cannot refresh a reclaimable marker, which the reclaim then removes", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 600)
        backdate(lockDir, 600)
        expect(runShell(guardFor(lockDir)).code).not.toBe(0)
        expect(statSync(markerPath).mtimeMs).toBe(before)
        expect(runShell(reclaimFor(lockDir, markerPath)).code).toBe(0)
        expect(existsSync(lockDir)).toBe(false)
      })
    })

    it("does not reclaim a refreshable marker, which the guard then refreshes", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 240)
        backdate(lockDir, 600)
        expect(runShell(reclaimFor(lockDir, markerPath)).code).not.toBe(0)
        expect(statSync(markerPath).mtimeMs).toBe(before)
        expect(runShell(guardFor(lockDir)).code).toBe(0)
        expect(statSync(markerPath).mtimeMs).toBeGreaterThan(before)
      })
    })

    it("leaves a lost but not yet reclaimable marker to both sides", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        const before = backdate(markerPath, 420)
        expect(runShell(guardFor(lockDir)).code).not.toBe(0)
        expect(runShell(reclaimFor(lockDir, markerPath)).code).not.toBe(0)
        expect(statSync(markerPath).mtimeMs).toBe(before)
      })
    })

    // A crash between the `mkdir` and the marker write leaves a lock
    // directory without a marker: the reclaim then falls back to the
    // directory's own age, with the same threshold.
    it("reclaims a lock directory without a marker once the directory is older than the reclaim threshold", () => {
      withRoot((root) => {
        const lockDir = join(root, "archive-extract-lock-0123456789abcdef")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir ${shellQuote(lockDir)}`).code).toBe(0)
        backdate(lockDir, 600)
        expect(runShell(reclaimFor(lockDir, markerPath)).code).toBe(0)
        expect(existsSync(lockDir)).toBe(false)
      })
    })

    it("keeps a lock directory without a marker that is not yet older than the reclaim threshold", () => {
      withRoot((root) => {
        const lockDir = join(root, "archive-extract-lock-0123456789abcdef")
        const markerPath = join(lockDir, "holder")
        expect(runShell(`mkdir ${shellQuote(lockDir)}`).code).toBe(0)
        backdate(lockDir, 420)
        expect(runShell(reclaimFor(lockDir, markerPath)).code).not.toBe(0)
        expect(existsSync(lockDir)).toBe(true)
      })
    })

    it("reads no stdin, so a following command still receives the whole input", () => {
      withRoot((root) => {
        const { lockDir } = createLock(root)
        const result = runShell(`${guardFor(lockDir)} || exit 97; cat`, { input: "payload\n" })
        expect(result).toStrictEqual({ code: 0, stderr: "", stdout: "payload\n" })
      })
    })

    it("works with positional operands and exits through the caller's status", () => {
      withRoot((root) => {
        const { lockDir } = createLock(root)
        const guard = buildFlagLockRefreshGuard({
          guardSeconds,
          lockDirectory: { kind: "parameter", name: "1" },
          token: { kind: "parameter", name: "2" },
        })
        const script = `${guard} || exit 97; cat`
        const accepted = runShell(script, { args: [lockDir, token], input: "data" })
        const refused = runShell(script, { args: [lockDir, "x".repeat(32)], input: "data" })
        expect(accepted).toStrictEqual({ code: 0, stderr: "", stdout: "data" })
        expect(refused).toStrictEqual({ code: 97, stderr: "", stdout: "" })
      })
    })

    it("reports owner lines and the approximate marker age as diagnostics", () => {
      withRoot((root) => {
        const { lockDir, markerPath } = createLock(root)
        backdate(markerPath, 200)
        const command = buildFlagLockDiagnosticsCommand({
          lockWord: shellQuote(lockDir),
          markerWord: shellQuote(markerPath),
        })
        const diagnostics = parseFlagLockHolderDiagnostics(runShell(command).stdout)
        expect(diagnostics).toMatchObject({
          kind: "held",
          markerPresent: true,
          ownerLines: ["host=controller pid=42", "entry=run-abc"],
        })
        expect(diagnostics).toHaveProperty("ageSeconds", expect.closeTo(200, -1))
      })
    })

    it("reports an absent lock and a lock without a marker", () => {
      withRoot((root) => {
        const lockDir = join(root, "archive-extract-lock-0123456789abcdef")
        const command = buildFlagLockDiagnosticsCommand({
          lockWord: shellQuote(lockDir),
          markerWord: shellQuote(join(lockDir, "holder")),
        })
        expect(parseFlagLockHolderDiagnostics(runShell(command).stdout)).toStrictEqual({
          kind: "absent",
        })
        expect(runShell(`mkdir ${shellQuote(lockDir)}`).code).toBe(0)
        expect(parseFlagLockHolderDiagnostics(runShell(command).stdout)).toMatchObject({
          kind: "held",
          markerPresent: false,
          ownerLines: [],
        })
      })
    })
  })
})
