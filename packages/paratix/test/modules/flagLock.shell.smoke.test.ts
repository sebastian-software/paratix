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
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

type ShellResult = { code: number; stderr: string; stdout: string }

function runShell(commandLine: string): ShellResult {
  const result = spawnSync("/bin/sh", ["-c", commandLine], {
    encoding: "utf8",
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
})
