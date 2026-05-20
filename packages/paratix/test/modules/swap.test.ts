import { describe, expect, it, vi } from "vitest"

import { swap } from "../../src/modules/swap.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import { makeIsVerifiedReleaseCall } from "../helpers/mockSshFlagLock.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(
    { hostname: { code: 0, stdout: "" }, ...responses },
    {
      ...options,
      allowFlagLockInternalDefaults: true,
      responseStubs: [
        // R-0000494: holder marker now uses shellQuote(hostname) so the printf
        // form differs from the legacy `"$(hostname)"` pattern recognized by
        // the flag-lock internal defaults.
        {
          command: /^printf '%s@%s %s\\n' "\$\$" '' "\$\(date \+%s\)" > \S+\/holder$/v,
          result: { code: 0 },
        },
        ...(options?.responseStubs ?? []),
      ],
    }
  )

const emptyEnv = {}
const swapPath = "/swapfile"
const swapSize = "2G"
const swapSizeBytes = "2147483648"
const fstabLine = `${swapPath} none swap sw 0 0`
const swapTempPath = "/.swapfile.paratix.ABC123"
const swapTempIdentity = "2050:12345"
const swapBackupPath = `${swapPath}.paratix-backup`
// R-0000771: safeParentCommand now prefixes a `[ ! -L ]` guard and runs
// `find` with `-P` so a symlinked parent directory cannot mask the safety
// check by resolving to a different root-owned directory at probe time.
const safeSwapParentCommand =
  "[ ! -L '/' ] && find -P '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/'"
const createSwapTempCommand = `fallocate -l '${swapSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=2048 conv=fsync status=none && truncate -s 2147483648 '${swapTempPath}' || { rm -f -- '${swapTempPath}'; false; }; }`
const mktempSwapCommand = "mktemp -p '/' '.swapfile.paratix.XXXXXX'"
const publishSwapCommand = `[ ! -L '/' ] && find -P '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/' && mv -T -n '${swapTempPath}' '${swapPath}'`
const statSwapTempIdentityCommand = `stat -c '%d:%i' '${swapTempPath}'`
// R-0000680: publishSwapTemporaryFile now prepends a `[ ! -L ]` guard on the
// final swap path before running the `find -type f`/`swaplabel` verification,
// mirroring the symlink-safe rename guards in `moveSwapToBackup` and
// `restoreSwapBackup` (R-0000647). Tests have to match the combined statement
// the production code emits.
const verifyPublishedSwapCommand = `[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -e '${swapTempPath}' ] && find '${swapPath}' -maxdepth 0 -type f | grep -Fx '${swapPath}' && [ "$(stat -c '%d:%i' '${swapPath}')" = '${swapTempIdentity}' ] && swaplabel '${swapPath}' >/dev/null 2>&1`
// R-0000647: moveSwapToBackup now refuses symlinks at `$path` and `$backupPath`
// before issuing the rename. The mock has to match the combined statement the
// production code emits.
const backupSwapCommand = `[ ! -L '${swapBackupPath}' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -n -- '${swapPath}' '${swapBackupPath}'`
const verifySwapBackupCommand = `[ ! -e '${swapPath}' ] && [ -f '${swapBackupPath}' ] && swaplabel '${swapBackupPath}' >/dev/null 2>&1`
// R-0000624: the restore path now refuses to overwrite a symlink-shaped
// `$path` or `$backupPath`; the mock has to mirror the doubled `[ ! -L ]`
// guard the production code emits.
const restoreSwapCommand = `[ ! -L '${swapBackupPath}' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -- '${swapBackupPath}' '${swapPath}'`
const flagsDirectoryCreateCommand = "mkdir -p /var/lib/paratix/flags"
const fstabLockMkdirCommand = "mkdir /var/lib/paratix/flags/'etc-fstab-mutex'"
// R-0000634: release is now a single shell statement; tests use the shared
// helper to recognise the combined ownership-check + rmdir command.
const isFstabVerifiedReleaseCall = makeIsVerifiedReleaseCall("etc-fstab-mutex")

// R-0000722: `isSwapActive` now routes the `swapon --show` probe through
// `ssh.exec(..., { ignoreExitCode: true, silent: true })` so a non-zero
// exit surfaces as a structured ModuleResult instead of throwing. Tests
// that previously seeded `vi.spyOn(ssh, "lines")` with a sequential
// stdout pattern use this helper to seed the same sequence on the new
// `exec` code path, while letting unrelated `ssh.exec` calls fall through
// to the underlying mock harness.
function mockSwapShowSequence(
  ssh: ReturnType<typeof createMockSsh>,
  sequence: Array<{ code?: number; stderr?: string; stdout: string }>
): void {
  const originalExec = ssh.exec.bind(ssh)
  const probeResults = [...sequence]
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    if (command === "swapon --show=NAME --noheadings") {
      await Promise.resolve()
      ssh.calls.push(command)
      ssh.execCalls.push({ command, options })
      const next = probeResults.shift() ?? { code: 0, stdout: "" }
      return {
        code: next.code ?? 0,
        stderr: next.stderr ?? "",
        stdout: next.stdout,
      }
    }
    return originalExec(command, options)
  })
}

describe("swap.file — check", () => {
  it("returns needs-apply when ssh is null", async () => {
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when swap file, activation, fstab entry, and mode all match", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c '%a' '${swapPath}'`]: { code: 0, stdout: "600\n" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when the swap file mode drifts", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c '%a' '${swapPath}'`]: { code: 0, stdout: "644\n" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when stat for the swap file mode fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c '%a' '${swapPath}'`]: { code: 1, stdout: "" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the swap file is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the size differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the file lacks a swap signature", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing bytes" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 1 },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the swap is not active", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok for absent state when file is gone, inactive, and not persisted", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply for absent state when the fstab entry still exists", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000648: a non-zero `stat -c %s` (e.g. the swap file vanished between
  // `[ -e ]` and `stat`, or stat hit a permission error) used to propagate
  // an unstructured exception out of `readFileSizeInBytes`. The check path
  // now treats it as NEEDS_APPLY so the subsequent apply can produce a
  // structured failed ModuleResult.
  it("R-0000648: returns needs-apply when stat for the swap file size fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c %s '${swapPath}'`]: { code: 1, stderr: "stat: cannot stat: Permission denied" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000648: when the fstab read fails inside `hasSwapFstabEntry` the
  // check path now also reports NEEDS_APPLY (instead of crashing) so the
  // apply path is reached and produces a structured failure.
  it("R-0000648: returns needs-apply for present state when fstab read fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c %s '${swapPath}'`]: { code: 0, stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    ssh.readFile = async (): Promise<string> => {
      await Promise.resolve()
      throw new Error("fstab read denied")
    }
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000648: absent-state check must also fall back to NEEDS_APPLY when
  // the underlying fstab read fails, instead of misclassifying the host as
  // converged.
  it("R-0000648: returns needs-apply for absent state when fstab read fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })
    ssh.readFile = async (): Promise<string> => {
      await Promise.resolve()
      throw new Error("fstab read denied")
    }
    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // R-0000722: a non-zero exit from `swapon --show=NAME --noheadings`
  // (transient kernel issue, missing util-linux, permission denial) must
  // no longer throw — `isSwapActive` returns a structured failure and
  // `checkPresent`/`checkAbsent` fall back to NEEDS_APPLY so the apply
  // path produces a real diagnostic.
  it("R-0000722: returns needs-apply for present state when swapon --show fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`stat -c '%a' '${swapPath}'`]: { code: 0, stdout: "0600" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": {
        code: 1,
        stderr: "swapon: cannot open /proc/swaps: Permission denied",
      },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000722: returns needs-apply for absent state when swapon --show fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      "swapon --show=NAME --noheadings": {
        code: 1,
        stderr: "swapon: cannot open /proc/swaps: Permission denied",
      },
    })
    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("swap.file — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = swap.file({ path: swapPath, size: swapSize })
    const applyModule = mod.apply
    const result = await applyModule(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000648: when `stat -c %s` exits non-zero during the
  // needsSwapRecreation check inside apply, the helper must return a
  // structured failed ModuleResult instead of throwing. Mirrors the
  // R-0000648 check-side coverage above.
  it("R-0000648: returns failed when stat fails during apply needsSwapRecreation", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c %s '${swapPath}'`]: { code: 1, stderr: "stat: Permission denied" },
    })
    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("stat failed while reading swap file size")
  })

  it("creates, initializes, enables, and persists a new swap file", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(`mkdir -p '/'`)
    expect(ssh.calls).toContain(safeSwapParentCommand)
    expect(ssh.calls).toContain(createSwapTempCommand)
    expect(ssh.calls).toContain(`chmod '0600' '${swapTempPath}'`)
    expect(ssh.calls).toContain(`mkswap '${swapTempPath}'`)
    expect(ssh.calls).toContain(publishSwapCommand)
    expect(ssh.calls).toContain(verifyPublishedSwapCommand)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([{ content: `# fstab\n${fstabLine}\n`, path: "/etc/fstab" }])
  })

  it("acquires and releases the etc-fstab mutex lock around present-state fstab writes", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 0 },
    })
    ssh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
    }

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(fstabLockMkdirCommand)
    expect(ssh.calls.some(isFstabVerifiedReleaseCall)).toBe(true)
    const acquireIndex = ssh.calls.indexOf(fstabLockMkdirCommand)
    const fstabReadIndex = ssh.calls.indexOf(`cat '/etc/fstab'`)
    const releaseIndex = ssh.calls.findIndex(isFstabVerifiedReleaseCall)
    expect(acquireIndex).toBeLessThan(fstabReadIndex)
    expect(fstabReadIndex).toBeLessThan(releaseIndex)
  })

  it("returns failed instead of rejecting when the fstab mutex lock cannot be acquired", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [flagsDirectoryCreateCommand]: { code: 1, stderr: "read-only filesystem" },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 0 },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to update /etc/fstab")
    expect(result.error?.message).toContain("read-only filesystem")
    expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
  })

  it("refuses to create a swap file in a writable parent directory", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`mkdir -p '/'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 1 },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("parent directory is not safe")
    expect(ssh.calls).not.toContain(mktempSwapCommand)
    expect(ssh.calls).not.toContain(createSwapTempCommand)
    expect(ssh.calls).not.toContain(`swapon '${swapPath}'`)
    expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
  })

  it("cleans up the temp file and fails when the final publish guard detects a target race", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 1 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swap file publish failed")
    expect(ssh.calls).toContain(`rm -f '${swapTempPath}'`)
    expect(ssh.calls).not.toContain(`swapon '${swapPath}'`)
    expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
  })

  it("fails, cleans up, and does not enable swap when mv -n skips publishing the temp file", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 1 },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swap file publish verification failed")
    expect(ssh.calls).toContain(publishSwapCommand)
    expect(ssh.calls).toContain(verifyPublishedSwapCommand)
    expect(ssh.calls).toContain(`rm -f '${swapTempPath}'`)
    expect(ssh.calls).not.toContain(`swapon '${swapPath}'`)
    expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
  })

  // R-0000680: the post-publish verification must refuse to follow a symlink
  // that was planted at the destination between `mv -T -n` and the
  // `find -type f`/`swaplabel` check. The leading `[ ! -L ]` guard surfaces
  // the failure via the standard publish-verification path so the temp file
  // is cleaned up and swap is not enabled.
  it("R-0000680: refuses publish verification when the destination is a symlink", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      // The combined verification command fails because the leading
      // `[ ! -L '${swapPath}' ]` guard exits non-zero when the destination
      // was swapped to a symlink between the rename and the verification.
      [verifyPublishedSwapCommand]: {
        code: 1,
        stderr: "swap path must not be a symlink",
      },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swap file publish verification failed")
    expect(ssh.calls).toContain(verifyPublishedSwapCommand)
    expect(ssh.calls).toContain(`rm -f '${swapTempPath}'`)
    expect(ssh.calls).not.toContain(`swapon '${swapPath}'`)
  })

  it("recreates the file when size changed and swap is active", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapBackupPath}'`]: { code: 0 },
      [`stat -c '%a' '${swapPath}'`]: { code: 0, stdout: "600\n" },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifyPublishedSwapCommand]: { code: 0 },
      [verifySwapBackupCommand]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).toContain(backupSwapCommand)
    expect(ssh.calls).toContain(`rm -f '${swapBackupPath}'`)
    expect(ssh.calls).toContain(`mkswap '${swapTempPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })

  it("fails and re-enables swap when backup move is skipped by an existing backup", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [verifySwapBackupCommand]: { code: 1 },
    })
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swap backup verification failed")
    expect(ssh.calls).toContain(backupSwapCommand)
    expect(ssh.calls).toContain(verifySwapBackupCommand)
    expect(ssh.calls).toContain(`rm -f '${swapTempPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(ssh.calls).not.toContain(publishSwapCommand)
    expect(ssh.calls).not.toContain(restoreSwapCommand)
    expect(ssh.calls).not.toContain(`rm -f '${swapBackupPath}'`)
  })

  it("converges mode drift without recreating an otherwise valid active swap file", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapPath}'`]: { code: 0 },
      [`stat -c '%a' '${swapPath}'`]: { code: 0, stdout: "644\n" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(`chmod '0600' '${swapPath}'`)
    expect(ssh.calls).not.toContain(mktempSwapCommand)
    expect(ssh.calls).not.toContain(`swapoff '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })

  // R-0000681: a soft `stat -c '%a'` failure on the apply path must surface
  // as a structured failed ModuleResult so the operator sees the real
  // diagnostic. The legacy implementation collapsed every non-zero stat exit
  // into a plain `false`, which made `ensureSwapFileMode` retry the chmod on
  // a stale assumption that the mode mismatched.
  it("R-0000681: surfaces stat soft failures from the swap file mode probe on apply", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`stat -c '%a' '${swapPath}'`]: { code: 1, stderr: "stat: Permission denied" },
      [`stat -c %s '${swapPath}'`]: { stdout: swapSizeBytes },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("stat failed while reading swap file mode")
    // The chmod must NOT have been retried on a stale assumption.
    expect(ssh.calls).not.toContain(`chmod '0600' '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })

  it("restores the old swap file and returns swapon failure when replacement publish fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon failed" },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 1, stderr: "publish failed" },
      [restoreSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifySwapBackupCommand]: { code: 0 },
    })
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swapon failed")
    expect(ssh.calls).toContain(backupSwapCommand)
    expect(ssh.calls).toContain(restoreSwapCommand)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
  })

  it("R-0000175: keeps the backup until swapon and rolls back on swapon failure", async () => {
    // After the new swap file is published, swapon fails. The pre-fix
    // implementation removed the backup before swapon, leaving no rollback
    // path; the fixed implementation must restore the backup and re-enable
    // swap on the original file.
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`rm -f '${swapBackupPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon failed" },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [restoreSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifyPublishedSwapCommand]: { code: 0 },
      [verifySwapBackupCommand]: { code: 0 },
    })
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swapon failed")
    // Restore must have run, and the backup must NOT have been deleted before
    // the rollback (the rollback path never reaches `rm -f`).
    expect(ssh.calls).toContain(restoreSwapCommand)
    expect(ssh.calls).not.toContain(`rm -f '${swapBackupPath}'`)
  })

  it("rolls back replacement and returns failed when persisting fstab throws", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [restoreSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifyPublishedSwapCommand]: { code: 0 },
      [verifySwapBackupCommand]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (): Promise<void> => {
      throw new Error("fstab write failed")
    }
    mockSwapShowSequence(ssh, [
      { stdout: `${swapPath}\n` },
      { stdout: "" },
      { stdout: `${swapPath}\n` },
    ])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to update /etc/fstab")
    expect(result.error?.message).toContain("fstab write failed")
    expect(ssh.calls).toContain(restoreSwapCommand)
    expect(ssh.calls).not.toContain(`rm -f '${swapBackupPath}'`)
  })

  // R-0000722: when the rollback path also trips on a `swapon --show` probe
  // failure (e.g. /proc/swaps denied us read access during recovery), the
  // structured probe failure must be chained with the primary swapon
  // failure instead of silently replacing it. Without the chain the
  // operator would lose the user-visible reason that triggered the
  // rollback in the first place.
  it("R-0000722: chains rollback probe failure with the original swapon failure", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon failed" },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifyPublishedSwapCommand]: { code: 0 },
      [verifySwapBackupCommand]: { code: 0 },
    })
    // Sequence:
    //   1. disableSwap probe (recreate path) — swap IS active.
    //   2. enableSwap probe (apply pipeline) — swap is NOT active.
    //   3. rollback disableSwap probe — `swapon --show` itself fails.
    mockSwapShowSequence(ssh, [
      { stdout: `${swapPath}\n` },
      { stdout: "" },
      { code: 1, stderr: "swapon: /proc/swaps: Permission denied", stdout: "" },
    ])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    // The primary apply failure (swapon failed) must stay visible.
    expect(result.error?.message).toContain("swapon failed")
    // The probe failure must be chained with the rollback marker.
    expect(result.error?.message).toContain("rollback disableSwap failed")
    expect(result.error?.message).toContain("swapon --show failed")
  })

  it("returns rollback swapoff failure before restoring the backup", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 1, stderr: "swapoff failed" },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon failed" },
      [backupSwapCommand]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      [verifyPublishedSwapCommand]: { code: 0 },
      [verifySwapBackupCommand]: { code: 0 },
    })
    mockSwapShowSequence(ssh, [{ stdout: "" }, { stdout: "" }, { stdout: `${swapPath}\n` }])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swapoff failed")
    expect(ssh.calls).not.toContain(restoreSwapCommand)
    expect(ssh.calls).not.toContain(`rm -f '${swapBackupPath}'`)
  })

  it("does not swapoff the existing swap file when replacement creation fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`mkdir -p '/'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [createSwapTempCommand]: { code: 1, stderr: "disk full" },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("swap file creation failed")
    expect(ssh.calls).not.toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
  })

  it("does not swapoff the existing swap file when replacement chmod fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 1, stderr: "chmod failed" },
      [`mkdir -p '/'`]: { code: 0 },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("chmod failed")
    expect(ssh.calls).not.toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
  })

  it("does not swapoff the existing swap file when replacement mkswap fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 1, stderr: "mkswap failed" },
      [`rm -f '${swapTempPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("mkswap failed")
    expect(ssh.calls).not.toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
  })

  it("refuses to recreate an existing regular file without a swap signature", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "important application data" },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 1 },
    })

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refusing to remove unsafe path")
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
    expect(ssh.calls).not.toContain(`mkswap '${swapPath}'`)
    expect(ssh.calls).not.toContain(`swapon '${swapPath}'`)
    expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
  })

  const unsafePathCases: Array<{
    description: string
    responses: Parameters<typeof createMockSsh>[0]
  }> = [
    {
      description: "symbolic link",
      responses: {
        [`[ -L '${swapPath}' ]`]: { code: 0 },
      },
    },
    {
      description: "directory",
      responses: {
        [`[ -e '${swapPath}' ]`]: { code: 0 },
        [`[ -f '${swapPath}' ]`]: { code: 1 },
        [`[ -L '${swapPath}' ]`]: { code: 1 },
      },
    },
  ]

  it.each(unsafePathCases)(
    "refuses to remove an unsafe $description for absent state",
    async ({ responses }) => {
      const ssh = createMockSsh(responses)

      const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("refusing to remove unsafe path")
      expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
      expect(ssh.calls).not.toContain(`swapoff '${swapPath}'`)
      expect(ssh.calls).not.toContain(`cat '/etc/fstab'`)
    }
  )

  it("uses 1M block size in dd fallback regardless of swap size", async () => {
    const smallSize = "512M"
    const createSmallSwapTempCommand = `fallocate -l '${smallSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=512 conv=fsync status=none && truncate -s 536870912 '${swapTempPath}' || { rm -f -- '${swapTempPath}'; false; }; }`
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createSmallSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: smallSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(createSmallSwapTempCommand)
    // The fallback writes the desired fstab line; confirm no other writes
    // leaked through the writeFile spy.
    expect(writtenFiles.map((entry) => entry.path)).toStrictEqual(["/etc/fstab"])
  })

  it("trims the dd fallback to the exact requested byte size for unaligned sizes", async () => {
    const unalignedSize = "1537K"
    const createUnalignedSwapTempCommand = `fallocate -l '${unalignedSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=2 conv=fsync status=none && truncate -s 1573888 '${swapTempPath}' || { rm -f -- '${swapTempPath}'; false; }; }`
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createUnalignedSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [statSwapTempIdentityCommand]: { code: 0, stdout: `${swapTempIdentity}\n` },
      "swapon --show=NAME --noheadings": { stdout: "" },
      [verifyPublishedSwapCommand]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: unalignedSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(createUnalignedSwapTempCommand)
    expect(writtenFiles.map((entry) => entry.path)).toStrictEqual(["/etc/fstab"])
  })

  it("removes swap activation, persistence, and file for absent state", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      // R-0000649: the pre-snapshot rm now refuses to operate on a symlink,
      // so the production code emits a combined `[ ! -L ] || exit 1; rm -f`
      // statement. The cleanup-rm after a successful snapshot still uses the
      // bare `rm -f --` form.
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      // R-0000618: snapshot the swap file before rm so a fstab-write failure
      // can be rolled back.
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).toContain(`rm -f '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([{ content: "\n", path: "/etc/fstab" }])
  })

  it("acquires and releases the etc-fstab mutex lock around absent-state fstab writes", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      // R-0000649: the pre-snapshot rm now refuses to operate on a symlink,
      // so the production code emits a combined `[ ! -L ] || exit 1; rm -f`
      // statement. The cleanup-rm after a successful snapshot still uses the
      // bare `rm -f --` form.
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      // R-0000618: snapshot the swap file before rm so a fstab-write failure
      // can be rolled back.
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    ssh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(fstabLockMkdirCommand)
    expect(ssh.calls.some(isFstabVerifiedReleaseCall)).toBe(true)
    const acquireIndex = ssh.calls.indexOf(fstabLockMkdirCommand)
    const fstabReadIndex = ssh.calls.indexOf(`cat '/etc/fstab'`)
    const releaseIndex = ssh.calls.findIndex(isFstabVerifiedReleaseCall)
    expect(acquireIndex).toBeLessThan(fstabReadIndex)
    expect(fstabReadIndex).toBeLessThan(releaseIndex)
  })

  // R-0000287: when removeSwapFile fails (permission denied, file busy), the
  // fstab entry must remain so the next run can still recover the managed
  // state. The earlier order pruned fstab first and left the swap file
  // orphaned on disk after a failing rm.
  it("R-0000287: keeps fstab entry intact and returns failed when rm fails for absent state", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      // R-0000649: the pre-snapshot rm now refuses to operate on a symlink,
      // so the production code emits a combined `[ ! -L ] || exit 1; rm -f`
      // statement. The cleanup-rm after a successful snapshot still uses the
      // bare `rm -f --` form.
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      // R-0000618: snapshot the swap file before rm so a fstab-write failure
      // can be rolled back.
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 1, stderr: "rm: cannot remove: Permission denied" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rm failed")
    expect(ssh.calls).toContain(`rm -f '${swapPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    // fstab must NOT have been rewritten — the entry stays so the next run
    // can recover.
    expect(writtenFiles).toStrictEqual([])
  })

  // R-0000618: when removeSwapFile succeeds but the subsequent fstab write
  // fails, the absent flow must restore the swap file from a hardlink
  // snapshot taken before the rm. Without the snapshot, the swap file would
  // be gone while /etc/fstab still references it, and `swapon -a` on the
  // next boot would fail.
  it("R-0000618: restores swap file from snapshot when absent fstab write fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -- '${swapPath}.paratix-absent-backup' '${swapPath}'`]:
        { code: 0 },
      // R-0000649: the pre-snapshot rm now refuses to operate on a symlink,
      // so the production code emits a combined `[ ! -L ] || exit 1; rm -f`
      // statement. The cleanup-rm after a successful snapshot still uses the
      // bare `rm -f --` form.
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
    })
    // First `swapon --show` (initial isSwapActive in disableSwap) reports
    // the swap active; the second call after the rollback (enableSwap →
    // isSwapActive) reports it inactive so swapon is invoked.
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])
    // eslint-disable-next-line @typescript-eslint/require-await -- intentionally synchronous reject
    ssh.writeFile = async (): Promise<void> => {
      throw new Error("fstab write blew up")
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("restored from snapshot")
    expect(ssh.calls).toContain(
      `[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`
    )
    expect(ssh.calls).toContain(`rm -f '${swapPath}'`)
    expect(ssh.calls).toContain(
      `[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -- '${swapPath}.paratix-absent-backup' '${swapPath}'`
    )
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
  })

  it("re-enables swap and reports both failures when absent removal rollback fails", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      // R-0000649: the pre-snapshot rm now refuses to operate on a symlink,
      // so the production code emits a combined `[ ! -L ] || exit 1; rm -f`
      // statement. The cleanup-rm after a successful snapshot still uses the
      // bare `rm -f --` form.
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      // R-0000618: snapshot the swap file before rm so a fstab-write failure
      // can be rolled back.
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 1, stderr: "rm: cannot remove: Permission denied" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon: failed" },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rm failed")
    expect(result.error?.message).toContain("rollback swapon failed")
    expect(result.error?.message).toContain("swapon failed")
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })

  // R-0000649: the pre-snapshot rm must run inside a single shell statement
  // that first rejects a symlink at backupPath. Without the combined check
  // an attacker with write access to the parent could plant a symlink at
  // backupPath after this rm but before the subsequent `ln -P --`, and the
  // unconditional rm would follow it to the link target. The probe and the
  // rm therefore have to live in the same shell invocation; the legacy
  // bare `rm -f -- <backupPath>` must no longer appear before the link.
  it("R-0000649: pre-snapshot rm is a single combined symlink-probe + rm statement", async () => {
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`]:
        { code: 0 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f -- '${swapPath}.paratix-absent-backup'`]: { code: 0 },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    ssh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const combinedPreSnapshotRm = `[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`
    const snapshotLink = `[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`
    expect(ssh.calls).toContain(combinedPreSnapshotRm)
    expect(ssh.calls).toContain(snapshotLink)
    // The combined pre-snapshot rm must execute before the snapshot link.
    expect(ssh.calls.indexOf(combinedPreSnapshotRm)).toBeLessThan(ssh.calls.indexOf(snapshotLink))
    // The cleanup-rm at the end of the absent flow still uses the bare
    // `rm -f --` form, but no occurrence of that bare form may precede the
    // snapshot link (i.e. there is no legacy unguarded pre-snapshot rm).
    const bareRmIndex = ssh.calls.indexOf(`rm -f -- '${swapPath}.paratix-absent-backup'`)
    expect(bareRmIndex).toBeGreaterThan(ssh.calls.indexOf(snapshotLink))
  })

  // R-0000679: when safeParentCommand fails after the swapoff already
  // disabled swap, the absent flow must reactivate swap before surfacing
  // the failure. Otherwise the host runs without swap until the next boot.
  it("R-0000679: reactivates swap when absent safeParent probe fails after swapoff", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [safeSwapParentCommand]: { code: 1 },
    })
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("parent directory is not safe")
    expect(ssh.calls).toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    // No rm or fstab edit must have happened — the snapshot was never taken.
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })

  // R-0000679: when snapshotSwapFileForAbsentFlow fails after the swapoff
  // already disabled swap, the absent flow must reactivate swap before
  // surfacing the snapshot failure. Same rationale as the safeParent path.
  it("R-0000679: reactivates swap when absent snapshot link fails after swapoff", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const snapshotLink = `[ ! -L '${swapPath}' ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- '${swapPath}' '${swapPath}.paratix-absent-backup'`
    const preSnapshotRm = `[ ! -L '${swapPath}.paratix-absent-backup' ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; rm -f -- '${swapPath}.paratix-absent-backup'`
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [preSnapshotRm]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      [snapshotLink]: { code: 1, stderr: "ln: cannot create hard link" },
    })
    mockSwapShowSequence(ssh, [{ stdout: `${swapPath}\n` }, { stdout: "" }])
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(ssh.calls).toContain(`swapoff '${swapPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    // No rm or fstab edit must have happened — the snapshot link itself failed.
    expect(ssh.calls).not.toContain(`rm -f '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
  })
})

describe("swap.file — option validation", () => {
  it("accepts valid path, mode, and priority boundaries", () => {
    expect(() =>
      swap.file({ mode: "0600", path: swapPath, priority: -1, size: swapSize })
    ).not.toThrow()
    expect(() => swap.file({ path: swapPath, priority: 0, size: swapSize })).not.toThrow()
    expect(() => swap.file({ path: swapPath, priority: 32_767, size: swapSize })).not.toThrow()
  })

  it("accepts valid swap file states", () => {
    expect(() => swap.file({ path: swapPath, size: swapSize, state: "present" })).not.toThrow()
    expect(() => swap.file({ path: swapPath, size: swapSize, state: "absent" })).not.toThrow()
  })

  it("rejects invalid swap file state strings", () => {
    for (const state of ["", "enabled", "ABSENT"]) {
      expect(() =>
        swap.file({ path: swapPath, size: swapSize, state: state as "absent" | "present" })
      ).toThrow('swap.file state must be "present" or "absent"')
    }
  })

  it("rejects non-string swap file states", () => {
    for (const state of [null, false, 1] as unknown[]) {
      expect(() =>
        swap.file({
          path: swapPath,
          size: swapSize,
          state: state as "absent" | "present",
        })
      ).toThrow('swap.file state must be "present" or "absent"')
    }
  })

  it("rejects unsafe swap file paths", () => {
    for (const path of ["", "swapfile", "/", "/var/../swapfile", "/swap file", "/swapfile\n"]) {
      expect(() => swap.file({ path, size: swapSize })).toThrow(/swap\.file: path/v)
    }
  })

  it("rejects invalid file modes", () => {
    for (const mode of ["888", "77", ""]) {
      expect(() => swap.file({ mode, path: swapPath, size: swapSize })).toThrow(/mode/v)
    }
  })

  it("rejects invalid priorities", () => {
    for (const priority of [1.5, Number.NaN, Number.POSITIVE_INFINITY, -2, 32_768]) {
      expect(() => swap.file({ path: swapPath, priority, size: swapSize })).toThrow(/priority/v)
    }
  })

  it("R-0000180: publish uses mv -T -n to avoid TOCTOU on the destination", () => {
    // The constructed command must contain `mv -T -n` and must NOT precede
    // it with the legacy `[ ! -e ] && [ ! -L ${swapPath} ]` test pair on
    // the destination, which left a TOCTOU window between test and rename.
    // R-0000771: a `[ ! -L ${parent} ]` guard on the parent directory plus
    // `find -P` is allowed (and required), so check for the destination
    // guard specifically by including the path itself.
    expect(publishSwapCommand).toContain("mv -T -n")
    expect(publishSwapCommand).not.toContain("[ ! -e")
    expect(publishSwapCommand).not.toContain(`[ ! -L '${swapPath}'`)
  })

  // R-0000246 regression: the swap-backup creation in swapHelpers must use
  // `mv -T -n` and must not precede it with a `[ ! -e backup ]` probe
  // (which leaves a TOCTOU window before the rename). Mirrors R-0000180 in
  // swapFileCreateHelpers.
  it("R-0000246: backup uses mv -T -n to avoid TOCTOU on the backup destination", () => {
    expect(backupSwapCommand).toContain("mv -T -n")
    expect(backupSwapCommand).not.toContain("[ ! -e")
  })

  it("R-0000178: rejects sizes that exceed Number.MAX_SAFE_INTEGER", () => {
    // 16P would translate to 16 * 1024^5 = ~1.8e16, well above
    // Number.MAX_SAFE_INTEGER (~9e15).
    expect(() => swap.file({ path: swapPath, size: "16P" })).toThrow(/MAX_SAFE_INTEGER/v)
  })

  it("R-0000178: accepts a size right at the safe-integer boundary", () => {
    // Largest accepted value: a count of TiB that stays below MAX_SAFE_INTEGER
    // when multiplied by 1024^4 = 8 * 1024^4 = 8 TiB.
    expect(() => swap.file({ path: swapPath, size: "8T" })).not.toThrow()
  })
})

describe("swap tuning wrappers", () => {
  it("uses sysctl.set for swappiness", () => {
    const mod = swap.swappiness(10)
    expect(mod.name).toBe("sysctl.set: vm.swappiness")
  })

  it("uses sysctl.set for vfs cache pressure", () => {
    const mod = swap.vfsCachePressure(50)
    expect(mod.name).toBe("sysctl.set: vm.vfs_cache_pressure")
  })
})
