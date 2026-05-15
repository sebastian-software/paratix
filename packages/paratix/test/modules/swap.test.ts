import { describe, expect, it, vi } from "vitest"

import { swap } from "../../src/modules/swap.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

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
const safeSwapParentCommand = "find '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/'"
const createSwapTempCommand = `fallocate -l '${swapSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=2048 status=none && truncate -s 2147483648 '${swapTempPath}'; }`
const mktempSwapCommand = "mktemp -p '/' '.swapfile.paratix.XXXXXX'"
const publishSwapCommand = `find '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/' && mv -T -n '${swapTempPath}' '${swapPath}'`
const statSwapTempIdentityCommand = `stat -c '%d:%i' '${swapTempPath}'`
const verifyPublishedSwapCommand = `[ ! -e '${swapTempPath}' ] && find '${swapPath}' -maxdepth 0 -type f | grep -Fx '${swapPath}' && [ "$(stat -c '%d:%i' '${swapPath}')" = '${swapTempIdentity}' ] && swaplabel '${swapPath}' >/dev/null 2>&1`
const backupSwapCommand = `mv -T -n '${swapPath}' '${swapBackupPath}'`
const verifySwapBackupCommand = `[ ! -e '${swapPath}' ] && [ -f '${swapBackupPath}' ] && swaplabel '${swapBackupPath}' >/dev/null 2>&1`
const restoreSwapCommand = `mv -T -- '${swapBackupPath}' '${swapPath}'`
const flagsDirectoryCreateCommand = "mkdir -p /var/lib/paratix/flags"
const fstabLockMkdirCommand = "mkdir /var/lib/paratix/flags/'etc-fstab-mutex'"
const fstabLockRmdirCommand = "rmdir /var/lib/paratix/flags/'etc-fstab-mutex'"

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
})

describe("swap.file — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = swap.file({ path: swapPath, size: swapSize })
    const applyModule = mod.apply
    const result = await applyModule(null, emptyEnv)
    expect(result.status).toBe("failed")
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
    expect(ssh.calls).toContain(fstabLockRmdirCommand)
    const acquireIndex = ssh.calls.indexOf(fstabLockMkdirCommand)
    const fstabReadIndex = ssh.calls.indexOf(`cat '/etc/fstab'`)
    const releaseIndex = ssh.calls.indexOf(fstabLockRmdirCommand)
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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValueOnce([])
      .mockResolvedValue([])

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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValueOnce([])
      .mockResolvedValue([])

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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValueOnce([])
      .mockResolvedValue([])

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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValueOnce([])
      .mockResolvedValue([])

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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValue([])

    const mod = swap.file({ path: swapPath, size: swapSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to update /etc/fstab")
    expect(result.error?.message).toContain("fstab write failed")
    expect(ssh.calls).toContain(restoreSwapCommand)
    expect(ssh.calls).not.toContain(`rm -f '${swapBackupPath}'`)
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
    vi.spyOn(ssh, "lines")
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([swapPath])
      .mockResolvedValue([])

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
    const createSmallSwapTempCommand = `fallocate -l '${smallSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=512 status=none && truncate -s 536870912 '${swapTempPath}'; }`
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
    const createUnalignedSwapTempCommand = `fallocate -l '${unalignedSize}' '${swapTempPath}' || { dd if=/dev/zero of='${swapTempPath}' bs=1M count=2 status=none && truncate -s 1573888 '${swapTempPath}'; }`
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
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
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
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      "swapon --show=NAME --noheadings": { stdout: `${swapPath}\n` },
    })
    ssh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
    }

    const mod = swap.file({ path: swapPath, size: swapSize, state: "absent" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(fstabLockMkdirCommand)
    expect(ssh.calls).toContain(fstabLockRmdirCommand)
    const acquireIndex = ssh.calls.indexOf(fstabLockMkdirCommand)
    const fstabReadIndex = ssh.calls.indexOf(`cat '/etc/fstab'`)
    const releaseIndex = ssh.calls.indexOf(fstabLockRmdirCommand)
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
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f '${swapPath}'`]: { code: 1, stderr: "rm: cannot remove: Permission denied" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
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

  it("re-enables swap and reports both failures when absent removal rollback fails", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 0 },
      [`[ -f '${swapPath}' ]`]: { code: 0 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: `${fstabLine}\n` },
      [`cat '${swapPath}'`]: { stdout: "existing swap bytes" },
      [`rm -f '${swapPath}'`]: { code: 1, stderr: "rm: cannot remove: Permission denied" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 1, stderr: "swapon: failed" },
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
    // it with the legacy `[ ! -e ] && [ ! -L ]` test pair, which left a
    // TOCTOU window between test and rename.
    expect(publishSwapCommand).toContain("mv -T -n")
    expect(publishSwapCommand).not.toContain("[ ! -e")
    expect(publishSwapCommand).not.toContain("[ ! -L")
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
    expect(mod.name).toBe("sysctl.set: vm.swappiness=10")
  })

  it("uses sysctl.set for vfs cache pressure", () => {
    const mod = swap.vfsCachePressure(50)
    expect(mod.name).toBe("sysctl.set: vm.vfs_cache_pressure=50")
  })
})
