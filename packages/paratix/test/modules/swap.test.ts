import { describe, expect, it, vi } from "vitest"

import { swap } from "../../src/modules/swap.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const emptyEnv = {}
const swapPath = "/swapfile"
const swapSize = "2G"
const swapSizeBytes = "2147483648"
const fstabLine = `${swapPath} none swap sw 0 0`
const swapTempPath = "/.swapfile.paratix.ABC123"
const safeSwapParentCommand = "find '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/'"
const createSwapTempCommand = `fallocate -l '${swapSize}' '${swapTempPath}' || dd if=/dev/zero of='${swapTempPath}' bs=1M count=2048 status=none`
const mktempSwapCommand = "mktemp -p '/' '.swapfile.paratix.XXXXXX'"
const publishSwapCommand = `find '/' -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx '/' && [ ! -e '${swapPath}' ] && [ ! -L '${swapPath}' ] && mv -T '${swapTempPath}' '${swapPath}'`

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
      "swapon --show=NAME --noheadings": { stdout: "" },
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
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([{ content: `# fstab\n${fstabLine}\n`, path: "/etc/fstab" }])
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
      [`rm -f '${swapPath}'`]: { code: 0 },
      [`stat -c %s '${swapPath}'`]: { stdout: "1073741824" },
      [`swaplabel '${swapPath}' >/dev/null 2>&1`]: { code: 0 },
      [`swapoff '${swapPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [createSwapTempCommand]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
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
    expect(ssh.calls).toContain(`rm -f '${swapPath}'`)
    expect(ssh.calls).toContain(`mkswap '${swapTempPath}'`)
    expect(ssh.calls).toContain(`swapon '${swapPath}'`)
    expect(writtenFiles).toStrictEqual([])
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
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`[ -e '${swapPath}' ]`]: { code: 1 },
      [`[ -L '${swapPath}' ]`]: { code: 1 },
      [`cat '/etc/fstab'`]: { stdout: "# fstab\n" },
      [`cat '${swapPath}'`]: { code: 1, stdout: "" },
      [`chmod '0600' '${swapTempPath}'`]: { code: 0 },
      [`fallocate -l '${smallSize}' '${swapTempPath}' || dd if=/dev/zero of='${swapTempPath}' bs=1M count=512 status=none`]:
        { code: 0 },
      [`mkdir -p '/'`]: { code: 0 },
      [`mkswap '${swapTempPath}'`]: { code: 0 },
      [`swapon '${swapPath}'`]: { code: 0 },
      [mktempSwapCommand]: { code: 0, stdout: `${swapTempPath}\n` },
      [publishSwapCommand]: { code: 0 },
      [safeSwapParentCommand]: { code: 0, stdout: "/\n" },
      "swapon --show=NAME --noheadings": { stdout: "" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- mock implementation
    ssh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }

    const mod = swap.file({ path: swapPath, size: smallSize })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain(
      `fallocate -l '${smallSize}' '${swapTempPath}' || dd if=/dev/zero of='${swapTempPath}' bs=1M count=512 status=none`
    )
    // The fallback writes the desired fstab line; confirm no other writes
    // leaked through the writeFile spy.
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
})

describe("swap.file — option validation", () => {
  it("accepts valid path, mode, and priority boundaries", () => {
    expect(() =>
      swap.file({ mode: "0600", path: swapPath, priority: -1, size: swapSize })
    ).not.toThrow()
    expect(() => swap.file({ path: swapPath, priority: 0, size: swapSize })).not.toThrow()
    expect(() => swap.file({ path: swapPath, priority: 32_767, size: swapSize })).not.toThrow()
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
