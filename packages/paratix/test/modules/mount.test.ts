// cspell:ignore fstype noexec nosuid nodev tmpfs umount findmnt noheadings mountpoint fstab
import { describe, expect, it } from "vitest"

import { mount } from "../../src/modules/mount.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const mountPath = "/mnt/data"
const mountSrc = "tmpfs"
const mountFstype = "tmpfs"
const mountOpts = "noexec,nosuid,nodev,size=512m"

// Exact fstab line as buildFstabLine would produce
const fstabLine = `${mountSrc} ${mountPath} ${mountFstype} ${mountOpts} 0 0`

const findmntCheckCmd = `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS '${mountPath}'`
const findmntTestCmd = `findmnt --noheadings '${mountPath}'`
const mountCmd = `mount -t '${mountFstype}' -o '${mountOpts}' '${mountSrc}' '${mountPath}'`
const umountCmd = `umount '${mountPath}'`
const mkdirCmd = `mkdir -p '${mountPath}'`

// ─── mount.present ────────────────────────────────────────────────────────────

describe("mount.present — check", () => {
  it("returns needs-apply when ssh is null", async () => {
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when mountpoint is not mounted (findmnt fails)", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when mounted and fstab entry matches (persist: true)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when mounted but fstab entry differs", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${mountSrc} ${mountPath} ${mountFstype} defaults 0 0\n` },
      [findmntCheckCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when mounted but no fstab entry exists", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when mounted (persist: false, no fstab check)", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("uses findmnt with correct arguments", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(findmntCheckCmd)
  })
})

describe("mount.present — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
  })

  it("creates mountpoint with mkdir -p", async () => {
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(mkdirCmd)
  })

  it("writes fstab entry when persist is true", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(writtenFiles.some((f) => f.path === "/etc/fstab")).toBe(true)
  })

  it("reads fstab before writing (cat command)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/fstab'")
  })

  it("runs mount command when not already mounted", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(mountCmd)
  })

  it("returns ok when already mounted and fstab matches", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when mount was needed", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns failed when mount command fails", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntTestCmd]: { code: 1 },
      [mountCmd]: { code: 1, stderr: "mount failed" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[mount.present: /mnt/data] mount failed")
  })

  it("updates existing fstab entry when options differ", async () => {
    const oldLine = `${mountSrc} ${mountPath} ${mountFstype} defaults 0 0`
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${oldLine}\n` },
      [findmntTestCmd]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    const fstabWrite = writtenFiles.find((f) => f.path === "/etc/fstab")
    expect(fstabWrite).toBeDefined()
    expect(fstabWrite?.content).toContain(fstabLine)
    expect(fstabWrite?.content).not.toContain(oldLine)
  })

  it("skips fstab when persist is false", async () => {
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
  })
})

// ─── mount.absent ─────────────────────────────────────────────────────────────

describe("mount.absent — check", () => {
  it("returns needs-apply when ssh is null", async () => {
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when mountpoint is mounted", async () => {
    // test() returns true (code 0) by default when no mock is registered
    const mockSsh = createMockSsh()
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when not mounted and no fstab entry (persist: true)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when not mounted but fstab entry exists", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when not mounted (persist: false)", async () => {
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath, persist: false })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })
})

describe("mount.absent — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = mount.absent({ path: mountPath })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
  })

  it("runs umount when mounted", async () => {
    // test() returns true by default (no response registered = code 0 = mounted)
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(umountCmd)
  })

  it("returns failed when umount fails", async () => {
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 0 },
      [umountCmd]: { code: 1, stderr: "umount failed" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[mount.absent: /mnt/data] umount failed")
  })

  it("removes fstab entry when persist is true", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntTestCmd]: { code: 1 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    const fstabWrite = writtenFiles.find((f) => f.path === "/etc/fstab")
    expect(fstabWrite).toBeDefined()
    expect(fstabWrite?.content).not.toContain(mountPath)
  })

  it("returns ok when nothing to do (not mounted, no fstab entry)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when umount was needed", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("skips fstab when persist is false", async () => {
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath, persist: false })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
  })

  it("skips umount when not mounted", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(umountCmd)
  })
})
