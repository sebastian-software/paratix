// cspell:ignore fstype noexec nosuid nodev tmpfs umount findmnt noheadings mountpoint fstab
import { describe, expect, it } from "vitest"

import { mount } from "../../src/modules/mount.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const successfulMountApplyOptions: MockSshOptions = {
  allowWrites: [{ options: { mode: "0644" }, remotePath: "/etc/fstab" }],
  defaultExecResult: { code: 0 },
}

function createMountApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulMountApplyOptions)
}

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

// findmnt --output stdout for a live mount whose source/fstype/options
// match the desired values exactly.
const liveMountStdout = `${mountSrc} ${mountFstype} ${mountOpts}`

// ─── path validation ──────────────────────────────────────────────────────────

describe("mount.absent — path validation", () => {
  it("throws when path is the empty string", () => {
    expect(() => mount.absent({ path: "" })).toThrow(/mount path must not be empty/v)
  })

  it("throws when path is '/'", () => {
    expect(() => mount.absent({ path: "/" })).toThrow(/destructive path/v)
  })

  it("throws when path contains a newline", () => {
    expect(() => mount.absent({ path: "/mnt/data\n" })).toThrow(/mount path is invalid/v)
  })

  it("throws when path contains a carriage return", () => {
    expect(() => mount.absent({ path: "/mnt/data\r" })).toThrow(/mount path is invalid/v)
  })

  it("throws when path is relative", () => {
    expect(() => mount.absent({ path: "mnt/data" })).toThrow(/mount path is invalid/v)
  })

  it("throws when path contains whitespace", () => {
    expect(() => mount.absent({ path: "/mnt/data other" })).toThrow(/mount path is invalid/v)
  })

  it("throws when path is not normalized", () => {
    expect(() => mount.absent({ path: "/mnt//data" })).toThrow(/mount path is invalid/v)
  })
})

describe("mount.present — path validation", () => {
  it("throws when path is the empty string", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "", src: mountSrc })
    ).toThrow(/mount path must not be empty/v)
  })

  it("throws when path is '/'", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "/", src: mountSrc })
    ).toThrow(/destructive path/v)
  })

  it("throws when path contains a newline", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "/mnt/data\n", src: mountSrc })
    ).toThrow(/mount path is invalid/v)
  })

  it("throws when path contains a carriage return", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "/mnt/data\r", src: mountSrc })
    ).toThrow(/mount path is invalid/v)
  })

  it("throws when path is relative", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "mnt/data", src: mountSrc })
    ).toThrow(/mount path is invalid/v)
  })

  it("throws when path contains whitespace", () => {
    expect(() =>
      mount.present({
        fstype: mountFstype,
        opts: mountOpts,
        path: "/mnt/data other",
        src: mountSrc,
      })
    ).toThrow(/mount path is invalid/v)
  })

  it("throws when path is not normalized", () => {
    expect(() =>
      mount.present({ fstype: mountFstype, opts: mountOpts, path: "/mnt//data", src: mountSrc })
    ).toThrow(/mount path is invalid/v)
  })

  it.each([
    ["src", { src: "" }],
    ["src", { src: "tmp fs" }],
    ["src", { src: "tmpfs\nother" }],
    ["src", { src: "tmpfs\rother" }],
    ["fstype", { fstype: "" }],
    ["fstype", { fstype: "tmp fs" }],
    ["fstype", { fstype: "tmpfs\nother" }],
    ["opts", { opts: "" }],
    ["opts", { opts: "noexec nosuid" }],
    ["opts", { opts: "noexec\tnosuid" }],
    ["opts", { opts: "noexec\nnosuid" }],
  ])("throws when %s is not a valid fstab field", (_fieldName, overrides) => {
    expect(() =>
      mount.present({
        fstype: mountFstype,
        opts: mountOpts,
        path: mountPath,
        src: mountSrc,
        ...overrides,
      })
    ).toThrow(/fstab field/v)
  })
})

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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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

  // R-0000049 regression: when the live mount source / fstype / options
  // drift from the desired values, check returns needs-apply.
  it("returns needs-apply when live source differs from desired", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: `/dev/sdb1 ${mountFstype} ${mountOpts}` },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live options differ from desired", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${mountSrc} ${mountFstype} defaults` },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live fstype differs from desired", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${mountSrc} ext4 ${mountOpts}` },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live options have the same set in a different order", async () => {
    const reordered = mountOpts.split(",").reverse().join(",")
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${mountSrc} ${mountFstype} ${reordered}` },
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
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${oldLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
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

  // R-0000049 regression: a live mount whose options drifted but whose
  // src and fstype still match is converged via `mount -o remount,<opts>`.
  it("issues mount -o remount when only options drifted", async () => {
    const remountCmd = `mount -o remount,'${mountOpts}' '${mountSrc}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${mountSrc} ${mountFstype} defaults` },
      [remountCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(remountCmd)
    // No umount when remount is sufficient.
    expect(mockSsh.calls).not.toContain(umountCmd)
  })

  // R-0000049 regression: a live mount whose source drifted falls back to
  // umount + a fresh mount because remount cannot change the source.
  it("issues umount + mount when the source drifted", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `/dev/sdb1 ${mountFstype} ${mountOpts}` },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(umountCmd)
    expect(mockSsh.calls).toContain(mountCmd)
    const umountIndex = mockSsh.calls.indexOf(umountCmd)
    const mountIndex = mockSsh.calls.indexOf(mountCmd)
    expect(umountIndex).toBeLessThan(mountIndex)
  })

  // R-0000049 regression: a drifted fstype also falls back to umount + mount.
  it("issues umount + mount when the fstype drifted", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${mountSrc} ext4 ${mountOpts}` },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(umountCmd)
    expect(mockSsh.calls).toContain(mountCmd)
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
    const mockSsh = createMockSsh({
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(findmntTestCmd)
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls.indexOf(findmntTestCmd)).toBeLessThan(mockSsh.calls.indexOf(umountCmd))
    expect(mockSsh.calls).toContain(umountCmd)
  })

  it("returns failed when umount fails", async () => {
    const mockSsh = createMountApplyMockSsh({
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
    const mockSsh = createMountApplyMockSsh({
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
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when umount was needed", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("skips fstab when persist is false", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath, persist: false })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
  })

  it("skips umount when not mounted", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntTestCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(umountCmd)
  })
})
