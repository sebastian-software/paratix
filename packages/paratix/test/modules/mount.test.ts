import { describe, expect, it } from "vitest"

import { mount } from "../../src/modules/mount.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh({ [mountPathSymlinkGuardCmd]: { code: 0 }, ...responses }, options)

const successfulMountApplyOptions: MockSshOptions = {
  allowUnstubbedDefaults: true,
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
const defaultMountOpts = "defaults"
const expandedDefaultMountOpts = "rw,relatime"

// Exact fstab line as buildFstabLine would produce
const fstabLine = `${mountSrc} ${mountPath} ${mountFstype} ${mountOpts} 0 0`

const findmntCheckCmd = `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS '${mountPath}'`
const findmntTestCmd = `findmnt --noheadings '${mountPath}'`
const mountCmd = `mount -t '${mountFstype}' -o '${mountOpts}' -- '${mountSrc}' '${mountPath}'`
const umountCmd = `umount '${mountPath}'`
const mkdirCmd = `mkdir -p '${mountPath}'`
const mountPathRealpathCmd = `readlink -f -- '${mountPath}' 2>/dev/null || printf '%s\\n' '${mountPath}'`
const mountPathSymlinkGuardCmd = [
  `mount_path='${mountPath}'`,
  'current="$mount_path"',
  'while [ "$current" != "/" ]; do',
  'if [ -e "$current" ] && [ -L "$current" ]; then',
  `printf '%s\\n' "mount path contains symlink: $current" >&2`,
  "exit 1",
  "fi",
  'current=$(dirname "$current")',
  "done",
].join("; ")

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

  it("throws when src starts with a flag prefix", () => {
    expect(() =>
      mount.present({
        fstype: mountFstype,
        opts: mountOpts,
        path: mountPath,
        src: "--bind",
      })
    ).toThrow(/src fstab field must not start with '-'/v)
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

  it("returns needs-apply when mount path contains a symlink", async () => {
    const mockSsh = createMockSsh({
      [mountPathSymlinkGuardCmd]: { code: 1, stderr: "mount path contains symlink: /mnt" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
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

  it("returns ok when fstab-only options are absent from live mount options", async () => {
    const optsWithFstabOnly = `${mountOpts},nofail,_netdev,x-systemd.requires=network-online.target`
    const fstabOnlyLine = `${mountSrc} ${mountPath} ${mountFstype} ${optsWithFstabOnly} 0 0`
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabOnlyLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: optsWithFstabOnly,
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

  it("returns ok when defaults are expanded in live mount options", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": {
        stdout: `${mountSrc} ${mountPath} ${mountFstype} ${defaultMountOpts} 0 0\n`,
      },
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts}`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when ext4 adds generated live options to defaults", async () => {
    const ext4Src = "/dev/sdb1"
    const ext4Fstype = "ext4"
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": {
        stdout: `${ext4Src} ${mountPath} ${ext4Fstype} ${defaultMountOpts} 0 0\n`,
      },
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${ext4Src} ${ext4Fstype} rw,relatime,errors=remount-ro`,
      },
    })
    const mod = mount.present({
      fstype: ext4Fstype,
      opts: defaultMountOpts,
      path: mountPath,
      src: ext4Src,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when tmpfs adds generated live inode options", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} rw,nosuid,nodev,noexec,relatime,size=512m,inode64`,
      },
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

  it("returns ok when tmpfs normalizes size units in live options", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} rw,nosuid,nodev,noexec,relatime,size=536870912`,
      },
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

  it("preserves explicit security option drift when defaults are desired", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts},noexec`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when explicit security options are combined with defaults", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts},noexec`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: `${defaultMountOpts},noexec`,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live options contain unexpected allow_other", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts},allow_other`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live options contain unexpected bind", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts},bind`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live options contain unexpected propagation", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts},shared:12`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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

  it("returns failed and skips mkdir when mount path contains a symlink", async () => {
    const mockSsh = createMountApplyMockSsh({
      [mountPathSymlinkGuardCmd]: { code: 1, stderr: "mount path contains symlink: /mnt" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[mount.present: /mnt/data] mount path symlink check failed"
    )
    expect(mockSsh.calls).not.toContain(mkdirCmd)
  })

  // R-0000224: defense-in-depth realpath re-check after the symlink guard.
  // If readlink resolves to a different path the mountpoint was likely
  // swapped between the guard and the mount call (TOCTOU).
  it("R-0000224: returns failed when readlink reports a TOCTOU swap", async () => {
    const mockSsh = createMountApplyMockSsh({
      [mountPathRealpathCmd]: { code: 0, stdout: "/srv/attacker-controlled\n" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("resolved path differs after symlink guard")
    expect(result.error?.message).toContain("/srv/attacker-controlled")
    // mount must not have been attempted
    expect(mockSsh.calls).not.toContain(mountCmd)
  })

  it("returns failed and does not touch fstab or mount when mkdir -p fails", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
      [mkdirCmd]: { code: 1, stderr: "permission denied" },
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
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[mount.present: /mnt/data] mkdir -p failed")
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
    expect(mockSsh.calls).not.toContain(mountCmd)
    expect(writtenFiles).toStrictEqual([])
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

  // R-0000169: read-modify-write on /etc/fstab must be serialized with a
  // mutex lock around the cat + writeFile sequence so concurrent runs cannot
  // lose competing fstab edits.
  it("acquires and releases the etc-fstab mutex lock around the fstab write", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    mockSsh.writeFile = async (): Promise<void> => {
      // The test only asserts on lock command ordering, not file contents.
      await Promise.resolve()
    }
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    await mod.apply(mockSsh, emptyEnv)
    const lockMkdir = "mkdir /var/lib/paratix/flags/'etc-fstab-mutex'"
    const lockRmdir = "rmdir /var/lib/paratix/flags/'etc-fstab-mutex'"
    expect(mockSsh.calls).toContain(lockMkdir)
    expect(mockSsh.calls).toContain(lockRmdir)
    const acquireIndex = mockSsh.calls.indexOf(lockMkdir)
    const fstabReadIndex = mockSsh.calls.indexOf("cat '/etc/fstab'")
    const releaseIndex = mockSsh.calls.indexOf(lockRmdir)
    expect(acquireIndex).toBeLessThan(fstabReadIndex)
    expect(fstabReadIndex).toBeLessThan(releaseIndex)
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

  it("returns ok when defaults are expanded in live mount options", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": {
        stdout: `${mountSrc} ${mountPath} ${mountFstype} ${defaultMountOpts} 0 0\n`,
      },
      [findmntCheckCmd]: {
        code: 0,
        stdout: `${mountSrc} ${mountFstype} ${expandedDefaultMountOpts}`,
      },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: defaultMountOpts,
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

  it("does not persist a new fstab entry when mount command fails", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
      [mountCmd]: { code: 1, stderr: "mount failed" },
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
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writtenFiles).toStrictEqual([])
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
    const remountCmd = `mount -o remount,'${mountOpts}' -- '${mountSrc}' '${mountPath}'`
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

  it("restores the previous live mount when replacement mount fails", async () => {
    const liveSource = "/dev/sdb1"
    const liveFstype = "ext4"
    const liveOptions = "rw,noexec"
    const restoreMountCmd = `mount -t '${liveFstype}' -o '${liveOptions}' -- '${liveSource}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${liveSource} ${liveFstype} ${liveOptions}` },
      [mountCmd]: { code: 1, stderr: "replacement failed" },
      [restoreMountCmd]: { code: 0 },
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
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[mount.present: /mnt/data] mount after umount failed")
    expect(mockSsh.calls).toContain(restoreMountCmd)
    expect(mockSsh.calls.indexOf(mountCmd)).toBeLessThan(mockSsh.calls.indexOf(restoreMountCmd))
  })

  it("returns the restore failure when replacement mount and rollback both fail", async () => {
    const liveSource = "/dev/sdb1"
    const liveFstype = "ext4"
    const liveOptions = "rw,noexec"
    const restoreMountCmd = `mount -t '${liveFstype}' -o '${liveOptions}' -- '${liveSource}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${liveSource} ${liveFstype} ${liveOptions}` },
      [mountCmd]: { code: 1, stderr: "replacement failed" },
      [restoreMountCmd]: { code: 32, stderr: "restore failed" },
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
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[mount.present: /mnt/data] mount after umount failed and restoring previous mount failed"
    )
    expect(result.error?.message).toContain("restore failure: restore failed")
    expect(result.error?.message).toContain("original mount failure: replacement failed")
    expect(mockSsh.calls).toContain(restoreMountCmd)
  })

  it("renders the restore stderr (not the original mount stderr) as the restore failure", async () => {
    const liveSource = "/dev/sdb1"
    const liveFstype = "ext4"
    const liveOptions = "rw,noexec"
    const restoreMountCmd = `mount -t '${liveFstype}' -o '${liveOptions}' -- '${liveSource}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: `${liveSource} ${liveFstype} ${liveOptions}` },
      [mountCmd]: { code: 1, stderr: "ORIGINAL_MOUNT_STDERR" },
      [restoreMountCmd]: { code: 32, stderr: "RESTORE_STDERR" },
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
    expect(result.status).toBe("failed")
    // Restore failure label MUST come from restoreResult.stderr — not mountFailure.stderr.
    expect(result.error?.message).toContain("restore failure: RESTORE_STDERR")
    expect(result.error?.message).not.toContain("restore failure: ORIGINAL_MOUNT_STDERR")
    // Original mount stderr is still rendered for completeness, just under a separate label.
    expect(result.error?.message).toContain("original mount failure: ORIGINAL_MOUNT_STDERR")
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

  it("returns needs-apply when mount path contains a symlink", async () => {
    const mockSsh = createMockSsh({
      [mountPathSymlinkGuardCmd]: { code: 1, stderr: "mount path contains symlink: /mnt" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(findmntTestCmd)
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

  it("returns failed and skips umount when mount path contains a symlink", async () => {
    const mockSsh = createMountApplyMockSsh({
      [mountPathSymlinkGuardCmd]: { code: 1, stderr: "mount path contains symlink: /mnt" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[mount.absent: /mnt/data] mount path symlink check failed"
    )
    expect(mockSsh.calls).not.toContain(findmntTestCmd)
    expect(mockSsh.calls).not.toContain(umountCmd)
  })

  it("returns failed before findmnt, umount, or fstab when readlink reports a TOCTOU swap", async () => {
    const mockSsh = createMountApplyMockSsh({
      [mountPathRealpathCmd]: { code: 0, stdout: "/srv/attacker-controlled\n" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("resolved path differs after symlink guard")
    expect(result.error?.message).toContain("/srv/attacker-controlled")
    expect(mockSsh.calls).toContain(mountPathSymlinkGuardCmd)
    expect(mockSsh.calls).toContain(mountPathRealpathCmd)
    expect(mockSsh.calls.indexOf(mountPathSymlinkGuardCmd)).toBeLessThan(
      mockSsh.calls.indexOf(mountPathRealpathCmd)
    )
    expect(mockSsh.calls).not.toContain(findmntTestCmd)
    expect(mockSsh.calls).not.toContain(umountCmd)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
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
