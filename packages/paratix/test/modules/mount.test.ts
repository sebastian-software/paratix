import { describe, expect, it } from "vitest"

import { mount } from "../../src/modules/mount.js"
import { parseLiveMount } from "../../src/modules/mountProbe.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import { makeIsVerifiedReleaseCall } from "../helpers/mockSshFlagLock.js"

type MockSshOptions = NonNullable<Parameters<typeof createBaseMockSsh>[1]>
type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(
    { hostname: { code: 0, stdout: "" }, [mountPathSymlinkGuardCmd]: { code: 0 }, ...responses },
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

const mountPath = "/mnt/data"
const mountSrc = "tmpfs"
const mountFstype = "tmpfs"
const mountOpts = "noexec,nosuid,nodev,size=512m"
const defaultMountOpts = "defaults"
const expandedDefaultMountOpts = "rw,relatime"

// Exact fstab line as buildFstabLine would produce
const fstabLine = `${mountSrc} ${mountPath} ${mountFstype} ${mountOpts} 0 0`

// Shared live-mount probe command issued by mount.present and mount.absent.
const findmntCheckCmd = `findmnt --noheadings --pairs --nofsroot --mountpoint '${mountPath}' --output ID,PARENT,MAJ:MIN,SOURCE,FSTYPE,OPTIONS,VFS-OPTIONS,FSROOT`
const mountCmd = `mount -t '${mountFstype}' -o '${mountOpts}' -- '${mountSrc}' '${mountPath}'`
const umountCmd = `umount '${mountPath}'`
// R-0000755: mount.present now walks each path component with a
// symlink-guarded `mkdir` snippet instead of the previous `mkdir -p`. The
// helper below mirrors `buildMountPathComponentMkdirCommand` so tests can
// stub the per-component calls.
function buildMountPathComponentMkdirCommand(component: string): string {
  return (
    `if [ -L '${component}' ]; then ` +
    `printf 'mount path component is symlink: %s\\n' '${component}' >&2; exit 1; ` +
    `fi; ` +
    `if [ ! -e '${component}' ]; then ` +
    `mkdir -- '${component}' || exit 1; ` +
    `if [ -L '${component}' ]; then ` +
    `printf 'mount path component became symlink after mkdir: %s\\n' '${component}' >&2; exit 1; ` +
    `fi; ` +
    `elif [ ! -d '${component}' ]; then ` +
    `printf 'mount path component exists but is not a directory: %s\\n' '${component}' >&2; exit 1; ` +
    `fi`
  )
}
const mountPathMkdirCmds = ["/mnt", "/mnt/data"].map((component) =>
  buildMountPathComponentMkdirCommand(component)
)
const mkdirCmd = mountPathMkdirCmds.at(-1) ?? ""
const mountPathRealpathCmd = `readlink -f -- '${mountPath}' 2>/dev/null || printf '%s\\n' '${mountPath}'`
const mountPathSymlinkGuardCmd = [
  `mount_path='${mountPath}'`,
  'current="$mount_path"',
  'while [ "$current" != "/" ]; do',
  'if [ -L "$current" ]; then',
  `printf '%s\\n' "mount path contains symlink: $current" >&2`,
  "exit 1",
  "fi",
  'current=$(dirname "$current")',
  "done",
].join("; ")
const flagsDirectoryCreateCmd = "mkdir -p /var/lib/paratix/flags"

const successfulMountApplyOptions: MockSshOptions = {
  allowWrites: [{ options: { mode: "0644" }, remotePath: "/etc/fstab" }],
  responseStubs: [
    { command: mountPathSymlinkGuardCmd, result: { code: 0 } },
    ...mountPathMkdirCmds.map((command) => ({ command, result: { code: 0 } })),
    { command: mountPathRealpathCmd, result: { code: 0, stdout: `${mountPath}\n` } },
  ],
}

function createMountApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses, successfulMountApplyOptions)
}

type LivePairsFields = {
  fsroot?: string
  fstype: string
  id?: number | string
  majMin?: string
  options: string
  parent?: number | string
  source: string
  vfsOptions?: string
}

const LIVE_VFS_OPTION_TOKENS = new Set([
  "noatime",
  "nodev",
  "nodiratime",
  "noexec",
  "nosuid",
  "nosymfollow",
  "relatime",
  "ro",
  "rw",
])

// Mirror findmnt's `--pairs` escaping of `"`, `$`, `\` and backtick.
function escapeFindmntValue(value: string): string {
  return value.replaceAll(
    /["$\\`]/gv,
    (character) => `\\x${(character.codePointAt(0) ?? 0).toString(16).padStart(2, "0")}`
  )
}

/**
 * Render one `findmnt --pairs` line as printed by the live-mount probe.
 * Defaults: ID 100, PARENT 1, MAJ:MIN 0:50, FSROOT `/`, and VFS-OPTIONS
 * derived from the per-mount flags in `options` (with `rw` when neither
 * `ro` nor `rw` is listed).
 *
 * @param fields - Column values; unspecified columns use the defaults.
 * @returns One findmnt output line.
 */
function livePairs(fields: LivePairsFields): string {
  const derivedVfsOptions = fields.options
    .split(",")
    .filter((option) => LIVE_VFS_OPTION_TOKENS.has(option))
  if (!derivedVfsOptions.includes("ro") && !derivedVfsOptions.includes("rw")) {
    derivedVfsOptions.unshift("rw")
  }
  const columns: Array<[string, string]> = [
    ["ID", String(fields.id ?? 100)],
    ["PARENT", String(fields.parent ?? 1)],
    ["MAJ:MIN", fields.majMin ?? "0:50"],
    ["SOURCE", fields.source],
    ["FSTYPE", fields.fstype],
    ["OPTIONS", fields.options],
    ["VFS-OPTIONS", fields.vfsOptions ?? derivedVfsOptions.join(",")],
    ["FSROOT", fields.fsroot ?? "/"],
  ]
  return columns.map(([key, value]) => `${key}="${escapeFindmntValue(value)}"`).join(" ")
}

// findmnt --pairs stdout for a live mount whose source/fstype/options
// match the desired values exactly.
const liveMountStdout = livePairs({ fstype: mountFstype, options: mountOpts, source: mountSrc })

function expectFstabFailure(
  result: Awaited<ReturnType<ReturnType<typeof mount.present>["apply"]>>
) {
  expect(result.status).toBe("failed")
  expect(result.error?.message).toContain(`failed to update /etc/fstab`)
}

function countCalls(calls: string[], command: string): number {
  return calls.filter((call) => call === command).length
}

function isMountMutation(call: string): boolean {
  return call.startsWith("umount ") || call.startsWith("mount ")
}

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

  it("returns needs-apply when the live mount probe fails unexpectedly", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 127, stderr: "findmnt: not found" },
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

  it("returns needs-apply when fstab cannot be read", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    let readAttempted = false
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.readFile = async (): Promise<string> => {
      readAttempted = true
      throw new Error("permission denied")
    }
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(readAttempted).toBe(true)
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: mountFstype, options: mountOpts, source: "/dev/sdb1" }),
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
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live options differ from desired", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: mountFstype, options: "defaults", source: mountSrc }),
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
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live fstype differs from desired", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: "ext4", options: mountOpts, source: mountSrc }),
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
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live options have the same set in a different order", async () => {
    const reordered = mountOpts.split(",").reverse().join(",")
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: mountFstype, options: reordered, source: mountSrc }),
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

  it("returns ok when defaults are expanded in live mount options", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": {
        stdout: `${mountSrc} ${mountPath} ${mountFstype} ${defaultMountOpts} 0 0\n`,
      },
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({
          fstype: mountFstype,
          options: expandedDefaultMountOpts,
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: ext4Fstype,
          options: "rw,relatime,errors=remount-ro",
          source: ext4Src,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: "rw,nosuid,nodev,noexec,relatime,size=512m,inode64",
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: "rw,nosuid,nodev,noexec,relatime,size=536870912",
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: `${expandedDefaultMountOpts},noexec`,
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: `${expandedDefaultMountOpts},noexec`,
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: `${expandedDefaultMountOpts},allow_other`,
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: `${expandedDefaultMountOpts},bind`,
          source: mountSrc,
        }),
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
        stdout: livePairs({
          fstype: mountFstype,
          options: `${expandedDefaultMountOpts},shared:12`,
          source: mountSrc,
        }),
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

  it("fails closed for unstubbed apply commands", async () => {
    const mockSsh = createMountApplyMockSsh()

    await expect(mockSsh.exec("unexpected mount helper")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: unexpected mount helper"
    )
  })

  it("creates mountpoint via a top-down per-component mkdir walk", async () => {
    // R-0000755: the previous single-call `mkdir -p` would silently follow
    // an attacker-planted symlink at any not-yet-existing ancestor. The new
    // walk issues one symlink-guarded `mkdir` per component (here `/mnt`
    // and `/mnt/data`) so a planted link trips an early failure.
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
    const parentMkdir = buildMountPathComponentMkdirCommand("/mnt")
    const leafMkdir = buildMountPathComponentMkdirCommand(mountPath)
    expect(mockSsh.calls).toContain(parentMkdir)
    expect(mockSsh.calls).toContain(leafMkdir)
    expect(mockSsh.calls.indexOf(parentMkdir)).toBeLessThan(mockSsh.calls.indexOf(leafMkdir))
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

  it("returns failed and does not touch fstab or mount when a component mkdir fails", async () => {
    // R-0000755: failures from any individual component mkdir surface as a
    // structured failure whose message identifies the failing component.
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
    expect(result.error?.message).toContain(
      `[mount.present: /mnt/data] mkdir at ${mountPath} failed`
    )
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
    expect(mockSsh.calls).not.toContain(mountCmd)
    expect(writtenFiles).toStrictEqual([])
  })

  it("returns failed and skips mount and fstab when findmnt is unavailable", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 127, stderr: "findmnt: not found" },
      [mountCmd]: { code: 0 },
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
    expect(result.error?.message).toContain(
      "[mount.present: /mnt/data] findmnt failed while probing live mount state"
    )
    expect(mockSsh.calls).not.toContain(mountCmd)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(writtenFiles).toStrictEqual([])
  })

  it("returns failed and skips mount and fstab when findmnt returns an unexpected code", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 2, stderr: "findmnt failed" },
      [mountCmd]: { code: 0 },
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
    expect(result.error?.message).toContain(
      "[mount.present: /mnt/data] findmnt failed while probing live mount state"
    )
    expect(mockSsh.calls).not.toContain(mountCmd)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
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
    // R-0000634: release is now a single shell statement (ownership check
    // + marker removal + rmdir); the shared helper centralises the match.
    const isVerifiedRelease = makeIsVerifiedReleaseCall("etc-fstab-mutex")
    expect(mockSsh.calls).toContain(lockMkdir)
    expect(mockSsh.calls.some(isVerifiedRelease)).toBe(true)
    const acquireIndex = mockSsh.calls.indexOf(lockMkdir)
    const fstabReadIndex = mockSsh.calls.indexOf("cat '/etc/fstab'")
    const releaseIndex = mockSsh.calls.findIndex(isVerifiedRelease)
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

  it("returns failed instead of rejecting when the fstab mutex lock cannot be acquired", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.present: /mnt/data]")
    expect(result.error?.message).toContain("read-only filesystem")
  })

  it("unmounts a new live mount when fstab persistence fails", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(mockSsh.calls).toContain(umountCmd)
    expect(mockSsh.calls.indexOf(flagsDirectoryCreateCmd)).toBeLessThan(
      mockSsh.calls.indexOf(umountCmd)
    )
  })

  it("restores the previous live mount when fstab persistence fails after replacement", async () => {
    const liveSource = "/dev/sdb1"
    const liveFstype = "ext4"
    const liveOptions = "rw,noexec"
    const restoreMountCmd = `mount -t '${liveFstype}' -o '${liveOptions}' -- '${liveSource}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: liveFstype, options: liveOptions, source: liveSource }),
      },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
      [mountCmd]: { code: 0 },
      [restoreMountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(countCalls(mockSsh.calls, umountCmd)).toBe(2)
    expect(mockSsh.calls).toContain(restoreMountCmd)
    expect(mockSsh.calls.indexOf(flagsDirectoryCreateCmd)).toBeLessThan(
      mockSsh.calls.indexOf(restoreMountCmd)
    )
  })

  it("reports rollback failure when unmounting a new live mount fails after fstab failure", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 32, stderr: "target is busy" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain("failed to roll back live mount")
    expect(result.error?.message).toContain("target is busy")
  })

  it("does not roll back when fstab persistence fails without a live mount change", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
    })
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(mockSsh.calls).not.toContain(umountCmd)
  })

  it("returns failed instead of rejecting when guarded fstab write detects a concurrent change", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    const fstabReads = ["# /etc/fstab\n", "# /etc/fstab\n# changed\n"]
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.readFile = async (): Promise<string> => fstabReads.shift()!
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.present: /mnt/data]")
    expect(result.error?.message).toContain("Concurrent modification detected on /etc/fstab")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
  })

  it("returns failed instead of rejecting when writing the fstab entry throws", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.reject(new Error("sftp write failed"))
    }
    const mod = mount.present({
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      src: mountSrc,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.present: /mnt/data]")
    expect(result.error?.message).toContain("sftp write failed")
  })

  it("runs mount command when not already mounted", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
      [mountCmd]: { code: 0 },
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
        stdout: livePairs({
          fstype: mountFstype,
          options: expandedDefaultMountOpts,
          source: mountSrc,
        }),
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
      [mountCmd]: { code: 0 },
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: mountFstype, options: "defaults", source: mountSrc }),
      },
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: mountFstype, options: mountOpts, source: "/dev/sdb1" }),
      },
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: "ext4", options: mountOpts, source: mountSrc }),
      },
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: liveFstype, options: liveOptions, source: liveSource }),
      },
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
    expect(result.error?.message).toContain(
      "[mount.present: /mnt/data] mount failed, previous mount was restored"
    )
    expect(mockSsh.calls).toContain(restoreMountCmd)
    expect(mockSsh.calls.indexOf(mountCmd)).toBeLessThan(mockSsh.calls.indexOf(restoreMountCmd))
  })

  it("returns the restore failure when replacement mount and rollback both fail", async () => {
    const liveSource = "/dev/sdb1"
    const liveFstype = "ext4"
    const liveOptions = "rw,noexec"
    const restoreMountCmd = `mount -t '${liveFstype}' -o '${liveOptions}' -- '${liveSource}' '${mountPath}'`
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: liveFstype, options: liveOptions, source: liveSource }),
      },
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
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({ fstype: liveFstype, options: liveOptions, source: liveSource }),
      },
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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(findmntCheckCmd)
  })

  it("returns needs-apply when the live mount probe fails unexpectedly", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 127, stderr: "findmnt: not found" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when mount path contains a symlink", async () => {
    const mockSsh = createMockSsh({
      [mountPathSymlinkGuardCmd]: { code: 1, stderr: "mount path contains symlink: /mnt" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
  })

  it("returns ok when not mounted and no fstab entry (persist: true)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when not mounted but fstab entry exists", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when fstab cannot be read", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 1 },
    })
    let readAttempted = false
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.readFile = async (): Promise<string> => {
      readAttempted = true
      throw new Error("permission denied")
    }
    const mod = mount.absent({ path: mountPath })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(readAttempted).toBe(true)
  })

  it("returns ok when not mounted (persist: false)", async () => {
    const mockSsh = createMockSsh({
      [findmntCheckCmd]: { code: 1 },
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
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls.indexOf(findmntCheckCmd)).toBeLessThan(mockSsh.calls.indexOf(umountCmd))
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
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
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
    expect(mockSsh.calls).not.toContain(findmntCheckCmd)
    expect(mockSsh.calls).not.toContain(umountCmd)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
  })

  it("returns failed when umount fails", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [umountCmd]: { code: 1, stderr: "umount failed" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[mount.absent: /mnt/data] umount failed")
  })

  it("returns failed and skips umount and fstab when findmnt is unavailable", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 127, stderr: "findmnt: not found" },
      [umountCmd]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.writeFile = async (path: string, content: string): Promise<void> => {
      writtenFiles.push({ content, path })
    }
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      "[mount.absent: /mnt/data] findmnt failed while probing live mount state"
    )
    expect(mockSsh.calls).not.toContain(umountCmd)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
    expect(writtenFiles).toStrictEqual([])
  })

  it("removes fstab entry when persist is true", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
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

  it("returns failed instead of rejecting when the fstab mutex lock cannot be acquired", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.absent: /mnt/data]")
    expect(result.error?.message).toContain("read-only filesystem")
  })

  it("restores the live mount when removing the fstab entry fails after umount", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(mockSsh.calls).toContain(umountCmd)
    expect(mockSsh.calls).toContain(mountCmd)
    expect(mockSsh.calls.indexOf(umountCmd)).toBeLessThan(mockSsh.calls.indexOf(mountCmd))
  })

  it("reports rollback failure when restoring the live mount fails after fstab failure", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" },
      [mountCmd]: { code: 32, stderr: "restore failed" },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })

    const result = await mod.apply(mockSsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain(
      "[mount.absent: /mnt/data] failed to restore live mount after fstab update failure"
    )
    expect(result.error?.message).toContain("restore failed")
  })

  it("returns failed instead of rejecting when guarded fstab write detects a concurrent change", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 1 },
    })
    const fstabReads = [`${fstabLine}\n`, `${fstabLine}\n# changed\n`]
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    mockSsh.readFile = async (): Promise<string> => fstabReads.shift()!
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.absent: /mnt/data]")
    expect(result.error?.message).toContain("Concurrent modification detected on /etc/fstab")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
  })

  it("returns failed instead of rejecting when removing the fstab entry throws", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: `${fstabLine}\n` },
      [findmntCheckCmd]: { code: 1 },
    })
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.reject(new Error("sftp write failed"))
    }
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expectFstabFailure(result)
    expect(result.error?.message).toContain("[mount.absent: /mnt/data]")
    expect(result.error?.message).toContain("sftp write failed")
  })

  it("returns ok when nothing to do (not mounted, no fstab entry)", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when umount was needed", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 0, stdout: liveMountStdout },
      [umountCmd]: { code: 0 },
    })
    const mod = mount.absent({ path: mountPath })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("skips fstab when persist is false", async () => {
    const mockSsh = createMountApplyMockSsh({
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath, persist: false })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("cat '/etc/fstab'")
  })

  it("skips umount when not mounted", async () => {
    const mockSsh = createMountApplyMockSsh({
      "cat '/etc/fstab'": { stdout: "# /etc/fstab\n" },
      [findmntCheckCmd]: { code: 1 },
    })
    const mod = mount.absent({ path: mountPath })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(umountCmd)
  })
})

// ─── bind mounts (smoke) ──────────────────────────────────────────────────────

describe("mount.present — bind mount smoke", () => {
  const bindSrc = "/srv/data/docker"
  const readlinkSrcCmd = `readlink -f -- '${bindSrc}'`
  const testDirectoryCmd = `test -d '${bindSrc}'`
  const testExistsCmd = `test -e '${bindSrc}'`
  const containingMountCmd = `findmnt --noheadings --pairs --nofsroot --output TARGET,MAJ:MIN,SOURCE,FSROOT --target '${bindSrc}'`
  const containingMountStdout = `TARGET="/srv/data" MAJ:MIN="253:1" SOURCE="/dev/mapper/data" FSROOT="/"`
  const boundLiveStdout = livePairs({
    fsroot: "/docker",
    fstype: "ext4",
    majMin: "253:1",
    options: "rw,nosuid,nodev,relatime,errors=remount-ro",
    source: "/dev/mapper/data",
  })
  const resolutionResponses = {
    [containingMountCmd]: { code: 0, stdout: containingMountStdout },
    [readlinkSrcCmd]: { code: 0, stdout: `${bindSrc}\n` },
    [testDirectoryCmd]: { code: 0 },
  }

  it("treats a correctly bound target as converged without any mount command", async () => {
    const responses = {
      ...resolutionResponses,
      [findmntCheckCmd]: { code: 0, stdout: boundLiveStdout },
    }
    const options = { fstype: "none", opts: "bind", path: mountPath, persist: false, src: bindSrc }

    const checkSsh = createMockSsh(responses)
    expect(await mount.present(options).check(checkSsh, emptyEnv)).toBe("ok")

    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(applySsh.calls.filter((call) => isMountMutation(call))).toStrictEqual([])
  })

  it("remounts explicit VFS flag drift without unmounting", async () => {
    const remountCmd = `mount -o remount,bind,ro -- '${bindSrc}' '${mountPath}'`
    const responses = {
      ...resolutionResponses,
      [findmntCheckCmd]: { code: 0, stdout: boundLiveStdout },
      [remountCmd]: { code: 0 },
    }
    const options = {
      fstype: "none",
      opts: "bind,ro",
      path: mountPath,
      persist: false,
      src: bindSrc,
    }

    expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe(
      "needs-apply"
    )
    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(applySsh.calls.filter((call) => isMountMutation(call))).toStrictEqual([remountCmd])
  })

  it("fails before probing or unmounting when the bind source is missing", async () => {
    const responses = {
      [readlinkSrcCmd]: { code: 0, stdout: `${bindSrc}\n` },
      [testDirectoryCmd]: { code: 1 },
      [testExistsCmd]: { code: 1 },
    }
    const options = { fstype: "none", opts: "bind", path: mountPath, persist: false, src: bindSrc }

    const checkSsh = createMockSsh(responses)
    expect(await mount.present(options).check(checkSsh, emptyEnv)).toBe("needs-apply")
    expect(checkSsh.calls.filter((call) => call !== mountPathSymlinkGuardCmd)).toStrictEqual([
      readlinkSrcCmd,
      testDirectoryCmd,
      testExistsCmd,
    ])

    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(`bind source does not exist: ${bindSrc}`)
    expect(applySsh.calls).not.toContain(findmntCheckCmd)
    expect(applySsh.calls.filter((call) => isMountMutation(call))).toStrictEqual([])
  })

  it("rejects a relative or nested bind source at construction", () => {
    expect(() =>
      mount.present({ fstype: "none", opts: "bind", path: mountPath, src: "srv/data" })
    ).toThrow(/bind src must be an absolute, normalized path/v)
    expect(() =>
      mount.present({ fstype: "none", opts: "rbind", path: mountPath, src: `${mountPath}/sub` })
    ).toThrow(/bind src must not be below the mount path/v)
  })
})

describe("mount live probe parsing (smoke)", () => {
  it("decodes escapes and selects the top-most of stacked mounts", () => {
    const lower = livePairs({ fstype: "ext4", id: 40, options: "rw", parent: 1, source: "/dev/a" })
    const upper = livePairs({
      fstype: "tmpfs",
      id: 41,
      options: "rw",
      parent: 40,
      source: 'we$ird"\u00E9',
    })
    const live = parseLiveMount(`${upper}\n${lower}\n`)
    expect(live?.id).toBe("41")
    expect(live?.source).toBe('we$ird"\u00E9')
  })

  it("decodes byte-wise escaped UTF-8 and rejects malformed lines", () => {
    const line = livePairs({ fstype: "tmpfs", options: "rw", source: "x" }).replace(
      'SOURCE="x"',
      String.raw`SOURCE="caf\xc3\xa9"`
    )
    expect(parseLiveMount(line)?.source).toBe("caf\u00E9")
    expect(parseLiveMount("tmpfs tmpfs rw")).toBeNull()
  })
})

// ─── bind mounts (#218 acceptance) ────────────────────────────────────────────

const bindSourcePath = "/srv/data/docker"
const bindFstype = "none"
const bindMajMin = "253:1"
const bindFsroot = "/docker"
const fstabPath = "cat '/etc/fstab'"

type BindMountResponses = NonNullable<MockSshResponses>

type ContainingMountFields = {
  fsroot?: string
  majMin?: string
  source?: string
  target: string
}

function readlinkCommand(src: string): string {
  return `readlink -f -- '${src}'`
}

function testDirCommand(resolved: string): string {
  return `test -d '${resolved}'`
}

function testExistsCommand(resolved: string): string {
  return `test -e '${resolved}'`
}

function containingMountCommand(resolved: string): string {
  return `findmnt --noheadings --pairs --nofsroot --output TARGET,MAJ:MIN,SOURCE,FSROOT --target '${resolved}'`
}

/**
 * Render one `findmnt --pairs` line of the containing-mount lookup.
 * Defaults: MAJ:MIN 253:1, SOURCE /dev/mapper/data, FSROOT `/`.
 *
 * @param fields - Column values; unspecified columns use the defaults.
 * @returns One findmnt output line.
 */
function containingPairs(fields: ContainingMountFields): string {
  const columns: Array<[string, string]> = [
    ["TARGET", fields.target],
    ["MAJ:MIN", fields.majMin ?? bindMajMin],
    ["SOURCE", fields.source ?? "/dev/mapper/data"],
    ["FSROOT", fields.fsroot ?? "/"],
  ]
  return columns.map(([key, value]) => `${key}="${escapeFindmntValue(value)}"`).join(" ")
}

/**
 * Stub the read-only bind source resolution: `readlink -f`, `test -d` on the
 * resolved path, and the `findmnt --target` lookup of the containing mount.
 * Defaults: `src` = {@link bindSourcePath} resolving to itself inside `/srv/data`.
 *
 * @param parameters - Resolution inputs.
 * @param parameters.containing - Containing mount line(s) printed by findmnt.
 * @param parameters.resolved - `readlink -f` output (defaults to `src`).
 * @param parameters.src - The configured bind source.
 * @returns Mock responses for the resolution commands.
 */
function bindResolutionResponses(
  parameters: {
    containing?: ContainingMountFields | ContainingMountFields[]
    resolved?: string
    src?: string
  } = {}
): BindMountResponses {
  const src = parameters.src ?? bindSourcePath
  const resolved = parameters.resolved ?? src
  const containing = parameters.containing ?? { target: "/srv/data" }
  const lines = (Array.isArray(containing) ? containing : [containing]).map((fields) =>
    containingPairs(fields)
  )
  return {
    [containingMountCommand(resolved)]: { code: 0, stdout: `${lines.join("\n")}\n` },
    [readlinkCommand(src)]: { code: 0, stdout: `${resolved}\n` },
    [testDirCommand(resolved)]: { code: 0 },
  }
}

/**
 * Live probe output for a bind of {@link bindSourcePath} at the mount path: the
 * backing ext4 device with superblock options and the inherited
 * `nosuid,nodev` VFS flags of a hardened data mount.
 *
 * @param fields - Column overrides.
 * @returns One findmnt output line.
 */
function boundLive(fields: Partial<LivePairsFields> = {}): string {
  return livePairs({
    fsroot: bindFsroot,
    fstype: "ext4",
    majMin: bindMajMin,
    options: "rw,nosuid,nodev,relatime,errors=remount-ro",
    source: "/dev/mapper/data",
    vfsOptions: "rw,nosuid,nodev,relatime",
    ...fields,
  })
}

function bindOptions(
  opts: string,
  overrides: { persist?: boolean; src?: string } = {}
): Parameters<typeof mount.present>[0] {
  return {
    fstype: bindFstype,
    opts,
    path: mountPath,
    persist: false,
    src: bindSourcePath,
    ...overrides,
  }
}

function bindFstabLine(opts: string, src = bindSourcePath): string {
  return `${src} ${mountPath} ${bindFstype} ${opts} 0 0`
}

function bindMountCmd(opts = "bind", src = bindSourcePath): string {
  return `mount -t '${bindFstype}' -o '${opts}' -- '${src}' '${mountPath}'`
}

function bindRemountCmd(flags: string, src = bindSourcePath): string {
  return `mount -o remount,bind,${flags} -- '${src}' '${mountPath}'`
}

function mountMutations(calls: string[]): string[] {
  return calls.filter((call) => isMountMutation(call))
}

// `check` may only read: the symlink guard shell snippet, readlink, test,
// findmnt, and the fstab read used for `persist`.
function isReadOnlyCheckCall(call: string): boolean {
  if (call === mountPathSymlinkGuardCmd || call === fstabPath) return true
  return /^(?:readlink|test|findmnt) /v.test(call)
}

describe("mount.present — bind: correctly bound targets (#218)", () => {
  it.each(["bind", "rbind"])(
    "opts %s: check ok and apply ok without umount/mount/remount although live FSTYPE, superblock options and inherited VFS flags differ",
    async (opts) => {
      const responses = {
        ...bindResolutionResponses(),
        [findmntCheckCmd]: { code: 0, stdout: boundLive() },
        [fstabPath]: { stdout: `${bindFstabLine(opts)}\n` },
      }
      const options = bindOptions(opts, { persist: true })

      expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe("ok")

      const applySsh = createMountApplyMockSsh(responses)
      const result = await mount.present(options).apply(applySsh, emptyEnv)
      expect(result.status).toBe("ok")
      expect(applySsh.calls.some((call) => call.startsWith("umount "))).toBe(false)
      expect(applySsh.calls.some((call) => call.startsWith("mount -t "))).toBe(false)
      expect(applySsh.calls.some((call) => call.startsWith("mount -o remount"))).toBe(false)
      expect(applySsh.writeFileCalls).toHaveLength(0)
    }
  )

  it("treats nosuid,nodev inherited from a hardened source as don't-care on the run after the first bind mount", async () => {
    const options = bindOptions("bind")

    const firstSsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      [bindMountCmd()]: { code: 0 },
      [findmntCheckCmd]: { code: 1 },
    })
    const first = await mount.present(options).apply(firstSsh, emptyEnv)
    expect(first.status).toBe("changed")
    expect(mountMutations(firstSsh.calls)).toStrictEqual([bindMountCmd()])

    const secondResponses = {
      ...bindResolutionResponses(),
      [findmntCheckCmd]: {
        code: 0,
        stdout: boundLive({ vfsOptions: "rw,nosuid,nodev,noexec,relatime" }),
      },
    }
    expect(await mount.present(options).check(createMockSsh(secondResponses), emptyEnv)).toBe("ok")
    const secondSsh = createMountApplyMockSsh(secondResponses)
    const second = await mount.present(options).apply(secondSsh, emptyEnv)
    expect(second.status).toBe("ok")
    expect(mountMutations(secondSsh.calls)).toStrictEqual([])
  })
})

describe("mount.present — bind: drift (#218)", () => {
  it.each([
    ["MAJ:MIN", { majMin: "253:2" }],
    ["FSROOT", { fsroot: "/other" }],
  ])(
    "live %s differing from the resolved source yields needs-apply and apply runs umount then mount",
    async (_column, override) => {
      const responses = {
        ...bindResolutionResponses(),
        [bindMountCmd()]: { code: 0 },
        [findmntCheckCmd]: { code: 0, stdout: boundLive(override) },
        [umountCmd]: { code: 0 },
      }
      const options = bindOptions("bind")

      expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe(
        "needs-apply"
      )
      const applySsh = createMountApplyMockSsh(responses)
      const result = await mount.present(options).apply(applySsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd, bindMountCmd()])
    }
  )

  it("treats two tmpfs-backed sources with equal SOURCE and FSROOT but different MAJ:MIN as different", async () => {
    const tmpfsSrc = "/run/cache-a"
    const resolution = bindResolutionResponses({
      containing: { fsroot: "/", majMin: "0:51", source: "tmpfs", target: tmpfsSrc },
      src: tmpfsSrc,
    })
    const tmpfsLive = (majMin: string): string =>
      livePairs({ fstype: "tmpfs", majMin, options: "rw,relatime", source: "tmpfs" })
    const options = bindOptions("bind", { src: tmpfsSrc })

    // Positive control: the same tmpfs instance (MAJ:MIN 0:51) is converged.
    expect(
      await mount.present(options).check(
        createMockSsh({
          ...resolution,
          [findmntCheckCmd]: { code: 0, stdout: tmpfsLive("0:51") },
        }),
        emptyEnv
      )
    ).toBe("ok")

    const otherInstance = {
      ...resolution,
      [bindMountCmd("bind", tmpfsSrc)]: { code: 0 },
      [findmntCheckCmd]: { code: 0, stdout: tmpfsLive("0:52") },
      [umountCmd]: { code: 0 },
    }
    expect(await mount.present(options).check(createMockSsh(otherInstance), emptyEnv)).toBe(
      "needs-apply"
    )
    const applySsh = createMountApplyMockSsh(otherInstance)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mountMutations(applySsh.calls)).toStrictEqual([
      umountCmd,
      bindMountCmd("bind", tmpfsSrc),
    ])
  })

  // The exact `bind,ro` remount for a live `rw` bind is pinned by the smoke
  // test "remounts explicit VFS flag drift without unmounting"; this covers
  // the rbind spelling, which must remount with `bind`.
  it("converges ro drift of an rbind with exactly `mount -o remount,bind,ro -- <src> <path>` and no umount", async () => {
    const remountCmd = `mount -o remount,bind,ro -- '${bindSourcePath}' '${mountPath}'`
    const responses = {
      ...bindResolutionResponses(),
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ vfsOptions: "rw,relatime" }) },
      [remountCmd]: { code: 0 },
    }
    const options = bindOptions("rbind,ro")

    expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe(
      "needs-apply"
    )
    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mountMutations(applySsh.calls)).toStrictEqual([remountCmd])
  })

  it("remounts with the explicit VFS flags only, in canonical order, ignoring fstab-only and propagation options", async () => {
    const opts =
      "nosymfollow,bind,noexec,_netdev,nofail,x-systemd.requires-mounts-for=/srv/data,private,nodiratime,noatime,nodev,nosuid,ro"
    const remountCmd = bindRemountCmd("ro,nosuid,nodev,noexec,noatime,nodiratime,nosymfollow")
    const responses = {
      ...bindResolutionResponses(),
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ vfsOptions: "rw,relatime" }) },
      [remountCmd]: { code: 0 },
    }

    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(bindOptions(opts)).apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mountMutations(applySsh.calls)).toStrictEqual([remountCmd])

    // Once every named flag is live, the fstab-only and propagation options
    // do not count as drift.
    const convergedLive = boundLive({
      vfsOptions: "ro,nosuid,nodev,noexec,noatime,nodiratime,nosymfollow",
    })
    expect(
      await mount.present(bindOptions(opts)).check(
        createMockSsh({
          ...bindResolutionResponses(),
          [findmntCheckCmd]: { code: 0, stdout: convergedLive },
        }),
        emptyEnv
      )
    ).toBe("ok")
  })

  it.each([
    {
      driftVfs: "rw,relatime",
      flag: "noatime",
      matchingVfs: "rw,noatime",
      remountFlags: "noatime",
    },
    { driftVfs: "rw", flag: "relatime", matchingVfs: "rw,relatime", remountFlags: "relatime" },
    {
      driftVfs: "rw,relatime",
      flag: "strictatime",
      matchingVfs: "rw",
      remountFlags: "strictatime",
    },
    { driftVfs: "rw,noatime", flag: "norelatime", matchingVfs: "rw", remountFlags: "strictatime" },
    {
      driftVfs: "rw,relatime",
      flag: "nodiratime",
      matchingVfs: "rw,relatime,nodiratime",
      remountFlags: "nodiratime",
    },
  ])(
    "atime state $flag: ok for live $matchingVfs, needs-apply and remount,bind,$remountFlags for live $driftVfs",
    async ({ driftVfs, flag, matchingVfs, remountFlags }) => {
      const options = bindOptions(`bind,${flag}`)

      const matching = createMockSsh({
        ...bindResolutionResponses(),
        [findmntCheckCmd]: { code: 0, stdout: boundLive({ vfsOptions: matchingVfs }) },
      })
      expect(await mount.present(options).check(matching, emptyEnv)).toBe("ok")

      const driftResponses = {
        ...bindResolutionResponses(),
        [bindRemountCmd(remountFlags)]: { code: 0 },
        [findmntCheckCmd]: { code: 0, stdout: boundLive({ vfsOptions: driftVfs }) },
      }
      expect(await mount.present(options).check(createMockSsh(driftResponses), emptyEnv)).toBe(
        "needs-apply"
      )
      const applySsh = createMountApplyMockSsh(driftResponses)
      const result = await mount.present(options).apply(applySsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mountMutations(applySsh.calls)).toStrictEqual([bindRemountCmd(remountFlags)])
    }
  )
})

describe("mount.present — bind: source resolution (#218)", () => {
  it.each([
    {
      case: "a source below a mount root (/srv/data/docker on /srv/data)",
      containing: { fsroot: "/", target: "/srv/data" },
      expectedFsroot: "/docker",
      naiveFsroot: "/",
      resolved: "/srv/data/docker",
      src: "/srv/data/docker",
    },
    {
      case: "a source that is itself a mount root",
      containing: { fsroot: "/", target: "/srv/data" },
      expectedFsroot: "/",
      naiveFsroot: "/data",
      resolved: "/srv/data",
      src: "/srv/data",
    },
    {
      case: "a source inside a mount that is itself a bind (non-/ FSROOT joined)",
      containing: { fsroot: "/volumes/app", target: "/srv/app" },
      expectedFsroot: "/volumes/app/cache",
      naiveFsroot: "/volumes/app",
      resolved: "/srv/app/cache",
      src: "/srv/app/cache",
    },
    {
      case: "a symlinked src (resolved by readlink -f before the lookup)",
      containing: { fsroot: "/", target: "/srv/data" },
      expectedFsroot: "/docker",
      naiveFsroot: "/",
      resolved: "/srv/data/docker",
      src: "/srv/docker-link",
    },
  ])("resolves $case to FSROOT $expectedFsroot", async (row) => {
    const resolution = bindResolutionResponses({
      containing: row.containing,
      resolved: row.resolved,
      src: row.src,
    })
    const options = bindOptions("bind", { src: row.src })

    const matchingSsh = createMockSsh({
      ...resolution,
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ fsroot: row.expectedFsroot }) },
    })
    expect(await mount.present(options).check(matchingSsh, emptyEnv)).toBe("ok")
    expect(matchingSsh.calls.filter((call) => call !== mountPathSymlinkGuardCmd)).toStrictEqual([
      readlinkCommand(row.src),
      testDirCommand(row.resolved),
      containingMountCommand(row.resolved),
      findmntCheckCmd,
    ])

    // A live bind of a different directory in the same mount (e.g. the
    // unjoined FSROOT of the containing mount) is not the desired identity.
    const driftSsh = createMockSsh({
      ...resolution,
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ fsroot: row.naiveFsroot }) },
    })
    expect(await mount.present(options).check(driftSsh, emptyEnv)).toBe("needs-apply")
  })

  it("keeps the configured symlinked src in the remount command and the fstab line", async () => {
    const linkSrc = "/srv/docker-link"
    const remountCmd = bindRemountCmd("ro", linkSrc)
    const responses = {
      ...bindResolutionResponses({ resolved: bindSourcePath, src: linkSrc }),
      [findmntCheckCmd]: { code: 0, stdout: boundLive() },
      [fstabPath]: { stdout: `${bindFstabLine("bind,ro", linkSrc)}\n` },
      [remountCmd]: { code: 0 },
    }
    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount
      .present(bindOptions("bind,ro", { persist: true, src: linkSrc }))
      .apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mountMutations(applySsh.calls)).toStrictEqual([remountCmd])
    expect(applySsh.writeFileCalls).toHaveLength(0)
  })

  it("uses the last line of the containing-mount lookup", async () => {
    const resolution = bindResolutionResponses({
      containing: [
        { fsroot: "/", majMin: "8:1", source: "/dev/sda1", target: "/" },
        { fsroot: "/", majMin: bindMajMin, target: "/srv/data" },
      ],
    })
    const ssh = createMockSsh({
      ...resolution,
      [findmntCheckCmd]: { code: 0, stdout: boundLive() },
    })
    expect(await mount.present(bindOptions("bind")).check(ssh, emptyEnv)).toBe("ok")
  })

  it("self-bind (src === path) is allowed at construction", () => {
    expect(() => mount.present(bindOptions("bind", { src: mountPath }))).not.toThrow()
  })

  // The source lookup of a self-bind resolves to the mount at `path` itself,
  // so whatever bind is mounted there matches its own identity: the check only
  // confirms "a bind of this path is mounted with the explicit VFS flags".
  it.each([
    { fsroot: "/docker", majMin: "253:1", source: "/dev/mapper/data" },
    { fsroot: "/", majMin: "0:77", source: "tmpfs" },
  ])(
    "self-bind check is degraded: any bind at the path ($source$fsroot) is ok, only explicit flags are verified",
    async (live) => {
      const responses = {
        ...bindResolutionResponses({ containing: { ...live, target: mountPath }, src: mountPath }),
        [findmntCheckCmd]: { code: 0, stdout: boundLive({ ...live, vfsOptions: "rw,relatime" }) },
      }
      const selfBind = (opts: string) => mount.present(bindOptions(opts, { src: mountPath }))

      expect(await selfBind("bind").check(createMockSsh(responses), emptyEnv)).toBe("ok")
      expect(await selfBind("bind,ro").check(createMockSsh(responses), emptyEnv)).toBe(
        "needs-apply"
      )
    }
  )
})

describe("mount.present — bind: validation (#218)", () => {
  it("missing src (readlink fails): check needs-apply, apply fails naming the source without probe, mount or umount", async () => {
    const responses = { [readlinkCommand(bindSourcePath)]: { code: 1 } }
    const options = bindOptions("bind")

    const checkSsh = createMockSsh(responses)
    expect(await mount.present(options).check(checkSsh, emptyEnv)).toBe("needs-apply")
    expect(checkSsh.calls).not.toContain(findmntCheckCmd)

    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe(
      `[mount.present: ${mountPath}] bind source does not exist: ${bindSourcePath}`
    )
    expect(applySsh.calls).not.toContain(findmntCheckCmd)
    expect(mountMutations(applySsh.calls)).toStrictEqual([])
  })

  it("src that is a regular file: check needs-apply, apply fails saying bind sources must be directories", async () => {
    const responses = {
      [readlinkCommand(bindSourcePath)]: { code: 0, stdout: `${bindSourcePath}\n` },
      [testDirCommand(bindSourcePath)]: { code: 1 },
      [testExistsCommand(bindSourcePath)]: { code: 0 },
    }
    const options = bindOptions("bind")

    expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe(
      "needs-apply"
    )
    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe(
      `[mount.present: ${mountPath}] bind source is not a directory: ${bindSourcePath} (bind sources must be directories)`
    )
    expect(applySsh.calls).not.toContain(findmntCheckCmd)
    expect(mountMutations(applySsh.calls)).toStrictEqual([])
  })

  it("src resolving below the mount path fails before probing or mounting", async () => {
    const linkSrc = "/srv/loop-link"
    const resolved = `${mountPath}/inner`
    const responses = { [readlinkCommand(linkSrc)]: { code: 0, stdout: `${resolved}\n` } }
    const options = bindOptions("bind", { src: linkSrc })

    expect(await mount.present(options).check(createMockSsh(responses), emptyEnv)).toBe(
      "needs-apply"
    )
    const applySsh = createMountApplyMockSsh(responses)
    const result = await mount.present(options).apply(applySsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe(
      `[mount.present: ${mountPath}] bind source ${linkSrc} resolves to ${resolved}, which is below the mount path`
    )
    expect(applySsh.calls).not.toContain(findmntCheckCmd)
    expect(mountMutations(applySsh.calls)).toStrictEqual([])
  })

  it.each(["srv/data", "./srv/data", "/srv//data", "/srv/./data", "/srv/data/../x"])(
    "construction rejects the relative or non-normalized bind src %j",
    (src) => {
      expect(() => mount.present(bindOptions("bind", { src }))).toThrow(
        `mount.present: bind src must be an absolute, normalized path: ${JSON.stringify(src)}`
      )
    }
  )

  it.each(["bind", "rbind", "BIND,ro"])(
    "construction rejects a src strictly below the mount path (opts %s)",
    (opts) => {
      const nested = `${mountPath}/sub/dir`
      expect(() => mount.present(bindOptions(opts, { src: nested }))).toThrow(
        `mount.present: bind src must not be below the mount path: ${nested} is below ${mountPath}`
      )
    }
  )

  it("construction accepts a sibling src that only shares the mount path prefix", () => {
    expect(() => mount.present(bindOptions("bind", { src: `${mountPath}2` }))).not.toThrow()
    expect(() => mount.present(bindOptions("bind", { src: "/mnt" }))).not.toThrow()
  })
})

describe("mount.present — bind: probe (#218)", () => {
  it("decodes \\xNN escapes ($, UTF-8 bytes) in the live probe before comparing SOURCE", async () => {
    const src = "server:/exports/café$"
    const escapedLine = livePairs({ fstype: "nfs", options: "rw", source: "placeholder" }).replace(
      'SOURCE="placeholder"',
      String.raw`SOURCE="server:/exports/caf\xc3\xa9\x24"`
    )
    const ssh = createMockSsh({ [findmntCheckCmd]: { code: 0, stdout: escapedLine } })
    const mod = mount.present({ fstype: "nfs", opts: "rw", path: mountPath, persist: false, src })
    expect(await mod.check(ssh, emptyEnv)).toBe("ok")
  })

  it("decodes \\xNN escapes in the containing-mount lookup before deriving the bind FSROOT", async () => {
    const target = "/srv/cost$center"
    const src = `${target}/docker`
    const resolution = bindResolutionResponses({ containing: { target }, src })
    // containingPairs escapes `$` as `\x24`, as findmnt does.
    expect(resolution[containingMountCommand(src)].stdout).toContain(String.raw`cost\x24center`)
    const ssh = createMockSsh({
      ...resolution,
      [findmntCheckCmd]: { code: 0, stdout: boundLive() },
    })
    expect(await mount.present(bindOptions("bind", { src })).check(ssh, emptyEnv)).toBe("ok")
  })

  it("compares the top-most of stacked mounts, chosen via ID/PARENT and not by line order", async () => {
    const lowerBind = boundLive({ id: 40, parent: 1 })
    const upperTmpfs = livePairs({
      fstype: "tmpfs",
      id: 41,
      majMin: "0:60",
      options: "rw",
      parent: 40,
      source: "tmpfs",
    })
    const options = bindOptions("bind")

    // The desired bind is buried under a tmpfs: not converged.
    const buried = createMockSsh({
      ...bindResolutionResponses(),
      [findmntCheckCmd]: { code: 0, stdout: `${lowerBind}\n${upperTmpfs}\n` },
    })
    expect(await mount.present(options).check(buried, emptyEnv)).toBe("needs-apply")

    // The desired bind is on top even though findmnt lists it first.
    const upperBind = boundLive({ id: 43, parent: 42 })
    const lowerTmpfs = livePairs({
      fstype: "tmpfs",
      id: 42,
      majMin: "0:60",
      options: "rw",
      parent: 1,
      source: "tmpfs",
    })
    const onTop = createMockSsh({
      ...bindResolutionResponses(),
      [findmntCheckCmd]: { code: 0, stdout: `${upperBind}\n${lowerTmpfs}\n` },
    })
    expect(await mount.present(options).check(onTop, emptyEnv)).toBe("ok")
  })

  it("falls back to the last line when the ID/PARENT top-most entry is not unique", () => {
    const first = livePairs({ fstype: "ext4", id: 50, options: "rw", parent: 1, source: "/dev/a" })
    const last = livePairs({ fstype: "tmpfs", id: 51, options: "rw", parent: 2, source: "tmpfs" })
    expect(parseLiveMount(`${first}\n${last}\n`)?.id).toBe("51")
  })
})

describe("mount.present — non-bind FSROOT regressions (#218)", () => {
  it("a non-bind desired mount matches only a live mount with FSROOT /", async () => {
    const options = {
      fstype: mountFstype,
      opts: mountOpts,
      path: mountPath,
      persist: false,
      src: mountSrc,
    }
    const liveAt = (fsroot: string): string =>
      livePairs({ fsroot, fstype: mountFstype, options: mountOpts, source: mountSrc })

    const rootSsh = createMockSsh({ [findmntCheckCmd]: { code: 0, stdout: liveAt("/") } })
    expect(await mount.present(options).check(rootSsh, emptyEnv)).toBe("ok")

    const subSsh = createMockSsh({ [findmntCheckCmd]: { code: 0, stdout: liveAt("/sub") } })
    expect(await mount.present(options).check(subSsh, emptyEnv)).toBe("needs-apply")
  })

  it("same SOURCE and fstype with live FSROOT /sub converges with umount + mount, not a remount", async () => {
    const applySsh = createMountApplyMockSsh({
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({
          fsroot: "/sub",
          fstype: mountFstype,
          options: "defaults",
          source: mountSrc,
        }),
      },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const result = await mount
      .present({
        fstype: mountFstype,
        opts: mountOpts,
        path: mountPath,
        persist: false,
        src: mountSrc,
      })
      .apply(applySsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd, mountCmd])
  })
})

describe("mount — rollback after an fstab write failure (#218)", () => {
  // Every test here fails the fstab update by making the mutex lock
  // directory creation fail, after the live change was applied.
  const fstabFailure = { [flagsDirectoryCreateCmd]: { code: 1, stderr: "read-only filesystem" } }

  it("bind remount-only change: remounts back to the previous known VFS flags without umount", async () => {
    const remountRo = bindRemountCmd("ro")
    const remountBack = bindRemountCmd("rw,relatime,nodev,nosuid")
    const applySsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      ...fstabFailure,
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ vfsOptions: "rw,relatime,nodev,nosuid" }) },
      [remountBack]: { code: 0 },
      [remountRo]: { code: 0 },
    })
    const result = await mount
      .present(bindOptions("bind,ro", { persist: true }))
      .apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(mountMutations(applySsh.calls)).toStrictEqual([remountRo, remountBack])
  })

  it("bind remount-only change: reports a failed remount back", async () => {
    const remountRo = bindRemountCmd("ro")
    const remountBack = bindRemountCmd("rw,nosuid,nodev,relatime")
    const applySsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      ...fstabFailure,
      [findmntCheckCmd]: { code: 0, stdout: boundLive() },
      [remountBack]: { code: 32, stderr: "remount refused" },
      [remountRo]: { code: 0 },
    })
    const result = await mount
      .present(bindOptions("bind,ro", { persist: true }))
      .apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain(
      `[mount.present: ${mountPath}] failed to roll back live bind remount after fstab update failure`
    )
    expect(result.error?.message).toContain("remount refused")
    expect(mountMutations(applySsh.calls)).toStrictEqual([remountRo, remountBack])
  })

  it("fresh bind mount: unmounts the new mount again", async () => {
    const applySsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      ...fstabFailure,
      [bindMountCmd()]: { code: 0 },
      [findmntCheckCmd]: { code: 1 },
      [umountCmd]: { code: 0 },
    })
    const result = await mount
      .present(bindOptions("bind", { persist: true }))
      .apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(mountMutations(applySsh.calls)).toStrictEqual([bindMountCmd(), umountCmd])
  })

  it("bind identity change: keeps the new mount, runs no umount and no restore, and appends a note", async () => {
    const applySsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      ...fstabFailure,
      [bindMountCmd()]: { code: 0 },
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ fsroot: "/", majMin: "8:1" }) },
      [umountCmd]: { code: 0 },
    })
    const result = await mount
      .present(bindOptions("bind", { persist: true }))
      .apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain(
      `\n[mount.present: ${mountPath}] note: the new bind mount was kept in place and the previous mount was not restored; re-run to persist /etc/fstab`
    )
    expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd, bindMountCmd()])
  })

  it("mount.present: skips restoring a previous mount whose FSROOT is not / and keeps the new mount without umount", async () => {
    const applySsh = createMountApplyMockSsh({
      ...fstabFailure,
      [findmntCheckCmd]: {
        code: 0,
        stdout: livePairs({
          fsroot: "/sub",
          fstype: mountFstype,
          options: mountOpts,
          source: mountSrc,
        }),
      },
      [mountCmd]: { code: 0 },
      [umountCmd]: { code: 0 },
    })
    const result = await mount
      .present({ fstype: mountFstype, opts: mountOpts, path: mountPath, src: mountSrc })
      .apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain(
      `[mount.present: ${mountPath}] previous mount could not be restored automatically after fstab update failure (previous FSROOT /sub is not /); the new mount was kept in place`
    )
    expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd, mountCmd])
  })

  it("mount.absent: reports the live mount as not restored when its FSROOT is not /", async () => {
    const applySsh = createMountApplyMockSsh({
      ...fstabFailure,
      [findmntCheckCmd]: { code: 0, stdout: boundLive() },
      [umountCmd]: { code: 0 },
    })
    const result = await mount.absent({ path: mountPath }).apply(applySsh, emptyEnv)

    expectFstabFailure(result)
    expect(result.error?.message).toContain(
      `[mount.absent: ${mountPath}] live mount was not restored after fstab update failure (previous FSROOT ${bindFsroot} is not /)`
    )
    expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd])
  })

  it("replacement mount failure after umount does not restore a previous mount whose FSROOT is not /", async () => {
    const applySsh = createMountApplyMockSsh({
      ...bindResolutionResponses(),
      [bindMountCmd()]: { code: 32, stderr: "special device does not exist" },
      [findmntCheckCmd]: { code: 0, stdout: boundLive({ fsroot: "/old", majMin: "253:9" }) },
      [umountCmd]: { code: 0 },
    })
    const result = await mount.present(bindOptions("bind")).apply(applySsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain(
      `[mount.present: ${mountPath}] mount after umount failed; previous mount was not restored (previous mount could not be restored automatically)`
    )
    expect(mountMutations(applySsh.calls)).toStrictEqual([umountCmd, bindMountCmd()])
  })
})

describe("mount.present — bind: read-only check (#218)", () => {
  it.each([
    { case: "converged", expected: "ok", liveStdout: boundLive(), opts: "bind" },
    { case: "VFS flag drift", expected: "needs-apply", liveStdout: boundLive(), opts: "bind,ro" },
    {
      case: "identity drift",
      expected: "needs-apply",
      liveStdout: boundLive({ majMin: "8:1" }),
      opts: "bind",
    },
  ])(
    "check ($case) issues only readlink, test, findmnt and fstab reads",
    async ({ expected, liveStdout, opts }) => {
      const ssh = createMockSsh({
        ...bindResolutionResponses(),
        [findmntCheckCmd]: { code: 0, stdout: liveStdout },
        [fstabPath]: { stdout: `${bindFstabLine(opts)}\n` },
      })
      expect(await mount.present(bindOptions(opts, { persist: true })).check(ssh, emptyEnv)).toBe(
        expected
      )
      expect(ssh.calls.filter((call) => !isReadOnlyCheckCall(call))).toStrictEqual([])
      expect(ssh.calls).toContain(readlinkCommand(bindSourcePath))
      expect(ssh.calls).toContain(testDirCommand(bindSourcePath))
      expect(ssh.calls).toContain(containingMountCommand(bindSourcePath))
      expect(ssh.calls).toContain(findmntCheckCmd)
      expect(ssh.writeFileCalls).toHaveLength(0)
      expect(ssh.uploadFileCalls).toHaveLength(0)
    }
  )

  it("check with a missing source issues only read commands", async () => {
    const ssh = createMockSsh({
      [readlinkCommand(bindSourcePath)]: { code: 0, stdout: `${bindSourcePath}\n` },
      [testDirCommand(bindSourcePath)]: { code: 1 },
      [testExistsCommand(bindSourcePath)]: { code: 1 },
    })
    expect(await mount.present(bindOptions("bind", { persist: true })).check(ssh, emptyEnv)).toBe(
      "needs-apply"
    )
    expect(ssh.calls.filter((call) => !isReadOnlyCheckCall(call))).toStrictEqual([])
    expect(ssh.writeFileCalls).toHaveLength(0)
  })
})
