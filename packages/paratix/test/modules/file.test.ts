import { createHash } from "node:crypto"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { file } from "../../src/modules/file.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowUploads: [
      { localPath: /^\/.+/v, options: { mode: "0644" }, remotePath: /^\/remote\/.+/v },
      { localPath: /^\/.+/v, options: { mode: "0600" }, remotePath: /^\/remote\/.+/v },
      ...(options?.allowUploads ?? []),
    ],
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/(?:etc|remote)\//v },
      { options: { mode: "0600" }, remotePath: /^\/(?:etc|remote)\//v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      {
        command: /^stat -c '%a %U %G' '\/(?:etc|remote|var)\//v,
        result: { stdout: "644 root root" },
      },
      { command: /^stat -c '%a' '\/(?:etc|remote|var)\//v, result: { stdout: "644" } },
      {
        command:
          /^\[ -e '\/(?:etc\/(?:config|hosts|über hosts|nginx\/nginx\.conf)|remote\/.+)' \]$/v,
        result: { code: 0 },
      },
      {
        command:
          /^\[ -f '\/(?:etc|remote|var)\/.+?' \] && \[ ! -L '\/(?:etc|remote|var)\/.+?' \]$/v,
        result: { code: 0 },
      },
      { command: /^\[ -f '\/(?:etc|remote|var)\/.+?' \]$/v, result: { code: 0 } },
      { command: /^\[ -L '\/(?:etc|remote|var)\/.+?' \]$/v, result: { code: 1 } },
      {
        command:
          /^grep -qF '# END paratix: (?:myblock|grüße-block)' '\/etc\/(?:hosts|über hosts)'$/v,
        result: { code: 0 },
      },
      { command: /^mkdir -p '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chmod '[0-7]+' '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chmod -- '[0-7]+' '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chown '[^']+' '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chown -- '[^']+' '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chgrp '[^']+' '\/(?:remote|var)\//v, result: { code: 0 } },
      { command: /^chgrp -- '[^']+' '\/(?:remote|var)\//v, result: { code: 0 } },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}
const unicodeContent = "Grüße aus Köln – こんにちは мир\n"
// R-0000139: keep filenames that hit the local filesystem ASCII-only.
// On macOS the filesystem normalizes unicode filenames to NFD while
// Linux ext4 preserves the bytes the program wrote — typically NFC.
// An identity comparison (`localPath === uploadedFiles[0].local`)
// would therefore break on whichever platform did not match the
// literal source bytes. Remote paths still travel as opaque strings
// and may contain unicode.
const unicodeName = "ascii-datei.txt"
const unicodeRemotePath = "/remote/über ordner/äöü.txt"

describe("file.directory", () => {
  it("check returns ok when the directory exists", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
    })
    const mod = file.directory("/var/app")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the directory does not exist", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 1 },
    })
    const mod = file.directory("/var/app")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the path is a symlink to a directory", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 0 },
    })
    const mod = file.directory("/var/app")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.directory("/var/app")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when directory mode differs", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 root root" },
    })

    const mod = file.directory("/var/app", { mode: "0700" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when directory owner differs", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "700 root root" },
    })

    const mod = file.directory("/var/app", { owner: "www-data:www-data" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression R-0000109 — apply returns ok and skips mkdir/chmod/chown when directory matches desired state", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 www-data www-data" },
    })

    const mod = file.directory("/var/app", { mode: "0755", owner: "www-data:www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("mkdir -p '/var/app'")
    expect(ssh.calls).not.toContain("chmod '0755' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
  })

  it("regression R-0000109 — apply returns changed and only issues mkdir when directory is missing", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 1 },
      "[ -L '/var/app' ]": { code: 1 },
    })

    const mod = file.directory("/var/app")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("mkdir -p '/var/app'")
  })

  it("regression R-0000109 — apply returns changed and only issues chmod when only mode drifted", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "700 www-data www-data" },
    })

    const mod = file.directory("/var/app", { mode: "0755", owner: "www-data:www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).not.toContain("mkdir -p '/var/app'")
    expect(ssh.calls).toContain("chmod '0755' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
  })

  it("regression R-0000109 — apply returns changed and only issues chown when only owner drifted", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 root root" },
    })

    const mod = file.directory("/var/app", { mode: "0755", owner: "www-data:www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).not.toContain("mkdir -p '/var/app'")
    expect(ssh.calls).not.toContain("chmod '0755' '/var/app'")
    expect(ssh.calls).toContain("chown -- 'www-data:www-data' '/var/app'")
  })

  it("rejects option-like owner components before directory chown", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "[ -L '/var/app' ]": { code: 1 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 root root" },
    })
    const mod = file.directory("/var/app", { owner: "--reference=/etc/shadow" })

    await expect(mod.apply(ssh, emptyEnv)).rejects.toThrow(
      'chown owner component must not start with "-": "--reference=/etc/shadow"'
    )
    expect(ssh.calls).not.toContain("chown -- '--reference=/etc/shadow' '/var/app'")
  })

  it("apply fails without mutating metadata when the path is a symlink to a directory", async () => {
    const ssh = createMockSsh({
      "[ -L '/var/app' ]": { code: 0 },
    })
    const mod = file.directory("/var/app", { mode: "0755", owner: "www-data:www-data" })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("path must not be a symlink")
    expect(ssh.calls).not.toContain("chmod '0755' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
  })
})

describe("file.absent", () => {
  it("rejects an empty remote path", () => {
    expect(() => file.absent("")).toThrow("file.absent: remotePath must not be empty")
  })

  it("rejects the root path", () => {
    expect(() => file.absent("/")).toThrow("file.absent: refusing to remove destructive path: /")
  })

  it("rejects relative paths", () => {
    expect(() => file.absent("tmp/old-file")).toThrow(
      "file.absent: remotePath must be an absolute path: tmp/old-file"
    )
    expect(() => file.absent(".")).toThrow("file.absent: remotePath must be an absolute path: .")
    expect(() => file.absent("..")).toThrow("file.absent: remotePath must be an absolute path: ..")
    expect(() => file.absent("foo/../..")).toThrow(
      "file.absent: remotePath must be an absolute path: foo/../.."
    )
  })

  it("rejects paths that normalize to root", () => {
    expect(() => file.absent("/var/..")).toThrow(
      "file.absent: refusing to remove destructive path: /var/.."
    )
  })

  it("check returns ok when the path does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ] || [ -L '/tmp/old-file' ]": { code: 1 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the path exists", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ] || [ -L '/tmp/old-file' ]": { code: 0 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the path is a dangling symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/dangling-link' ] || [ -L '/tmp/dangling-link' ]": { code: 0 },
    })
    const mod = file.absent("/tmp/dangling-link")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = file.absent("/tmp/old-file")
    // eslint-disable-next-line prefer-spread -- mod.apply is a Module method, not Function.prototype.apply
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns ok and skips rm when the path is already absent", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ] || [ -L '/tmp/old-file' ]": { code: 1 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("rm -rf '/tmp/old-file'")
  })

  it("apply removes an existing path with shell quoting", async () => {
    const remotePath = "/tmp/old file's dir"
    const ssh = createMockSsh({
      "[ -e '/tmp/old file'\\''s dir' ] || [ -L '/tmp/old file'\\''s dir' ]": { code: 0 },
      "rm -rf '/tmp/old file'\\''s dir'": { code: 0 },
    })
    const mod = file.absent(remotePath)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.execCalls).toContainEqual({
      command: "rm -rf '/tmp/old file'\\''s dir'",
      options: { ignoreExitCode: true, silent: true },
    })
  })

  it("apply removes a dangling symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/dangling-link' ] || [ -L '/tmp/dangling-link' ]": { code: 0 },
      "rm -rf '/tmp/dangling-link'": { code: 0 },
    })
    const mod = file.absent("/tmp/dangling-link")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.execCalls).toContainEqual({
      command: "rm -rf '/tmp/dangling-link'",
      options: { ignoreExitCode: true, silent: true },
    })
  })

  it("apply returns failed when rm exits non-zero", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/stubborn' ] || [ -L '/tmp/stubborn' ]": { code: 0 },
      "rm -rf '/tmp/stubborn'": { code: 1, stderr: "permission denied" },
    })
    const mod = file.absent("/tmp/stubborn")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("rm failed")
  })
})

describe("file.chmod", () => {
  it("check returns ok when the mode already matches", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "644 root root" },
    })

    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the path does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 1 },
    })

    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the mode differs", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "600 root root" },
    })

    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply runs chmod", async () => {
    const ssh = createMockSsh()
    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chmod '0644' '/var/app/config.yml'")
  })

  it("regression R-0000133 — apply refuses to chmod through a symlink", async () => {
    // chmod follows symlinks, so without an explicit -L guard file.chmod on a
    // symlinked path silently rewrites the mode of the link target. The guard
    // must reject the operation up-front, even when the link is dangling.
    const ssh = createMockSsh({
      "[ -L '/var/app/config.yml' ]": { code: 0 },
    })
    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to operate through symlink")
    expect(ssh.calls).not.toContain("chmod '0644' '/var/app/config.yml'")
  })

  it("regression R-0000133 — check returns needs-apply when the target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "[ -L '/var/app/config.yml' ]": { code: 0 },
    })
    const mod = file.chmod("/var/app/config.yml", "0644")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.chown", () => {
  it("check returns ok when the owner already matches", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "644 www-data www-data" },
    })

    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when a group-only ownership spec already matches", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "644 root www-data" },
    })

    const mod = file.chown("/var/app/config.yml", ":www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when a group-only ownership spec differs", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "644 root root" },
    })

    const mod = file.chown("/var/app/config.yml", ":www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the path does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 1 },
    })

    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the owner differs", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app/config.yml'": { stdout: "644 root root" },
    })

    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply runs chown", async () => {
    const ssh = createMockSsh()
    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chown -- 'www-data:www-data' '/var/app/config.yml'")
  })

  it("renders -- before normal and numeric owner specs", async () => {
    const ssh = createMockSsh()
    const mod = file.chown("/var/app/config.yml", "1000:1000")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chown -- '1000:1000' '/var/app/config.yml'")
  })

  it("rejects owner specs whose group component starts with a dash", async () => {
    const ssh = createMockSsh()
    const mod = file.chown("/var/app/config.yml", "deploy:-R")

    await expect(mod.apply(ssh, emptyEnv)).rejects.toThrow(
      'chown group component must not start with "-": "-R"'
    )
  })

  it("regression R-0000133 — apply refuses to chown through a symlink", async () => {
    // chown follows symlinks, so without an explicit -L guard file.chown on a
    // symlinked path silently rewrites the ownership of the link target.
    const ssh = createMockSsh({
      "[ -L '/var/app/config.yml' ]": { code: 0 },
    })
    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to operate through symlink")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app/config.yml'")
  })

  it("regression R-0000133 — check returns needs-apply when the target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/var/app/config.yml' ]": { code: 0 },
      "[ -L '/var/app/config.yml' ]": { code: 0 },
    })
    const mod = file.chown("/var/app/config.yml", "www-data:www-data")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// Helper: compute sha256 hex of a string
function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}

// Helper: compute sha256 hex of a buffer
function sha256HexBuffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex")
}

describe("file.copy", () => {
  it("check returns ok when SHA-256 matches and the default mode 0644 is in effect", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        // exists check: [ -e '/remote/file.txt' ] -> true
        "[ -e '/remote/file.txt' ]": { code: 0 },
        // sha256 check: [ -f '/remote/file.txt' ] -> true
        "[ -f '/remote/file.txt' ]": { code: 0 },
        // sha256sum returns matching hash
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        // remote mode matches the documented default (0644)
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "644 root root" },
      })

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when file does not exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const ssh = createMockSsh({
        // exists check: file does not exist
        "[ -e '/remote/file.txt' ]": { code: 1 },
        "[ -f '/remote/file.txt' ] && [ ! -L '/remote/file.txt' ]": { code: 1 },
      })

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when the remote path is a symlink to a matching file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const ssh = createMockSsh({
        "[ -f '/remote/file.txt' ] && [ ! -L '/remote/file.txt' ]": { code: 1 },
      })

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when SHA-256 differs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        // sha256sum returns a different hash
        "sha256sum '/remote/file.txt'": { stdout: "deadbeef00000000  /remote/file.txt" },
      })

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when ssh is null", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when mode differs despite matching SHA-256", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "644 www-data www-data" },
      })

      const mod = file.copy("/remote/file.txt", localPath, { mode: "0600" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when owner differs despite matching SHA-256", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "600 root root" },
      })

      const mod = file.copy("/remote/file.txt", localPath, { owner: "www-data:www-data" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns ok when group-only owner spec matches despite matching SHA-256", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "644 root www-data" },
      })

      const mod = file.copy("/remote/file.txt", localPath, { owner: ":www-data" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply calls uploadFile and forwards the default mode 0644", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const uploadedFiles: Array<{
        local: string
        options: { mode?: string } | undefined
        remote: string
      }> = []
      const ssh = createMockSsh()
      ssh.uploadFile = async (local: string, remote: string, options?: { mode?: string }) => {
        await Promise.resolve()
        uploadedFiles.push({ local, options, remote })
      }

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(uploadedFiles).toStrictEqual([
        { local: localPath, options: { mode: "0644" }, remote: "/remote/file.txt" },
      ])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply preserves unicode content and paths and forwards the default mode", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, unicodeName)
      writeFileSync(localPath, unicodeContent, "utf8")

      const uploadedFiles: Array<{
        local: string
        options: { mode?: string } | undefined
        remote: string
      }> = []
      const ssh = createMockSsh()
      ssh.uploadFile = async (local: string, remote: string, options?: { mode?: string }) => {
        await Promise.resolve()
        uploadedFiles.push({ local, options, remote })
      }

      const mod = file.copy(unicodeRemotePath, localPath)
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(uploadedFiles).toStrictEqual([
        { local: localPath, options: { mode: "0644" }, remote: unicodeRemotePath },
      ])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply forwards an explicit mode to uploadFile and sets owner via chown", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const uploadedFiles: Array<{
        local: string
        options: { mode?: string } | undefined
        remote: string
      }> = []
      const ssh = createMockSsh()
      ssh.uploadFile = async (local: string, remote: string, options?: { mode?: string }) => {
        await Promise.resolve()
        uploadedFiles.push({ local, options, remote })
      }

      const mod = file.copy("/remote/file.txt", localPath, { mode: "0600", owner: "www-data" })
      await mod.apply(ssh, emptyEnv)

      // The mode must be forwarded into uploadFile so the resulting file is
      // never produced as the silent uploadFile temp default.
      expect(uploadedFiles).toStrictEqual([
        { local: localPath, options: { mode: "0600" }, remote: "/remote/file.txt" },
      ])
      // file.copy no longer issues a separate chmod after uploadFile.
      expect(ssh.calls).not.toContain("chmod '0600' '/remote/file.txt'")
      expect(ssh.calls).toContain("chown -- 'www-data' '/remote/file.txt'")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when remote mode drifts from the default 0644", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        // Server-side drift: remote was chmod'd to 0600 by an operator.
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "600 root root" },
      })

      // No options.mode → file.copy defaults to 0644 on both apply and check.
      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns ok when remote mode matches an explicit mode option", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")
      const localHash = sha256HexBuffer(Buffer.from("hello world"))

      const ssh = createMockSsh({
        "[ -e '/remote/file.txt' ]": { code: 0 },
        "[ -f '/remote/file.txt' ]": { code: 0 },
        "sha256sum '/remote/file.txt'": { stdout: `${localHash}  /remote/file.txt` },
        "stat -c '%a %U %G' '/remote/file.txt'": { stdout: "600 root root" },
      })

      const mod = file.copy("/remote/file.txt", localPath, { mode: "0600" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("regression R-0000032: detects mode drift on the explicit-mode path even without options.owner", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "nginx.conf")
      writeFileSync(localPath, "server { listen 80; }")
      const localHash = sha256HexBuffer(Buffer.from("server { listen 80; }"))

      const ssh = createMockSsh({
        "[ -e '/etc/nginx/nginx.conf' ]": { code: 0 },
        "[ -f '/etc/nginx/nginx.conf' ]": { code: 0 },
        "sha256sum '/etc/nginx/nginx.conf'": { stdout: `${localHash}  /etc/nginx/nginx.conf` },
        // Operator manually ran `chmod 0600 nginx.conf`.
        "stat -c '%a %U %G' '/etc/nginx/nginx.conf'": { stdout: "600 root root" },
      })

      // Explicit mode 0644, no owner — previously the missing-owner path skipped
      // the mode comparison entirely and returned "ok" despite the drift.
      const mod = file.copy("/etc/nginx/nginx.conf", localPath, { mode: "0644" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("regression R-0000032: detects mode drift on the default-mode path even without options.owner", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "html.htm")
      writeFileSync(localPath, "<html></html>")
      const localHash = sha256HexBuffer(Buffer.from("<html></html>"))

      const ssh = createMockSsh({
        "[ -e '/var/www/index.html' ]": { code: 0 },
        "[ -f '/var/www/index.html' ]": { code: 0 },
        "sha256sum '/var/www/index.html'": { stdout: `${localHash}  /var/www/index.html` },
        // Drift: file is 0600 (e.g. previous uploadFile temp default leaked through).
        "stat -c '%a %U %G' '/var/www/index.html'": { stdout: "600 www-data www-data" },
      })

      // No options at all — default mode 0644 must still be enforced via check.
      const mod = file.copy("/var/www/index.html", localPath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })
})

describe("file.line", () => {
  it("check returns ok when line exists (without match)", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "some-line\nmy-line\nother-line" },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when line is missing (without match)", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "some-line\nother-line" },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the file does not exist (without match)", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 1 },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("cat '/etc/config'")
  })

  it("check returns needs-apply when the line target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "[ -f '/etc/config' ] && [ ! -L '/etc/config' ]": { code: 1 },
      "cat '/etc/config'": { stdout: "my-line\n" },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("cat '/etc/config'")
  })

  it("regression — check returns needs-apply for a substring match without an exact target line", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "some-line\nprefix-my-line-suffix\nother-line" },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns ok when exact line exists (with match)", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nKEY=value\nMORE=bar" },
    })
    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when match found but line differs", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nKEY=old\nMORE=bar" },
    })
    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when match not found", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nMORE=bar" },
    })
    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the file does not exist (with match)", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 1 },
    })
    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("cat '/etc/config'")
  })

  it("regression — check returns needs-apply when the matched target line differs even if the desired line exists elsewhere", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "KEY=old\nOTHER=foo\nKEY=value" },
    })
    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.line — apply without options.match", () => {
  it("apply fails without appending when the line target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -L '/etc/config' ]": { code: 0 },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("path must be a regular file and not a symlink")
    expect(ssh.calls).not.toContain("cat >> '/etc/config'")
  })

  it("regression R-0000132 — apply rejects dangling symlinks before appending", async () => {
    // [ -e path ] returns false for dangling symlinks because it dereferences
    // the link, while [ -L path ] still reports the link itself. Without an
    // explicit -L probe, applyLineAppend would skip the regular-file guard and
    // pipe `cat >> path` through the symlink, writing to the resolved target
    // (or creating it). The new guard must detect this case up-front.
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 1 },
      "[ -L '/etc/config' ]": { code: 0 },
    })
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("path must be a regular file and not a symlink")
    expect(ssh.calls).not.toContain("cat >> '/etc/config'")
  })

  it("regression R-0000108 — apply returns ok and does not append a duplicate when the line is already present", async () => {
    const appendCalls: string[] = []
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "first-line\nmy-line\nlast-line\n" },
    })
    const baseExec = ssh.exec
    ssh.exec = async (command: string) => {
      appendCalls.push(command)
      return baseExec(command)
    }

    const mod = file.line("/etc/config", "my-line")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    const appendIssued = appendCalls.some((command) => command === "cat >> '/etc/config'")
    expect(appendIssued).toBe(false)
  })

  it("regression R-0000108 — second apply is a no-op once the line was appended", async () => {
    // Drive two consecutive applies against a mutable view of the remote
    // file. After the first apply we manually flip the remote content to
    // include "my-line" — this models the post-append filesystem state and
    // proves that the second apply does not append a duplicate.
    const state = { content: "first-line\nlast-line\n" }
    const appendCalls: string[] = []
    const ssh = createMockSsh()
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.exists = async () => true
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.readFile = async () => state.content
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.exec = async (command: string) => {
      appendCalls.push(command)
      return { code: 0, stderr: "", stdout: "" }
    }

    const mod = file.line("/etc/config", "my-line")
    const firstResult = await mod.apply(ssh, emptyEnv)
    // Reflect the append on the simulated remote so the second apply sees
    // the post-state — exactly what would happen on a real remote.
    state.content = `${state.content}my-line\n`
    const secondResult = await mod.apply(ssh, emptyEnv)

    expect(firstResult.status).toBe("changed")
    expect(secondResult.status).toBe("ok")
    const appendCount = appendCalls.filter((command) => command === "cat >> '/etc/config'").length
    expect(appendCount).toBe(1)
    // The remote view must contain "my-line" exactly once.
    const occurrences = state.content.match(/^my-line$/gmv)
    expect(occurrences).toStrictEqual(["my-line"])
  })

  it("appends the line through stdin so secret content is not exposed in the SSH command", async () => {
    const secretLine = "API_TOKEN=secret-token-with 'quotes' and spaces"
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "first-line\nlast-line\n" },
      "cat >> '/etc/config'": { code: 0 },
    })

    const mod = file.line("/etc/config", secretLine)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.execCalls).toContainEqual({
      command: "cat >> '/etc/config'",
      options: { ignoreExitCode: true, input: `${secretLine}\n`, silent: true },
    })
    expect(ssh.execCalls.map((call) => call.command).join("\n")).not.toContain(secretLine)
  })

  // R-0000159: cat append failures (ENOSPC, RO-FS, EACCES) must surface as a
  // failedCommand result with maskable stderr, not as an uncaught exception
  // and not as a misleading "changed" status.
  it("returns failed when cat >> exits non-zero (e.g. ENOSPC)", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "first-line\n" },
      "cat >> '/etc/config'": {
        code: 1,
        stderr: "cat: write error: No space left on device\n",
      },
    })

    const mod = file.line("/etc/config", "my-line")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[file.line: /etc/config] cat append failed")
    expect(result.error?.message).toContain("No space left on device")
  })
})

describe("file.line — sed-Escaping Regression (apply with options.match)", () => {
  it("apply returns ok without writing when the matched line already equals the target", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nKEY=value\nEND=bar\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(writtenFiles).toStrictEqual([])
  })

  it("regression — apply replaces the full matching line, not only the matched substring", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "prefix KEY=old suffix\nSECOND=line\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    await mod.apply(ssh, emptyEnv)

    expect(writtenFiles[0]?.content).toBe("KEY=value\nSECOND=line\n")
  })

  it("apply replaces line containing & without treating it as a backreference", async () => {
    // JS String.replace with a RegExp treats $& as "insert matched substring".
    // The implementation must escape the replacement string so that & is literal.
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "DB_URL=old\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/config", "DB_URL=postgres://user:pass@host/db & more", {
      match: "DB_URL=.*",
    })
    await mod.apply(ssh, emptyEnv)

    expect(writtenFiles[0]?.content).toContain("DB_URL=postgres://user:pass@host/db & more")
    expect(writtenFiles[0]?.content).not.toContain("DB_URL=oldDB_URL=old")
  })

  it("apply replaces line containing backslash without treating it as an escape sequence", async () => {
    // JS String.replace treats $` and $' specially. A bare backslash in the
    // replacement is literal in JS, but the implementation must not mangle it.
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "LOG_DIR=old\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/config", "LOG_DIR=C:\\logs\\app", { match: "LOG_DIR=.*" })
    await mod.apply(ssh, emptyEnv)

    expect(writtenFiles[0]?.content).toContain("LOG_DIR=C:\\logs\\app")
  })

  it("apply replaces line containing forward slashes correctly", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/nginx/nginx.conf'": { stdout: "include old;\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/nginx/nginx.conf", "include /etc/nginx/conf.d/*.conf;", {
      match: "include .*",
    })
    await mod.apply(ssh, emptyEnv)

    expect(writtenFiles[0]?.content).toContain("include /etc/nginx/conf.d/*.conf;")
  })

  it("regression — apply fails instead of writing unchanged content when no match is found", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nMORE=bar\n" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.line("/etc/config", "KEY=value", { match: "KEY=.*" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("No line matching KEY=.* found for replacement")
    expect(writtenFiles).toStrictEqual([])
  })
})

describe("file.line — clientseitiges Matching (check with options.match)", () => {
  it("check returns ok when exact line is present after match", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": {
        stdout: "OTHER=foo\nDB_URL=postgres://user:pass@host/db & more\nEND=bar",
      },
    })
    const mod = file.line("/etc/config", "DB_URL=postgres://user:pass@host/db & more", {
      match: "DB_URL=.*",
    })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when match exists but line content differs", async () => {
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "OTHER=foo\nDB_URL=old-value\nEND=bar" },
    })
    const mod = file.line("/etc/config", "DB_URL=new-value", { match: "DB_URL=.*" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.template", () => {
  it("check returns ok when rendered SHA-256 matches remote", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")
      const renderedHash = sha256Hex("Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
        "[ -f '/remote/out.txt' ]": { code: 0 },
        "sha256sum '/remote/out.txt'": { stdout: `${renderedHash}  /remote/out.txt` },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when the rendered target is a symlink to a matching file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")

      const ssh = createMockSsh({
        "[ -f '/remote/out.txt' ] && [ ! -L '/remote/out.txt' ]": { code: 1 },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("renders dotted environment keys in template placeholders", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "listen {{app.port|raw}} on {{system.host|raw}}")
      const renderedContent = "listen 8080 on app.example.com"
      const renderedHash = sha256Hex(renderedContent)

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
        "[ -f '/remote/out.txt' ]": { code: 0 },
        "sha256sum '/remote/out.txt'": { stdout: `${renderedHash}  /remote/out.txt` },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(ssh, {
        "app.port": 8080,
        "system.host": "app.example.com",
      })
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when file does not exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 1 },
        "[ -f '/remote/out.txt' ] && [ ! -L '/remote/out.txt' ]": { code: 1 },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when SHA-256 differs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
        "[ -f '/remote/out.txt' ]": { code: 0 },
        "sha256sum '/remote/out.txt'": { stdout: "deadbeef00000000  /remote/out.txt" },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when template mode differs despite identical rendered content", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")
      const renderedHash = sha256Hex("Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
        "[ -f '/remote/out.txt' ]": { code: 0 },
        "sha256sum '/remote/out.txt'": { stdout: `${renderedHash}  /remote/out.txt` },
        "stat -c '%a %U %G' '/remote/out.txt'": { stdout: "644 root root" },
      })

      const mod = file.template("/remote/out.txt", templatePath, { mode: "0600" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when template owner differs despite identical rendered content", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")
      const renderedHash = sha256Hex("Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
        "[ -f '/remote/out.txt' ]": { code: 0 },
        "sha256sum '/remote/out.txt'": { stdout: `${renderedHash}  /remote/out.txt` },
        "stat -c '%a %U %G' '/remote/out.txt'": { stdout: "600 root root" },
      })

      const mod = file.template("/remote/out.txt", templatePath, {
        mode: "0600",
        owner: "www-data:www-data",
      })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when ssh is null", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")

      const mod = file.template("/remote/out.txt", templatePath)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("defaults to strict mode and rejects bare placeholders", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello {{name}}")
      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 0 },
      })

      const mod = file.template("/remote/out.txt", templatePath)
      await expect(mod.check(ssh, { name: "World" })).rejects.toThrow(/Strict mode/v)
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply writes rendered content", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello {{name}}")

      const writtenFiles: Array<{ content: string; path: string }> = []
      const ssh = createMockSsh()
      // eslint-disable-next-line @typescript-eslint/require-await -- Mock
      ssh.writeFile = async (path: string, content: string) => {
        writtenFiles.push({ content, path })
      }

      const mod = file.template("/remote/out.txt", templatePath, { strict: false })
      const result = await mod.apply(ssh, { name: "World" })

      expect(result.status).toBe("changed")
      expect(writtenFiles).toStrictEqual([{ content: "Hello World", path: "/remote/out.txt" }])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply renders unicode template content and values", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      // R-0000139: ASCII-only template filename for filesystem stability;
      // unicode is exercised via content/values and remote paths below.
      const templatePath = join(dir, "ascii-template.tmpl")
      writeFileSync(templatePath, "Hallo {{name|raw}} aus {{city|raw}}", "utf8")

      const writtenFiles: Array<{ content: string; path: string }> = []
      const ssh = createMockSsh()
      // eslint-disable-next-line @typescript-eslint/require-await -- Mock
      ssh.writeFile = async (path: string, content: string) => {
        writtenFiles.push({ content, path })
      }

      const mod = file.template("/remote/über-vorlage.txt", templatePath)
      const result = await mod.apply(ssh, { city: "München", name: "Jörg" })

      expect(result.status).toBe("changed")
      expect(writtenFiles).toStrictEqual([
        { content: "Hallo Jörg aus München", path: "/remote/über-vorlage.txt" },
      ])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })
})

describe("file.assemble", () => {
  it("check returns ok when SHA-256 of concatenated fragments matches", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      const frag2 = join(dir, "frag2.txt")
      writeFileSync(frag1, "Hello ")
      writeFileSync(frag2, "World")
      const combinedHash = sha256Hex("Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: `${combinedHash}  /remote/assembled.txt` },
        "stat -c '%a %U %G' '/remote/assembled.txt'": { stdout: "644 root root" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1, frag2])
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when the assembled target is a symlink to a matching file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh({
        "[ -f '/remote/assembled.txt' ] && [ ! -L '/remote/assembled.txt' ]": { code: 1 },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns ok when no mode is configured and an existing file has mode 0600", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")
      const combinedHash = sha256Hex("Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: `${combinedHash}  /remote/assembled.txt` },
        "stat -c '%a %U %G' '/remote/assembled.txt'": { stdout: "600 root root" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when file does not exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 1 },
        "[ -f '/remote/assembled.txt' ] && [ ! -L '/remote/assembled.txt' ]": { code: 1 },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when SHA-256 differs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: "deadbeef00000000  /remote/assembled.txt" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when ssh is null", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply rejects invalid mode string", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh(
        { "[ -L '/remote/assembled.txt' ]": { code: 1 } },
        { allowWrites: [{ options: { mode: "999" }, remotePath: "/remote/assembled.txt" }] }
      )
      const mod = file.assemble("/remote/assembled.txt", [frag1], { mode: "999" })

      await expect(mod.apply(ssh, emptyEnv)).rejects.toThrow(/mode/v)
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply writes concatenated fragments", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      const frag2 = join(dir, "frag2.txt")
      writeFileSync(frag1, "Hello ")
      writeFileSync(frag2, "World")

      const writtenFiles: Array<{ content: string; path: string }> = []
      const ssh = createMockSsh({
        "[ -L '/remote/assembled.txt' ]": { code: 1 },
      })
      // eslint-disable-next-line @typescript-eslint/require-await -- Mock
      ssh.writeFile = async (path: string, content: string) => {
        writtenFiles.push({ content, path })
      }

      const mod = file.assemble("/remote/assembled.txt", [frag1, frag2])
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(writtenFiles).toStrictEqual([
        { content: "Hello World", path: "/remote/assembled.txt" },
      ])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply refuses to write through a symlink", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const writtenFiles: Array<{ content: string; path: string }> = []
      const ssh = createMockSsh({
        "[ -L '/remote/assembled.txt' ]": { code: 0 },
      })
      // eslint-disable-next-line @typescript-eslint/require-await -- Mock
      ssh.writeFile = async (path: string, content: string) => {
        writtenFiles.push({ content, path })
      }

      const mod = file.assemble("/remote/assembled.txt", [frag1])
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("refuses to write through symlink")
      expect(writtenFiles).toStrictEqual([])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  // R-0000059: file.assemble.check must detect explicit mode/owner drift.
  // Hash-only comparison previously masked manual chmod/chown edits and the
  // recipe falsely reported `ok` after operator drift.
  it("check returns needs-apply when the hash matches but the mode drifted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")
      const combinedHash = sha256Hex("Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: `${combinedHash}  /remote/assembled.txt` },
        // Operator manually chmod'd 0644 even though the recipe pinned 0600.
        "stat -c '%a %U %G' '/remote/assembled.txt'": { stdout: "644 root root" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1], { mode: "0600" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns needs-apply when the hash matches but the owner drifted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")
      const combinedHash = sha256Hex("Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: `${combinedHash}  /remote/assembled.txt` },
        // Recipe pins owner=www-data but the file is currently owned by root.
        "stat -c '%a %U %G' '/remote/assembled.txt'": { stdout: "644 root root" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1], { owner: "www-data" })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("needs-apply")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("check returns ok when hash matches and the explicit mode/owner also match", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")
      const combinedHash = sha256Hex("Hello")

      const ssh = createMockSsh({
        "[ -e '/remote/assembled.txt' ]": { code: 0 },
        "[ -f '/remote/assembled.txt' ]": { code: 0 },
        "sha256sum '/remote/assembled.txt'": { stdout: `${combinedHash}  /remote/assembled.txt` },
        "stat -c '%a %U %G' '/remote/assembled.txt'": { stdout: "600 www-data www-data" },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1], {
        mode: "0600",
        owner: "www-data:www-data",
      })
      const result = await mod.check(ssh, emptyEnv)
      expect(result).toBe("ok")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("R-0000268: returns failed when chmod after writeFile exits non-zero", async () => {
    // chmod errors after writeFile (read-only mount, EPERM after relabel,
    // immutable bit) must surface as a failedCommand ModuleResult instead
    // of an unguarded CommandError that bypasses the runner pipeline.
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh({
        "[ -L '/remote/assembled.txt' ]": { code: 1 },
        "chmod '0600' '/remote/assembled.txt'": {
          code: 1,
          stderr: "chmod: changing permissions of '/remote/assembled.txt': Read-only file system",
        },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1], { mode: "0600" })
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("chmod failed")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("R-0000268: returns failed when chown after writeFile exits non-zero", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const frag1 = join(dir, "frag1.txt")
      writeFileSync(frag1, "Hello")

      const ssh = createMockSsh({
        "[ -L '/remote/assembled.txt' ]": { code: 1 },
        "chown -- 'www-data' '/remote/assembled.txt'": {
          code: 1,
          stderr: "chown: invalid user: 'www-data'",
        },
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1], { owner: "www-data" })
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("chown failed")
    } finally {
      rmSync(dir, { recursive: true })
    }
  })
})

describe("file.block", () => {
  it("check returns ok when block exists with correct content", async () => {
    const beginMarker = "# BEGIN paratix: myblock"
    const endMarker = "# END paratix: myblock"
    const fileContent = `some line\n${beginMarker}\ncontent line\n${endMarker}\nother line`

    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: fileContent },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
    })

    const mod = file.block("/etc/hosts", { content: "content line", name: "myblock" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when markers not found", async () => {
    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: "unmanaged content\n" },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 1 },
    })

    const mod = file.block("/etc/hosts", { content: "content line", name: "myblock" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when block content differs", async () => {
    const beginMarker = "# BEGIN paratix: myblock"
    const endMarker = "# END paratix: myblock"
    const fileContent = `${beginMarker}\nold content\n${endMarker}`

    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: fileContent },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
    })

    const mod = file.block("/etc/hosts", { content: "new content", name: "myblock" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when block end marker is missing", async () => {
    const beginMarker = "# BEGIN paratix: myblock"
    const fileContent = `${beginMarker}\ncontent line\nimportant foreign content`

    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: fileContent },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
      [`grep -qF '# END paratix: myblock' '/etc/hosts'`]: { code: 1 },
    })

    const mod = file.block("/etc/hosts", { content: "content line", name: "myblock" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the block target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/hosts' ]": { code: 0 },
      "[ -f '/etc/hosts' ] && [ ! -L '/etc/hosts' ]": { code: 1 },
      [`cat '/etc/hosts'`]: {
        stdout: "# BEGIN paratix: myblock\ncontent line\n# END paratix: myblock\n",
      },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
    })

    const mod = file.block("/etc/hosts", { content: "content line", name: "myblock" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("cat '/etc/hosts'")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.block("/etc/hosts", { content: "content line", name: "myblock" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply appends block when markers not found", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: "existing content\n" },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 1 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.block("/etc/hosts", { content: "my line", name: "myblock" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.path).toBe("/etc/hosts")
    expect(writtenFiles[0]?.content).toContain("# BEGIN paratix: myblock")
    expect(writtenFiles[0]?.content).toContain("my line")
    expect(writtenFiles[0]?.content).toContain("# END paratix: myblock")
    expect(writtenFiles[0]?.content).toContain("existing content")
  })

  it("apply fails without writing when the block target is a symlink", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "[ -e '/etc/hosts' ]": { code: 0 },
      "[ -f '/etc/hosts' ] && [ ! -L '/etc/hosts' ]": { code: 1 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.block("/etc/hosts", { content: "my line", name: "myblock" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("path must be a regular file and not a symlink")
    expect(writtenFiles).toStrictEqual([])
  })

  it("apply replaces block content when markers exist", async () => {
    const beginMarker = "# BEGIN paratix: myblock"
    const endMarker = "# END paratix: myblock"
    const existingContent = `before\n${beginMarker}\nold content\n${endMarker}\nafter`

    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: existingContent },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.block("/etc/hosts", { content: "new content", name: "myblock" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.content).toContain("new content")
    expect(writtenFiles[0]?.content).not.toContain("old content")
  })

  it("apply fails without writing when block end marker is missing", async () => {
    const beginMarker = "# BEGIN paratix: myblock"
    const existingContent = `before\n${beginMarker}\nold content\nafter`

    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`cat '/etc/hosts'`]: { stdout: existingContent },
      [`grep -qF '# BEGIN paratix: myblock' '/etc/hosts'`]: { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.block("/etc/hosts", { content: "new content", name: "myblock" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("invalid marker pair")
    expect(writtenFiles).toHaveLength(0)
  })

  it("apply preserves unicode block content and unicode paths", async () => {
    const unicodeBlockPath = "/etc/über hosts"
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      [`cat '${unicodeBlockPath}'`]: { stdout: "bestehend\n" },
      [`grep -qF '# BEGIN paratix: grüße-block' '${unicodeBlockPath}'`]: { code: 1 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.block(unicodeBlockPath, {
      content: "Привет\nこんにちは\nGrüße",
      name: "grüße-block",
    })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.path).toBe(unicodeBlockPath)
    expect(writtenFiles[0]?.content).toContain("# BEGIN paratix: grüße-block")
    expect(writtenFiles[0]?.content).toContain("Привет")
    expect(writtenFiles[0]?.content).toContain("こんにちは")
    expect(writtenFiles[0]?.content).toContain("Grüße")
  })
})

describe("file.properties", () => {
  it("rejects invalid modes before rendering chmod", () => {
    expect(() => file.properties("/var/app", { mode: "--reference=/tmp/source" })).toThrow(
      "Invalid file mode"
    )
  })

  it("rejects option-like owner names before rendering chown", () => {
    expect(() => file.properties("/var/app", { owner: "--reference=/tmp/source" })).toThrow(
      'user name "--reference=/tmp/source" is invalid'
    )
  })

  it("rejects option-like group names before rendering chgrp", () => {
    expect(() => file.properties("/var/app", { group: "--reference=/tmp/source" })).toThrow(
      'group name "--reference=/tmp/source" is invalid'
    )
  })

  it("check returns ok when all properties match", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data www-data" },
    })

    const mod = file.properties("/var/app", { group: "www-data", mode: "0644", owner: "www-data" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when mode differs", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 www-data www-data" },
    })

    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when owner differs", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 root www-data" },
    })

    const mod = file.properties("/var/app", { owner: "www-data" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply runs chmod and chown when mode and owner differ from current state", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 root root" },
    })
    const mod = file.properties("/var/app", { mode: "0644", owner: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chmod -- '0644' '/var/app'")
    expect(ssh.calls).toContain("chown -- 'www-data' '/var/app'")
  })

  it("apply returns ok and does not run chmod/chown/chgrp when nothing has drifted", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data www-data" },
    })
    const mod = file.properties("/var/app", {
      group: "www-data",
      mode: "0644",
      owner: "www-data",
    })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("chmod -- '0644' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chgrp -- 'www-data' '/var/app'")
  })

  it("apply only runs chmod when only mode has drifted", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 www-data www-data" },
    })
    const mod = file.properties("/var/app", {
      group: "www-data",
      mode: "0644",
      owner: "www-data",
    })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chmod -- '0644' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
  })

  it("apply combines chown owner:group when both have drifted", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 root root" },
    })
    const mod = file.properties("/var/app", {
      group: "www-data",
      mode: "0644",
      owner: "www-data",
    })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).not.toContain("chmod -- '0644' '/var/app'")
    expect(ssh.calls).toContain("chown -- 'www-data:www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chgrp -- 'www-data' '/var/app'")
  })

  it("apply only invokes chgrp when group alone has drifted", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data root" },
    })
    const mod = file.properties("/var/app", { group: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chgrp -- 'www-data' '/var/app'")
  })

  it("apply normalises mode comparisons: 0644 desired matches 644 from stat", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data www-data" },
    })
    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("chmod -- '0644' '/var/app'")
  })

  it("regression R-0000133 — apply refuses to mutate a symlinked path", async () => {
    // chmod/chown/chgrp follow symlinks. file.properties must reject symlinks
    // before reading state or issuing any mutation, otherwise a malicious or
    // accidental link redirects the change onto the target.
    const ssh = createMockSsh({
      "[ -L '/var/app' ]": { code: 0 },
    })
    const mod = file.properties("/var/app", { group: "www-data", mode: "0644", owner: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refuses to operate through symlink")
    expect(ssh.calls).not.toContain("chmod -- '0644' '/var/app'")
    expect(ssh.calls).not.toContain("chown -- 'www-data:www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chgrp -- 'www-data' '/var/app'")
    expect(ssh.calls).not.toContain("stat -c '%a %U %G' '/var/app'")
  })

  it("regression R-0000133 — check returns needs-apply when the target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -L '/var/app' ]": { code: 0 },
    })
    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000268: returns failed when chmod exits non-zero (read-only fs)", async () => {
    // chmod on a read-only mount must surface as a maskable failedCommand
    // ModuleResult instead of an unguarded CommandError that bypasses the
    // runner's failure pipeline.
    const ssh = createMockSsh({
      "chmod -- '0644' '/var/app'": {
        code: 1,
        stderr: "chmod: changing permissions of '/var/app': Read-only file system",
      },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 www-data www-data" },
    })
    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("chmod failed")
  })

  it("R-0000268: returns failed when combined chown exits non-zero", async () => {
    const ssh = createMockSsh({
      "chown -- 'www-data:www-data' '/var/app'": {
        code: 1,
        stderr: "chown: invalid user: 'www-data:www-data'",
      },
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 root root" },
    })
    const mod = file.properties("/var/app", { group: "www-data", owner: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("chown failed")
  })

  it("R-0000268: returns failed when single chgrp exits non-zero", async () => {
    const ssh = createMockSsh({
      "chgrp -- 'www-data' '/var/app'": {
        code: 1,
        stderr: "chgrp: invalid group: 'www-data'",
      },
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data root" },
    })
    const mod = file.properties("/var/app", { group: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("chgrp failed")
  })
})

describe("file.replace", () => {
  it("check returns ok when pattern not found (nothing to replace)", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "alpha beta gamma" },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when pattern found and replacement would change content", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "foo old-value bar" },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when remote file does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 1 },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when the replace target is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "[ -f '/etc/config' ] && [ ! -L '/etc/config' ]": { code: 1 },
      "cat '/etc/config'": { stdout: "foo old-value bar" },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(ssh.calls).not.toContain("cat '/etc/config'")
  })

  it("check returns ok after apply when replacement uses negative lookahead to prevent re-matching", async () => {
    // Regression for R-0000034: pattern "foo(?!bar)" with replacement "foobar".
    // The old grep-based check reported needs-apply forever because the file
    // still contains "foo" as a substring of "foobar". The new content-based
    // check correctly detects that applying the regex on "alpha foobar gamma"
    // would not change the file (the negative lookahead skips "foo" inside
    // "foobar") and reports ok.
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "alpha foobar gamma" },
    })

    const mod = file.replace("/etc/config", "foo(?!bar)", "foobar")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok after a successful apply (post-replacement state, no remaining matches)", async () => {
    // Regression for R-0000034 in the common non-overlapping case: pattern
    // "old-value" replacement "new-value". After apply the file contains only
    // "new-value" and the pattern no longer matches, so check returns ok.
    const ssh = createMockSsh({
      "[ -e '/etc/config' ]": { code: 0 },
      "cat '/etc/config'": { stdout: "alpha new-value gamma" },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("apply reads file, replaces content and writes back", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "foo old-value bar old-value baz" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writtenFiles[0]?.content).toBe("foo new-value bar new-value baz")
  })

  it("apply fails without writing when the replace target is a symlink", async () => {
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "[ -f '/etc/config' ] && [ ! -L '/etc/config' ]": { code: 1 },
      "cat '/etc/config'": { stdout: "foo old-value bar" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("path must be a regular file and not a symlink")
    expect(writtenFiles).toStrictEqual([])
  })

  it("apply returns ok and does not write when pattern produces no replacement", async () => {
    // R-0000075: when the regex does not match anything in the file, apply
    // must short-circuit, return status ok, and skip the SFTP write so the
    // run is not flagged as "changed" forever.
    const writtenFiles: Array<{ content: string; path: string }> = []
    const ssh = createMockSsh({
      "cat '/etc/config'": { stdout: "alpha beta gamma" },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock
    ssh.writeFile = async (path: string, content: string) => {
      writtenFiles.push({ content, path })
    }

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(writtenFiles).toStrictEqual([])
  })
})

describe("file.stat", () => {
  it("marks itself as a dry-run meta producer", () => {
    const mod = file.stat("/var/app/file.txt")
    expect(mod._dryRunMetaProducer).toBe(true)
  })

  it("check always returns needs-apply so runner invokes apply", async () => {
    const ssh = createMockSsh()
    const mod = file.stat("/var/app/file.txt")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.stat("/var/app/file.txt")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns metadata in meta field", async () => {
    const ssh = createMockSsh({
      "stat -c '%s %a %U %G %F %Y' '/var/app/file.txt'": {
        stdout: "1234 644 www-data www-data regular file 1700000000",
      },
    })

    const mod = file.stat("/var/app/file.txt")
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    const environment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(environment, "file.stat.group")).resolves.toBe("www-data")
    await expect(resolveEnvironment(environment, "file.stat.mode")).resolves.toBe("644")
    await expect(resolveEnvironment(environment, "file.stat.mtime")).resolves.toBe("1700000000")
    await expect(resolveEnvironment(environment, "file.stat.owner")).resolves.toBe("www-data")
    await expect(resolveEnvironment(environment, "file.stat.size")).resolves.toBe("1234")
    await expect(resolveEnvironment(environment, "file.stat.type")).resolves.toBe("regular file")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = file.stat("/var/app/file.txt")
    const ssh = null
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
