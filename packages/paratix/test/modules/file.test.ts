import { createHash } from "node:crypto"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { file } from "../../src/modules/file.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}
const unicodeContent = "Grüße aus Köln – こんにちは мир\n"
const unicodeName = "über datei.txt"
const unicodeRemotePath = "/remote/über ordner/äöü.txt"

describe("file.directory", () => {
  it("check returns ok when the directory exists", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
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

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.directory("/var/app")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when directory mode differs", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "755 root root" },
    })

    const mod = file.directory("/var/app", { mode: "0700" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when directory owner differs", async () => {
    const ssh = createMockSsh({
      "[ -d '/var/app' ]": { code: 0 },
      "stat -c '%a %U %G' '/var/app'": { stdout: "700 root root" },
    })

    const mod = file.directory("/var/app", { owner: "www-data:www-data" })
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.absent", () => {
  it("rejects an empty remote path", () => {
    expect(() => file.absent("")).toThrow("file.absent: remotePath must not be empty")
  })

  it("rejects the root path", () => {
    expect(() => file.absent("/")).toThrow("file.absent: refusing to remove destructive path: /")
  })

  it("rejects paths that normalize to root", () => {
    expect(() => file.absent("/var/..")).toThrow(
      "file.absent: refusing to remove destructive path: /var/.."
    )
  })

  it("check returns ok when the path does not exist", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ]": { code: 1 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the path exists", async () => {
    const ssh = createMockSsh({
      "[ -e '/tmp/old-file' ]": { code: 0 },
    })
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.absent("/tmp/old-file")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
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
    expect(ssh.calls).toContain("chown 'www-data:www-data' '/var/app/config.yml'")
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
      expect(ssh.calls).toContain("chown 'www-data' '/remote/file.txt'")
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

describe("file.line — sed-Escaping Regression (apply with options.match)", () => {
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

    expect(writtenFiles[0]?.content).toBe("KEY=value\nSECOND=line")
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

  it("check returns needs-apply when file does not exist", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const templatePath = join(dir, "template.txt")
      writeFileSync(templatePath, "Hello World")

      const ssh = createMockSsh({
        "[ -e '/remote/out.txt' ]": { code: 1 },
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
      const templatePath = join(dir, "grüße-テンプレート.tmpl")
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
      })

      const mod = file.assemble("/remote/assembled.txt", [frag1, frag2])
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

      const ssh = createMockSsh()
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
      const ssh = createMockSsh()
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
    expect(ssh.calls).toContain("chmod '0644' '/var/app'")
    expect(ssh.calls).toContain("chown 'www-data' '/var/app'")
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
    expect(ssh.calls).not.toContain("chmod '0644' '/var/app'")
    expect(ssh.calls).not.toContain("chown 'www-data:www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chown 'www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chgrp 'www-data' '/var/app'")
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
    expect(ssh.calls).toContain("chmod '0644' '/var/app'")
    expect(ssh.calls).not.toContain("chown 'www-data:www-data' '/var/app'")
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
    expect(ssh.calls).not.toContain("chmod '0644' '/var/app'")
    expect(ssh.calls).toContain("chown 'www-data:www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chown 'www-data' '/var/app'")
    expect(ssh.calls).not.toContain("chgrp 'www-data' '/var/app'")
  })

  it("apply only invokes chgrp when group alone has drifted", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data root" },
    })
    const mod = file.properties("/var/app", { group: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chgrp 'www-data' '/var/app'")
  })

  it("apply normalises mode comparisons: 0644 desired matches 644 from stat", async () => {
    const ssh = createMockSsh({
      "stat -c '%a %U %G' '/var/app'": { stdout: "644 www-data www-data" },
    })
    const mod = file.properties("/var/app", { mode: "0644" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(ssh.calls).not.toContain("chmod '0644' '/var/app'")
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

  it("check returns ok after apply when replacement uses negative lookahead to prevent re-matching", async () => {
    // Regression for R-0000034: pattern "foo(?!bar)" with replacement "foobar".
    // The old grep-based check reported needs-apply forever because the file
    // still contains "foo" as a substring of "foobar". The new content-based
    // check correctly recognises that applying the regex on "alpha foobar gamma"
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
})

describe("file.stat", () => {
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
