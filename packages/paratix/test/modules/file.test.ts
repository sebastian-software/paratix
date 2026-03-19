import { createHash } from "node:crypto"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import { file } from "../../src/modules/file.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

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

// Helper: compute sha256 hex of a string
function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex")
}

// Helper: compute sha256 hex of a buffer
function sha256HexBuffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex")
}

describe("file.copy", () => {
  it("check returns ok when SHA-256 matches", async () => {
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

  it("apply calls uploadFile", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const uploadedFiles: Array<{ local: string; remote: string }> = []
      const ssh = createMockSsh()
      // eslint-disable-next-line @typescript-eslint/require-await -- Mock
      ssh.uploadFile = async (local: string, remote: string) => {
        uploadedFiles.push({ local, remote })
      }

      const mod = file.copy("/remote/file.txt", localPath)
      const result = await mod.apply(ssh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(uploadedFiles).toStrictEqual([{ local: localPath, remote: "/remote/file.txt" }])
    } finally {
      rmSync(dir, { recursive: true })
    }
  })

  it("apply sets mode and owner when specified", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paratix-test-"))
    try {
      const localPath = join(dir, "source.txt")
      writeFileSync(localPath, "hello world")

      const ssh = createMockSsh()
      const mod = file.copy("/remote/file.txt", localPath, { mode: "0644", owner: "www-data" })
      await mod.apply(ssh, emptyEnv)

      expect(ssh.calls).toContain("chmod '0644' '/remote/file.txt'")
      expect(ssh.calls).toContain("chown 'www-data' '/remote/file.txt'")
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

  it("check returns needs-apply when ssh is null", async () => {
    const mod = file.line("/etc/config", "my-line")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("file.line — sed-Escaping Regression (apply with options.match)", () => {
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

  it("apply runs chmod and chown", async () => {
    const ssh = createMockSsh()
    const mod = file.properties("/var/app", { mode: "0644", owner: "www-data" })
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("chmod '0644' '/var/app'")
    expect(ssh.calls).toContain("chown 'www-data' '/var/app'")
  })
})

describe("file.replace", () => {
  it("check returns ok when pattern not found (nothing to replace)", async () => {
    const ssh = createMockSsh({
      "grep -qE 'old-value' '/etc/config'": { code: 1 },
    })

    const mod = file.replace("/etc/config", "old-value", "new-value")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when pattern found", async () => {
    const ssh = createMockSsh({
      "grep -qE 'old-value' '/etc/config'": { code: 0 },
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
    expect(result.meta).toMatchObject({
      "file.stat.group": "www-data",
      "file.stat.mode": "644",
      "file.stat.mtime": "1700000000",
      "file.stat.owner": "www-data",
      "file.stat.size": "1234",
      "file.stat.type": "regular file",
    })
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = file.stat("/var/app/file.txt")
    const ssh = null
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
