import { describe, expect, it } from "vitest"

import {
  buildCertificateConfig,
  includePatterns,
  parseCertificateFileArgument,
  parseIncludeValue,
  scanCertificateSshdConfig,
} from "../../../src/modules/sshCertificateConfig.js"
import { CertificateFileError } from "../../../src/modules/sshCertificateFiles.js"
import {
  applySshdSettingToContent,
  parseSshdConfigLine,
} from "../../../src/modules/sshdConfigHelpers.js"
import { shellQuote } from "../../../src/ssh.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

function expandCommand(glob: string): string {
  return `for paratix_include in ${glob}; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf '%s\\n' "$paratix_include"; fi; done`
}

function commentWordCommand(word: string): string {
  return expandCommand(`'/etc/ssh/${word}'`)
}

describe("single certificate filename argument", () => {
  it.each([
    ["/etc/ssh/key # managed", "/etc/ssh/key"],
    ['"/etc/ssh/key"\t# note', "/etc/ssh/key"],
    ["'/etc/ssh/key' # note", "/etc/ssh/key"],
    ["/etc/ssh/key#1 # note", "/etc/ssh/key#1"],
    ['"/etc/ssh/key#1" # note', "/etc/ssh/key#1"],
    ['"/etc/ssh/key with spaces" # note', "/etc/ssh/key with spaces"],
    [String.raw`/etc/ssh/key # ignored " '\escape`, "/etc/ssh/key"],
  ])("resolves %j without the trailing comment", (value, expected) => {
    expect(parseCertificateFileArgument("HostCertificate", value).value).toBe(expected)
  })

  it.each([
    "",
    "# note",
    '"" # note',
    "''",
    "/etc/ssh/key /etc/ssh/other # note",
    '/etc/ssh/"key" # note',
    '"/etc/ssh/key"suffix',
    '"/etc/ssh/key',
    "'/etc/ssh/key",
    String.raw`/etc/ssh/key\name # note`,
    String.raw`"/etc/ssh/key\name"`,
    '"/etc/ssh/key"#note',
    "/etc/ssh/key\u0000",
  ])("rejects unresolved filename %j", (value) => {
    expect(() => parseCertificateFileArgument("HostCertificate", value)).toThrow(
      CertificateFileError
    )
  })
})

describe("sshd certificate configuration", () => {
  it("keeps trailing comments verbatim in generic parsing and settings apply", () => {
    const line = "HostCertificate /etc/ssh/host-cert.pub # managed"
    expect(parseSshdConfigLine(line)).toStrictEqual({
      directive: "HostCertificate",
      value: "/etc/ssh/host-cert.pub # managed",
    })
    expect(applySshdSettingToContent(`${line}\n`, "HostCertificate", "/new/path # retained")).toBe(
      "HostCertificate /new/path # retained\n"
    )
  })

  it("updates only managed global directives and preserves unrelated settings", () => {
    const input = [
      "Port 22",
      "TrustedUserCAKeys /old/ca",
      "AuthorizedPrincipalsFile /old/%u",
      "PermitRootLogin no",
    ].join("\n")
    expect(
      buildCertificateConfig(
        input,
        {
          AuthorizedPrincipalsFile: "/etc/ssh/auth_principals/%u",
          TrustedUserCAKeys: "/etc/ssh/trusted_user_ca_keys",
        },
        "present"
      )
    ).toContain("PermitRootLogin no")
    expect(
      buildCertificateConfig(
        input,
        {
          AuthorizedPrincipalsFile: "/old/%u",
          TrustedUserCAKeys: "/old/ca",
        },
        "absent"
      )
    ).toContain("Port 22")
  })

  it("rejects removal of foreign directives and keeps managed directives inside Match untouched", () => {
    expect(() =>
      buildCertificateConfig(
        "TrustedUserCAKeys /different/ca\n",
        { TrustedUserCAKeys: "/etc/ssh/trusted_user_ca_keys" },
        "absent"
      )
    ).toThrow(/foreign TrustedUserCAKeys/v)
    const content = [
      "TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys",
      "Match User alice",
      "TrustedUserCAKeys /match/ca",
    ].join("\n")
    expect(
      buildCertificateConfig(
        content,
        { TrustedUserCAKeys: "/etc/ssh/trusted_user_ca_keys" },
        "absent"
      )
    ).toContain("TrustedUserCAKeys /match/ca")
  })

  it("scans active Includes, detects Match conflicts, and accepts known empty globs", async () => {
    const ssh = createMockSsh(
      {
        "cat '/etc/ssh/conf.d/cert.conf'": {
          stdout: "TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n",
        },
        'for paratix_include in /etc/ssh/conf.d/cert.conf; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf \'%s\\n\' "$paratix_include"; fi; done':
          {
            stdout: "/etc/ssh/conf.d/cert.conf\n",
          },
        "readlink -f -- '/etc/ssh/conf.d/cert.conf'": {
          stdout: "/etc/ssh/conf.d/cert.conf\n",
        },
      },
      {
        responseStubs: [
          {
            command: "[ -f '/etc/ssh/conf.d/cert.conf' ] && [ -r '/etc/ssh/conf.d/cert.conf' ]",
            result: { code: 0 },
          },
          {
            command:
              "[ -e '/etc/ssh/trusted_user_ca_keys' ] || [ -L '/etc/ssh/trusted_user_ca_keys' ]",
            result: { code: 0 },
          },
        ],
      }
    )
    const scan = await scanCertificateSshdConfig(ssh, {
      content: "Match User alice\nInclude /etc/ssh/conf.d/cert.conf\n",
      path: "/etc/ssh/sshd_config",
      rejectMatch: true,
    }).catch((error: unknown) => error)
    expect(String(scan)).toMatch(/Match block/v)

    const emptyGlob = createMockSsh(
      {},
      {
        responseStubs: [
          { command: /^for paratix_include in .*; do /v, result: { code: 0, stdout: "" } },
        ],
      }
    )
    await expect(
      scanCertificateSshdConfig(emptyGlob, {
        content: "Include conf.d/*.conf\n",
        path: "/etc/ssh/sshd_config",
        rejectMatch: true,
      })
    ).resolves.toMatchObject({ files: ["/etc/ssh/sshd_config"] })
  })
})

describe("includePatterns", () => {
  it.each([
    ["/etc/ssh/sshd_config.d/*.conf # distro default", ["/etc/ssh/sshd_config.d/*.conf"]],
    ["a.conf b.conf #c d.conf", ["/etc/ssh/a.conf", "/etc/ssh/b.conf"]],
    ["a.conf # distro default", ["/etc/ssh/a.conf"]],
    ['"/etc/ssh/sshd_config.d/*.conf"', ["/etc/ssh/sshd_config.d/*.conf"]],
    ["'/etc/ssh/sshd_config.d/*.conf'", ["/etc/ssh/sshd_config.d/*.conf"]],
  ])("resolves %j", (value, expected) => {
    expect(includePatterns(value)).toStrictEqual(expected)
  })

  it.each([
    ["a quoted path containing a hash", '"/etc/ssh/a#b.conf"'],
    ["a double-quoted token starting with a hash", 'a.conf "#b.conf"'],
    ["a single-quoted token starting with a hash", "a.conf '#b.conf'"],
    ["an unquoted mid-token hash", "a#b.conf"],
    ["a quote opened mid-token", 'a.conf" #note"'],
    ["an unterminated quote", '"a.conf #c'],
    ["a lone opening quote", '"b'],
    ["a quoted string glued to a comment", '"a.conf"#c'],
    ["a quoted string glued to a word", '"a.conf"b.conf'],
    ["a vertical tab before a hash", "a.conf\v#c"],
    ["a glob-like comment word", "a.conf # see sshd_config.d/*.conf"],
    ["a comment-only value", "# note"],
    ["a hash directly behind a word", "a.conf# c"],
    ["a backslash", String.raw`a\.conf`],
    ["a backslash in a comment word", String.raw`a.conf # a\lice`],
    ["a comment word starting with a tilde", "a.conf # ~alice"],
    ["a quoted comment word starting with a tilde", 'a.conf # "~a b"'],
    ["a tilde behind an equals sign", "a.conf # key=~alice"],
  ])("rejects %s", (_label, value) => {
    expect(() => includePatterns(value)).toThrow(CertificateFileError)
  })
})

describe("parseIncludeValue", () => {
  it.each([
    ["a.conf", []],
    ["a.conf # alice", ["#", "alice"]],
    ["a.conf #c d.conf", ["#c", "d.conf"]],
    ["a.conf # key=alice", ["#", "key", "alice"]],
    ['a.conf # "a b"', ["#", "a", "b", "a b"]],
    ['a.conf # a"lice"', ["#", "a", "lice", "alice"]],
    ['a.conf # x"a b"z"c"', ["#", "x", "a", "b", "z", "c", "xa b", "zc"]],
    ["a.conf # alice alice", ["#", "alice"]],
  ])("returns the comment words of %j", (value, expected) => {
    expect(parseIncludeValue(value)).toStrictEqual({
      commentWords: expected,
      patterns: ["/etc/ssh/a.conf"],
    })
  })
})

describe("scanCertificateSshdConfig trailing comments", () => {
  const ROOT = "/etc/ssh/sshd_config"
  const INCLUDED = "/etc/ssh/conf.d/a.conf"

  function scanSsh(
    overrides: Record<string, { code?: number; stderr?: string; stdout?: string }> = {}
  ) {
    return createMockSsh(
      {
        [`cat '${INCLUDED}'`]: { stdout: "Port 22\n" },
        [`readlink -f -- '${INCLUDED}'`]: { stdout: `${INCLUDED}\n` },
        [expandCommand("/etc/ssh/conf.d/*.conf")]: { stdout: `${INCLUDED}\n` },
        ...overrides,
      },
      {
        responseStubs: [
          { command: /^\[ -f /v, result: { code: 0 } },
          { command: /^\[ -e .* \] \|\| \[ -L /v, result: { code: 1 } },
          { command: /^for paratix_include in '/v, result: { stdout: "" } },
        ],
      }
    )
  }

  async function scan(content: string, ssh = scanSsh()) {
    return scanCertificateSshdConfig(ssh, { content, path: ROOT, rejectMatch: true })
  }

  it("scans the same include tree as the comment-free line", async () => {
    const plainSsh = scanSsh()
    const commentSsh = scanSsh()
    const plain = await scan("Include conf.d/*.conf\n", plainSsh)
    const commented = await scan("Include conf.d/*.conf # note\n", commentSsh)
    expect(plain.files).toStrictEqual([ROOT, INCLUDED])
    expect(commented.files).toStrictEqual(plain.files)
    expect(commentSsh.calls).toContain(expandCommand("/etc/ssh/conf.d/*.conf"))
  })

  it.each([
    ["a plain word", "# alice", "alice"],
    ["the hash word", "# alice", "#"],
    ["a hash-prefixed word", "#c d.conf", "#c"],
    ["a word behind a hash-prefixed word", "#c d.conf", "d.conf"],
    ["the key of a key=value word", "# key=alice", "key"],
    ["the value of a key=value word", "# key=alice", "alice"],
    ["a quoted span", '# "a b"', "a b"],
    ["a span joined to its prefix", '# a"lice"', "alice"],
  ])("rejects a comment naming an existing file through %s", async (_label, comment, word) => {
    const ssh = scanSsh({ [commentWordCommand(word)]: { stdout: `/etc/ssh/${word}\n` } })
    const error = await scan(`Include conf.d/*.conf ${comment}\n`, ssh).catch(
      (error_: unknown) => error_
    )
    expect(error).toBeInstanceOf(CertificateFileError)
    expect((error as Error).message).toContain(`comment word ${word}`)
    expect(ssh.calls).not.toContain(expandCommand("/etc/ssh/conf.d/*.conf"))
  })

  it("checks every comment word and accepts a comment that names no file", async () => {
    const ssh = scanSsh()
    const result = await scan("Include conf.d/*.conf # alice key=bob\n", ssh)
    expect(result.files).toStrictEqual([ROOT, INCLUDED])
    expect(ssh.calls).toStrictEqual(
      expect.arrayContaining(["#", "alice", "key", "bob"].map((word) => commentWordCommand(word)))
    )
  })

  it("shell-quotes a comment word before checking it on the host", async () => {
    const ssh = scanSsh()
    await scan("Include conf.d/*.conf # it's $(id)\n", ssh)
    expect(ssh.calls).toStrictEqual(
      expect.arrayContaining(
        ["/etc/ssh/it's", "/etc/ssh/$(id)"].map((path) => expandCommand(shellQuote(path)))
      )
    )
  })

  it("treats a dangling symlink named by a comment word as an existing file", async () => {
    expect(commentWordCommand("alice")).toContain('[ -L "$paratix_include" ]')
    const ssh = scanSsh({ [commentWordCommand("alice")]: { stdout: "/etc/ssh/alice\n" } })
    await expect(scan("Include conf.d/*.conf # alice\n", ssh)).rejects.toThrow(
      /comment word alice/v
    )
  })

  it("fails closed when the comment word check fails", async () => {
    const ssh = scanSsh({ [commentWordCommand("alice")]: { code: 1, stderr: "sudo: failure" } })
    await expect(scan("Include conf.d/*.conf # alice\n", ssh)).rejects.toThrow(CertificateFileError)
    expect(ssh.calls).not.toContain(expandCommand("/etc/ssh/conf.d/*.conf"))
  })

  it("rejects a comment word in an included file", async () => {
    const ssh = scanSsh({
      [`cat '${INCLUDED}'`]: { stdout: "Include b.conf # alice\n" },
      [commentWordCommand("alice")]: { stdout: "/etc/ssh/alice\n" },
    })
    await expect(scan("Include conf.d/*.conf\n", ssh)).rejects.toThrow(/comment word alice/v)
  })

  it.each([
    ["# ssh_host_ed25519_key-cert.pub", "/etc/ssh/ssh_host_ed25519_key-cert.pub"],
    ["# trusted_user_ca_keys", "/etc/ssh/trusted_user_ca_keys"],
    ["# key=revoked_keys", "/etc/ssh/./revoked_keys"],
    ['# "host cert.pub"', "/etc/ssh/host cert.pub"],
  ])("rejects absent planned writes named by %j", async (comment, path) => {
    const ssh = scanSsh()
    await expect(
      scanCertificateSshdConfig(ssh, {
        content: `Include conf.d/*.conf ${comment}\n`,
        path: ROOT,
        plannedWrites: [path],
        rejectMatch: true,
      })
    ).rejects.toThrow(/comment word .*planned write/v)
    expect(ssh.calls).not.toContain(expandCommand("/etc/ssh/conf.d/*.conf"))
  })

  it("propagates planned writes through included files", async () => {
    const ssh = scanSsh({
      [`cat '${INCLUDED}'`]: { stdout: "Include empty.conf # trusted_user_ca_keys\n" },
    })
    await expect(
      scanCertificateSshdConfig(ssh, {
        content: "Include conf.d/*.conf\n",
        path: ROOT,
        plannedWrites: ["/etc/ssh/trusted_user_ca_keys"],
        rejectMatch: true,
      })
    ).rejects.toThrow(/comment word trusted_user_ca_keys.*planned write/v)
  })

  it("reads the CA path before the comment", async () => {
    const result = await scan("TrustedUserCAKeys /etc/ssh/ca.pub # note\n")
    expect(result.caFiles).toContain("/etc/ssh/ca.pub")
    expect(result.caFiles.some((path) => path.includes("#"))).toBe(false)
  })

  it("reads the revocation path before the comment", async () => {
    const result = await scan("RevokedKeys /etc/ssh/revoked # note\n")
    expect(result.revocations).toContain("/etc/ssh/revoked")
    expect(result.revocations.some((path) => path.includes("#"))).toBe(false)
  })

  it.each([
    ["TrustedUserCAKeys", "ca.pub"],
    ["TrustedUserCAKeys", '"ca.pub"'],
    ["RevokedKeys", "revoked"],
    ["RevokedKeys", "'revoked'"],
    ["TrustedUserCAKeys", "~/ca.pub"],
    ["RevokedKeys", "~/revoked"],
  ])("rejects relative %s path %s before probing the remote host", async (directive, path) => {
    const ssh = scanSsh()
    const error = await scan(`${directive} ${path}\n`, ssh).catch((error_: unknown) => error_)
    expect(error).toBeInstanceOf(CertificateFileError)
    expect((error as Error).message).toContain(directive)
    expect((error as Error).message).toContain(path)
    expect(ssh.calls).toStrictEqual([])
  })

  it("keeps an absolute quoted TrustedUserCAKeys path and its physical symlink target", async () => {
    const path = "/var/lib/paratix/ca.pub"
    const physicalPath = "/srv/keys/ca.pub"
    const ssh = scanSsh({
      [`[ -e '${path}' ] || [ -L '${path}' ]`]: { code: 0 },
      [`readlink -f -- '${path}'`]: { stdout: `${physicalPath}\n` },
    })
    const result = await scan(`TrustedUserCAKeys "${path}"\n`, ssh)
    expect(result.caFiles).toStrictEqual([path, physicalPath])
  })

  it("keeps an absolute quoted RevokedKeys path and its physical symlink target", async () => {
    const path = "/var/lib/paratix/ca.pub"
    const physicalPath = "/srv/keys/ca.pub"
    const ssh = scanSsh({
      [`[ -e '${path}' ] || [ -L '${path}' ]`]: { code: 0 },
      [`readlink -f -- '${path}'`]: { stdout: `${physicalPath}\n` },
    })
    const result = await scan(`RevokedKeys "${path}"\n`, ssh)
    expect(result.revocations).toStrictEqual([path, physicalPath])
  })

  it.each(["TrustedUserCAKeys", "RevokedKeys"])(
    "rejects an empty physical target for %s",
    async (directive) => {
      const path = "/var/lib/paratix/link"
      const ssh = scanSsh({
        [`[ -e '${path}' ] || [ -L '${path}' ]`]: { code: 0 },
        [`readlink -f -- '${path}'`]: { stdout: "" },
      })
      await expect(scan(`${directive} ${path}\n`, ssh)).rejects.toBeInstanceOf(CertificateFileError)
    }
  )

  it.each(["none", '"none"', "None", "NONE # note"])(
    "reports no TrustedUserCAKeys path for %s",
    async (value) => {
      const ssh = scanSsh()
      const result = await scan(`TrustedUserCAKeys ${value}\n`, ssh)
      expect(result.caFiles).toStrictEqual([])
      expect(ssh.calls).toStrictEqual([])
    }
  )

  it.each(["none", '"none"', "None", "NONE # note"])(
    "reports no RevokedKeys path for %s",
    async (value) => {
      const ssh = scanSsh()
      const result = await scan(`RevokedKeys ${value}\n`, ssh)
      expect(result.revocations).toStrictEqual([])
      expect(ssh.calls).toStrictEqual([])
    }
  )

  it("keeps a quoted hash inside the CA path", async () => {
    const result = await scan('TrustedUserCAKeys "/etc/ssh/ca#1.pub"\n')
    expect(result.caFiles).toContain("/etc/ssh/ca#1.pub")
  })

  it.each([
    "TrustedUserCAKeys a.pub b.pub",
    "RevokedKeys # note",
    'TrustedUserCAKeys ""',
    'TrustedUserCAKeys "/etc/ssh/ca.pub',
    String.raw`TrustedUserCAKeys "/etc/ssh/ca\" #x"`,
    'TrustedUserCAKeys "/etc/ssh/ca.pub"#x',
  ])("rejects %j", async (line) => {
    await expect(scan(`${line}\n`)).rejects.toThrow(CertificateFileError)
  })

  it("names the directive in the rejection of several CA arguments", async () => {
    const error = await scan("TrustedUserCAKeys a.pub b.pub\n").catch((error_: unknown) => error_)
    expect(error).toBeInstanceOf(CertificateFileError)
    expect((error as Error).message).toMatch(/TrustedUserCAKeys/v)
    expect((error as Error).message).not.toContain("Include")
  })
})
