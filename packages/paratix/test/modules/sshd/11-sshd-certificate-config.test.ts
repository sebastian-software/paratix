import { describe, expect, it } from "vitest"

import {
  buildCertificateConfig,
  includePatterns,
  scanCertificateSshdConfig,
} from "../../../src/modules/sshCertificateConfig.js"
import { CertificateFileError } from "../../../src/modules/sshCertificateFiles.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

function expandCommand(glob: string): string {
  return `for paratix_include in ${glob}; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf '%s\\n' "$paratix_include"; fi; done`
}

describe("sshd certificate configuration", () => {
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
  ])("rejects %s", (_label, value) => {
    expect(() => includePatterns(value)).toThrow(CertificateFileError)
  })
})

describe("scanCertificateSshdConfig trailing comments", () => {
  const ROOT = "/etc/ssh/sshd_config"
  const INCLUDED = "/etc/ssh/conf.d/a.conf"

  function scanSsh() {
    return createMockSsh(
      {
        [`cat '${INCLUDED}'`]: { stdout: "Port 22\n" },
        [`readlink -f -- '${INCLUDED}'`]: { stdout: `${INCLUDED}\n` },
        [expandCommand("/etc/ssh/conf.d/*.conf")]: { stdout: `${INCLUDED}\n` },
      },
      {
        responseStubs: [
          { command: /^\[ -f /v, result: { code: 0 } },
          { command: /^\[ -e .* \] \|\| \[ -L /v, result: { code: 1 } },
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
    "RevokedKeys none # note",
    'RevokedKeys "none"',
    "RevokedKeys None",
    "RevokedKeys NONE # note",
  ])("reports no revocation path for %j", async (line) => {
    const result = await scan(`${line}\n`)
    expect(result.revocations).toStrictEqual([])
  })

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
