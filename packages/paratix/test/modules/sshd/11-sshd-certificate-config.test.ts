import { describe, expect, it } from "vitest"

import {
  buildCertificateConfig,
  scanCertificateSshdConfig,
} from "../../../src/modules/sshCertificateConfig.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

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
