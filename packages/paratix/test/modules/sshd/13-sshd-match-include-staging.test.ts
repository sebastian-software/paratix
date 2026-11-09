import { posix } from "node:path"
import { describe, expect, it } from "vitest"

import { scanCertificateSshdConfig } from "../../../src/modules/sshCertificateConfig.js"
import { includeGlobMatches, stageSshdConfigTree } from "../../../src/modules/sshdIncludeStaging.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

const DROP_IN_GLOB = "/etc/ssh/sshd_config.d/*.conf"
function expandCommand(glob: string): string {
  return `for paratix_include in ${glob}; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf '%s\\n' "$paratix_include"; fi; done`
}
const EXPAND = expandCommand(DROP_IN_GLOB)
const STAGING = "/tmp/paratix-sshd-match.ABCDEF"
const B_CONF = "/etc/ssh/sshd_config.d/b.conf"

// `existing` holds the glob results exactly as the remote shell prints them.
function stagingSsh(existing: string[], glob = DROP_IN_GLOB) {
  return createMockSsh(
    {
      [expandCommand(glob)]: { stdout: existing.map((path) => `${path}\n`).join("") },
      ...Object.fromEntries(
        existing.map((path) => [`cat '${posix.normalize(path)}'`, { stdout: `# ${path}\n` }])
      ),
    },
    {
      allowWrites: [
        {
          options: { mode: "0600" },
          remotePath: /^\/tmp\/paratix-sshd-match\.ABCDEF\/validation-\d+$/v,
        },
      ],
      responseStubs: [
        { command: /^\[ -L /v, result: { code: 1 } },
        { command: /^\[ -[edf] /v, result: { code: 0 } },
        { command: /^stat -c '%a %u %g' -- /v, result: { stdout: "755 0 0" } },
        { command: /^sha256sum /v, result: { stdout: "hash  file" } },
      ],
    }
  )
}

describe("generic sshd Include staging", () => {
  it("matches Include globs with pathname semantics", () => {
    expect(includeGlobMatches(DROP_IN_GLOB, "/etc/ssh/sshd_config.d/ops-ro.conf")).toBe(true)
    expect(includeGlobMatches(DROP_IN_GLOB, "/etc/ssh/sshd_config.d/sub/ops.conf")).toBe(false)
    expect(includeGlobMatches(DROP_IN_GLOB, "/etc/ssh/sshd_config.d/.hidden.conf")).toBe(false)
    expect(includeGlobMatches(DROP_IN_GLOB, "/etc/ssh/sshd_config.d/ops.conf.bak")).toBe(false)
    expect(
      includeGlobMatches("/etc/ssh/sshd_config.d/[0-4]?.conf", "/etc/ssh/sshd_config.d/3a.conf")
    ).toBe(true)
    expect(
      includeGlobMatches("/etc/ssh/sshd_config.d/[0-4]?.conf", "/etc/ssh/sshd_config.d/5a.conf")
    ).toBe(false)
  })

  it("inserts a not yet existing candidate at its sorted glob position", async () => {
    const ssh = stagingSsh(["/etc/ssh/sshd_config.d/a.conf", "/etc/ssh/sshd_config.d/c.conf"])
    const root = await stageSshdConfigTree(ssh, {
      content: `Include ${DROP_IN_GLOB}\nPort 22`,
      directory: STAGING,
      includeOverride: {
        content: "Match User ops\n    PermitTTY no\n",
        path: "/etc/ssh/sshd_config.d/b.conf",
      },
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(root).toBe(`${STAGING}/validation-3`)
    expect(ssh.writeFileCalls.map((call) => call.content)).toStrictEqual([
      "# /etc/ssh/sshd_config.d/a.conf\n",
      "Match User ops\n    PermitTTY no\n",
      "# /etc/ssh/sshd_config.d/c.conf\n",
      `Include ${STAGING}/validation-0 ${STAGING}/validation-1 ${STAGING}/validation-2\nPort 22`,
    ])
  })

  it("normalizes doubled-slash glob results before placing the candidate", async () => {
    const glob = "/etc/ssh//sshd_config.d/*.conf"
    const ssh = stagingSsh(
      ["/etc/ssh//sshd_config.d/a.conf", "/etc/ssh//sshd_config.d/c.conf"],
      glob
    )
    await stageSshdConfigTree(ssh, {
      content: `Include ${glob}`,
      directory: STAGING,
      includeOverride: { content: "candidate\n", path: B_CONF },
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(ssh.writeFileCalls.map((call) => call.content)).toStrictEqual([
      "# /etc/ssh//sshd_config.d/a.conf\n",
      "candidate\n",
      "# /etc/ssh//sshd_config.d/c.conf\n",
      `Include ${STAGING}/validation-0 ${STAGING}/validation-1 ${STAGING}/validation-2`,
    ])
  })

  it("replaces an existing doubled-slash candidate instead of staging it twice", async () => {
    const glob = "/etc/ssh//sshd_config.d/*.conf"
    const ssh = stagingSsh(["/etc/ssh//sshd_config.d/b.conf"], glob)
    await stageSshdConfigTree(ssh, {
      content: `Include ${glob}`,
      directory: STAGING,
      includeOverride: { content: null, path: B_CONF },
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(ssh.writeFileCalls.map((call) => call.content)).toStrictEqual(["# Empty Include"])
  })

  it("replaces an existing candidate without reading it and omits it for absent", async () => {
    const existing = [B_CONF, "/etc/ssh/sshd_config.d/c.conf"]
    const present = stagingSsh(existing)
    await stageSshdConfigTree(present, {
      content: `Include ${DROP_IN_GLOB}`,
      directory: STAGING,
      includeOverride: { content: "candidate\n", path: B_CONF },
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(present.calls).not.toContain(`cat '${B_CONF}'`)
    expect(present.writeFileCalls[0]?.content).toBe("candidate\n")

    const absent = stagingSsh(existing)
    await stageSshdConfigTree(absent, {
      content: `Include ${DROP_IN_GLOB}`,
      directory: STAGING,
      includeOverride: { content: null, path: B_CONF },
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(absent.writeFileCalls.map((call) => call.content)).toStrictEqual([
      "# /etc/ssh/sshd_config.d/c.conf\n",
      `Include ${STAGING}/validation-0`,
    ])
  })

  // The remote shell may print glob results in a locale collation (for
  // example `B.conf` after `a.conf`); sshd's glob(3) sorts in byte order.
  const LOCALE_ORDER = [
    "/etc/ssh/sshd_config.d/a.conf",
    "/etc/ssh/sshd_config.d/B.conf",
    "/etc/ssh/sshd_config.d/_z.conf",
  ]
  const BYTE_ORDER_CONTENTS = [
    "# /etc/ssh/sshd_config.d/B.conf\n",
    "# /etc/ssh/sshd_config.d/_z.conf\n",
    "# /etc/ssh/sshd_config.d/a.conf\n",
  ]

  it.each([
    ["without an override (host-certificate staging)", undefined],
    ["with a non-matching override", { content: "x\n", path: "/etc/ssh/other.conf" }],
    ["for an absent override", { content: null, path: B_CONF }],
  ])("sorts glob results in byte order %s", async (_label, includeOverride) => {
    const ssh = stagingSsh(LOCALE_ORDER)
    await stageSshdConfigTree(ssh, {
      content: `Include ${DROP_IN_GLOB}`,
      directory: STAGING,
      includeOverride,
      rootPath: "/etc/ssh/sshd_config",
    })
    expect(ssh.writeFileCalls.map((call) => call.content).slice(0, -1)).toStrictEqual(
      BYTE_ORDER_CONTENTS
    )
  })
})

function scannerSsh(includedContent: string) {
  return createMockSsh(
    {
      "[ -e '/etc/ssh/trusted_user_ca_keys' ] || [ -L '/etc/ssh/trusted_user_ca_keys' ]": {
        code: 1,
      },
      "[ -f '/etc/ssh/sshd_config.d/ops.conf' ] && [ -r '/etc/ssh/sshd_config.d/ops.conf' ]": {
        code: 0,
      },
      "cat '/etc/ssh/sshd_config.d/ops.conf'": { stdout: includedContent },
      [EXPAND]: { stdout: "/etc/ssh/sshd_config.d/ops.conf\n" },
      "readlink -f -- '/etc/ssh/sshd_config.d/ops.conf'": {
        stdout: "/etc/ssh/sshd_config.d/ops.conf\n",
      },
    },
    {}
  )
}

describe("certificate Include scanner Match scope", () => {
  it("ends a Match opened in an included file at that file's end", async () => {
    const scan = await scanCertificateSshdConfig(scannerSsh("Match User ops\n    PermitTTY no\n"), {
      content: `Include ${DROP_IN_GLOB}\nTrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n`,
      path: "/etc/ssh/sshd_config",
      rejectMatch: true,
    })
    expect(scan.match).toBe(false)
    expect(scan.files).toContain("/etc/ssh/sshd_config.d/ops.conf")
  })

  it("still rejects managed directives inside a Match in the included file", async () => {
    await expect(
      scanCertificateSshdConfig(
        scannerSsh("Match User ops\n    TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n"),
        { content: `Include ${DROP_IN_GLOB}\n`, path: "/etc/ssh/sshd_config", rejectMatch: true }
      )
    ).rejects.toThrow(/Match block/v)
  })
  it("treats an Include inside a Match block as inside Match", async () => {
    await expect(
      scanCertificateSshdConfig(scannerSsh("TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\n"), {
        content: `Match User ops\n    Include ${DROP_IN_GLOB}\n`,
        path: "/etc/ssh/sshd_config",
        rejectMatch: true,
      })
    ).rejects.toThrow(/Match block/v)
  })

  it("keeps directives after an Include top-level when the included file opens a Match", async () => {
    const scan = await scanCertificateSshdConfig(scannerSsh("Match User ops\n    PermitTTY no\n"), {
      content: `Include ${DROP_IN_GLOB}\nTrustedUserCAKeys /etc/ssh/trusted_user_ca_keys\nRevokedKeys none\n`,
      path: "/etc/ssh/sshd_config",
      rejectMatch: true,
    })
    expect(scan.match).toBe(false)
    expect(scan.caFiles).toContain("/etc/ssh/trusted_user_ca_keys")
  })
})
