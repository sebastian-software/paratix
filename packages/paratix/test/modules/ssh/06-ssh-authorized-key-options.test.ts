import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import {
  advancePastAuthorizedKeyOptions,
  authorizedKeyOptionEntries,
  parseAuthorizedKeyOptionEntries,
  serializeAuthorizedKeyOptions,
} from "../../../src/modules/sshAuthorizedKeyOptions.js"
import { authorizedKeysAccountCommand } from "../../../src/modules/sshAuthorizedKeysAccount.js"
import {
  type AuthorizedKeysTarget,
  authorizedKeysTargetLine,
  parseAuthorizedKeysLine,
  planAuthorizedKeysContent,
} from "../../../src/modules/sshAuthorizedKeysContent.js"
import { authorizedKeysReadCommand } from "../../../src/modules/sshAuthorizedKeysFile.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

function sshString(value: Buffer | string): Buffer {
  const valueBytes = typeof value === "string" ? Buffer.from(value) : value
  const lengthBuffer = Buffer.alloc(4)
  lengthBuffer.writeUInt32BE(valueBytes.length)
  return Buffer.concat([lengthBuffer, valueBytes])
}

function ed25519Blob(fill: number): string {
  return Buffer.concat([sshString("ssh-ed25519"), sshString(Buffer.alloc(32, fill))]).toString(
    "base64"
  )
}

const blob = ed25519Blob(1)
const key = `ssh-ed25519 ${blob} test-key`
const otherKey = `ssh-ed25519 ${ed25519Blob(2)} other-key`

function thrownMessage(action: () => unknown): string {
  try {
    action()
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
  return ""
}

function target(overrides: Partial<AuthorizedKeysTarget> = {}): AuthorizedKeysTarget {
  return {
    identity: { blob, keyType: "ssh-ed25519" },
    line: key,
    optionsProvided: false,
    state: "present",
    ...overrides,
  }
}

describe("serializeAuthorizedKeyOptions", () => {
  it("emits restrict first, then options alphabetically by OpenSSH name", () => {
    expect(
      serializeAuthorizedKeyOptions({
        command: "/usr/local/bin/ops-ro-shell",
        environment: { LANG: "C" },
        expiryTime: "20261231",
        from: ["10.0.0.0/8", "!10.0.0.5"],
        noAgentForwarding: true,
        permitListen: ["8080"],
        permitOpen: ["localhost:80"],
        portForwarding: true,
        pty: true,
        restrict: true,
        userRc: true,
        x11Forwarding: true,
      })
    ).toBe(
      'restrict,command="/usr/local/bin/ops-ro-shell",environment="LANG=C",expiry-time="20261231",from="10.0.0.0/8,!10.0.0.5",no-agent-forwarding,permitlisten="8080",permitopen="localhost:80",port-forwarding,pty,user-rc,X11-forwarding'
    )
  })

  it("maps every negative flag and treats false like an omitted flag", () => {
    expect(
      serializeAuthorizedKeyOptions({
        agentForwarding: false,
        noAgentForwarding: true,
        noPortForwarding: true,
        noPty: true,
        noUserRc: true,
        noX11Forwarding: true,
        restrict: false,
      })
    ).toBe("no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding")
  })

  it("repeats permitopen, permitlisten and environment in input order", () => {
    expect(
      serializeAuthorizedKeyOptions({
        // eslint-disable-next-line perfectionist/sort-objects -- insertion order is under test
        environment: { B_VAR: "2", A_VAR: "1" },
        permitOpen: ["b:2", "a:1"],
      })
    ).toBe('environment="B_VAR=2",environment="A_VAR=1",permitopen="b:2",permitopen="a:1"')
  })

  it("returns an empty block for an empty options object", () => {
    expect(serializeAuthorizedKeyOptions({})).toBe("")
  })

  it("escapes only double quotes and keeps backslashes", () => {
    expect(serializeAuthorizedKeyOptions({ command: 'printf "%s" a\\b' })).toBe(
      'command="printf \\"%s\\" a\\b"'
    )
  })

  it.each([
    ["double quotes", 'echo "quoted" text'],
    ["an inner backslash", "C:\\path\\to"],
    ["spaces", "/usr/bin/env  two  spaces"],
    ["a backslash before a quote", 'a\\"b'],
  ])("round-trips command values with %s", (_label, command) => {
    const block = serializeAuthorizedKeyOptions({ command, environment: { NOTE: command } })
    expect(parseAuthorizedKeyOptionEntries(block)).toStrictEqual(
      authorizedKeyOptionEntries({ command, environment: { NOTE: command } })
    )
    expect(parseAuthorizedKeyOptionEntries(block)?.[0]).toStrictEqual({
      name: "command",
      value: command,
    })
  })
})

describe("authorizedKeyOptionEntries validation", () => {
  it.each(["certAuthority", "principals", "tunnel", "noTouchRequired", "verifyRequired", "foo"])(
    "rejects the unsupported option field %s",
    (field) => {
      expect(() => authorizedKeyOptionEntries({ [field]: true })).toThrow("unsupported option")
    }
  )

  it.each([
    [{ restrict: "yes" }, "restrict must be a boolean"],
    [{ command: 1 }, "command must be a non-empty string"],
    [{ command: "" }, "command must be a non-empty string"],
    [{ from: "10.0.0.1" }, "from must be a non-empty array"],
    [{ from: [] }, "from must be a non-empty array"],
    [{ from: [""] }, "from[0] must be a non-empty string"],
    [{ permitOpen: ["a:1,b:2"] }, "permitOpen[0] must not contain commas or whitespace"],
    [{ permitListen: ["80 81"] }, "permitListen[0] must not contain commas or whitespace"],
    [{ environment: ["A=1"] }, "environment must be a plain object"],
    [{ environment: { "1A": "x" } }, "must match"],
    [{ environment: { "A-B": "x" } }, "must match"],
    [{ environment: { A: 1 } }, "environment.A must be a string"],
    [{ expiryTime: Number("20261231") }, "expiryTime must be a valid time"],
    [{ noPty: true, pty: true }, "pty and noPty contradict each other"],
    [{ agentForwarding: true, noAgentForwarding: true }, "contradict"],
    [{ noPortForwarding: true, portForwarding: true }, "contradict"],
    [{ noUserRc: true, userRc: true }, "contradict"],
    [{ noX11Forwarding: true, x11Forwarding: true }, "contradict"],
  ])("rejects %j", (options, message) => {
    expect(() => authorizedKeyOptionEntries(options)).toThrow(message)
  })

  it.each([null, [], "restrict"])("rejects non-object options %j", (options) => {
    expect(() => authorizedKeyOptionEntries(options)).toThrow("must be a plain object")
  })

  it.each([
    ["a newline", "line\nbreak"],
    ["a carriage return", "line\rbreak"],
    ["NUL", "nul\u0000byte"],
    ["a tab", "tab\there"],
    ["DEL", "del\u007Fchar"],
    ["a C1 control", "c1\u0085char"],
  ])("rejects %s without echoing secret values", (_label, value) => {
    for (const options of [{ command: value }, { environment: { TOKEN: value } }]) {
      const message = thrownMessage(() => authorizedKeyOptionEntries(options))
      expect(message).toContain("must not contain newlines, NUL or other control characters")
      expect(message).not.toContain(value)
    }
  })

  it.each([{ command: "run\\" }, { environment: { A: "x\\" } }, { from: ["a\\"] }])(
    "rejects values ending in a backslash: %j",
    (options) => {
      expect(() => authorizedKeyOptionEntries(options)).toThrow("must not end with a backslash")
    }
  )

  it.each(["20261231", "202612312359", "20261231235959", "20261231Z", "20240229"])(
    "accepts the expiry time %s",
    (expiryTime) => {
      expect(authorizedKeyOptionEntries({ expiryTime })).toStrictEqual([
        { name: "expiry-time", value: expiryTime },
      ])
    }
  )

  it.each([
    "2026123",
    "2026123100",
    "20261301",
    "20260230",
    "20250229",
    "202612312460",
    "20261231235960",
    "20261231z",
    "2026-12-31",
  ])("rejects the expiry time %s", (expiryTime) => {
    expect(() => authorizedKeyOptionEntries({ expiryTime })).toThrow(
      "expiryTime must be a valid time"
    )
  })

  it("ignores fields whose value is undefined", () => {
    expect(authorizedKeyOptionEntries({ command: undefined, restrict: true })).toStrictEqual([
      { name: "restrict" },
    ])
  })
})

describe("authorized_keys option block parsing", () => {
  it("ends the option block at the first blank outside quotes", () => {
    const block = 'command="echo \\"a b\\" c",from="x"'
    expect(advancePastAuthorizedKeyOptions(`${block} ${key}`)).toBe(block.length)
  })

  it("reports an unterminated quote", () => {
    expect(advancePastAuthorizedKeyOptions('command="open ended')).toBeNull()
  })

  it.each(["", ",restrict", "restrict,", "restrict,,pty", "command=unquoted", 'command="x"y'])(
    "rejects the malformed option block %j",
    (block) => {
      expect(parseAuthorizedKeyOptionEntries(block)).toBeNull()
    }
  )
})

describe("parseAuthorizedKeysLine", () => {
  it.each(["", "   ", "# comment", `  # ${key}`])("ignores blank and comment line %j", (line) => {
    expect(parseAuthorizedKeysLine(line)).toStrictEqual({ kind: "ignored" })
  })

  it("parses a key line without options", () => {
    expect(parseAuthorizedKeysLine(`  ${key}`)).toStrictEqual({
      identity: { blob, keyType: "ssh-ed25519" },
      kind: "key",
      optionBlock: "",
    })
  })

  it("parses quoted options with spaces and escaped quotes", () => {
    expect(parseAuthorizedKeysLine(`command="echo \\"hi there\\"",no-pty\t${key}`)).toStrictEqual({
      identity: { blob, keyType: "ssh-ed25519" },
      kind: "key",
      optionBlock: 'command="echo \\"hi there\\"",no-pty',
    })
  })

  it.each([`ssh-ed25519 not-base64! c`, `command="x ${blob}`, `restrict ${blob}`, "garbage"])(
    "classifies %j as unparseable",
    (line) => {
      expect(parseAuthorizedKeysLine(line)).toStrictEqual({ kind: "unparseable" })
    }
  )
})

describe("planAuthorizedKeysContent", () => {
  it("appends the target line to a missing or unrelated file", () => {
    expect(planAuthorizedKeysContent(null, target())).toStrictEqual({
      content: `${key}\n`,
      kind: "rewrite",
    })
    expect(planAuthorizedKeysContent(`# keep\n${otherKey}`, target())).toStrictEqual({
      content: `# keep\n${otherKey}\n${key}\n`,
      kind: "rewrite",
    })
  })

  it("reports converged only for exactly one byte-identical line", () => {
    expect(planAuthorizedKeysContent(`${otherKey}\n${key}\n`, target())).toStrictEqual({
      kind: "converged",
    })
    expect(planAuthorizedKeysContent(`${key}\n${key}\n`, target())).toStrictEqual({
      content: `${key}\n`,
      kind: "rewrite",
    })
  })

  it("replaces the first line of the blob in place and removes later duplicates", () => {
    const restricted = `restrict ssh-ed25519 ${blob} old-comment`
    const content = `${otherKey}\nssh-ed25519 ${blob} old-comment\n# note\n${restricted}\n`
    const line = authorizedKeysTargetLine(key, serializeAuthorizedKeyOptions({ restrict: true }))
    expect(
      planAuthorizedKeysContent(content, target({ line, optionsProvided: true }))
    ).toStrictEqual({
      content: `${otherKey}\nrestrict ${key}\n# note\n`,
      kind: "rewrite",
    })
  })

  it("fails instead of dropping existing options when options are omitted", () => {
    const content = `${key}\ncommand="/bin/secret-token",from="10.0.0.1" ssh-ed25519 ${blob} c\n`
    expect(planAuthorizedKeysContent(content, target())).toStrictEqual({
      kind: "options-guard",
      optionNames: ["command", "from"],
    })
  })

  it("removes existing options when options are explicitly empty", () => {
    const content = `restrict,command="x" ssh-ed25519 ${blob} test-key\n`
    expect(planAuthorizedKeysContent(content, target({ optionsProvided: true }))).toStrictEqual({
      content: `${key}\n`,
      kind: "rewrite",
    })
  })

  it("blocks both states on an unparseable line that contains the blob as a token", () => {
    const content = `${otherKey}\ncommand="unterminated ssh-ed25519 ${blob}\n`
    expect(planAuthorizedKeysContent(content, target())).toStrictEqual({
      kind: "conflict",
      lineNumber: 2,
    })
    expect(planAuthorizedKeysContent(content, target({ state: "absent" }))).toStrictEqual({
      kind: "conflict",
      lineNumber: 2,
    })
  })

  it("blocks both states on the same blob under another key type", () => {
    const content = `${otherKey}\nssh-rsa ${blob} same-blob\n`
    for (const state of ["present", "absent"] as const) {
      expect(planAuthorizedKeysContent(content, target({ state }))).toStrictEqual({
        kind: "conflict",
        lineNumber: 2,
      })
    }
  })

  it("does not report parsed lines of other keys that mention the blob as a conflict", () => {
    const mentionsInComment = `ssh-ed25519 ${ed25519Blob(4)} rotated-from ${blob}`
    const mentionsInOptions = `command="echo ${blob}" ssh-ed25519 ${ed25519Blob(5)} c`
    const content = `${mentionsInComment}\n${mentionsInOptions}\n`
    expect(planAuthorizedKeysContent(content, target())).toStrictEqual({
      content: `${content}${key}\n`,
      kind: "rewrite",
    })
    expect(planAuthorizedKeysContent(content, target({ state: "absent" }))).toStrictEqual({
      kind: "converged",
    })
  })

  it("classifies a CRLF key line without comment as the managed key and drops its CR", () => {
    expect(parseAuthorizedKeysLine(`ssh-ed25519 ${blob}\r`)).toStrictEqual({
      identity: { blob, keyType: "ssh-ed25519" },
      kind: "key",
      optionBlock: "",
    })
    const content = `${otherKey}\r\nssh-ed25519 ${blob}\r\n# note\r\n`
    expect(planAuthorizedKeysContent(content, target())).toStrictEqual({
      content: `${otherKey}\r\n${key}\n# note\r\n`,
      kind: "rewrite",
    })
    expect(planAuthorizedKeysContent(content, target({ state: "absent" }))).toStrictEqual({
      content: `${otherKey}\r\n# note\r\n`,
      kind: "rewrite",
    })
  })

  it.each(["cert-authority", "Cert-Authority", 'cert-authority,principals="ops"'])(
    "keeps a %s line of the same blob unchanged in both states",
    (optionBlock) => {
      const authority = `${optionBlock} ssh-ed25519 ${blob} user-ca`
      expect(planAuthorizedKeysContent(`${authority}\n`, target())).toStrictEqual({
        content: `${authority}\n${key}\n`,
        kind: "rewrite",
      })
      expect(planAuthorizedKeysContent(`${authority}\n${key}\n`, target())).toStrictEqual({
        kind: "converged",
      })
      expect(
        planAuthorizedKeysContent(`${key}\n${authority}\n`, target({ state: "absent" }))
      ).toStrictEqual({ content: `${authority}\n`, kind: "rewrite" })
      expect(
        planAuthorizedKeysContent(`${authority}\n`, target({ state: "absent" }))
      ).toStrictEqual({ kind: "converged" })
    }
  )

  it("keeps unparseable lines that do not reference the blob byte-identical", () => {
    const foreign = "not a key line \u00FF\u00FE"
    expect(planAuthorizedKeysContent(`${foreign}\n`, target())).toStrictEqual({
      content: `${foreign}\n${key}\n`,
      kind: "rewrite",
    })
  })

  it("removes every line of the blob for absent regardless of options and comment", () => {
    const content = `${key}\n${otherKey}\nrestrict ssh-ed25519 ${blob} x\nssh-ed25519 ${blob}`
    expect(planAuthorizedKeysContent(content, target({ state: "absent" }))).toStrictEqual({
      content: `${otherKey}\n`,
      kind: "rewrite",
    })
    expect(planAuthorizedKeysContent(`${otherKey}\n`, target({ state: "absent" }))).toStrictEqual({
      kind: "converged",
    })
  })

  it("encodes non-ASCII target lines as UTF-8 bytes", () => {
    expect(authorizedKeysTargetLine("ssh-ed25519 AAAA j\u00FCrgen", "")).toBe(
      Buffer.from("ssh-ed25519 AAAA j\u00FCrgen", "utf8").toString("latin1")
    )
  })
})

describe("ssh.authorizedKeys options guard", () => {
  const keysPath = "/home/alice/.ssh/authorized_keys"
  const existing = `restrict,environment="TOKEN=secret-value" ssh-ed25519 ${blob} test-key\n`
  const existingReadOutput = Buffer.from(`${existing}\n0`, "latin1").toString("base64")

  function guardMock() {
    return createMockSsh({
      "[ -e '/home/alice/.ssh' ]": { code: 0 },
      "[ -L '/home/alice/.ssh' ]": { code: 1 },
      [`[ -e '${keysPath}' ]`]: { code: 0 },
      [`[ -L '${keysPath}' ]`]: { code: 1 },
      [`stat -c '%a %U %G %F' '${keysPath}'`]: { stdout: "600 alice alice regular file" },
      [authorizedKeysAccountCommand({ home: "/home/alice", user: "alice" })]: {
        stdout: "setpriv 1000 1000\n/home/alice\n/usr/bin/setpriv\n",
      },
      [authorizedKeysReadCommand({
        dropPrefix: "'/usr/bin/setpriv' --reuid=1000 --regid=1000 --init-groups -- ",
        expectedSshDirectory: "/home/alice/.ssh",
        gid: "1000",
        uid: "1000",
        user: "alice",
      })]: {
        stdout: `present\n${existingReadOutput}`,
      },
      "getent passwd 'alice' | cut -d: -f6": { stdout: "/home/alice" },
      "id -gn 'alice'": { stdout: "alice" },
      "stat -c '%a %U %G %F' '/home/alice/.ssh'": { stdout: "700 alice alice directory" },
    })
  }

  it("rejects invalid options at construction time", () => {
    expect(() =>
      ssh.authorizedKeys("alice", key, { options: { certAuthority: true } as never })
    ).toThrow("unsupported option")
  })

  it("reports needs-apply in check and failed in dry-run without leaking option values", async () => {
    const mod = ssh.authorizedKeys("alice", key)
    const mockSsh = guardMock()

    await expect(mod.check(mockSsh, {})).resolves.toBe("needs-apply")
    const result = await mod._applyDryRun?.(mockSsh, {})

    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("(environment, restrict)")
    expect(result?.error?.message).not.toContain("secret-value")
    expect(mockSsh.writeFileCalls).toStrictEqual([])
  })

  it("reports converged dry-runs and checks as ok for a matching options line", async () => {
    const mod = ssh.authorizedKeys("alice", key, {
      options: { environment: { TOKEN: "secret-value" }, restrict: true },
    })
    const mockSsh = guardMock()

    await expect(mod.check(mockSsh, {})).resolves.toBe("ok")
    await expect(mod._applyDryRun?.(mockSsh, {})).resolves.toStrictEqual({ status: "ok" })
  })

  it("reports changed in dry-run when the options differ", async () => {
    const mod = ssh.authorizedKeys("alice", key, { options: {} })
    const mockSsh = guardMock()

    await expect(mod.check(mockSsh, {})).resolves.toBe("needs-apply")
    await expect(mod._applyDryRun?.(mockSsh, {})).resolves.toStrictEqual({ status: "changed" })
  })
})
