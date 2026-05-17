import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  promptForAdminPublicKey,
  promptForHost,
  promptForHostFingerprint,
  promptForInitialUserConfig,
  resolveCliOrPromptHost,
} from "../src/index.js"
import { cleanupSelectInput, createSelectLines } from "../src/promptUi.js"
import { expectProcessExit, setProcessTtyForTest } from "./helpers.js"

describe("promptForInitialUserConfig", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("supports the interactive root flow", async () => {
    const prompt = vi.fn()
    const select = vi.fn().mockResolvedValueOnce("root")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "root",
    })
    expect(prompt).not.toHaveBeenCalled()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenCalledWith(
      "Which SSH user already works for the first connection to this server?",
      [
        {
          description:
            "Fresh server with SSH access only as root. Paratix bootstraps a dedicated admin user first.",
          label: "Root user",
          value: "root",
        },
        {
          description:
            "A named admin user already exists. Paratix connects directly as that user and skips root bootstrap.",
          label: "Admin user",
          value: "admin",
        },
      ]
    )
  })

  it("supports the interactive admin flow with a concrete username", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("deploy")
    const select = vi.fn().mockResolvedValueOnce("admin")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "admin",
      user: "deploy",
    })
    expect(select).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenNthCalledWith(1, "Admin username: ")
  })

  it("closes prompt and select sessions when an error propagates from the admin prompt", async () => {
    const closePrompt = vi.fn()
    const closeSelect = vi.fn()
    const ask = vi.fn().mockRejectedValueOnce(new Error("stdin closed"))
    const chooseInitialUser = vi.fn().mockResolvedValueOnce("admin")
    const createSession = vi.fn(() => ({
      ask,
      chooseInitialUser,
      closePrompt,
      closeSelect,
    }))

    await expect(promptForInitialUserConfig(undefined, undefined, createSession)).rejects.toThrow(
      "stdin closed"
    )

    expect(chooseInitialUser).toHaveBeenCalledTimes(1)
    expect(ask).toHaveBeenCalledWith("Admin username: ")
    expect(closeSelect).toHaveBeenCalledTimes(1)
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })

  it("closes prompt and select sessions when the chooser itself throws", async () => {
    const closePrompt = vi.fn()
    const closeSelect = vi.fn()
    const ask = vi.fn()
    const chooseInitialUser = vi.fn().mockRejectedValueOnce(new Error("chooser cancelled"))
    const createSession = vi.fn(() => ({
      ask,
      chooseInitialUser,
      closePrompt,
      closeSelect,
    }))

    await expect(promptForInitialUserConfig(undefined, undefined, createSession)).rejects.toThrow(
      "chooser cancelled"
    )

    expect(ask).not.toHaveBeenCalled()
    expect(closeSelect).toHaveBeenCalledTimes(1)
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })

  // R-0000229: the admin-username prompt aborts deterministically when stdin
  // closes (returns "" repeatedly) instead of looping forever.
  it("aborts with a CliExitError when the admin prompt sees EOF", async () => {
    const prompt = vi.fn().mockResolvedValue("")
    const select = vi.fn().mockResolvedValueOnce("admin")

    await expect(promptForInitialUserConfig(prompt, select)).rejects.toMatchObject({
      cliMessage: expect.stringContaining("stdin is closed or empty"),
      name: "CliExitError",
    })
    expect(prompt).toHaveBeenCalledTimes(1)
  })

  // R-0000229: bound the admin-username retry loop so persistent invalid
  // values surface as a CliExitError instead of an endless console.error spam.
  it("aborts after too many invalid admin username entries", async () => {
    const prompt = vi.fn().mockResolvedValue("ROOT")
    const select = vi.fn().mockResolvedValueOnce("admin")

    await expect(promptForInitialUserConfig(prompt, select)).rejects.toMatchObject({
      cliMessage: expect.stringContaining("Too many invalid admin username entries"),
      name: "CliExitError",
    })
    expect(prompt.mock.calls.length).toBeGreaterThanOrEqual(3)
  })
})

describe("promptForHost", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("accepts a valid interactive host", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("example.com")

    await expect(promptForHost(prompt)).resolves.toBe("example.com")
    expect(prompt).toHaveBeenCalledWith("Server host (domain or IP): ")
  })

  it("closes the host prompt session after a successful prompt run", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("example.com")
    const closePrompt = vi.fn()

    await expect(promptForHost(prompt, () => void closePrompt())).resolves.toBe("example.com")
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })

  it("retries until a valid host is entered", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("bad host").mockResolvedValueOnce("203.0.113.10")

    await expect(promptForHost(prompt)).resolves.toBe("203.0.113.10")
    expect(console.error).toHaveBeenCalledWith(
      "Error: Please enter a domain name, IPv4, or IPv6 address without spaces."
    )
  })

  it("also closes the host prompt session after retries", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("bad host").mockResolvedValueOnce("203.0.113.10")
    const closePrompt = vi.fn()

    await expect(promptForHost(prompt, () => void closePrompt())).resolves.toBe("203.0.113.10")
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })

  // R-0000229: a prompt that always returns the empty string (closed stdin /
  // EOF / piped from /dev/null) must not loop forever. We expect a fast
  // CliExitError-style abort with an EOF-specific message.
  it("aborts with a CliExitError when stdin returns empty (EOF)", async () => {
    const prompt = vi.fn().mockResolvedValue("")

    await expect(promptForHost(prompt)).rejects.toMatchObject({
      cliMessage: expect.stringContaining("stdin is closed or empty"),
      name: "CliExitError",
    })
    expect(prompt).toHaveBeenCalledTimes(1)
  })

  // R-0000229: a prompt that keeps returning invalid (but non-empty) values
  // must give up after a bounded number of attempts instead of looping forever.
  it("aborts with a CliExitError after too many invalid host entries", async () => {
    const prompt = vi.fn().mockResolvedValue("bad host")

    await expect(promptForHost(prompt)).rejects.toMatchObject({
      cliMessage: expect.stringContaining("Too many invalid host entries"),
      name: "CliExitError",
    })
    expect(prompt.mock.calls.length).toBeGreaterThanOrEqual(3)
  })
})

describe("resolveCliOrPromptHost", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("uses the provided --host without prompting", async () => {
    const prompt = vi.fn().mockResolvedValue("prompted.example.com")

    await expect(resolveCliOrPromptHost("example.com", prompt)).resolves.toBe("example.com")
    expect(prompt).not.toHaveBeenCalled()
  })

  it("fails fast without --host in non-interactive environments", async () => {
    const prompt = vi.fn().mockResolvedValue("prompted.example.com")
    const restoreTty = setProcessTtyForTest(false, false)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    try {
      await expectProcessExit(async () => {
        await resolveCliOrPromptHost(undefined, prompt)
      })

      expect(console.error).toHaveBeenCalledWith(
        "Missing --host in non-interactive environment. Pass --host <domain-or-ip>."
      )
      expect(prompt).not.toHaveBeenCalled()
    } finally {
      restoreTty()
    }
  })
})

describe("promptForAdminPublicKey", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("keeps the placeholder when the user declines local key reuse", async () => {
    const select = vi.fn().mockResolvedValueOnce("placeholder")

    await expect(promptForAdminPublicKey(select)).resolves.toBeUndefined()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenNthCalledWith(
      1,
      "How should create-paratix configure the admin SSH public key?",
      [
        {
          description:
            "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
          label: "Use local public key",
          value: "local",
        },
        {
          description:
            "Keep the placeholder in server.ts and paste your public key manually before the first apply.",
          label: "Keep placeholder",
          value: "placeholder",
        },
      ]
    )
  })

  it("does not offer the placeholder for root bootstrap admin key selection", async () => {
    const select = vi
      .fn()
      .mockResolvedValueOnce("local")
      .mockResolvedValueOnce("/tmp/id_ed25519.pub")

    await expect(
      promptForAdminPublicKey(
        select,
        [
          {
            key: "ssh-ed25519 AAAA example-ed25519",
            label: "id_ed25519.pub",
            path: "/tmp/id_ed25519.pub",
          },
        ],
        { allowPlaceholder: false }
      )
    ).resolves.toBe("ssh-ed25519 AAAA example-ed25519")
    expect(select).toHaveBeenNthCalledWith(
      1,
      "How should create-paratix configure the admin SSH public key?",
      [
        {
          description:
            "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
          label: "Use local public key",
          value: "local",
        },
      ]
    )
  })

  it("selects from multiple local public keys via the cursor flow", async () => {
    const select = vi
      .fn()
      .mockResolvedValueOnce("local")
      .mockResolvedValueOnce("/tmp/id_ed25519.pub")

    await expect(
      promptForAdminPublicKey(select, [
        {
          key: "ssh-rsa AAAA example-rsa",
          label: "id_rsa.pub",
          path: "/tmp/id_rsa.pub",
        },
        {
          key: "ssh-ed25519 AAAA example-ed25519",
          label: "id_ed25519.pub",
          path: "/tmp/id_ed25519.pub",
        },
      ])
    ).resolves.toBe("ssh-ed25519 AAAA example-ed25519")
    expect(select).toHaveBeenCalledTimes(2)
  })

  it("falls back to the placeholder when no readable local public keys exist", async () => {
    const select = vi.fn().mockResolvedValueOnce("local")

    await expect(promptForAdminPublicKey(select, [])).resolves.toBeUndefined()
    expect(console.error).toHaveBeenCalledWith(
      "No readable public keys were found in ~/.ssh. Keeping the placeholder in server.ts."
    )
  })

  it("throws a CliExitError for root bootstrap when no local keys exist", async () => {
    // R-0000497: root-bootstrap with no local keys must surface an actionable
    // CliExitError pointing to --admin-public-key / --admin-public-key-file
    // instead of silently returning undefined and letting a generic stack
    // trace propagate later.
    const select = vi.fn().mockResolvedValueOnce("local")

    await expect(promptForAdminPublicKey(select, [], { allowPlaceholder: false })).rejects.toThrow(
      /Root bootstrap requires an admin SSH public key/v
    )
  })
})

describe("createSelectLines", () => {
  it("escapes unsafe terminal characters in prompt and option text", () => {
    const escapeByte = String.fromCharCode(0x1b)
    const bidiOverride = String.fromCodePoint(0x20_2e)
    const rendered = createSelectLines(
      `Select${escapeByte} public key:`,
      [
        {
          description: `/tmp/${bidiOverride}id_ed25519.pub`,
          label: `id${escapeByte}_ed25519.pub`,
          value: `/tmp/${escapeByte}${bidiOverride}id_ed25519.pub`,
        },
      ],
      0
    ).join("\n")

    expect(rendered).toContain("Select\\u{001B} public key:")
    expect(rendered).toContain("> id\\u{001B}_ed25519.pub")
    expect(rendered).toContain("/tmp/\\u{202E}id_ed25519.pub")
    expect(rendered).not.toContain(escapeByte)
    expect(rendered).not.toContain(bidiOverride)
  })
})

describe("promptForHostFingerprint", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    vi.spyOn(console, "log").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("keeps the placeholder when the user declines host-key scanning", async () => {
    const select = vi.fn().mockResolvedValueOnce("placeholder")
    const scanner = vi.fn()

    await expect(promptForHostFingerprint("example.com", select, scanner)).resolves.toBeUndefined()
    expect(scanner).not.toHaveBeenCalled()
    expect(select).toHaveBeenCalledWith(
      "How should create-paratix bootstrap the SSH host key for example.com?",
      [
        {
          description:
            "Read the currently presented host key from SSH port 22 via ssh2 and pin its fingerprint in server.ts.",
          label: "Scan host key",
          value: "scan",
        },
        {
          description:
            "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified expectedHostFingerprint/PublicKey is added.",
          label: "Skip pinning",
          value: "placeholder",
        },
      ]
    )
  })

  // R-0000122: a single "scan" choice must NOT pin the fingerprint silently.
  // Operators have to confirm out-of-band before the value reaches server.ts.
  it("pins the scanned host fingerprint only after explicit confirmation", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("pin")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await expect(promptForHostFingerprint("example.com", select, scanner)).resolves.toBe(
      "SHA256:scanned-fingerprint"
    )
    expect(scanner).toHaveBeenCalledWith("example.com")
    expect(select).toHaveBeenCalledTimes(2)
    expect(select).toHaveBeenNthCalledWith(2, "Pin the scanned host fingerprint for example.com?", [
      {
        description: expect.stringContaining("fail closed"),
        label: "Discard and skip",
        value: "discard",
      },
      {
        description: expect.stringContaining("Pin the scanned fingerprint"),
        label: "Pin this fingerprint",
        value: "pin",
      },
    ])
  })

  // R-0000202: after a scan has happened, discarding it must keep scaffolding
  // fail-closed instead of silently trusting the presented key.
  it("rejects when the operator discards the scanned fingerprint", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("discard")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /scanned host fingerprint for example.com was not pinned/v
    )
    expect(scanner).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenCalledTimes(2)
  })

  // R-0000122: the scanned material must be displayed in an isolated,
  // multi-line block so an operator can copy it cleanly for an out-of-band
  // comparison. The algorithm has to appear next to the fingerprint.
  it("renders algorithm and fingerprint on isolated lines before asking to pin", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("pin")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await promptForHostFingerprint("example.com", select, scanner)

    expect(console.log).toHaveBeenCalledTimes(1)
    const message = vi.mocked(console.log).mock.calls[0]?.[0]
    expect(message).toContain("Scanned SSH host key for example.com:22")
    expect(message).toContain("algorithm:")
    expect(message).toContain("ssh-ed25519")
    expect(message).toContain("fingerprint:")
    expect(message).toContain("SHA256:scanned-fingerprint")
    expect(message).toContain("out-of-band")
  })

  // R-0000231: chooseFrom must reject a chooser result that is not part of
  // the offered options instead of casting it through. We exercise the path
  // by mocking the host-fingerprint chooser to return a stray "scan" value
  // for the confirm step (whose options are only "discard" / "pin").
  it("rejects a chooser result that is not one of the offered options", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("not-a-real-option")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /Internal error: select returned an unexpected option/v
    )
    expect(select).toHaveBeenCalledTimes(2)
  })

  // R-0000202: a scan failure must surface as an explicit MITM-style warning
  // and abort instead of silently trusting the presented key.
  it("emits a MITM warning and rejects after a scan failure", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error("network timeout"))

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /host-key scan for example.com failed \(network timeout\)/v
    )

    const errorMock = console.error as unknown as { mock: { calls: unknown[][] } }
    const warningCalls = errorMock.mock.calls.map((call) => String(call[0])).join("\n")
    expect(warningCalls).toContain("Warning: failed to scan SSH host key for example.com.")
    expect(warningCalls).toContain("network timeout")
    expect(warningCalls).toContain("man-in-the-middle")
    expect(warningCalls).toContain("Verify the host key out of band")

    expect(select).toHaveBeenCalledTimes(1)
  })

  it("escapes control bytes in host-key scan warnings", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    const host = `example${escapeByte}.com`
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error(`network${escapeByte}timeout`))

    await expect(promptForHostFingerprint(host, select, scanner)).rejects.toThrow(
      /host-key scan for example\\u\{001B\}\.com failed \(network\\u\{001B\}timeout\)/v
    )

    const warningCalls = vi
      .mocked(console.error)
      .mock.calls.map((call) => String(call[0]))
      .join("\n")
    expect(warningCalls).toContain("Warning: failed to scan SSH host key for example\\u{001B}.com.")
    expect(warningCalls).toContain("network\\u{001B}timeout")
    expect(warningCalls).not.toContain(escapeByte)
    expect(select).toHaveBeenCalledTimes(1)
  })

  it("rejects with an actionable error after a scan failure", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error("connect ETIMEDOUT"))

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /Aborting scaffolding: host-key scan for example.com failed \(connect ETIMEDOUT\)/v
    )
    expect(select).toHaveBeenCalledTimes(1)
  })
})

// R-0000664: prompts that drive createTerminalSelect()/setRawMode must
// fail fast with CliExitError when invoked outside a TTY. Otherwise a CI
// runner (no stdin TTY) crashes inside setRawMode and leaves the
// terminal in an unknown state. The check runs only when the caller
// uses the default select; tests and other consumers that inject their
// own select keep working unchanged.
describe("R-0000664: TTY gate on default-select prompts", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("promptForAdminPublicKey rejects without a stdin TTY", async () => {
    const restoreTty = setProcessTtyForTest(false, true)
    try {
      await expect(promptForAdminPublicKey()).rejects.toThrow(/Interactive prompt requires a TTY/v)
    } finally {
      restoreTty()
    }
  })

  it("promptForAdminPublicKey rejects without a stdout TTY", async () => {
    const restoreTty = setProcessTtyForTest(true, false)
    try {
      await expect(promptForAdminPublicKey()).rejects.toThrow(/Interactive prompt requires a TTY/v)
    } finally {
      restoreTty()
    }
  })

  it("promptForHostFingerprint rejects without a TTY", async () => {
    const restoreTty = setProcessTtyForTest(false, false)
    try {
      await expect(promptForHostFingerprint("example.com")).rejects.toThrow(
        /Interactive prompt requires a TTY/v
      )
    } finally {
      restoreTty()
    }
  })

  it("promptForAdminPublicKey skips the TTY gate when a select is injected", async () => {
    const restoreTty = setProcessTtyForTest(false, false)
    const select = vi.fn().mockResolvedValueOnce("placeholder")
    try {
      await expect(promptForAdminPublicKey(select)).resolves.toBeUndefined()
      expect(select).toHaveBeenCalledTimes(1)
    } finally {
      restoreTty()
    }
  })

  it("promptForHostFingerprint skips the TTY gate when a select is injected", async () => {
    const restoreTty = setProcessTtyForTest(false, false)
    const select = vi.fn().mockResolvedValueOnce("placeholder")
    const scanner = vi.fn()
    try {
      await expect(
        promptForHostFingerprint("example.com", select, scanner)
      ).resolves.toBeUndefined()
      expect(scanner).not.toHaveBeenCalled()
    } finally {
      restoreTty()
    }
  })
})

// R-0000190: cleanupSelectInput must not call setRawMode on non-TTY stdin
// (test harness, piped input). The original implementation defaulted
// previousRawMode to `false`, which would either throw or silently mutate
// the parent shell state.
describe("cleanupSelectInput", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("skips setRawMode when previousRawMode is undefined", () => {
    const stdin = process.stdin as {
      setRawMode?: (mode: boolean) => NodeJS.ReadStream
    } & NodeJS.ReadStream
    const setRawModeCalls: boolean[] = []
    const previousSetRawMode = stdin.setRawMode
    stdin.setRawMode = (mode: boolean): NodeJS.ReadStream => {
      setRawModeCalls.push(mode)
      return stdin
    }
    const pauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    try {
      cleanupSelectInput(undefined)
      expect(setRawModeCalls).toStrictEqual([])
      expect(pauseSpy).toHaveBeenCalled()
      expect(writeSpy).toHaveBeenCalledWith("\x1B[?25h")
    } finally {
      stdin.setRawMode = previousSetRawMode
      pauseSpy.mockRestore()
      writeSpy.mockRestore()
    }
  })

  it("restores previousRawMode when it is a boolean", () => {
    const stdin = process.stdin as {
      setRawMode?: (mode: boolean) => NodeJS.ReadStream
    } & NodeJS.ReadStream
    const setRawModeCalls: boolean[] = []
    const previousSetRawMode = stdin.setRawMode
    stdin.setRawMode = (mode: boolean): NodeJS.ReadStream => {
      setRawModeCalls.push(mode)
      return stdin
    }
    const pauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    try {
      cleanupSelectInput(true)
      expect(setRawModeCalls).toStrictEqual([true])
    } finally {
      stdin.setRawMode = previousSetRawMode
      pauseSpy.mockRestore()
      writeSpy.mockRestore()
    }
  })
})
