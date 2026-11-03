import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import { knownHostsTarget } from "../../../src/modules/sshKnownHostsFiles.js"
import { NEEDS_APPLY } from "../../../src/types.js"
import { createMockSsh } from "../../helpers/mockSsh.js"
import {
  createCaSsh,
  DIRECTORY_METADATA,
  FILE_METADATA,
  isInspection,
  isMutation,
  isPublication,
  isStage,
  publicKey,
  respondWhen,
  snapshotOnRead,
  TEMPORARY,
} from "./knownHostsCaTestHelpers.js"

const key = publicKey()
const desired = `@cert-authority *.example.com ${key}\n`

function module(state: "absent" | "present" = "present") {
  return ssh.knownHostsCertAuthority("alice", { hosts: ["*.example.com"], publicKey: key, state })
}

function lockCommands(calls: string[]): string[] {
  return calls.filter((command) => command.startsWith("mkdir /var/lib/paratix/flags/"))
}

describe("host CA target and filesystem behavior", () => {
  it("creates the target user's file with primary-group metadata, then becomes idempotent", async () => {
    const remote = createCaSsh({ directory: null, file: null })
    const mod = module()
    expect(await mod.check(remote.connection, {})).toBe(NEEDS_APPLY)
    expect(await mod.apply(remote.connection, {})).toMatchObject({ status: "changed" })
    expect(remote.state).toStrictEqual({
      content: desired,
      directory: DIRECTORY_METADATA,
      file: FILE_METADATA.replace("1:3:", "1:4:"),
    })
    expect(await mod.check(remote.connection, {})).toBe("ok")
    expect(await mod.apply(remote.connection, {})).toMatchObject({ status: "ok" })
    expect(remote.connection.calls.filter(isPublication)).toHaveLength(1)
    expect(remote.connection.calls.join("\n")).toContain("chown -h -- 'alice:developers'")
    expect(remote.connection.calls).not.toContain("printf '%s' \"$HOME\"")
  })

  it.each([
    "h\u012a.example.com",
    "h\u013f.example.com",
    "h\u010a.example.com",
    "h\u010d.example.com",
    "h\u0120.example.com",
  ])(
    "publishes Unicode pattern %j as UTF-8 without introducing wildcard or line-separator bytes",
    async (host) => {
      const foreign = Buffer.from([0x23, 0x20, 0xff, 0xfe, 0xa0, 0x0a])
      const remote = createCaSsh({ content: foreign.toString("latin1") })
      const mod = ssh.knownHostsCertAuthority("alice", { hosts: [host], publicKey: key })
      const expected = Buffer.concat([
        foreign,
        Buffer.from(`@cert-authority ${host} ${key}\n`, "utf8"),
      ])
      expect(await mod.apply(remote.connection, {})).toMatchObject({ status: "changed" })
      expect(Buffer.from(remote.state.content, "latin1")).toStrictEqual(expected)
      expect(await mod.check(remote.connection, {})).toBe("ok")
      expect(await mod.apply(remote.connection, {})).toMatchObject({ status: "ok" })
      const absent = ssh.knownHostsCertAuthority("alice", { publicKey: key, state: "absent" })
      expect(await absent.apply(remote.connection, {})).toMatchObject({ status: "changed" })
      expect(Buffer.from(remote.state.content, "latin1")).toStrictEqual(foreign)
    }
  )

  it("replaces patterns and removes its CA without a hosts filter while preserving foreign lines", async () => {
    const foreign = `# retained\n@revoked host ${key}\nhost ${key}\n`
    const remote = createCaSsh({ content: `${foreign}@cert-authority old ${key} comment\n` })
    expect(await module().apply(remote.connection, {})).toMatchObject({ status: "changed" })
    expect(remote.state.content).toBe(`${foreign}${desired}`)
    const absent = ssh.knownHostsCertAuthority("alice", {
      publicKey: `${key} new comment`,
      state: "absent",
    })
    expect(await absent.apply(remote.connection, {})).toMatchObject({ status: "changed" })
    expect(remote.state.content).toBe(foreign)
    expect(await absent.apply(remote.connection, {})).toMatchObject({ status: "ok" })
  })

  it("repairs metadata drift even when content already matches", async () => {
    const remote = createCaSsh({
      content: desired,
      directory: "1:2 755 root root",
      file: "1:3:10:mtime:ctime 644 root root",
    })
    expect(await module().check(remote.connection, {})).toBe(NEEDS_APPLY)
    expect(await module().apply(remote.connection, {})).toMatchObject({ status: "changed" })
    expect(remote.state.content).toBe(desired)
    expect(remote.state.directory).toBe(DIRECTORY_METADATA)
    expect(remote.state.file).toContain(" 600 alice developers")
  })

  it.each([
    { directory: null, file: null },
    { directory: "1:2 755 root root", file: "1:3:0:mtime:ctime 644 root root" },
  ])(
    "absent with no matching CA creates nothing and preserves unrelated metadata: %j",
    async (metadata) => {
      const remote = createCaSsh({ ...metadata, content: "# foreign\n" })
      const before = { ...remote.state }
      const mod = ssh.knownHostsCertAuthority("alice", { publicKey: key, state: "absent" })
      expect(await mod.check(remote.connection, {})).toBe("ok")
      expect(await mod.apply(remote.connection, {})).toMatchObject({ status: "ok" })
      expect(remote.state).toStrictEqual(before)
      expect(remote.connection.calls.filter(isStage)).toHaveLength(0)
      expect(remote.connection.calls.filter(isPublication)).toHaveLength(0)
    }
  )

  it("check and dry-run detect content and metadata drift without locks or filesystem changes", async () => {
    const remote = createCaSsh({ content: "# unrelated\n", directory: "1:2 755 root root" })
    const before = { ...remote.state }
    const mod = module()
    expect(await mod.check(remote.connection, {})).toBe(NEEDS_APPLY)
    expect(await mod._applyDryRun?.(remote.connection, {})).toMatchObject({ status: "changed" })
    expect(remote.state).toStrictEqual(before)
    expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
  })

  it.each([
    ".ssh must be a real directory",
    "known_hosts must be a regular file, not a symlink",
    "known_hosts changed during read",
    ".ssh changed during read",
  ])(
    "unsafe read is a structured dry-run/apply failure with no file writes: %s",
    async (diagnostic) => {
      const remote = createCaSsh({
        intercept: respondWhen(isInspection, { code: 1, stderr: diagnostic }),
      })
      expect(await module()._applyDryRun?.(remote.connection, {})).toMatchObject({
        error: { message: expect.stringContaining(diagnostic) },
        status: "failed",
      })
      expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
      expect(await module().apply(remote.connection, {})).toMatchObject({ status: "failed" })
      expect(remote.connection.calls.filter(isStage)).toHaveLength(0)
      expect(remote.published()).toBe(false)
    }
  )

  it.each([
    "",
    "bob:x:1:1::/home/alice:/bin/sh",
    "alice:x:1:1::relative:/bin/sh",
    "alice:x:1:1::/home/alice/../bob:/bin/sh",
    "alice:x:1:1::/home/alice:/bin/sh\nbob:x:2:2::/home/bob:/bin/sh",
  ])(
    "rejects missing, mismatched or ambiguous account records before mutations: %j",
    async (record) => {
      const remote = createCaSsh({
        intercept: respondWhen((command) => command === "getent passwd 'alice'", {
          stdout: record,
        }),
      })
      expect(await module().apply(remote.connection, {})).toMatchObject({ status: "failed" })
      expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
    }
  )

  it("rejects failed primary-group resolution before mutations", async () => {
    const remote = createCaSsh({
      intercept: respondWhen((command) => command === "id -gn 'alice'", {
        code: 1,
        stderr: "group lookup failed",
      }),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({
      error: { message: expect.stringContaining("group lookup failed") },
      status: "failed",
    })
    expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
  })

  it.each([
    "/",
    "relative",
    "/home//alice",
    "/home/../alice",
    "/home/alice\u200b",
    "/home/alice\n",
  ])("rejects unsafe target homes: %j", (home) => {
    expect(() => knownHostsTarget(home)).toThrow(/safe home/v)
  })

  it("rejects a physical-path alias before acquiring a lock or mutating the file", async () => {
    const remote = createCaSsh({
      intercept: respondWhen((command) => command.includes("readlink -m"), {
        stdout: "/real-home/alice/.ssh/known_hosts",
      }),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({
      error: { message: expect.stringContaining("ambiguous physical path") },
      status: "failed",
    })
    expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
  })

  it("uses the same path lock for CA and raw writers and keeps its name after a file rename", async () => {
    const remote = createCaSsh({ content: desired })
    expect(await module().apply(remote.connection, {})).toMatchObject({ status: "ok" })
    Object.assign(remote.state, { file: FILE_METADATA.replace("1:3:", "1:99:") })
    expect(await module().apply(remote.connection, {})).toMatchObject({ status: "ok" })
    const mod = ssh.knownHosts("host", { state: "absent" })
    const rawConnection = {
      ...remote.connection,
      test: createMockSsh({
        "[ -e '/home/alice/.ssh/known_hosts' ]": { code: 1 },
        "[ -L '/home/alice/.ssh' ]": { code: 1 },
        "[ -L '/home/alice/.ssh/known_hosts' ]": { code: 1 },
      }).test,
    }
    const environment = {}
    expect(await mod.apply(rawConnection, environment)).toMatchObject({ status: "ok" })
    expect(lockCommands(remote.connection.calls)).toHaveLength(3)
    expect(new Set(lockCommands(remote.connection.calls)).size).toBe(1)
  })

  it("reports missing SSH consistently", async () => {
    const conn = null
    expect(await module().check(null, {})).toBe(NEEDS_APPLY)
    expect(await module().apply(conn, {})).toMatchObject({ status: "failed" })
    expect(await module()._applyDryRun?.(null, {})).toMatchObject({ status: "failed" })
  })
})

describe("host CA failure paths", () => {
  it.each([
    ["read", (command: string) => isInspection(command)],
    ["lock", (command: string) => command === "mkdir -p /var/lib/paratix/flags"],
    ["stage", isStage],
    ["publication", isPublication],
  ] as const)(
    "returns a structured %s failure without publishing foreign content and cleans staging artifacts",
    async (phase, matches) => {
      const original = "# foreign content\n"
      const remote = createCaSsh({
        content: original,
        intercept: respondWhen(matches, { code: 2, stderr: `${phase} failed` }),
      })
      expect(await module().apply(remote.connection, {})).toMatchObject({
        error: { message: expect.stringContaining(`${phase} failed`) },
        status: "failed",
      })
      expect(remote.state.content).toBe(original)
      expect(remote.published()).toBe(false)
      expect(remote.connection.calls.filter(isStage).length).toBeLessThanOrEqual(1)
    }
  )

  it.each([isStage, isPublication])(
    "removes its temporary file after a stage/publication failure",
    async (matches) => {
      const remote = createCaSsh({
        intercept: respondWhen(matches, { code: 1, stderr: "injected failure" }),
      })
      expect(await module().apply(remote.connection, {})).toMatchObject({ status: "failed" })
      expect(remote.connection.calls).toContain(`rm -f -- '${TEMPORARY}'`)
      expect(remote.connection.calls.at(-1)).toContain("rmdir -- /var/lib/paratix/flags/")
    }
  )

  it("does not accept a successful shell exit when the no-follow read itself failed", async () => {
    const encoded = Buffer.from("partial data\n1", "latin1").toString("base64")
    const remote = createCaSsh({
      intercept: respondWhen(isInspection, {
        stdout: `${DIRECTORY_METADATA}\n${FILE_METADATA}\n${encoded}`,
      }),
    })
    expect(await module()._applyDryRun?.(remote.connection, {})).toMatchObject({
      error: {
        message: expect.stringContaining("failed to read known_hosts without following symlinks"),
      },
      status: "failed",
    })
    expect(remote.connection.calls.filter(isMutation)).toStrictEqual([])
  })

  it("rejects a foreign mktemp path before any write or cleanup of that foreign path", async () => {
    const remote = createCaSsh({
      intercept: respondWhen((command) => command.startsWith("mktemp "), {
        stdout: "/tmp/foreign-file",
      }),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({ status: "failed" })
    expect(remote.connection.calls.filter(isStage)).toHaveLength(0)
    expect(remote.connection.calls.join("\n")).not.toContain("rm -f -- '/tmp/foreign-file'")
  })

  it("detects a concurrent content/inode change before staging and retains the foreign update", async () => {
    const remote = createCaSsh({
      content: "# before\n",
      intercept: snapshotOnRead(
        2,
        { content: "# external update\n", file: FILE_METADATA.replace("1:3:", "1:99:") },
        true
      ),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({
      error: { message: expect.stringContaining("changed before staging") },
      status: "failed",
    })
    expect(remote.state.content).toBe("# external update\n")
    expect(remote.connection.calls.filter(isStage)).toHaveLength(0)
  })

  it("rejects directory replacement before preparation without publishing", async () => {
    const remote = createCaSsh({
      intercept: respondWhen((command) => command.includes("changed during prepare"), {
        code: 1,
        stderr: ".ssh changed before prepare",
      }),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({
      error: { message: expect.stringContaining("changed before prepare") },
      status: "failed",
    })
    expect(remote.published()).toBe(false)
  })

  it("does not report success when post-publication content or metadata verification fails", async () => {
    const remote = createCaSsh({
      intercept: snapshotOnRead(4, { file: "1:4:10:mtime:ctime 644 root root" }),
    })
    expect(await module().apply(remote.connection, {})).toMatchObject({
      error: { message: expect.stringContaining("after publication") },
      status: "failed",
    })
    expect(remote.published()).toBe(true)
    expect(remote.connection.calls).toContain(`rm -f -- '${TEMPORARY}'`)
  })
})
