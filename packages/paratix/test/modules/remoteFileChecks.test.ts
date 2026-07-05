import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import {
  allocateRemoteStagingDirectory,
  cleanupRemoteStagingPath,
  findSymlinkInAncestors,
  findSymlinkInAncestorWalk,
  isRegularFileWithoutSymlink,
  isSymlink,
  publishRemoteStagedDirectory,
  verifiedPhysicalDirectoryCommand,
} from "../../src/modules/remoteFileChecks.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const EXEC_OPTIONS: ExecOptions = {}

describe("isRegularFileWithoutSymlink", () => {
  it("returns true when the path is a regular non-symlink file", async () => {
    const ssh = createMockSsh({ "[ -f '/etc/app.conf' ] && [ ! -L '/etc/app.conf' ]": { code: 0 } })
    expect(await isRegularFileWithoutSymlink(ssh, "/etc/app.conf")).toBe(true)
  })

  it("returns false when the guard command fails", async () => {
    const ssh = createMockSsh({ "[ -f '/etc/app.conf' ] && [ ! -L '/etc/app.conf' ]": { code: 1 } })
    expect(await isRegularFileWithoutSymlink(ssh, "/etc/app.conf")).toBe(false)
  })
})

describe("isSymlink", () => {
  it("reports the link itself, not its target", async () => {
    const ssh = createMockSsh({ "[ -L '/etc/link' ]": { code: 0 } })
    expect(await isSymlink(ssh, "/etc/link")).toBe(true)
  })

  it("returns false for a non-symlink path", async () => {
    const ssh = createMockSsh({ "[ -L '/etc/link' ]": { code: 1 } })
    expect(await isSymlink(ssh, "/etc/link")).toBe(false)
  })
})

describe("findSymlinkInAncestorWalk", () => {
  it("flags the leaf path when it is itself a symlink", async () => {
    const ssh = createMockSsh({ "[ -L '/a/b/c' ]": { code: 0 } })
    expect(await findSymlinkInAncestorWalk(ssh, "/a/b/c")).toStrictEqual({
      kind: "leaf",
      path: "/a/b/c",
    })
  })

  it("flags the first symlinked ancestor directory", async () => {
    const ssh = createMockSsh({
      "[ -L '/a/b' ]": { code: 0 },
      "[ -L '/a/b/c' ]": { code: 1 },
    })
    expect(await findSymlinkInAncestorWalk(ssh, "/a/b/c")).toStrictEqual({
      kind: "ancestor",
      path: "/a/b",
    })
  })

  it("returns null when neither the leaf nor any ancestor is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -L '/a' ]": { code: 1 },
      "[ -L '/a/b' ]": { code: 1 },
      "[ -L '/a/b/c' ]": { code: 1 },
    })
    expect(await findSymlinkInAncestorWalk(ssh, "/a/b/c")).toBeNull()
  })
})

describe("findSymlinkInAncestors", () => {
  it("returns the first symlinked ancestor without probing the leaf", async () => {
    const ssh = createMockSsh({
      "[ -L '/a' ]": { code: 1 },
      "[ -L '/a/b' ]": { code: 0 },
    })
    expect(await findSymlinkInAncestors(ssh, "/a/b/c")).toBe("/a/b")
  })

  it("returns null when no ancestor is a symlink", async () => {
    const ssh = createMockSsh({
      "[ -L '/a' ]": { code: 1 },
      "[ -L '/a/b' ]": { code: 1 },
    })
    expect(await findSymlinkInAncestors(ssh, "/a/b/c")).toBeNull()
  })
})

describe("verifiedPhysicalDirectoryCommand", () => {
  it("wraps a command in symlink-safe physical-directory guards", () => {
    expect(verifiedPhysicalDirectoryCommand("/srv/app", "run")).toBe(
      `[ ! -L '/srv/app' ] && [ -d '/srv/app' ] && cd -P -- '/srv/app' && [ "$(pwd -P)" = '/srv/app' ] && run`
    )
  })
})

describe("allocateRemoteStagingDirectory", () => {
  it("returns the validated staging path on success", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [
        { command: /mktemp -d -p/v, result: { code: 0, stdout: "/srv/app.ABC123\n" } },
      ],
    })
    const result = await allocateRemoteStagingDirectory(ssh, {
      execOptions: EXEC_OPTIONS,
      parent: "/srv",
      prefix: "app",
    })
    expect(result).toBe("/srv/app.ABC123")
  })

  it("returns null when the staging command exits non-zero", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [{ command: /mktemp -d -p/v, result: { code: 1, stdout: "" } }],
    })
    const result = await allocateRemoteStagingDirectory(ssh, {
      execOptions: EXEC_OPTIONS,
      parent: "/srv",
      prefix: "app",
    })
    expect(result).toBeNull()
  })

  it("returns null when mktemp emits an unexpected path", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [
        { command: /mktemp -d -p/v, result: { code: 0, stdout: "/elsewhere/evil\n" } },
      ],
    })
    const result = await allocateRemoteStagingDirectory(ssh, {
      execOptions: EXEC_OPTIONS,
      parent: "/srv",
      prefix: "app",
    })
    expect(result).toBeNull()
  })
})

describe("cleanupRemoteStagingPath", () => {
  it("removes the staging path recursively", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [{ command: /rm -rf --/v, result: { code: 0 } }],
    })
    await cleanupRemoteStagingPath(ssh, "/srv/app.ABC123", EXEC_OPTIONS)
    expect(ssh.calls).toContain("rm -rf -- '/srv/app.ABC123'")
  })
})

describe("publishRemoteStagedDirectory", () => {
  const parameters = {
    destination: "/srv/app",
    execOptions: EXEC_OPTIONS,
    parent: "/srv",
    postPublishDirectory: "/srv/app",
    stagingDestination: "/srv/app.ABC123",
  }

  it("returns true when the atomic publish succeeds", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [{ command: /mv -T -n/v, result: { code: 0 } }],
    })
    expect(await publishRemoteStagedDirectory(ssh, parameters)).toBe(true)
  })

  it("cleans up the staging directory and returns false when the publish fails", async () => {
    const ssh = createMockSsh(undefined, {
      rejectNonZeroExit: false,
      responseStubs: [
        { command: /mv -T -n/v, result: { code: 1 } },
        { command: /rm -rf --/v, result: { code: 0 } },
      ],
    })
    expect(await publishRemoteStagedDirectory(ssh, parameters)).toBe(false)
    expect(ssh.calls).toContain("rm -rf -- '/srv/app.ABC123'")
  })
})
