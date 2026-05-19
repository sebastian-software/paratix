import { describe, expect, it } from "vitest"

import type { MockResponseStub } from "../helpers/mockSshCommandResponses.js"

import { git } from "../../src/modules/git.js"
import { shellQuote } from "../../src/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

type MockSshResponses = Parameters<typeof createBaseMockSsh>[0]

const emptyEnv = {}

const repo = "git@github.com:example/repo.git"
const destination = "/opt/myapp"
const destinationParent = "/opt"
const gitDir = `${destination}/.git`
const originUrlCommand = `git -C '${destination}' remote get-url origin`
const stagingDestination = `${destinationParent}/paratix-git-clone.TEST123`
const destinationSymlinkProbe = `[ -L '${destination}' ]`
const optSymlinkProbe = "[ -L '/opt' ]"
const gitDirSymlinkProbe = `[ -L '${gitDir}' ]`
const stagingMktempCommand = verifiedPhysicalDirectoryCommand(
  destinationParent,
  `mktemp -d -p '${destinationParent}' -- paratix-git-clone.XXXXXX`
)
const publishStagedCloneCommand = verifiedPhysicalDirectoryCommand(
  destinationParent,
  [
    `[ ! -e '${destination}' ]`,
    `[ ! -L '${destination}' ]`,
    `mv -T -n -- '${stagingDestination}' '${destination}'`,
    `[ ! -e '${stagingDestination}' ]`,
    `[ -d '${gitDir}' ]`,
  ].join(" && ")
)
const noSymlinkResponseStubs: MockResponseStub[] = [
  { command: /^\[ -L .+ \]$/v, result: { code: 1 } },
]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(
    {
      // R-0000279: apply now reads HEAD before and after `updateRepo` to
      // detect no-op runs. Default the probe to "no HEAD readable" so
      // existing fixtures (which expect "changed") keep passing. Tests that
      // exercise the idempotency path override these with explicit stable-SHA
      // stubs.
      [`git -C '${destination}' rev-parse HEAD`]: { code: 1, stdout: "" },
      [originUrlCommand]: { code: 0, stdout: repo },
      ...responses,
    },
    {
      ...options,
      responseStubs: [...(options?.responseStubs ?? []), ...noSymlinkResponseStubs],
    }
  )

function createGitApplyMockSsh(responses: MockSshResponses = {}) {
  return createMockSsh(responses)
}

function verifiedPhysicalDirectoryCommand(directory: string, command: string): string {
  const quotedDirectory = shellQuote(directory)
  return `[ ! -L ${quotedDirectory} ] && [ -d ${quotedDirectory} ] && cd -P -- ${quotedDirectory} && [ "$(pwd -P)" = ${quotedDirectory} ] && ${command}`
}

function expectNoGitMutationCalls(calls: string[]) {
  expect(
    calls.filter((call) => call.startsWith("git ") || call.startsWith("rm -rf"))
  ).toStrictEqual([])
}

describe("git.clone — validation", () => {
  it("rejects HTTPS repo URLs with embedded credentials", () => {
    expect(() => git.clone("https://user:secret@example.com/org/repo.git", destination)).toThrow(
      "must not embed credentials"
    )
  })

  it("rejects repo operands that look like Git options", () => {
    expect(() => git.clone("--upload-pack=touch injected", destination)).toThrow(
      "repo must not start with '-'"
    )
  })

  it("rejects non-empty ref operands that look like Git options", () => {
    expect(() => git.clone(repo, destination, { ref: "--detach" })).toThrow(
      "ref must not start with '-'"
    )
  })

  it("accepts an empty ref", () => {
    expect(() => git.clone(repo, destination, { ref: "" })).not.toThrow()
  })

  // R-0000278: shellQuote stops shell metacharacter injection, but newlines
  // and backslashes still corrupt `output.split("\n")` and downstream
  // consumers. Defense-in-depth ensures these refs are rejected at module
  // construction time.
  it("rejects refs containing newline characters", () => {
    expect(() => git.clone(repo, destination, { ref: "main\nrm -rf /" })).toThrow(
      "whitespace, backslashes, apostrophes, or '..' sequences"
    )
  })

  it("rejects refs containing whitespace", () => {
    expect(() => git.clone(repo, destination, { ref: "release v1" })).toThrow(
      "whitespace, backslashes, apostrophes, or '..' sequences"
    )
  })

  it("rejects refs containing backslashes", () => {
    expect(() => git.clone(repo, destination, { ref: "main\\branch" })).toThrow(
      "whitespace, backslashes, apostrophes, or '..' sequences"
    )
  })

  it("rejects refs containing parent-directory sequences", () => {
    expect(() => git.clone(repo, destination, { ref: "main/../etc" })).toThrow(
      "whitespace, backslashes, apostrophes, or '..' sequences"
    )
  })

  // R-0000482: updateRepo and isRemoteTrackingBranch build
  // `origin/${shellQuote(reference)}` paths via concatenation, so a single
  // quote inside the reference would otherwise corrupt the resulting shell
  // token. Reject apostrophes at module construction time.
  it("rejects refs containing apostrophes", () => {
    expect(() => git.clone(repo, destination, { ref: "main'branch" })).toThrow(
      "whitespace, backslashes, apostrophes, or '..' sequences"
    )
  })

  it("rejects HTTPS repo URLs with only a username", () => {
    expect(() => git.clone("https://token@example.com/org/repo.git", destination)).toThrow(
      "must not embed credentials"
    )
  })

  it.each([
    ["token", "https://example.com/org/repo.git?token=abc123"],
    ["signature", "https://example.com/org/repo.git?signature=sig456"],
    ["password", "https://example.com/org/repo.git?password=secret"],
  ])("rejects HTTPS repo URLs with sensitive %s query parameters", (_name, url) => {
    expect(() => git.clone(url, destination)).toThrow("sensitive query parameters")
  })

  it("accepts HTTPS repo URLs without credentials", () => {
    expect(() => git.clone("https://github.com/example/repo.git", destination)).not.toThrow()
  })

  it("accepts HTTPS repo URLs with non-sensitive query parameters", () => {
    expect(() =>
      git.clone("https://github.com/example/repo.git?ref=main&download=true", destination)
    ).not.toThrow()
  })

  it("accepts SCP-like and SSH repo URLs", () => {
    expect(() => git.clone("git@github.com:example/repo.git", destination)).not.toThrow()
    expect(() => git.clone("ssh://git@github.com/example/repo.git", destination)).not.toThrow()
  })

  // R-0000730: `git.clone` interpolates the destination into `rm -rf --
  // <destination>` during fallback cleanup. Reject inputs that could trigger a
  // destructive operation before any async path executes.
  it("rejects an empty destination", () => {
    expect(() => git.clone(repo, "")).toThrow("destination must not be empty")
  })

  it("rejects a destination consisting only of whitespace", () => {
    expect(() => git.clone(repo, "   ")).toThrow("destination must not be empty")
  })

  it("rejects a destination padded with whitespace", () => {
    expect(() => git.clone(repo, " /opt/app")).toThrow(
      "destination must not start or end with whitespace"
    )
  })

  it("rejects the root destination", () => {
    expect(() => git.clone(repo, "/")).toThrow("destructive destination path")
  })

  it("rejects a relative destination", () => {
    expect(() => git.clone(repo, "opt/app")).toThrow("destination must be an absolute path")
  })

  it("rejects a destination starting with '-'", () => {
    expect(() => git.clone(repo, "-rf")).toThrow("destination must not start with '-'")
  })

  it("rejects a non-normalised destination with '..' components", () => {
    expect(() => git.clone(repo, "/opt/app/../etc")).toThrow("destination must be normalized")
  })

  it("rejects a non-normalised destination with redundant slashes", () => {
    expect(() => git.clone(repo, "/opt//app")).toThrow("destination must be normalized")
  })
})

describe("git.clone — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = git.clone(repo, destination)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when .git directory does not exist", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 1 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the destination is a symlink", async () => {
    const mockSsh = createMockSsh({
      [destinationSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
    expect(mockSsh.calls).not.toContain(originUrlCommand)
  })

  it("returns needs-apply when a destination ancestor is a symlink", async () => {
    const mockSsh = createMockSsh({
      [optSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
    expect(mockSsh.calls).not.toContain(originUrlCommand)
  })

  it("returns needs-apply when .git is a symlink", async () => {
    const mockSsh = createMockSsh({
      [gitDirSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
    expect(mockSsh.calls).not.toContain(originUrlCommand)
  })

  it("returns ok when .git directory exists and no ref is specified", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin HEAD`]: {
        code: 0,
        stdout: `${sha}\tHEAD\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when no ref is specified and remote default branch advanced", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin HEAD`]: {
        code: 0,
        stdout: "bbb222\tHEAD\n",
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: "aaa111" },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the existing checkout HEAD is unreadable", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' rev-parse HEAD`]: { code: 1, stdout: "" },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the existing checkout points at a different origin URL", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin HEAD`]: {
        code: 0,
        stdout: `${sha}\tHEAD\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
      [originUrlCommand]: { code: 0, stdout: "git@github.com:other/repo.git" },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when .git directory exists, ref is specified, and HEAD matches branch ref", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'main'`]: {
        code: 0,
        stdout: `${sha}\trefs/heads/main\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when .git exists, ref is specified, and HEAD does not match", async () => {
    const headSha = "aaa111"
    const remoteSha = "bbb222"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'main'`]: {
        code: 0,
        stdout: `${remoteSha}\trefs/heads/main\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: headSha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("resolves annotated tag via ls-remote dereferenced line and HEAD matches", async () => {
    const sha = "deadbeef"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'v1.0.0'`]: {
        code: 0,
        stdout: `aaa111bbb222\trefs/tags/v1.0.0\n${sha}\trefs/tags/v1.0.0^{}\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("prefers a remote branch over a same-named annotated tag during check", async () => {
    const branchSha = "111111"
    const tagSha = "222222"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'release'`]: {
        code: 0,
        stdout: `aaa111\trefs/tags/release\n${tagSha}\trefs/tags/release^{}\n${branchSha}\trefs/heads/release\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: branchSha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "release" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("falls back to bare SHA when ls-remote returns empty output", async () => {
    const headSha = "aaa111"
    const bareSha = "ccc333"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin '${bareSha}'`]: { code: 2, stdout: "" },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: headSha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: bareSha })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when ref is a bare SHA and HEAD matches", async () => {
    const sha = "abc123def456"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin '${sha}'`]: { code: 2, stdout: "" },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("resolves lightweight tag via first ls-remote line", async () => {
    // R-0000811: the first ls-remote line is now validated against the
    // canonical `[a-f0-9]{40}\t` shape before its SHA fragment is returned,
    // so the fixture uses a full 40-character hex digest.
    const sha = "deadbeef00112233445566778899aabbccddeeff"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'v2.0.0'`]: {
        code: 0,
        stdout: `${sha}\trefs/tags/v2.0.0\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v2.0.0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("uses ls-remote to resolve ref during check", async () => {
    const sha = "abc123"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote -- origin 'main'`]: {
        code: 0,
        stdout: `${sha}\trefs/heads/main\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`git -C '${destination}' ls-remote -- origin 'main'`)
  })

  it("quotes adversarial destination and ref values during check", async () => {
    const adversarialRepo = "git@example.com:team/repo '$(touch repo-check)'.git"
    const adversarialDestination = "/opt/my app/it's $(touch dest-check)"
    // R-0000482: refs may no longer contain apostrophes. The remaining
    // metacharacters still exercise shell-quote on the command boundary.
    const adversarialRef = "release/x;$(touch_ref-check)"
    const adversarialGitDir = `${adversarialDestination}/.git`
    const quotedDestination = shellQuote(adversarialDestination)
    const quotedRef = shellQuote(adversarialRef)
    const sha = "abc123"
    const mockSsh = createMockSsh({
      [`git -C ${quotedDestination} ls-remote -- origin ${quotedRef}`]: {
        code: 0,
        stdout: `${sha}\trefs/heads/${adversarialRef}\n`,
      },
      [`git -C ${quotedDestination} remote get-url origin`]: {
        code: 0,
        stdout: adversarialRepo,
      },
      [`git -C ${quotedDestination} rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d ${shellQuote(adversarialGitDir)}`]: { code: 0 },
    })
    const mod = git.clone(adversarialRepo, adversarialDestination, { ref: adversarialRef })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain(`git -C ${quotedDestination} ls-remote -- origin ${quotedRef}`)
  })
})

describe("git.clone — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = git.clone(repo, destination)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("clones repo without branch when .git does not exist and no ref is given", async () => {
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [publishStagedCloneCommand]: { code: 0 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(stagingMktempCommand)
    expect(mockSsh.calls).toContain(`git clone -- '${repo}' '${stagingDestination}'`)
    expect(mockSsh.calls).toContain(publishStagedCloneCommand)
    expect(mockSsh.calls).not.toContain(`git clone -- '${repo}' '${destination}'`)
  })

  it("returns failed without mutation when the destination is a symlink", async () => {
    const mockSsh = createGitApplyMockSsh({
      [destinationSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error?.message)).toContain("must not contain symlinks")
    expectNoGitMutationCalls(mockSsh.calls)
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
  })

  it("returns failed without mutation when a destination ancestor is a symlink", async () => {
    const mockSsh = createGitApplyMockSsh({
      [optSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error?.message)).toContain("must not contain symlinks")
    expectNoGitMutationCalls(mockSsh.calls)
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
  })

  it("returns failed without mutation when .git is a symlink", async () => {
    const mockSsh = createGitApplyMockSsh({
      [gitDirSymlinkProbe]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error?.message)).toContain("must not contain symlinks")
    expectNoGitMutationCalls(mockSsh.calls)
    expect(mockSsh.calls).not.toContain(`test -d '${gitDir}'`)
  })

  it("clones repo with --branch when .git does not exist and ref is given", async () => {
    const mockSsh = createGitApplyMockSsh({
      [`git clone --branch 'main' -- '${repo}' '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [publishStagedCloneCommand]: { code: 0 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `git clone --branch 'main' -- '${repo}' '${stagingDestination}'`
    )
    expect(mockSsh.calls).toContain(publishStagedCloneCommand)
  })

  it("quotes adversarial repo, destination, and ref values when cloning", async () => {
    const adversarialRepo = "git@example.com:team/repo '$(touch repo-apply)'.git"
    const adversarialDestination = "/opt/my app/it's $(touch dest-apply)"
    const adversarialParent = "/opt/my app"
    const adversarialStagingDestination = `${adversarialParent}/paratix-git-clone.APPLY123`
    // R-0000482: refs may no longer contain apostrophes. The remaining
    // metacharacters still exercise shell-quote on the command boundary.
    const adversarialRef = "release/x;$(touch_ref-apply)"
    const adversarialGitDir = `${adversarialDestination}/.git`
    const expectedMktempCommand = verifiedPhysicalDirectoryCommand(
      adversarialParent,
      `mktemp -d -p ${shellQuote(adversarialParent)} -- paratix-git-clone.XXXXXX`
    )
    const expectedCommand = [
      "git clone --branch",
      shellQuote(adversarialRef),
      "--",
      shellQuote(adversarialRepo),
      shellQuote(adversarialStagingDestination),
    ].join(" ")
    const expectedPublishCommand = verifiedPhysicalDirectoryCommand(
      adversarialParent,
      [
        `[ ! -e ${shellQuote(adversarialDestination)} ]`,
        `[ ! -L ${shellQuote(adversarialDestination)} ]`,
        `mv -T -n -- ${shellQuote(adversarialStagingDestination)} ${shellQuote(adversarialDestination)}`,
        `[ ! -e ${shellQuote(adversarialStagingDestination)} ]`,
        `[ -d ${shellQuote(adversarialGitDir)} ]`,
      ].join(" && ")
    )
    const mockSsh = createMockSsh({
      [`test -d ${shellQuote(adversarialGitDir)}`]: { code: 1 },
      [expectedCommand]: { code: 0 },
      [expectedMktempCommand]: { code: 0, stdout: `${adversarialStagingDestination}\n` },
      [expectedPublishCommand]: { code: 0 },
    })
    const mod = git.clone(adversarialRepo, adversarialDestination, { ref: adversarialRef })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.execCalls).toContainEqual({
      command: expectedCommand,
      options: { ignoreExitCode: true, silent: true },
    })
    expect(mockSsh.calls).toContain(expectedPublishCommand)
  })

  it("resets to the remote default HEAD when .git exists and no ref is given", async () => {
    const fetchHeadCommand = verifiedPhysicalDirectoryCommand(destination, "git fetch origin HEAD")
    const resetHeadCommand = verifiedPhysicalDirectoryCommand(
      destination,
      "git reset --hard FETCH_HEAD"
    )
    const mockSsh = createGitApplyMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
      [fetchHeadCommand]: { code: 0 },
      [resetHeadCommand]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(fetchHeadCommand)
    expect(mockSsh.calls).toContain(resetHeadCommand)
  })

  // R-0000279: when a `fetch + reset --hard` rerun lands on the same HEAD
  // the apply path must report "ok" instead of "changed" so downstream
  // signals (service.reload, ...) only fire on real updates.
  it("returns ok when fetch + reset --hard leaves HEAD unchanged", async () => {
    const sha = "1234567890abcdef1234567890abcdef12345678"
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: `${sha}\n` },
      [`test -d '${gitDir}'`]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin HEAD")]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git reset --hard FETCH_HEAD")]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when fetch + reset --hard moves HEAD to a new commit", async () => {
    // Stable stub returning the same SHA every call would yield "ok"; here we
    // intentionally do NOT stub rev-parse HEAD so it falls through to the
    // default (code: 1, stdout: "") and the comparison short-circuits to
    // "changed". This matches the existing apply fixtures.
    const mockSsh = createGitApplyMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin HEAD")]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git reset --hard FETCH_HEAD")]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("updates the origin URL before resetting to remote HEAD when an existing checkout drifted", async () => {
    const oldRepo = "git@github.com:other/repo.git"
    const setOriginCommand = verifiedPhysicalDirectoryCommand(
      destination,
      `git remote set-url origin '${repo}'`
    )
    const fetchHeadCommand = verifiedPhysicalDirectoryCommand(destination, "git fetch origin HEAD")
    const resetHeadCommand = verifiedPhysicalDirectoryCommand(
      destination,
      "git reset --hard FETCH_HEAD"
    )
    const mockSsh = createGitApplyMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
      [fetchHeadCommand]: { code: 0 },
      [originUrlCommand]: { code: 0, stdout: oldRepo },
      [resetHeadCommand]: { code: 0 },
      [setOriginCommand]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(setOriginCommand)
    expect(mockSsh.calls).toContain(fetchHeadCommand)
    expect(mockSsh.calls).toContain(resetHeadCommand)
  })

  it("adds origin before resetting to remote HEAD when an existing git repository has no origin", async () => {
    const addOriginCommand = verifiedPhysicalDirectoryCommand(
      destination,
      `git remote add origin '${repo}'`
    )
    const fetchHeadCommand = verifiedPhysicalDirectoryCommand(destination, "git fetch origin HEAD")
    const resetHeadCommand = verifiedPhysicalDirectoryCommand(
      destination,
      "git reset --hard FETCH_HEAD"
    )
    const mockSsh = createGitApplyMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
      [addOriginCommand]: { code: 0 },
      [fetchHeadCommand]: { code: 0 },
      [originUrlCommand]: { code: 2 },
      [resetHeadCommand]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(addOriginCommand)
    expect(mockSsh.calls).toContain(fetchHeadCommand)
    expect(mockSsh.calls).toContain(resetHeadCommand)
    const originCall = mockSsh.execCalls.find((call) => call.command === originUrlCommand)
    expect(originCall?.options).toStrictEqual({ ignoreExitCode: true, silent: true })
  })

  it("fetches, checks out, and resets to origin/<ref> when ref is a remote-tracking branch", async () => {
    const fetchCommand = verifiedPhysicalDirectoryCommand(
      destination,
      "git fetch origin --tags --force"
    )
    const checkoutCommand = verifiedPhysicalDirectoryCommand(destination, "git checkout 'main'")
    const resetCommand = verifiedPhysicalDirectoryCommand(
      destination,
      "git reset --hard 'origin/main'"
    )
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) 'refs/remotes/origin/main'`]: {
        code: 0,
        stdout: "refs/remotes/origin/main\n",
      },
      [`test -d '${gitDir}'`]: { code: 0 },
      [checkoutCommand]: { code: 0 },
      [fetchCommand]: { code: 0 },
      [resetCommand]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(fetchCommand)
    expect(mockSsh.calls).toContain(checkoutCommand)
    expect(mockSsh.calls).toContain(resetCommand)
    expect(mockSsh.calls).not.toContain(
      verifiedPhysicalDirectoryCommand(destination, "git reset --hard 'main'")
    )
  })

  it("resets directly to <ref> when ref is a tag and has no remote-tracking branch", async () => {
    // The for-each-ref probe returns no match, so the direct reset path
    // resolves the tag commit (and not a same-named branch tip).
    const resetCommand = verifiedPhysicalDirectoryCommand(destination, "git reset --hard 'v1.0.0'")
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) 'refs/remotes/origin/v1.0.0'`]: {
        code: 0,
        stdout: "",
      },
      [`test -d '${gitDir}'`]: { code: 0 },
      [resetCommand]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git checkout 'v1.0.0'")]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin --tags --force")]: {
        code: 0,
      },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(resetCommand)
    expect(mockSsh.calls).not.toContain(
      verifiedPhysicalDirectoryCommand(destination, "git reset --hard 'origin/v1.0.0'")
    )
  })

  it("resets directly to <ref> when ref is a bare commit SHA", async () => {
    const sha = "abc123def456"
    const resetCommand = verifiedPhysicalDirectoryCommand(destination, `git reset --hard '${sha}'`)
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) 'refs/remotes/origin/${sha}'`]: {
        code: 0,
        stdout: "",
      },
      [`test -d '${gitDir}'`]: { code: 0 },
      [resetCommand]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin --tags --force")]: {
        code: 0,
      },
      [verifiedPhysicalDirectoryCommand(destination, `git checkout '${sha}'`)]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(resetCommand)
    expect(mockSsh.calls).not.toContain(
      verifiedPhysicalDirectoryCommand(destination, `git reset --hard 'origin/${sha}'`)
    )
  })

  it("returns failed when branch reset fails", async () => {
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) 'refs/remotes/origin/main'`]: {
        code: 0,
        stdout: "refs/remotes/origin/main\n",
      },
      [`test -d '${gitDir}'`]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git checkout 'main'")]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin --tags --force")]: {
        code: 0,
      },
      [verifiedPhysicalDirectoryCommand(destination, "git reset --hard 'origin/main'")]: {
        code: 1,
      },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when direct reset fails for a tag", async () => {
    const mockSsh = createGitApplyMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) 'refs/remotes/origin/v1.0.0'`]: {
        code: 0,
        stdout: "",
      },
      [`test -d '${gitDir}'`]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git checkout 'v1.0.0'")]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin --tags --force")]: {
        code: 0,
      },
      [verifiedPhysicalDirectoryCommand(destination, "git reset --hard 'v1.0.0'")]: { code: 1 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("falls back to clone without --branch when --branch fails (bare SHA)", async () => {
    const sha = "abc123def456"
    const fallbackStagingDestination = stagingDestination
    const fallbackCheckoutCommand = verifiedPhysicalDirectoryCommand(
      fallbackStagingDestination,
      `git checkout '${sha}'`
    )
    const fallbackPublishCommand = publishStagedCloneCommand.replace(
      stagingDestination,
      fallbackStagingDestination
    )
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${fallbackStagingDestination}'`]: { code: 0 },
      [`git clone --branch '${sha}' -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [fallbackCheckoutCommand]: { code: 0 },
      [fallbackPublishCommand]: { code: 0 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git clone -- '${repo}' '${fallbackStagingDestination}'`)
    expect(mockSsh.calls).toContain(fallbackCheckoutCommand)
    expect(mockSsh.calls).not.toContain(`rm -rf -- '${destination}'`)
  })

  // R-0000223: a failed first-pass `git clone --branch <ref>` can leave a
  // partially-populated staging directory behind. The fallback `git clone`
  // would then abort if it reused that path. Ensure the fallback path removes
  // only the staging directory before allocating the second clone target.
  it("R-0000223: removes the staging directory before retrying fallback clone", async () => {
    const sha = "abc123def456"
    const fallbackStagingDestination = stagingDestination
    const fallbackCheckoutCommand = verifiedPhysicalDirectoryCommand(
      fallbackStagingDestination,
      `git checkout '${sha}'`
    )
    const fallbackPublishCommand = publishStagedCloneCommand.replace(
      stagingDestination,
      fallbackStagingDestination
    )
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${fallbackStagingDestination}'`]: { code: 0 },
      [`git clone --branch '${sha}' -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [fallbackCheckoutCommand]: { code: 0 },
      [fallbackPublishCommand]: { code: 0 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const cleanupIndex = mockSsh.calls.indexOf(`rm -rf -- '${stagingDestination}'`)
    const fallbackIndex = mockSsh.calls.indexOf(
      `git clone -- '${repo}' '${fallbackStagingDestination}'`
    )
    expect(cleanupIndex).toBeGreaterThanOrEqual(0)
    expect(fallbackIndex).toBeGreaterThan(cleanupIndex)
    expect(mockSsh.calls).not.toContain(`rm -rf -- '${destination}'`)
  })

  it("does not remove a pre-existing non-git destination after a failed ref clone", async () => {
    const sha = "abc123def456"
    const fallbackStagingDestination = stagingDestination
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${fallbackStagingDestination}'`]: { code: 128 },
      [`git clone --branch '${sha}' -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: sha })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).not.toContain(`rm -rf -- '${destination}'`)
    expect(mockSsh.calls).toContain(`git clone -- '${repo}' '${fallbackStagingDestination}'`)
  })

  // R-0000642: when the initial `git clone --branch <ref>` fails and the
  // unconstrained fallback succeeds, but the subsequent `git checkout <ref>`
  // fails, the host is left with a partial clone at the repository's default
  // branch. Ensure the fallback path cleans up only its staging directory.
  it("R-0000642: removes the fallback staging clone when checkout fails", async () => {
    const sha = "abc123def456"
    const checkoutCommand = verifiedPhysicalDirectoryCommand(
      stagingDestination,
      `git checkout '${sha}'`
    )
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${stagingDestination}'`]: { code: 0 },
      [`git clone --branch '${sha}' -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [checkoutCommand]: { code: 1 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: sha })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // Two rm calls: one before the fallback clone (R-0000223), one after the
    // failed checkout (R-0000642). Both must be present, and the post-checkout
    // cleanup must follow the failed checkout.
    const cleanupCalls = mockSsh.calls.filter((c) => c === `rm -rf -- '${stagingDestination}'`)
    expect(cleanupCalls.length).toBeGreaterThanOrEqual(2)
    const checkoutIndex = mockSsh.calls.indexOf(checkoutCommand)
    const lastCleanupIndex = mockSsh.calls.lastIndexOf(`rm -rf -- '${stagingDestination}'`)
    expect(checkoutIndex).toBeGreaterThanOrEqual(0)
    expect(lastCleanupIndex).toBeGreaterThan(checkoutIndex)
    expect(mockSsh.calls).not.toContain(`rm -rf -- '${destination}'`)
  })

  it("R-0000939: fails publish without replacing a destination created during clone", async () => {
    const sha = "abc123def456"
    const checkoutCommand = verifiedPhysicalDirectoryCommand(
      stagingDestination,
      `git checkout '${sha}'`
    )
    const failedPublishCommand = publishStagedCloneCommand
    const mockSsh = createGitApplyMockSsh({
      [`git clone -- '${repo}' '${stagingDestination}'`]: { code: 0 },
      [`git clone --branch '${sha}' -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [checkoutCommand]: { code: 0 },
      [failedPublishCommand]: { code: 1 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination, { ref: sha })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).toContain(failedPublishCommand)
    expect(mockSsh.calls).toContain(`rm -rf -- '${stagingDestination}'`)
    expect(mockSsh.calls).not.toContain(`rm -rf -- '${destination}'`)
  })

  it("returns failed when clone fails", async () => {
    const mockSsh = createMockSsh({
      [`git clone -- '${repo}' '${stagingDestination}'`]: { code: 128 },
      [`rm -rf -- '${stagingDestination}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 1 },
      [stagingMktempCommand]: { code: 0, stdout: `${stagingDestination}\n` },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when update fetch fails", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
      [verifiedPhysicalDirectoryCommand(destination, "git fetch origin --tags --force")]: {
        code: 1,
      },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
