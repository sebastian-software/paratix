import { describe, expect, it } from "vitest"

import { git } from "../../src/modules/git.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const repo = "git@github.com:example/repo.git"
const destination = "/opt/myapp"
const gitDir = `${destination}/.git`
const originUrlCommand = `git -C '${destination}' remote get-url origin`

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(
    {
      [originUrlCommand]: { code: 0, stdout: repo },
      ...responses,
    },
    { strict: false, ...options }
  )

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

  it("returns ok when .git directory exists and no ref is specified", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote origin HEAD`]: {
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
      [`git -C '${destination}' ls-remote origin HEAD`]: {
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

  it("returns needs-apply when the existing checkout points at a different origin URL", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [originUrlCommand]: { code: 0, stdout: "git@github.com:other/repo.git" },
      [`git -C '${destination}' ls-remote origin HEAD`]: {
        code: 0,
        stdout: `${sha}\tHEAD\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when .git directory exists, ref is specified, and HEAD matches branch ref", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote origin 'main'`]: {
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
      [`git -C '${destination}' ls-remote origin 'main'`]: {
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
      [`git -C '${destination}' ls-remote origin 'v1.0.0'`]: {
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

  it("falls back to bare SHA when ls-remote returns empty output", async () => {
    const headSha = "aaa111"
    const bareSha = "ccc333"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote origin '${bareSha}'`]: { code: 2, stdout: "" },
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
      [`git -C '${destination}' ls-remote origin '${sha}'`]: { code: 2, stdout: "" },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("resolves lightweight tag via first ls-remote line", async () => {
    const sha = "deadbeef123"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' ls-remote origin 'v2.0.0'`]: {
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
      [`git -C '${destination}' ls-remote origin 'main'`]: {
        code: 0,
        stdout: `${sha}\trefs/heads/main\n`,
      },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`git -C '${destination}' ls-remote origin 'main'`)
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
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 1 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git clone '${repo}' '${destination}'`)
  })

  it("clones repo with --branch when .git does not exist and ref is given", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 1 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git clone --branch 'main' '${repo}' '${destination}'`)
  })

  it("pulls when .git exists and no ref is given", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' pull`)
  })

  it("updates the origin URL before pulling when an existing checkout drifted", async () => {
    const oldRepo = "git@github.com:other/repo.git"
    const mockSsh = createMockSsh({
      [originUrlCommand]: { code: 0, stdout: oldRepo },
      [`git -C '${destination}' remote set-url origin '${repo}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' remote set-url origin '${repo}'`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' pull`)
  })

  it("fetches, checks out, and resets to origin/<ref> when ref is a remote-tracking branch", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) refs/remotes/origin/'main'`]: {
        code: 0,
        stdout: "refs/remotes/origin/main\n",
      },
      [`git -C '${destination}' reset --hard origin/'main'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' fetch origin --tags --force`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' checkout 'main'`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' reset --hard origin/'main'`)
    expect(mockSsh.calls).not.toContain(`git -C '${destination}' reset --hard 'main'`)
  })

  it("resets directly to <ref> when ref is a tag and has no remote-tracking branch", async () => {
    // The for-each-ref probe returns no match, so the direct reset path
    // resolves the tag commit (and not a same-named branch tip).
    const mockSsh = createMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) refs/remotes/origin/'v1.0.0'`]: {
        code: 0,
        stdout: "",
      },
      [`git -C '${destination}' reset --hard 'v1.0.0'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' reset --hard 'v1.0.0'`)
    expect(mockSsh.calls).not.toContain(`git -C '${destination}' reset --hard origin/'v1.0.0'`)
  })

  it("resets directly to <ref> when ref is a bare commit SHA", async () => {
    const sha = "abc123def456"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) refs/remotes/origin/'${sha}'`]: {
        code: 0,
        stdout: "",
      },
      [`git -C '${destination}' reset --hard '${sha}'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' reset --hard '${sha}'`)
    expect(mockSsh.calls).not.toContain(`git -C '${destination}' reset --hard origin/'${sha}'`)
  })

  it("returns failed when branch reset fails", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) refs/remotes/origin/'main'`]: {
        code: 0,
        stdout: "refs/remotes/origin/main\n",
      },
      [`git -C '${destination}' reset --hard origin/'main'`]: { code: 1 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when direct reset fails for a tag", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' for-each-ref --format=%(refname) refs/remotes/origin/'v1.0.0'`]: {
        code: 0,
        stdout: "",
      },
      [`git -C '${destination}' reset --hard 'v1.0.0'`]: { code: 1 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("falls back to clone without --branch when --branch fails (bare SHA)", async () => {
    const sha = "abc123def456"
    const mockSsh = createMockSsh({
      [`git clone --branch '${sha}' '${repo}' '${destination}'`]: { code: 128 },
      [`test -d '${gitDir}'`]: { code: 1 },
    })
    const mod = git.clone(repo, destination, { ref: sha })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git clone '${repo}' '${destination}'`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' checkout '${sha}'`)
  })

  it("returns failed when clone fails", async () => {
    const mockSsh = createMockSsh({
      [`git clone '${repo}' '${destination}'`]: { code: 128 },
      [`test -d '${gitDir}'`]: { code: 1 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when update fetch fails", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 1 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
