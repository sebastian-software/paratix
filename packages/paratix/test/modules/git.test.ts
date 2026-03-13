import { describe, expect, it } from "vitest"

import { git } from "../../src/modules/git.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const repo = "git@github.com:example/repo.git"
const destination = "/opt/myapp"
const gitDir = `${destination}/.git`

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
    const mockSsh = createMockSsh({
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when .git directory exists, ref is specified, and HEAD matches branch ref", async () => {
    const sha = "abc1234567890"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 0 },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`git -C '${destination}' rev-parse origin/'main'`]: { code: 0, stdout: sha },
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
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 0 },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: headSha },
      [`git -C '${destination}' rev-parse origin/'main'`]: { code: 0, stdout: remoteSha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("falls back to tag/commit ref when origin/<ref> lookup fails and HEAD matches", async () => {
    const sha = "deadbeef"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 0 },
      [`git -C '${destination}' rev-parse 'v1.0.0^{commit}'`]: { code: 0, stdout: sha },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`git -C '${destination}' rev-parse origin/'v1.0.0'`]: { code: 1, stdout: "" },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("falls back to tag/commit ref when origin/<ref> lookup fails and HEAD does not match", async () => {
    const headSha = "aaa111"
    const tagSha = "ccc333"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 0 },
      [`git -C '${destination}' rev-parse 'v1.0.0^{commit}'`]: { code: 0, stdout: tagSha },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: headSha },
      [`git -C '${destination}' rev-parse origin/'v1.0.0'`]: { code: 1, stdout: "" },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("fetches origin before resolving ref during check", async () => {
    const sha = "abc123"
    const mockSsh = createMockSsh({
      [`git -C '${destination}' fetch origin --tags --force`]: { code: 0 },
      [`git -C '${destination}' rev-parse HEAD`]: { code: 0, stdout: sha },
      [`git -C '${destination}' rev-parse origin/'main'`]: { code: 0, stdout: sha },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`git -C '${destination}' fetch origin --tags --force`)
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

  it("fetches, checks out, and resets to origin/<ref> when .git exists and ref is given", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' reset --hard origin/'main'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' fetch origin --tags --force`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' checkout 'main'`)
    expect(mockSsh.calls).toContain(`git -C '${destination}' reset --hard origin/'main'`)
  })

  it("falls back to reset --hard <ref> when origin/<ref> reset fails", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' reset --hard origin/'v1.0.0'`]: { code: 1 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "v1.0.0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`git -C '${destination}' reset --hard 'v1.0.0'`)
  })

  it("does not run fallback reset when origin/<ref> reset succeeds", async () => {
    const mockSsh = createMockSsh({
      [`git -C '${destination}' reset --hard origin/'main'`]: { code: 0 },
      [`test -d '${gitDir}'`]: { code: 0 },
    })
    const mod = git.clone(repo, destination, { ref: "main" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(`git -C '${destination}' reset --hard 'main'`)
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
