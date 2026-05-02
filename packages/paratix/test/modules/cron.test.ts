import { describe, expect, it } from "vitest"

import { cron } from "../../src/modules/cron.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("cron.job", () => {
  // ---------------------------------------------------------------------------
  // check (state: present)
  // ---------------------------------------------------------------------------

  it("check returns ok when marker and correct job line exist (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when no crontab exists (exit code 1) (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when marker is missing (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when marker exists but job line differs (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null (state: present)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // ---------------------------------------------------------------------------
  // check (state: absent)
  // ---------------------------------------------------------------------------

  it("check returns ok when marker is not found (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when no crontab exists (exit code 1) (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when marker is found (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // ---------------------------------------------------------------------------
  // apply (state: present)
  // ---------------------------------------------------------------------------

  it("apply appends marker and job to empty crontab (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stdout: "" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).toContain("# paratix: backup")
    expect(writeCall).toContain("0 3 * * * /backup.sh")
    expect(writeCall).toContain("crontab -u 'alice' -")
  })

  it("apply appends marker and job to existing crontab with other entries (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).toContain("0 5 * * * /other.sh")
    expect(writeCall).toContain("# paratix: backup")
    expect(writeCall).toContain("0 3 * * * /backup.sh")
  })

  it("apply replaces job line when marker exists but job differs (state: present)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).toContain("# paratix: backup")
    expect(writeCall).toContain("0 3 * * * /backup.sh")
    expect(writeCall).not.toContain("0 5 * * * /backup.sh")
  })

  it("apply returns failed when ssh is null (state: present)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // ---------------------------------------------------------------------------
  // apply (state: absent)
  // ---------------------------------------------------------------------------

  it("apply removes marker and job from crontab (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).not.toContain("# paratix: backup")
    expect(writeCall).not.toContain("0 3 * * * /backup.sh")
    expect(writeCall).toContain("0 5 * * * /other.sh")
  })

  it("apply returns ok when marker is not found (nothing to remove) (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeUndefined()
  })

  it("apply removes crontab entirely when last job is removed (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeUndefined()
  })

  it("apply returns failed when ssh is null (state: absent)", async () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh", state: "absent" })
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // ---------------------------------------------------------------------------
  // name
  // ---------------------------------------------------------------------------

  it("has correct name format: cron.job: <name> (<user>)", () => {
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    expect(mod.name).toBe("cron.job: backup (alice)")
  })

  // ---------------------------------------------------------------------------
  // edge cases
  // ---------------------------------------------------------------------------

  it("check returns needs-apply when marker is last line without job line", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 0, stdout: "# paratix: backup\n" },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    expect(await mod.check(mockSsh, emptyEnv)).toBe("needs-apply")
  })

  it("apply only modifies the targeted marker when multiple exist", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout:
          "# paratix: cleanup\n0 1 * * * /cleanup.sh\n# paratix: backup\n0 5 * * * /backup.sh\n",
      },
    })
    const mod = cron.job("alice", "backup", { job: "0 3 * * * /backup.sh" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toContain("0 1 * * * /cleanup.sh")
    expect(writeCall).toContain("0 3 * * * /backup.sh")
    expect(writeCall).not.toContain("0 5 * * * /backup.sh")
  })

  // ---------------------------------------------------------------------------
  // input validation
  // ---------------------------------------------------------------------------

  it("throws when name contains a newline", () => {
    expect(() => cron.job("alice", "bad\nname", { job: "0 3 * * * /backup.sh" })).toThrow(
      "must not contain newlines"
    )
  })

  it("throws when job contains a newline", () => {
    expect(() => cron.job("alice", "backup", { job: "0 3 * * *\n/backup.sh" })).toThrow(
      "must not contain newlines"
    )
  })
})

describe("cron.absent", () => {
  it("check returns ok when marker is not in the crontab", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 0, stdout: "0 5 * * * /other.sh\n" },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("ok")
  })

  it("check returns ok when no crontab exists", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": { code: 1, stdout: "" },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("ok")
  })

  it("check returns needs-apply when marker is found", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(mockSsh, emptyEnv)).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = cron.absent("alice", "backup")
    expect(await mod.check(null, emptyEnv)).toBe("needs-apply")
  })

  it("apply removes marker and following job line from crontab", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).not.toContain("# paratix: backup")
    expect(writeCall).not.toContain("0 3 * * * /backup.sh")
    expect(writeCall).toContain("0 5 * * * /other.sh")
  })

  it("apply removes the crontab entirely when last managed entry is removed", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("crontab -u 'alice' -r")
  })

  it("apply returns ok when marker is not present (nothing to remove)", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeUndefined()
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = cron.absent("alice", "backup")
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("has correct name format: cron.absent: <name> (<user>)", () => {
    const mod = cron.absent("alice", "backup")
    expect(mod.name).toBe("cron.absent: backup (alice)")
  })

  it("only touches the targeted marker when multiple managed entries exist", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout:
          "# paratix: cleanup\n0 1 * * * /cleanup.sh\n# paratix: backup\n0 3 * * * /backup.sh\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toContain("# paratix: cleanup")
    expect(writeCall).toContain("0 1 * * * /cleanup.sh")
    expect(writeCall).not.toContain("# paratix: backup")
    expect(writeCall).not.toContain("0 3 * * * /backup.sh")
  })

  it("apply removes a trailing marker without a following job line", async () => {
    const mockSsh = createMockSsh({
      "crontab -u 'alice' -l": {
        code: 0,
        stdout: "0 5 * * * /other.sh\n# paratix: backup\n",
      },
    })
    const mod = cron.absent("alice", "backup")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const writeCall = mockSsh.calls.find((c) => c.startsWith("printf '%s'"))
    expect(writeCall).toBeDefined()
    expect(writeCall).not.toContain("# paratix: backup")
    expect(writeCall).toContain("0 5 * * * /other.sh")
  })

  it("throws when name contains a newline", () => {
    expect(() => cron.absent("alice", "bad\nname")).toThrow("must not contain newlines")
  })
})
