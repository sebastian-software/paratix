import { describe, expect, it, vi } from "vitest"

import { sha256String } from "../../src/modules/fileHelpers.js"
import { systemd } from "../../src/modules/systemd.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/etc\/systemd\/system\/.+$/v },
      ...(options?.allowWrites ?? []),
    ],
  })

function mockDaemonReloadSequence(
  ssh: ReturnType<typeof createMockSsh>,
  results: Array<{ code: number; stderr: string; stdout: string }>
): void {
  const originalExec = ssh.exec.bind(ssh)
  const reloadResults = [...results]
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    const handlers: Record<string, () => ReturnType<typeof ssh.exec>> = {
      "systemctl daemon-reload": async () => {
        await Promise.resolve()
        ssh.calls.push(command)
        ssh.execCalls.push({ command, options })
        return reloadResults.shift() ?? { code: 0, stderr: "", stdout: "" }
      },
    }
    return (handlers[command] ?? (async () => originalExec(command, options)))()
  })
}

describe("systemd.daemonReload", () => {
  it("check always returns needs-apply with a valid ssh connection", async () => {
    const ssh = createMockSsh()
    const mod = systemd.daemonReload()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check always returns needs-apply when ssh is null", async () => {
    const mod = systemd.daemonReload()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl daemon-reload and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 0 },
    })
    const mod = systemd.daemonReload()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
  })

  it("apply returns failed when daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl daemon-reload": { code: 1 },
    })
    const mod = systemd.daemonReload()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.daemonReload()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.masked", () => {
  it("check returns ok when unit is already masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 0, stdout: "masked\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when unit is enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when unit is disabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 1, stdout: "disabled\n" },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl mask and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl mask -- 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl mask -- 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl mask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl mask -- 'apt-daily.timer'": { code: 1 },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.masked("apt-daily.timer")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.unit", () => {
  const unitName = "my-app.service"
  // Content without trailing newline so mock output matches after trim()
  const unitContent = "[Unit]\nDescription=My App\n\n[Service]\nExecStart=/usr/bin/my-app"
  const filePath = `/etc/systemd/system/${unitName}`
  const reloadFlag = `systemd-unit-${sha256String(unitName).slice(0, 16)}-${sha256String(unitContent).slice(0, 16)}`
  const reloadFlagCheck = `[ -f /var/lib/paratix/flags/'${reloadFlag}' ]`
  const reloadFlagSet =
    `find /var/lib/paratix/flags -maxdepth 1 -name ` +
    `'systemd-unit-${sha256String(unitName).slice(0, 16)}-*' ! -name '*.lock' -delete && ` +
    `touch /var/lib/paratix/flags/'${reloadFlag}'`

  it("check returns ok when file exists, content matches, and mode is 0644", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: unitContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644\n" },
      [reloadFlagCheck]: { code: 0 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when file does not exist", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when file content differs", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: "[Unit]\nDescription=Old Content\n" },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when content matches but mode drifts to 0600", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: unitContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when stat for the unit file mode fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: unitContent },
      [`stat -c '%a' '${filePath}'`]: { code: 1, stdout: "" },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when daemon-reload marker is missing", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { code: 0, stdout: unitContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "644\n" },
      [reloadFlagCheck]: { code: 1 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply writes the file and runs daemon-reload returning changed on success", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      [reloadFlagSet]: { code: 0 },
      "systemctl daemon-reload": { code: 0 },
    })
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl daemon-reload")
    expect(ssh.calls).toContain(reloadFlagSet)
  })

  it("apply returns failed when daemon-reload exits with non-zero code", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      [`rm -f '${filePath}'`]: { code: 0 },
      "systemctl daemon-reload": { code: 1 },
    })
    vi.spyOn(ssh, "exists").mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    vi.spyOn(ssh, "readFile").mockResolvedValueOnce(unitContent)
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain(reloadFlagSet)
    expect(ssh.calls).toContain(`rm -f '${filePath}'`)
  })

  it("restores an existing unit file when daemon-reload fails", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 1 },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(unitContent)
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
  })

  it("reports daemon-reload and rollback write failures when both fail", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 1, stderr: "daemon reload failed\n" },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(unitContent)
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("rollback write failed: ENOSPC"))
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl daemon-reload failed")
    expect(String(result.error)).toContain("daemon reload failed")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("ENOSPC")
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
  })

  it("restores an existing unit file when daemon-reload flag persistence fails", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      [reloadFlagSet]: {
        code: 1,
        stderr:
          "touch: cannot touch '/var/lib/paratix/flags/systemd-unit-marker': Permission denied\n",
      },
      "systemctl daemon-reload": { code: 0 },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(unitContent)
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to persist versioned flag")
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
    expect(ssh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(2)
  })

  it("reports rollback daemon-reload failure after restoring a loaded unit file", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      [reloadFlagSet]: {
        code: 1,
        stderr:
          "touch: cannot touch '/var/lib/paratix/flags/systemd-unit-marker': Permission denied\n",
      },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(unitContent)
    mockDaemonReloadSequence(ssh, [
      { code: 0, stderr: "", stdout: "" },
      { code: 1, stderr: "daemon reload failed\n", stdout: "" },
    ])
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("rollback systemctl daemon-reload failed")
    expect(String(result.error)).toContain("daemon reload failed")
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
    expect(ssh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(2)
  })

  it("does not overwrite a concurrently changed unit file when daemon-reload fails", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const concurrentContent = "[Unit]\nDescription=Concurrent\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 1 },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(concurrentContent)
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
  })

  it("does not delete a concurrently created unit file when daemon-reload flag persistence fails", async () => {
    const concurrentContent = "[Unit]\nDescription=Concurrent\n"
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
      [reloadFlagSet]: {
        code: 1,
        stderr:
          "touch: cannot touch '/var/lib/paratix/flags/systemd-unit-marker': Permission denied\n",
      },
      "systemctl daemon-reload": { code: 0 },
    })
    vi.spyOn(ssh, "exists").mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    vi.spyOn(ssh, "readFile").mockResolvedValueOnce(concurrentContent)
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to persist versioned flag")
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(ssh.calls).not.toContain(`rm -f '${filePath}'`)
    expect(ssh.calls.filter((call) => call === "systemctl daemon-reload")).toHaveLength(1)
  })

  // R-0000211: writeFile can throw (SFTP error after a partial write,
  // permission denied, network drop). Without the try/catch around the
  // writeFile call, the unit file would stay half-written and the captured
  // snapshot would be discarded unrestored. Mirrors quadlet's R-0000182 fix.
  it("R-0000211: restores an existing unit file when writeFile throws", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP write failed: ENOSPC"))
      .mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write unit file")
    expect(String(result.error)).toContain("ENOSPC")
    // First call attempted the new content; second call restored the snapshot.
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  it("reports writeFile and rollback failures when both fail", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP write failed: ENOSPC"))
      .mockRejectedValueOnce(new Error("rollback write failed: EROFS"))
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write unit file")
    expect(String(result.error)).toContain("ENOSPC")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("EROFS")
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
    expect(writeFile).toHaveBeenNthCalledWith(2, filePath, previousContent, { mode: "600" })
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  // R-0000211: when the file did not exist before, the snapshot is "absent"
  // and the rollback path removes the freshly-written file via `rm -f`.
  it("R-0000211: removes a freshly-written unit file when writeFile throws and snapshot is absent", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      [`rm -f '${filePath}'`]: { code: 0 },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("network drop during writeFile"))
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write unit file")
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(ssh.calls).toContain(`rm -f '${filePath}'`)
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.unit(unitName, unitContent)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

describe("systemd.unit — input validation", () => {
  const factories = [
    (name: string) => systemd.masked(name),
    (name: string) => systemd.unmasked(name),
    (name: string) => systemd.unit(name, "[Unit]"),
  ]

  it("throws when name is empty", () => {
    for (const createModule of factories) {
      expect(() => createModule("")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name can be interpreted as a systemctl option", () => {
    for (const createModule of factories) {
      expect(() => createModule("--global.service")).toThrow(/Invalid systemd unit name/v)
      expect(() => createModule("-foo.service")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name contains path traversal (../../etc/passwd)", () => {
    for (const createModule of factories) {
      expect(() => createModule("../../etc/passwd")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name contains a forward slash (foo/bar.service)", () => {
    for (const createModule of factories) {
      expect(() => createModule("foo/bar.service")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name contains a space", () => {
    for (const createModule of factories) {
      expect(() => createModule("my service.service")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name contains shell metacharacters (semicolon)", () => {
    for (const createModule of factories) {
      expect(() => createModule("app;rm.service")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("allows valid service names with letters, digits, dots, hyphens, and underscores", () => {
    for (const createModule of factories) {
      expect(() => createModule("my-app.service")).not.toThrow()
    }
  })

  it("allows valid timer names", () => {
    for (const createModule of factories) {
      expect(() => createModule("backup.timer")).not.toThrow()
    }
  })

  it("allows names with the @ instance specifier", () => {
    for (const createModule of factories) {
      expect(() => createModule("app@instance.service")).not.toThrow()
    }
  })
})

describe("systemd.unmasked", () => {
  it("check returns ok when unit is not masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when unit is disabled but not masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 1, stdout: "disabled\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when unit is masked", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 1, stdout: "masked\n" },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply executes systemctl unmask and returns changed on success", async () => {
    const ssh = createMockSsh({
      "systemctl unmask -- 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl unmask -- 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl unmask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl unmask -- 'apt-daily.timer'": { code: 1 },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.unmasked("apt-daily.timer")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})
