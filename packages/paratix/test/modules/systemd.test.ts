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
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
      "systemctl mask -- 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl mask -- 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl mask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 0, stdout: "enabled\n" },
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

  // R-0000772: a toolchain failure of the `systemctl is-enabled` probe
  // (non-zero exit with empty stdout) must surface as a structured failed
  // ModuleResult instead of silently rendering the unit as not-masked.
  // The mask call must NOT run after the probe failed.
  it("R-0000772: apply returns failed when is-enabled probe fails with empty stdout", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": {
        code: 1,
        stderr: "Failed to connect to bus",
        stdout: "",
      },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl is-enabled failed while probing masked state")
    expect(ssh.calls).not.toContain("systemctl mask -- 'apt-daily.timer'")
  })

  // R-0000772: in the check phase a probe-toolchain failure cannot surface
  // structurally, so the module returns `needs-apply` and lets the apply
  // phase re-issue the probe and report the real cause.
  it("R-0000772: check returns needs-apply when is-enabled probe fails with empty stdout", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": {
        code: 1,
        stderr: "Failed to connect to bus",
        stdout: "",
      },
    })
    const mod = systemd.masked("apt-daily.timer")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
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
    `find /var/lib/paratix/flags -maxdepth 1 -type f -name ` +
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
    // R-0000779: restoreUnitFileSnapshot now guards the rm with a
    // `[ ! -L ] && [ -f ]` check so a symlink planted between the
    // snapshot capture (which reported `exists: false`) and the rollback
    // cannot be silently unlinked. The rollback path also probes `[ -L ]`
    // via `isSymlink` before reading the current content.
    const guardedRmCommand = `[ ! -L '${filePath}' ] && [ -f '${filePath}' ] && rm -f '${filePath}' || [ ! -e '${filePath}' ]`
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [guardedRmCommand]: { code: 0 },
      "systemctl daemon-reload": { code: 1 },
    })
    vi.spyOn(ssh, "exists").mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    vi.spyOn(ssh, "readFile").mockResolvedValueOnce(unitContent)
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(ssh.calls).not.toContain(reloadFlagSet)
    expect(ssh.calls).toContain(guardedRmCommand)
  })

  it("restores an existing unit file when daemon-reload fails", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      // R-0000683: restoreUnitFileSnapshot now probes `[ -L ]` before
      // writing back so a planted symlink cannot redirect the write.
      // Default to "not a symlink" so the restore path keeps running.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000683: see the daemon-reload-fails sibling test.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000683: see the daemon-reload-fails sibling test.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000683: see the daemon-reload-fails sibling test.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000779: the rollback path now probes `[ -L ]` before reading
      // the current content to refuse a symlink that materialized at the
      // unit path. Default to "not a symlink" so the existing skipped
      // branch (content mismatch) keeps running.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000683: see the daemon-reload-fails sibling test.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      // R-0000683: see the daemon-reload-fails sibling test.
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
  // R-0000779: the rollback `rm -f` is now wrapped in a `[ ! -L ] && [ -f ]`
  // guard so a symlink planted between the snapshot capture and the
  // rollback cannot be silently unlinked.
  it("R-0000211: removes a freshly-written unit file when writeFile throws and snapshot is absent", async () => {
    const guardedRmCommand = `[ ! -L '${filePath}' ] && [ -f '${filePath}' ] && rm -f '${filePath}' || [ ! -e '${filePath}' ]`
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      [guardedRmCommand]: { code: 0 },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("network drop during writeFile"))
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write unit file")
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(ssh.calls).toContain(guardedRmCommand)
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  it("apply returns failed when ssh is null", async () => {
    const mod = systemd.unit(unitName, unitContent)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000721: a rollback-time `ssh.readFile` failure (TOCTOU race, transient
  // SFTP error, permission denial between snapshot and rollback) must surface
  // alongside the primary daemon-reload failure. Without the try/catch the
  // read error would bubble out of the module unstructured and the
  // user-visible reason for the rollback would be lost entirely.
  it("R-0000721: surfaces rollback readFile failure after daemon-reload failure", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 1, stderr: "daemon reload failed\n" },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockRejectedValueOnce(new Error("SFTP read failed: connection reset"))
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("systemctl daemon-reload failed")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("rollback read of")
    expect(String(result.error)).toContain("connection reset")
    // The first write attempted the new content; the rollback writeFile must
    // NOT have been issued because the conditional read failed first.
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
  })

  // R-0000721: the same guarantee for the flag-persistence rollback path.
  // When `setVersionedFlag` fails and the subsequent rollback read trips
  // on a transient error, both failures must be chained into one
  // ModuleResult instead of swallowing the flag-persistence reason.
  it("R-0000721: surfaces rollback readFile failure after flag persistence failure", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
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
      .mockRejectedValueOnce(new Error("SFTP read failed: connection reset"))
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to persist versioned flag")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("rollback read of")
    expect(String(result.error)).toContain("connection reset")
    // The first write applied the new content; the rollback writeFile must
    // NOT have been issued because the conditional read failed first.
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
  })

  // R-0000683: a readFile failure on the pre-write snapshot must surface as
  // a structured failed ModuleResult instead of bubbling an unstructured
  // throw out of applySystemdUnit. Without this guard the writeFile path
  // would overwrite the existing unit file while the rollback would have
  // nothing to restore.
  it("R-0000683: refuses to write unit file when snapshot read fails", async () => {
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      [`[ -L '${filePath}' ]`]: { code: 1 },
    })
    vi.spyOn(ssh, "readFile").mockRejectedValueOnce(
      new Error("SFTP read failed: Permission denied")
    )
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to snapshot unit file")
    expect(String(result.error)).toContain(filePath)
    expect(String(result.error)).toContain("Permission denied")
    // The writeFile must NOT have been issued — there is no recoverable
    // snapshot, so the apply must abort before touching the live unit file.
    expect(writeFile).not.toHaveBeenCalled()
    expect(ssh.calls).not.toContain("systemctl daemon-reload")
  })

  // R-0000779: when the snapshot reported `exists: false` and the
  // rollback path tries to remove the freshly-written unit file, the
  // `rm -f` must be wrapped in a `[ ! -L ] && [ -f ]` guard so a
  // symlink that materialized at the destination between the snapshot
  // and the rollback cannot be silently unlinked. The unit-file path
  // belongs to systemd, so a planted symlink that points at an
  // unrelated file must NOT be followed by the rollback's `rm`.
  it("R-0000779: rm-rollback refuses to unlink through a symlinked unit path", async () => {
    const guardedRmCommand = `[ ! -L '${filePath}' ] && [ -f '${filePath}' ] && rm -f '${filePath}' || [ ! -e '${filePath}' ]`
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 1 },
      // The combined guard exits non-zero when the destination is a
      // symlink: `[ ! -L ]` fails and the trailing `[ ! -e ]` fallback
      // is also false because the path exists (as a symlink).
      [guardedRmCommand]: { code: 1, stderr: "symlink guard tripped" },
    })
    const writeFile = vi
      .spyOn(ssh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP write failed: connection reset"))
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write unit file")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("symlink guard tripped")
    // The guarded rm was issued exactly once. Without R-0000779 the
    // legacy unconditional `rm -f` would have removed the planted
    // symlink instead of refusing the rollback.
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(ssh.calls.filter((call) => call === guardedRmCommand)).toHaveLength(1)
  })

  // R-0000683 / R-0000779: the restore path must refuse to follow a
  // planted symlink at the unit file path. Without the leading `[ -L ]`
  // probe a swap between the snapshot read and the rollback would let
  // `ssh.writeFile` follow the link to its target (potentially
  // overwriting an unrelated system file). With R-0000779 the rollback
  // probes `[ -L ]` before reading the live content, so the failure
  // surfaces structurally via `restoreUnitFileSnapshotIfCurrentMatches`
  // and the message names the symlinked path.
  it("R-0000683: refuses to restore through a symlink", async () => {
    const previousContent = "[Unit]\nDescription=Previous\n"
    const ssh = createMockSsh({
      [`[ -e '${filePath}' ]`]: { code: 0 },
      // The destination became a symlink between snapshot and rollback.
      [`[ -L '${filePath}' ]`]: { code: 0 },
      [`cat '${filePath}'`]: { stdout: previousContent },
      [`stat -c '%a' '${filePath}'`]: { code: 0, stdout: "600\n" },
      "systemctl daemon-reload": { code: 1, stderr: "daemon reload failed\n" },
    })
    vi.spyOn(ssh, "readFile")
      .mockResolvedValueOnce(previousContent)
      .mockResolvedValueOnce(unitContent)
    const writeFile = vi.spyOn(ssh, "writeFile").mockResolvedValue()
    const mod = systemd.unit(unitName, unitContent)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("rollback")
    expect(String(result.error)).toContain("symbolic link")
    expect(String(result.error)).toContain(filePath)
    // The first writeFile attempted the new content; the second (rollback)
    // writeFile must NOT have been issued.
    expect(writeFile).toHaveBeenCalledTimes(1)
    expect(writeFile).toHaveBeenNthCalledWith(1, filePath, unitContent, { mode: "0644" })
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

  // R-0000659: the regex `^[\w@.\-]+$` accepts the bare values "." and
  // ".." because both match `[\w@.\-]+`. Used as `${name}` inside a path
  // like `/etc/systemd/system/${name}` they would resolve to the unit
  // directory itself (a writeFile to a directory, or `rm -f` against the
  // parent). Reject them before the regex check.
  it("throws when name is a bare dot (.)", () => {
    for (const createModule of factories) {
      expect(() => createModule(".")).toThrow(/Invalid systemd unit name/v)
    }
  })

  it("throws when name is a bare double-dot (..)", () => {
    for (const createModule of factories) {
      expect(() => createModule("..")).toThrow(/Invalid systemd unit name/v)
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
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 1, stdout: "masked\n" },
      "systemctl unmask -- 'apt-daily.timer'": { code: 0 },
    })
    const mod = systemd.unmasked("apt-daily.timer")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("systemctl unmask -- 'apt-daily.timer'")
  })

  it("apply returns failed when systemctl unmask exits with non-zero code", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled -- 'apt-daily.timer'": { code: 1, stdout: "masked\n" },
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
