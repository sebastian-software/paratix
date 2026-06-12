import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import type { SshConnection } from "../../src/types.js"

import { sysctl } from "../../src/modules/sysctl.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/etc\/sysctl\.d\/99-paratix-.+\.conf$/v },
      ...(options?.allowWrites ?? []),
    ],
  })

const KEY = "net.ipv4.ip_forward"
const VALUE = "1"
const CONF_PATH = configPathForKey(KEY)
const CONF_CONTENT = "net.ipv4.ip_forward = 1\n"
// R-0000769: the absent flow now wraps the `rm -f` in a `[ ! -L ]` guard so a
// symlink planted between the snapshot capture and the rm cannot redirect the
// unlink. The verification path expects the same single-shell statement.
const ABSENT_RM_COMMAND = `[ ! -L '${CONF_PATH}' ] || { echo 'sysctl persistence file must not be a symlink' >&2; exit 1; }; rm -f '${CONF_PATH}'`
const ABSENT_SYMLINK_PROBE = `[ -L '${CONF_PATH}' ]`
type ExecLike = SshConnection["exec"]

function buildSequentialRollbackSymlinkProbeExec(input: {
  onSymlinkProbe: () => void
  originalExec: ExecLike
}): ExecLike {
  const symlinkProbeResults = [
    { code: 1, stderr: "", stdout: "" },
    { code: 0, stderr: "", stdout: "" },
  ]
  return async (command, options) => {
    if (command === ABSENT_SYMLINK_PROBE) {
      input.onSymlinkProbe()
      return symlinkProbeResults.shift() ?? { code: 0, stderr: "", stdout: "" }
    }
    return input.originalExec(command, options)
  }
}

// R-0000650: mirror the production-side digest width (96 bits / 24 hex
// digits) so the test helper stays in sync with the live persistence-path
// derivation in `sysctl.set`.
function configPathForKey(key: string): string {
  const sanitizedKey = key.replaceAll(".", "-")
  const hash = createHash("sha256").update(key).digest("hex").slice(0, 24)
  return `/etc/sysctl.d/99-paratix-${sanitizedKey}-${hash}.conf`
}

// ─── sysctl.set — check ───────────────────────────────────────────────────────

describe("sysctl.set — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live value matches and config file exists with correct content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: CONF_CONTENT },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live value differs", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when sysctl -n exits non-zero (e.g. unknown key)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 255, stderr: "sysctl: cannot stat ...", stdout: "" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file has wrong content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: "net.ipv4.ip_forward = 0\n" },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // state: absent

  it("returns ok when config file does not exist (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when config file still exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // state: absent + resetValue

  it("returns ok when config file is gone and live value matches resetValue (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live value differs from resetValue (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "1" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live value cannot be read (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 255, stderr: "unknown key", stdout: "" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ─── sysctl.set — apply ───────────────────────────────────────────────────────

describe("sysctl.set — apply", () => {
  it("returns changed and executes sysctl -w and writes config file (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`sysctl -n '${KEY}'`)
    expect(mockSsh.calls).toContain(`sysctl -w '${KEY}=${VALUE}'`)
    expect(writeFileSpy).toHaveBeenCalledWith(CONF_PATH, CONF_CONTENT, { mode: "0644" })
  })

  it("returns failed when sysctl -w fails (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("masks the desired value when sysctl -w fails (state: present)", async () => {
    const sensitiveValue = "present-secret-sentinel-0000987"
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=${sensitiveValue}'`]: {
        code: 1,
        stderr: `permission denied for ${sensitiveValue}`,
        stdout: `attempted ${sensitiveValue}`,
      },
    })
    const mod = sysctl.set(KEY, sensitiveValue)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed")
    expect(String(result.error)).not.toContain(sensitiveValue)
    expect(mockSsh.execCalls.at(-1)).toMatchObject({
      command: `sysctl -w '${KEY}=${sensitiveValue}'`,
      options: { ignoreExitCode: true, secrets: [sensitiveValue], silent: true },
    })
  })

  it("returns failed when the previous live value cannot be read (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 255, stderr: "unknown key" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to read live value before applying")
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=${VALUE}'`)
  })

  // R-0000242 regression: when the persistence write throws (read-only
  // filesystem, missing parent dir, network drop) the live kernel value
  // has already drifted via `sysctl -w`. Surface this as a structured
  // `failed` ModuleResult instead of letting the exception propagate.
  // Mirrors the R-0000182 hardening in similar persist-after-mutation
  // paths.
  it("R-0000242: returns failed when the persistence writeFile throws (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(
      new Error("SFTP write failed: read-only file system")
    )
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to persist config to")
    expect(String(result.error)).toContain("read-only file system")
    // R-0000651: the previousValue is no longer interpolated into the
    // rollback success message — operators see the abstract phrasing
    // instead so the value cannot leak through the rendered error.
    expect(String(result.error)).toContain("rolled back live value to previous value")
    expect(String(result.error)).not.toContain('"0"')
    expect(mockSsh.calls).toStrictEqual([
      `sysctl -n '${KEY}'`,
      `sysctl -w '${KEY}=${VALUE}'`,
      `sysctl -w '${KEY}=0'`,
    ])
  })

  it("returns failed and reports rollback failure when writeFile and rollback fail", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
    })
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(
      new Error("SFTP write failed: read-only file system")
    )
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to persist config to")
    // R-0000651: the rollback failure now flows through `failedCommand`
    // with previousValue registered as a secret, so the rendered message
    // is abstract — the verbatim previous value does not appear.
    expect(String(result.error)).toContain("rollback to previous value failed")
    expect(String(result.error)).toContain("permission denied")
    expect(String(result.error)).not.toContain('"0"')
  })

  // R-0000651: when the previous live value is sensitive (e.g. a crypto
  // tuning parameter that exposes platform configuration) it must not
  // appear verbatim in the rollback diagnostic. The secret sink masks any
  // occurrence of the value that bubbles up through stderr.
  it("R-0000651: masks the previousValue when sysctl -w echoes it on failure", async () => {
    const sensitivePrevious = "supersecret-crypto-param-42"
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: sensitivePrevious },
      [`sysctl -w '${KEY}=${sensitivePrevious}'`]: {
        code: 1,
        stderr: `sysctl: failed to write ${sensitivePrevious}`,
      },
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(
      new Error("SFTP write failed: read-only file system")
    )
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    const rendered = String(result.error)
    expect(rendered).toContain("rollback to previous value failed")
    expect(rendered).not.toContain(sensitivePrevious)
  })

  it("returns failed when conn is null (state: present)", async () => {
    const mod = sysctl.set(KEY, VALUE)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed and removes config file (state: absent)", async () => {
    const mockSsh = createMockSsh({
      // R-0000658: the absent flow snapshots the persistence file before
      // rm so a failing live-reset can roll the file back.
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      // R-0000770: the snapshot capture starts with a symlink probe so the
      // absent flow refuses to remove a symlinked persistence file.
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(ABSENT_RM_COMMAND)
  })

  it("returns failed when removing config file fails (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 1, stderr: "read-only file system" },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to remove config file")
  })

  it("removes file and writes resetValue to live kernel (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(ABSENT_RM_COMMAND)
    expect(mockSsh.calls).toContain(`sysctl -w '${KEY}=0'`)
    expect(mockSsh.calls).toContain(`sysctl -n '${KEY}'`)
  })

  it("returns failed when sysctl -w fails during reset (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
  })

  it("masks the resetValue when sysctl -w fails during reset", async () => {
    const sensitiveResetValue = "reset-secret-sentinel-0000987"
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=${sensitiveResetValue}'`]: {
        code: 1,
        stderr: `permission denied for ${sensitiveResetValue}`,
        stdout: `attempted ${sensitiveResetValue}`,
      },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, {
      resetValue: sensitiveResetValue,
      state: "absent",
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
    expect(String(result.error)).not.toContain(sensitiveResetValue)
    expect(mockSsh.execCalls.at(-1)).toMatchObject({
      command: `sysctl -w '${KEY}=${sensitiveResetValue}'`,
      options: { ignoreExitCode: true, secrets: [sensitiveResetValue], silent: true },
    })
  })

  it("returns failed when live value did not converge after reset (state: absent + resetValue)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "1" },
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("did not converge")
  })

  it("does not expose resetValue or actual live value when reset verification mismatches", async () => {
    const sensitiveResetValue = "reset-verify-secret-sentinel-0000987"
    const sensitiveActualValue = "actual-verify-secret-sentinel-0000987"
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: sensitiveActualValue },
      [`sysctl -w '${KEY}=${sensitiveResetValue}'`]: { code: 0 },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, {
      resetValue: sensitiveResetValue,
      state: "absent",
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("live value did not converge to reset value")
    expect(String(result.error)).not.toContain(sensitiveResetValue)
    expect(String(result.error)).not.toContain(sensitiveActualValue)
  })

  it("does not run sysctl -w when resetValue is not given (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=${VALUE}'`)
  })

  // R-0000658: when the persistence file is removed but the subsequent
  // live-reset fails, the absent flow must restore the persistence file
  // from a content snapshot so the next reboot does not load the kernel
  // default. Mirrors the rollbackUnitAfterFlagPersistenceFailure pattern
  // in systemd.ts.
  it("R-0000658: restores persistence file when sysctl -w fails during reset", async () => {
    const previousFileContent = `${KEY} = 1\n`
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: previousFileContent },
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      // R-0000769: the rollback path probes the persistence file for a
      // symlink before writing back the snapshot.
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
    expect(String(result.error)).toContain("persistence file restored from snapshot")
    expect(writeFileSpy).toHaveBeenCalledWith(CONF_PATH, previousFileContent, { mode: "0644" })
  })

  it("R-0000769: refuses rollback write when persistence file becomes a symlink after reset failure", async () => {
    const previousFileContent = `${KEY} = 1\n`
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: previousFileContent },
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
      [ABSENT_RM_COMMAND]: { code: 0 },
    })
    const originalExec = mockSsh.exec
    let symlinkProbeCount = 0
    vi.spyOn(mockSsh, "exec").mockImplementation(
      buildSequentialRollbackSymlinkProbeExec({
        onSymlinkProbe() {
          symlinkProbeCount += 1
        },
        originalExec,
      })
    )
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
    expect(String(result.error)).toContain("persistence file restore refused")
    expect(String(result.error)).toContain("is a symbolic link")
    expect(symlinkProbeCount).toBe(2)
    expect(writeFileSpy).not.toHaveBeenCalled()
  })

  // R-0000658: when the persistence file did not exist at the start of
  // the absent flow there is nothing to restore. The apply must still
  // report the original reset failure, but the rollback message reflects
  // the missing snapshot so operators do not chase a phantom restore.
  it("R-0000658: reports missing snapshot when persistence file was already absent", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
    expect(String(result.error)).toContain("no persistence-file snapshot to restore")
    expect(writeFileSpy).not.toHaveBeenCalled()
  })

  // R-0000658: when both the live-reset and the rollback writeFile fail
  // the apply must surface both failures so operators see the full
  // breakage chain.
  it("R-0000658: chains rollback writeFile failures into the reset failure", async () => {
    const previousFileContent = `${KEY} = 1\n`
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: previousFileContent },
      [`sysctl -w '${KEY}=0'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      // R-0000769: the rollback path probes the persistence file for a
      // symlink before writing back the snapshot.
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(
      new Error("SFTP write failed: read-only file system")
    )
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("sysctl -w failed while resetting live value")
    expect(String(result.error)).toContain("persistence file restore failed")
    expect(String(result.error)).toContain("read-only file system")
  })

  // R-0000682: when `test -f` reports the persistence file as present but
  // the subsequent readFile throws (transient SFTP error, permission
  // denied), the absent flow must NOT proceed with the rm. The legacy
  // implementation collapsed the read failure into `null`, removed the
  // file anyway, and reported "no snapshot to restore" — masking the loss.
  // The apply must abort with a structured failure that names the
  // persistence path and the underlying reason.
  it("R-0000682: refuses to remove persistence file when snapshot read fails", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=0'`]: { code: 0 },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
      [ABSENT_RM_COMMAND]: { code: 0 },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    vi.spyOn(mockSsh, "readFile").mockRejectedValueOnce(
      new Error("SFTP read failed: Permission denied")
    )
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("persistence-file snapshot failed")
    expect(String(result.error)).toContain(CONF_PATH)
    expect(String(result.error)).toContain("Permission denied")
    // The rm must NOT have been issued.
    expect(mockSsh.calls).not.toContain(ABSENT_RM_COMMAND)
    // The live-reset must NOT have been issued either.
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=0'`)
  })

  // R-0000769: the absent flow must refuse to unlink the persistence file
  // when the path was swapped for a symlink between the snapshot capture
  // and the rm. Without the inline `[ ! -L ]` guard the rm would follow
  // the link target through `unlink(2)` and the subsequent rollback
  // could observe a dangling link, masking the loss.
  it("R-0000769: refuses to remove persistence file when path is a symlink", async () => {
    // The snapshot probe reports "not a symlink" (TOCTOU: the symlink is
    // planted between the snapshot capture and the rm), so the inline
    // `[ ! -L ]` guard inside ABSENT_RM_COMMAND must trip and surface the
    // failure instead of unlinking the link.
    const previousFileContent = `${KEY} = 1\n`
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: previousFileContent },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
      [ABSENT_RM_COMMAND]: {
        code: 1,
        stderr: "sysctl persistence file must not be a symlink",
      },
      [ABSENT_SYMLINK_PROBE]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to remove config file")
    expect(String(result.error)).toContain("must not be a symlink")
    // The live-reset must NOT have been issued after the guarded rm failed.
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=0'`)
  })

  // R-0000770: the snapshot phase must refuse to capture content through a
  // symlinked persistence path. Without the leading `[ -L ]` probe a
  // `test -f` follow-the-link plus `readFile` would snapshot the target's
  // contents and a subsequent rollback would write back foreign content
  // into the original location.
  it("R-0000770: refuses to snapshot persistence file when path is a symlink", async () => {
    const mockSsh = createMockSsh({
      [ABSENT_SYMLINK_PROBE]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { resetValue: "0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("persistence-file snapshot failed")
    expect(String(result.error)).toContain(CONF_PATH)
    expect(String(result.error)).toContain("symbolic link")
    // The rm and the live-reset must NOT have been issued.
    expect(mockSsh.calls).not.toContain(ABSENT_RM_COMMAND)
    expect(mockSsh.calls).not.toContain(`sysctl -w '${KEY}=0'`)
  })

  // R-0000769: the rollback writeFile is also wrapped in a `[ -L ]`
  // probe so a symlink that appears between the snapshot capture
  // (R-0000770) and the rollback write does not redirect the restore.
  // The snapshot guard from R-0000770 already aborts the apply before
  // the rm when the initial probe reports a symlink, so the rollback
  // branch is defensive and not reachable from these mock-driven
  // tests; the `restorePersistenceFile` symlink-probe is exercised in
  // production via the same TOCTOU race window that motivates the
  // `moveSwapToBackup` (R-0000647) and `restoreUnitFileSnapshot`
  // (R-0000683) symlink guards.
})

describe("sysctl.set — config path", () => {
  it("uses distinct persistence paths for keys that differ only by dot and hyphen", async () => {
    const dottedKey = "net.ipv4.test-key"
    const hyphenatedKey = "net-ipv4.test-key"
    const dottedPath = configPathForKey(dottedKey)
    const hyphenatedPath = configPathForKey(hyphenatedKey)
    const mockSsh = createMockSsh({
      [`sysctl -n '${dottedKey}'`]: { code: 0, stdout: "0" },
      [`sysctl -n '${hyphenatedKey}'`]: { code: 0, stdout: "0" },
      [`sysctl -w '${dottedKey}=1'`]: { code: 0 },
      [`sysctl -w '${hyphenatedKey}=1'`]: { code: 0 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")

    await sysctl.set(dottedKey, "1").apply(mockSsh, emptyEnv)
    await sysctl.set(hyphenatedKey, "1").apply(mockSsh, emptyEnv)

    expect(dottedPath).not.toBe(hyphenatedPath)
    expect(writeFileSpy).toHaveBeenCalledWith(dottedPath, `${dottedKey} = 1\n`, {
      mode: "0644",
    })
    expect(writeFileSpy).toHaveBeenCalledWith(hyphenatedPath, `${hyphenatedKey} = 1\n`, {
      mode: "0644",
    })
  })

  // R-0000650: with a 48-bit (12-hex) digest two sysctl entries that share
  // the same sanitized prefix and only differ in their suffix could land on
  // the same persistence-file path after a single hash collision. The 96-bit
  // digest keeps the persistence-file path unique for keys that sanitize to
  // the same prefix but carry a different suffix.
  it("R-0000650: produces distinct paths for keys that share the sanitized prefix", () => {
    const firstKey = "net.ipv4.tcp_rmem-alpha"
    const secondKey = "net.ipv4.tcp_rmem-beta"
    const firstPath = configPathForKey(firstKey)
    const secondPath = configPathForKey(secondKey)
    expect(firstPath).not.toBe(secondPath)
    // Both paths must share the sanitized prefix (the `.`->`-` transform is
    // identical for both keys) but the trailing hash component differs.
    const sanitizedFirst = firstKey.replaceAll(".", "-")
    const sanitizedSecond = secondKey.replaceAll(".", "-")
    expect(firstPath.startsWith(`/etc/sysctl.d/99-paratix-${sanitizedFirst}-`)).toBe(true)
    expect(secondPath.startsWith(`/etc/sysctl.d/99-paratix-${sanitizedSecond}-`)).toBe(true)
  })

  // R-0000650: regression guard for the digest width itself. Truncating to
  // 12 hex digits (48 bits) hits the birthday bound around 2^24 keys, which
  // is reachable by realistic playbooks; 24 hex digits (96 bits) push the
  // bound past 2^48 and keep the filename well below the 255-byte limit.
  it("R-0000650: persistence path embeds a 24-hex-digit (96-bit) digest", () => {
    const path = configPathForKey(KEY)
    const match = /-paratix-net-ipv4-ip_forward-(?<hash>[0-9a-f]+)\.conf$/v.exec(path)
    expect(match?.groups?.hash).toBeDefined()
    expect(match?.groups?.hash.length).toBe(24)
  })
})

// ─── sysctl.set — name ────────────────────────────────────────────────────────

describe("sysctl.set — name", () => {
  it("has descriptive name for present state without exposing the value", () => {
    const mod = sysctl.set(KEY, VALUE)
    expect(mod.name).toBe(`sysctl.set: ${KEY}`)
  })

  it("does not leak sensitive values through the present-state module name", () => {
    const sensitiveValue = "module-name-secret-sentinel-0000992"
    const mod = sysctl.set(KEY, sensitiveValue)
    expect(mod.name).toBe(`sysctl.set: ${KEY}`)
    expect(mod.name).not.toContain(sensitiveValue)
  })

  it("has descriptive name for absent state", () => {
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    expect(mod.name).toBe(`sysctl.set: absent ${KEY}`)
  })
})

// ─── sysctl.set — validation ──────────────────────────────────────────────────

describe("sysctl.set — validation", () => {
  it("throws when runtime state is an unknown string", () => {
    expect(() => sysctl.set(KEY, VALUE, { state: "removed" as "present" })).toThrow(
      'sysctl.set: state must be "present" or "absent"'
    )
  })

  it("throws when runtime state is not a string", () => {
    expect(() => sysctl.set(KEY, VALUE, { state: 1 as unknown as "present" })).toThrow(
      'sysctl.set: state must be "present" or "absent"'
    )
  })

  it("accepts valid runtime states", () => {
    expect(() => sysctl.set(KEY, VALUE, { state: "present" })).not.toThrow()
    expect(() => sysctl.set(KEY, VALUE, { state: "absent" })).not.toThrow()
  })

  it("throws when key is empty", () => {
    expect(() => sysctl.set("", VALUE)).toThrow(/key must not be empty/v)
  })

  it("throws when key contains a newline", () => {
    expect(() => sysctl.set(`${KEY}\nmalicious = 1`, VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a carriage return", () => {
    expect(() => sysctl.set(`${KEY}\rmalicious`, VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a path separator", () => {
    expect(() => sysctl.set("net/ipv4/ip_forward", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains whitespace", () => {
    expect(() => sysctl.set("net.ipv4 ip_forward", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key contains a shell metacharacter", () => {
    expect(() => sysctl.set("net.ipv4.ip_forward;rm", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key starts with a short sysctl option", () => {
    expect(() => sysctl.set("-w", VALUE)).toThrow(/key must match/v)
  })

  it("throws when key starts with a long sysctl option", () => {
    expect(() => sysctl.set("--system", VALUE)).toThrow(/key must match/v)
  })

  it("throws when value contains a newline", () => {
    expect(() => sysctl.set(KEY, "1\nkernel.hostname = pwned")).toThrow(
      /value must not contain newline/v
    )
  })

  it("throws when value contains a carriage return", () => {
    expect(() => sysctl.set(KEY, "1\rinjected")).toThrow(/value must not contain newline/v)
  })

  it("accepts a key with dots, underscores, hyphens, and digits", () => {
    expect(() => sysctl.set("net.ipv4.tcp_rmem-max_v2", "4096 87380 6291456")).not.toThrow()
  })
})

describe("sysctl.set — dry-run diff", () => {
  it("declares itself as a dry-run diff producer", () => {
    const mod = sysctl.set(KEY, VALUE)
    expect(mod._dryRunDiffProducer).toBe(true)
    expect(typeof mod._applyDryRun).toBe("function")
  })

  it("_applyDryRun returns a key-value diff between live and desired value", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod._applyDryRun!(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toBe(`-${KEY} = 0\n+${KEY} = 1`)
  })

  it("_applyDryRun renders the insert when the live key is unset", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 1, stderr: `sysctl: cannot stat /proc/sys/${KEY}` },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod._applyDryRun!(mockSsh, emptyEnv)
    expect(result.diff).toBe(`+${KEY} = 1`)
  })

  it("_applyDryRun surfaces the error code via _dryRunDetail when the probe throws", async () => {
    // R-0001018: the catch in buildSysctlDryRunResult previously swallowed
    // every exception silently. Force the inner exec to throw an Error with a
    // `code` property and assert the detail is surfaced.
    const mockSsh = createMockSsh()
    mockSsh.exec = async () => {
      const error = new Error("broken pipe") as Error & { code: string }
      error.code = "EPIPE"
      throw error
    }
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod._applyDryRun!(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.diff).toBeUndefined()
    expect(result._dryRunDetail).toBe("(dry-run, diff unavailable: EPIPE)")
  })
})
