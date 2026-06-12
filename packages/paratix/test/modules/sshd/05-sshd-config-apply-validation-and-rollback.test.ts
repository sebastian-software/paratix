/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(
    // R-0000613: the flag-lock holder marker uses `ssh.output("hostname")`;
    // stub the lookup with an empty string so the printf form matches the
    // default flag-lock allow list.
    { hostname: { code: 0, stdout: "" }, ...responses },
    {
      ...options,
      // R-0000613: sshd.config and sshd.port apply paths now serialise through
      // a shared `/etc/ssh/sshd_config` mutex; opt into the default flag-lock
      // internal stubs so the tests do not need to spell out every mkdir/rmdir.
      allowFlagLockInternalDefaults: true,
      allowWrites: [
        // R-0000587: dry-run tempfiles carry restrictive 0600 permissions.
        { options: { mode: "0600" }, remotePath: /^\/tmp\/paratix-sshd-dry-run\./v },
        ...(options?.allowWrites ?? []),
      ],
      responseStubs: [
        // R-0000613: the holder-printf shell command writes the lock marker
        // file; the mutex helper invokes it after the hostname lookup.
        {
          command: /^printf '%s@%s %s\\n' "\$\$" '' "\$\(date \+%s\)" > \S+\/holder$/v,
          result: { code: 0 },
        },
        { command: "mkdir -p '/run/sshd'", result: { code: 0 } },
        { command: "sshd -t", result: { code: 0 } },
        // R-0000766: allocateProspectiveSshdConfigPath allocates the dry-run
        // path via `mktemp -p /tmp -- paratix-sshd-dry-run.XXXXXX`.
        {
          command: "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'",
          result: { code: 0, stdout: "/tmp/paratix-sshd-dry-run.ABCDEF" },
        },
        // R-0000539: validateProspectiveSshdConfig writes a temp file and
        // validates it with `sshd -t -f <UUID>.conf` before overwriting the
        // live config.
        {
          command: /^sshd -t -f '\/tmp\/paratix-sshd-dry-run\.[^']+'$/v,
          result: { code: 0 },
        },
        { command: SYSTEMCTL_CAT_SSHD, result: { code: 0 } },
        { command: SYSTEMCTL_CAT_SSH, result: { code: 1 } },
        { command: "systemctl is-enabled --quiet sshd.service", result: { code: 0 } },
        { command: "systemctl is-enabled --quiet ssh.service", result: { code: 0 } },
        // R-0000496: sshd.config probes for ExecReload before reloading.
        {
          command: "systemctl cat 'sshd' | grep -E '^ExecReload='",
          result: { code: 0, stdout: "ExecReload=/bin/kill -HUP $MAINPID\n" },
        },
        {
          command: "systemctl cat 'ssh' | grep -E '^ExecReload='",
          result: { code: 0, stdout: "ExecReload=/bin/kill -HUP $MAINPID\n" },
        },
        { command: "systemctl reload sshd", result: { code: 0 } },
        { command: "systemctl reload ssh", result: { code: 0 } },
        { command: "systemctl reload-or-restart sshd", result: { code: 0 } },
        { command: "systemctl reload-or-restart ssh", result: { code: 0 } },
        // R-0000492: socket-state probes no longer use shell redirects.
        // R-0000608: `captureSshSocketState` now probes both `ssh.socket`
        // (Debian/Ubuntu) and `sshd.socket` (Fedora/RHEL); both default-miss
        // here so the default Debian/Ubuntu service-restart path stays
        // selected.
        { command: "systemctl cat ssh.socket", result: { code: 1 } },
        { command: "systemctl cat sshd.socket", result: { code: 1 } },
        { command: "systemctl is-enabled --quiet ssh.socket", result: { code: 1 } },
        { command: "systemctl is-active --quiet ssh.socket", result: { code: 1 } },
        { command: "systemctl is-enabled --quiet sshd.socket", result: { code: 1 } },
        { command: "systemctl is-active --quiet sshd.socket", result: { code: 1 } },
        { command: "systemctl disable --now ssh.socket", result: { code: 0 } },
        { command: "systemctl disable --now sshd.socket", result: { code: 0 } },
        { command: "systemctl enable --now ssh.socket", result: { code: 0 } },
        { command: "systemctl enable --now sshd.socket", result: { code: 0 } },
        { command: "systemctl restart sshd", result: { code: 0 } },
        { command: /^rm -f '\/tmp\/paratix-sshd-dry-run\..+'$/v, result: { code: 0 } },
        ...(options?.responseStubs ?? []),
      ],
    }
  )

const emptyEnv = {}
const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`
const SSHD_T = "sshd -T"
// R-0000492: shell redirects removed from resolveSshServiceUnit.
const SYSTEMCTL_CAT_SSH = "systemctl cat ssh.service"
const SYSTEMCTL_CAT_SSHD = "systemctl cat sshd.service"

function trackWriteFile(
  mockSsh: ReturnType<typeof createMockSsh>
): Array<{ content: string; path: string }> {
  const writtenFiles: Array<{ content: string; path: string }> = []
  // eslint-disable-next-line @typescript-eslint/promise-function-async -- vi.mockImplementation requires matching return type
  vi.spyOn(mockSsh, "writeFile").mockImplementation((path: string, content: string) => {
    writtenFiles.push({ content, path })
    return Promise.resolve()
  })
  return writtenFiles
}

// R-0000613: sshd.config now serialises through a shared `/etc/ssh/sshd_config`
// mutex; tests using a strict `mockResolvedValueOnce` sequence need to skip the
// mutex bookkeeping commands so the queue stays aligned with the production
// domain calls being asserted.
const MUTEX_BOOKKEEPING_PATTERNS_05: RegExp[] = [
  /^mkdir -p \/var\/lib\/paratix\/flags$/v,
  /^mkdir \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'$/v,
  /^rmdir -- \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'$/v,
  /^rm -f -- \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'\/holder$/v,
  /^printf '%s@%s %s\\n' "\$\$" '[^']*' "\$\(date \+%s\)" > \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'\/holder$/v,
  // R-0000634: acquire reads back the holder token via `ssh.output`; release
  // is now a single atomic shell statement (ownership check + marker remove
  // + rmdir).
  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  /^awk 'NR==1\{print \$1\}' '\/var\/lib\/paratix\/flags\/[\w.\-]+-mutex\/holder'$/v,
  /^awk_token=\$\(awk 'NR==1\{print \$1\}' '\/var\/lib\/paratix\/flags\/[\w.\-]+-mutex\/holder' 2>\/dev\/null\); awk_status=\$\?; \[ "\$awk_status" = 0 \] && \[ "x\$awk_token" = 'x[^']*' \] && rm -f -- \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'\/holder && rmdir -- \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'$/v,
  /^if \[ -d \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex' \]/v,
  /^i=0; while \[ -d \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex' \]/v,
  /^hostname$/v,
]

function isMutexBookkeepingCommand05(command: string): boolean {
  return MUTEX_BOOKKEEPING_PATTERNS_05.some((pattern) => pattern.test(command))
}

type ScriptedExecStep05 =
  | { code: number; stderr?: string; stdout?: string }
  | { kind: "reject"; reason: Error }

type ScriptedExecHarness05 = {
  assertConsumed: () => void
  exec: ReturnType<typeof createMockSsh>["exec"]
}

function buildMutexAwareExecSequence05(
  steps: readonly ScriptedExecStep05[]
): ScriptedExecHarness05 {
  let cursor = 0
  const exec: ReturnType<typeof createMockSsh>["exec"] = async (command) => {
    if (isMutexBookkeepingCommand05(command)) {
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "" }
    }
    // R-0000766: route the dry-run mktemp call to a fixed stub path so the
    // step cursor only advances over production-domain calls and the
    // validateProspectiveSshdConfig pipeline still gets a usable path.
    if (command === "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'") {
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "/tmp/paratix-sshd-dry-run.ABCDEF" }
    }
    if (cursor >= steps.length) {
      throw new Error(`Unexpected exec command after scripted sequence was consumed: ${command}`)
    }
    const step = steps[cursor]
    cursor += 1
    if ("kind" in step) {
      await Promise.resolve()
      throw step.reason
    }
    await Promise.resolve()
    return { code: step.code, stderr: step.stderr ?? "", stdout: step.stdout ?? "" }
  }
  return {
    assertConsumed() {
      expect(cursor).toBe(steps.length)
    },
    exec,
  }
}

// R-0000766: route the dry-run mktemp call to a fixed stub path so the
// validateProspectiveSshdConfig pipeline can proceed.
const SSHD_DRY_RUN_MKTEMP = "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'"
const SSHD_DRY_RUN_TEMP_PATH = "/tmp/paratix-sshd-dry-run.ABCDEF"

function mockSshdDryRunExecSuccess(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (command === SSHD_DRY_RUN_MKTEMP) {
      return { code: 0, stderr: "", stdout: SSHD_DRY_RUN_TEMP_PATH }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
}

function mockSshdDryRunExecValidationFailure(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (command === SSHD_DRY_RUN_MKTEMP) {
      return { code: 0, stderr: "", stdout: SSHD_DRY_RUN_TEMP_PATH }
    }
    if (command.startsWith("sshd -t -f ")) {
      return { code: 1, stderr: "Bad configuration option", stdout: "" }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
}

// R-0000539: helper for the failing-dry-run interceptor — kept outside the test
// body so the conditional branching satisfies vitest's no-conditional-in-test.
function createDryRunFailingExec(
  mockSsh: ReturnType<typeof createMockSsh>,
  originalExec: typeof mockSsh.exec,
  dryRunFailPattern: RegExp
): typeof mockSsh.exec {
  return async (command, options) => {
    if (dryRunFailPattern.test(command)) {
      mockSsh.calls.push(command)
      return { code: 1, stderr: "sshd: bad config", stdout: "" }
    }
    return originalExec(command, options)
  }
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

describe("sshd.config — apply: validation and rollback", () => {
  // R-0000539: validate prospective sshd_config in a tempfile BEFORE overwriting
  // the live config. When `sshd -t -f <tmp>` fails, the live /etc/ssh/sshd_config
  // is never touched and no rollback is needed.
  it("rolls back to original config and returns failed when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: place the failing dry-run stub in responses (exact string key would not work
    // for dynamic UUID paths), so use a custom exec interceptor that fails only for the
    // prospective-validation command and forwards everything else to the stub-based handler.
    const dryRunFailPattern = /^sshd -t -f '\/tmp\/paratix-sshd-dry-run\./v
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    // Capture the original stub-based exec before overriding.
    const originalExec = mockSsh.exec.bind(mockSsh)
    const execSpy = vi
      .spyOn(mockSsh, "exec")
      .mockImplementation(createDryRunFailingExec(mockSsh, originalExec, dryRunFailPattern))

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config validation failed")

    // The live config must NEVER have been touched — no rollback write needed.
    expect(writtenFiles.filter((f) => f.path === SSHD_CONFIG)).toHaveLength(0)
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  // R-0000539: "rollback also failed" now occurs when the live-config write
  // fails AND the subsequent rollback write also fails (not when sshd -t fails,
  // since the new flow validates in a tempfile before the live write).
  it("returns failed with rollback note when both validation and rollback write fail", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const newConfig = "PasswordAuthentication no"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // R-0000539: readFile sequence — initial read, guard read (guardedWriteFile),
    // and rollback check read. The rollback check must see the newContent so the
    // rollback write path is entered (simulates a partial SFTP write that committed
    // the new content before the connection dropped).
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdConfig
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
      .mockResolvedValueOnce(newConfig) // rollback check: current == newConfig → rollback
    // writeFile sequence: tmpfile (dry-run), live SSHD_CONFIG (fails), rollback (fails).
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockRejectedValueOnce(new Error("SFTP write failed")) // live config write fails
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
  })

  it("rolls back and returns failed when the initial config write reports failure after remote replacement", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const newConfig = "PasswordAuthentication no"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdConfig
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
      .mockResolvedValueOnce(newConfig) // rollback check: current == newConfig → rollback
    // R-0000539: first writeFile is the temp file for prospective validation (succeeds),
    // second is the live SSHD_CONFIG write (fails), third is the rollback write (succeeds).
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write succeeds
      .mockRejectedValueOnce(new Error("SFTP write failed")) // live config write fails
      .mockResolvedValueOnce(undefined) // rollback write succeeds
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("SFTP write failed")
    // The live config writes: first fails, second is the rollback.
    // Filter out the tmpfile write (dynamic UUID path) to check only live config writes.
    const liveConfigWrites = writeFileSpy.mock.calls.filter(([path]) => path === SSHD_CONFIG)
    expect(liveConfigWrites).toStrictEqual([
      [SSHD_CONFIG, newConfig, { mode: "0644" }],
      [SSHD_CONFIG, originalConfig, { mode: "0644" }],
    ])
    // R-0000539: plain `sshd -t` is never called; validation uses `sshd -t -f <tmpfile>`.
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("sshd -t")
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  it("writes new config and reloads sshd without rollback when validation succeeds", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: createMockSsh responseStubs handle all exec calls including the
    // dry-run `sshd -t -f <tmpfile>` and cleanup `rm -f <tmpfile>` with dynamic UUIDs.
    const mockSsh = createMockSsh(
      { [CAT_SSHD]: { stdout: originalConfig } },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // R-0000539: validateProspectiveSshdConfig writes a tmpfile before the live config.
    // Filter to SSHD_CONFIG writes only: expect exactly one (the new config, no rollback).
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites).toHaveLength(1)
    expect(liveConfigWrites[0]?.content).toContain("PasswordAuthentication no")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    // Core operations must still be executed in the correct order.
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe and reload action must follow.
    expect(execCommands).toContain("systemctl cat 'sshd' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload sshd")
    // Dry-run temp file must have been cleaned up.
    expect(execCommands.some((cmd) => cmd.startsWith("rm -f '/tmp/paratix-sshd-dry-run."))).toBe(
      true
    )
  })

  it("rolls back and returns failed when sshd -T reports an included override after validation", async () => {
    const originalConfig = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes"
    // R-0000539: responseStubs handle exec calls including the dry-run tempfile validation.
    // sshd -T returns the overriding value ("yes") to trigger the effective-config mismatch.
    const mockSsh = createMockSsh(
      { [CAT_SSHD]: { stdout: originalConfig } },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication yes\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("effective sshd configuration does not match")
    // Last write must be the rollback to the original config.
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // No reload because effective config check failed.
    expect(execCommands).not.toContain("systemctl reload sshd")
  })

  it("returns failed when sshd reload fails after successful validation", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: responseStubs handle exec calls including dry-run tempfile validation.
    // R-0000616: after the failed reload + rollback write the module triggers
    // a second `systemctl reload sshd` so the daemon reverts to the original
    // config on disk. Wrap the real mock-exec with a call counter so the first
    // reload fails and the second one succeeds.
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: originalConfig },
      },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    // R-0000616: scripted queue so the first `systemctl reload sshd` call
    // surfaces the original reload failure and the second one (the
    // post-rollback reload introduced by R-0000616) succeeds. Wrapping the
    // dispatch inside the spy implementation is the canonical pattern for
    // command-specific overrides in this file; oxlint's
    // `vitest/no-conditional-in-test` flags the necessary branch — disable
    // it locally rather than reshape the dispatch into a parallel test case.
    const reloadResults: Array<{ code: number; stderr: string; stdout: string }> = [
      { code: 1, stderr: "reload failed", stdout: "" },
      { code: 0, stderr: "", stdout: "" },
    ]
    /* oxlint-disable vitest/no-conditional-in-test -- command dispatch is the test fixture, not test logic */
    const execSpy = vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
      const queued = command === "systemctl reload sshd" ? reloadResults.shift() : undefined
      return queued ?? originalExec(command, options)
    })
    /* oxlint-enable vitest/no-conditional-in-test */

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe must run before the reload action.
    expect(execCommands).toContain("systemctl cat 'sshd' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload sshd")
    // R-0000616: the post-rollback reload must run a second time after the
    // rollback write so sshd actually picks up the restored config.
    const reloadCalls = execCommands.filter((cmd) => cmd === "systemctl reload sshd")
    expect(reloadCalls).toHaveLength(2)
    // Last write: rollback to original config after reload failure.
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
  })

  it("falls back to ssh.service for reload on Ubuntu-style systems", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: responseStubs handle all exec calls including the dry-run tempfile validation.
    // SYSTEMCTL_CAT_SSHD is set via responses (highest priority) to fail (code 1),
    // forcing fallback to ssh.service. ExecReload probe for ssh returns empty stdout
    // so the module uses `reload-or-restart` instead of `reload`.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
      // sshd -T returns match so that effective config check passes.
      "sshd -T": { code: 0, stdout: "passwordauthentication no\n" },
      // Responses take priority over responseStubs; override service unit probes:
      // sshd.service fails → forces fallback to ssh.service which succeeds.
      [SYSTEMCTL_CAT_SSH]: { code: 0 },
      [SYSTEMCTL_CAT_SSHD]: { code: 1 },
      // R-0000496: override ExecReload probe for ssh to return empty stdout
      // → sshdUnitDefinesExecReload returns false → action becomes reload-or-restart.
      "systemctl cat 'ssh' | grep -E '^ExecReload='": { code: 0, stdout: "" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSH)
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe runs; with no ExecReload directive the
    // module falls back to `reload-or-restart`.
    expect(execCommands).toContain("systemctl cat 'ssh' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload-or-restart ssh")
    expect(result.status).toBe("changed")
  })

  it("returns failed without writing config when neither sshd.service nor ssh.service exists", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    const execSequence = buildMutexAwareExecSequence05([{ code: 1 }, { code: 1 }])
    execSpy.mockImplementation(execSequence.exec)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("could not find a systemd SSH service unit")
    expect(writtenFiles).toHaveLength(0)
    // R-0000613: filter mutex bookkeeping commands so the strict ordering
    // assertion sees only the domain calls.
    const domainCommands = execSpy.mock.calls
      .map((args) => args[0])
      .filter((cmd) => !isMutexBookkeepingCommand05(cmd))
    expect(domainCommands).toStrictEqual([SYSTEMCTL_CAT_SSHD, SYSTEMCTL_CAT_SSH])
    execSequence.assertConsumed()
  })

  // R-0000621: when the original reload fails and the rollback path lands on
  // a unit without `ExecReload=`, the post-rollback reload must NOT fall back
  // to `reload-or-restart` (the fallback would kill the live SSH session as a
  // side-effect of an unattended rollback). The module surfaces a manual
  // `systemctl restart sshd` instruction instead.
  it("R-0000621: surfaces manual restart when post-rollback reload has no ExecReload", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // Unit has no ExecReload: `sshdUnitDefinesExecReload` returns false during
    // both the apply-time reload AND the post-rollback reload. The apply-time
    // `reloadSshd` falls back to `reload-or-restart`; we make that fail so the
    // rollback path triggers. The post-rollback reload (my fix) must NOT fall
    // back to `reload-or-restart` and must surface a manual-restart message.
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: originalConfig },
        // Unit has no ExecReload — the rollback path must refuse the
        // reload-or-restart fallback rather than risk killing the session.
        "systemctl cat 'sshd' | grep -E '^ExecReload='": { code: 0, stdout: "" },
        // Apply-time `reload-or-restart` fails → rollback path runs.
        "systemctl reload-or-restart sshd": { code: 1, stderr: "reload-or-restart failed" },
      },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // The rollback write itself must have landed.
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
    // The error must surface the manual-restart instruction instead of the
    // session-killing `reload-or-restart` fallback.
    expect(result.error?.message).toContain("manual `systemctl restart sshd` is required")
    expect(result.error?.message).toContain("rolled back on disk")
    // Critically: the dangerous `reload-or-restart` action must run only once
    // (the apply-time reload that triggered the rollback), never again from
    // the post-rollback reload path.
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    const reloadOrRestartCalls = execCommands.filter(
      (cmd) => cmd === "systemctl reload-or-restart sshd"
    )
    expect(reloadOrRestartCalls).toHaveLength(1)
  })

  // R-0000284: a reload failure followed by a failing rollback writeFile
  // (e.g. SFTP error) must surface a combined error that names both causes.
  // Without the try/catch the rollback exception bubbled up and masked the
  // original reload diagnostic.
  it("R-0000284: combines reload failure with rollback writeFile failure in the error message", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: responseStubs handle exec calls including dry-run tempfile validation.
    // Override reload to fail via responses (highest priority over responseStubs defaults).
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: originalConfig },
        // Responses take priority; override reload to fail.
        "systemctl reload sshd": { code: 1, stderr: "reload failed" },
      },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    // R-0000539: tmpfile write (call 1) and new config write (call 2) succeed;
    // rollback write (call 3) fails.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockResolvedValueOnce(undefined) // live config write succeeds
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd reload failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
  })
})

// ─── sshd.port — apply ────────────────────────────────────────────────────────
