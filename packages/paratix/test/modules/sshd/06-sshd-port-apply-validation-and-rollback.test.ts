/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { isSshdPortMetaEntry } from "../../../src/meta.js"
import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const ssh = createBaseMockSsh(
    // R-0000613: the flag-lock holder marker uses `ssh.output("hostname")`;
    // stub the lookup with an empty string so the printf form matches the
    // default flag-lock allow list.
    { hostname: { code: 0, stdout: "" }, ...responses },
    {
      ...options,
      // R-0000613: sshd.port apply paths now serialise through a shared
      // `/etc/ssh/sshd_config` mutex; opt into the default flag-lock internal
      // stubs so the tests do not need to spell out every mkdir/rmdir.
      allowFlagLockInternalDefaults: true,
      allowWrites: [
        // R-0000587: dry-run tempfiles carry restrictive 0600 permissions.
        { options: { mode: "0600" }, remotePath: /^\/tmp\/paratix-sshd-dry-run-/v },
        ...(options?.allowWrites ?? []),
      ],
      responseStubs: [
        ...(options?.responseStubs ?? []),
        // R-0000613: the holder-printf shell command writes the lock marker
        // file; the mutex helper invokes it after the hostname lookup.
        {
          command: /^printf '%s@%s %s\\n' "\$\$" '' "\$\(date \+%s\)" > \S+\/holder$/v,
          result: { code: 0 },
        },
        { command: "ufw status", result: { stdout: "Status: inactive" } },
        { command: "mkdir -p '/run/sshd'", result: { code: 0 } },
        { command: "sshd -t", result: { code: 0 } },
        // R-0000539: validateProspectiveSshdConfig writes a temp file and
        // validates it with `sshd -t -f <UUID>.conf` before overwriting the
        // live config.
        {
          command: /^sshd -t -f '\/tmp\/paratix-sshd-dry-run-[^']+\.conf'$/v,
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
        { command: /^rm -f '\/tmp\/paratix-sshd-dry-run-.+\.conf'$/v, result: { code: 0 } },
        // R-0000283: default the post-restart live verify to "listener
        // present" so existing fixtures keep passing. Tests that exercise the
        // missing listener path stub `ss` explicitly with a non-zero exit.
        {
          command: /^ss -H -ltnp 'sport = :\d+'$/v,
          result: {
            code: 0,
            stdout: 'LISTEN 0 128 0.0.0.0:2222 users:(("sshd",pid=1,fd=3))\n',
          },
        },
      ],
    }
  )
  vi.spyOn(ssh, "getConnectionInfo").mockReturnValue({
    ...ssh.getConnectionInfo(),
    configuredPorts: [22, 2222],
  })
  return ssh
}

const emptyEnv = {}
const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`
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

// R-0000283: post-restart live verify probes `ss -H -ltnp 'sport = :<port>'`.
// Tests that bulk-mock exec to `code: 0, stdout: ""` need a stand-in stdout for
// these probes so `liveSshdPortMatches` returns true and the verify loop exits
// instead of polling until timeout.
const SS_PROBE_PATTERN = /^ss -H -ltnp 'sport = :\d+'$/v
const SS_PROBE_LISTENING_STDOUT = 'LISTEN 0 128 0.0.0.0:0 users:(("sshd",pid=1,fd=3))\n'

type ExecSpy = {
  mockImplementation: (impl: ReturnType<typeof createMockSsh>["exec"]) => unknown
} & ReturnType<typeof createMockSsh>["exec"]

function mockExecResolvedValue(
  execSpy: ExecSpy,
  result: { code: number; stderr?: string; stdout?: string }
) {
  execSpy.mockImplementation(async (command) => {
    await Promise.resolve()
    if (SS_PROBE_PATTERN.test(command) && result.code === 0) {
      return { code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT }
    }
    return { code: result.code, stderr: result.stderr ?? "", stdout: result.stdout ?? "" }
  })
}

function buildExecWithSsOverride(
  originalExec: ReturnType<typeof createMockSsh>["exec"],
  ssResponse: { code: number; stderr?: string; stdout?: string }
): ReturnType<typeof createMockSsh>["exec"] {
  return async (command, options) => {
    if (!SS_PROBE_PATTERN.test(command)) return originalExec(command, options)
    await Promise.resolve()
    return {
      code: ssResponse.code,
      stderr: ssResponse.stderr ?? "",
      stdout: ssResponse.stdout ?? "",
    }
  }
}

// R-0000613: sshd.config/sshd.port apply paths acquire the
// `/etc/ssh/sshd_config` mutex via `withMutexLock` before reading any
// domain-specific files. Tests that drive the exec spy through a strict
// `mockResolvedValueOnce` queue need to skip those mutex bookkeeping calls so
// the queue stays aligned with the production logic the test is actually
// asserting against. Pattern set mirrors `mockSshFlagLock.isFlagLockInternalSuccessCommand`.
const MUTEX_BOOKKEEPING_PATTERNS: RegExp[] = [
  /^mkdir -p \/var\/lib\/paratix\/flags$/v,
  /^mkdir \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'$/v,
  /^rmdir \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'$/v,
  /^rm -f \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'\/holder$/v,
  /^printf '%s@%s %s\\n' "\$\$" '[^']*' "\$\(date \+%s\)" > \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex'\/holder$/v,
  /^if \[ -d \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex' \]/v,
  /^i=0; while \[ -d \/var\/lib\/paratix\/flags\/'[\w.\-]+-mutex' \]/v,
  /^hostname$/v,
]

function isMutexBookkeepingCommand(command: string): boolean {
  return MUTEX_BOOKKEEPING_PATTERNS.some((pattern) => pattern.test(command))
}

// R-0000613: build an exec implementation that consumes the mutex bookkeeping
// commands with a default success result and dispatches every other call to a
// scripted sequence. Mirrors the historic `mockResolvedValueOnce` shape so
// existing tests can describe their domain-call sequence without counting the
// new mutex acquire/release commands.
type ScriptedExecStep =
  | { code: number; stderr?: string; stdout?: string }
  | { kind: "reject"; reason: Error }

function buildMutexAwareExecSequence(
  steps: readonly ScriptedExecStep[]
): ReturnType<typeof createMockSsh>["exec"] {
  let cursor = 0
  return async (command) => {
    if (isMutexBookkeepingCommand(command)) {
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "" }
    }
    const step = steps[cursor] ?? { code: 0, stderr: "", stdout: "" }
    cursor += 1
    if ("kind" in step) {
      await Promise.resolve()
      throw step.reason
    }
    await Promise.resolve()
    return { code: step.code, stderr: step.stderr ?? "", stdout: step.stdout ?? "" }
  }
}

function buildSequencedSsProbeExec(
  originalExec: ReturnType<typeof createMockSsh>["exec"],
  responses: ReadonlyArray<{ code: number; stderr?: string; stdout?: string }>
): ReturnType<typeof createMockSsh>["exec"] {
  let callIndex = 0
  return async (command, options) => {
    if (!SS_PROBE_PATTERN.test(command)) {
      return originalExec(command, options)
    }
    const response = responses[Math.min(callIndex, responses.length - 1)] ?? { code: 0 }
    callIndex += 1
    await Promise.resolve()
    return { code: response.code, stderr: response.stderr ?? "", stdout: response.stdout ?? "" }
  }
}

function mockSshdDryRunExecSuccess(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (SS_PROBE_PATTERN.test(command)) {
      return { code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
}

function mockSshdDryRunExecValidationFailure(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi
    .spyOn(mockSsh, "exec")
    .mockImplementationOnce(async (command) => {
      mockSsh.calls.push(command)
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "" }
    })
    .mockImplementationOnce(async (command) => {
      mockSsh.calls.push(command)
      await Promise.resolve()
      return { code: 1, stderr: "Bad configuration option", stdout: "" }
    })
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

describe("sshd.port — apply: validation and rollback", () => {
  it("fails before validation or restart when target port is not statically configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      ...mockSsh.getConnectionInfo(),
      configuredPorts: [22],
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("static ssh.ports")
    expect(writtenFiles).toHaveLength(0)
    expect(execSpy).not.toHaveBeenCalled()
  })

  // R-0000539: validation now runs in a temp file BEFORE writing the live config.
  // When `sshd -t -f <tmpfile>` fails, `/etc/ssh/sshd_config` is never touched —
  // no rollback write is needed.
  it("returns failed without writing live config when sshd -t -f fails", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only. mkdir -p /run/sshd succeeds (dry-run),
    // then sshd -t -f <tmpfile> fails.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 1, stderr: "sshd: invalid port" }, // sshd -t -f
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config validation failed")

    // R-0000539: live config is never touched when validation fails pre-write.
    // Only the tmpfile write happened; no SSHD_CONFIG write at all.
    expect(writtenFiles.filter((f) => f.path === SSHD_CONFIG)).toHaveLength(0)

    // systemctl restart must NOT have been called
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("rolls back and returns failed when the initial port write reports failure after remote replacement", async () => {
    const originalConfig = "Port 22"
    const newConfig = "Port 2222"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // R-0000539: readFile sequence — initial read, guard read (guardedWriteFile),
    // rollback check read. Rollback check sees newContent so rollback write is triggered.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
      .mockResolvedValueOnce(newConfig) // rollback check: current == newConfig → rollback
    // R-0000539: writeFile sequence: tmpfile (dry-run), live SSHD_CONFIG (fails), rollback.
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockRejectedValueOnce(new Error("SFTP write failed")) // live config write fails
      .mockResolvedValueOnce(undefined) // rollback write succeeds
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("SFTP write failed")
    // Filter out the tmpfile write (dynamic UUID path); check only live config writes.
    const liveConfigWrites = writeFileSpy.mock.calls.filter(([path]) => path === SSHD_CONFIG)
    expect(liveConfigWrites).toStrictEqual([
      [SSHD_CONFIG, newConfig, { mode: "0644" }],
      [SSHD_CONFIG, originalConfig, { mode: "0644" }],
    ])
    // R-0000539: plain `sshd -t` is never called; validation uses `sshd -t -f <tmpfile>`.
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("sshd -t")
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
  })

  it("writes new port config and restarts sshd when sshd -t succeeds", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    // All exec calls succeed: sshd -t -f <tmpfile> passes (dry-run), systemctl restart runs.
    mockExecResolvedValue(execSpy, { code: 0 })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSshdPortMetaEntry)?.port).toBe(2222)
    // R-0000539: validateProspectiveSshdConfig writes a tmpfile before the live config.
    // Filter to SSHD_CONFIG writes only: expect exactly one (no rollback).
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites).toHaveLength(1)
    expect(liveConfigWrites[0]?.content).toContain("Port 2222")

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("mkdir -p '/run/sshd'")
    // R-0000492: socket-state probes no longer use shell redirects.
    expect(execCommands).toContain("systemctl cat ssh.socket")
    expect(execCommands).toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl restart sshd")
    expect(addPortSpy).toHaveBeenCalledWith(2222)
  })

  it("disables ssh.socket before restarting sshd on socket-activated hosts", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    mockExecResolvedValue(execSpy, { code: 0 })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const socketDisableIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl disable --now ssh.socket"
    )
    const restartIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl restart sshd"
    )

    expect(socketDisableIndex).toBeGreaterThanOrEqual(0)
    expect(restartIndex).toBeGreaterThan(socketDisableIndex)
  })

  it("enables the SSH service for boot when disabling an enabled ssh.socket", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    // R-0000539: spy on readFile to prevent exec from being called for guard reads,
    // which keeps the exec spy chain simple and aligned with real exec calls only.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 0 }, // ssh.socket exists
        { code: 0 }, // ssh.socket enabled
        { code: 0 }, // ssh.socket active
        { code: 0 }, // disable --now ssh.socket
        { code: 0 }, // sshd.service exists
        { code: 1 }, // sshd.service disabled
        { code: 0 }, // enable sshd.service
        { code: 0 }, // restart sshd
        { code: 0, stdout: SS_PROBE_LISTENING_STDOUT }, // ss probe
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl enable sshd.service")
  })

  // R-0000608: Fedora/RHEL ship socket activation as `sshd.socket` rather than
  // the Debian/Ubuntu `ssh.socket`. The capture/restore helpers must follow the
  // resolved unit name through enable/disable so socket-state rollback actually
  // restores the unit that was present on the host.
  it("R-0000608: disables sshd.socket before restarting sshd on Fedora-style hosts", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // systemctl cat ssh.socket → miss
        { code: 0 }, // systemctl cat sshd.socket → hit
        { code: 0 }, // is-enabled sshd.socket
        { code: 0 }, // is-active sshd.socket
        { code: 0 }, // disable --now sshd.socket
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service is-enabled
        { code: 0 }, // systemctl restart sshd
        { code: 0, stdout: SS_PROBE_LISTENING_STDOUT }, // ss probe
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl cat sshd.socket")
    expect(execCommands).toContain("systemctl disable --now sshd.socket")
    expect(execCommands).not.toContain("systemctl disable --now ssh.socket")
    const disableIndex = execCommands.indexOf("systemctl disable --now sshd.socket")
    const restartIndex = execCommands.indexOf("systemctl restart sshd")
    expect(disableIndex).toBeGreaterThanOrEqual(0)
    expect(restartIndex).toBeGreaterThan(disableIndex)
  })

  // R-0000608: when the Fedora/RHEL `sshd.socket` rollback fires after a failed
  // restart, the restore call must use the resolved unit name (`sshd.socket`).
  // The previous hard-coded `systemctl enable --now ssh.socket` would no-op on
  // such hosts and silently leave socket activation disabled across reboots.
  it("R-0000608: restores sshd.socket on rollback when restart fails on Fedora-style hosts", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // systemctl cat ssh.socket → miss
        { code: 0 }, // systemctl cat sshd.socket → hit
        { code: 0 }, // is-enabled sshd.socket
        { code: 0 }, // is-active sshd.socket
        { code: 0 }, // disable --now sshd.socket
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service is-enabled
        { kind: "reject", reason: new Error("systemctl restart sshd failed") }, // restart sshd fails
        { code: 0 }, // enable --now sshd.socket (restore)
        { code: 0 }, // restart sshd (best-effort restore)
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl disable --now sshd.socket")
    expect(execCommands).toContain("systemctl enable --now sshd.socket")
    expect(execCommands).not.toContain("systemctl enable --now ssh.socket")
    expect(writtenFiles.at(-1)?.content).toBe(originalConfig)
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
  })

  it("keeps the previous restart path when ssh.socket does not exist", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    // R-0000539: spy on readFile to prevent exec from being called for guard reads.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { code: 0 }, // restart sshd
        { code: 0, stdout: SS_PROBE_LISTENING_STDOUT }, // ss probe
      ])
    )

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000492: socket-state probes no longer use shell redirects.
    expect(execCommands).toContain("systemctl cat ssh.socket")
    expect(execCommands).not.toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("creates /run/sshd before sshd -t during first port bootstrap validation", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    // R-0000539: spy on readFile so exec is not called for internal guard reads,
    // making exec call ordering assertions independent of cat readFile calls.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    mockExecResolvedValue(execSpy, { code: 0 })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: dry-run validation uses `sshd -t -f <tmpfile>` (not plain `sshd -t`).
    // mkdir -p '/run/sshd' must run immediately before `sshd -t -f`.
    // R-0000613: filter mutex bookkeeping commands so the ordering assertion
    // sees only the domain calls.
    const firstDomainCommand = execCommands.find((cmd) => !isMutexBookkeepingCommand(cmd))
    expect(firstDomainCommand).toBe("mkdir -p '/run/sshd'")
    const mkdirIndex = execCommands.indexOf("mkdir -p '/run/sshd'")
    const dryRunIndex = execCommands.findIndex((cmd) =>
      cmd.startsWith("sshd -t -f '/tmp/paratix-sshd-dry-run-")
    )
    expect(mkdirIndex).toBeGreaterThanOrEqual(0)
    expect(dryRunIndex).toBeGreaterThan(mkdirIndex)
    // Plain `sshd -t` must not be called directly.
    expect(execCommands).not.toContain("sshd -t")
  })

  it("returns ok and does not write when the desired port is already configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      "ss -H -ltnp 'sport = :2222'": {
        code: 0,
        stdout: 'LISTEN 0 128 0.0.0.0:2222 users:(("sshd",pid=123,fd=3))\n',
      },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    // No write, no restart, no addPort — early return when config and live listener are correct
    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("ok")
    expect(result).not.toHaveProperty("meta")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
  })

  // R-0000612: the no-change apply path used to synthesise a rollback config
  // pinned to `originalPort` unconditionally. When `originalPort` is not part
  // of the static `configuredPorts` list, dialling it after a failed verify
  // would still lock the runner out — the rollback must therefore fall back
  // to the captured `originalConfig` and leave the listening port to the
  // operator's deployed config instead.
  it("R-0000612: rolls back to originalConfig when originalPort is not configured", async () => {
    // Config already has the target port; the live socket is not on it, so
    // the no-change apply path runs the restart + verify dance. Configure the
    // runner so `originalPort` (22) is NOT in the static `configuredPorts`
    // list — only the target port 2222 is — so the rollback must use the
    // captured `originalConfig` verbatim.
    const originalConfig = "Port 2222\n"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      ...mockSsh.getConnectionInfo(),
      configuredPorts: [2222],
      port: 22,
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("rolled back")
    // The rollback write must restore the captured `originalConfig` verbatim —
    // never a synthetic config pinning `originalPort` 22.
    expect(writtenFiles.at(-1)?.content).toBe(originalConfig)
    expect(writtenFiles.at(-1)?.content).not.toContain("Port 22\n")
  }, 10_000)

  it("restarts and emits reconnect meta when config matches but target port is not live", async () => {
    // R-0000283: live-verify probes `ss -H -ltnp` twice — once before the
    // restart (where the listener is not yet present) and once after (where
    // the post-restart verify confirms the listener is up). Use the sequenced
    // helper so the pre/post progression is explicit.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    const execSpy = vi
      .spyOn(mockSsh, "exec")
      .mockImplementation(
        buildSequencedSsProbeExec(originalExec, [
          { code: 1 },
          { code: 0, stdout: SS_PROBE_LISTENING_STDOUT },
        ])
      )
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSshdPortMetaEntry)?.port).toBe(2222)
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl restart sshd")
  })

  it("regression — addPort is called before systemctl restart sshd", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    mockExecResolvedValue(execSpy, { code: 0 })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const addPortOrder = addPortSpy.mock.invocationCallOrder[0]
    const restartCallIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl restart sshd"
    )
    const restartOrder = execSpy.mock.invocationCallOrder[restartCallIndex]

    expect(addPortOrder).toBeDefined()
    expect(restartOrder).toBeDefined()
    expect(addPortOrder).toBeLessThan(restartOrder)
  })

  it("regression — removes added port again when systemctl restart sshd fails with a real error", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only. sshd -t succeeds, then `systemctl restart
    // sshd` fails.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd
        { code: 0 }, // sshd -t
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { kind: "reject", reason: new Error("systemctl restart sshd failed") }, // systemctl restart
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writtenFiles.at(-1)?.content).toBe("Port 22")
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
  })

  it("restores config and ssh.socket when restart fails after disabling socket activation", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    // R-0000539: spy on readFile to prevent exec from being called for guard reads.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 0 }, // ssh.socket exists
        { code: 0 }, // ssh.socket enabled
        { code: 0 }, // ssh.socket active
        { code: 0 }, // disable --now ssh.socket
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { kind: "reject", reason: new Error("systemctl restart sshd failed") }, // systemctl restart fails
        { code: 0 }, // enable --now ssh.socket (restore)
        { code: 0 }, // systemctl restart sshd (restore)
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl enable --now ssh.socket")
    expect(execCommands.filter((command) => command === "systemctl restart sshd")).toHaveLength(2)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writtenFiles.at(-1)?.content).toBe(originalConfig)
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
  })

  it("regression — removes added port even when rollback writeFile fails after restart error", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // R-0000539: spy on readFile to prevent exec from being called for guard reads.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")
    // R-0000539: writeFile sequence: tmpfile (dry-run), new config (succeeds),
    // rollback (fails after restart error).
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run
      .mockResolvedValueOnce(undefined) // live config write succeeds
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { kind: "reject", reason: new Error("systemctl restart sshd failed") }, // restart fails
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
    // Even though the rollback writeFile threw, removePort must still have been called
    // so the runner reverts to the previous port instead of staying on the new one.
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  })

  it("reconnects and live-verifies the target port when restart aborts the SSH session", async () => {
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: "Port 22" },
      },
      { allowReconnect: true }
    )
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const reconnectSpy = vi.spyOn(mockSsh, "reconnect")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd
        { code: 0 }, // sshd -t
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { kind: "reject", reason: new Error("SSH connection closed unexpectedly") },
        { code: 0, stdout: SS_PROBE_LISTENING_STDOUT },
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result).toMatchObject({
      meta: [{ kind: "sshd.port", port: 2222 }],
      status: "changed",
    })
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(reconnectSpy).toHaveBeenCalledOnce()
    expect(removePortSpy).not.toHaveBeenCalled()
  })

  it("returns failed and removes the target port when reconnect after restart disconnect fails", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const reconnectError = new Error("reconnect refused")
    vi.spyOn(mockSsh, "reconnect").mockRejectedValue(reconnectError)
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd
        { code: 0 }, // sshd -t
        { code: 0 }, // rm -f <tmpfile>
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 0 }, // sshd.service exists
        { code: 0 }, // sshd.service enabled
        { kind: "reject", reason: new Error("ECONNRESET") },
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("before the target port could be verified")
    expect(result.error?.message).toContain("reconnect refused")
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  })

  // R-0000614: when the post-restart live-port verification fails the rollback
  // path must keep trying every step instead of bailing on the first failure.
  // Previously a transient sshd_config write error stopped the loop before
  // `restoreSshServiceBootState`, `restoreSocketActivatedSsh`, and the ssh
  // service restart ran — leaving socket-activated hosts in a reboot-time
  // lockout state because `ssh.socket` stayed disabled.
  it("R-0000614: keeps rolling back socket state when the config rewrite fails after verify timeout", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    // writeFile sequence: tmpfile dry-run + live config succeed; the rollback
    // write fails first try, but the rest of the rollback loop must continue.
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run
      .mockResolvedValueOnce(undefined) // live config write
      .mockRejectedValueOnce(new Error("SFTP rollback write failed"))
    const removePortSpy = vi.spyOn(mockSsh, "removePort")
    // The ss probe always returns "no listener" so the verify loop times out.
    const originalExec = mockSsh.exec.bind(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    execSpy.mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("sshd_config rewrite failed")
    expect(result.error?.message).toContain("SFTP rollback write failed")
    // Even though the rollback writeFile threw, the remaining rollback steps
    // (socket activation restore + service restart) must still have run.
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writeFileSpy).toHaveBeenCalled()
  }, 10_000)

  // R-0000613: serialise read-modify-write cycles against /etc/ssh/sshd_config
  // by acquiring the `etc-ssh-sshd-config-mutex` lock around `sshd.port`. A
  // concurrent `sshd.config` apply on the same host shares the same mutex, so
  // neither apply can stomp on the other's snapshot.
  it("R-0000613: acquires the etc-ssh-sshd-config-mutex around the sshd.port apply path", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    mockExecResolvedValue(execSpy, { code: 0 })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("mkdir /var/lib/paratix/flags/'etc-ssh-sshd-config-mutex'")
    expect(execCommands).toContain("rmdir /var/lib/paratix/flags/'etc-ssh-sshd-config-mutex'")
    // The mutex must be acquired before any sshd_config writes / restarts and
    // released only after the apply has finished.
    const acquireIndex = execCommands.indexOf(
      "mkdir /var/lib/paratix/flags/'etc-ssh-sshd-config-mutex'"
    )
    const restartIndex = execCommands.indexOf("systemctl restart sshd")
    const releaseIndex = execCommands.indexOf(
      "rmdir /var/lib/paratix/flags/'etc-ssh-sshd-config-mutex'"
    )
    expect(acquireIndex).toBeGreaterThanOrEqual(0)
    expect(restartIndex).toBeGreaterThan(acquireIndex)
    expect(releaseIndex).toBeGreaterThan(restartIndex)
  })

  it("falls back to ssh.service for restart on Ubuntu-style systems", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    // R-0000539: spy on readFile to prevent exec from being called for guard reads.
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdPort
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
    const execSpy = vi.spyOn(mockSsh, "exec")

    // R-0000613: bypass mutex bookkeeping commands so the scripted sequence
    // matches the domain calls only.
    execSpy.mockImplementation(
      buildMutexAwareExecSequence([
        { code: 0 }, // mkdir -p /run/sshd (dry-run)
        { code: 0 }, // sshd -t -f <tmpfile>
        { code: 0 }, // rm -f <tmpfile>
        // R-0000608: socket-state probes both `ssh.socket` and `sshd.socket`.
        { code: 1 }, // ssh.socket missing
        { code: 1 }, // sshd.socket missing
        { code: 1 }, // sshd.service not found
        { code: 0 }, // ssh.service found
        { code: 0 }, // ssh.service is-enabled
        { code: 0 }, // systemctl restart ssh
        { code: 0, stdout: SS_PROBE_LISTENING_STDOUT }, // ss probe
      ])
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl restart ssh")
  })

  // R-0000283: a successful restart that leaves no listener on the target port
  // must not be reported as `changed`. The runner would reconnect into the
  // void; instead surface a structured failure and roll back.
  it("R-0000283: returns failed when restart succeeds but no listener appears on the target port", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("rolled back")
    // Last write must restore the original config.
    expect(writtenFiles.at(-1)?.content).toBe(originalConfig)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  }, 10_000)

  // R-0000609: `ss` failures from a missing binary or permission denial used
  // to be swallowed as "no listener yet", which spun the verify loop until
  // timeout and then rolled back even though the restart actually succeeded.
  // The probe now surfaces the environmental failure verbatim so the operator
  // can react instead of chasing phantom restart issues.
  it("R-0000609: surfaces ss command-not-found as a structured failure during live-port verify", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(
      buildExecWithSsOverride(originalExec, {
        code: 127,
        stderr: "ss: command not found\n",
      })
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("live-port probe via `ss` failed")
    expect(result.error?.message).toContain("command not found")
    // The hard error must short-circuit the verify loop rather than running it
    // out to LIVE_VERIFY_TIMEOUT_MS — the test would otherwise need a >5s
    // timeout to complete.
  })

  // R-0000609: the no-change apply path probes `ss` before triggering a
  // restart. A hard `ss` failure must surface immediately so the operator
  // does not keep retrying a restart that cannot be verified.
  it("R-0000609: returns failed when ss permission-denied blocks the no-change live-port probe", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(
      buildExecWithSsOverride(originalExec, {
        code: 1,
        stderr: "ss: Permission denied\n",
      })
    )

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("live-port probe via `ss` failed")
    expect(result.error?.message).toContain("Permission denied")
    // The no-change apply path must not write or restart when the probe fails.
    expect(writtenFiles).toHaveLength(0)
  })

  it("R-0000283: combines verify failure with rollback writeFile failure in the error message", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // R-0000539: tmpfile (dry-run) write succeeds, then live config write succeeds,
    // then rollback write (after ss-verify timeout) fails.
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockResolvedValueOnce(undefined) // live config write succeeds
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
    expect(writeFileSpy).toHaveBeenCalled()
  }, 10_000)
})

// ─── sshd.port — dry-run ─────────────────────────────────────────────────────
