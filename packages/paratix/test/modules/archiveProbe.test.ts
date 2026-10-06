import { afterEach, describe, expect, it, vi } from "vitest"

import type * as ArchiveProbeModule from "../../src/modules/archiveProbe.js"
import type * as SshModule from "../../src/ssh.js"
import type * as SshHelpersModule from "../../src/sshHelpers.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import {
  buildSymlinkListingProbeScript,
  buildSymlinkProbeScript,
  encodeNulPayload,
  encodePreStagingEntry,
  encodeSymlinkListingEntry,
  runBatchedProbe,
} from "../../src/modules/archiveProbe.js"
import { SudoInputUnsupportedError } from "../../src/ssh.js"
import {
  CAPTURE_TRUNCATION_MARKER,
  DEFAULT_MAX_OUTPUT_BYTES,
  InvalidUtf8OutputError,
} from "../../src/sshHelpers.js"

function connectionReturning(result: Partial<ExecResult>): {
  conn: SshConnection
  execCalls: Array<{ command: string; options?: ExecOptions }>
} {
  const execCalls: Array<{ command: string; options?: ExecOptions }> = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      execCalls.push({ command, options })
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "", ...result }
    },
  } as unknown as SshConnection
  return { conn, execCalls }
}

/**
 * #193: the published package bundles `sshHelpers.ts` and `ssh.ts` twice —
 * once into `dist/cli.js` (which creates the SSH connection whose `exec`
 * throws) and once into the library chunk behind `dist/index.js` (where the
 * archive module runs the probe). Loading the error classes and the probe
 * across `vi.resetModules()` simulates that bundle split without a build.
 *
 * @returns The error classes of copy A and the probe of copy B.
 */
async function loadErrorsAndProbeFromDifferentCopies(): Promise<{
  probe: typeof ArchiveProbeModule
  ssh: typeof SshModule
  sshHelpers: typeof SshHelpersModule
}> {
  vi.resetModules()
  const sshHelpers = await import("../../src/sshHelpers.js")
  const ssh = await import("../../src/ssh.js")
  vi.resetModules()
  const probe = await import("../../src/modules/archiveProbe.js")
  return { probe, ssh, sshHelpers }
}

function connectionRejectingWith(error: Error): SshConnection {
  return {
    async exec(): Promise<ExecResult> {
      await Promise.resolve()
      throw error
    },
  } as unknown as SshConnection
}

describe("runBatchedProbe across module copies (#193)", () => {
  afterEach(() => {
    vi.resetModules()
  })

  it("reports another copy's InvalidUtf8OutputError as a failure instead of rethrowing it", async () => {
    const { probe, sshHelpers } = await loadErrorsAndProbeFromDifferentCopies()
    const error = new sshHelpers.InvalidUtf8OutputError(
      "Command stdout is not valid UTF-8 (exit code 0): probe"
    )
    expect(error).not.toBeInstanceOf(InvalidUtf8OutputError)

    const outcome = await probe.runBatchedProbe(connectionRejectingWith(error), {
      entries: ["/opt/app"],
      script: probe.buildSymlinkListingProbeScript(),
    })

    expect(outcome).toStrictEqual({ detail: error.message, kind: "failed" })
  })

  it("reports another copy's SudoInputUnsupportedError as a failure instead of rethrowing it", async () => {
    const { probe, ssh } = await loadErrorsAndProbeFromDifferentCopies()
    const error = new ssh.SudoInputUnsupportedError()
    expect(error).not.toBeInstanceOf(SudoInputUnsupportedError)

    const outcome = await probe.runBatchedProbe(connectionRejectingWith(error), {
      entries: ["/opt/app"],
      script: probe.buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({ detail: error.message, kind: "failed" })
  })
})

describe("runBatchedProbe", () => {
  it("runs nothing at all for an empty entry list", async () => {
    const { conn, execCalls } = connectionReturning({})

    const outcome = await runBatchedProbe(conn, {
      entries: [],
      script: buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({ fields: [], kind: "ok" })
    expect(execCalls).toHaveLength(0)
  })

  it("transports the entries NUL-terminated on stdin", async () => {
    const { conn, execCalls } = connectionReturning({})

    await runBatchedProbe(conn, {
      entries: ["/opt/app", "/opt/two\nlines"],
      script: buildSymlinkProbeScript(),
    })

    expect(execCalls).toHaveLength(1)
    expect(execCalls[0]?.options).toStrictEqual({
      ignoreExitCode: true,
      input: "/opt/app\u0000/opt/two\nlines\u0000",
      silent: true,
      strictUtf8Stdout: true,
    })
  })

  it("reports a rejected exec, e.g. stdout that is not valid UTF-8, as a failure (Issue #219)", async () => {
    const conn = {
      async exec(): Promise<ExecResult> {
        await Promise.resolve()
        throw new InvalidUtf8OutputError("Command stdout is not valid UTF-8 (exit code 0): probe")
      },
    } as unknown as SshConnection

    const outcome = await runBatchedProbe(conn, {
      entries: ["/opt/app"],
      script: buildSymlinkListingProbeScript(),
    })

    expect(outcome).toStrictEqual({
      detail: "Command stdout is not valid UTF-8 (exit code 0): probe",
      kind: "failed",
    })
  })

  it("reports an exec refused for stdin under password sudo as a failure", async () => {
    const conn = {
      async exec(): Promise<ExecResult> {
        await Promise.resolve()
        throw new SudoInputUnsupportedError()
      },
    } as unknown as SshConnection

    const outcome = await runBatchedProbe(conn, {
      entries: ["/opt/app"],
      script: buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({
      detail: new SudoInputUnsupportedError().message,
      kind: "failed",
    })
  })

  it("rethrows any other exec rejection, e.g. a dropped connection", async () => {
    const dropped = new Error("SSH connection lost")
    const conn = {
      async exec(): Promise<ExecResult> {
        await Promise.resolve()
        throw dropped
      },
    } as unknown as SshConnection

    await expect(
      runBatchedProbe(conn, { entries: ["/opt/app"], script: buildSymlinkProbeScript() })
    ).rejects.toBe(dropped)
  })

  it("reports a non-zero exit as a failure rather than an empty violation list", async () => {
    const { conn } = connectionReturning({ code: 2, stderr: "xargs: sh: No such file" })

    const outcome = await runBatchedProbe(conn, {
      entries: ["/opt/app"],
      script: buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({ detail: "xargs: sh: No such file", kind: "failed" })
  })

  it("refuses to evaluate output that hit the captured-output cap", async () => {
    // R-0000668: the marker is appended silently, so a probe that parsed the
    // partial list would decide on evidence it never fully received.
    const { conn } = connectionReturning({
      stdout: `/opt/app\u0000/opt/other${CAPTURE_TRUNCATION_MARKER}`,
    })

    const outcome = await runBatchedProbe(conn, {
      entries: ["/opt/app"],
      script: buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({
      detail: expect.stringContaining("truncated"),
      kind: "failed",
      truncated: true,
    })
  })

  it("passes a captured-output cap to exec only when the caller sets one (Issue #219)", async () => {
    const { conn, execCalls } = connectionReturning({})

    await runBatchedProbe(conn, { entries: ["/opt/app"], script: buildSymlinkListingProbeScript() })
    await runBatchedProbe(conn, {
      entries: ["/opt/app"],
      maxOutputBytes: 16_777_216,
      script: buildSymlinkListingProbeScript(),
    })

    expect(execCalls.map(({ options }) => options)).toStrictEqual([
      { ignoreExitCode: true, input: "/opt/app\u0000", silent: true, strictUtf8Stdout: true },
      {
        ignoreExitCode: true,
        input: "/opt/app\u0000",
        maxOutputBytes: 16_777_216,
        silent: true,
        strictUtf8Stdout: true,
      },
    ])
  })

  it.each([
    { cap: DEFAULT_MAX_OUTPUT_BYTES, limit: {} },
    { cap: 16_777_216, limit: { maxOutputBytes: 16_777_216 } },
  ])(
    "names the effective cap of $cap bytes when the output was truncated (Issue #219)",
    async ({ cap, limit }) => {
      const { conn } = connectionReturning({
        stdout: `/opt/app/l\u0000..\u0000${CAPTURE_TRUNCATION_MARKER}`,
      })

      const outcome = await runBatchedProbe(conn, {
        entries: ["/opt/app"],
        ...limit,
        script: buildSymlinkListingProbeScript(),
      })

      expect(outcome).toStrictEqual({
        detail: `probe output exceeded the captured-output cap of ${String(cap)} bytes; refusing to evaluate a truncated result`,
        kind: "failed",
        truncated: true,
      })
    }
  )

  it("keeps interior empty fields, which the ownership probe emits for an unstattable path", async () => {
    const { conn } = connectionReturning({ stdout: "/opt/gone\u0000\u0000\u0000\u0000\u0000" })

    const outcome = await runBatchedProbe(conn, {
      entries: ["/opt/gone"],
      script: buildSymlinkProbeScript(),
    })

    expect(outcome).toStrictEqual({ fields: ["/opt/gone", "", "", "", ""], kind: "ok" })
  })
})

describe("encodeNulPayload", () => {
  it("terminates every entry, so the last one is not a special case", () => {
    expect(encodeNulPayload(["a", "b"])).toBe("a\u0000b\u0000")
    expect(encodeNulPayload([])).toBe("")
  })
})

/**
 * Stdout for the truncated-ownership scenario, keyed by command shape so the
 * test body itself stays free of branching.
 *
 * @param command - The command the module issued.
 * @returns The stdout that command should produce.
 */
function truncatedOwnershipStdout(command: string): string {
  const responses: Array<[(value: string) => boolean, string]> = [
    [(value) => value.includes(".owner-paths"), JSON.stringify(["/opt/app/file"])],
    [
      (value) => value.includes(".members"),
      JSON.stringify([{ kind: "file", path: "/opt/app/file" }]),
    ],
    [
      (value) => value.startsWith("xargs -0 sh -c 'eu="),
      `/opt/app/file\u0000${CAPTURE_TRUNCATION_MARKER}`,
    ],
  ]
  return responses.find(([matches]) => matches(command))?.[1] ?? ""
}

describe("truncation reaches the ownership caller", () => {
  it("makes ownerMatchesPaths report drift instead of a match", async () => {
    // The failure path is what the guard buys: without it, the trailing partial
    // record is dropped and every complete record happening to match would be
    // read as "ownership is fine".
    const { archive } = await import("../../src/modules/archive.js")
    const conn = {
      async exec(command: string): Promise<ExecResult> {
        await Promise.resolve()
        return { code: 0, stderr: "", stdout: truncatedOwnershipStdout(command) }
      },
      async test(): Promise<boolean> {
        await Promise.resolve()
        return true
      },
    } as unknown as SshConnection
    vi.spyOn(conn, "test").mockResolvedValue(true)

    const mod = archive.extract("/tmp/app.tar.gz", "/opt/app", { owner: "www-data:www-data" })
    const result = await mod.check(conn, {})

    expect(result).toBe("needs-apply")
  })
})

describe("tagged probe entries (Issue #219)", () => {
  it("prefixes the path with the check code and keeps colons inside the path", () => {
    expect(encodePreStagingEntry("l", "/opt/app/a")).toBe("l:/opt/app/a")
    expect(encodePreStagingEntry("n", "/opt/app/a:b")).toBe("n:/opt/app/a:b")
    expect(encodePreStagingEntry("d", "/opt/app/x:y:z")).toBe("d:/opt/app/x:y:z")
  })

  it("prefixes the listing entry with its kind and keeps colons inside the path", () => {
    expect(encodeSymlinkListingEntry("r", "/opt/app")).toBe("r:/opt/app")
    expect(encodeSymlinkListingEntry("n", "/opt/app/n:x")).toBe("n:/opt/app/n:x")
  })
})
