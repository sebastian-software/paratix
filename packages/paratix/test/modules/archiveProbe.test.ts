import { describe, expect, it, vi } from "vitest"

import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import {
  buildSymlinkProbeScript,
  encodeNulPayload,
  runBatchedProbe,
} from "../../src/modules/archiveProbe.js"
import { CAPTURE_TRUNCATION_MARKER } from "../../src/sshHelpers.js"

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
    expect(execCalls[0]?.options?.input).toBe("/opt/app\u0000/opt/two\nlines\u0000")
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
    })
  })

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
