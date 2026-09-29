import { describe, expect, it } from "vitest"

import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import {
  buildKernelCrossCheckScript,
  kernelCrossCheckEntry,
  kernelCrossCheckVerdicts,
  runKernelCrossCheck,
} from "../../src/modules/archiveKernelCrossCheck.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "../../src/modules/archiveMemberValidation.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../../src/sshHelpers.js"

/**
 * Issue #219: a successful cross-check exec that returned the given fields.
 *
 * @param fields - The decoded `(link, verdict)` fields.
 * @returns The batched probe outcome.
 */
function reported(...fields: string[]): { fields: string[]; kind: "ok" } {
  return { fields, kind: "ok" }
}

/**
 * Issue #219: a connection whose `exec` answers every call with one result, or
 * rejects with one error.
 *
 * @param answer - The result to return, or the error to reject with.
 * @returns The connection and the recorded calls.
 */
function connectionAnswering(answer: Error | Partial<ExecResult>): {
  conn: SshConnection
  execCalls: Array<{ command: string; options?: ExecOptions }>
} {
  const execCalls: Array<{ command: string; options?: ExecOptions }> = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      execCalls.push({ command, options })
      await Promise.resolve()
      if (answer instanceof Error) throw answer
      return { code: 0, stderr: "", stdout: "", ...answer }
    },
  } as unknown as SshConnection
  return { conn, execCalls }
}

describe("kernelCrossCheckEntry (Issue #219)", () => {
  it("joins the expected location and the link with the first `//`", () => {
    expect(kernelCrossCheckEntry("/opt/app/d", "/opt/app/d/esc")).toBe("/opt/app/d///opt/app/d/esc")
    expect(kernelCrossCheckEntry("/opt/app", "/opt/app/l")).toBe("/opt/app///opt/app/l")
  })

  it.each([
    ["/opt/app//d", "/opt/app/l"],
    ["/opt/app/d", "/opt/app//l"],
    ["opt/app/d", "/opt/app/l"],
    ["/opt/app/d/", "/opt/app/l"],
    ["/opt/app/./d", "/opt/app/l"],
    ["/opt/app/d", "/opt/app/../l"],
    ["/opt/app/d", "/opt/app/l\u0000x"],
  ])("refuses the pair %j -> %j that cannot be split unambiguously", (expected, link) => {
    expect(kernelCrossCheckEntry(expected, link)).toBeNull()
  })
})

describe("kernelCrossCheckVerdicts (Issue #219)", () => {
  const requested = ["/opt/app/a", "/opt/app/b"]

  it("accepts same, differ and dangling verdicts for every requested link", () => {
    const result = kernelCrossCheckVerdicts(
      requested,
      reported("/opt/app/b", "dangling", "/opt/app/a", "same")
    )

    expect(result).toStrictEqual({
      kind: "ok",
      verdicts: new Map([
        ["/opt/app/a", "same"],
        ["/opt/app/b", "dangling"],
      ]),
    })
  })

  it.each([
    {
      name: "a failed exec",
      outcome: { detail: "exit code 65", kind: "failed" as const },
      reason: "exit code 65",
    },
    {
      name: "an odd field count",
      outcome: reported("/opt/app/a", "same", "/opt/app/b"),
      reason: "returned 3 fields, expected (link, verdict) pairs",
    },
    {
      name: "an unknown verdict",
      outcome: reported("/opt/app/a", "same", "/opt/app/b", "maybe"),
      reason: 'reported unknown verdict "maybe"',
    },
    {
      name: "a link that was not requested",
      outcome: reported("/opt/app/a", "same", "/etc/passwd", "same"),
      reason: 'reported unexpected link "/etc/passwd"',
    },
    {
      name: "a link reported twice",
      outcome: reported("/opt/app/a", "same", "/opt/app/a", "same"),
      reason: 'reported unexpected link "/opt/app/a"',
    },
    {
      name: "a missing link",
      outcome: reported("/opt/app/a", "same"),
      reason: 'reported no verdict for "/opt/app/b"',
    },
  ])("fails closed on $name", ({ outcome, reason }) => {
    expect(kernelCrossCheckVerdicts(requested, outcome)).toStrictEqual({
      detail: reason,
      kind: "failed",
    })
  })
})

describe("runKernelCrossCheck (Issue #219)", () => {
  const destination = "/opt/app"
  const inside = new Map([
    ["d/esc", "d"],
    ["top", ""],
  ])

  it("sends one entry per link judged inside in one strict-UTF-8 exec and reports differ", async () => {
    const { conn, execCalls } = connectionAnswering({
      stdout: "/opt/app/d/esc\u0000differ\u0000/opt/app/top\u0000same\u0000",
    })

    const result = await runKernelCrossCheck(conn, { destination, inside })

    expect(result).toStrictEqual({
      kind: "ok",
      mismatches: [{ expected: "/opt/app/d", key: "d/esc" }],
    })
    expect(execCalls).toStrictEqual([
      {
        command: buildKernelCrossCheckScript(),
        options: {
          ignoreExitCode: true,
          input: "/opt/app/d///opt/app/d/esc\u0000/opt/app///opt/app/top\u0000",
          maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
          silent: true,
          strictUtf8Stdout: true,
        },
      },
    ])
  })

  it("accepts same and dangling without mismatches", async () => {
    const { conn } = connectionAnswering({
      stdout: "/opt/app/d/esc\u0000dangling\u0000/opt/app/top\u0000same\u0000",
    })

    await expect(runKernelCrossCheck(conn, { destination, inside })).resolves.toStrictEqual({
      kind: "ok",
      mismatches: [],
    })
  })

  it.each([
    { answer: { code: 65, stderr: "test -ef is not supported" }, name: "a non-zero exit" },
    {
      answer: { stdout: `/opt/app/d/esc\u0000same\u0000${CAPTURE_TRUNCATION_MARKER}` },
      name: "a truncated capture",
    },
    {
      answer: new InvalidUtf8OutputError("Command stdout is not valid UTF-8 (exit code 0): x"),
      name: "stdout that is not valid UTF-8",
    },
    { answer: { stdout: "/opt/app/d/esc\u0000same\u0000" }, name: "a missing link" },
  ])("fails closed on $name", async ({ answer }) => {
    const { conn } = connectionAnswering(answer)

    const result = await runKernelCrossCheck(conn, { destination, inside })

    expect(result.kind).toBe("failed")
  })

  it("refuses the filesystem root as destination without any exec", async () => {
    const { conn, execCalls } = connectionAnswering({})

    const result = await runKernelCrossCheck(conn, { destination: "/", inside })

    expect(result).toStrictEqual({
      detail: "the destination is the filesystem root",
      kind: "failed",
    })
    expect(execCalls).toStrictEqual([])
  })

  it("refuses a link path that cannot be transported without any exec", async () => {
    const { conn, execCalls } = connectionAnswering({})

    const result = await runKernelCrossCheck(conn, {
      destination,
      inside: new Map([["d//x", "d"]]),
    })

    expect(result).toStrictEqual({
      detail: 'cannot transport symlink "/opt/app/d//x"',
      kind: "failed",
    })
    expect(execCalls).toStrictEqual([])
  })
})
