import { describe, expect, it } from "vitest"

import type { SymlinkTrail } from "../../src/modules/archiveSymlinkResolver.js"
import type { ExecOptions, ExecResult, SshConnection } from "../../src/types.js"

import {
  buildKernelCrossCheckScript,
  isTransportableTrailPath,
  KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES,
  kernelCrossCheckEntry,
  kernelCrossCheckVerdicts,
  runKernelCrossCheck,
} from "../../src/modules/archiveKernelCrossCheck.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "../../src/modules/archiveMemberValidation.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../../src/sshHelpers.js"

/**
 * Issue #219: a successful cross-check exec that returned the given fields.
 *
 * @param fields - The decoded `(link, verdict, level)` fields.
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

/**
 * Issue #219: a trail source that answers from fixed trails.
 *
 * @param trails - The trail per destination-relative link path.
 * @returns The trail source.
 */
function fixedTrails(
  trails: Record<string, SymlinkTrail>
): (key: string, maxLength: number) => "oversized" | null | SymlinkTrail {
  return (key) => trails[key] ?? null
}

describe("isTransportableTrailPath (Issue #219)", () => {
  it.each(["/opt/app/d", "/opt/app/d/..", "/opt/app/d/../../outside/n", "/..", "/opt/app/.hidden"])(
    "accepts %j",
    (path) => {
      expect(isTransportableTrailPath(path)).toBe(true)
    }
  )

  it.each([
    "/",
    "opt/app",
    "/opt//app",
    "/opt/app/",
    "/opt/./app",
    "/opt/app/.",
    "/opt/a\u0000b",
    "",
  ])("refuses %j", (path) => {
    expect(isTransportableTrailPath(path)).toBe(false)
  })
})

describe("kernelCrossCheckEntry (Issue #219)", () => {
  it("joins the link and the trail points from the full target path down to the base with `//`", () => {
    expect(
      kernelCrossCheckEntry("/opt/app/d/esc", [
        { expected: "/opt/app/d", host: "/opt/app/d" },
        { expected: "/opt/app", host: "/opt/app/d/.." },
        { expected: "/opt/app/n", host: "/opt/app/d/../n" },
      ])
    ).toStrictEqual({
      entry:
        "/opt/app/d/esc///opt/app/d/../n///opt/app/n///opt/app/d/..///opt/app///opt/app/d///opt/app/d",
      kind: "entry",
    })
    expect(
      kernelCrossCheckEntry("/opt/app/l", [{ expected: "/opt/app", host: "/opt/app" }])
    ).toStrictEqual({ entry: "/opt/app/l///opt/app///opt/app", kind: "entry" })
  })

  it.each([
    { link: "/opt/app//l", point: { expected: "/opt/app/d", host: "/opt/app/d" } },
    { link: "/opt/app/../l", point: { expected: "/opt/app/d", host: "/opt/app/d" } },
    { link: "/opt/app/l\u0000x", point: { expected: "/opt/app/d", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app//d", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "opt/app/d", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/d/", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/./d", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/x/../d", host: "/opt/app/d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/d", host: "/opt/app//d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/d", host: "/opt/app/./d" } },
    { link: "/opt/app/l", point: { expected: "/opt/app/d", host: "/opt/app/d/" } },
  ])(
    "refuses the link $link with point $point that cannot be split unambiguously",
    ({ link, point }) => {
      expect(kernelCrossCheckEntry(link, [point])).toStrictEqual({ kind: "invalid-path" })
    }
  )

  it("refuses a link without trail points", () => {
    expect(kernelCrossCheckEntry("/opt/app/l", [])).toStrictEqual({ kind: "invalid-path" })
  })

  it("refuses an entry above the size bound as oversized", () => {
    const link = "/opt/app/l"
    // `<link>//<host>///opt/app` is exactly the bound with this host path.
    const host = "/opt/app/".padEnd(KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES - 22, "x")
    const atBound = `${link}//${host}///opt/app`

    expect(Buffer.byteLength(atBound)).toBe(KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES)
    expect(kernelCrossCheckEntry(link, [{ expected: "/opt/app", host }])).toStrictEqual({
      entry: atBound,
      kind: "entry",
    })
    expect(kernelCrossCheckEntry(link, [{ expected: "/opt/app", host: `${host}x` }])).toStrictEqual(
      { kind: "oversized" }
    )
    // Multi-byte names count by their UTF-8 bytes.
    const wide = `/opt/app/${"\u00e9".repeat(KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES / 2)}`
    expect(kernelCrossCheckEntry(link, [{ expected: "/opt/app", host: wide }])).toStrictEqual({
      kind: "oversized",
    })
  })
})

describe("kernelCrossCheckVerdicts (Issue #219)", () => {
  const requested = new Map([
    ["/opt/app/a", 2],
    ["/opt/app/b", 0],
  ])

  it("accepts same, differ and dangling reports for every requested link", () => {
    const result = kernelCrossCheckVerdicts(
      requested,
      reported("/opt/app/b", "dangling", "1", "/opt/app/a", "same", "0")
    )

    expect(result).toStrictEqual({
      kind: "ok",
      reports: new Map([
        ["/opt/app/a", { level: 0, verdict: "same" }],
        ["/opt/app/b", { level: 1, verdict: "dangling" }],
      ]),
    })
  })

  it.each([
    ["/opt/app/a", "differ", "0"],
    ["/opt/app/a", "differ", "3"],
    ["/opt/app/a", "differ", "4"],
    ["/opt/app/a", "dangling", "3"],
  ])("accepts the report %j", (link, verdict, level) => {
    const result = kernelCrossCheckVerdicts(
      requested,
      reported(link, verdict, level, "/opt/app/b", "same", "0")
    )

    expect(result.kind).toBe("ok")
  })

  it.each([
    {
      name: "a failed exec",
      outcome: { detail: "exit code 65", kind: "failed" as const },
      reason: "exit code 65",
    },
    {
      name: "a field count that is not a multiple of three",
      outcome: reported("/opt/app/a", "same", "0", "/opt/app/b", "same"),
      reason: "returned 5 fields, expected (link, verdict, level) triples",
    },
    {
      name: "an unknown verdict",
      outcome: reported("/opt/app/a", "same", "0", "/opt/app/b", "maybe", "0"),
      reason: 'reported unknown verdict "maybe"',
    },
    {
      name: "a link that was not requested",
      outcome: reported("/opt/app/a", "same", "0", "/etc/passwd", "same", "0"),
      reason: 'reported unexpected link "/etc/passwd"',
    },
    {
      name: "a link reported twice",
      outcome: reported("/opt/app/a", "same", "0", "/opt/app/a", "same", "0"),
      reason: 'reported unexpected link "/opt/app/a"',
    },
    {
      name: "a missing link",
      outcome: reported("/opt/app/a", "same", "0"),
      reason: 'reported no verdict for "/opt/app/b"',
    },
    {
      name: "a same verdict above level 0",
      outcome: reported("/opt/app/a", "same", "1", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "1" for "/opt/app/a"',
    },
    {
      name: "a dangling verdict at level 0",
      outcome: reported("/opt/app/a", "dangling", "0", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "0" for "/opt/app/a"',
    },
    {
      name: "a dangling verdict past the last trail point",
      outcome: reported("/opt/app/a", "dangling", "4", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "4" for "/opt/app/a"',
    },
    {
      name: "a level beyond the trail",
      outcome: reported("/opt/app/a", "differ", "5", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "5" for "/opt/app/a"',
    },
    {
      name: "a level that is not a plain decimal",
      outcome: reported("/opt/app/a", "differ", "01", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "01" for "/opt/app/a"',
    },
    {
      name: "an empty level",
      outcome: reported("/opt/app/a", "differ", "", "/opt/app/b", "same", "0"),
      reason: 'reported invalid level "" for "/opt/app/a"',
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
  const trail = fixedTrails({
    "d/esc": { base: "d", locations: ["d", "", "d"], segments: ["..", "d"] },
    top: { base: "", locations: [""], segments: [] },
  })
  const links = ["d/esc", "top"]
  const escEntry =
    "/opt/app/d/esc///opt/app/d/../d///opt/app/d///opt/app/d/..///opt/app///opt/app/d///opt/app/d"

  it("sends one entry per link judged inside in one strict-UTF-8 exec and reports differ", async () => {
    const { conn, execCalls } = connectionAnswering({
      stdout: "/opt/app/d/esc\u0000differ\u00000\u0000/opt/app/top\u0000same\u00000\u0000",
    })

    const result = await runKernelCrossCheck(conn, { destination, links, trail })

    expect(result).toStrictEqual({
      kind: "ok",
      mismatches: [{ at: { kind: "link" }, expected: "/opt/app/d", key: "d/esc" }],
    })
    expect(execCalls).toStrictEqual([
      {
        command: buildKernelCrossCheckScript(),
        options: {
          ignoreExitCode: true,
          input: `${escEntry}\u0000/opt/app/top///opt/app///opt/app\u0000`,
          maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
          silent: true,
          strictUtf8Stdout: true,
        },
      },
    ])
  })

  it.each([
    { at: { host: "/opt/app/d/../d", kind: "point", location: "/opt/app/d" }, level: "1" },
    { at: { host: "/opt/app/d/..", kind: "point", location: "/opt/app" }, level: "2" },
    { at: { host: "/opt/app/d", kind: "point", location: "/opt/app/d" }, level: "3" },
    { at: { kind: "none" }, level: "4" },
  ])(
    "names the trail point where a link that reaches nothing differs (level $level)",
    async ({ at, level }) => {
      const { conn } = connectionAnswering({
        stdout: `/opt/app/d/esc\u0000differ\u0000${level}\u0000/opt/app/top\u0000same\u00000\u0000`,
      })

      await expect(runKernelCrossCheck(conn, { destination, links, trail })).resolves.toStrictEqual(
        {
          kind: "ok",
          mismatches: [{ at, expected: "/opt/app/d", key: "d/esc" }],
        }
      )
    }
  )

  it("accepts same and dangling without mismatches", async () => {
    const { conn } = connectionAnswering({
      stdout: "/opt/app/d/esc\u0000dangling\u00002\u0000/opt/app/top\u0000same\u00000\u0000",
    })

    await expect(runKernelCrossCheck(conn, { destination, links, trail })).resolves.toStrictEqual({
      kind: "ok",
      mismatches: [],
    })
  })

  it.each([
    { answer: { code: 65, stderr: "test -ef is not supported" }, name: "a non-zero exit" },
    {
      answer: { stdout: `/opt/app/d/esc\u0000same\u00000\u0000${CAPTURE_TRUNCATION_MARKER}` },
      name: "a truncated capture",
    },
    {
      answer: new InvalidUtf8OutputError("Command stdout is not valid UTF-8 (exit code 0): x"),
      name: "stdout that is not valid UTF-8",
    },
    { answer: { stdout: "/opt/app/d/esc\u0000same\u00000\u0000" }, name: "a missing link" },
  ])("fails closed on $name", async ({ answer }) => {
    const { conn } = connectionAnswering(answer)

    const result = await runKernelCrossCheck(conn, { destination, links, trail })

    expect(result.kind).toBe("failed")
  })

  it("refuses the filesystem root as destination without any exec", async () => {
    const { conn, execCalls } = connectionAnswering({})

    const result = await runKernelCrossCheck(conn, { destination: "/", links, trail })

    expect(result).toStrictEqual({
      detail: "the destination is the filesystem root",
      kind: "failed",
    })
    expect(execCalls).toStrictEqual([])
  })

  it.each<{ detail: string; links: string[]; trails: Record<string, SymlinkTrail> }>([
    {
      detail: 'cannot transport symlink "/opt/app/d//x"',
      links: ["d//x"],
      trails: { "d//x": { base: "d", locations: ["d"], segments: [] } },
    },
    {
      detail: 'cannot transport symlink "/opt/app/d/x"',
      links: ["d/x"],
      trails: { "d/x": { base: "d", locations: ["d", "d"], segments: ["."] } },
    },
    {
      detail: 'cannot trace symlink "/opt/app/d/x"',
      links: ["d/x"],
      trails: {},
    },
  ])(
    "refuses a link that cannot be sent without any exec: $detail",
    async ({ detail, links: keys, trails }) => {
      const { conn, execCalls } = connectionAnswering({})

      const result = await runKernelCrossCheck(conn, {
        destination,
        links: keys,
        trail: fixedTrails(trails),
      })

      expect(result).toStrictEqual({ detail, kind: "failed" })
      expect(execCalls).toStrictEqual([])
    }
  )

  it("fails closed without any exec when a link's entry would exceed the size bound", async () => {
    const { conn, execCalls } = connectionAnswering({})
    const segments = Array.from({ length: 400 }, () => "segment")
    const locations = segments.map((_segment, index) =>
      ["d", ...segments.slice(0, index)].join("/")
    )
    locations.push(["d", ...segments].join("/"))

    const oversizedTrail = await runKernelCrossCheck(conn, {
      destination,
      links: ["d/long"],
      trail: fixedTrails({ "d/long": { base: "d", locations, segments } }),
    })
    const refusedBySource = await runKernelCrossCheck(conn, {
      destination,
      links: ["d/long"],
      trail: () => "oversized",
    })

    const detail = `the cross-check entry of symlink "/opt/app/d/long" would exceed ${String(KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES)} bytes`
    expect(oversizedTrail).toStrictEqual({ detail, kind: "failed" })
    expect(refusedBySource).toStrictEqual({ detail, kind: "failed" })
    expect(execCalls).toStrictEqual([])
  })

  it("passes the entry size bound to the trail source", async () => {
    const { conn } = connectionAnswering({ stdout: "/opt/app/top\u0000same\u00000\u0000" })
    const bounds: number[] = []

    await runKernelCrossCheck(conn, {
      destination,
      links: ["top"],
      trail(_key, maxLength) {
        bounds.push(maxLength)
        return { base: "", locations: [""], segments: [] }
      },
    })

    expect(bounds).toStrictEqual([KERNEL_CROSS_CHECK_ENTRY_LIMIT_BYTES])
  })
})
