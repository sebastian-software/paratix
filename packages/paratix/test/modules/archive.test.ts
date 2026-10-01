import { createHash } from "node:crypto"
import { EventEmitter } from "node:events"
import { posix } from "node:path"
import { describe, expect, it, vi } from "vitest"

import type { ExecOptions, ExecResult, ModuleResult, SshConnection } from "../../src/types.js"

import { archive } from "../../src/modules/archive.js"
import {
  POST_MERGE_VIOLATION_REPORT_LIMIT,
  runSymlinkContainmentBackstop,
} from "../../src/modules/archiveContainmentBackstop.js"
import {
  enforceSymlinkContainment,
  validateMergedSymlinkContainment,
} from "../../src/modules/archiveContainmentEnforcement.js"
import {
  buildContainmentClearScript,
  buildContainmentEstablishCommand,
  buildContainmentEstablishScript,
  CONTAINMENT_ENTRY_READ_LIMIT,
  CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES,
  CONTAINMENT_FLAG_BODY_LIMIT_BYTES,
  CONTAINMENT_FLAG_LINK_LIMIT,
  containmentFlagBody,
  type ContainmentPaths,
  noContainmentEntriesCommand,
  parseContainmentFlag,
  STOPPED_AFTER_MERGE_STARTED,
  TOO_MANY_OFFENDING_LINKS,
  UNIDENTIFIED_OFFENDING_LINKS,
} from "../../src/modules/archiveContainmentFlag.js"
import { buildKernelCrossCheckScript } from "../../src/modules/archiveKernelCrossCheck.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  type ArchiveMember,
  listArchiveMembers,
} from "../../src/modules/archiveMemberValidation.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  buildPreStagingProbeScript,
  buildSymlinkListingProbeScript,
  buildSymlinkProbeScript,
  encodeNulPayload,
} from "../../src/modules/archiveProbe.js"
import {
  boundedStagingMergeCommand,
  buildStagingMergeExec,
  buildStagingMergeScript,
  STAGING_MERGE_TIME_LIMITS,
} from "../../src/modules/archiveStagingMergeScript.js"
import { SYMLINK_LISTING_CAPTURE_LIMIT_BYTES } from "../../src/modules/archiveSymlinkListing.js"
import { tarListingScript } from "../../src/modules/archiveTarListing.js"
import { shellQuote } from "../../src/ssh.js"
import {
  CAPTURE_TRUNCATION_MARKER,
  collectStreamOutput,
  InvalidUtf8OutputError,
  type StreamOutputParameters,
} from "../../src/sshHelpers.js"
import { createMockSsh as createBaseMockSsh, type ExecCall } from "../helpers/mockSsh.js"

const emptyEnv = {}

const src = "/tmp/app.tar.gz"
const destination = "/opt/app"
const alternateDestination = "/opt/app-alt"
/** Issue #219: a second source extracted into the same destination. */
const otherSrc = "/tmp/other.tar.gz"
const safeTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/file"
const archiveListingMaxOutputBytes = ARCHIVE_CAPTURE_LIMIT_BYTES
const legacyCaptureLimitBytes = 1_048_576

// Stable hash of `${src}\n${destination}` for marker file naming.
const srcHash = "2889be4b654d6b7f7922971e7fb3fdf1c5ebd92b9c52462be2683a735c7562ef"
const marker = `/var/lib/paratix/flags/archive-${srcHash}.sha256`
const membersMarker = `${marker}.members`
const archiveSha = "abc123def456"
const extractedFileMember = { kind: "file", path: `${destination}/app/file` } as const
const symlinkProbeCommand = buildSymlinkProbeScript()
/**
 * Issue #219: the listing of host symlinks. The pre-merge check and the
 * post-merge backstop issue the identical command; only the stdin tells them
 * apart (see {@link postMergeListingInput}).
 */
const symlinkListingProbeCommand = buildSymlinkListingProbeScript()
/**
 * Issue #219: the stdin of the post-merge backstop listing: the destination as
 * its only `r` entry. The pre-merge listing adds one `n` entry per
 * non-directory member.
 */
const postMergeListingInput = `r:${destination}\u0000`
/** Issue #219: the pre-staging probe: symlink guards plus member type checks. */
const preStagingProbeCommand = buildPreStagingProbeScript()
/**
 * Issue #219: the kernel cross-check the post-merge backstop runs for every
 * link it judges inside.
 */
const kernelCrossCheckCommand = buildKernelCrossCheckScript()

/**
 * Issue #219: the links a kernel cross-check exec carries, in order.
 *
 * @param input - The exec's NUL-terminated `<link>//<K_n>//<E_n>//...`
 *   entries.
 * @returns The absolute link paths.
 */
function crossCheckedLinks(input: string | undefined): string[] {
  return (input ?? "")
    .split("\u0000")
    .filter((entry) => entry !== "")
    .map((entry) => entry.slice(0, entry.indexOf("//")))
}

/**
 * Issue #219: a kernel cross-check answer that confirms every carried link as
 * `same`.
 *
 * @param input - The exec's stdin.
 * @returns The NUL-framed `(link, verdict, level)` triples.
 */
function crossCheckStdout(input: string | undefined): string {
  return crossCheckedLinks(input)
    .map((link) => `${link}\u0000same\u00000\u0000`)
    .join("")
}

/**
 * Issue #219: the cross-check entry of a link whose target walks no symlink,
 * as `[link, K_n, E_n, ..., K_0, E_0]`: each host path `K_j` keeps the
 * target's `..` segments, each expected location `E_j` is normalized.
 *
 * @param link - The absolute link path.
 * @param target - The stored target; an absolute one lies inside the destination.
 * @returns The entry's paths, to be joined with `//`.
 */
function plainCrossCheckEntry(link: string, target: string): string[] {
  const absolute = target.startsWith("/")
  const base = absolute ? destination : posix.dirname(link)
  const path = absolute ? target.slice(destination.length + 1) : target
  const points = [[base, base]]
  let host = base
  let expected = base
  for (const segment of path.split("/").filter((part) => part !== "" && part !== ".")) {
    host = `${host}/${segment}`
    expected = segment === ".." ? posix.dirname(expected) : `${expected}/${segment}`
    points.push([host, expected])
  }
  return [link, ...points.toReversed().flat()]
}

/**
 * Issue #219: every apply names its own containment entry `run-<32 hex>` from
 * random bytes. The tests number them per test instead (`run-000…1` for the
 * first apply, `run-000…2` for the second), so commands and paths are
 * predictable; see {@link ownEntryName}. The numbering restarts when the
 * current test name changes, so every test here needs a distinct name.
 */
const containmentEntryNames = vi.hoisted(() => ({ issued: 0, test: "" }))

vi.mock("../../src/modules/archiveContainmentFlag.js", async (importOriginal) => {
  const original: Record<string, unknown> = await importOriginal()
  const { expect: currentExpect } = await import("vitest")
  return {
    ...original,
    newContainmentEntryName(): string {
      // Issue #219: the numbering restarts with every test.
      const test = currentExpect.getState().currentTestName ?? ""
      if (containmentEntryNames.test !== test) {
        containmentEntryNames.test = test
        containmentEntryNames.issued = 0
      }
      containmentEntryNames.issued += 1
      return `run-${String(containmentEntryNames.issued).padStart(32, "0")}`
    },
  }
})

const flagsDirectory = "/var/lib/paratix/flags"

/**
 * Issue #219: where the containment state of a destination lives, derived
 * independently of the module so a changed key is caught.
 *
 * @param path - The extraction destination.
 * @returns The flags directory, the entry directory and the old flag file.
 */
function containmentPathsFor(path: string): ContainmentPaths {
  const hash = createHash("sha256").update(path).digest("hex")
  const base = `${flagsDirectory}/archive-containment-${hash}`
  return { directory: flagsDirectory, entryDirectory: `${base}.d`, legacyFlag: `${base}.failed` }
}

const containment = containmentPathsFor(destination)

/**
 * Issue #219: the sentence a recoverable whole-destination violation ends with, naming
 * how to clear the destination's containment entries when the offending links
 * are intended.
 */
const intendedLinksHint = `; if the offending symlinks are intended (for example a virtualenv's interpreter link), they keep failing this check: first stop or wait for all archive.extract applies to this destination to finish and prevent new applies until inspection and state clearing are complete; then check the destination yourself and, before retrying, clear its containment state with rm -f -- '${containment.entryDirectory}'/run-* '${containment.legacyFlag}'`

/** Issue #219: the single flag file of older paratix versions. */
const legacyContainmentFlag = containment.legacyFlag

/**
 * Issue #219: the name of the own entry of the n-th apply in a test.
 *
 * @param run - The apply's position in the test, from 1.
 * @returns The entry name, `run-` and 32 digits.
 */
function ownEntryName(run = 1): string {
  return `run-${String(run).padStart(32, "0")}`
}

/**
 * Issue #219: the own entry of the n-th apply in a test.
 *
 * @param run - The apply's position in the test, from 1.
 * @param path - The extraction destination.
 * @returns The absolute entry path.
 */
function ownEntry(run = 1, path = destination): string {
  return `${containmentPathsFor(path).entryDirectory}/${ownEntryName(run)}`
}

/** Issue #219: the entry an earlier (or concurrent) apply left. */
const earlierEntryName = `run-${"e".repeat(32)}`
const earlierEntry = `${containment.entryDirectory}/${earlierEntryName}`

/**
 * Issue #219: the establish exec of the n-th apply in a test: it reads every
 * containment entry and creates the apply's own entry.
 *
 * @param run - The apply's position in the test, from 1.
 * @param path - The extraction destination.
 * @returns The `sh -c` command.
 */
function containmentEstablishCommand(run = 1, path = destination): string {
  return buildContainmentEstablishCommand({
    ...containmentPathsFor(path),
    ownEntry: ownEntry(run, path),
  })
}

/** Issue #219: every establish exec starts with its script. */
const containmentEstablishPrefix = `sh -c ${shellQuote(buildContainmentEstablishScript())} sh `

/** Issue #219: every clear exec starts with its script. */
const containmentClearPrefix = `sh -c ${shellQuote(buildContainmentClearScript())} sh `

/**
 * Issue #219: the clear execs among the issued commands.
 *
 * @param calls - The issued commands.
 * @returns The clear execs, in order.
 */
function containmentClears(calls: readonly string[]): string[] {
  return calls.filter((command) => command.startsWith(containmentClearPrefix))
}

/**
 * Issue #219: whether a command is the clear exec.
 *
 * @param command - The command, if any.
 * @returns True for the clear exec.
 */
function isContainmentClear(command: string | undefined): boolean {
  return command?.startsWith(containmentClearPrefix) === true
}

/**
 * Issue #219: the containment state of the destination in the host files:
 * every entry by name, and the old flag file as `legacy`.
 *
 * @param files - The host marker and containment files.
 * @returns The bodies, keyed by entry name.
 */
function containmentState(files: ReadonlyMap<string, string>): Record<string, string> {
  const prefix = `${containment.entryDirectory}/`
  return Object.fromEntries(
    [...files]
      .filter(([path]) => path === legacyContainmentFlag || path.startsWith(`${prefix}run-`))
      .map(
        ([path, body]) =>
          [path === legacyContainmentFlag ? "legacy" : path.slice(prefix.length), body] as const
      )
      .toSorted(([left], [right]) => left.localeCompare(right))
  )
}

/**
 * Issue #219: whether any containment entry or the old flag file exists.
 *
 * @param files - The host marker and containment files.
 * @returns True while `check` must report needs-apply.
 */
function hasContainmentState(files: ReadonlyMap<string, string>): boolean {
  return Object.keys(containmentState(files)).length > 0
}

/**
 * Issue #219: the entry body a failed apply records for these link keys.
 *
 * @param links - Destination-relative link keys.
 * @returns The JSON body.
 */
function recordedFlag(...links: string[]): string {
  return containmentFlagBody({ links, state: "failed" })
}

/**
 * Issue #219: link keys an earlier failed apply recorded under `x`, where the
 * later archive writes nothing.
 *
 * @param count - How many keys to generate.
 * @returns The destination-relative link keys.
 */
function recordedKeys(count: number): string[] {
  return Array.from({ length: count }, (_value, index) => `x/esc${String(index)}`)
}

/**
 * Issue #219: `check` tests the marker and the absence of every containment
 * entry and the old flag file in one exec.
 *
 * @param markerFile - The marker path.
 * @param path - The extraction destination the entries are keyed by.
 * @returns The combined test command.
 */
function markerCheckCommand(markerFile: string, path = destination): string {
  return `test -f '${markerFile}' && ${noContainmentEntriesCommand(containmentPathsFor(path))}`
}
const extractedFileTypeProbe = buildMemberTypeProbeScript()
const batchedChownCommand = "xargs -0 chown -h -- 'www-data:www-data'"
const memberTypeMatchResponse = { code: 0, stdout: "" }
const memberTypeDriftResponse = { code: 0, stdout: `${destination}/app/file\u0000` }

function ownershipProbeCommand(owner: string): string {
  const [user = "", group = ""] = owner.split(":", 2)
  return buildOwnershipProbeScript(user, group)
}

/**
 * Ownership-probe stub. The remote script only pre-filters, so reporting a path
 * is always valid: `ownerMatchesStat` re-decides in TypeScript. Tests therefore
 * report unconditionally and let the production rule produce the verdict.
 *
 * @param path - The reported path.
 * @param stat - The `%U %G %u %g` output to transport.
 * @returns A probe response reporting that path.
 */
function ownershipReport(path: string, stat: string): { code: number; stdout: string } {
  const fields = stat.trim().split(/\s+/v)
  return { code: 0, stdout: [path, ...fields].map((field) => `${field}\u0000`).join("") }
}

// R-0000162: archive.extract now extracts into a paratix-controlled staging
// directory under the destination via `mktemp -d`, then atomically moves the
// extracted entries into the destination. Tests stub the staging-directory
// allocation, the move command and the staging-dir cleanup with regex stubs
// so individual tests can keep their familiar `tar … -C '${destination}'`
// expectations.
const archiveStageDirectory = "/opt/app/.paratix-stage.AbCdEfGh"
const archiveStageMktempPattern = /^mktemp -d '\/opt\/app\/\.paratix-stage\.X{8}'$/v
// Issue #219: the merge runs under `command -p timeout -k 10 100 … ; exit $?`
// (see `boundedStagingMergeCommand`) as `sh -c <outer> sh <staging> <merge
// script> <destination> <guard count>`; the guard paths travel on stdin (see
// `buildStagingMergeExec`).
const archiveStageMovePattern =
  /^command -p timeout -k 10 100 sh -c '.*' sh '\/opt\/app\/\.paratix-stage\.[^']+' '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' '\/opt\/app' \d+; exit \$\?$/sv
const archiveStageCleanupPattern = /^rm -rf -- '\/opt\/app\/\.paratix-stage\.[^']+'$/v
const archiveAlternateStageMktempPattern = /^mktemp -d '\/opt\/app-alt\/\.paratix-stage\.X{8}'$/v
const archiveAlternateStageMovePattern =
  /^command -p timeout -k 10 100 sh -c '.*' sh '\/opt\/app-alt\/\.paratix-stage\.[^']+' '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' '\/opt\/app-alt' \d+; exit \$\?$/sv
const archiveAlternateStageCleanupPattern = /^rm -rf -- '\/opt\/app-alt\/\.paratix-stage\.[^']+'$/v
const archiveMembersMarkerPattern =
  /^cat '\/var\/lib\/paratix\/flags\/archive-[a-f0-9]+\.sha256\.members'$/v

function guardedArchiveDestinationMkdirCommand(path: string): string {
  return [
    `if [ -L '${path}' ]; then`,
    `  printf '%s\\n' 'destination path is a symlink' >&2`,
    `  exit 1`,
    `fi`,
    `if [ -e '${path}' ] && [ ! -d '${path}' ]; then`,
    `  printf '%s\\n' 'destination path exists and is not a directory' >&2`,
    `  exit 1`,
    `fi`,
    `if [ ! -d '${path}' ]; then`,
    `  mkdir -- '${path}'`,
    `fi`,
  ].join("\n")
}

function findGuardedArchiveMkdirCall(calls: string[], path: string): string | undefined {
  return calls.find(
    (call) => call.includes(`if [ -L '${path}' ];`) && call.includes(`mkdir -- '${path}'`)
  )
}

const archiveCleanupPaths = [
  "/tmp/paratix-upload.AbCdEfGh",
  "/tmp/paratix-upload.FAIL1234",
  "/tmp/paratix-upload.FIRST111",
  "/tmp/paratix-upload.SECOND22",
]

/**
 * Issue #219: the listing command `archive.extract` runs for a tar archive.
 *
 * @param path - The archive path on the host.
 * @param flags - The `tar` list flags, `-tvzf` for a `.tar.gz`.
 * @returns The listing script.
 */
function tarListCommand(path: string, flags = "-tvzf"): string {
  return tarListingScript(flags, path)
}

/** Issue #219: the mode line the listing script prints for GNU tar in C.UTF-8. */
const gnuTarListingModeLine = "paratix-tar-listing gnu C.UTF-8\n"

/** Issue #219: the mode line for a tar whose names are used as listed. */
const otherTarListingModeLine = "paratix-tar-listing other C.UTF-8\n"

/** Issue #219: the mode line the listing script prints for bsdtar. */
const bsdTarListingModeLine = "paratix-tar-listing bsd C\n"

/**
 * Issue #219: mock stdout of the listing script on a host with GNU tar and a
 * UTF-8 C locale: the mode line, then the `tar -tv` output.
 *
 * @param listing - The `tar -tv` output.
 * @returns The complete stdout of the listing script.
 */
function gnuTarListing(listing: string): string {
  return `${gnuTarListingModeLine}${listing}`
}

function tarListingForMemberPaths(memberPaths: string[]): string {
  return memberPaths
    .map((memberPath) => `-rw-r--r-- root/root 0 1970-01-01 00:00 ${memberPath}`)
    .join("\n")
}

function listingLargerThanLegacyCaptureLimit(memberLine: string): string {
  const line = `${memberLine}\n`
  return line.repeat(Math.floor(legacyCaptureLimitBytes / line.length) + 1)
}

function singleMemberTarListingOfUtf8Size(sizeBytes: number, suffix = ""): string {
  const prefix = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/"
  const paddingBytes =
    sizeBytes - Buffer.byteLength(prefix, "utf8") - Buffer.byteLength(suffix, "utf8")
  if (paddingBytes < 1) throw new Error("tar listing size is too small for a valid member")
  return `${prefix}${"a".repeat(paddingBytes)}${suffix}`
}

/**
 * Assert that a capture-sized exec ran with the expected options.
 *
 * @param mockSsh - The mock connection.
 * @param command - The command that must have run with these options.
 * @param extra - Optional expectations.
 * @param extra.pinCLocale - Whether the exec pins `LC_ALL=C`.
 * @param extra.strictUtf8 - Issue #219: whether stdout is decoded as strict
 *   UTF-8, as for the archive listing.
 */
function expectArchiveCaptureExecCall(
  mockSsh: MockSsh,
  command: string,
  extra: { pinCLocale?: boolean; strictUtf8?: boolean } = {}
): void {
  expect(mockSsh.execCalls).toContainEqual({
    command,
    options: {
      ...(extra.pinCLocale === true ? { env: { LC_ALL: "C" } } : {}),
      ignoreExitCode: true,
      maxOutputBytes: archiveListingMaxOutputBytes,
      silent: true,
      ...(extra.strictUtf8 === true ? { strictUtf8Stdout: true } : {}),
    },
  })
}

const archiveApplyResponseStubs: NonNullable<
  Parameters<typeof createBaseMockSsh>[1]
>["responseStubs"] = [
  { command: archiveMembersMarkerPattern, result: { code: 1, stderr: "cat: No such file" } },
  { command: symlinkProbeCommand, result: { code: 0, stdout: "" } },
  // Issue #219: the pre-staging probe; a clean host reports nothing.
  { command: preStagingProbeCommand, result: { code: 0, stdout: "" } },
  // Issue #219: the pre-merge listing of host symlinks and the post-merge
  // backstop listing; by default the host has none.
  { command: symlinkListingProbeCommand, result: { code: 0, stdout: "" } },
  // Issue #219: the kernel cross-check; `createMockSsh` answers an empty
  // result with `same` for every link it carries.
  { command: kernelCrossCheckCommand, result: { code: 0, stdout: "" } },
  // Issue #219: a successful apply clears the containment entries in one
  // exec; the host model applies it when the test models files.
  { command: /^sh -c 'LC_ALL=C; export LC_ALL; own=\$1;/v, result: { code: 0 } },
  { command: extractedFileTypeProbe, result: { code: 0, stdout: "" } },
  { command: batchedChownCommand, result: { code: 0 } },
  {
    command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
    result: { code: 0 },
  },
  {
    command: `[ -d '${alternateDestination}' ] && [ ! -L '${alternateDestination}' ]`,
    result: { code: 0 },
  },
  { command: guardedArchiveDestinationMkdirCommand("/opt"), result: { code: 0 } },
  { command: guardedArchiveDestinationMkdirCommand(destination), result: { code: 0 } },
  { command: guardedArchiveDestinationMkdirCommand(alternateDestination), result: { code: 0 } },
  { command: `readlink -f -- '${destination}'`, result: { code: 0, stdout: `${destination}\n` } },
  {
    command: `readlink -f -- '${alternateDestination}'`,
    result: { code: 0, stdout: `${alternateDestination}\n` },
  },
  { command: "mkdir -p '/var/lib/paratix/flags'", result: { code: 0 } },
  // Issue #219: the establish exec reads the containment entries and creates
  // the own entry; by default there is no entry, and the host model answers
  // from its files when the test models them.
  {
    command: /^sh -c 'LC_ALL=C; export LC_ALL; umask 022; paratix_read\(\)/v,
    result: { code: 0, stdout: "done\n" },
  },
  { command: archiveStageMktempPattern, result: { code: 0, stdout: archiveStageDirectory } },
  { command: archiveStageMovePattern, result: { code: 0 } },
  { command: archiveStageCleanupPattern, result: { code: 0 } },
  {
    command: archiveAlternateStageMktempPattern,
    result: { code: 0, stdout: "/opt/app-alt/.paratix-stage.AbCdEfGh" },
  },
  { command: archiveAlternateStageMovePattern, result: { code: 0 } },
  { command: archiveAlternateStageCleanupPattern, result: { code: 0 } },
  ...archiveCleanupPaths.map((path) => ({
    command: `rm -f -- '${path}'`,
    result: { code: 0 },
  })),
]

/**
 * Report a symlink violation only for the sweep whose payload actually carries
 * the path. Every sweep issues the identical batched command, so the
 * transported stdin is the only thing that tells them apart — the exact-match
 * mock cannot.
 *
 * @param mockSsh - The mock connection to patch.
 * @param memberPath - The member path whose recheck should report a symlink.
 * @returns A handle exposing how many member-carrying sweeps ran.
 */
function stubSymlinkRecheck(mockSsh: MockSsh, memberPath: string): { sweeps: () => number } {
  const originalExec = mockSsh.exec.bind(mockSsh)
  let sweeps = 0
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    // Issue #219: the sweep before extraction is the pre-staging probe, which
    // carries its symlink checks as `l:` entries.
    if (command === preStagingProbeCommand) {
      mockSsh.calls.push(command)
      if (taggedEntryPaths(options?.input, "l").includes(memberPath)) sweeps += 1
      return { code: 0, stderr: "", stdout: "" }
    }
    if (command !== symlinkProbeCommand) return originalExec(command, options)
    mockSsh.calls.push(command)
    const carriesMember = (options?.input ?? "").includes(`${memberPath}\u0000`)
    if (!carriesMember) return { code: 0, stderr: "", stdout: "" }
    sweeps += 1
    // Only the recheck reports, so a failure can only originate from the sweep
    // that runs after extraction.
    return { code: 0, stderr: "", stdout: sweeps >= 2 ? `${memberPath}\u0000` : "" }
  })
  return { sweeps: () => sweeps }
}

/**
 * Report a symlink violation only for the sweep whose payload carries the path.
 *
 * @param mockSsh - The mock connection to patch.
 * @param path - The path to report as a symlink.
 */
function stubSymlinkViolationFor(mockSsh: MockSsh, path: string): void {
  const originalExec = mockSsh.exec.bind(mockSsh)
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    // Issue #219: the pre-staging probe carries symlink checks as `l:` entries
    // and reports `(check, path)` pairs.
    if (command === preStagingProbeCommand) {
      mockSsh.calls.push(command)
      const carries = taggedEntryPaths(options?.input, "l").includes(path)
      return { code: 0, stderr: "", stdout: carries ? `l\u0000${path}\u0000` : "" }
    }
    if (command !== symlinkProbeCommand) return originalExec(command, options)
    mockSsh.calls.push(command)
    const payload = options?.input ?? ""
    const reported = payload.includes(`${path}\u0000`) ? `${path}\u0000` : ""
    return { code: 0, stderr: "", stdout: reported }
  })
}

/**
 * Issue #219: a failed apply records its outcome in its own containment
 * entry through `writeFile`, so the shared mock accepts that write.
 */
const containmentFlagWritePattern =
  /^\/var\/lib\/paratix\/flags\/archive-containment-[a-f0-9]{64}\.d\/run-[0-9a-f]{32}$/v

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const mockSsh = createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      ...(options?.allowWrites ?? []),
      { options: { mode: "0644" }, remotePath: containmentFlagWritePattern },
    ],
    // Test-supplied stubs take priority over the module-scope defaults so a
    // single test can override e.g. the staging-dir mktemp / move / cleanup
    // commands without having to disable the shared stubs entirely.
    responseStubs: [...(options?.responseStubs ?? []), ...archiveApplyResponseStubs],
  })
  // Issue #219: a successful, empty kernel cross-check answer stands for a
  // host whose kernel confirms every link it was asked about; a test that
  // needs another verdict stubs a non-empty answer.
  const baseExec = mockSsh.exec
  mockSsh.exec = async (command, execOptions) => {
    const result = await baseExec(command, execOptions)
    if (command !== kernelCrossCheckCommand || result.code !== 0 || result.stdout !== "") {
      return result
    }
    return { ...result, stdout: crossCheckStdout(execOptions?.input) }
  }
  return mockSsh
}

type MockSsh = ReturnType<typeof createMockSsh>
function validMembersMarkerResponse(member = extractedFileMember): ExecResult {
  return { code: 0, stderr: "", stdout: JSON.stringify([member]) }
}

function expectNoTarExtractCalls(mockSsh: MockSsh): void {
  const tarExtractCalls = mockSsh.calls.filter((command) => /^tar\b.*\s-x\S*\s/v.test(command))
  expect(tarExtractCalls).toStrictEqual([])
}

function expectNoUnzipExtractCalls(mockSsh: MockSsh): void {
  const unzipExtractCalls = mockSsh.calls.filter((command) => command.startsWith("unzip -o "))
  expect(unzipExtractCalls).toStrictEqual([])
}

function expectNoArchiveMarkerWrite(mockSsh: MockSsh): void {
  // Issue #219: the own containment entry records a failure; it is not a
  // marker and never lets `check` report ok.
  const markerWrites = mockSsh.writeFileCalls.filter(
    ({ remotePath }) => !containmentFlagWritePattern.test(remotePath)
  )
  expect(markerWrites).toHaveLength(0)
}

function rotateUploadMktempResponses(mockSsh: MockSsh, responses: readonly string[]): void {
  const originalOutput = mockSsh.output.bind(mockSsh)
  const remaining = [...responses]
  vi.spyOn(mockSsh, "output").mockImplementation(async (command) => {
    const isUploadMktemp = command === "mktemp /tmp/paratix-upload.XXXXXXXX"
    return isUploadMktemp
      ? consumeNextUploadMktemp(mockSsh, command, remaining)
      : originalOutput(command)
  })
}

async function consumeNextUploadMktemp(
  mockSsh: MockSsh,
  command: string,
  remaining: string[]
): Promise<string> {
  await Promise.resolve()
  mockSsh.calls.push(command)
  return remaining.shift() ?? ""
}

// Issue #219: builders for inline `tar -tv` listings with directory, symlink
// and hardlink members, plus recorders for the batched symlink probe payloads
// and the staging-merge guard paths.
const tarListingLineFields = "root/root 0 1970-01-01 00:00"
/**
 * The staged `tar -x` of a `.tar.gz` source into the staging directory.
 *
 * @param source - Remote path of the `.tar.gz` archive to extract.
 * @returns The `tar` command that extracts it into the staging directory.
 */
function stagedTarExtractCommandFor(source: string): string {
  return `tar --no-same-owner --no-overwrite-dir -xzf '${source}' -C '${archiveStageDirectory}'`
}

const stagedTarExtractCommand = stagedTarExtractCommandFor(src)

function tarFileLine(path: string): string {
  return `-rw-r--r-- ${tarListingLineFields} ${path}`
}

function tarDirectoryLine(path: string): string {
  return `drwxr-xr-x ${tarListingLineFields} ${path}`
}

function tarSymlinkLine(path: string, target: string): string {
  return `lrwxrwxrwx ${tarListingLineFields} ${path} -> ${target}`
}

function tarHardlinkLine(path: string, target: string): string {
  return `hrw-r--r-- ${tarListingLineFields} ${path} link to ${target}`
}

// Issue #219: the bsdtar `-tv` layout (`ls -l` columns: mode, link count,
// user, group, size, month, day, year) for listings under the bsd mode line.
const bsdTarListingLineFields = "0 root   wheel       0 Jan  1  1970"

/**
 * Issue #219: one bsdtar `-tv` listing line.
 *
 * @param mode - The ten-character symbolic mode as bsdtar prints it.
 * @param rest - The name, with any ` -> ` or ` link to ` suffix.
 * @returns The listing line.
 */
function bsdTarLine(mode: string, rest: string): string {
  return `${mode}  ${bsdTarListingLineFields} ${rest}`
}

type SymlinkProbeRecord = { callIndex: number; entries: string[] }

/**
 * Issue #219: the symlinks a host keeps below the destination across runs,
 * keyed by absolute link path. Each run's successful staging merge adds (or
 * replaces) the links it ships, and both the pre-merge listing probe and the
 * post-merge backstop listing are answered from the whole map, so a test can
 * span several runs on one host.
 */
type HostLinkTree = Map<string, string>

type HostLinkRun = {
  /**
   * Issue #219: links the host gains while the merge runs, e.g. from a
   * concurrent change after the pre-merge listing. They land even when the
   * merge exec fails or throws, like entries a half-done merge already copied.
   */
  injectedOnMerge?: ReadonlyArray<readonly [string, string]>
  shipped: ReadonlyArray<readonly [string, string]>
  tree: HostLinkTree
}

const tarSymlinkLinePrefix = `lrwxrwxrwx ${tarListingLineFields} `

/**
 * The symlinks a listing built with `tarSymlinkLine` ships, as host paths.
 *
 * @param lines - The listing lines.
 * @returns `[link, target]` pairs below the destination.
 */
function shippedSymlinks(lines: readonly string[]): Array<readonly [string, string]> {
  return lines
    .filter((line) => line.startsWith(tarSymlinkLinePrefix))
    .map((line) => {
      const [path = "", target = ""] = line.slice(tarSymlinkLinePrefix.length).split(" -> ")
      return [posix.join(destination, path), target] as const
    })
}

function pathsFromNulPayload(input: string | undefined): string[] {
  return (input ?? "").split("\u0000").filter((entry) => entry !== "")
}

/**
 * Issue #219: the paths of the tagged probe entries with the given kind.
 *
 * @param input - The probe's NUL-terminated `<kind>:<path>` entries.
 * @param kind - The entry kind to keep.
 * @returns The paths of the matching entries, in order.
 */
function taggedEntryPaths(input: string | undefined, kind: string): string[] {
  return pathsFromNulPayload(input)
    .filter((entry) => entry.startsWith(`${kind}:`))
    .map((entry) => entry.slice(kind.length + 1))
}

/**
 * Issue #219: one listing field as the probe emits it: printable ASCII as is,
 * anything else as the marker byte 0x01 followed by the hex of its UTF-8
 * bytes.
 *
 * @param text - A decoded link path or target.
 * @returns The encoded field.
 */
function listingField(text: string): string {
  return /^[\x20-\x7E]*$/v.test(text) ? text : `\u0001${Buffer.from(text).toString("hex")}`
}

/**
 * Issue #219: the NUL-framed `l` records of the listing probe for absolute
 * `(link, target)` pairs below a root, with link paths relative to the root.
 *
 * @param root - The listed destination.
 * @param links - The absolute link paths with their raw targets.
 * @returns The probe output.
 */
function listingRecords(root: string, links: Iterable<readonly [string, string]>): string {
  return [...links]
    .flatMap(([link, target]) => ["l", link.slice(root.length + 1), target])
    .map((field, index) => `${index % 3 === 0 ? field : listingField(field)}\u0000`)
    .join("")
}

/**
 * Answer the pre-merge listing probe from the host model: one `l` record for
 * every link below a transported `r` entry. The model has no directories, so
 * `n` entries never report.
 *
 * @param tree - The host symlinks.
 * @param input - The probe's NUL-terminated tagged entries.
 * @returns The NUL-framed probe output.
 */
function listingProbeStdout(tree: ReadonlyMap<string, string>, input: string): string {
  return taggedEntryPaths(input, "r")
    .map((root) =>
      listingRecords(
        root,
        [...tree].filter(([link]) => link.startsWith(`${root}/`))
      )
    )
    .join("")
}

/**
 * Apply what a successful command changes on the modelled host: the staging
 * merge places the shipped (and any injected) links, and `rm -f` of a flags
 * file removes it.
 *
 * @param host - The host model to update.
 * @param command - The executed command.
 */
/**
 * Issue #219: an exec that rejects instead of returning a result, e.g. a
 * dropped connection. With `input`, only the exec with exactly that stdin
 * rejects, which tells the post-merge listing from the pre-merge one.
 */
type ThrowingExec = { command: RegExp | string; error: Error; input?: string }

/**
 * Issue #219: reject the exec when it is the one the harness should fail,
 * after recording it. The links the host gains during the merge still land
 * when the merge throws, as after a connection that dropped half-way through
 * the copy.
 *
 * @param mockSsh - The mock connection whose calls are recorded.
 * @param exchange - The command being executed and its stdin.
 * @param exchange.command - The command being executed.
 * @param exchange.input - The exec's stdin.
 * @param harness - The optional host link model and the exec to reject.
 * @param harness.host - Host link model whose injected links the merge places.
 * @param harness.throwOn - The exec to reject; nothing is rejected when unset.
 */
function rejectMatchingExec(
  mockSsh: MockSsh,
  exchange: { command: string; input: string | undefined },
  harness: { host?: HostLinkRun; throwOn?: ThrowingExec }
): void {
  const { host, throwOn } = harness
  if (throwOn === undefined) return
  const { command } = exchange
  const { command: expected, error, input } = throwOn
  const matches = typeof expected === "string" ? expected === command : expected.test(command)
  if (!matches || (input !== undefined && input !== exchange.input)) return
  mockSsh.calls.push(command)
  if (host !== undefined && archiveStageMovePattern.test(command)) publishInjectedLinks(host)
  throw error
}

/**
 * Issue #219: place the links the host gains while the merge runs.
 *
 * @param host - The host model to update.
 */
function publishInjectedLinks(host: HostLinkRun): void {
  for (const [link, target] of host.injectedOnMerge ?? []) host.tree.set(link, target)
}

/**
 * Issue #219: the sha256 of a modelled file, as the scripts print it.
 *
 * @param content - The file content.
 * @returns The lowercase hex digest.
 */
function sha256Of(content: string): string {
  return createHash("sha256").update(content).digest("hex")
}

/**
 * Issue #219: the single-quoted arguments of a `sh -c` exec after its script.
 *
 * @param command - The exec's full command line.
 * @param prefix - The `sh -c '<script>' sh ` prefix.
 * @returns The unquoted arguments and the unquoted hex digests, in order.
 */
function scriptArguments(command: string, prefix: string): string[] {
  return [
    ...command.slice(prefix.length).matchAll(/'(?<quoted>[^']*)'|(?<digest>[\da-f]{64})/gv),
  ].map(({ groups }) => groups?.quoted ?? groups?.digest ?? "")
}

/**
 * Issue #219: model the establish exec on the host files: print one line per
 * entry (up to the read limit) and for the old flag file, create the own
 * entry and print `done`, as the production script does.
 *
 * @param files - The host marker and containment files, updated in place.
 * @param command - The establish exec.
 * @returns The script's stdout.
 */
function modelContainmentEstablish(files: Map<string, string>, command: string): string {
  const [, legacy = "", entryDirectory = "", own = "", body = ""] = scriptArguments(
    command,
    containmentEstablishPrefix
  )
  const readLine = (label: string, content: string): string =>
    `${label} ${sha256Of(content)} ${Buffer.from(content)
      .subarray(0, CONTAINMENT_FLAG_BODY_LIMIT_BYTES + 1)
      .toString("hex")}`
  const entries = [...files.keys()]
    .filter((path) => path.startsWith(`${entryDirectory}/run-`))
    .toSorted()
  const lines = entries
    .slice(0, CONTAINMENT_ENTRY_READ_LIMIT)
    .map((path) => readLine(`entry ${posix.basename(path)}`, files.get(path) ?? ""))
  const legacyContent = files.get(legacy)
  if (legacyContent !== undefined) lines.push(readLine("legacy", legacyContent))
  if (entries.length > CONTAINMENT_ENTRY_READ_LIMIT) lines.push("more")
  files.set(own, body)
  return `${[...lines, "done"].join("\n")}\n`
}

/**
 * Issue #219: model the clear exec on the host files: claim every listed
 * entry, remove the claim when its content still has the hash that was read,
 * keep it under its claim name otherwise, then remove the own entry.
 *
 * @param files - The host marker and containment files, updated in place.
 * @param command - The clear exec.
 */
function modelContainmentClear(files: Map<string, string>, command: string): void {
  const [own = "", ...pairs] = scriptArguments(command, containmentClearPrefix)
  for (let index = 0; index * 2 < pairs.length; index += 1) {
    const path = pairs[index * 2] ?? ""
    const content = files.get(path)
    if (content === undefined) continue
    files.delete(path)
    if (sha256Of(content) !== pairs[index * 2 + 1])
      files.set(`${own}-claim-${String(index)}`, content)
  }
  files.delete(own)
}

/**
 * Issue #219: apply what a successful containment exec changes on the
 * modelled host files, and answer the establish exec from them.
 *
 * @param files - The host marker and containment files, if the test models them.
 * @param command - The executed command.
 * @param result - The mock's answer, kept when the exec failed or no files are modelled.
 * @returns The answer the module sees.
 */
function answerFromHostFiles(
  files: Map<string, string> | undefined,
  command: string,
  result: ExecResult
): ExecResult {
  if (files === undefined || result.code !== 0) return result
  if (command.startsWith(containmentEstablishPrefix)) {
    return { ...result, stdout: modelContainmentEstablish(files, command) }
  }
  if (command.startsWith(containmentClearPrefix)) modelContainmentClear(files, command)
  return result
}

function applyHostSideEffects(host: HostLinkRun, command: string): void {
  if (archiveStageMovePattern.test(command)) {
    const merged = [...host.shipped, ...(host.injectedOnMerge ?? [])]
    for (const [link, target] of merged) host.tree.set(link, target)
  }
}

function answerFromHostLinks(
  host: HostLinkRun,
  command: string,
  exchange: { input: string | undefined; result: ExecResult }
): ExecResult {
  const { input, result } = exchange
  if (result.code === 0) applyHostSideEffects(host, command)
  else if (archiveStageMovePattern.test(command)) publishInjectedLinks(host)
  if (command === symlinkListingProbeCommand) {
    return { ...result, stdout: listingProbeStdout(host.tree, input ?? "") }
  }
  return result
}

/**
 * Issue #219: scripted answers for the post-merge backstop listing, consumed
 * in call order. The last answer repeats once the others are used up.
 */
type BackstopScript = {
  /** Answers of the post-merge listings. */
  listings: Array<Partial<ExecResult>>
}

/**
 * Issue #219: take the next scripted answer from a queue, keeping the last one.
 *
 * @param queue - The remaining answers, updated in place.
 * @returns The answer, or undefined when nothing is scripted.
 */
function nextScriptedAnswer(queue: Array<Partial<ExecResult>>): ExecResult | undefined {
  const next = queue.length > 1 ? queue.shift() : queue[0]
  return next === undefined ? undefined : { code: 0, stderr: "", stdout: "", ...next }
}

/**
 * Issue #219: whether an exec is the post-merge backstop listing: the listing
 * command with the destination as its only entry.
 *
 * @param command - The executed command.
 * @param input - The exec's stdin.
 * @returns True for the post-merge listing, false for the pre-merge one.
 */
function isPostMergeListing(command: string, input: string | undefined): boolean {
  return command === symlinkListingProbeCommand && input === postMergeListingInput
}

/**
 * Issue #219: the scripted backstop answer for an exec, if any.
 *
 * @param script - The scripted backstop answers, consumed in place.
 * @param command - The executed command.
 * @param input - The exec's stdin.
 * @returns The scripted result, or undefined to keep the mock's answer.
 */
function scriptedBackstopAnswer(
  script: BackstopScript | undefined,
  command: string,
  input: string | undefined
): ExecResult | undefined {
  if (script === undefined) return undefined
  if (isPostMergeListing(command, input)) return nextScriptedAnswer(script.listings)
  return undefined
}

/**
 * Issue #219: the host model, scripted backstop answers and failure injection
 * the apply harness adds to the mock connection.
 */
type ExecHarness = {
  backstop?: BackstopScript
  /** Issue #219: the host marker and containment files the containment execs model. */
  files?: Map<string, string>
  host?: HostLinkRun
  postMergeListings?: number[]
  throwOn?: ThrowingExec
}

/**
 * Issue #219: run one exec through the harness: record a post-merge listing,
 * reject the exec the harness should fail, then answer from the mock, the host
 * model and the scripted backstop answers, in increasing priority.
 *
 * @param mockSsh - The mock connection whose calls are recorded.
 * @param exchange - The exec to run.
 * @param exchange.command - The command being executed.
 * @param exchange.options - Stdin and flags passed to exec.
 * @param exchange.originalExec - The mock's own exec, before the spy.
 * @param harness - The additions to apply (see {@link recordSymlinkProbes}).
 * @returns The answer the module sees.
 */
async function harnessedExec(
  mockSsh: MockSsh,
  exchange: {
    command: string
    options: ExecOptions | undefined
    originalExec: SshConnection["exec"]
  },
  harness: ExecHarness
): Promise<ExecResult> {
  const { command, options, originalExec } = exchange
  const { backstop, host } = harness
  const input = options?.input
  // Recorded before the exec, so a listing that throws is counted as well.
  if (isPostMergeListing(command, input)) harness.postMergeListings?.push(mockSsh.calls.length)
  rejectMatchingExec(mockSsh, { command, input }, harness)
  const executed = answerFromHostFiles(harness.files, command, await originalExec(command, options))
  const modelled =
    host === undefined ? executed : answerFromHostLinks(host, command, { input, result: executed })
  return scriptedBackstopAnswer(backstop, command, input) ?? modelled
}

/**
 * Record the NUL-separated payload of every batched symlink probe and report
 * the given host paths as symlinks whenever a probe carries them.
 *
 * @param mockSsh - The mock connection to patch.
 * @param hostSymlinks - Absolute host paths the probe reports as symlinks.
 * @param harness - Optional host link model and exec to reject.
 * @param harness.backstop - Issue #219: scripted post-merge listing answers.
 * @param harness.files - Issue #219: host files the containment execs model.
 * @param harness.host - Host link model that the merge updates and both listings read.
 * @param harness.postMergeListings - Issue #219: collects the position in
 *   `mockSsh.calls` of every post-merge backstop listing.
 * @param harness.throwOn - Issue #219: an exec that rejects after being recorded.
 * @returns The recorded probes, in call order, with their position in `mockSsh.calls`.
 */
function recordSymlinkProbes(
  mockSsh: MockSsh,
  hostSymlinks: readonly string[] = [],
  harness: ExecHarness = {}
): SymlinkProbeRecord[] {
  const originalExec = mockSsh.exec.bind(mockSsh)
  const probes: SymlinkProbeRecord[] = []
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    const result = await harnessedExec(mockSsh, { command, options, originalExec }, harness)
    if (command !== symlinkProbeCommand && command !== preStagingProbeCommand) return result
    // Issue #219: the pre-staging probe carries its symlink checks as `l:`
    // entries and reports `(check, path)` pairs.
    const preStaging = command === preStagingProbeCommand
    const entries = preStaging
      ? taggedEntryPaths(options?.input, "l")
      : pathsFromNulPayload(options?.input)
    probes.push({ callIndex: mockSsh.calls.length - 1, entries })
    const reported = entries.filter((entry) => hostSymlinks.includes(entry))
    if (reported.length === 0) return result
    const fields = preStaging ? reported.flatMap((entry) => ["l", entry]) : reported
    return { ...result, stdout: fields.map((field) => `${field}\u0000`).join("") }
  })
  return probes
}

type TarListingApplyRun = {
  markerWrites: () => number
  mockSsh: MockSsh
  /**
   * Issue #219: the own containment entry the establish exec created, or
   * undefined when the apply never got that far.
   */
  ownEntry: string | undefined
  /**
   * Issue #219: the position in `mockSsh.calls` of every post-merge backstop
   * listing, in call order.
   */
  postMergeListings: number[]
  probes: SymlinkProbeRecord[]
  result: ModuleResult
  /** Issue #219: what `apply` rejected with; undefined when it returned a result. */
  thrown: unknown
  /** Every `writeFile`, with the number of `exec` calls issued before it. */
  writes: Array<{ callIndex: number; remotePath: string }>
}

/**
 * Issue #219: the archive content hash the mocks report for a source, distinct
 * per source so two sources never share a matching marker.
 *
 * @param source - The archive path.
 * @returns The hash `sha256` reports for it.
 */
function archiveShaFor(source: string): string {
  return source === src ? archiveSha : createHash("sha256").update(source).digest("hex")
}

/**
 * The content marker path for a source extracted into the destination,
 * derived independently of the module.
 *
 * @param source - The archive path.
 * @returns The absolute marker path.
 */
function markerFor(source: string): string {
  const hash = createHash("sha256").update(`${source}\n${destination}`).digest("hex")
  return `/var/lib/paratix/flags/archive-${hash}.sha256`
}

/**
 * Issue #219: the own entry the establish exec of a run created.
 *
 * @param calls - The run's commands.
 * @returns The own entry, or undefined when no establish exec ran.
 */
function ownEntryOf(calls: readonly string[]): string | undefined {
  const establish = calls.find((command) => command.startsWith(containmentEstablishPrefix))
  return establish === undefined
    ? undefined
    : scriptArguments(establish, containmentEstablishPrefix)[3]
}

/**
 * Issue #219: a run's commands with the establish and clear execs replaced by
 * placeholders; they differ between runs only in their arguments (the own
 * entry, the entries to remove).
 *
 * @param run - The recorded apply run.
 * @param run.mockSsh - The mock connection with the recorded commands.
 * @returns The commands in call order.
 */
function commandsWithoutContainmentArguments(run: { mockSsh: MockSsh }): string[] {
  return run.mockSsh.calls.map((command) => {
    if (command.startsWith(containmentEstablishPrefix)) return "<establish>"
    return isContainmentClear(command) ? "<clear>" : command
  })
}

type TarListingApplyOptions = {
  /**
   * Issue #219: scripted answers of the post-merge listings; the last one
   * repeats. The pre-merge listing is unaffected.
   */
  backstopListings?: ReadonlyArray<Partial<ExecResult>>
  /** `writeFile` rejects this path, e.g. to fail the containment-flag write. */
  failWrite?: string
  /**
   * Issue #219: `writeFile` rejects a write for which this returns true, e.g.
   * only the failure record of the containment flag.
   */
  failWriteWhen?: (remotePath: string, content: string) => boolean
  /**
   * Issue #219: host marker and containment files. Writes add them, and the
   * establish and clear execs read and change them, so a test can span
   * several runs on one host and `check` can be answered from them.
   */
  files?: Map<string, string>
  hostLinks?: HostLinkTree
  hostSymlinks?: readonly string[]
  injectedOnMerge?: ReadonlyArray<readonly [string, string]>
  /**
   * Issue #219: the listing mode line before the lines; GNU tar in C.UTF-8
   * when omitted.
   */
  listingModeLine?: string
  owner?: string
  /** Exact command responses that take priority over the shared stubs. */
  responses?: NonNullable<Parameters<typeof createBaseMockSsh>[0]>
  /** Issue #219: pattern stubs that take priority over the shared stubs. */
  responseStubs?: NonNullable<typeof archiveApplyResponseStubs>
  source?: string
  /** Issue #219: an exec that rejects instead of returning a result. */
  throwOn?: ThrowingExec
}

async function applyTarListing(
  lines: readonly string[],
  options: TarListingApplyOptions = {}
): Promise<TarListingApplyRun> {
  const { failWrite, files, hostLinks, source = src } = options
  const mockSsh = createMockSsh(
    {
      [stagedTarExtractCommandFor(source)]: { code: 0 },
      [tarListCommand(source)]: {
        code: 0,
        stdout: `${options.listingModeLine ?? gnuTarListingModeLine}${lines.join("\n")}\n`,
      },
      ...options.responses,
    },
    { responseStubs: options.responseStubs }
  )
  vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveShaFor(source))
  const writes: TarListingApplyRun["writes"] = []
  vi.spyOn(mockSsh, "writeFile").mockImplementation(async (remotePath, content) => {
    await Promise.resolve()
    writes.push({ callIndex: mockSsh.calls.length, remotePath })
    if (remotePath === failWrite || options.failWriteWhen?.(remotePath, content) === true) {
      throw new Error("No space left on device")
    }
    files?.set(remotePath, content)
  })
  // With a host link model, the pre-merge probes see the links earlier runs left.
  const hostSymlinks = options.hostSymlinks ?? [...(hostLinks?.keys() ?? [])]
  const host =
    hostLinks === undefined
      ? undefined
      : {
          injectedOnMerge: options.injectedOnMerge,
          shipped: shippedSymlinks(lines),
          tree: hostLinks,
        }
  const postMergeListings: number[] = []
  const backstop = { listings: [...(options.backstopListings ?? [])] }
  const probes = recordSymlinkProbes(mockSsh, hostSymlinks, {
    backstop,
    files,
    host,
    postMergeListings,
    throwOn: options.throwOn,
  })
  const moduleOptions = options.owner === undefined ? {} : { owner: options.owner }
  let thrown: unknown
  const result = await archive
    .extract(source, destination, moduleOptions)
    .apply(mockSsh, emptyEnv)
    .catch((error: unknown): ModuleResult => {
      thrown = error
      return { status: "failed" }
    })
  return {
    markerWrites: () => writes.length,
    mockSsh,
    ownEntry: ownEntryOf(mockSsh.calls),
    postMergeListings,
    probes,
    result,
    thrown,
    writes,
  }
}

/**
 * Issue #219: run `check` for a source against the marker and containment
 * files an earlier apply left in the host model. The combined marker test is
 * answered from the model, so any containment entry or old flag file makes
 * it fail.
 *
 * @param source - The archive path.
 * @param files - The host marker and flag files.
 * @returns The check verdict and the issued commands.
 */
async function checkAgainstHostFiles(
  source: string,
  files: ReadonlyMap<string, string>
): Promise<{ calls: string[]; result: "needs-apply" | "ok" }> {
  const sourceMarker = markerFor(source)
  const catFile = (path: string): Partial<ExecResult> => {
    const content = files.get(path)
    return content === undefined
      ? { code: 1, stderr: `cat: ${path}: No such file or directory` }
      : { code: 0, stdout: content }
  }
  const markerTestPasses = files.has(sourceMarker) && !hasContainmentState(files)
  const mockSsh = createMockSsh({
    [`cat '${sourceMarker}.members'`]: catFile(`${sourceMarker}.members`),
    [`cat '${sourceMarker}'`]: catFile(sourceMarker),
    [markerCheckCommand(sourceMarker)]: { code: markerTestPasses ? 0 : 1 },
  })
  vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveShaFor(source))
  const result = await archive.extract(source, destination).check(mockSsh, emptyEnv)
  return { calls: mockSsh.calls, result }
}

/**
 * Condense an apply run into the facts the link-target tests assert on. The
 * summary carries the rejection reason, so a failing acceptance case prints
 * why it was refused.
 *
 * @param run - The recorded apply run.
 * @returns Status, error text, `tar -x` invocations and whether markers were written.
 */
function extractionSummary(run: TarListingApplyRun): {
  error: string | undefined
  markerWritten: boolean
  status: ModuleResult["status"]
  tarExtractCalls: string[]
} {
  return {
    error: run.result.error === undefined ? undefined : String(run.result.error),
    markerWritten: run.markerWrites() > 0,
    status: run.result.status,
    tarExtractCalls: run.mockSsh.calls.filter((command) => /^tar\b.*\s-x\S*\s/v.test(command)),
  }
}

const extractedThroughStaging = {
  error: undefined,
  markerWritten: true,
  status: "changed",
  tarExtractCalls: [stagedTarExtractCommand],
}

function refusedBeforeExtraction(reason: string): ReturnType<typeof extractionSummary> {
  return {
    error: expect.stringContaining(`[archive.extract] refusing to extract ${src}: ${reason}`),
    markerWritten: false,
    status: "failed",
    tarExtractCalls: [],
  }
}

/**
 * Issue #219: the summary of an apply that host state refused after it
 * created its containment entry, before anything was staged: the only write
 * is the failure record in that entry, which counts as `markerWritten` here.
 *
 * @param reason - The refusal reason after the source.
 * @returns The expected summary.
 */
function refusedAfterContainmentFlag(reason: string): ReturnType<typeof extractionSummary> {
  return { ...refusedBeforeExtraction(reason), markerWritten: true }
}

/**
 * Issue #219: the writes of the first apply in a test that failed after it
 * created its containment entry: only the failure record in that entry; the
 * establish exec created the entry itself.
 */
const containmentFlagWritesOfFailedApply = [ownEntry()]

/**
 * Issue #219: assert that an apply wrote only its failure record into its own
 * containment entry and never ran the clear exec, so `check` keeps reporting
 * needs-apply.
 *
 * @param run - The recorded apply run.
 */
function expectContainmentFlagKept(run: TarListingApplyRun): void {
  expect(run.ownEntry).toBeDefined()
  expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([run.ownEntry])
  expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
}

/**
 * Collect the entries of every symlink probe issued after the archive listing
 * and before the staged `tar -x`, i.e. the pre-staging member probe.
 *
 * @param run - The recorded apply run.
 * @returns The probed host paths.
 */
function preStagingProbeEntries(run: TarListingApplyRun): string[] {
  const listingIndex = run.mockSsh.calls.indexOf(tarListCommand(src))
  const extractIndex = run.mockSsh.calls.indexOf(stagedTarExtractCommand)
  const endIndex = extractIndex === -1 ? Number.POSITIVE_INFINITY : extractIndex
  return run.probes
    .filter((probe) => probe.callIndex > listingIndex && probe.callIndex < endIndex)
    .flatMap((probe) => probe.entries)
}

/**
 * Issue #219: the guard paths the staging merge received, decoded from the
 * NUL-terminated stdin of its exec.
 *
 * @param mockSsh - The mock connection whose exec calls are recorded.
 * @returns The guard paths, or an empty list when no merge ran.
 */
function stagingMergeGuardPaths(mockSsh: MockSsh): string[] {
  const merge = mockSsh.execCalls.find(({ command }) => archiveStageMovePattern.test(command))
  return pathsFromNulPayload(merge?.options?.input)
}

describe("archive.extract — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = archive.extract(src, destination)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when destination does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [
          {
            command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
            result: { code: 1 },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when destination is a symlink to a directory", async () => {
    const mockSsh = createMockSsh(
      {
        [markerCheckCommand(marker)]: { code: 0 },
      },
      {
        responseStubs: [
          {
            command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
            result: { code: 1 },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when destination resolves elsewhere", async () => {
    const mockSsh = createMockSsh(
      {
        [markerCheckCommand(marker)]: { code: 0 },
      },
      {
        responseStubs: [
          {
            command: `readlink -f -- '${destination}'`,
            result: { code: 0, stdout: "/tmp/attacker-target\n" },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when marker file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 1 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when marker matches remote archive sha256", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
  })

  it("folds the containment-failure flag into the single marker test (Issue #219)", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const result = await archive.extract(src, destination).check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    // One `test` call covers the marker and the flag, so `check` issues no
    // extra round trip for the flag and never writes or removes it.
    expect(
      mockSsh.calls.filter((command) => command.includes("archive-containment-"))
    ).toStrictEqual([markerCheckCommand(marker)])
    expect(mockSsh.calls.filter((command) => command.includes(marker))).toStrictEqual([
      markerCheckCommand(marker),
      `cat '${membersMarker}'`,
      `cat '${marker}'`,
    ])
    expect(mockSsh.writeFileCalls).toStrictEqual([])
    expect(mockSsh.calls.some((command) => /^(?:rm|mkdir) /v.test(command))).toBe(false)
  })

  it("returns needs-apply when an extracted member was deleted after extraction", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeDriftResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when an extracted directory was replaced by a symlink", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "directory", path: `${destination}/app` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: { code: 0, stdout: `${destination}/app\u0000` },
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the members marker is missing", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: { code: 1, stderr: "cat: No such file or directory" },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when the members marker contains invalid JSON", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: { code: 0, stdout: "{not-json" },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
  })

  it("returns needs-apply when the members marker read was truncated", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: `${JSON.stringify([extractedFileMember])}${CAPTURE_TRUNCATION_MARKER}`,
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
    })

    const result = await archive.extract(src, destination).check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
    expect(mockSsh.calls).not.toContain(extractedFileTypeProbe)
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when the members marker has an invalid schema", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "socket", path: `${destination}/app/file` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns ok when marker matches and extracted owner matches", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, { pinCLocale: true })
  })

  it("returns needs-apply when extracted owner has drifted", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expect(mockSsh.calls).toContain(ownershipProbeCommand("www-data:www-data"))
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("issues one ownership probe no matter how many members are recorded", async () => {
    // Issue #180: this used to assert that at most eight owner checks ran
    // concurrently. There is no concurrency left to bound — the whole set now
    // travels in a single probe, which is the stronger property.
    const memberPaths = Array.from({ length: 500 }, (_value, index) => `app/file-${String(index)}`)
    const ownerPathsMarker = `${marker}.owner-paths`
    const ownerProbe = ownershipProbeCommand("www-data:www-data")
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify(
          memberPaths.map((path) => ({ kind: "file", path: `${destination}/${path}` }))
        ),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify(memberPaths.map((path) => `${destination}/${path}`)),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      [ownerProbe]: { code: 0, stdout: "" },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls.filter((command) => command === ownerProbe)).toHaveLength(1)
  })

  it("returns needs-apply when marker does not match remote archive sha256", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: "old-hash" },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const sha256Spy = vi.spyOn(mockSsh, "sha256").mockResolvedValue("new-hash")
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
    expect(sha256Spy).toHaveBeenCalledWith(src)
  })

  it("uses a distinct marker for a second destination with the same archive", async () => {
    const alternateMarkerHash = "cde8e7e8eb1b5af4f516117a5a2ed09a67b8a0fbbcc792d793901f00f15bc9a0"
    const alternateMarker = `/var/lib/paratix/flags/archive-${alternateMarkerHash}.sha256`
    const mockSsh = createMockSsh({
      [`test -d '${alternateDestination}'`]: { code: 0 },
      [markerCheckCommand(alternateMarker, alternateDestination)]: { code: 1 },
    })

    const mod = archive.extract(src, alternateDestination)
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(markerCheckCommand(marker))
  })

  it("R-0000276: returns needs-apply when marker cat fails with a non-missing error", async () => {
    // Permission-denied (or any non "No such file" error) on the marker
    // must not abort the whole run. Treat the unreadable marker as drift
    // so apply rewrites the marker on the next run instead of throwing
    // past the runner.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': Permission denied` },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
  })

  it("R-0000105: returns needs-apply when marker cat reports 'No such file'", async () => {
    // Race between test -f and cat (e.g. concurrent cleanup): treat the
    // missing marker as a regular needs-apply, identical to the case where
    // test -f already failed.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': No such file or directory` },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
  })

  it("R-0000276: returns needs-apply when owner-paths marker cat fails with permission denied", async () => {
    // Permission drift on the owner-paths marker (or any non-"no such file"
    // stderr) must not abort the run, but it also must not be confused with a
    // genuinely missing legacy marker. Fail closed without consulting a live
    // archive that may no longer describe the extracted paths.
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 1,
        stderr: `cat: '${ownerPathsMarker}': Permission denied`,
      },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, { pinCLocale: true })
    expect(mockSsh.calls).not.toContain(tarListCommand(src))
    expect(mockSsh.calls).not.toContain(ownershipProbeCommand("www-data:www-data"))
  })

  it("computes local sha256 when upload is true without uploading", async () => {
    const localFile = "/local/app.tar.gz"
    const localFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    // sha256String of `${localFile}\n${destination}` for marker name
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`

    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${localMarker}.members'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${localMarker}'`]: { code: 0, stdout: localFileHash },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(localMarker)]: { code: 0 },
    })

    const fileHelpers = await import("../../src/modules/fileHelpers.js")
    vi.spyOn(fileHelpers, "localSha256").mockResolvedValue(localFileHash)

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    // Verify no upload was triggered during check.
    expect(mockSsh.calls).not.toContain(expect.stringContaining("upload"))

    vi.restoreAllMocks()
  })

  it("returns ok for upload archives when the stored owner paths still match", async () => {
    const localFile = "/local/app.tar.gz"
    const localFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${localMarker}.members'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${localMarker}'`]: { code: 0, stdout: localFileHash },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(localMarker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })

    const fileHelpers = await import("../../src/modules/fileHelpers.js")
    vi.spyOn(fileHelpers, "localSha256").mockResolvedValue(localFileHash)
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()

    vi.restoreAllMocks()
  })

  it("returns needs-apply for upload archives when a stored owner path drifts", async () => {
    const localFile = "/local/app.tar.gz"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`cat '${localMarker}.members'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(localMarker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expect(mockSsh.calls).toContain(ownershipProbeCommand("www-data:www-data"))
    expect(mockSsh.calls).not.toContain(`cat '${localMarker}'`)
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })
})

describe("archive.extract — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = archive.extract(src, destination)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
  })

  // R-0000067: tar invocations now run with `--no-same-owner --no-overwrite-dir`
  // and a member-validation step. Each apply test stubs the member listing
  // with a single safe entry so the validation step passes.
  const safeZipListing = "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file\n"

  it("extracts tar.gz archive and writes marker", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, "/opt")).toBeDefined()
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeDefined()
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`
    )
    expect(mockSsh.calls).toContain(`mkdir -p '/var/lib/paratix/flags'`)
    // R-0000162: extraction must run into the staging dir, never directly into destination.
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(marker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      membersMarker,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
  })

  it("extracts .tar archive", async () => {
    const tarSrc = "/tmp/app.tar"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(tarSrc, "-tvf")]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tarSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .tar.bz2 archive", async () => {
    const bz2Src = "/tmp/app.tar.bz2"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(bz2Src, "-tvjf")]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(bz2Src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .tar.xz archive", async () => {
    const xzSrc = "/tmp/app.tar.xz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(xzSrc, "-tvJf")]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(xzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .zip archive", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -o '${zipSrc}' -d '${archiveStageDirectory}'`]: { code: 0 },
      [`unzip -Zs '${zipSrc}'`]: { code: 0, stdout: safeZipListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`unzip -o '${zipSrc}' -d '${archiveStageDirectory}'`)
    // Issue #219: zip symlinks are rejected, so a zip apply never lists the
    // host's symlinks and never runs the kernel cross-check.
    expect(mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(mockSsh.calls).not.toContain(kernelCrossCheckCommand)
  })

  it("extracts .tgz archive", async () => {
    const tgzSrc = "/tmp/app.tgz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(tgzSrc)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tgzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${archiveStageDirectory}'`
    )
  })

  // Issue #206: realistic distribution archives can emit more than the SSH
  // layer's default 1 MiB capture limit while every member is still safe.
  // The mock does not apply capture limits, so the options assertion is the
  // evidence that production requests the archive-specific 16 MiB budget.
  it.each([
    {
      extractCommand: `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`,
      format: "tar",
      listingCommand: tarListCommand(src),
      listingPrefix: gnuTarListingModeLine,
      memberLine: safeTarListing,
      source: src,
    },
    {
      extractCommand: `unzip -o '/tmp/app.zip' -d '${archiveStageDirectory}'`,
      format: "zip",
      listingCommand: "unzip -Zs '/tmp/app.zip'",
      listingPrefix: "",
      memberLine: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file",
      source: "/tmp/app.zip",
    },
  ])("accepts a safe $format listing above the legacy capture limit", async (testCase) => {
    const listing = `${testCase.listingPrefix}${listingLargerThanLegacyCaptureLimit(testCase.memberLine)}`
    expect(listing.length).toBeGreaterThan(legacyCaptureLimitBytes)
    const mockSsh = createMockSsh({
      [testCase.extractCommand]: { code: 0 },
      [testCase.listingCommand]: { code: 0, stdout: listing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(testCase.source, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expectArchiveCaptureExecCall(mockSsh, testCase.listingCommand, { strictUtf8: true })
  })

  it("accepts a complete archive listing at the exact capture limit", async () => {
    const listing = gnuTarListing(
      singleMemberTarListingOfUtf8Size(
        archiveListingMaxOutputBytes - Buffer.byteLength(gnuTarListingModeLine, "utf8")
      )
    )
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toMatchObject({ members: [{ format: "tar", kind: "file" }] })
    expectArchiveCaptureExecCall(mockSsh, tarListCommand(src), { strictUtf8: true })
  })

  it("treats the truncation marker as authoritative at the capture boundary", async () => {
    const listing = gnuTarListing(
      singleMemberTarListingOfUtf8Size(
        archiveListingMaxOutputBytes - Buffer.byteLength(gnuTarListingModeLine, "utf8"),
        CAPTURE_TRUNCATION_MARKER
      )
    )
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toStrictEqual({
      failureReason: expect.stringMatching(/truncat/iv),
    })
    expectArchiveCaptureExecCall(mockSsh, tarListCommand(src), { strictUtf8: true })
  })

  it("reports an actionable failure when the archive listing is truncated", async () => {
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: {
        code: 0,
        stdout: gnuTarListing(`${safeTarListing}${CAPTURE_TRUNCATION_MARKER}`),
      },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    const message = String(result.error)
    expect(message).toMatch(/truncat/iv)
    expect(message).toContain(String(archiveListingMaxOutputBytes))
    expect(message).not.toContain("could not parse tar listing line")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeUndefined()
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a UTF-8 members marker above the byte limit before destination mutation", async () => {
    const unicodeMemberPath = `app/${"é".repeat(Math.floor(archiveListingMaxOutputBytes / 2))}`
    const listing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ${unicodeMemberPath}`
    const expectedPayload = JSON.stringify([
      { kind: "file", path: `${destination}/${unicodeMemberPath}` },
    ])
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(listing) },
    })

    const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)

    expect(expectedPayload.length).toBeLessThan(archiveListingMaxOutputBytes)
    expect(Buffer.byteLength(expectedPayload, "utf8")).toBeGreaterThan(archiveListingMaxOutputBytes)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("archive members marker payload")
    expect(String(result.error)).toContain(String(Buffer.byteLength(expectedPayload, "utf8")))
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeUndefined()
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("limits chown to extracted members when owner is specified", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [batchedChownCommand]: { code: 0 },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(batchedChownCommand)
    expect(mockSsh.calls).not.toContain(`chown -R 'www-data:www-data' '${destination}'`)
  })

  it("issues one chown no matter how many members are extracted", async () => {
    const memberPaths = Array.from({ length: 500 }, (_value, index) => `app/file-${String(index)}`)
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: {
        code: 0,
        stdout: gnuTarListing(tarListingForMemberPaths(memberPaths)),
      },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.filter((command) => command === batchedChownCommand)).toHaveLength(1)
  })

  it("keeps the symlink probe count constant as the member count grows", async () => {
    // The bound is deliberately a fixed number rather than a ratio: a
    // regression back to per-path probing would push this far past it, which is
    // what makes the assertion worth having.
    const runWith = async (
      memberCount: number,
      extraLines: readonly string[] = []
    ): Promise<{
      crossChecks: number
      listingProbes: number
      postMergeListings: number
      symlinkProbes: number
    }> => {
      const memberPaths = Array.from(
        { length: memberCount },
        (_value, index) => `app/file-${String(index)}`
      )
      const mockSsh = createMockSsh({
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [tarListCommand(src)]: {
          code: 0,
          stdout: gnuTarListing([tarListingForMemberPaths(memberPaths), ...extraLines].join("\n")),
        },
      })
      vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
      vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

      const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      const count = (probe: string): number =>
        mockSsh.calls.filter((command) => command === probe).length
      const listings = mockSsh.execCalls.filter(
        ({ command }) => command === symlinkListingProbeCommand
      )
      const postMerge = listings.filter(({ options }) => options?.input === postMergeListingInput)
      return {
        crossChecks: count(kernelCrossCheckCommand),
        listingProbes: listings.length - postMerge.length,
        postMergeListings: postMerge.length,
        symlinkProbes: count(symlinkProbeCommand),
      }
    }

    const few = await runWith(5)
    const many = await runWith(500)
    // Issue #219: only an archive with a symlink member needs the listings.
    const symlinkLine = tarSymlinkLine("app/link", "file-0")
    const fewWithSymlink = await runWith(5, [symlinkLine])
    const manyWithSymlink = await runWith(500, [symlinkLine])

    expect(many.symlinkProbes).toBe(few.symlinkProbes)
    expect(many.symlinkProbes).toBeLessThanOrEqual(4)
    expect(manyWithSymlink.symlinkProbes).toBe(fewWithSymlink.symlinkProbes)
    // Issue #219: an archive without symlink members cannot change how any
    // path resolves, so neither the pre-merge listing nor the post-merge
    // backstop runs an exec for it.
    expect([few, many].map(({ listingProbes }) => listingProbes)).toStrictEqual([0, 0])
    expect([few, many].map(({ postMergeListings }) => postMergeListings)).toStrictEqual([0, 0])
    // Issue #219: with a symlink member, the post-merge backstop lists the
    // whole tree in one exec and resolves it in TypeScript, and the pre-merge
    // listing is one exec as well, regardless of member count.
    expect(
      [fewWithSymlink, manyWithSymlink].map(({ listingProbes, postMergeListings }) => [
        listingProbes,
        postMergeListings,
      ])
    ).toStrictEqual([
      [1, 1],
      [1, 1],
    ])
    // Issue #219: a tree without judged symlinks needs no kernel cross-check.
    expect(
      [few, many, fewWithSymlink, manyWithSymlink].map(({ crossChecks }) => crossChecks)
    ).toStrictEqual([0, 0, 0, 0])
  })

  it("R-0000267: returns failed when chown of an extracted member fails", async () => {
    // chown errors (EPERM, ENOENT, quota) must surface as a maskable
    // failedCommand result instead of leaking past Promise.all in the
    // concurrency-limited mapper as an uncaught CommandError.
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [batchedChownCommand]: {
        code: 1,
        stderr: "chown: changing ownership of '/opt/app/app/file': Operation not permitted",
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("chown failed for")
    expect(String(result.error)).toContain(`${destination}/app/file`)
    // Marker must not be written when chown fails — otherwise the next check
    // would flag the broken state as ok. Issue #219: only the containment flag,
    // written before the merge, is on disk, and it keeps `check` at needs-apply.
    // The backstop had passed, so the failure records no offending links.
    const flagWrites = vi.mocked(mockSsh.writeFile).mock.calls
    expect(flagWrites.map(([path]) => path)).toStrictEqual(containmentFlagWritesOfFailedApply)
    expect(flagWrites.at(-1)?.[1]).toBe(recordedFlag())
  })

  it("rejects option-like owner specs before member chown", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "-R" })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      'chown owner component must not start with "-": "-R"'
    )
    expect(mockSsh.calls).not.toContain("xargs -0 chown -h -- '-R'")
  })

  // R-0000700 / R-0000706: invalid destinations now fail fast at module
  // construction so no apply/check work is ever scheduled. The tests below
  // therefore assert that the constructor throws instead of yielding a
  // `failed` ModuleResult.
  it("rejects root destination before extracting when owner is specified", () => {
    expect(() => archive.extract(src, "/", { owner: "www-data:www-data" })).toThrow(
      /refusing to extract/v
    )
  })

  it.each(["/", "/tmp/..", "/var/.."])(
    "rejects destination %s after POSIX normalization",
    (rootLikeDestination) => {
      expect(() => archive.extract(src, rootLikeDestination)).toThrow(/destructive destination \//v)
    }
  )

  it("rejects relative destinations before extracting", () => {
    expect(() => archive.extract(src, "opt/app")).toThrow(/destination must be an absolute path/v)
  })

  // R-0000672: control characters in the extract destination must be rejected
  // before moveExtractedContentsIntoDestination feeds the guard-paths list into
  // the symlink walk. A literal `\n` in destination would split the list and
  // bypass the per-ancestor symlink probes; `\x00` would terminate the path
  // early when interpolated into a shell argument. Tests use JavaScript escape
  // sequences instead of literal control bytes so the source stays
  // grep-friendly and the intent of each case is explicit.
  // Issue #219: the guard paths now travel NUL-terminated on stdin, so a
  // newline no longer splits them; a NUL now would, and the refusal stays.
  it.each([
    ["newline", "/opt/app\n/etc"],
    ["carriage return", "/opt/app\r/etc"],
    ["NUL", "/opt/app\u0000/etc"],
    ["tab", "/opt/app\t/etc"],
  ])("rejects destinations containing %s control characters", (_label, destinationWithControl) => {
    expect(() => archive.extract(src, destinationWithControl)).toThrow(
      /must not contain control characters/v
    )
  })

  it("uploads file via mktemp-allocated path and cleans up when upload is true", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
      [tarListCommand(remoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.uploadFile).toHaveBeenCalledWith(localFile, remoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
  })

  it("persists extracted owner paths for upload archives with owner", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [batchedChownCommand]: { code: 0 },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
      [tarListCommand(remoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFile).toHaveBeenCalledWith(localMarker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      `${localMarker}.members`,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      ownerPathsMarker,
      JSON.stringify([`${destination}/app/file`]),
      { mode: "0644" }
    )
  })

  it("regression: allocates a fresh remote upload path per invocation, even with identical local sources", async () => {
    const localFile = "/local/app.tar.gz"
    const firstRemoteTmp = "/tmp/paratix-upload.FIRST111"
    const secondRemoteTmp = "/tmp/paratix-upload.SECOND22"

    const responses: string[] = [firstRemoteTmp, secondRemoteTmp]
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${firstRemoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${secondRemoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "ignored-by-spy" },
      [tarListCommand(firstRemoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      [tarListCommand(secondRemoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    // mktemp is queried via conn.output; rotate the response so concurrent
    // upload invocations produce different paths even though the local source
    // is identical. The staging-dir mktemp -d (R-0000162) is delegated to the
    // base output implementation so it still resolves via the response stubs
    // configured at module scope.
    rotateUploadMktempResponses(mockSsh, responses)
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const modA = archive.extract(localFile, destination, { upload: true })
    const modB = archive.extract(localFile, destination, { upload: true })

    const resultA = await modA.apply(mockSsh, emptyEnv)
    const resultB = await modB.apply(mockSsh, emptyEnv)

    expect(resultA.status).toBe("changed")
    expect(resultB.status).toBe("changed")
    expect(mockSsh.uploadFile).toHaveBeenNthCalledWith(1, localFile, firstRemoteTmp)
    expect(mockSsh.uploadFile).toHaveBeenNthCalledWith(2, localFile, secondRemoteTmp)
    expect(firstRemoteTmp).not.toBe(secondRemoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${firstRemoteTmp}'`)
    expect(mockSsh.calls).toContain(`rm -f -- '${secondRemoteTmp}'`)
  })

  it("regression: rejects with a clear error when mktemp returns an empty string", async () => {
    const localFile = "/local/app.tar.gz"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "" },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp did not return a remote path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("R-0000106: rejects a poisoned mktemp output (locale warning) without uploading", async () => {
    // Older paratix versions handed every byte from `mktemp` straight into
    // `uploadFile` / `tar -xzf` / `rm -f`. A locale warning prepended by a
    // hostile or misconfigured shell would turn into a path like
    //   "mktemp: ungültiges Format ...\n/tmp/paratix-upload.AbCdEfGh"
    // and silently corrupt the upload pipeline. The validateMktempPath
    // guard rejects the entire payload instead of using the second line.
    const localFile = "/local/app.tar.gz"
    const poisonedOutput = "mktemp: ungültiges Format ...\n/tmp/paratix-upload.AbCdEfGh"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: poisonedOutput },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp produced an unexpected path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("R-0000106: rejects a mktemp output with the wrong prefix without uploading", async () => {
    // A `mktemp` whose stdout escapes /tmp/paratix-upload.* (e.g. the
    // operator pinned an alternate template via PATH=/usr/local/bin) must
    // not be used as the upload path — uploadFile and tar would otherwise
    // touch a file outside the dedicated namespace.
    const localFile = "/local/app.tar.gz"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": {
        code: 0,
        stdout: "/tmp/other-prefix.AbCdEfGh",
      },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp produced an unexpected path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("returns failed when extraction fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 1,
        stderr: "tar: unexpected EOF",
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[archive.extract] failed to extract")
    // R-0000162: even when extraction fails, the staging directory must be cleaned up.
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("returns failed for unsupported archive format", async () => {
    const badSrc = "/tmp/app.rar"
    const mockSsh = createMockSsh({})

    const mod = archive.extract(badSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("unsupported archive format")
  })

  it("cleans up uploaded file when extraction fails", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.FAIL1234"

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 1,
        },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
      [tarListCommand(remoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // Cleanup must remove the same mktemp-allocated path that was used for the upload.
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
  })

  it("returns failed and stops when creating the destination directory fails", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"
    const mockSsh = createMockSsh(
      {
        "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
        [tarListCommand(remoteTmp)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: guardedArchiveDestinationMkdirCommand(destination),
            result: { code: 1, stderr: "mkdir: cannot create directory: Permission denied" },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create destination directory")
    expect(mockSsh.uploadFile).toHaveBeenCalledWith(localFile, remoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
    expect(mockSsh.calls).toContain(tarListCommand(remoteTmp))
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`
    )
    expect(mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("fails when the inline destination mkdir guard sees a symlink after validation", async () => {
    const mockSsh = createMockSsh(
      {
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: guardedArchiveDestinationMkdirCommand(destination),
            result: { code: 1, stderr: "destination path is a symlink\n" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create destination directory")
    expect(mockSsh.calls).toContain(guardedArchiveDestinationMkdirCommand(destination))
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("returns failed when sha256 of remote archive is null", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(null)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns failed when the archive marker directory cannot be created", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: "mkdir -p '/var/lib/paratix/flags'",
            result: { code: 1, stderr: "mkdir: permission denied" },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create archive marker directory")
    // Issue #219: the flags directory is created by the flag read, which is a
    // separate command; only the marker writes are missing, and the flag
    // records the failure without offending links.
    const flagWrites = vi.mocked(mockSsh.writeFile).mock.calls
    expect(flagWrites.map(([path]) => path)).toStrictEqual(containmentFlagWritesOfFailedApply)
    expect(flagWrites.at(-1)?.[1]).toBe(recordedFlag())
  })

  it("returns failed when writing the archive content marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the establish exec creates the containment entry, so the
    // first write is the content marker.
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(new Error("disk full"))

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive marker")
    expect(String(result.error)).toContain("disk full")
  })

  it("returns failed when writing the extracted members marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the establish exec creates the containment entry, so the
    // first write is the content marker.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("quota exceeded"))

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive members marker")
    expect(String(result.error)).toContain("quota exceeded")
  })

  it("returns failed when writing the owner paths marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [batchedChownCommand]: { code: 0 },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the establish exec creates the containment entry, so the
    // first write is the content marker.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("read-only file system"))

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive owner marker")
    expect(String(result.error)).toContain("read-only file system")
  })

  // R-0000067 regression: archive.extract must list members and reject any
  // path that escapes the destination via `..` or absolute paths, before
  // running the actual extract command. This prevents zip-slip / tar-slip
  // even when the archive's sha256 has been pinned previously but the
  // archive was crafted before the pin.
  it("rejects a tar archive that contains a `../escape` member without invoking tar -x", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ../escape\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member is an absolute path", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 /etc/passwd\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target points outside the destination", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target is an absolute path", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to /etc/passwd\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target traverses outside the destination", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction when an existing destination ancestor is a symlink", async () => {
    const mockSsh = createMockSsh({
      [symlinkProbeCommand]: { code: 0, stdout: `${destination}\u0000` },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("destination path")
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).not.toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction before creating the destination when a parent directory is a symlink", async () => {
    const symlinkedDestinationAncestor = "/opt"
    const mockSsh = createMockSsh({})
    stubSymlinkViolationFor(mockSsh, symlinkedDestinationAncestor)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(JSON.stringify(symlinkedDestinationAncestor))
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).not.toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction when an existing member ancestor is a symlink", async () => {
    const symlinkedMemberAncestor = `${destination}/app`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    stubSymlinkViolationFor(mockSsh, symlinkedMemberAncestor)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(JSON.stringify(symlinkedMemberAncestor))
    expect(String(result.error)).toContain("is a symlink")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeDefined()
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // Issue #219: relative symlink targets resolve from the directory that
  // contains the link, hardlink targets from the archive root. Accepted links
  // must reach the staged `tar -x`; every link that could point, write or
  // resolve outside the destination is still refused before it.
  describe("archive.extract link targets (Issue #219)", () => {
    function nodeDistributionLines(version: string): string[] {
      const root = `./externals/${version}`
      return [
        tarDirectoryLine(`${root}/`),
        tarDirectoryLine(`${root}/bin/`),
        `-rwxr-xr-x ${tarListingLineFields} ${root}/bin/node`,
        tarSymlinkLine(`${root}/bin/corepack`, "../lib/node_modules/corepack/dist/corepack.js"),
        tarSymlinkLine(`${root}/bin/npm`, "../lib/node_modules/npm/bin/npm-cli.js"),
        tarSymlinkLine(`${root}/bin/npx`, "../lib/node_modules/npm/bin/npx-cli.js"),
        tarDirectoryLine(`${root}/lib/`),
        tarDirectoryLine(`${root}/lib/node_modules/`),
        tarDirectoryLine(`${root}/lib/node_modules/corepack/`),
        tarDirectoryLine(`${root}/lib/node_modules/corepack/dist/`),
        tarFileLine(`${root}/lib/node_modules/corepack/dist/corepack.js`),
        tarDirectoryLine(`${root}/lib/node_modules/npm/`),
        tarDirectoryLine(`${root}/lib/node_modules/npm/bin/`),
        tarFileLine(`${root}/lib/node_modules/npm/bin/npm-cli.js`),
        tarFileLine(`${root}/lib/node_modules/npm/bin/npx-cli.js`),
      ]
    }

    /**
     * A chain `l0 -> l1 -> … -> l<links-1> -> end` that ends at a regular file.
     *
     * @param links - Number of symlinks in the chain.
     * @returns The listing lines, the target file last.
     */
    function symlinkChainLines(links: number): string[] {
      const chain = Array.from({ length: links - 1 }, (_value, index) =>
        tarSymlinkLine(`l${String(index)}`, `l${String(index + 1)}`)
      )
      return [...chain, tarSymlinkLine(`l${String(links - 1)}`, "end"), tarFileLine("end")]
    }

    it("extracts the actions runner layout with bin -> ../lib symlinks for node20 and node24", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("./"),
        tarDirectoryLine("./externals/"),
        ...nodeDistributionLines("node20"),
        ...nodeDistributionLines("node24"),
        `-rwxr-xr-x ${tarListingLineFields} ./run.sh`,
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("accepts a symlink into a sibling directory (a/bin/x -> ../lib/y)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/bin/"),
        tarSymlinkLine("a/bin/x", "../lib/y"),
        tarDirectoryLine("a/lib/"),
        tarFileLine("a/lib/y"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a depth-1 symlink whose target climbs two levels (a/x -> ../../y)", async () => {
      const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/x", "../../y")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/x" -> "../../y" would escape destination')
      )
    })

    it("still rejects a root-level symlink that climbs out (x -> ../y)", async () => {
      const run = await applyTarListing([tarSymlinkLine("x", "../y")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "x" -> "../y" would escape destination')
      )
    })

    it("accepts root-level symlinks to a sibling and to the destination root (x -> y, z -> .)", async () => {
      const run = await applyTarListing([
        tarSymlinkLine("x", "y"),
        tarFileLine("y"),
        tarSymlinkLine("z", "."),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it.each([".", "./"])("rejects a symlink member at the destination root (%s)", async (path) => {
      const run = await applyTarListing([tarSymlinkLine(path, "app"), tarDirectoryLine("app/")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(`member ${JSON.stringify(path)} is a link at the destination root`)
      )
    })

    it("rejects a hardlink member at the destination root", async () => {
      const run = await applyTarListing([tarFileLine("app"), tarHardlinkLine(".", "app")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "." is a link at the destination root')
      )
    })

    it("still rejects an absolute symlink target below the destination root", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarSymlinkLine("a/passwd", "/etc/passwd"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/passwd" -> "/etc/passwd" would escape destination')
      )
    })

    it("resolves hardlink targets from the archive root (a/h link to b/f)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("b/"),
        tarFileLine("b/f"),
        tarHardlinkLine("a/h", "b/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a hardlink whose archive-root-relative target climbs out (a/h link to ../f)", async () => {
      // A symlink `a/h -> ../f` would be fine; a hardlink target is a member
      // name relative to the archive root, so `../f` leaves the destination.
      const run = await applyTarListing([tarDirectoryLine("a/"), tarHardlinkLine("a/h", "../f")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/h" -> "../f" would escape destination')
      )
    })

    it("rejects a symlink that escapes through another archive symlink (a/up -> .., a/esc -> up/..)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarSymlinkLine("a/up", ".."),
        tarSymlinkLine("a/esc", "up/.."),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/esc" -> "up/.." would escape destination')
      )
    })

    it("accepts a symlink to its parent directory on its own (a/up -> ..)", async () => {
      const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("accepts a symlink that resolves through an archive symlink to a directory (lib64 -> lib)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("venv/"),
        tarDirectoryLine("venv/lib/"),
        tarFileLine("venv/lib/site.py"),
        tarSymlinkLine("venv/lib64", "lib"),
        tarDirectoryLine("venv/bin/"),
        tarSymlinkLine("venv/bin/site.py", "../lib64/site.py"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a symlink cycle with the resolution-limit reason", async () => {
      const run = await applyTarListing([tarSymlinkLine("a", "b"), tarSymlinkLine("b", "a")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a" -> "b" exceeds the symlink resolution limit')
      )
    })

    it("rejects a chain of more than 40 symlink hops", async () => {
      // 42 links l0 -> l1 -> … -> l41 -> end: resolving l0 needs more than the
      // 40 hops Linux allows (MAXSYMLINKS), whichever end of the chain counts.
      const run = await applyTarListing(symlinkChainLines(42))

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "l0" -> "l1" exceeds the symlink resolution limit')
      )
    })

    it("accepts a chain of 40 symlink hops that ends inside the destination", async () => {
      const run = await applyTarListing(symlinkChainLines(40))

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    // Issue #219: listed tail first, every link finds its successor already
    // memoized, so the limit is reached by summing hop counts rather than by
    // the recursion-depth cut-off. The first member over the limit in listing
    // order is the one with 41 hops: l0 in a 41-link chain, l1 in a 42-link one.
    it.each([
      { failing: "l0", links: 41, target: "l1" },
      { failing: "l1", links: 42, target: "l2" },
    ])(
      "rejects a reversed chain of $links symlinks by summing memoized hops",
      async ({ failing, links, target }) => {
        const run = await applyTarListing(symlinkChainLines(links).toReversed())

        expect(extractionSummary(run)).toStrictEqual(
          refusedBeforeExtraction(
            `member ${JSON.stringify(failing)} -> ${JSON.stringify(target)} exceeds the symlink resolution limit`
          )
        )
      }
    )

    it("accepts a reversed chain of 40 symlink hops", async () => {
      const run = await applyTarListing(symlinkChainLines(40).toReversed())

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    // Issue #219: `tar -tv` does not escape ` -> ` or ` link to ` inside names
    // or targets, so a link line that carries a separator more than once has
    // no recoverable name/target split and fails the listing before `tar -x`.
    it.each([
      {
        detail: 'link separator " -> " occurs more than once',
        line: tarSymlinkLine("d/a -> b", "../../../x"),
        name: "a symlink named d/a -> b whose real target escapes",
      },
      {
        detail: 'link separator " -> " occurs more than once',
        line: tarSymlinkLine("a -> b", "/etc"),
        name: "a symlink line a -> b -> /etc",
      },
      {
        detail: 'hardlink contains both " -> " and " link to "',
        line: tarHardlinkLine("a -> b", "d/e/c"),
        name: "a hardlink named a -> b to d/e/c",
      },
      {
        detail: 'link separator " link to " occurs more than once',
        line: tarHardlinkLine("a link to b", "c"),
        name: "a hardlink line a link to b link to c",
      },
    ])("refuses an ambiguous listing line: $name", async ({ detail, line }) => {
      const run = await applyTarListing([
        tarDirectoryLine("d/"),
        tarDirectoryLine("d/e/"),
        tarSymlinkLine("d/e/c", "../../x"),
        tarFileLine("x"),
        line,
      ])

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] ambiguous tar listing line (${detail}): ${JSON.stringify(line)}`
        ),
        markerWritten: false,
        status: "failed",
        tarExtractCalls: [],
      })
    })

    it("still extracts a regular file whose name contains -> (f -> g)", async () => {
      // Only link members are split at the separator; a plain file keeps it.
      const run = await applyTarListing([tarFileLine("f -> g")])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      expect(stagingMergeGuardPaths(run.mockSsh)).toContain(`${destination}/f -> g`)
    })

    it("rejects a member below an archive symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarSymlinkLine("x/link", "y"),
        tarDirectoryLine("x/y/"),
        tarFileLine("x/link/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "x/link/f" is below archive symlink "x/link"')
      )
    })

    it("rejects a hardlink whose target passes through an archive symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarSymlinkLine("x/link", "y"),
        tarDirectoryLine("x/y/"),
        tarFileLine("x/y/f"),
        tarHardlinkLine("h", "x/link/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "x/link"')
      )
    })

    it("rejects a hardlink to an archive symlink member", async () => {
      // `link(2)` does not follow symlinks: `h` would become a second name for
      // the symlink and read `../../x` from the archive root instead of `a/b`.
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/b/"),
        tarSymlinkLine("a/b/s", "../../x"),
        tarFileLine("x"),
        tarHardlinkLine("h", "a/b/s"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "a/b/s"')
      )
    })

    // Issue #219: a case-folding or normalizing filesystem stores `x/L` and
    // `x/l` as one entry, so `x/l/f` would be written through the symlink.
    it("rejects a member below a case variant of an archive symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarSymlinkLine("x/L", "y"),
        tarDirectoryLine("x/y/"),
        tarFileLine("x/l/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "x/l/f" is below archive symlink "x/L"')
      )
    })

    it("rejects a hardlink to a case variant of an archive symlink member", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/b/"),
        tarSymlinkLine("a/b/S", "../../x"),
        tarFileLine("x"),
        tarHardlinkLine("h", "a/b/s"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "a/b/S"')
      )
    })

    // Issue #219: bsdtar lists a hardlink whose header mode field carries
    // S_IFREG bits with `-`, yet prints ` link to TARGET`, and `tar -x` makes
    // `h` a second name for the symlink `a/b/s -> ../../x`, which then reads
    // `../../x` from the archive root. BusyBox tar lists every hardlink as a
    // regular file `name -> target`. Both must meet the hardlink rules.
    it.each([
      {
        lines: [
          bsdTarLine("drwxr-xr-x", "a/"),
          bsdTarLine("drwxr-xr-x", "a/b/"),
          bsdTarLine("lrwxrwxrwx", "a/b/s -> ../../x"),
          bsdTarLine("-rw-r--r--", "x"),
          bsdTarLine("-rw-r--r--", "h link to a/b/s"),
        ],
        listingModeLine: bsdTarListingModeLine,
        name: "a bsdtar hardlink listed with a regular-file mode",
      },
      {
        lines: [
          tarDirectoryLine("a/"),
          tarDirectoryLine("a/b/"),
          tarSymlinkLine("a/b/s", "../../x"),
          tarFileLine("x"),
          `-rw-r--r-- ${tarListingLineFields} h -> a/b/s`,
        ],
        listingModeLine: otherTarListingModeLine,
        name: "a BusyBox hardlink listed as a regular file h -> a/b/s",
      },
    ])("rejects $name to an archive symlink member", async ({ lines, listingModeLine }) => {
      const run = await applyTarListing(lines, { listingModeLine })

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "a/b/s"')
      )
    })

    it("extracts a bsdtar hardlink listed with a regular-file mode to a regular file", async () => {
      const run = await applyTarListing(
        [
          bsdTarLine("drwxr-xr-x", "a/"),
          bsdTarLine("drwxr-xr-x", "b/"),
          bsdTarLine("-rw-r--r--", "b/f"),
          bsdTarLine("-rw-r--r--", "a/h link to b/f"),
        ],
        { listingModeLine: bsdTarListingModeLine }
      )

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("reads a bsdtar regular file named `notes link to ../x` as an escaping hardlink", async () => {
      // Issue #219: bsdtar lists this regular file exactly like the hardlink
      // `notes` to `../x` with S_IFREG mode bits, so it is judged as that
      // hardlink, whose archive-root-relative target leaves the destination.
      const run = await applyTarListing([bsdTarLine("-rw-r--r--", "notes link to ../x")], {
        listingModeLine: bsdTarListingModeLine,
      })

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "notes" -> "../x" would escape destination')
      )
    })

    it("rejects a path that occurs as both a directory and a symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarDirectoryLine("y/"),
        tarSymlinkLine("./x", "y"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          'member "x/" occurs more than once with conflicting link types or targets'
        )
      )
    })

    it("rejects duplicate symlink entries with different targets", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarFileLine("a/t"),
        tarFileLine("a/u"),
        tarSymlinkLine("a/l", "t"),
        tarSymlinkLine("./a/l", "u"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          'member "a/l" occurs more than once with conflicting link types or targets'
        )
      )
    })

    it("accepts identical duplicate symlink entries", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarFileLine("a/t"),
        tarSymlinkLine("a/l", "t"),
        tarSymlinkLine("./a/l", "t"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("probes the non-member prefixes of a link target and refuses a host symlink there", async () => {
      const hostSymlink = `${destination}/a/lib`
      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarDirectoryLine("a/bin/"), tarSymlinkLine("a/bin/x", "../lib/y")],
        { hostSymlinks: [hostSymlink] }
      )

      const probed = preStagingProbeEntries(run)
      expect(probed).toContain(hostSymlink)
      expect(probed).toContain(`${destination}/a/lib/y`)
      expect(extractionSummary(run)).toStrictEqual(
        refusedAfterContainmentFlag(
          `link target of member "a/bin/x" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
      // Issue #219: the pre-staging probe runs after the flag was written.
      expectContainmentFlagKept(run)
    })

    it("refuses a link that walks through a symlink an earlier archive left on the host", async () => {
      // An earlier archive shipped `a/up -> ..`; on its own this archive is
      // harmless, but on this host `a/esc -> up/..` resolves above `/opt/app`.
      const hostSymlink = `${destination}/a/up`
      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
        { hostSymlinks: [hostSymlink] }
      )

      expect(preStagingProbeEntries(run)).toContain(hostSymlink)
      expect(extractionSummary(run)).toStrictEqual(
        refusedAfterContainmentFlag(
          `link target of member "a/esc" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
      expectContainmentFlagKept(run)
    })

    it("refuses a later run whose link makes an earlier run's link escape (a/esc -> up/.., then a/up -> ..)", async () => {
      // Issue #219: the reverse order of the case above. Run 1 ships
      // `a/esc -> up/..`, which resolves to `a` while `a/up` does not exist.
      // Run 2 ships `a/up -> ..`, which on its own resolves to the destination
      // root. Neither archive is unsafe, and the pre-staging probe of run 2
      // never looks at `a/esc`. The pre-merge listing of the host's links does:
      // resolved together with run 2's links, `a/esc` goes via `a/up/..` to the
      // parent of `/opt/app`, so run 2 is refused before anything is copied.
      const hostLinks: HostLinkTree = new Map()
      const owner = "www-data:www-data"
      const escapingLink = `${destination}/a/esc`

      const first = await applyTarListing(
        [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
        { hostLinks, owner }
      )

      expect(extractionSummary(first)).toStrictEqual(extractedThroughStaging)
      const firstCalls = first.mockSsh.calls
      // Issue #219: one post-merge listing on a converged tree.
      expect(first.postMergeListings).toHaveLength(1)
      const [firstContainment] = first.postMergeListings
      const firstCleanup = firstCalls.findIndex((command) =>
        archiveStageCleanupPattern.test(command)
      )
      expect(firstCalls.findIndex((command) => archiveStageMovePattern.test(command))).toBeLessThan(
        firstCleanup
      )
      expect(firstContainment).toBeGreaterThan(firstCleanup)
      expect(firstCalls.indexOf(batchedChownCommand)).toBeGreaterThan(firstContainment)
      expect(first.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
        expect.arrayContaining([marker, membersMarker])
      )
      // Issue #219: the containment entry is created by the establish exec
      // before the merge; every marker write comes after the containment
      // backstop.
      expect(firstCalls.indexOf(containmentEstablishCommand(1))).toBeLessThan(firstContainment)
      for (const write of first.writes) {
        expect(write.callIndex).toBeGreaterThan(firstContainment)
      }

      const second = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
        hostLinks,
        owner,
      })

      expect(extractionSummary(second)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to extract ${src}: symlink ${JSON.stringify(escapingLink)} -> "up/.." would resolve outside destination ${JSON.stringify(destination)} once this archive is merged`
        ),
        // The only write is the failure record in the own containment entry,
        // not a marker.
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(preStagingProbeEntries(second)).not.toContain(escapingLink)
      const secondCalls = second.mockSsh.calls
      expect(secondCalls).toContain(symlinkListingProbeCommand)
      expect(secondCalls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
      expect(secondCalls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
      expect(second.postMergeListings).toStrictEqual([])
      expect(secondCalls).not.toContain(batchedChownCommand)
      expect(second.writes.map(({ remotePath }) => remotePath)).toStrictEqual([ownEntry(2)])
      // Issue #219: the containment entry is established before the pre-merge
      // listing; the failure is recorded after it.
      const establish = secondCalls.indexOf(containmentEstablishCommand(2))
      const secondListing = secondCalls.indexOf(symlinkListingProbeCommand)
      expect(establish).toBeGreaterThanOrEqual(0)
      expect(establish).toBeLessThan(secondListing)
      expect(second.writes[0]?.callIndex).toBeGreaterThan(secondListing)
      // Nothing of run 2 reached the destination.
      expect([...hostLinks]).toStrictEqual([[escapingLink, "up/.."]])
    })

    it("refuses the reverse order before the merge as well (a/up -> .., then a/esc -> up/..)", async () => {
      // Issue #219: run 1 ships `a/up -> ..`, contained on its own. Run 2 ships
      // `a/esc -> up/..`, whose target passes the non-member prefix `a/up`. The
      // pre-staging probe already reports that host symlink, so run 2 stops
      // before the listing probe and the merge. The host tree is untouched, but
      // the containment flag was written before the destination was probed, so
      // `check` of run 1's source reports needs-apply instead of trusting its
      // old marker, until an apply succeeds.
      const hostLinks: HostLinkTree = new Map()
      const files = new Map<string, string>()
      const owner = "www-data:www-data"
      const upLink = `${destination}/a/up`

      const first = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
        files,
        hostLinks,
        owner,
      })
      expect(extractionSummary(first)).toStrictEqual(extractedThroughStaging)

      const second = await applyTarListing(
        [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
        { files, hostLinks, owner, source: otherSrc }
      )

      expect(extractionSummary(second)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to extract ${otherSrc}: link target of member "a/esc" passes through existing host symlink ${JSON.stringify(upLink)}`
        ),
        // The only write is the containment-failure flag, not a marker.
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(preStagingProbeEntries(second)).toContain(upLink)
      const secondCalls = second.mockSsh.calls
      expect(secondCalls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
      expect(secondCalls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
      expect(second.postMergeListings).toStrictEqual([])
      expect(secondCalls).not.toContain(batchedChownCommand)
      expect([...hostLinks]).toStrictEqual([[upLink, ".."]])
      expect(hasContainmentState(files)).toBe(true)
      expectContainmentFlagKept(second)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
        result: "needs-apply",
      })
    })

    // Issue #219: the same two-run combination, but spelled with a case
    // variant. The host model is case-sensitive like ext4, so the pre-staging
    // probe of `d/UP` finds nothing; only the name-variant rule of the
    // pre-merge check sees that a case-folding host would follow `d/up`.
    it.each([
      {
        first: tarSymlinkLine("d/up", ".."),
        hostLink: [`${destination}/d/up`, ".."] as const,
        name: "d/up -> .., then d/esc -> UP/..",
        second: tarSymlinkLine("d/esc", "UP/.."),
      },
      {
        first: tarSymlinkLine("d/esc", "UP/.."),
        hostLink: [`${destination}/d/esc`, "UP/.."] as const,
        name: "d/esc -> UP/.., then d/up -> ..",
        second: tarSymlinkLine("d/up", ".."),
      },
    ])(
      "refuses a later run that completes a case-variant escape before the merge ($name)",
      async ({ first, hostLink, second }) => {
        const hostLinks: HostLinkTree = new Map()
        const files = new Map<string, string>()

        const firstRun = await applyTarListing([tarDirectoryLine("d/"), first], {
          files,
          hostLinks,
        })
        expect(extractionSummary(firstRun)).toStrictEqual(extractedThroughStaging)

        const secondRun = await applyTarListing([tarDirectoryLine("d/"), second], {
          files,
          hostLinks,
          source: otherSrc,
        })

        expect(extractionSummary(secondRun)).toStrictEqual({
          error: expect.stringContaining(
            `[archive.extract] refusing to extract ${otherSrc}: symlink "/opt/app/d/esc" -> "UP/.." passes through "d/UP", a name that differs from existing symlink "d/up" only by letter case or Unicode normalization`
          ),
          markerWritten: true,
          status: "failed",
          tarExtractCalls: [],
        })
        const secondCalls = secondRun.mockSsh.calls
        expect(secondCalls).toContain(symlinkListingProbeCommand)
        expect(secondCalls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
        expect(secondRun.postMergeListings).toStrictEqual([])
        expect([...hostLinks]).toStrictEqual([hostLink])
        expectContainmentFlagKept(secondRun)
      }
    )

    it("accepts an archive symlink that replaces a host link and makes the combination safe", async () => {
      // Issue #219: on their own the host links `a/up -> ..` and
      // `a/esc -> up/..` escape. This archive ships `a/up -> b`, which the merge
      // puts in place of the host link (`--remove-destination`), so after the
      // merge `a/esc` resolves via `a/b/..` to `a`. The pre-merge check models
      // that replacement and does not refuse.
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/a/esc`, "up/.."],
        [`${destination}/a/up`, ".."],
      ])

      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarDirectoryLine("a/b/"), tarSymlinkLine("a/up", "b")],
        { hostLinks }
      )

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      expect(run.mockSsh.calls).toContain(symlinkListingProbeCommand)
      // Issue #219: the containment entry is established before the merge and
      // cleared once the apply has fully succeeded.
      expect(run.mockSsh.calls).toContain(containmentEstablishCommand())
      expect(containmentClears(run.mockSsh.calls)).toHaveLength(1)
      expect(Object.fromEntries(hostLinks)).toStrictEqual({
        [`${destination}/a/esc`]: "up/..",
        [`${destination}/a/up`]: "b",
      })
    })

    it("refuses a regular file member at the path of a host link before any merge", async () => {
      // Issue #219: a non-symlink member would remove the host link `a/up`
      // (`mergedArchiveSymlinks`), but the member path itself is a guard path,
      // so the pre-staging probe refuses the existing host symlink first. No
      // listing probe and no staging; only the containment flag, written
      // before the probe, reached the host and stays set.
      const upLink = `${destination}/a/up`
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/a/esc`, "up/.."],
        [upLink, ".."],
      ])

      const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/up")], {
        hostLinks,
      })

      expect(extractionSummary(run)).toStrictEqual(
        refusedAfterContainmentFlag(`destination path ${JSON.stringify(upLink)} is a symlink`)
      )
      expect(preStagingProbeEntries(run)).toContain(upLink)
      expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
      expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(
        false
      )
      expectContainmentFlagKept(run)
    })

    it.each([
      { link: "abs-inside", target: `${destination}/b` },
      { link: "abs-root", target: destination },
      { link: "abs-root-slash", target: `${destination}/` },
      { link: "a/abs-sibling-dir", target: `${destination}/a/../c` },
    ])(
      "accepts a host link whose absolute target $target stays inside the destination",
      async ({ link, target }) => {
        const hostLinks: HostLinkTree = new Map([[`${destination}/${link}`, target]])

        const run = await applyTarListing([tarFileLine("f")], { hostLinks })

        expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      }
    )

    // Issue #219: an archive without symlink members cannot change where any
    // host link resolves, so no listing runs and an unrelated host link that
    // points outside never blocks the apply.
    it.each([
      { link: "etc", target: "/etc" },
      { link: "a/up", target: `${destination}/..` },
      { link: "a/deep-up", target: `${destination}/a/../..` },
      { link: "sibling", target: `${alternateDestination}/x` },
      { link: "_work/proj/.venv/bin/python3", target: "/usr/bin/python3" },
    ])(
      "accepts an archive without symlinks next to a host link whose absolute target $target leaves the destination, without any listing",
      async ({ link, target }) => {
        const hostLinks: HostLinkTree = new Map([[`${destination}/${link}`, target]])

        const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/f")], {
          hostLinks,
        })

        expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
        expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
        expect(run.mockSsh.calls).not.toContain(kernelCrossCheckCommand)
        expect(containmentClears(run.mockSsh.calls)).toHaveLength(1)
      }
    )

    // Issue #219: with a symlink member, the listing runs, but only a host
    // link whose walk passes through a path the archive writes is judged.
    // `/opt/app/a/../..` restarts at the destination root and walks through
    // `a`, which the archive writes; the others escape without touching it.
    const linkArchive = [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")]

    it.each([
      { link: "etc", target: "/etc" },
      { link: "a/up", target: `${destination}/..` },
      { link: "sibling", target: `${alternateDestination}/x` },
    ])(
      "ignores a host link whose absolute target $target leaves the destination without passing through an archive path",
      async ({ link, target }) => {
        const hostLinks: HostLinkTree = new Map([[`${destination}/${link}`, target]])

        const run = await applyTarListing(linkArchive, { hostLinks })

        expect(run.mockSsh.calls).toContain(symlinkListingProbeCommand)
        expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      }
    )

    it("refuses a host link whose absolute target walks through an archive path and leaves the destination", async () => {
      const linkPath = `${destination}/a/deep-up`
      const target = `${destination}/a/../..`
      const hostLinks: HostLinkTree = new Map([[linkPath, target]])

      const run = await applyTarListing(linkArchive, { hostLinks })

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to extract ${src}: symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(target)} would resolve outside destination ${JSON.stringify(destination)} once this archive is merged`
        ),
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
    })

    it("accepts an archive with symlinks next to an unrelated virtual environment link, before and after the merge", async () => {
      // Issue #219: the finding this fixes: a runner's `.venv/bin/python3 ->
      // /usr/bin/python3` refused every apply into the runner directory.
      const venvLink = `${destination}/_work/proj/.venv/bin/python3`
      const files = new Map<string, string>()
      const hostLinks: HostLinkTree = new Map([[venvLink, "/usr/bin/python3"]])

      const run = await applyTarListing(
        [
          tarDirectoryLine("bin/"),
          tarFileLine("lib/node_modules/npm/bin/npm-cli.js"),
          tarSymlinkLine("bin/node", "../lib/node_modules/npm/bin/npm-cli.js"),
        ],
        { files, hostLinks }
      )

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      // Both listings ran; the kernel cross-check carried only the archive link.
      expect(run.postMergeListings).toHaveLength(1)
      const crossChecks = run.mockSsh.execCalls.filter(
        ({ command }) => command === kernelCrossCheckCommand
      )
      expect(crossChecks.map(({ options }) => crossCheckedLinks(options?.input))).toStrictEqual([
        [`${destination}/bin/node`],
      ])
      expect(hasContainmentState(files)).toBe(false)
      expect(hostLinks.get(venvLink)).toBe("/usr/bin/python3")
    })

    it("refuses a host link cycle through an archive path before the merge with the resolution-limit reason", async () => {
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/loop-a`, "a/../loop-b"],
        [`${destination}/loop-b`, "a/../loop-a"],
      ])

      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")],
        { hostLinks }
      )

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to extract ${src}: symlink "/opt/app/loop-a" -> "a/../loop-b" would exceed the symlink resolution limit once this archive is merged; the archive's symlinks and the existing symlinks whose resolution passes through a path it writes are checked together before anything is copied (and 1 more)`
        ),
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
        containmentFlagWritesOfFailedApply
      )
    })

    it("accepts an archive with symlinks next to an unrelated host link cycle", async () => {
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/x/loop-a`, "loop-b"],
        [`${destination}/x/loop-b`, "loop-a"],
      ])

      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")],
        { hostLinks }
      )

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it.each([
      {
        detail: "find: '/opt/app/private': Permission denied",
        name: "a non-zero exit",
        response: { code: 1, stderr: "find: '/opt/app/private': Permission denied" },
      },
      {
        detail: `the destination holds too many symlinks to check: the symlink listing exceeded its captured-output cap of ${String(SYMLINK_LISTING_CAPTURE_LIMIT_BYTES)} bytes`,
        name: "a truncated capture",
        response: {
          code: 0,
          stdout: `l\u0000a/up\u0000..\u0000l\u0000a/e${CAPTURE_TRUNCATION_MARKER}`,
        },
      },
      {
        detail: 'probe output ends inside a "l" record',
        name: "a record cut off at the end",
        response: { code: 0, stdout: "l\u0000a/up\u0000..\u0000l\u0000b\u0000" },
      },
      {
        detail: 'probe reported unknown record kind "/opt/app/a/up"',
        name: "the former pair format",
        response: { code: 0, stdout: `${destination}/a/up\u0000..\u0000` },
      },
      {
        detail:
          'probe reported symlink "/opt/other/l", which is not a normalized path below the destination',
        name: "an absolute link path",
        response: { code: 0, stdout: "l\u0000/opt/other/l\u0000x\u0000" },
      },
      {
        detail:
          'probe reported symlink "../app-alt/l", which is not a normalized path below the destination',
        name: "a link in a sibling sharing the destination's prefix",
        response: { code: 0, stdout: "l\u0000../app-alt/l\u0000x\u0000" },
      },
      {
        detail: 'probe reported symlink "", which is not a normalized path below the destination',
        name: "the destination itself",
        response: { code: 0, stdout: "l\u0000\u0000x\u0000" },
      },
      {
        detail:
          'probe reported field "\u00e9" with characters outside printable ASCII that were not hex-encoded',
        name: "a non-ASCII field that is not hex-encoded",
        response: { code: 0, stdout: "l\u0000\u00e9\u0000x\u0000" },
      },
    ])(
      "fails closed before the merge on a listing probe with $name",
      async ({ detail, response }) => {
        const run = await applyTarListing([tarFileLine("f"), tarSymlinkLine("l", "f")], {
          responses: { [symlinkListingProbeCommand]: response },
        })

        expect(extractionSummary(run)).toStrictEqual({
          error: `Error: [archive.extract] refusing to extract ${src}: symlink listing before the merge failed: ${detail}`,
          markerWritten: true,
          status: "failed",
          tarExtractCalls: [],
        })
        expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
          containmentFlagWritesOfFailedApply
        )
        expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(
          false
        )
        expect(run.mockSsh.execCalls).toContainEqual({
          command: symlinkListingProbeCommand,
          options: {
            ignoreExitCode: true,
            // Issue #219: the destination as `r` entry, the non-directory
            // members as `n` entries.
            input: `r:${destination}\u0000n:${destination}/f\u0000n:${destination}/l\u0000`,
            maxOutputBytes: SYMLINK_LISTING_CAPTURE_LIMIT_BYTES,
            silent: true,
            strictUtf8Stdout: true,
          },
        })
      }
    )

    it("still refuses via the post-merge backstop when a host link appears after the listing", async () => {
      // Issue #219: the pre-merge listing sees no link, so `a/up -> ..` passes.
      // While the merge runs, the host gains `a/esc -> up/..`; only the
      // whole-tree check after the merge can see that combination.
      const hostLinks: HostLinkTree = new Map()
      const files = new Map<string, string>()
      const escapingLink = `${destination}/a/esc`

      const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
        files,
        hostLinks,
        injectedOnMerge: [[escapingLink, "up/.."]],
        owner: "www-data:www-data",
      })

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to complete extraction of ${src}: symlink ${JSON.stringify(escapingLink)} -> "up/.." resolves outside destination ${JSON.stringify(destination)}; after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship; nothing was removed or changed; while the offending symlinks remain, remove them or point them inside the destination manually; this apply's containment entry records them and keeps check at needs-apply, and a later apply of any source verifies them again (every symlink under the destination when the entry could not record them) and, only when they pass, removes the entries it read that are still unchanged`
        ),
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [stagedTarExtractCommand],
      })
      const { calls } = run.mockSsh
      const listing = calls.indexOf(symlinkListingProbeCommand)
      const merge = calls.findIndex((command) => archiveStageMovePattern.test(command))
      // Issue #219: the backstop lists once and only reports.
      expect(run.postMergeListings).toHaveLength(1)
      const [backstopListing] = run.postMergeListings
      expect(listing).toBeGreaterThanOrEqual(0)
      expect(listing).toBeLessThan(backstopListing)
      expect(merge).toBeGreaterThan(listing)
      expect(backstopListing).toBeGreaterThan(merge)
      expect(calls).not.toContain(batchedChownCommand)
      expect(containmentClears(calls)).toStrictEqual([])
      expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
        containmentFlagWritesOfFailedApply
      )
      // Issue #219: the containment entry is established before the pre-merge
      // listing, and the backstop leaves the escaping link it found in place:
      // after its listing only the kernel cross-check of `a/up` runs.
      expect(calls.indexOf(containmentEstablishCommand())).toBeLessThan(listing)
      expect([...files.keys()]).toStrictEqual([ownEntry()])
      expect(files.get(ownEntry())).toBe(recordedFlag("a/esc"))
      expect(callsFromBackstop(run)).toStrictEqual([
        symlinkListingProbeCommand,
        kernelCrossCheckCommand,
      ])
      expect([...hostLinks.keys()].toSorted()).toStrictEqual(
        [`${destination}/a/up`, escapingLink].toSorted()
      )
    })

    it("keeps archive symlink leaves out of the pre-staging probe and the merge guard paths", async () => {
      // Downward links only, so the listing already validates today: this case
      // isolates the guard set, which used to include the link paths themselves
      // and failed on every run where the archive's own links already existed.
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/bin/"),
        tarSymlinkLine("a/bin/x", "y"),
        tarFileLine("a/bin/y"),
        tarSymlinkLine("current", "a/bin"),
        tarFileLine("README"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      const symlinkLeaves = [`${destination}/a/bin/x`, `${destination}/current`]
      const expectedGuards = [
        `${destination}/a`,
        `${destination}/a/bin`,
        `${destination}/a/bin/y`,
        `${destination}/README`,
      ]
      const probed = preStagingProbeEntries(run)
      const guardPaths = stagingMergeGuardPaths(run.mockSsh)
      expect(probed).toStrictEqual(expect.arrayContaining(expectedGuards))
      expect(guardPaths).toStrictEqual(expect.arrayContaining(expectedGuards))
      for (const leaf of symlinkLeaves) {
        expect(probed).not.toContain(leaf)
        expect(guardPaths).not.toContain(leaf)
        // The pre-merge recheck reuses the same guard set.
        expect(run.probes.flatMap((probe) => probe.entries)).not.toContain(leaf)
      }
    })

    it("validates a ~10,000-member listing with many chained and sibling symlinks", async () => {
      // Resolution is memoized per symlink, so the archive-level walk stays
      // linear; the default test timeout is the bound, not a wall-clock check.
      const lines = Array.from({ length: 1000 }, (_value, index) => {
        const directory = `d${String(index)}`
        // Each `up` points into the previous directory's chain (d0 into d999).
        const previous = `../../d${String((index + 999) % 1000)}/bin/c0`
        return [
          tarDirectoryLine(`${directory}/`),
          tarDirectoryLine(`${directory}/bin/`),
          tarDirectoryLine(`${directory}/lib/`),
          tarFileLine(`${directory}/lib/f`),
          tarSymlinkLine(`${directory}/lib64`, "lib"),
          tarSymlinkLine(`${directory}/bin/s`, "../lib/f"),
          tarSymlinkLine(`${directory}/bin/c1`, "s"),
          tarSymlinkLine(`${directory}/bin/c0`, "c1"),
          tarSymlinkLine(`${directory}/bin/up`, previous),
          tarSymlinkLine(`${directory}/bin/via64`, "../lib64/f"),
        ]
      }).flat()
      expect(lines).toHaveLength(10_000)

      const run = await applyTarListing(lines)

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })
  })

  it("rejects a tar archive that contains a block device member", async () => {
    const tarListing = `brw-r--r-- root/root 8,0 1970-01-01 00:00 app/device\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a special file")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive with an unparsed listing line before invoking tar -x", async () => {
    const tarListing = `${safeTarListing}\nnot-a-member\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("could not parse tar listing line")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000636: control characters in archive member paths must be rejected
  // before they reach moveExtractedContentsIntoDestination, where a literal
  // newline could split the guard-paths list and bypass the per-ancestor
  // symlink protection. A NUL byte would silently terminate a path argument
  // when interpolated into a shell command. The tests use JavaScript escape
  // sequences (\x00, \x01) instead of literal control bytes so the source
  // stays grep-friendly and the intent of each test is explicit.
  it("rejects a tar archive whose member name contains a NUL byte", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 app\x00file\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member name contains a SOH control byte", async () => {
    // We use \x01 (start of heading) as a representative low-control byte
    // that survives parseTarVerboseLine (carriage returns are already
    // rejected as unparseable because `.` in the listing regex excludes
    // line terminators). The control-character guard must catch \x01,
    // \x02, \t, … before they reach downstream guards or shell helpers.
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 app\x01file\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target contains a NUL byte", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> target\x00evil\n`
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("link target contains control characters")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // Issue #219: GNU tar prints a backslash as `\\` and non-printable bytes as
  // `\NNN`, other tar implementations print names raw, so a listed name with a
  // backslash or a U+FFFD cannot be mapped reliably to the extracted name.
  // Listings of GNU tar and bsdtar are decoded first; a decoded real
  // backslash is refused all the same, so the verdict does not depend on the
  // tar on the host.
  it.each([
    {
      line: tarFileLine("app/a\\\\b"),
      modeLine: gnuTarListingModeLine,
      name: "GNU tar: an escaped backslash in the path",
    },
    {
      line: tarFileLine("app/\ufffd"),
      modeLine: gnuTarListingModeLine,
      name: "GNU tar: a U+FFFD in the path",
    },
    {
      line: tarFileLine("app/\\357\\277\\275"),
      modeLine: "paratix-tar-listing gnu C\n",
      name: "GNU tar in C: an escaped U+FFFD in the path",
    },
    {
      line: tarSymlinkLine("app/l", "x\\\\y"),
      modeLine: gnuTarListingModeLine,
      name: "GNU tar: an escaped backslash in the link target",
    },
    {
      line: tarSymlinkLine("app/l", "\ufffd"),
      modeLine: gnuTarListingModeLine,
      name: "GNU tar: a U+FFFD in the link target",
    },
    {
      line: tarFileLine("app/a\\b"),
      modeLine: otherTarListingModeLine,
      name: "another tar: a raw backslash in the path",
    },
    {
      line: tarFileLine("app/\\303\\251"),
      modeLine: otherTarListingModeLine,
      name: "another tar: an octal escape in the path",
    },
    {
      line: tarFileLine("app/\ufffd"),
      modeLine: otherTarListingModeLine,
      name: "another tar: a U+FFFD in the path",
    },
    {
      line: tarSymlinkLine("app/l", "x\\y"),
      modeLine: otherTarListingModeLine,
      name: "another tar: a raw backslash in the link target",
    },
    {
      line: tarSymlinkLine("app/l", "\ufffd"),
      modeLine: otherTarListingModeLine,
      name: "another tar: a U+FFFD in the link target",
    },
  ])(
    "rejects a tar archive with $name before anything reaches the host",
    async ({ line, modeLine }) => {
      const mockSsh = createMockSsh({
        [tarListCommand(src)]: { code: 0, stdout: `${modeLine}${line}\n` },
      })

      const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("a backslash or a U+FFFD replacement character")
      expect(String(result.error)).toContain(
        "member names with a backslash are refused in every listing"
      )
      expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeUndefined()
      expectNoTarExtractCalls(mockSsh)
      expect(mockSsh.writeFileCalls).toStrictEqual([])
    }
  )

  it("refuses an archive whose listing is not valid UTF-8 (Issue #219)", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "exec").mockRejectedValue(
      new InvalidUtf8OutputError(
        `Command stdout is not valid UTF-8 (exit code 0): tar -tvzf '${src}'`
      )
    )

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(result).toStrictEqual({
      failureReason: `archive listing for ${src} is not valid UTF-8; refusing to validate member names that cannot be mapped to the extracted names reliably (a member name whose bytes are not valid UTF-8 cannot be mapped)`,
    })
  })

  it("lets any other exec rejection of the listing propagate (Issue #219)", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "exec").mockRejectedValue(new Error("channel closed"))

    await expect(listArchiveMembers(mockSsh, { archivePath: src, source: src })).rejects.toThrow(
      "channel closed"
    )
  })

  // R-0000703: tar members carrying setuid or setgid bits must be rejected
  // before `cp -aT --no-dereference` propagates the elevated permission bits
  // onto the destination filesystem. The archive validator looks at the
  // ten-character symbolic mode string and refuses members with `s`/`S` in
  // either the user- or group-execute slot. Operators who need a setuid
  // binary should chmod it in a follow-up module so the change is visible
  // in the playbook.
  it("rejects a tar archive whose member has the setuid bit set", async () => {
    const tarListing = "-rwsr-xr-x root/root 0 1970-01-01 00:00 app/suid-bin\n"
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member has the setgid bit set", async () => {
    const tarListing = "-rwxr-sr-x root/root 0 1970-01-01 00:00 app/sgid-bin\n"
    const mockSsh = createMockSsh({
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(tarListing) },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(tarListCommand(src))
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000703: same guard for zip archives — unzip is just as willing to
  // restore setuid/setgid bits when the Unix attributes are present.
  it("rejects a zip archive whose member has the setuid bit set", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rwsr-xr-x  2.0 unx        0 b- defN 26-May-04 00:00 app/suid-bin\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a `/etc/passwd` member without invoking unzip -o", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 /etc/passwd\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a `..` traversal member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 ../escape\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a symlink member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "lrwxrwxrwx  2.0 unx       11 b- stor 26-May-04 00:00 app/link\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000636: zip members with control characters in their names must be
  // rejected before unzip restores them, mirroring the tar guard. NUL bytes
  // would silently truncate downstream shell arguments; carriage returns and
  // other low control bytes would let crafted archives smuggle entries past
  // the per-member guard list used by moveExtractedContentsIntoDestination.
  it("rejects a zip archive whose member name contains a NUL byte", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app\x00file\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive whose member name contains a SOH control byte", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app\x01file\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a fifo member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "prw-r--r--  2.0 unx        0 b- stor 26-May-04 00:00 app/fifo\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a special file")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive with an unparsed listing line before invoking unzip -o", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file\nnot-a-member\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("could not parse zip listing line")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("has correct module name", () => {
    const mod = archive.extract(src, destination)
    expect(mod.name).toBe(`archive.extract: ${destination}`)
  })

  // R-0000162: extraction must happen into a paratix-controlled staging
  // sub-directory under the destination (`mktemp -d`), and the contents are
  // then atomically moved into the destination. This prevents a TOCTOU race
  // between `validateNoSymlinkPaths` and the `tar -xzf` / `unzip -o`
  // execution from being exploitable, because tar/unzip never writes
  // directly into a path the attacker could replace with a symlink.
  it("R-0000162: extracts into a paratix mktemp staging dir under the destination, then moves into place", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.some((c) => archiveStageMktempPattern.test(c))).toBe(true)
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(true)
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`
    )
  })

  it("R-0000162: cleans up the staging directory when the move into the destination fails", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: archiveStageMovePattern,
            result: { code: 1, stderr: "cp: cross-device link" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to copy extracted files")
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("fails closed when the in-merge symlink guard rejects a swapped destination path", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: archiveStageMovePattern,
            result: {
              code: 64,
              stderr: `[archive.extract] refusing staging merge: destination path ${destination}/app/file is a symlink`,
            },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to copy extracted files")
    expect(String(result.error)).toContain("refusing staging merge")
    // Issue #219: only the containment flag, written before the merge, is on disk.
    expect(vi.mocked(mockSsh.writeFile).mock.calls.map(([path]) => path)).toStrictEqual(
      containmentFlagWritesOfFailedApply
    )
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("rejects a destination that resolves elsewhere after guarded creation", async () => {
    const mockSsh = createMockSsh(
      {
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: `readlink -f -- '${destination}'`,
            result: { code: 0, stdout: "/tmp/attacker-target\n" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("destination path")
    expect(String(result.error)).toContain("/tmp/attacker-target")
    expectNoTarExtractCalls(mockSsh)
  })

  it("rechecks member destination symlinks immediately before staging merge", async () => {
    // R-0000751: the sweep before extraction and the one immediately before the
    // merge are separate on purpose, so a symlink planted in between is still
    // caught. Batching made both sweeps issue the identical command, so the
    // transported payload is what tells them apart — and the second sweep
    // carrying the member path is the recheck this asserts.
    const memberPath = `${destination}/app/file`
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    const recheck = stubSymlinkRecheck(mockSsh, memberPath)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(memberPath)
    expect(recheck.sweeps()).toBe(2)
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(false)
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  // R-0000221: per-entry `mv -f` cannot merge into a pre-existing destination
  // sub-directory; the first conflict aborts the move and the destination is
  // left in a partial state. Per-entry `cp -aT` recurses into existing entries
  // and merges conflict-free, then the staging directory is removed wholesale.
  it("R-0000221: uses cp -aT to merge into existing destination directories conflict-free", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toBeDefined()
    expect(mergeCommand).toContain("cp -aT --no-dereference --remove-destination")
    expect(mockSsh.calls.some((c) => c.includes("xargs -0 -I {} mv -f"))).toBe(false)
  })

  it("preserves existing destination directory metadata while merging staged contents", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(
      `cp -aT --no-dereference --remove-destination '${archiveStageDirectory}' '${destination}'`
    )
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(true)
  })

  it("hardens the staging merge so existing destination symlinks are replaced", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toContain("cp -aT --no-dereference --remove-destination")
    expect(mergeCommand).toContain('readlink -f -- "$destination"')
    expect(mergeCommand).toContain('[ -L "$guarded_path" ]')
    expect(mergeCommand).toContain('[ -L "$target_path" ]')
    expect(mergeCommand).toContain("--remove-destination")
  })

  // R-0000751 / R-0000847: the staging merge runs exactly one
  // `[ -L "$target_path" ]` probe, placed immediately before `cp -aT` so a
  // symlink planted in the TOCTOU window between any earlier guard and the
  // copy cannot smuggle the merge through. R-0000847 removed a second
  // identical probe that had no functional effect — the surviving probe
  // sits as close to `cp` as the shell allows, which is the only window
  // that matters for the recheck-just-before-write pattern documented in
  // R-0000677.
  it("R-0000847: keeps a single target_path symlink probe immediately before cp -aT", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toBeDefined()
    // The shell text must contain exactly one `[ -L "$target_path" ]` probe
    // after R-0000847 removed the redundant duplicate.
    const targetSymlinkProbes = mergeCommand?.match(/\[ -L "\$target_path" \]/gv)
    expect(targetSymlinkProbes?.length).toBe(1)
    // The single surviving probe must still sit directly before `cp -aT`
    // so the recheck-just-before-write guarantee holds. We require the
    // exact one-line shell sub-segment that runs the probe, prints the
    // rejection message, closes the `if` and then invokes `cp -aT`.
    // Issue #219: the probe only refuses when the staged entry is not itself a
    // symlink, so a top-level archive symlink from an earlier run is replaced
    // by `cp --remove-destination` instead of failing every later run.
    expect(mergeCommand).toContain(
      'if [ -L "$target_path" ] && [ ! -L "$source_path" ]; then echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; exit 64; fi; cp -aT'
    )
  })

  // R-0000166: the owner-paths marker is now written for both upload and
  // non-upload extracts, so the owner re-check stays deterministic even
  // when the source archive is mutated, replaced or removed between apply
  // and the next check.
  it("R-0000166: persists extracted owner paths for non-upload archives with owner", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [batchedChownCommand]: { code: 0 },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFile).toHaveBeenCalledWith(marker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      membersMarker,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      ownerPathsMarker,
      JSON.stringify([`${destination}/app/file`]),
      { mode: "0644" }
    )
  })

  it("serializes UTF-8 bytes consistently in members and owner-paths markers", async () => {
    const unicodePath = "app/grüße-こんにちは.txt"
    const listing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ${unicodePath}`
    const ownerPathsMarker = `${marker}.owner-paths`
    const membersPayload = JSON.stringify([{ kind: "file", path: `${destination}/${unicodePath}` }])
    const ownerPathsPayload = JSON.stringify([`${destination}/${unicodePath}`])
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [batchedChownCommand]: { code: 0 },
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(listing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const result = await archive
      .extract(src, destination, { owner: "www-data:www-data" })
      .apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(Buffer.byteLength(membersPayload, "utf8")).toBeGreaterThan(membersPayload.length)
    expect(Buffer.byteLength(ownerPathsPayload, "utf8")).toBeGreaterThan(ownerPathsPayload.length)
    expect(mockSsh.writeFile).toHaveBeenCalledWith(membersMarker, membersPayload, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(ownerPathsMarker, ownerPathsPayload, {
      mode: "0644",
    })
  })

  it("R-0000166: non-upload owner check operates on the persisted member list, not the live archive", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    // The live archive on disk now contains a *different* member; without
    // the persisted marker the check would stat the wrong path. With the
    // marker the check resolves the original member and reports `ok`.
    const driftedTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/replacement"
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(driftedTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    // The check must not consult the live archive listing when the marker is
    // available — that's the entire point of R-0000166.
    expect(mockSsh.calls).not.toContain(tarListCommand(src))
  })

  it.each([
    { label: "malformed", ownerPaths: "{not-json" },
    {
      label: "truncated",
      ownerPaths: `${JSON.stringify([extractedFileMember.path])}${CAPTURE_TRUNCATION_MARKER}`,
    },
  ])("fails closed for a $label owner-paths marker without legacy fallback", async (testCase) => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: { code: 0, stdout: testCase.ownerPaths },
      [`test -d '${destination}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [markerCheckCommand(marker)]: { code: 0 },
    })

    const result = await archive
      .extract(src, destination, { owner: "www-data:www-data" })
      .check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, { pinCLocale: true })
    expect(mockSsh.calls).not.toContain(tarListCommand(src))
    expect(mockSsh.calls).not.toContain(ownershipProbeCommand("www-data:www-data"))
  })

  it("R-0000166: falls back to the live archive listing when the owner-paths marker is missing (legacy host)", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 1,
        stderr: "cat: No such file or directory",
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
      [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, { pinCLocale: true })
    expectArchiveCaptureExecCall(mockSsh, tarListCommand(src), { strictUtf8: true })
    expect(mockSsh.calls).toContain(tarListCommand(src))
  })

  it("returns ok when a numeric owner matches the extracted member ids", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      // No passwd or group entry for 65532, so GNU coreutils answers UNKNOWN
      // for the name columns; only the numeric columns can match.
      [ownershipProbeCommand("65532:65532")]: ownershipReport(
        `${destination}/app/file`,
        "UNKNOWN UNKNOWN 65532 65532"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "65532:65532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain(ownershipProbeCommand("65532:65532"))
  })

  it("returns ok for a leading-zero numeric owner on extracted members", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("065532:065532")]: ownershipReport(
        `${destination}/app/file`,
        "UNKNOWN UNKNOWN 65532 65532"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "065532:065532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("returns needs-apply when a numeric owner does not match the extracted member ids", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [markerCheckCommand(marker)]: { code: 0 },
      [ownershipProbeCommand("65532:65532")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "65532:65532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("R-0000162: rejects a poisoned mktemp -d output for the staging directory", async () => {
    const mockSsh = createMockSsh(
      {
        [tarListCommand(src)]: { code: 0, stdout: gnuTarListing(safeTarListing) },
      },
      {
        responseStubs: [
          {
            command: archiveStageMktempPattern,
            result: { code: 0, stdout: "/tmp/elsewhere.AbCdEfGh" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp -d produced an unexpected staging path/v
    )
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`
    )
  })
})

describe("archive.extract containment-failure flag (Issue #219)", () => {
  // Issue #219: a host link the archive's `a/up -> ..` makes escape; an
  // unrelated escaping host link would no longer refuse the apply.
  const escapingHostLinks = (): HostLinkTree => new Map([[`${destination}/a/esc`, "up/.."]])
  const refusedArchive = [tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")]
  const escRefusal = `[archive.extract] refusing to extract ${src}: symlink "/opt/app/a/esc" -> "up/.." would resolve outside destination "/opt/app" once this archive is merged; the archive's symlinks and the existing symlinks whose resolution passes through a path it writes are checked together before anything is copied`

  it("makes check of an earlier source report needs-apply after a later source was refused, until an apply succeeds", async () => {
    // Source A ships `a/esc -> up/..` and succeeds. Source B ships `a/up -> ..`,
    // which would make A's link escape, and is refused before the merge. A's
    // marker still matches A's archive, so only the destination-keyed flag
    // keeps `check(A)` from reporting ok after that rollback.
    const hostLinks: HostLinkTree = new Map()
    const files = new Map<string, string>()
    const markerA = markerFor(src)
    const markerB = markerFor(otherSrc)

    const applyA = await applyTarListing(
      [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
      { files, hostLinks }
    )
    expect(extractionSummary(applyA)).toStrictEqual(extractedThroughStaging)
    expect(markerA).toBe(marker)
    expect(files.get(markerA)).toBe(archiveSha)
    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })

    const applyB = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
      files,
      hostLinks,
      source: otherSrc,
    })
    expect(applyB.result.status).toBe("failed")
    expect(applyB.writes.map(({ remotePath }) => remotePath)).toStrictEqual([ownEntry(2)])
    expect(files.get(markerA)).toBe(archiveSha)
    expect(files.has(markerB)).toBe(false)
    expect(hasContainmentState(files)).toBe(true)

    const checkAfterRefusal = await checkAgainstHostFiles(src, files)
    expect(checkAfterRefusal.result).toBe("needs-apply")
    // The marker content is never read: the combined test already failed.
    expect(checkAfterRefusal.calls).toContain(markerCheckCommand(markerA))
    expect(checkAfterRefusal.calls).not.toContain(`cat '${markerA}'`)
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "needs-apply",
    })

    const reapplyA = await applyTarListing(
      [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
      { files, hostLinks }
    )
    expect(extractionSummary(reapplyA)).toStrictEqual(extractedThroughStaging)
    const clear = reapplyA.mockSsh.calls.findIndex((command) => isContainmentClear(command))
    const markerWrites = reapplyA.writes.filter(({ remotePath }) => remotePath.startsWith(markerA))
    expect(markerWrites.map(({ remotePath }) => remotePath)).toStrictEqual([markerA, membersMarker])
    for (const write of markerWrites) expect(clear).toBeGreaterThanOrEqual(write.callIndex)
    // Issue #219: the reapply removed B's entry, which it read and verified,
    // and then its own.
    expect(hasContainmentState(files)).toBe(false)

    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })
  })

  it("leaves an existing entry in place when the apply is refused again", async () => {
    // Issue #219: an earlier apply's entry; a refused apply never touches it
    // and records its own failure in its own entry.
    const files = new Map<string, string>([[earlierEntry, recordedFlag()]])
    const hostLinks = escapingHostLinks()

    const run = await applyTarListing(refusedArchive, { files, hostLinks })

    expect(run.result.error?.message).toBe(escRefusal)
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag(),
      [ownEntryName()]: recordedFlag(),
    })
  })

  it("establishes the own entry in one exec before the destination is touched, then records the refusal with the marker mode", async () => {
    const run = await applyTarListing(refusedArchive, { hostLinks: escapingHostLinks() })

    expect(run.result.error?.message).toBe(escRefusal)
    expect(run.mockSsh.writeFileCalls).toStrictEqual([])
    const writeSpy = vi.mocked(run.mockSsh.writeFile)
    // Issue #219: the establish exec created the `in-progress` entry; the only
    // write is the record of the refusal before the merge, into that entry:
    // nothing was published, so no links are recorded.
    expect(writeSpy.mock.calls).toStrictEqual([[ownEntry(), recordedFlag(), { mode: "0644" }]])
    // Issue #219: the entries are read and the own entry is created, in the
    // one exec that also creates the flags directory, after the archive
    // listing and before the destination is created, resolved or probed, so
    // it precedes the pre-staging probe and the pre-merge listing as well.
    const { calls } = run.mockSsh
    expect(run.mockSsh.execCalls).toContainEqual({
      command: containmentEstablishCommand(),
      options: {
        ignoreExitCode: true,
        maxOutputBytes: CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES,
        silent: true,
      },
    })
    expect(calls.filter((command) => command.startsWith(containmentEstablishPrefix))).toHaveLength(
      1
    )
    const establish = calls.indexOf(containmentEstablishCommand())
    const archiveListing = calls.indexOf(tarListCommand(src))
    const destinationMkdir = calls.indexOf(guardedArchiveDestinationMkdirCommand(destination))
    const destinationReadlink = calls.indexOf(`readlink -f -- '${destination}'`)
    const preStagingProbe = calls.indexOf(preStagingProbeCommand)
    const listing = calls.indexOf(symlinkListingProbeCommand)
    expect(archiveListing).toBeLessThan(establish)
    expect(
      Math.min(destinationMkdir, destinationReadlink, preStagingProbe, listing)
    ).toBeGreaterThan(establish)
  })

  it("fails a fully extracted apply when the entries cannot be cleared", async () => {
    const clearCommand = `${containmentClearPrefix}'${ownEntry()}'`
    const run = await applyTarListing([tarFileLine("f")], {
      responses: {
        [clearCommand]: {
          code: 6,
          stderr: `rm: cannot remove '${ownEntry()}': Read-only file system`,
        },
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to remove containment entry ${ownEntry()} and the entries it verified (exit code 6)\nrm: cannot remove '${ownEntry()}': Read-only file system`
    )
    // The clear exec is the last step: every marker was already written.
    // Issue #219: after the failed clear, the own entry records the failure
    // without offending links.
    const clear = run.mockSsh.calls.indexOf(clearCommand)
    expect(clear).toBe(run.mockSsh.calls.length - 1)
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([
      marker,
      membersMarker,
      ownEntry(),
    ])
    const [markerWrite, membersWrite, recordWrite] = run.writes
    for (const write of [markerWrite, membersWrite]) {
      expect(clear).toBeGreaterThanOrEqual(write.callIndex)
    }
    expect(recordWrite.callIndex).toBeGreaterThan(clear)
    expect(vi.mocked(run.mockSsh.writeFile).mock.calls.at(-1)?.[1]).toBe(recordedFlag())
  })

  /**
   * Issue #219: assert that an apply stopped before it created, resolved or
   * probed the destination.
   *
   * @param run - The recorded apply run.
   */
  function expectDestinationUntouched(run: TarListingApplyRun): void {
    const { calls } = run.mockSsh
    expect(calls).not.toContain(guardedArchiveDestinationMkdirCommand(destination))
    expect(calls).not.toContain(`readlink -f -- '${destination}'`)
    expect(calls).not.toContain(preStagingProbeCommand)
  }

  // Issue #219: the own entry is established before the destination is
  // created or probed, so an entry that cannot be created stops the apply
  // before the destination mkdir, the pre-staging probe and anything listed,
  // staged or copied.
  it("refuses before the listing and the merge when the own entry cannot be created", async () => {
    const run = await applyTarListing(refusedArchive, {
      hostLinks: escapingHostLinks(),
      responses: {
        [containmentEstablishCommand()]: { code: 13, stderr: "sh: No space left on device" },
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: failed to create containment entry in ${containment.entryDirectory}: sh: No space left on device; the containment entry must be in place before the destination is touched`
    )
    expect(run.writes).toStrictEqual([])
    expectDestinationUntouched(run)
    expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("refuses before the listing and the merge when the flags directory cannot be created", async () => {
    const run = await applyTarListing(refusedArchive, {
      hostLinks: escapingHostLinks(),
      responses: {
        // Issue #219: the establish exec creates the flags directory and
        // exits 2 when that fails.
        [containmentEstablishCommand()]: {
          code: 2,
          stderr: "mkdir: cannot create directory '/var/lib/paratix': Read-only file system",
        },
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: failed to create archive marker directory for containment entries ${containment.entryDirectory}: mkdir: cannot create directory '/var/lib/paratix': Read-only file system; the containment entry must be in place before the destination is touched`
    )
    expect(run.writes).toStrictEqual([])
    expectDestinationUntouched(run)
    expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("never reaches the merge or the backstop when the own entry cannot be created", async () => {
    const escapingLink = `${destination}/a/esc`
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
      hostLinks,
      injectedOnMerge: [[escapingLink, "up/.."]],
      responses: { [containmentEstablishCommand()]: { code: 13 } },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain("failed to create containment entry")
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(run.postMergeListings).toStrictEqual([])
    expect([...hostLinks]).toStrictEqual([])
  })
})

/**
 * Issue #219: NUL-framed kernel cross-check output of
 * `(link, verdict, level)` triples.
 *
 * @param reports - The triples.
 * @returns The cross-check's stdout.
 */
function crossCheckReports(...reports: ReadonlyArray<readonly [string, string, string]>): string {
  return reports
    .flat()
    .map((field) => `${field}\u0000`)
    .join("")
}

/**
 * Issue #219: a connection that answers the backstop's listing and kernel
 * cross-check execs from scripted queues and records every exec. The last
 * answer of a queue repeats; an `Error` answer makes that exec reject. Any
 * other exec is unscripted and rejects, so a backstop that tried to change
 * the host would fail the test.
 *
 * @param script - The scripted answers.
 * @param script.crossChecks - Issue #219: answers of the kernel cross-checks;
 *   unscripted, every carried link is confirmed as `same`.
 * @param script.listings - Answers of the listings.
 * @returns The connection and its recorded execs.
 */
function scriptedBackstopConnection(script: {
  crossChecks?: Array<Error | Partial<ExecResult>>
  listings: Array<Error | Partial<ExecResult>>
}): { conn: SshConnection; execCalls: ExecCall[] } {
  const execCalls: ExecCall[] = []
  const queues = new Map([
    [kernelCrossCheckCommand, [...(script.crossChecks ?? [])]],
    [symlinkListingProbeCommand, [...script.listings]],
  ])
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      await Promise.resolve()
      execCalls.push({ command, options })
      const queue = queues.get(command) ?? []
      const next = queue.length > 1 ? queue.shift() : queue[0]
      // Issue #219: an unscripted kernel cross-check confirms every link.
      if (next === undefined && command === kernelCrossCheckCommand) {
        return { code: 0, stderr: "", stdout: crossCheckStdout(options?.input) }
      }
      if (next === undefined) throw new Error(`unscripted exec: ${command}`)
      if (next instanceof Error) throw next
      return { code: 0, stderr: "", stdout: "", ...next }
    },
  } as unknown as SshConnection
  return { conn, execCalls }
}

/**
 * Issue #219: the backstop's description of a link beyond the resolution limit.
 *
 * @param link - The absolute link path.
 * @param stored - The stored target.
 * @returns The violation text.
 */
function beyondLimit(link: string, stored: string): string {
  return `symlink ${JSON.stringify(link)} -> ${JSON.stringify(stored)} cannot be resolved within the symlink resolution limit`
}

/**
 * Issue #219: an archive member for the backstop's scope.
 *
 * @param path - Destination-relative path as the archive listing spells it.
 * @param linkTarget - Where a symlink member points, or null for a regular file.
 * @param kind - What the listing reports the entry as; a symlink when `linkTarget` is set, a file otherwise.
 * @returns A tar member with the mode that matches its kind.
 */
function archiveMember(
  path: string,
  linkTarget: null | string,
  kind: ArchiveMember["kind"] = linkTarget === null ? "file" : "symlink"
): ArchiveMember {
  const modes: Record<ArchiveMember["kind"], string> = {
    directory: "drwxr-xr-x",
    file: "-rw-r--r--",
    hardlink: "hrw-r--r--",
    special: "prw-r--r--",
    symlink: "lrwxrwxrwx",
  }
  return { format: "tar", kind, linkTarget, mode: modes[kind], path }
}

/**
 * Issue #219: archive symlink members for absolute `(link, target)` pairs
 * below the destination, so the backstop judges exactly those links.
 *
 * @param links - Absolute link paths with their targets.
 * @returns One symlink member per link.
 */
function shippedMembers(links: ReadonlyArray<readonly [string, string]>): ArchiveMember[] {
  return links.map(([link, target]) => archiveMember(link.slice(destination.length + 1), target))
}

/**
 * Issue #219: a hex-encoded listing field.
 *
 * @param parts - Text (as UTF-8) and single raw bytes, concatenated.
 * @returns The marker byte 0x01 followed by the hex of the bytes.
 */
function hexListingField(...parts: Array<number | string>): string {
  const bytes = parts.map((part) =>
    typeof part === "number" ? Buffer.from([part]) : Buffer.from(part, "utf8")
  )
  return `\u0001${Buffer.concat(bytes).toString("hex")}`
}

describe("archive containment recovery hint", () => {
  const clearHint = "clear its containment state with rm -f --"
  const unrelated = [[`${destination}/elsewhere/escape`, "/etc"]] as const
  const shipped = [[`${destination}/a/s`, "/etc"]] as const
  const touched = [[`${destination}/x/escape`, "../a/../.."]] as const
  const unrelatedMembers = [archiveMember("b/f", null)]
  const symlinkMembers = [archiveMember("a/s", "f")]

  it.each([
    {
      hint: false,
      links: shipped,
      members: symlinkMembers,
      name: "an archive-owned violation in archive scope",
      recordedLinks: [],
      verifyWholeDestination: false,
    },
    {
      hint: false,
      links: touched,
      members: symlinkMembers,
      name: "a touched link violation in archive scope",
      recordedLinks: [],
      verifyWholeDestination: false,
    },
    {
      hint: false,
      links: unrelated,
      members: unrelatedMembers,
      name: "a recorded violation in archive scope",
      recordedLinks: ["elsewhere/escape"],
      verifyWholeDestination: false,
    },
    {
      hint: true,
      links: unrelated,
      members: unrelatedMembers,
      name: "an unrelated outward link in whole-destination scope",
      recordedLinks: ["elsewhere/escape"],
      verifyWholeDestination: true,
    },
    {
      hint: true,
      links: unrelated,
      members: symlinkMembers,
      name: "an unrelated outward link with an archive symlink in whole-destination scope",
      recordedLinks: [],
      verifyWholeDestination: true,
    },
    {
      hint: false,
      links: shipped,
      members: symlinkMembers,
      name: "an archive-owned violation in whole-destination scope",
      recordedLinks: [],
      verifyWholeDestination: true,
    },
    {
      hint: false,
      links: touched,
      members: symlinkMembers,
      name: "a touched link violation in whole-destination scope",
      recordedLinks: [],
      verifyWholeDestination: true,
    },
  ])("offers state clearing only when it can recover from $name", async (testCase) => {
    const { conn, execCalls } = scriptedBackstopConnection({
      listings: [{ stdout: listingRecords(destination, testCase.links) }],
    })

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...testCase,
      destination,
      entryDirectory: containment.entryDirectory,
      legacyFlag: containment.legacyFlag,
      source: src,
    })

    expect(outcome.failure?.status).toBe("failed")
    const message = String(outcome.failure?.error?.message)
    expect(message.includes(clearHint)).toBe(testCase.hint)
    expect(outcome.offendingLinks).toStrictEqual([
      testCase.links[0][0].slice(destination.length + 1),
    ])
    expect(execCalls.map(({ command }) => command)).toStrictEqual([symlinkListingProbeCommand])
  })

  it.each([
    { members: [archiveMember("locked/s", "f")], name: "an unreadable archive member" },
    { members: symlinkMembers, name: "an unrelated unreadable directory" },
  ])("suppresses the hint with $name", async ({ members }) => {
    const { conn, execCalls } = scriptedBackstopConnection({
      listings: [{ stdout: `u\u0000locked\u0000${listingRecords(destination, unrelated)}` }],
    })

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      entryDirectory: containment.entryDirectory,
      legacyFlag: containment.legacyFlag,
      members,
      source: src,
      verifyWholeDestination: true,
    })

    expect(outcome.failure?.error?.message).toContain("is not readable")
    expect(outcome.failure?.error?.message).not.toContain(clearHint)
    expect(outcome.offendingLinks).toBe("unidentified")
    expect(execCalls.map(({ command }) => command)).toStrictEqual([symlinkListingProbeCommand])
  })

  it("suppresses the hint when a link in archive scope has a kernel mismatch", async () => {
    const inside = [`${destination}/a/s`, "f"] as const
    const { conn, execCalls } = scriptedBackstopConnection({
      crossChecks: [{ stdout: crossCheckReports([inside[0], "differ", "0"]) }],
      listings: [{ stdout: listingRecords(destination, [...unrelated, inside]) }],
    })

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      entryDirectory: containment.entryDirectory,
      legacyFlag: containment.legacyFlag,
      members: symlinkMembers,
      source: src,
      verifyWholeDestination: true,
    })

    expect(outcome.failure?.error?.message).toContain(
      "resolves on the host to a different location"
    )
    expect(outcome.failure?.error?.message).not.toContain(clearHint)
    expect(outcome.offendingLinks).toStrictEqual(["elsewhere/escape", "a/s"])
    expect(execCalls.map(({ command }) => command)).toStrictEqual([
      symlinkListingProbeCommand,
      kernelCrossCheckCommand,
    ])
  })

  it("quotes both known containment paths and keeps the entry glob active", async () => {
    const { conn, execCalls } = scriptedBackstopConnection({
      listings: [{ stdout: listingRecords(destination, unrelated) }],
    })

    const outcome = await runSymlinkContainmentBackstop(conn, {
      destination,
      entryDirectory: "/flags/a'b.d",
      legacyFlag: "/old flags/a'b.failed",
      members: unrelatedMembers,
      source: src,
      verifyWholeDestination: true,
    })

    expect(outcome.failure?.error?.message).toContain(
      `${clearHint} '/flags/a'\\''b.d'/run-* '/old flags/a'\\''b.failed'`
    )
    expect(execCalls.map(({ command }) => command)).toStrictEqual([symlinkListingProbeCommand])
  })

  it.each([
    { entryDirectory: containment.entryDirectory, legacyFlag: undefined, name: "the legacy flag" },
    { entryDirectory: undefined, legacyFlag: containment.legacyFlag, name: "the entry directory" },
  ])("omits an incomplete recovery command without $name", async (paths) => {
    const { conn } = scriptedBackstopConnection({
      listings: [{ stdout: listingRecords(destination, unrelated) }],
    })

    const outcome = await runSymlinkContainmentBackstop(conn, {
      ...paths,
      destination,
      members: unrelatedMembers,
      source: src,
      verifyWholeDestination: true,
    })

    expect(outcome.failure?.status).toBe("failed")
    expect(outcome.failure?.error?.message).not.toContain(clearHint)
  })
})

describe("enforceSymlinkContainment (Issue #219)", () => {
  const refusal = `[archive.extract] refusing to complete extraction of ${src}: `
  const checkedAfterMerge =
    "after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship"
  const nothingChanged =
    "nothing was removed or changed; while the offending symlinks remain, remove them or point them inside the destination manually; this apply's containment entry records them and keeps check at needs-apply, and a later apply of any source verifies them again (every symlink under the destination when the entry could not record them) and, only when they pass, removes the entries it read that are still unchanged"
  /** Issue #219: the message tail every post-merge violation ends with. */
  const reportTail = `${checkedAfterMerge}; ${nothingChanged}`
  const listingCall: ExecCall = {
    command: symlinkListingProbeCommand,
    options: {
      ignoreExitCode: true,
      input: postMergeListingInput,
      maxOutputBytes: SYMLINK_LISTING_CAPTURE_LIMIT_BYTES,
      silent: true,
      strictUtf8Stdout: true,
    },
  }
  /**
   * Issue #219: the kernel cross-check exec for links the resolver judged
   * inside.
   *
   * @param entries - One `[link, K_n, E_n, ..., K_0, E_0]` list of absolute
   *   paths per link (see {@link plainCrossCheckEntry}).
   * @returns The expected exec call.
   */
  const crossCheckCall = (...entries: ReadonlyArray<readonly string[]>): ExecCall => ({
    command: kernelCrossCheckCommand,
    options: {
      ignoreExitCode: true,
      input: entries.map((paths) => `${paths.join("//")}\u0000`).join(""),
      maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
      silent: true,
      strictUtf8Stdout: true,
    },
  })
  const etc = [`${destination}/a/etc`, "/etc"] as const
  const escapesEtc = `symlink "/opt/app/a/etc" -> "/etc" resolves outside destination "/opt/app"`

  /** Issue #219: an archive symlink the listed trees do not contain. */
  const absentArchiveLink = [archiveMember("zz/l", "f")]

  /**
   * Issue #219: run the backstop against scripted listing and cross-check
   * answers.
   *
   * @param script - The scripted answers.
   * @param members - The archive members; by default one symlink that is not
   *   in the listing, so the backstop runs but judges only links whose walk
   *   touches `zz` or `zz/l`.
   * @returns The execs, the failure message and the outcome.
   */
  async function enforce(
    script: Parameters<typeof scriptedBackstopConnection>[0],
    members: readonly ArchiveMember[] = absentArchiveLink
  ): Promise<{ execCalls: ExecCall[]; message: string | undefined; outcome: ModuleResult | null }> {
    const { conn, execCalls } = scriptedBackstopConnection(script)
    const outcome = await enforceSymlinkContainment(conn, { destination, members, source: src })
    return { execCalls, message: outcome?.error?.message, outcome }
  }

  /**
   * Issue #219: run the backstop as if the archive shipped every given link,
   * so each of them is judged.
   *
   * @param links - Absolute link paths with their stored targets, listed in order.
   * @param script - Further scripted answers.
   * @param script.crossChecks - Answers of the kernel cross-checks.
   * @returns The execs, the failure message and the outcome.
   */
  async function enforceShipped(
    links: ReadonlyArray<readonly [string, string]>,
    script: { crossChecks?: Array<Error | Partial<ExecResult>> } = {}
  ): ReturnType<typeof enforce> {
    return enforce(
      { ...script, listings: [{ stdout: listingRecords(destination, links) }] },
      shippedMembers(links)
    )
  }

  it("lists the destination, cross-checks the links with the kernel and accepts a tree whose links all stay inside", async () => {
    const { execCalls, outcome } = await enforceShipped([
      [`${destination}/a/lib64`, "lib"],
      [`${destination}/a/up`, ".."],
      [`${destination}/a/abs`, `${destination}/a/lib`],
      [`${destination}/a/dangling`, "missing/y/z"],
      [`${destination}/a/esc`, "up/a"],
    ])

    expect(outcome).toBeNull()
    expect(execCalls).toStrictEqual([
      listingCall,
      crossCheckCall(
        plainCrossCheckEntry(`${destination}/a/lib64`, "lib"),
        plainCrossCheckEntry(`${destination}/a/up`, ".."),
        plainCrossCheckEntry(`${destination}/a/abs`, `${destination}/a/lib`),
        plainCrossCheckEntry(`${destination}/a/dangling`, "missing/y/z"),
        // `up` is a link, so the model's location after it is the root.
        [
          `${destination}/a/esc`,
          `${destination}/a/up/a`,
          `${destination}/a`,
          `${destination}/a/up`,
          destination,
          `${destination}/a`,
          `${destination}/a`,
        ]
      ),
    ])
  })

  it("runs no kernel cross-check for a tree without symlinks", async () => {
    const { execCalls, outcome } = await enforce({ listings: [{ stdout: "" }] })

    expect(outcome).toBeNull()
    expect(execCalls).toStrictEqual([listingCall])
  })

  it("runs no exec at all for an archive without symlink members", async () => {
    const { execCalls, outcome } = await enforce({ listings: [new Error("never listed")] }, [
      archiveMember("a/", null, "directory"),
      archiveMember("a/f", null),
    ])

    expect(outcome).toBeNull()
    expect(execCalls).toStrictEqual([])
  })

  it("ignores unrelated host links, even escaping, looping or unmappable ones, and cross-checks only the judged links", async () => {
    const shipped = [`${destination}/bin/node`, "../lib/node_modules/npm/bin/npm-cli.js"] as const
    const unrelated = [
      [`${destination}/_work/proj/.venv/bin/python3`, "/usr/bin/python3"],
      [`${destination}/x/loop`, "loop"],
      [`${destination}/x/up`, "../.."],
    ] as const
    const unmappable = `l\u0000${hexListingField("x/", 0xff)}\u0000/etc\u0000`
    const { execCalls, outcome } = await enforce(
      {
        listings: [
          { stdout: `${listingRecords(destination, [...unrelated, shipped])}${unmappable}` },
        ],
      },
      [...shippedMembers([shipped]), archiveMember("lib/node_modules/npm/bin/npm-cli.js", null)]
    )

    expect(outcome).toBeNull()
    expect(execCalls).toStrictEqual([listingCall, crossCheckCall(plainCrossCheckEntry(...shipped))])
  })

  it("reports a host link that walks through an archive link and one that follows it", async () => {
    const esc = [`${destination}/x/esc`, "../a/up/.."] as const
    const chained = [`${destination}/y/l`, "../x/esc/f"] as const
    const { message } = await enforce(
      {
        listings: [
          { stdout: listingRecords(destination, [esc, chained, [`${destination}/a/up`, ".."]]) },
        ],
      },
      [archiveMember("a/", null, "directory"), archiveMember("a/up", "..")]
    )

    expect(message).toBe(
      `${refusal}symlink "/opt/app/x/esc" -> "../a/up/.." resolves outside destination "/opt/app"; symlink "/opt/app/y/l" -> "../x/esc/f" resolves outside destination "/opt/app"; ${reportTail}`
    )
  })

  it("ignores an unrelated unreadable directory but reports a judged walk into it and an archive member below it", async () => {
    const intoLocked = [`${destination}/a/l`, "../locked/f"] as const
    const unrelated = await enforce({ listings: [{ stdout: "u\u0000other\u0000" }] })
    const judged = await enforce(
      {
        listings: [{ stdout: `u\u0000locked\u0000${listingRecords(destination, [intoLocked])}` }],
      },
      [...shippedMembers([intoLocked]), archiveMember("locked/f", null)]
    )

    expect(unrelated.outcome).toBeNull()
    expect(judged.message).toBe(
      `${refusal}archive member path "/opt/app/locked/f" cannot be checked: directory "/opt/app/locked" is not readable; symlink "/opt/app/a/l" -> "../locked/f" cannot be checked: directory "/opt/app/locked" is not readable; ${reportTail}`
    )
    expect(judged.execCalls).toStrictEqual([listingCall])
  })

  it("reports a judged link whose name is not UTF-8 with the bytes spelled as escapes", async () => {
    const { message } = await enforce(
      { listings: [{ stdout: `l\u0000${hexListingField("zz/", 0xff)}\u0000../zz/l\u0000` }] },
      absentArchiveLink
    )

    expect(message).toBe(
      `${refusal}symlink "/opt/app/zz/\\\\xff" -> "../zz/l" cannot be checked: its path or target is not valid UTF-8; rename or remove that symlink; ${reportTail}`
    )
  })

  // Issue #219: the success path costs the listing plus one kernel
  // cross-check, two execs, however many links the tree holds.
  it("keeps the success path at exactly two execs however many links the tree holds", async () => {
    const execCounts = await Promise.all(
      [1, 2000].map(async (count) => {
        const links = Array.from(
          { length: count },
          (_value, index) => [`${destination}/d${String(index)}/l`, "../f"] as const
        )
        const { execCalls, outcome } = await enforceShipped(links)
        expect(outcome).toBeNull()
        return execCalls.length
      })
    )

    expect(execCounts).toStrictEqual([2, 2])
  })

  it.each([
    {
      detail: "sh: 1: readlink: not found",
      name: "a non-zero exit, e.g. a missing readlink",
      response: { code: 1, stderr: "sh: 1: readlink: not found\n" },
    },
    {
      detail: "exit code 1",
      name: "a non-zero exit without output",
      response: { code: 1 },
    },
    {
      detail: `the destination holds too many symlinks to check: the symlink listing exceeded its captured-output cap of ${String(SYMLINK_LISTING_CAPTURE_LIMIT_BYTES)} bytes`,
      name: "a truncated capture",
      response: {
        stdout: `l\u0000a/etc\u0000/etc\u0000l\u0000a/e${CAPTURE_TRUNCATION_MARKER}`,
      },
    },
    {
      detail: 'probe output ends inside a "l" record',
      name: "a record cut off at the end",
      response: { stdout: "l\u0000a/etc\u0000/etc\u0000l\u0000b\u0000" },
    },
    {
      detail: 'probe reported unknown record kind "q"',
      name: "an unknown record kind",
      response: { stdout: "q\u0000a\u0000" },
    },
    {
      detail: `probe reported directory "${destination}/a", which is not a requested member path below the destination`,
      name: "a directory hit, which the backstop never requests",
      response: { stdout: `n\u0000${destination}/a\u0000` },
    },
    {
      detail:
        'probe reported symlink "/opt/other/l", which is not a normalized path below the destination',
      name: "an absolute link path",
      response: { stdout: "l\u0000/opt/other/l\u0000x\u0000" },
    },
    {
      detail:
        'probe reported symlink "../app-alt/l", which is not a normalized path below the destination',
      name: "a link in a sibling sharing the destination's prefix",
      response: { stdout: "l\u0000../app-alt/l\u0000/etc\u0000" },
    },
    {
      detail: 'probe reported an empty target for symlink "l"; readlink output is unusable',
      name: "an empty stored target",
      response: { stdout: `l\u0000l\u0000\u0000${listingRecords(destination, [etc])}` },
    },
    {
      detail:
        'probe reported unreadable directory "a/", which is not a normalized path below the destination or was reported more than once',
      name: "an unreadable directory that is not normalized",
      response: { stdout: "u\u0000a/\u0000" },
    },
  ])("fails closed and removes nothing on a listing with $name", async ({ detail, response }) => {
    const { execCalls, message } = await enforce({ listings: [response] })

    expect(message).toBe(`${refusal}symlink containment check failed: ${detail}`)
    expect(execCalls).toStrictEqual([listingCall])
  })

  it("reports an escaping link and removes nothing: the listing and its cross-check are the only execs", async () => {
    const inside = [`${destination}/a/in`, "f"] as const
    const { execCalls, message, outcome } = await enforceShipped([etc, inside])

    expect(outcome?.status).toBe("failed")
    expect(message).toBe(`${refusal}${escapesEtc}; ${reportTail}`)
    expect(execCalls).toStrictEqual([listingCall, crossCheckCall(plainCrossCheckEntry(...inside))])
  })

  it("reports links beyond the resolution limit, cycles included, with the limit wording", async () => {
    // `x -> y`, `y -> x` is a cycle and `b -> b/..` extends itself on every
    // hop; GNU `realpath` never returns on the latter. The resolver stops both.
    const links = [
      [`${destination}/x`, "y"],
      [`${destination}/y`, "x"],
      [`${destination}/b`, "b/.."],
    ] as const
    const { execCalls, message } = await enforceShipped(links)

    expect(message).toBe(
      `${refusal}${links.map(([link, stored]) => beyondLimit(link, stored)).join("; ")}; ${reportTail}`
    )
    expect(execCalls).toStrictEqual([listingCall])
  })

  it("names every violation with its link path, stored target and reason", async () => {
    const root = [`${destination}/a/root`, "../.."] as const
    const loop = [`${destination}/loop`, "loop"] as const
    const { execCalls, message } = await enforceShipped([etc, root, loop])

    expect(message).toBe(
      `${refusal}${escapesEtc}; symlink "/opt/app/a/root" -> "../.." resolves outside destination "/opt/app"; symlink "/opt/app/loop" -> "loop" cannot be resolved within the symlink resolution limit; ${reportTail}`
    )
    expect(message).not.toContain("more)")
    expect(execCalls).toStrictEqual([listingCall])
  })

  // Issue #219: the message names a bounded number of links, so a tree with
  // many offending links cannot inflate it; the rest is counted.
  it.each([
    { extra: 0, suffix: "" },
    { extra: 1, suffix: " (and 1 more)" },
    { extra: 25, suffix: " (and 25 more)" },
  ])(
    "names at most the report limit of violations and counts $extra more",
    async ({ extra, suffix }) => {
      const links = Array.from(
        { length: POST_MERGE_VIOLATION_REPORT_LIMIT + extra },
        (_value, index) => [`${destination}/e${String(index)}`, "/etc"] as const
      )
      const { execCalls, message } = await enforceShipped(links)

      const named = links
        .slice(0, POST_MERGE_VIOLATION_REPORT_LIMIT)
        .map(
          ([link]) =>
            `symlink ${JSON.stringify(link)} -> "/etc" resolves outside destination "/opt/app"`
        )
      expect(message).toBe(`${refusal}${named.join("; ")}${suffix}; ${reportTail}`)
      for (const [link] of links.slice(POST_MERGE_VIOLATION_REPORT_LIMIT)) {
        expect(message).not.toContain(JSON.stringify(link))
      }
      expect(execCalls).toStrictEqual([listingCall])
    }
  )

  // Issue #219: a violation costs no exec beyond the listing and, when a link
  // is judged inside, its kernel cross-check.
  it.each([
    { commands: [symlinkListingProbeCommand], inside: 0 },
    { commands: [symlinkListingProbeCommand, kernelCrossCheckCommand], inside: 1 },
    { commands: [symlinkListingProbeCommand, kernelCrossCheckCommand], inside: 500 },
  ])(
    "spends no exec beyond the listing and its cross-check on a violation with $inside link(s) judged inside",
    async ({ commands, inside }) => {
      const links = Array.from(
        { length: inside },
        (_value, index) => [`${destination}/in${String(index)}`, "f"] as const
      )
      const { execCalls, outcome } = await enforceShipped([etc, ...links])

      expect(outcome?.status).toBe("failed")
      expect(execCalls.map(({ command }) => command)).toStrictEqual(commands)
    }
  )

  it("fails closed and removes nothing when the listing exec throws", async () => {
    const { execCalls, message } = await enforce({ listings: [new Error("channel closed")] })

    expect(message).toBe(`${refusal}symlink containment check failed: channel closed`)
    expect(execCalls).toStrictEqual([listingCall])
  })

  it("reports a link the kernel resolves elsewhere, names both locations and removes nothing", async () => {
    const up = [`${destination}/d/up`, ".."] as const
    const esc = [`${destination}/d/esc`, "Up2/.."] as const
    const { execCalls, message } = await enforceShipped([up, esc], {
      crossChecks: [{ stdout: crossCheckReports([up[0], "same", "0"], [esc[0], "differ", "0"]) }],
    })

    expect(message).toBe(
      `${refusal}symlink "/opt/app/d/esc" -> "Up2/.." resolves on the host to a different location than the containment check computed ("/opt/app/d"); ${reportTail}`
    )
    expect(execCalls).toStrictEqual([
      listingCall,
      crossCheckCall(plainCrossCheckEntry(...up), plainCrossCheckEntry(...esc)),
    ])
  })

  it.each([
    {
      level: "2",
      reason:
        'reaches nothing on the host, and the nearest existing point of its target path, "/opt/app/d/missing" on the host, is not the location the containment check computed for it ("/opt/app/d/missing")',
    },
    {
      level: "4",
      reason:
        'reaches nothing on the host, and no point of its target path exists on the host or where the containment check computed it, so its location ("/opt/app/d/missing/n") cannot be confirmed',
    },
  ])(
    "reports a link that reaches nothing where the kernel disagrees at level $level and removes nothing",
    async ({ level, reason }) => {
      const dangling = [`${destination}/d/l`, "missing/n"] as const
      const { execCalls, message } = await enforceShipped([dangling], {
        crossChecks: [{ stdout: crossCheckReports([dangling[0], "differ", level]) }],
      })

      expect(message).toBe(
        `${refusal}symlink "/opt/app/d/l" -> "missing/n" ${reason}; ${reportTail}`
      )
      expect(execCalls).toStrictEqual([
        listingCall,
        crossCheckCall(plainCrossCheckEntry(...dangling)),
      ])
    }
  )

  it("reports a link that passes through a case variant of another symlink and removes nothing", async () => {
    const up = [`${destination}/d/up`, ".."] as const
    const esc = [`${destination}/d/esc`, "UP/.."] as const
    const { execCalls, message } = await enforceShipped([up, esc])

    expect(message).toBe(
      `${refusal}symlink "/opt/app/d/esc" -> "UP/.." passes through "d/UP", a name that differs from existing symlink "d/up" only by letter case or Unicode normalization; a case-insensitive or normalizing filesystem may follow that symlink instead; ${reportTail}`
    )
    expect(execCalls).toStrictEqual([listingCall, crossCheckCall(plainCrossCheckEntry(...up))])
  })

  it.each([
    { name: "a non-zero exit", response: { code: 65, stderr: "test -ef is not supported" } },
    {
      name: "an unknown verdict",
      response: { stdout: crossCheckReports([`${destination}/a/in`, "maybe", "0"]) },
    },
    {
      name: "an invalid level",
      response: { stdout: crossCheckReports([`${destination}/a/in`, "same", "1"]) },
    },
    { name: "a missing link", response: { stdout: "" } },
    { name: "a rejected exec", response: new Error("channel closed") },
  ])(
    "fails closed and removes nothing when the kernel cross-check has $name",
    async ({ response }) => {
      const inside = [`${destination}/a/in`, "f"] as const
      const { execCalls, message } = await enforceShipped([inside], { crossChecks: [response] })

      expect(message).toMatch(
        /^\[archive\.extract\] refusing to complete extraction of \/tmp\/app\.tar\.gz: symlink containment check failed: kernel cross-check could not be completed: /v
      )
      expect(execCalls.map(({ command }) => command)).toStrictEqual([
        symlinkListingProbeCommand,
        kernelCrossCheckCommand,
      ])
    }
  )

  it("fails closed on a listing that reports the same link twice or an unencoded non-ASCII name", async () => {
    const twice = await enforce({ listings: [{ stdout: listingRecords(destination, [etc, etc]) }] })
    const unencoded = await enforce({ listings: [{ stdout: "l\u0000a/\ufffd\u0000f\u0000" }] })

    expect(twice.message).toBe(
      `${refusal}symlink containment check failed: probe reported symlink "a/etc" more than once`
    )
    expect(unencoded.message).toContain(
      "with characters outside printable ASCII that were not hex-encoded"
    )
    expect(twice.execCalls).toStrictEqual([listingCall])
    expect(unencoded.execCalls).toStrictEqual([listingCall])
  })

  it("accepts a hex-encoded literal U+FFFD in a judged link name as an exact name", async () => {
    const replacement = [`${destination}/a/\ufffd`, "f"] as const
    const { execCalls, outcome } = await enforceShipped([replacement])

    expect(outcome).toBeNull()
    expect(execCalls).toStrictEqual([
      listingCall,
      crossCheckCall(plainCrossCheckEntry(...replacement)),
    ])
  })
})

/**
 * Issue #219: a connection whose `exec` hands the given raw stdout bytes to the
 * production stream collector (`collectStreamOutput`) through a fake channel
 * that then closes with exit code 0, so the exec decodes them exactly as the
 * SSH layer would, including `strictUtf8Stdout`. It needs no filesystem that
 * stores such names, so it also runs where APFS refuses them.
 *
 * @param stdout - The raw bytes the remote command printed.
 * @returns The connection and the commands it executed.
 */
function rawStdoutConnection(stdout: Buffer): { commands: string[]; conn: SshConnection } {
  const commands: string[] = []
  const conn = {
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      commands.push(command)
      return new Promise<ExecResult>((resolve, reject) => {
        const stream = Object.assign(new EventEmitter(), { stderr: new EventEmitter() })
        const timer = setTimeout(() => {
          /* the fake channel closes synchronously; this never fires */
        }, 60_000)
        collectStreamOutput({
          command,
          options: options ?? {},
          reject,
          resolve,
          stream: stream as unknown as StreamOutputParameters["stream"],
          timer,
        })
        stream.emit("data", stdout)
        stream.emit("close", 0)
        clearTimeout(timer)
      })
    },
  } as unknown as SshConnection
  return { commands, conn }
}

describe("host symlink names that are not UTF-8 (Issue #219)", () => {
  // `d/<fe> -> ..` escapes, `d/<ff> -> .` stays inside. A lossy decode reads
  // both names as `d/U+FFFD`, so in one listing order the contained link
  // would hide the escaping one. The probe therefore hex-encodes every name
  // outside printable ASCII; raw bytes that are not UTF-8 can only come from a
  // broken probe and still fail closed in both orders.
  const linkDirectory = Buffer.from(`${destination}/d/`)
  const escaping = [Buffer.concat([linkDirectory, Buffer.from([0xfe])]), Buffer.from("..")]
  const contained = [Buffer.concat([linkDirectory, Buffer.from([0xff])]), Buffer.from(".")]
  const nul = Buffer.from([0])
  const listing = (...pairs: Buffer[][]): Buffer =>
    Buffer.concat(pairs.flatMap((pair) => pair.flatMap((field) => [field, nul])))
  const orders = [
    { name: "escaping link first", stdout: listing(escaping, contained) },
    { name: "escaping link last", stdout: listing(contained, escaping) },
  ]
  const notUtf8 = `Command stdout is not valid UTF-8 (exit code 0): ${symlinkListingProbeCommand}`
  /** Issue #219: an archive link in `d`, so the links there are judged. */
  const members = [archiveMember("d/", null, "directory"), archiveMember("d/l", ".")]

  it("would collapse both names into one under the lenient default decode", () => {
    // The premise of the strict decode: different host bytes, same string.
    expect(escaping[0].toString("utf8")).toBe(contained[0].toString("utf8"))
    expect(escaping[0].equals(contained[0])).toBe(false)
  })

  it.each(orders)(
    "fails the post-merge backstop closed and removes nothing on raw bytes ($name)",
    async ({ stdout }) => {
      const { commands, conn } = rawStdoutConnection(stdout)

      const outcome = await enforceSymlinkContainment(conn, { destination, members, source: src })

      expect(outcome?.error?.message).toBe(
        `[archive.extract] refusing to complete extraction of ${src}: symlink containment check failed: ${notUtf8}`
      )
      expect(commands).toStrictEqual([symlinkListingProbeCommand])
    }
  )

  it.each(orders)("fails the pre-merge check closed on raw bytes ($name)", async ({ stdout }) => {
    const { commands, conn } = rawStdoutConnection(stdout)

    const outcome = await validateMergedSymlinkContainment(conn, {
      destination,
      members,
      source: src,
    })

    expect(outcome?.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: symlink listing before the merge failed: ${notUtf8}`
    )
    expect(commands).toStrictEqual([symlinkListingProbeCommand])
  })

  const escapingRecord = ["l", hexListingField("d/", 0xfe), "l/../.."]
  const containedRecord = ["l", hexListingField("d/", 0xff), "l"]

  it.each([
    { name: "escaping link first", records: [escapingRecord, containedRecord] },
    { name: "escaping link last", records: [containedRecord, escapingRecord] },
  ])(
    "keeps the hex-encoded names apart and reports the judged links as unmappable ($name)",
    async ({ records: ordered }) => {
      const records = ordered
        .flat()
        .map((field) => `${field}\u0000`)
        .join("")
      const { commands, conn } = rawStdoutConnection(Buffer.from(records))

      const outcome = await validateMergedSymlinkContainment(conn, {
        destination,
        members,
        source: src,
      })

      // Both targets walk through `d/l`, which the archive writes, so both
      // links are judged, and neither can be checked: their names are not
      // UTF-8. Two tokens keep the two names apart.
      expect(outcome?.error?.message).toMatch(
        /cannot be checked: its path or target is not valid UTF-8; rename or remove that symlink; .* \(and 1 more\)$/v
      )
      expect(commands).toStrictEqual([symlinkListingProbeCommand])
    }
  )
})

describe("archive.extract containment flag lifecycle (Issue #219)", () => {
  const owner = "www-data:www-data"
  // Issue #219: the archive ships a symlink, so both listings run.
  const lifecycleLines = [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")]
  /** Issue #219: a host link whose walk passes through `a`, which the archive writes. */
  const escapesThroughArchive = [`${destination}/x/esc`, "../a/../.."] as const

  it("establishes the own entry before the destination is created or probed, the listing, staging, extract and merge, and clears it last", async () => {
    const files = new Map<string, string>()

    const run = await applyTarListing(lifecycleLines, {
      files,
      hostLinks: new Map(),
      owner,
    })

    expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    const { calls } = run.mockSsh
    const markerWrites = run.writes
    const establish = calls.indexOf(containmentEstablishCommand())
    expect(establish).toBeGreaterThanOrEqual(0)
    // Issue #219: the pre-merge and the post-merge listing issue the same
    // command; exactly one of each runs on a converged tree.
    expect(run.postMergeListings).toHaveLength(1)
    expect(calls.filter((command) => command === symlinkListingProbeCommand)).toHaveLength(2)
    // Issue #219: the destination mkdir, its `readlink -f` check and the
    // pre-staging probe all run after the establish exec.
    const destinationMkdir = calls.indexOf(guardedArchiveDestinationMkdirCommand(destination))
    const listing = calls.indexOf(symlinkListingProbeCommand)
    const chown = calls.indexOf(batchedChownCommand)
    const order = [
      destinationMkdir,
      calls.indexOf(`readlink -f -- '${destination}'`),
      calls.indexOf(preStagingProbeCommand),
      listing,
      calls.findIndex((command) => archiveStageMktempPattern.test(command)),
      calls.indexOf(stagedTarExtractCommand),
      calls.findIndex((command) => archiveStageMovePattern.test(command)),
      run.postMergeListings[0],
      calls.indexOf(kernelCrossCheckCommand),
      chown,
    ]
    expect(Math.min(...order)).toBeGreaterThanOrEqual(0)
    expect(order).toStrictEqual(order.toSorted((left, right) => left - right))
    expect(establish).toBeLessThan(destinationMkdir)
    expect(establish).toBeLessThan(listing)
    expect(markerWrites.map(({ remotePath }) => remotePath)).toStrictEqual(
      expect.arrayContaining([marker, membersMarker])
    )
    for (const write of markerWrites) expect(write.callIndex).toBeGreaterThan(chown)
    // The clear exec is the very last command, after every marker write; the
    // apply read no other entry, so it removes only its own.
    expect(calls.at(-1)).toBe(`${containmentClearPrefix}'${ownEntry()}'`)
    for (const write of markerWrites) {
      expect(calls.length - 1).toBeGreaterThanOrEqual(write.callIndex)
    }
    expect(hasContainmentState(files)).toBe(false)
  })

  it.each([
    {
      error: "destination path probe failed",
      name: "a pre-staging refusal",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        responses: { [preStagingProbeCommand]: { code: 1, stderr: "xargs: sh: not found" } },
      }),
    },
    {
      error: "failed to resolve destination",
      name: "a failed destination validation",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        responses: {
          [`readlink -f -- '${destination}'`]: { code: 1, stderr: "readlink: denied" },
        },
      }),
    },
    {
      error: "would resolve outside destination",
      name: "a pre-merge refusal",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map([escapesThroughArchive]),
      }),
    },
    {
      error: "symlink listing before the merge failed: find: Permission denied",
      name: "a failed listing",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        responses: {
          [symlinkListingProbeCommand]: { code: 1, stderr: "find: Permission denied" },
        },
      }),
    },
    {
      error: `failed to copy extracted files into ${destination}`,
      name: "a failed merge",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        responseStubs: [
          { command: archiveStageMovePattern, result: { code: 1, stderr: "cp: failed" } },
        ],
      }),
    },
    {
      error: "refusing to complete extraction",
      name: "a backstop violation",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        injectedOnMerge: [escapesThroughArchive],
      }),
    },
    {
      error: "chown failed for one or more extracted members",
      name: "a failed chown",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        owner,
        responses: { [batchedChownCommand]: { code: 1, stderr: "chown: denied" } },
      }),
    },
    {
      error: "No space left on device",
      name: "a failed marker write",
      options: (): TarListingApplyOptions => ({ failWrite: marker, hostLinks: new Map() }),
    },
  ])("leaves the flag set after $name", async ({ error, options }) => {
    const files = new Map<string, string>()

    const run = await applyTarListing(lifecycleLines, {
      ...options(),
      files,
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(error)
    expect(run.writes.at(-1)?.remotePath).toBe(ownEntry())
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    expect(hasContainmentState(files)).toBe(true)
    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it("leaves the flag set when an exec throws during the extract", async () => {
    const files = new Map<string, string>()

    const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/f")], {
      files,
      hostLinks: new Map(),
      throwOn: { command: stagedTarExtractCommand, error: new Error("channel closed") },
    })

    expect(run.thrown).toStrictEqual(new Error("channel closed"))
    const { calls } = run.mockSsh
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
      containmentFlagWritesOfFailedApply
    )
    expect(containmentClears(calls)).toStrictEqual([])
    expect(calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    // The staging directory is still cleaned up.
    expect(calls.some((command) => archiveStageCleanupPattern.test(command))).toBe(true)
    expect(hasContainmentState(files)).toBe(true)
  })
})

/**
 * Issue #219: the commands an apply run issued from its first post-merge
 * backstop listing on. The backstop only reads, so after a violation this is
 * the listing and, when a link is judged inside, its kernel cross-check.
 *
 * @param run - The recorded apply run.
 * @returns The commands from the first post-merge listing on.
 */
function callsFromBackstop(run: TarListingApplyRun): string[] {
  if (run.postMergeListings.length === 0) return []
  return run.mockSsh.calls.slice(run.postMergeListings[0])
}

describe("archive.extract post-merge backstop (Issue #219)", () => {
  // Issue #219: the backstop judges the archive's links and every link whose
  // walk passes through a path the archive writes (`a`, `a/f`, `a/l`), so the
  // escaping links below walk through `a` or the archive link `a/l`.
  const escapingLink = `${destination}/a/esc`
  const escapingTarget = "../a/../.."
  const rootLink = `${destination}/a/root`
  const lines = [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")]
  const backstopRefusal = `[archive.extract] refusing to complete extraction of ${src}: `
  const checkedAfterMerge =
    "after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship"
  const nothingChanged = `nothing was removed or changed; while the offending symlinks remain, remove them or point them inside the destination manually; this apply's containment entry records them and keeps check at needs-apply, and a later apply of any source verifies them again (every symlink under the destination when the entry could not record them) and, only when they pass, removes the entries it read that are still unchanged`
  const escapesEtc = `symlink ${JSON.stringify(escapingLink)} -> ${JSON.stringify(escapingTarget)} resolves outside destination ${JSON.stringify(destination)}`
  const escapesRoot = `symlink ${JSON.stringify(rootLink)} -> "l/../../.." resolves outside destination ${JSON.stringify(destination)}`
  const reportedEtc = `${backstopRefusal}${escapesEtc}; ${checkedAfterMerge}; ${nothingChanged}`
  const cpFailure = "cp: cannot overwrite directory '/opt/app/a/b' with non-directory"

  it("runs after a failed merge, reports the escaping link without removing it and joins both messages", async () => {
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing(lines, {
      hostLinks,
      injectedOnMerge: [[escapingLink, escapingTarget]],
      owner: "www-data:www-data",
      responseStubs: [{ command: archiveStageMovePattern, result: { code: 1, stderr: cpFailure } }],
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination} (exit code 1)\n${cpFailure}; ${reportedEtc}`
    )
    const { calls } = run.mockSsh
    const merge = calls.findIndex((command) => archiveStageMovePattern.test(command))
    // One listing and nothing after it: no cross-check without a link judged
    // inside, no removal, no flag removal.
    expect(run.postMergeListings).toHaveLength(1)
    expect(run.postMergeListings[0]).toBeGreaterThan(merge)
    expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
    expect(calls).not.toContain(batchedChownCommand)
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
      containmentFlagWritesOfFailedApply
    )
    expect([...hostLinks]).toStrictEqual([[escapingLink, escapingTarget]])
  })

  it("runs after a merge exec that threw and joins both messages", async () => {
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing(lines, {
      hostLinks,
      injectedOnMerge: [[escapingLink, escapingTarget]],
      throwOn: { command: archiveStageMovePattern, error: new Error("channel closed") },
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination}: channel closed; ${reportedEtc}`
    )
    const { calls } = run.mockSsh
    const cleanup = calls.findIndex((command) => archiveStageCleanupPattern.test(command))
    expect(cleanup).toBeGreaterThan(
      calls.findIndex((command) => archiveStageMovePattern.test(command))
    )
    expect(run.postMergeListings[0]).toBeGreaterThan(cleanup)
    expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
    expect([...hostLinks]).toStrictEqual([[escapingLink, escapingTarget]])
  })

  it("reports only the merge failure when the backstop after it finds nothing", async () => {
    const run = await applyTarListing(lines, {
      hostLinks: new Map(),
      responseStubs: [{ command: archiveStageMovePattern, result: { code: 1, stderr: cpFailure } }],
    })

    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination} (exit code 1)\n${cpFailure}`
    )
    expect(run.postMergeListings).toHaveLength(1)
    expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
  })

  it("names every violating link, removes nothing and keeps the flag", async () => {
    const insideLink = `${destination}/a/inside`
    const hostLinks: HostLinkTree = new Map([[`${destination}/a/old`, "f"]])
    const files = new Map<string, string>()

    const run = await applyTarListing(lines, {
      files,
      hostLinks,
      injectedOnMerge: [
        [escapingLink, escapingTarget],
        [insideLink, "../a/f"],
        [rootLink, "l/../../.."],
        // Issue #219: unrelated to the archive, so neither judged nor reported.
        [`${destination}/x/etc`, "/etc"],
      ],
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `${backstopRefusal}${escapesEtc}; ${escapesRoot}; ${checkedAfterMerge}; ${nothingChanged}`
    )
    // The listing and the kernel cross-check of the links judged inside are
    // the only execs after the merge.
    expect(run.postMergeListings).toHaveLength(1)
    expect(callsFromBackstop(run)).toStrictEqual([
      symlinkListingProbeCommand,
      kernelCrossCheckCommand,
    ])
    expect([...hostLinks.keys()].toSorted()).toStrictEqual(
      [
        escapingLink,
        insideLink,
        `${destination}/a/l`,
        `${destination}/a/old`,
        rootLink,
        `${destination}/x/etc`,
      ].toSorted()
    )
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    expect(hasContainmentState(files)).toBe(true)
  })

  it("names at most the report limit of links and counts the rest", async () => {
    const links = Array.from(
      { length: POST_MERGE_VIOLATION_REPORT_LIMIT + 3 },
      (_value, index) => `${destination}/e${String(index).padStart(2, "0")}`
    )

    const run = await applyTarListing(lines, {
      backstopListings: [
        {
          stdout: listingRecords(
            destination,
            links.map((link) => [link, "a/../.."] as const)
          ),
        },
      ],
    })

    const named = links
      .slice(0, POST_MERGE_VIOLATION_REPORT_LIMIT)
      .map(
        (link) =>
          `symlink ${JSON.stringify(link)} -> "a/../.." resolves outside destination ${JSON.stringify(destination)}`
      )
    expect(run.result.error?.message).toBe(
      `${backstopRefusal}${named.join("; ")} (and 3 more); ${checkedAfterMerge}; ${nothingChanged}`
    )
    expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
  })

  it.each([
    { listed: "a/s", name: "the literal member path", parent: "a" },
    { listed: "A/S", name: "a different letter case", parent: "a" },
    { listed: "é/s", name: "NFD for an NFC member path", parent: "é" },
  ])(
    "reports the archive's own link listed as $name after the merge and keeps the flag",
    async ({ listed, parent }) => {
      // Issue #219: the archive ships `<parent>/s -> t`, but the host changes
      // the link during the merge and lists it only under the spelling it
      // keeps on disk. Walking `../../x` from that parent touches no written
      // path, yet the link is the archive's own and escapes.
      const files = new Map<string, string>()
      const listedLink = `${destination}/${listed}`

      const run = await applyTarListing(
        [tarDirectoryLine(`${parent}/`), tarSymlinkLine(`${parent}/s`, "t")],
        {
          backstopListings: [{ stdout: listingRecords(destination, [[listedLink, "../../x"]]) }],
          files,
          hostLinks: new Map(),
        }
      )

      expect(run.result.status).toBe("failed")
      expect(run.result.error?.message).toBe(
        `${backstopRefusal}symlink ${JSON.stringify(listedLink)} -> "../../x" resolves outside destination ${JSON.stringify(destination)}; ${checkedAfterMerge}; ${nothingChanged}`
      )
      expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
      expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
      expect(hasContainmentState(files)).toBe(true)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
        result: "needs-apply",
      })
    }
  )

  it("fails closed on a listed link whose path is not normalized and changes nothing", async () => {
    // Issue #219: link paths arrive relative to the destination; one that is
    // not a normalized relative path cannot be keyed and fails the listing.
    const run = await applyTarListing(lines, {
      backstopListings: [{ stdout: "l\u0000../etc-link\u0000/etc-link\u0000" }],
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `${backstopRefusal}symlink containment check failed: probe reported symlink "../etc-link", which is not a normalized path below the destination`
    )
    expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
  })

  const channelClosed = `${backstopRefusal}symlink containment check failed: channel closed`

  it.each([
    {
      expected: `[archive.extract] failed to copy extracted files into ${destination} (exit code 1)\n${cpFailure}; ${channelClosed}`,
      name: "the listing after a failed merge",
      options: (): TarListingApplyOptions => ({
        responseStubs: [
          { command: archiveStageMovePattern, result: { code: 1, stderr: cpFailure } },
        ],
        throwOn: {
          command: symlinkListingProbeCommand,
          error: new Error("channel closed"),
          input: postMergeListingInput,
        },
      }),
    },
    {
      expected: channelClosed,
      name: "the listing after a successful merge",
      options: (): TarListingApplyOptions => ({
        throwOn: {
          command: symlinkListingProbeCommand,
          error: new Error("channel closed"),
          input: postMergeListingInput,
        },
      }),
    },
  ])(
    "fails with the containment check reason and keeps the flag when $name throws",
    async ({ expected, options }) => {
      const files = new Map<string, string>()
      const hostLinks: HostLinkTree = new Map()

      const run = await applyTarListing(lines, {
        ...options(),
        files,
        hostLinks,
        owner: "www-data:www-data",
      })

      expect(run.thrown).toBeUndefined()
      expect(run.result.status).toBe("failed")
      expect(run.result.error?.message).toBe(expected)
      expect(run.postMergeListings).toHaveLength(1)
      expect(run.mockSsh.calls).not.toContain(batchedChownCommand)
      expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
      expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
        containmentFlagWritesOfFailedApply
      )
      expect(hasContainmentState(files)).toBe(true)
    }
  )
})

describe("archive.extract containment flag records offending links (Issue #219)", () => {
  // Issue #219: the backstop only judges links the current archive can affect.
  // The destination-keyed flag must therefore remember which links made an
  // earlier apply fail, so a later source that never touches them cannot clear
  // the flag while they still escape.
  const escapingLink = `${destination}/a/esc`
  const escapingTarget = "../a/../.."
  // Issue #219: the escaping link walks through `a`, which this archive writes,
  // so its backstop judges and reports the link.
  const linesThroughEscapingLink = [
    tarDirectoryLine("a/"),
    tarFileLine("a/f"),
    tarSymlinkLine("a/l", "f"),
  ]
  // Issue #219: archives whose members lie outside `a`, so neither the
  // pre-merge check nor the backstop would judge the escaping link for them.
  const linesWithoutSymlinks = [tarDirectoryLine("b/"), tarFileLine("b/g")]
  const linesWithUnrelatedSymlink = [...linesWithoutSymlinks, tarSymlinkLine("b/s", "g")]

  /**
   * Issue #219: fail an apply of `src` after the merge because a link that
   * escapes appeared below `a` during the merge. The link stays on the host
   * and the flag stays set.
   *
   * @returns The host marker and flag files and the host links after the run.
   */
  async function failAfterMergeWithEscapingLink(): Promise<{
    files: Map<string, string>
    hostLinks: HostLinkTree
  }> {
    const files = new Map<string, string>()
    const hostLinks: HostLinkTree = new Map()
    const run = await applyTarListing(linesThroughEscapingLink, {
      files,
      hostLinks,
      injectedOnMerge: [[escapingLink, escapingTarget]],
    })
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain("refusing to complete extraction")
    expect(run.result.error?.message).toContain(escapingLink)
    // Issue #219: the own entry records the offending link, not just its
    // presence.
    expect(Object.values(containmentState(files))).toStrictEqual([recordedFlag("a/esc")])
    expect(hostLinks.get(escapingLink)).toBe(escapingTarget)
    return { files, hostLinks }
  }

  it("keeps the flag and fails a later source without symlinks while the recorded link still escapes", async () => {
    const { files, hostLinks } = await failAfterMergeWithEscapingLink()

    const run = await applyTarListing(linesWithoutSymlinks, {
      files,
      hostLinks,
      source: otherSrc,
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(escapingLink)
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    // Issue #219: B's own work passed, so A's entry still records exactly the
    // link A left, B's own entry records the same link, which B re-verified,
    // and B wrote none of its markers.
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName(1)]: recordedFlag("a/esc"),
      [ownEntryName(2)]: recordedFlag("a/esc"),
    })
    expect(files.has(markerFor(otherSrc))).toBe(false)
    // Issue #219: the failure record went through the guarded `writeFile`
    // with the marker mode, into B's own entry only; the only exec that
    // touched the entries is the establish exec.
    const entryWrites = vi
      .mocked(run.mockSsh.writeFile)
      .mock.calls.filter(([path]) => path.startsWith(containment.entryDirectory))
    expect(entryWrites.map(([path, , options]) => [path, options])).toStrictEqual([
      [ownEntry(2), { mode: "0644" }],
    ])
    expect(
      run.mockSsh.calls.filter((command) => command.includes(containment.entryDirectory))
    ).toStrictEqual([containmentEstablishCommand(2)])
    expect(hostLinks.get(escapingLink)).toBe(escapingTarget)
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it("keeps the flag and fails a later source whose symlinks lie in an unrelated directory, without extra execs", async () => {
    const { files, hostLinks } = await failAfterMergeWithEscapingLink()

    const run = await applyTarListing(linesWithUnrelatedSymlink, {
      files,
      hostLinks,
      source: otherSrc,
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(escapingLink)
    // Issue #219: the recorded link is judged from the one post-merge listing
    // the archive's own symlink already needs; the kernel cross-check covers
    // the archive link judged inside. Nothing runs after them.
    expect(run.postMergeListings).toHaveLength(1)
    expect(callsFromBackstop(run)).toStrictEqual([
      symlinkListingProbeCommand,
      kernelCrossCheckCommand,
    ])
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    expect(hasContainmentState(files)).toBe(true)
    expect(hostLinks.get(escapingLink)).toBe(escapingTarget)
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it.each([
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.delete(escapingLink)
      },
      name: "removed",
    },
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.set(escapingLink, "f")
      },
      name: "pointed back inside the destination",
    },
  ])(
    "clears the flag on the next successful apply once the recorded link was $name",
    async ({ fix }) => {
      const { files, hostLinks } = await failAfterMergeWithEscapingLink()
      fix(hostLinks)

      const run = await applyTarListing(linesWithoutSymlinks, {
        files,
        hostLinks,
        source: otherSrc,
      })

      expect(run.result.status).toBe("changed")
      expect(containmentClears(run.mockSsh.calls)).toHaveLength(1)
      expect(hasContainmentState(files)).toBe(false)
      await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
        result: "ok",
      })
    }
  )

  it.each([
    {
      linesFor: (index: string): string[] => [
        tarDirectoryLine(`d${index}/`),
        tarFileLine(`d${index}/f`),
      ],
      name: "without symlinks",
    },
    {
      linesFor: (index: string): string[] => [
        tarDirectoryLine(`d${index}/`),
        tarFileLine(`d${index}/f`),
        tarSymlinkLine(`d${index}/l`, "f"),
      ],
      name: "with symlinks in unrelated directories",
    },
  ])(
    "keeps the exec count of a later source $name constant as its member count grows while a link is recorded",
    async ({ linesFor }) => {
      const runWith = async (
        memberCount: number
      ): Promise<{
        calls: number
        crossChecks: number
        namesLink: boolean
        postMergeListings: number
        status: ModuleResult["status"]
        writes: number
      }> => {
        const { files, hostLinks } = await failAfterMergeWithEscapingLink()
        const lines = Array.from({ length: memberCount }, (_value, index) =>
          linesFor(String(index))
        ).flat()
        const run = await applyTarListing(lines, { files, hostLinks, source: otherSrc })
        const { calls } = run.mockSsh
        return {
          calls: calls.length,
          crossChecks: calls.filter((command) => command === kernelCrossCheckCommand).length,
          namesLink: String(run.result.error?.message).includes(escapingLink),
          postMergeListings: run.postMergeListings.length,
          status: run.result.status,
          writes: run.writes.length,
        }
      }

      const few = await runWith(3)
      const many = await runWith(300)

      expect(few).toMatchObject({ namesLink: true, status: "failed" })
      expect(many).toStrictEqual(few)
    }
  )

  it.each([
    {
      expectedFlagFor: (): string[] => [],
      hostLinksFor: (): HostLinkTree => new Map(),
      name: "are gone",
      status: "changed",
    },
    {
      // Issue #219: the earlier entry stays, and the own entry records every
      // recorded link that still escapes.
      expectedFlagFor: (keys: readonly string[]): string[] => [
        recordedFlag(...keys),
        recordedFlag(...keys),
      ],
      hostLinksFor: (keys: readonly string[]): HostLinkTree =>
        new Map(keys.map((key) => [`${destination}/${key}`, "../.."] as const)),
      name: "still escape",
      status: "failed",
    },
  ] as const)(
    "keeps the exec count of a later source constant in the number of recorded links that $name",
    async ({ expectedFlagFor, hostLinksFor, status }) => {
      const runWith = async (
        linkCount: number
      ): Promise<{
        calls: number
        flag: string[]
        postMergeListings: number
        status: ModuleResult["status"]
      }> => {
        // Issue #219: links an earlier failed apply recorded under `x`, where
        // this archive writes nothing.
        const keys = recordedKeys(linkCount)
        const files = new Map([[earlierEntry, recordedFlag(...keys)]])
        const hostLinks = hostLinksFor(keys)
        const run = await applyTarListing(linesWithoutSymlinks, {
          files,
          hostLinks,
          source: otherSrc,
        })
        return {
          calls: run.mockSsh.calls.length,
          flag: Object.values(containmentState(files)),
          postMergeListings: run.postMergeListings.length,
          status: run.result.status,
        }
      }

      const one = await runWith(1)
      const many = await runWith(200)

      expect(one).toMatchObject({ postMergeListings: 1, status })
      expect(many.status).toBe(status)
      expect(many.calls).toBe(one.calls)
      expect(many.postMergeListings).toBe(one.postMergeListings)
      // Issue #219: a clean run removes the earlier entry and its own; a
      // failing one records every recorded link that still escapes.
      expect(many.flag).toStrictEqual(expectedFlagFor(recordedKeys(200)))
    }
  )
})

/**
 * Issue #219: the `in-progress` body an apply creates its own entry with; an
 * older version's in-progress flag may still carry links.
 *
 * @param links - The carried link keys.
 * @returns The JSON body.
 */
function inProgress(...links: string[]): string {
  return containmentFlagBody({ links, state: "in-progress" })
}

/**
 * Issue #219: the entry body of a failure whose offending links are unknown.
 *
 * @param reason - Why they are unknown.
 * @returns The JSON body.
 */
function unknownFlag(reason: string): string {
  return containmentFlagBody({ reason, state: "unknown" })
}

/**
 * Issue #219: whether a write is a containment record. The establish exec
 * creates the own entry, so every `writeFile` into the entry directory is a
 * failure record.
 *
 * @param path - The written path.
 * @returns True for a containment record.
 */
function isContainmentFlagRecord(path: string): boolean {
  return path.startsWith(`${containment.entryDirectory}/run-`)
}

describe("archive.extract containment flag recording and verification (Issue #219)", () => {
  // Issue #219: `a/esc` walks through `a`, which these archives write, so the
  // backstop judges it; `x/esc` lies where none of them writes.
  const escapingLink = `${destination}/a/esc`
  const escapingTarget = "../a/../.."
  const linesThroughA = [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")]
  const linesThroughB = [tarDirectoryLine("b/"), tarFileLine("b/g"), tarSymlinkLine("b/s", "g")]
  const entryDirectory = containment.entryDirectory

  /**
   * Issue #219: the entry bodies an apply wrote through `writeFile`, in order.
   *
   * @param run - The recorded apply run.
   * @returns The contents of every containment record write.
   */
  function flagBodies(run: TarListingApplyRun): string[] {
    return vi
      .mocked(run.mockSsh.writeFile)
      .mock.calls.filter(([path]) => isContainmentFlagRecord(path))
      .map(([, content]) => content)
  }

  it.each([
    {
      answer: { code: 3 },
      name: "an old flag file that is a symlink",
      reason: `containment-failure flag ${legacyContainmentFlag} is a symlink; remove it`,
    },
    {
      answer: { code: 4 },
      name: "an old flag file that is not a regular file",
      reason: `containment-failure flag ${legacyContainmentFlag} exists but is not a regular file; remove it`,
    },
    {
      answer: { code: 12, stderr: "sha256sum: Input/output error\n" },
      name: "an unreadable old flag file",
      reason: `failed to read containment-failure flag ${legacyContainmentFlag}: sha256sum: Input/output error`,
    },
    {
      answer: { code: 5 },
      name: "an entry directory that is a symlink",
      reason: `containment entry directory ${entryDirectory} is a symlink; remove it`,
    },
    {
      answer: { code: 6 },
      name: "an entry directory that is no directory",
      reason: `containment entry directory ${entryDirectory} is not a directory and cannot be created; remove it`,
    },
    {
      answer: { code: 7 },
      name: "an inaccessible entry directory",
      reason: `containment entry directory ${entryDirectory} is not readable, writable and searchable`,
    },
    {
      answer: { code: 8, stderr: `${earlierEntryName}\n` },
      name: "a symlink entry",
      reason: `containment entry ${earlierEntry} is a symlink; remove it`,
    },
    {
      answer: { code: 9, stderr: `${earlierEntryName}\n` },
      name: "an entry that is not a regular file",
      reason: `containment entry ${earlierEntry} exists but is not a regular file; remove it`,
    },
    {
      answer: { code: 10 },
      name: "an entry name outside the run charset",
      reason: `containment entry directory ${entryDirectory} holds a run-* entry whose name has characters other than ASCII letters, digits and "-"; remove that entry`,
    },
    {
      answer: { code: 11, stderr: `sha256sum: Input/output error\n${earlierEntryName}\n` },
      name: "an unreadable entry",
      reason: `failed to read containment entry ${earlierEntry}`,
    },
    {
      answer: { code: 1, stderr: "sh: Input/output error" },
      name: "a failed exec",
      reason: `failed to read containment entries in ${entryDirectory}: sh: Input/output error`,
    },
    {
      answer: { code: 0, stdout: "garbage\ndone\n" },
      name: "output it does not print",
      reason: `failed to read containment entries in ${entryDirectory}: unexpected output`,
    },
    {
      answer: { code: 0, stdout: "" },
      name: "no output",
      reason: `failed to read containment entries in ${entryDirectory}: unexpected output`,
    },
  ])(
    "refuses and writes nothing when the establish exec reports $name",
    async ({ answer, reason }) => {
      const run = await applyTarListing(linesThroughA, {
        responses: { [containmentEstablishCommand()]: answer },
      })

      expect(run.result.error?.message).toBe(
        `[archive.extract] refusing to extract ${src}: ${reason}; the containment entry must be in place before the destination is touched`
      )
      expect(run.writes).toStrictEqual([])
      expect(run.mockSsh.calls).not.toContain(guardedArchiveDestinationMkdirCommand(destination))
      expectNoTarExtractCalls(run.mockSsh)
    }
  )

  it("refuses and writes nothing when the establish exec throws", async () => {
    const run = await applyTarListing(linesThroughA, {
      throwOn: { command: containmentEstablishCommand(), error: new Error("channel closed") },
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: failed to read containment entries in ${entryDirectory}: channel closed; the containment entry must be in place before the destination is touched`
    )
    expect(run.writes).toStrictEqual([])
    expect(run.mockSsh.calls).not.toContain(guardedArchiveDestinationMkdirCommand(destination))
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("records no links in its own entry after a refusal before the merge and leaves the earlier entry alone", async () => {
    // Issue #219: `a/up -> ..` would make the host's `a/esc -> up/..` escape,
    // so the pre-merge check refuses; nothing is published. The link an
    // earlier apply recorded (`x/esc`) stays recorded in that apply's entry.
    const files = new Map([[earlierEntry, recordedFlag("x/esc")]])
    const hostLinks: HostLinkTree = new Map([
      [`${destination}/a/esc`, "up/.."],
      [`${destination}/x/esc`, "../.."],
    ])

    const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
      files,
      hostLinks,
    })

    expect(run.result.error?.message).toContain("would resolve outside destination")
    expect(run.postMergeListings).toStrictEqual([])
    expect(flagBodies(run)).toStrictEqual([recordedFlag()])
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag("x/esc"),
      [ownEntryName()]: recordedFlag(),
    })
  })

  it("records no links when an exec throws before the merge, and rethrows", async () => {
    const files = new Map([[earlierEntry, recordedFlag("x/esc")]])

    const run = await applyTarListing(linesThroughA, {
      files,
      hostLinks: new Map(),
      throwOn: { command: stagedTarExtractCommand, error: new Error("channel closed") },
    })

    expect(run.thrown).toStrictEqual(new Error("channel closed"))
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag("x/esc"),
      [ownEntryName()]: recordedFlag(),
    })
  })

  it("records no links when an exec throws after the backstop passed, and rethrows", async () => {
    const files = new Map([[earlierEntry, recordedFlag("x/esc")]])

    const run = await applyTarListing(linesThroughA, {
      files,
      hostLinks: new Map(),
      owner: "www-data:www-data",
      throwOn: { command: batchedChownCommand, error: new Error("channel closed") },
    })

    expect(run.thrown).toStrictEqual(new Error("channel closed"))
    // The recorded link is gone from the host, so the backstop passed; the
    // earlier entry is only removed by a fully successful apply.
    expect(run.postMergeListings).toHaveLength(1)
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag("x/esc"),
      [ownEntryName()]: recordedFlag(),
    })
  })

  it("records unknown when the backstop listing throws after the merge, and the next apply verifies the destination and clears it", async () => {
    const files = new Map<string, string>()

    const run = await applyTarListing(linesThroughA, {
      files,
      hostLinks: new Map(),
      throwOn: {
        command: symlinkListingProbeCommand,
        error: new Error("channel closed"),
        input: postMergeListingInput,
      },
    })

    // Issue #219: the backstop wraps its own throw, so the apply fails and
    // records that the offending links could not be identified.
    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName()]: unknownFlag(UNIDENTIFIED_OFFENDING_LINKS),
    })
    // Issue #219: an unknown entry does not refuse the next apply; that apply
    // runs, finds no escaping link anywhere under the destination and removes
    // the unknown entry and its own.
    const next = await applyTarListing(linesThroughB, {
      files,
      hostLinks: new Map(),
      source: otherSrc,
    })
    expect(next.result.error).toBeUndefined()
    expect(next.result.status).toBe("changed")
    expect(next.postMergeListings).toHaveLength(1)
    expect(containmentClears(next.mockSsh.calls)).toHaveLength(1)
    expect(hasContainmentState(files)).toBe(false)
  })

  it("records the new offender, not the fixed recorded link, when another source fails", async () => {
    const files = new Map([[earlierEntry, recordedFlag("a/esc")]])
    // The recorded link was pointed back inside.
    const hostLinks: HostLinkTree = new Map([[escapingLink, "f"]])

    const run = await applyTarListing(linesThroughB, {
      files,
      hostLinks,
      injectedOnMerge: [[`${destination}/b/esc`, "../b/../.."]],
      source: otherSrc,
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(`${destination}/b/esc`)
    expect(run.result.error?.message).not.toContain(escapingLink)
    // Issue #219: a failing apply never touches another apply's entry.
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag("a/esc"),
      [ownEntryName()]: recordedFlag("b/esc"),
    })
  })

  it("records a recorded link that still escapes next to a new offender", async () => {
    const files = new Map([[earlierEntry, recordedFlag("a/esc")]])
    const hostLinks: HostLinkTree = new Map([[escapingLink, escapingTarget]])

    const run = await applyTarListing(linesThroughB, {
      files,
      hostLinks,
      injectedOnMerge: [[`${destination}/b/esc`, "../b/../.."]],
      source: otherSrc,
    })

    expect(run.result.error?.message).toContain(
      `symlink ${JSON.stringify(escapingLink)} -> ${JSON.stringify(escapingTarget)}, recorded by an earlier failed apply, resolves outside destination`
    )
    expect(containmentState(files)).toStrictEqual({
      [earlierEntryName]: recordedFlag("a/esc"),
      [ownEntryName()]: recordedFlag("a/esc", "b/esc"),
    })
  })

  it("records unknown when more links offend than an entry can list, and the next apply names them and records unknown again", async () => {
    const files = new Map<string, string>()
    const hostLinks: HostLinkTree = new Map()
    const injected = Array.from(
      { length: CONTAINMENT_FLAG_LINK_LIMIT + 1 },
      (_value, index) => [`${destination}/a/esc${String(index)}`, escapingTarget] as const
    )

    const run = await applyTarListing(linesThroughA, {
      files,
      hostLinks,
      injectedOnMerge: injected,
    })

    expect(run.result.status).toBe("failed")
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName(1)]: unknownFlag(TOO_MANY_OFFENDING_LINKS),
    })
    expect(parseContainmentFlag(String(files.get(ownEntry(1)))).kind).toBe("unknown")
    // Issue #219: the next apply of an unrelated source runs, judges every
    // link under the destination, names a bounded number of the offenders and
    // records unknown in its own entry, because they still do not fit.
    const next = await applyTarListing(linesThroughB, {
      files,
      hostLinks,
      source: otherSrc,
    })
    expect(next.thrown).toBeUndefined()
    expect(next.result.status).toBe("failed")
    expect(next.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(true)
    const message = String(next.result.error?.message)
    expect(message).toContain(JSON.stringify(`${destination}/a/esc0`))
    expect(message).toContain(
      `(and ${String(CONTAINMENT_FLAG_LINK_LIMIT + 1 - POST_MERGE_VIOLATION_REPORT_LIMIT)} more)`
    )
    expect(message).toContain("nothing was removed")
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName(1)]: unknownFlag(TOO_MANY_OFFENDING_LINKS),
      [ownEntryName(2)]: unknownFlag(TOO_MANY_OFFENDING_LINKS),
    })
    expect(files.has(markerFor(otherSrc))).toBe(false)
    expect(injected.filter(([link]) => hostLinks.get(link) === escapingTarget)).toStrictEqual(
      injected
    )
  })

  it("keeps the in-progress entry and says so when the failure record cannot be written", async () => {
    const files = new Map<string, string>()

    const run = await applyTarListing(linesThroughA, {
      failWriteWhen: isContainmentFlagRecord,
      files,
      hostLinks: new Map(),
      injectedOnMerge: [[escapingLink, escapingTarget]],
    })

    expect(run.result.error?.message).toContain(escapingLink)
    expect(run.result.error?.message).toContain(
      `; [archive.extract] failed to write containment entry ${ownEntry()}: No space left on device`
    )
    // Issue #219: an unfinished entry does not make the next apply refuse, so
    // the message must not promise that; it names what the next apply does.
    expect(run.result.error?.message).not.toContain("next apply refuses")
    expect(run.result.error?.message).toContain(
      "the entry still marks the apply as unfinished, so the next apply verifies the whole destination"
    )
    expect(containmentState(files)).toStrictEqual({ [ownEntryName()]: inProgress() })
  })

  it("re-creates the own entry with the failure record when another apply removed it meanwhile", async () => {
    // Issue #219: race 1: another apply read this apply's `in-progress`
    // entry, verified the whole destination and removed it. The failure record
    // goes through `writeFile`, which renames onto the entry path and so
    // creates the entry again; no other entry is written.
    const files = new Map<string, string>()
    const removedBeforeRecord = onFirstWriteOf(ownEntry(), () => {
      files.delete(ownEntry())
    })

    const run = await applyTarListing(linesThroughA, {
      failWriteWhen: removedBeforeRecord.hook,
      files,
      hostLinks: new Map(),
      injectedOnMerge: [[escapingLink, escapingTarget]],
    })

    expect(run.result.status).toBe("failed")
    expect(removedBeforeRecord.fired()).toBe(true)
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([ownEntry()])
    expect(containmentState(files)).toStrictEqual({ [ownEntryName()]: recordedFlag("a/esc") })
  })

  it("records unknown and re-creates a removed own entry when the apply throws after its merge started", async () => {
    // Issue #219: the only throw that escapes after the merge started is one
    // the staging cleanup cannot contain: its warning to a closed stderr
    // throws again. Meanwhile a concurrent clean apply removed this apply's
    // `in-progress` entry (race 1); the record must create it again.
    const files = new Map<string, string>()
    const stderrWrite = vi.spyOn(process.stderr, "write").mockImplementation(() => {
      files.delete(ownEntry())
      throw new Error("write EPIPE")
    })
    let run: TarListingApplyRun
    try {
      run = await applyTarListing(linesThroughA, {
        files,
        hostLinks: new Map(),
        responseStubs: [
          { command: archiveStageCleanupPattern, result: { code: 1, stderr: "rm: busy" } },
        ],
      })
    } finally {
      stderrWrite.mockRestore()
    }

    expect(run.thrown).toStrictEqual(new Error("write EPIPE"))
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(true)
    expect(run.postMergeListings).toStrictEqual([])
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([ownEntry()])
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName()]: unknownFlag(STOPPED_AFTER_MERGE_STARTED),
    })
  })

  it("verifies the whole destination after an unfinished entry and records the link that still escapes", async () => {
    const files = new Map<string, string>()
    const hostLinks: HostLinkTree = new Map()
    await applyTarListing(linesThroughA, {
      failWriteWhen: isContainmentFlagRecord,
      files,
      hostLinks,
      injectedOnMerge: [[escapingLink, escapingTarget]],
    })
    expect(containmentState(files)).toStrictEqual({ [ownEntryName(1)]: inProgress() })

    // Issue #219: `b` shares nothing with `a/esc`; only the destination-wide
    // verification an unknown entry requires can find the link.
    const run = await applyTarListing(linesThroughB, { files, hostLinks, source: otherSrc })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(JSON.stringify(escapingLink))
    expect(containmentState(files)).toStrictEqual({
      [ownEntryName(1)]: inProgress(),
      [ownEntryName(2)]: recordedFlag("a/esc"),
    })
    expect(files.has(markerFor(otherSrc))).toBe(false)
  })
})

/**
 * Issue #219: the commands one run issued that another did not, counting a
 * repeated command once per occurrence, in the order the first run issued them.
 *
 * @param more - The commands of the run expected to issue more.
 * @param fewer - The commands of the run to compare against.
 * @returns The commands only the first run issued.
 */
function extraCommands(more: readonly string[], fewer: readonly string[]): string[] {
  const remaining = [...fewer]
  return more.filter((command) => {
    const index = remaining.indexOf(command)
    if (index === -1) return true
    remaining.splice(index, 1)
    return false
  })
}

/**
 * Issue #219: the serialized `unknown` flag record, whatever its reason.
 */
const unknownFlagRecordPattern = /^\{"reason":".+","state":"unknown","version":1\}\n$/v

describe("archive.extract unknown containment flag verifies the whole destination (Issue #219)", () => {
  // Issue #219: a flag without a usable list of offending links no longer
  // refuses the apply. The apply runs normally; at its end the post-merge
  // listing of the whole destination judges every symlink under it, and the
  // flag is cleared only when none escapes or is unresolvable.
  const linesWithoutSymlinks = [tarDirectoryLine("b/"), tarFileLine("b/g")]
  const linesWithSymlinks = [...linesWithoutSymlinks, tarSymlinkLine("b/s", "g")]
  const archives = [
    { archive: "without symlinks", lines: linesWithoutSymlinks },
    { archive: "with symlinks", lines: linesWithSymlinks },
  ]
  const legacyFlagBody = "archive apply in progress or symlink containment check failed\n"
  // Issue #219: every case is an entry of another apply, except the first:
  // the single flag file of older paratix versions, which always forces the
  // destination-wide verification and is claimed like an entry.
  const unknownFlagBodies = [
    { content: legacyFlagBody, flag: "the old flag file", path: legacyContainmentFlag },
    { content: legacyFlagBody, flag: "the fixed text of older versions", path: earlierEntry },
    { content: "", flag: "an empty entry", path: earlierEntry },
    {
      content: '{"version":1,"state":"failed","links":["a/esc"',
      flag: "garbled JSON",
      path: earlierEntry,
    },
    {
      content: recordedFlag("a/esc").replace('"version":1', '"version":2'),
      flag: "another version",
      path: earlierEntry,
    },
    { content: inProgress("a/esc"), flag: "an in-progress body", path: earlierEntry },
    // Issue #219: the body another run of this version creates its own entry
    // with; it carries no links, so only the whole destination can clear it.
    {
      content: inProgress(),
      flag: "the in-progress entry of another run",
      path: earlierEntry,
    },
    {
      content: unknownFlag(TOO_MANY_OFFENDING_LINKS),
      flag: "an unknown record",
      path: earlierEntry,
    },
  ]
  const flagCases = unknownFlagBodies.flatMap((body) =>
    archives.map((shape) => ({ ...body, ...shape }))
  )
  // Issue #219: a host link in a directory no archive here writes, so neither
  // the pre-merge check nor the archive-scoped backstop judges it.
  const escapingElsewhere = `${destination}/elsewhere/esc`
  const outsideTarget = "../../.."
  /** Issue #219: a directory below the destination the listing cannot read. */
  const lockedDirectory = `${destination}/locked`
  /** Issue #219: a host link inside the destination, unrelated to the archives. */
  const insideHostLink = [`${destination}/x/in`, "f"] as const

  /**
   * Issue #219: the position of the staging merge in an apply run.
   *
   * @param run - The recorded apply run.
   * @returns The index of the merge in `mockSsh.calls`, or -1 without a merge.
   */
  function mergeIndex(run: TarListingApplyRun): number {
    return run.mockSsh.calls.findIndex((command) => archiveStageMovePattern.test(command))
  }

  /**
   * Issue #219: the links every kernel cross-check of an apply run carried,
   * sorted.
   *
   * @param run - The recorded apply run.
   * @returns The absolute link paths.
   */
  function crossCheckedLinksOf(run: TarListingApplyRun): string[] {
    return run.mockSsh.execCalls
      .filter(({ command }) => command === kernelCrossCheckCommand)
      .flatMap(({ options }) => crossCheckedLinks(options?.input))
      .toSorted()
  }

  /**
   * Issue #219: apply an archive of `src` on a host with the given flag files
   * and host links.
   *
   * @param lines - The archive listing lines.
   * @param host - The host state before the apply.
   * @param host.files - The flag entries on the host; empty for an absent flag.
   * @param host.links - The host symlinks below the destination.
   * @returns The run and the host files after it.
   */
  async function applyOnHost(
    lines: readonly string[],
    host: {
      files: ReadonlyArray<readonly [string, string]>
      links: ReadonlyArray<readonly [string, string]>
    }
  ): Promise<{ files: Map<string, string>; run: TarListingApplyRun }> {
    const files = new Map<string, string>(host.files)
    const run = await applyTarListing(lines, { files, hostLinks: new Map(host.links) })
    return { files, run }
  }

  it.each(flagCases)(
    "runs the apply and clears $flag on a clean destination for an archive $archive",
    async ({ content, lines, path }) => {
      const files = new Map([[path, content]])

      const run = await applyTarListing(lines, { files, hostLinks: new Map() })

      expect(run.thrown).toBeUndefined()
      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      // Issue #219: the destination-wide verification is the one post-merge
      // listing, after the merge.
      expect(run.postMergeListings).toHaveLength(1)
      expect(run.postMergeListings[0]).toBeGreaterThan(mergeIndex(run))
      expect(run.writes.some(({ remotePath }) => isContainmentFlagRecord(remotePath))).toBe(false)
      expect(isContainmentClear(run.mockSsh.calls.at(-1))).toBe(true)
      expect(hasContainmentState(files)).toBe(false)
      expect(files.get(marker)).toBe(archiveSha)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })
    }
  )

  it.each([
    {
      name: "an establish capture cut at its cap",
      options: (): TarListingApplyOptions => ({
        responses: {
          [containmentEstablishCommand()]: {
            code: 0,
            stdout: `entry ${earlierEntryName} ${"0".repeat(64)} 7b226c${CAPTURE_TRUNCATION_MARKER}`,
          },
        },
      }),
    },
    {
      name: "an entry that is not valid UTF-8",
      options: (): TarListingApplyOptions => ({
        responses: {
          [containmentEstablishCommand()]: {
            code: 0,
            stdout: `entry ${earlierEntryName} ${"0".repeat(64)} 7bff7d\ndone\n`,
          },
        },
      }),
    },
    {
      name: "more entries than it reads",
      options: (): TarListingApplyOptions => ({
        responses: {
          [containmentEstablishCommand()]: { code: 0, stdout: "more\ndone\n" },
        },
      }),
    },
  ])(
    "runs the apply, verifies the whole destination and clears after $name on a clean destination",
    async ({ options }) => {
      const run = await applyTarListing(linesWithoutSymlinks, {
        ...options(),
        hostLinks: new Map(),
      })

      expect(run.thrown).toBeUndefined()
      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      expect(run.postMergeListings).toHaveLength(1)
      expect(isContainmentClear(run.mockSsh.calls.at(-1))).toBe(true)
    }
  )

  it.each(flagCases)(
    "fails after the merge with $flag and an escaping link elsewhere for an archive $archive, and records exactly that link",
    async ({ content, lines, path }) => {
      const files = new Map([[path, content]])
      const hostLinks: HostLinkTree = new Map([[escapingElsewhere, outsideTarget]])

      const run = await applyTarListing(lines, { files, hostLinks })

      expect(run.thrown).toBeUndefined()
      expect(run.result.status).toBe("failed")
      // Issue #219: the apply's own work ran; only the verification failed.
      expect(run.mockSsh.calls).toContain(stagedTarExtractCommand)
      expect(mergeIndex(run)).toBeGreaterThanOrEqual(0)
      expect(run.postMergeListings).toHaveLength(1)
      const message = String(run.result.error?.message)
      expect(message).toContain(JSON.stringify(escapingElsewhere))
      expect(message).toContain("nothing was removed")
      expect(message).toContain(intendedLinksHint)
      // Issue #219: the unusable entry stays as it was; the own entry records
      // exactly the link.
      expect(files.get(path)).toBe(content)
      expect(files.get(ownEntry())).toBe(recordedFlag("elsewhere/esc"))
      expect(files.has(marker)).toBe(false)
      expect(files.has(membersMarker)).toBe(false)
      expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
      expect(hostLinks.get(escapingElsewhere)).toBe(outsideTarget)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
        result: "needs-apply",
      })
    }
  )

  it.each([
    {
      keys: ["elsewhere/abs"],
      links: [[`${destination}/elsewhere/abs`, "/etc"]] as const,
      name: "an absolute target outside the destination",
    },
    {
      keys: ["elsewhere/x", "elsewhere/y"],
      links: [
        [`${destination}/elsewhere/x`, "y"],
        [`${destination}/elsewhere/y`, "x"],
      ] as const,
      name: "a cycle that cannot be resolved",
    },
  ])(
    "fails with an unknown flag and records the links elsewhere with $name",
    async ({ keys, links }) => {
      const { files, run } = await applyOnHost(linesWithSymlinks, {
        files: [[legacyContainmentFlag, legacyFlagBody]],
        links,
      })

      expect(run.result.status).toBe("failed")
      expect(mergeIndex(run)).toBeGreaterThanOrEqual(0)
      expect(run.result.error?.message).toContain(JSON.stringify(links[0][0]))
      expect(run.result.error?.message).toContain("nothing was removed")
      expect(files.get(ownEntry())).toBe(recordedFlag(...keys))
      expect(files.has(marker)).toBe(false)
    }
  )

  it("names at most the report limit of links elsewhere and records every one of them", async () => {
    const keys = Array.from(
      { length: POST_MERGE_VIOLATION_REPORT_LIMIT + 3 },
      (_value, index) => `elsewhere/e${String(index).padStart(2, "0")}`
    )

    const { files, run } = await applyOnHost(linesWithoutSymlinks, {
      files: [[legacyContainmentFlag, legacyFlagBody]],
      links: keys.map((key) => [`${destination}/${key}`, "../../.."] as const),
    })

    const message = String(run.result.error?.message)
    expect(run.result.status).toBe("failed")
    expect(message).toContain(JSON.stringify(`${destination}/elsewhere/e00`))
    expect(message).not.toContain(JSON.stringify(`${destination}/${String(keys.at(-1))}`))
    expect(message).toContain("(and 3 more)")
    expect(files.get(ownEntry())).toBe(recordedFlag(...keys))
  })

  it.each([
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.delete(escapingElsewhere)
      },
      name: "removed",
    },
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.set(escapingElsewhere, "../b/g")
      },
      name: "pointed back inside the destination",
    },
  ])("clears the flag on the next apply once the link elsewhere was $name", async ({ fix }) => {
    const files = new Map([[legacyContainmentFlag, legacyFlagBody]])
    const hostLinks: HostLinkTree = new Map([[escapingElsewhere, outsideTarget]])
    const failing = await applyTarListing(linesWithoutSymlinks, { files, hostLinks })
    expect(failing.result.status).toBe("failed")
    expect(containmentState(files)).toStrictEqual({
      legacy: legacyFlagBody,
      [ownEntryName(1)]: recordedFlag("elsewhere/esc"),
    })
    fix(hostLinks)

    const run = await applyTarListing(linesWithoutSymlinks, {
      files,
      hostLinks,
      source: otherSrc,
    })

    expect(run.result.error).toBeUndefined()
    expect(run.result.status).toBe("changed")
    expect(containmentClears(run.mockSsh.calls)).toHaveLength(1)
    expect(hasContainmentState(files)).toBe(false)
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "ok",
    })
  })

  it.each(archives)(
    "keeps a flag with a usable list precise and leaves the link elsewhere unjudged for an archive $archive",
    async ({ lines }) => {
      // Issue #219: the control for the destination-wide cases above. A flag
      // that records its links re-verifies only those (here `x/gone`, no
      // longer on the host) and the links the archive can affect, so the same
      // escaping link elsewhere neither fails the apply nor keeps the flag.
      const { files, run } = await applyOnHost(lines, {
        files: [[earlierEntry, recordedFlag("x/gone")]],
        links: [[escapingElsewhere, outsideTarget]],
      })

      expect(run.thrown).toBeUndefined()
      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      expect(run.postMergeListings).toHaveLength(1)
      expect(crossCheckedLinksOf(run)).not.toContain(escapingElsewhere)
      expect(isContainmentClear(run.mockSsh.calls.at(-1))).toBe(true)
      expect(hasContainmentState(files)).toBe(false)
    }
  )

  const unreadableLocked = `directory ${JSON.stringify(lockedDirectory)} is not readable`
  const incompleteVerifications = [
    {
      detail: unreadableLocked,
      name: "an unreadable directory",
      options: (): TarListingApplyOptions => ({
        backstopListings: [{ stdout: "u\u0000locked\u0000" }],
      }),
    },
    {
      detail: unreadableLocked,
      name: "an unreadable directory next to an escaping link",
      options: (): TarListingApplyOptions => ({
        backstopListings: [
          {
            stdout: `u\u0000locked\u0000${listingRecords(destination, [[escapingElsewhere, outsideTarget]])}`,
          },
        ],
      }),
    },
    {
      detail: "find: '/opt/app/locked': Permission denied",
      name: "a failed listing",
      options: (): TarListingApplyOptions => ({
        backstopListings: [{ code: 1, stderr: "find: '/opt/app/locked': Permission denied" }],
      }),
    },
    {
      detail: "the destination holds too many symlinks to check",
      name: "a listing above its capture cap",
      options: (): TarListingApplyOptions => ({
        backstopListings: [
          { stdout: `l\u0000x/in\u0000f\u0000l\u0000x/e${CAPTURE_TRUNCATION_MARKER}` },
        ],
      }),
    },
    {
      detail: "symlink containment check failed: channel closed",
      name: "a listing that throws",
      options: (): TarListingApplyOptions => ({
        throwOn: {
          command: symlinkListingProbeCommand,
          error: new Error("channel closed"),
          input: postMergeListingInput,
        },
      }),
    },
  ]
  const incompleteCases = incompleteVerifications.flatMap((verification) =>
    archives.map((shape) => ({ ...verification, ...shape }))
  )

  it.each(incompleteCases)(
    "fails and records the flag as unknown when the verification meets $name for an archive $archive",
    async ({ detail, lines, options }) => {
      const files = new Map([[legacyContainmentFlag, legacyFlagBody]])

      const run = await applyTarListing(lines, { ...options(), files, hostLinks: new Map() })

      expect(run.thrown).toBeUndefined()
      expect(run.result.status).toBe("failed")
      expect(run.result.error?.message).toContain(detail)
      expect(mergeIndex(run)).toBeGreaterThanOrEqual(0)
      expect(run.postMergeListings).toHaveLength(1)
      // Issue #219: the verification did not complete, so no list of links is
      // known to be complete; the own entry must not record `failed`, and the
      // old flag file stays.
      expect(files.get(ownEntry())).toMatch(unknownFlagRecordPattern)
      expect(files.get(legacyContainmentFlag)).toBe(legacyFlagBody)
      expect(files.has(marker)).toBe(false)
      expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
        result: "needs-apply",
      })
    }
  )

  it.each([
    {
      error: "destination path probe failed",
      name: "a pre-staging refusal",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map(),
        responses: { [preStagingProbeCommand]: { code: 1, stderr: "xargs: sh: not found" } },
      }),
    },
    {
      error: "would resolve outside destination",
      name: "a pre-merge refusal",
      options: (): TarListingApplyOptions => ({
        // Issue #219: walks through `b`, which the archive writes.
        hostLinks: new Map([[`${destination}/x/esc`, "../b/../.."]]),
      }),
    },
  ])("keeps the old flag file unknown after $name before the merge", async ({ error, options }) => {
    const files = new Map([[legacyContainmentFlag, legacyFlagBody]])

    const run = await applyTarListing(linesWithSymlinks, { ...options(), files })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(error)
    expect(mergeIndex(run)).toBe(-1)
    // Issue #219: nothing before the merge verified the destination, so the
    // old flag file must stay and still read as unknown; the own entry only
    // records that this apply published nothing.
    expect(parseContainmentFlag(String(files.get(legacyContainmentFlag))).kind).toBe("unknown")
    expect(containmentState(files)).toStrictEqual({
      legacy: legacyFlagBody,
      [ownEntryName()]: recordedFlag(),
    })
    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it("keeps the old flag file unknown when an exec throws before the merge, and rethrows", async () => {
    const files = new Map([[legacyContainmentFlag, legacyFlagBody]])

    const run = await applyTarListing(linesWithSymlinks, {
      files,
      hostLinks: new Map(),
      throwOn: { command: stagedTarExtractCommand, error: new Error("channel closed") },
    })

    expect(run.thrown).toStrictEqual(new Error("channel closed"))
    expect(mergeIndex(run)).toBe(-1)
    expect(containmentState(files)).toStrictEqual({
      legacy: legacyFlagBody,
      [ownEntryName()]: recordedFlag(),
    })
  })

  it.each([
    {
      linesFor: (index: string): string[] => [
        tarDirectoryLine(`d${index}/`),
        tarFileLine(`d${index}/f`),
      ],
      name: "without symlinks",
    },
    {
      linesFor: (index: string): string[] => [
        tarDirectoryLine(`d${index}/`),
        tarFileLine(`d${index}/f`),
        tarSymlinkLine(`d${index}/l`, "f"),
      ],
      name: "with symlinks",
    },
  ])(
    "keeps the exec count constant in the member count for an archive $name after an unknown flag",
    async ({ linesFor }) => {
      const runWith = async (
        memberCount: number
      ): Promise<{
        calls: number
        crossChecks: number
        postMergeListings: number
        status: ModuleResult["status"]
        writes: number
      }> => {
        const lines = Array.from({ length: memberCount }, (_value, index) =>
          linesFor(String(index))
        ).flat()
        const { run } = await applyOnHost(lines, {
          files: [[legacyContainmentFlag, legacyFlagBody]],
          links: [insideHostLink],
        })
        const { calls } = run.mockSsh
        return {
          calls: calls.length,
          crossChecks: calls.filter((command) => command === kernelCrossCheckCommand).length,
          postMergeListings: run.postMergeListings.length,
          status: run.result.status,
          writes: run.writes.length,
        }
      }

      const few = await runWith(3)
      const many = await runWith(300)

      expect(few).toMatchObject({ crossChecks: 1, postMergeListings: 1, status: "changed" })
      expect(many).toStrictEqual(few)
    }
  )

  it.each([
    {
      crossChecked: [],
      extra: [symlinkListingProbeCommand],
      hostLinks: [],
      lines: linesWithoutSymlinks,
      name: "an archive without symlinks on a clean destination",
    },
    {
      crossChecked: [insideHostLink[0]],
      extra: [symlinkListingProbeCommand, kernelCrossCheckCommand],
      hostLinks: [insideHostLink],
      lines: linesWithoutSymlinks,
      name: "an archive without symlinks next to a host link inside",
    },
    {
      crossChecked: [`${destination}/b/s`],
      extra: [],
      hostLinks: [],
      lines: linesWithSymlinks,
      name: "an archive with symlinks on a clean destination",
    },
    {
      crossChecked: [`${destination}/b/s`, insideHostLink[0]],
      extra: [],
      hostLinks: [insideHostLink],
      lines: linesWithSymlinks,
      name: "an archive with symlinks next to a host link inside",
    },
  ])(
    "costs an unknown flag only the destination-wide listing and cross-check over an absent flag for $name",
    async ({ crossChecked, extra, hostLinks, lines }) => {
      const absent = await applyOnHost(lines, { files: [], links: hostLinks })
      const unknown = await applyOnHost(lines, {
        files: [[legacyContainmentFlag, legacyFlagBody]],
        links: hostLinks,
      })

      expect(absent.run.result.status).toBe("changed")
      expect(unknown.run.result.status).toBe("changed")
      expect(hasContainmentState(unknown.files)).toBe(false)
      // Issue #219: at most the whole-destination listing plus one kernel
      // cross-check more; with an archive symlink both already run.
      // Issue #219: the establish and clear execs differ only in their
      // arguments; each runs once.
      expect(
        extraCommands(
          commandsWithoutContainmentArguments(unknown.run),
          commandsWithoutContainmentArguments(absent.run)
        )
      ).toStrictEqual(extra)
      expect(unknown.run.mockSsh.calls.length - absent.run.mockSsh.calls.length).toBe(extra.length)
      expect(unknown.run.writes.map(({ remotePath }) => remotePath)).toStrictEqual(
        absent.run.writes.map(({ remotePath }) => remotePath)
      )
      // Issue #219: every link the resolver judges inside is confirmed by the
      // kernel, not only the archive's own.
      expect(crossCheckedLinksOf(unknown.run)).toStrictEqual(crossChecked)
    }
  )
})

/**
 * Issue #219: the own containment entry of a concurrent apply A.
 */
const concurrentEntry = earlierEntry

/**
 * Issue #219: simulate a concurrent apply A to the same destination failing
 * and recording its offending link in the containment state. This is the only
 * place that knows how that state is stored (one entry per apply in the
 * destination's entry directory; A rewrites only its own entry), so a changed
 * storage layout only needs this helper adapted.
 *
 * @param files - The host marker and containment files.
 * @param links - The destination-relative link keys A records.
 */
function recordConcurrentContainmentFailure(files: Map<string, string>, ...links: string[]): void {
  files.set(concurrentEntry, recordedFlag(...links))
}

/**
 * Issue #219: a `failWriteWhen` hook that never fails a write but runs a side
 * effect once, when the given path is first written, e.g. to simulate a
 * concurrent apply at that point of the run.
 *
 * @param path - The written path that triggers the side effect.
 * @param sideEffect - What happens on the host at that point.
 * @returns The hook and whether it fired.
 */
function onFirstWriteOf(
  path: string,
  sideEffect: () => void
): { fired: () => boolean; hook: (remotePath: string) => boolean } {
  let fired = false
  return {
    fired: () => fired,
    hook(remotePath) {
      if (remotePath === path && !fired) {
        fired = true
        sideEffect()
      }
      return false
    },
  }
}

describe("archive.extract concurrent applies to one destination (Issue #219)", () => {
  // Issue #219: A and B extract different sources into the same destination.
  // A created its `in-progress` entry first; B read it, created its own and,
  // after its clean post-merge listing, finishes successfully. In between, A
  // failed and recorded its escaping link `x/esc` in its own entry.
  const concurrentLinkKey = "x/esc"
  const concurrentLink = `${destination}/${concurrentLinkKey}`
  const benignLines = [tarDirectoryLine("b/"), tarFileLine("b/g")]

  it("keeps the failure a concurrent apply recorded after the post-merge listing when this apply succeeds", async () => {
    const files = new Map([[concurrentEntry, inProgress()]])
    const hostLinks: HostLinkTree = new Map()
    const bMarker = markerFor(otherSrc)
    // Issue #219: B's content marker is written after its post-merge listing
    // and before it removes the flag, which is where A's failure lands.
    const concurrentFailure = onFirstWriteOf(bMarker, () => {
      hostLinks.set(concurrentLink, "../..")
      recordConcurrentContainmentFailure(files, concurrentLinkKey)
    })

    const run = await applyTarListing(benignLines, {
      failWriteWhen: concurrentFailure.hook,
      files,
      hostLinks,
      source: otherSrc,
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.error).toBeUndefined()
    expect(run.result.status).toBe("changed")
    expect(run.postMergeListings).toHaveLength(1)
    expect(concurrentFailure.fired()).toBe(true)
    expect(files.has(bMarker)).toBe(true)
    // Issue #219: A's escaping link still sits in the destination, so `check`
    // must not report B's marker as converged.
    expect(hostLinks.get(concurrentLink)).toBe("../..")
    const check = await checkAgainstHostFiles(otherSrc, files)
    expect(check.result).toBe("needs-apply")
    // Issue #219: B read A's `in-progress` entry and tried to remove it, but
    // A's record had replaced it since, so B left it (under B's claim name,
    // still an entry) and removed only its own.
    expect(Object.values(containmentState(files))).toStrictEqual([recordedFlag(concurrentLinkKey)])
  })

  /** Issue #219: the claim name B (run 1) leaves A's rewritten entry under. */
  const claimedConcurrentEntry = `${ownEntryName(1)}-claim-0`

  /**
   * Issue #219: B (run 1) succeeds while A fails and records `x/esc` after
   * B's post-merge listing, as in the reproduction above.
   *
   * @param initial - The body of A's entry when B reads it.
   * @returns The host files and links after B.
   */
  async function succeedWhileConcurrentApplyFails(
    initial: string
  ): Promise<{ files: Map<string, string>; hostLinks: HostLinkTree }> {
    const files = new Map([[concurrentEntry, initial]])
    const hostLinks: HostLinkTree = new Map()
    const concurrentFailure = onFirstWriteOf(markerFor(otherSrc), () => {
      hostLinks.set(concurrentLink, "../..")
      recordConcurrentContainmentFailure(files, concurrentLinkKey)
    })
    const run = await applyTarListing(benignLines, {
      failWriteWhen: concurrentFailure.hook,
      files,
      hostLinks,
      source: otherSrc,
    })
    expect(run.result.status).toBe("changed")
    expect(concurrentFailure.fired()).toBe(true)
    return { files, hostLinks }
  }

  it("keeps an entry rewritten after it was read under its claim name, even when it asked for no destination-wide verification", async () => {
    // Issue #219: A's entry records `failed` without links when B reads it,
    // so B verifies no link for it and runs no destination-wide listing. The
    // hash B read still keeps B from removing A's newer record.
    const { files, hostLinks } = await succeedWhileConcurrentApplyFails(recordedFlag())

    expect(containmentState(files)).toStrictEqual({
      [claimedConcurrentEntry]: recordedFlag(concurrentLinkKey),
    })
    expect(hostLinks.get(concurrentLink)).toBe("../..")
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it("fails a later apply of another source that names the concurrent apply's link as recorded while it still escapes", async () => {
    const { files, hostLinks } = await succeedWhileConcurrentApplyFails(inProgress())
    expect(containmentState(files)).toStrictEqual({
      [claimedConcurrentEntry]: recordedFlag(concurrentLinkKey),
    })

    // Issue #219: C writes only below `c`, far from `x/esc`; the claim entry
    // alone makes it judge the link.
    const run = await applyTarListing([tarDirectoryLine("c/"), tarFileLine("c/h")], {
      files,
      hostLinks,
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(
      `symlink ${JSON.stringify(concurrentLink)} -> "../..", recorded by an earlier failed apply, resolves outside destination`
    )
    expect(containmentClears(run.mockSsh.calls)).toStrictEqual([])
    expect(containmentState(files)).toStrictEqual({
      [claimedConcurrentEntry]: recordedFlag(concurrentLinkKey),
      [ownEntryName(2)]: recordedFlag(concurrentLinkKey),
    })
    expect(files.has(marker)).toBe(false)
    await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
      result: "needs-apply",
    })
  })

  it.each([
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.delete(concurrentLink)
      },
      name: "removed",
    },
    {
      fix(hostLinks: HostLinkTree): void {
        hostLinks.set(concurrentLink, "../b/g")
      },
      name: "pointed back inside the destination",
    },
  ])(
    "removes the concurrent apply's entry on the next successful apply of any source once its link was $name",
    async ({ fix }) => {
      const { files, hostLinks } = await succeedWhileConcurrentApplyFails(inProgress())
      fix(hostLinks)

      const run = await applyTarListing([tarDirectoryLine("c/"), tarFileLine("c/h")], {
        files,
        hostLinks,
      })

      expect(run.result.error).toBeUndefined()
      expect(run.result.status).toBe("changed")
      // Issue #219: the recorded link was re-verified by the one post-merge
      // listing an archive without symlinks runs only for recorded links.
      expect(run.postMergeListings).toHaveLength(1)
      const [clear] = containmentClears(run.mockSsh.calls)
      expect(scriptArguments(clear, containmentClearPrefix)).toStrictEqual([
        ownEntry(2),
        `${containment.entryDirectory}/${claimedConcurrentEntry}`,
        sha256Of(recordedFlag(concurrentLinkKey)),
      ])
      expect(hasContainmentState(files)).toBe(false)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })
      await expect(checkAgainstHostFiles(otherSrc, files)).resolves.toMatchObject({
        result: "ok",
      })
    }
  )
})

describe("archive.extract bounded staging merge (Issue #219)", () => {
  it("keeps the remote bound strictly below the client timeout", () => {
    const { clientTimeoutMs, killAfterSeconds, timeoutSeconds } = STAGING_MERGE_TIME_LIMITS

    expect(STAGING_MERGE_TIME_LIMITS).toStrictEqual({
      clientTimeoutMs: 120_000,
      killAfterSeconds: 10,
      timeoutSeconds: 100,
    })
    expect((timeoutSeconds + killAfterSeconds) * 1000).toBeLessThan(clientTimeoutMs)
  })

  it("wraps the merge command in command -p timeout and passes its exit status through", () => {
    expect(boundedStagingMergeCommand("find '/s' -exec sh -c 'x' sh {} +")).toBe(
      "command -p timeout -k 10 100 find '/s' -exec sh -c 'x' sh {} +; exit $?"
    )
    expect(
      boundedStagingMergeCommand("find /s", {
        clientTimeoutMs: 5000,
        killAfterSeconds: 1,
        timeoutSeconds: 2,
      })
    ).toBe("command -p timeout -k 1 2 find /s; exit $?")
  })

  it("builds the merge exec with the guard paths deduplicated and NUL-terminated on stdin", () => {
    const merge = buildStagingMergeExec({
      destination: "/opt/app",
      guardPaths: ["/opt", "/opt/app", "/opt", "/opt/app/it's"],
      staging: "/opt/app/.paratix-stage.AbCdEfGh",
    })

    expect(merge.input).toBe("/opt\0/opt/app\0/opt/app/it's\0")
    expect(merge.command).toMatch(
      /^sh -c '.*mktemp.*' sh '\/opt\/app\/\.paratix-stage\.AbCdEfGh' /sv
    )
    expect(merge.command).toContain(` sh '/opt/app/.paratix-stage.AbCdEfGh' `)
    expect(merge.command.endsWith(` ${shellQuote(buildStagingMergeScript())} '/opt/app' 3`)).toBe(
      true
    )
    expect(merge.command).not.toContain("it'\\''s")
  })

  it("builds the merge exec for an empty guard list", () => {
    const merge = buildStagingMergeExec({
      destination: "/opt/app",
      guardPaths: [],
      staging: "/opt/app/.paratix-stage.AbCdEfGh",
    })

    expect(merge.input).toBe("")
    expect(merge.command.endsWith(" '/opt/app' 0")).toBe(true)
  })

  it("issues the merge bounded on the host and with the client timeout", async () => {
    const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/f")])

    expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    const merges = run.mockSsh.execCalls.filter(({ command }) =>
      archiveStageMovePattern.test(command)
    )
    expect(merges).toHaveLength(1)
    const [merge] = merges
    expect(merge.command.startsWith("command -p timeout -k 10 100 sh -c '")).toBe(true)
    expect(merge.command.endsWith(" '/opt/app' 4; exit $?")).toBe(true)
    // Issue #219: the guard paths travel NUL-terminated on stdin.
    expect(merge.options).toStrictEqual({
      ignoreExitCode: true,
      input: encodeNulPayload(["/opt", "/opt/app", "/opt/app/a", "/opt/app/a/f"]),
      silent: true,
      timeout: 120_000,
    })
  })

  it("keeps the merge command small and moves a guard list above 128 KiB to stdin", async () => {
    // Issue #219: Linux caps one argument at 128 KiB (MAX_ARG_STRLEN). The
    // guard paths used to travel as one newline-separated argument of the
    // merge, so a Node.js tarball with about 6,000 members (about 750 KB of
    // guard paths) failed the merge with E2BIG after validation had passed.
    const lines = Array.from({ length: 6000 }, (_, index) =>
      tarFileLine(
        `node-v24.21.0-linux-x64/lib/node_modules/npm/node_modules/package-${String(index)}/lib/index.js`
      )
    )
    const run = await applyTarListing(lines)

    expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    const merges = run.mockSsh.execCalls.filter(({ command }) =>
      archiveStageMovePattern.test(command)
    )
    expect(merges).toHaveLength(1)
    const [merge] = merges
    const guardPaths = stagingMergeGuardPaths(run.mockSsh)
    expect(guardPaths).toHaveLength(18_007)
    expect(guardPaths).toContain(
      `${destination}/node-v24.21.0-linux-x64/lib/node_modules/npm/node_modules/package-5999/lib/index.js`
    )
    // The old transport would have exceeded the per-argument limit ...
    expect(Buffer.byteLength(guardPaths.join("\n"))).toBeGreaterThan(128 * 1024)
    // ... while the command, and with it every argument the SSH layer and the
    // remote shells build from it, stays a few KiB and names no guard path.
    expect(Buffer.byteLength(merge.command)).toBeLessThan(16 * 1024)
    expect(merge.command).not.toContain("package-0")
    expect(merge.command.endsWith(` '${destination}' 18007; exit $?`)).toBe(true)
    expect(merge.options?.input).toBe(encodeNulPayload(guardPaths))
  })

  const stopped = `: the merge was stopped on the host after 100 seconds`

  it.each([
    { code: 124, reason: stopped },
    { code: 137, reason: stopped },
    { code: 127, reason: "" },
  ])(
    "reports exit $code of the merge with the right reason and still runs the backstop",
    async ({ code, reason }) => {
      // Issue #219: the archive ships a symlink, and the escaping link walks
      // through `a`, which the archive writes, so the backstop judges it.
      const escapingLink = `${destination}/x/esc`
      const hostLinks: HostLinkTree = new Map()

      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarFileLine("a/f"), tarSymlinkLine("a/l", "f")],
        {
          hostLinks,
          injectedOnMerge: [[escapingLink, "../a/../.."]],
          responseStubs: [
            { command: archiveStageMovePattern, result: { code, stderr: "Terminated" } },
          ],
        }
      )

      expect(run.result.error?.message).toBe(
        `[archive.extract] failed to copy extracted files into ${destination}${reason} (exit code ${String(code)})\nTerminated; [archive.extract] refusing to complete extraction of ${src}: symlink ${JSON.stringify(escapingLink)} -> "../a/../.." resolves outside destination ${JSON.stringify(destination)}; after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship; nothing was removed or changed; while the offending symlinks remain, remove them or point them inside the destination manually; this apply's containment entry records them and keeps check at needs-apply, and a later apply of any source verifies them again (every symlink under the destination when the entry could not record them) and, only when they pass, removes the entries it read that are still unchanged`
      )
      expect(run.postMergeListings).toHaveLength(1)
      expect(callsFromBackstop(run)).toStrictEqual([symlinkListingProbeCommand])
      expect([...hostLinks]).toStrictEqual([[escapingLink, "../a/../.."]])
    }
  )
})

describe("archive.extract pre-staging type conflicts (Issue #219)", () => {
  it.each([
    {
      lines: [tarDirectoryLine("a/"), tarSymlinkLine("a/b", "q")],
      reason: `archive member "a/b" is a symlink but destination path "${destination}/a/b" is an existing directory`,
      reported: `n\u0000${destination}/a/b\u0000`,
    },
    {
      lines: [tarDirectoryLine("a/"), tarFileLine("a/b")],
      reason: `archive member "a/b" is a regular file but destination path "${destination}/a/b" is an existing directory`,
      reported: `n\u0000${destination}/a/b\u0000`,
    },
    {
      lines: [tarDirectoryLine("a/"), tarFileLine("a/f"), tarHardlinkLine("a/b", "a/f")],
      reason: `archive member "a/b" is a hardlink but destination path "${destination}/a/b" is an existing directory`,
      reported: `n\u0000${destination}/a/b\u0000`,
    },
    {
      lines: [tarDirectoryLine("a/"), tarDirectoryLine("a/b/"), tarFileLine("a/b/f")],
      reason: `archive member "a/b/" is a directory but destination path "${destination}/a/b" exists and is not a directory`,
      reported: `d\u0000${destination}/a/b\u0000`,
    },
    {
      lines: [tarFileLine("x/y/f")],
      reason: `archive member "x/y/f" needs destination path "${destination}/x" as a directory, but it exists and is not a directory`,
      reported: `d\u0000${destination}/x\u0000`,
    },
    {
      lines: [tarFileLine("f")],
      reason: `destination path probe failed: unexpected record "n" for "${destination}/g"`,
      reported: `n\u0000${destination}/g\u0000`,
    },
    {
      lines: [tarFileLine("f")],
      reason:
        "destination path probe failed: probe returned 1 fields, expected (check, path) pairs",
      reported: `n\u0000`,
    },
  ])("refuses before anything is staged: $reason", async ({ lines, reason, reported }) => {
    const run = await applyTarListing(lines, {
      responses: { [preStagingProbeCommand]: { code: 0, stdout: reported } },
    })

    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: ${reason}`
    )
    // Issue #219: the pre-staging probe runs after the containment flag was
    // written, so the refusal leaves the flag set.
    expectContainmentFlagKept(run)
    const { calls } = run.mockSsh
    expect(calls).not.toContain(symlinkListingProbeCommand)
    expect(calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("sends the n and d checks for every member in the one pre-staging exec", async () => {
    const run = await applyTarListing([
      tarDirectoryLine("a/"),
      tarSymlinkLine("a/b", "q"),
      tarFileLine("x/y/f"),
    ])

    expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    const probes = run.mockSsh.execCalls.filter(({ command }) => command === preStagingProbeCommand)
    expect(probes).toHaveLength(1)
    const entries = pathsFromNulPayload(probes[0]?.options?.input)
    expect(entries).toStrictEqual(
      expect.arrayContaining([
        `d:${destination}/a`,
        `n:${destination}/a/b`,
        `n:${destination}/x/y/f`,
        `d:${destination}/x/y`,
        `d:${destination}/x`,
      ])
    )
    expect(entries).not.toContain(`d:${destination}`)
  })
})

/**
 * Issue #219: the name of the n-th entry an earlier apply left; the names sort
 * in index order and never collide with an own entry of a test.
 *
 * @param index - The entry's position, from 0.
 * @returns `run-e` and the zero-padded index, 36 characters in all.
 */
function entryNameAt(index: number): string {
  return `run-e${String(index).padStart(31, "0")}`
}

describe("archive.extract round trips (Issue #219)", () => {
  it("keeps the total exec count of an apply constant as the member count grows", async () => {
    const runWith = async (
      memberCount: number
    ): Promise<{ calls: number; crossChecks: number; writes: number }> => {
      const lines = Array.from({ length: memberCount }, (_value, index) => [
        tarDirectoryLine(`d${String(index)}/`),
        tarFileLine(`d${String(index)}/f`),
        tarSymlinkLine(`d${String(index)}/l`, "f"),
      ]).flat()
      // Issue #219: with a host model the merge publishes the shipped links,
      // so the backstop lists them and runs its kernel cross-check.
      const run = await applyTarListing(lines, {
        hostLinks: new Map(),
        owner: "www-data:www-data",
      })
      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      const crossChecks = run.mockSsh.calls.filter((command) => command === kernelCrossCheckCommand)
      return {
        calls: run.mockSsh.calls.length,
        crossChecks: crossChecks.length,
        writes: run.writes.length,
      }
    }

    const few = await runWith(3)
    const many = await runWith(300)

    expect(many).toStrictEqual(few)
    // Issue #219: the backstop costs two execs on a converged tree with links:
    // one listing and one kernel cross-check, whatever the link count.
    expect(many.crossChecks).toBe(1)
  })

  it("keeps one establish and one clear exec as the entry count grows, and verifies the whole destination past the read limit", async () => {
    const lines = [tarDirectoryLine("b/"), tarFileLine("b/g")]
    const runWith = async (
      entryCount: number
    ): Promise<{
      calls: number
      clearedEntries: string[]
      clears: number
      establishes: number
      files: Map<string, string>
      postMergeListings: number
      status: ModuleResult["status"]
    }> => {
      // Issue #219: entries of earlier failed applies without links, so only
      // their number can make the apply verify the whole destination.
      const files = new Map(
        Array.from(
          { length: entryCount },
          (_value, index) =>
            [`${containment.entryDirectory}/${entryNameAt(index)}`, recordedFlag()] as const
        )
      )
      const run = await applyTarListing(lines, { files, hostLinks: new Map() })
      const { calls } = run.mockSsh
      const clears = containmentClears(calls)
      const [, ...pairs] = scriptArguments(clears[0], containmentClearPrefix)
      return {
        calls: calls.length,
        clearedEntries: pairs
          .filter((_value, index) => index % 2 === 0)
          .map((path) => posix.basename(path)),
        clears: clears.length,
        establishes: calls.filter((command) => command.startsWith(containmentEstablishPrefix))
          .length,
        files,
        postMergeListings: run.postMergeListings.length,
        status: run.result.status,
      }
    }
    const overLimit = CONTAINMENT_ENTRY_READ_LIMIT + 4

    const one = await runWith(1)
    const ten = await runWith(10)
    const many = await runWith(overLimit)

    for (const run of [one, ten, many]) {
      expect(run).toMatchObject({ clears: 1, establishes: 1, status: "changed" })
    }
    expect(one.postMergeListings).toBe(0)
    expect(ten.calls).toBe(one.calls)
    expect(ten.postMergeListings).toBe(0)
    expect(ten.clearedEntries).toStrictEqual(Array.from({ length: 10 }, (_v, i) => entryNameAt(i)))
    // Issue #219: past the read limit the establish exec reports `more`,
    // which costs exactly the destination-wide listing; the clear removes
    // only the entries it read, so the rest keeps `check` at needs-apply.
    expect(many.postMergeListings).toBe(1)
    expect(many.calls).toBe(one.calls + 1)
    expect(many.clearedEntries).toStrictEqual(
      Array.from({ length: CONTAINMENT_ENTRY_READ_LIMIT }, (_v, i) => entryNameAt(i))
    )
    const unread = Array.from({ length: 4 }, (_v, i) =>
      entryNameAt(CONTAINMENT_ENTRY_READ_LIMIT + i)
    )
    expect(Object.keys(containmentState(many.files))).toStrictEqual(unread)
    await expect(checkAgainstHostFiles(src, many.files)).resolves.toMatchObject({
      result: "needs-apply",
    })

    // Issue #219: the next apply reads the rest and converges.
    const next = await applyTarListing(lines, {
      files: many.files,
      hostLinks: new Map(),
      source: otherSrc,
    })
    expect(next.result.status).toBe("changed")
    expect(hasContainmentState(many.files)).toBe(false)
    await expect(checkAgainstHostFiles(src, many.files)).resolves.toMatchObject({ result: "ok" })
  })
})
