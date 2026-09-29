import { createHash } from "node:crypto"
import { posix } from "node:path"
import { describe, expect, it, vi } from "vitest"

import type { ExecResult, ModuleResult } from "../../src/types.js"

import { archive } from "../../src/modules/archive.js"
import { validateSymlinkContainment } from "../../src/modules/archiveContainmentEnforcement.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  listArchiveMembers,
} from "../../src/modules/archiveMemberValidation.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  buildPreStagingProbeScript,
  buildSymlinkContainmentProbeScript,
  buildSymlinkListingProbeScript,
  buildSymlinkProbeScript,
  buildSymlinkRemovalScript,
} from "../../src/modules/archiveProbe.js"
import { CAPTURE_TRUNCATION_MARKER, DEFAULT_MAX_OUTPUT_BYTES } from "../../src/sshHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

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
const symlinkContainmentProbeCommand = buildSymlinkContainmentProbeScript()
const symlinkListingProbeCommand = buildSymlinkListingProbeScript()
/** Issue #219: the pre-staging probe: symlink guards plus member type checks. */
const preStagingProbeCommand = buildPreStagingProbeScript()
/** Issue #219: the post-merge removal of escaping symlinks for the destination. */
const symlinkRemovalCommand = buildSymlinkRemovalScript(destination)

/**
 * Issue #219: the destination-keyed flag that records a symlink containment
 * failure, derived independently of the module so a changed key is caught.
 *
 * @param path - The extraction destination.
 * @returns The absolute flag path.
 */
function containmentFlagPath(path: string): string {
  const hash = createHash("sha256").update(path).digest("hex")
  return `/var/lib/paratix/flags/archive-containment-${hash}.failed`
}

const containmentFlag = containmentFlagPath(destination)

/**
 * Issue #219: `check` tests the marker and the absence of the containment
 * flag in one `test` call.
 *
 * @param markerFile - The marker path.
 * @param path - The extraction destination the flag is keyed by.
 * @returns The combined test command.
 */
function markerCheckCommand(markerFile: string, path = destination): string {
  const flag = containmentFlagPath(path)
  return `test -f '${markerFile}' && test ! -e '${flag}' && test ! -L '${flag}'`
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
const archiveStageMovePattern =
  /^find '\/opt\/app\/\.paratix-stage\.[^']+' -mindepth 1 -maxdepth 1 -exec sh -c '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' sh '\/opt\/app' '\/opt\/app' '[^']*' \{\} \+$/sv
const archiveStageCleanupPattern = /^rm -rf -- '\/opt\/app\/\.paratix-stage\.[^']+'$/v
const archiveAlternateStageMktempPattern = /^mktemp -d '\/opt\/app-alt\/\.paratix-stage\.X{8}'$/v
const archiveAlternateStageMovePattern =
  /^find '\/opt\/app-alt\/\.paratix-stage\.[^']+' -mindepth 1 -maxdepth 1 -exec sh -c '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' sh '\/opt\/app-alt' '\/opt\/app-alt' '[^']*' \{\} \+$/sv
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

function expectArchiveCaptureExecCall(mockSsh: MockSsh, command: string, pinCLocale = false): void {
  expect(mockSsh.execCalls).toContainEqual({
    command,
    options: {
      ...(pinCLocale ? { env: { LC_ALL: "C" } } : {}),
      ignoreExitCode: true,
      maxOutputBytes: archiveListingMaxOutputBytes,
      silent: true,
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
  // Issue #219: the removal of escaping symlinks after a backstop violation.
  { command: symlinkRemovalCommand, result: { code: 0, stdout: "" } },
  // Issue #219: the post-merge containment check; a converged tree reports nothing.
  { command: symlinkContainmentProbeCommand, result: { code: 0, stdout: "" } },
  // Issue #219: the pre-merge listing of host symlinks; by default the host has none.
  { command: symlinkListingProbeCommand, result: { code: 0, stdout: "" } },
  // Issue #219: a successful apply clears the containment-failure flag.
  ...[destination, alternateDestination].map((path) => ({
    command: `rm -f -- '${containmentFlagPath(path)}'`,
    result: { code: 0 },
  })),
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
 * Issue #219: every apply that reaches the staging step writes the
 * destination's containment flag first, so the shared mock accepts that write.
 */
const containmentFlagWritePattern =
  /^\/var\/lib\/paratix\/flags\/archive-containment-[a-f0-9]{64}\.failed$/v

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
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
  // Issue #219: the containment flag is written before the merge; it is not a
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
const archiveStageMergeGuardPathsPattern =
  / sh '\/opt\/app' '\/opt\/app' '(?<guards>[^']*)' \{\} \+$/v

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

type SymlinkProbeRecord = { callIndex: number; entries: string[] }

/**
 * Issue #219: the symlinks a host keeps below the destination across runs,
 * keyed by absolute link path. Each run's successful staging merge adds (or
 * replaces) the links it ships, and both the pre-merge listing probe and the
 * post-merge containment probe are answered from the whole map, so a test can
 * span several runs on one host.
 */
type HostLinkTree = Map<string, string>

type HostLinkRun = {
  /**
   * Issue #219: the marker and flag files on the host, keyed by path. Writes
   * add them and a successful `rm -f -- <flag file>` removes one, so `check`
   * can be answered from what earlier runs left behind.
   */
  files?: Map<string, string>
  /**
   * Issue #219: links the host gains while the merge runs, e.g. from a
   * concurrent change after the pre-merge listing. They land even when the
   * merge exec fails or throws, like entries a half-done merge already copied.
   */
  injectedOnMerge?: ReadonlyArray<readonly [string, string]>
  shipped: ReadonlyArray<readonly [string, string]>
  tree: HostLinkTree
}

const flagFileRemovalPattern = /^rm -f -- '(?<path>\/var\/lib\/paratix\/flags\/[^']+)'$/v

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

function pathComponents(path: string): string[] {
  return path.split("/").filter((component) => component !== "")
}

/**
 * Resolve a host path the way `realpath -m` does: follow every symlink of the
 * tree component by component and treat a missing component as a directory.
 *
 * @param tree - The host symlinks.
 * @param path - The absolute path to resolve.
 * @returns The resolved absolute path.
 */
function resolveOnHost(tree: ReadonlyMap<string, string>, path: string): string {
  let resolved: string[] = []
  const pending = pathComponents(path)
  let hops = 0
  while (pending.length > 0) {
    const component = pending.shift() ?? "."
    const target = tree.get(`/${[...resolved, component].join("/")}`)
    if (target === undefined) {
      resolved = appendPathComponent(resolved, component)
    } else {
      hops += 1
      if (hops > 40) throw new Error(`test host model: symlink loop resolving ${path}`)
      if (target.startsWith("/")) resolved = []
      pending.unshift(...pathComponents(target))
    }
  }
  return `/${resolved.join("/")}`
}

function appendPathComponent(resolved: string[], component: string): string[] {
  if (component === "..") return resolved.slice(0, -1)
  return component === "." ? resolved : [...resolved, component]
}

function isInsideDirectory(root: string, path: string): boolean {
  return path === root || path.startsWith(`${root}/`)
}

/**
 * Answer the containment probe from the host model: one `(link, resolved)`
 * pair for every link below a transported destination that resolves outside it.
 *
 * @param tree - The host symlinks.
 * @param input - The probe's NUL-terminated destinations.
 * @returns The NUL-framed probe output.
 */
function containmentProbeStdout(tree: ReadonlyMap<string, string>, input: string): string {
  return pathsFromNulPayload(input)
    .flatMap((root) =>
      [...tree.keys()]
        .filter((link) => link.startsWith(`${root}/`))
        .map((link) => [link, resolveOnHost(tree, link)] as const)
        .filter(([, resolved]) => !isInsideDirectory(root, resolved))
    )
    .flat()
    .map((field) => `${field}\u0000`)
    .join("")
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
 * Answer the pre-merge listing probe from the host model: one
 * `(link, raw target)` pair for every link below a transported `r` entry. The
 * model has no directories, so `n` entries never report.
 *
 * @param tree - The host symlinks.
 * @param input - The probe's NUL-terminated tagged entries.
 * @returns The NUL-framed probe output.
 */
function listingProbeStdout(tree: ReadonlyMap<string, string>, input: string): string {
  return taggedEntryPaths(input, "r")
    .flatMap((root) => [...tree].filter(([link]) => link.startsWith(`${root}/`)))
    .flat()
    .map((field) => `${field}\u0000`)
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
 * Issue #219: answer the removal of escaping symlinks from the host model:
 * every transported link that is a modelled symlink is removed.
 *
 * @param tree - The host symlinks, updated in place.
 * @param input - The removal's NUL-terminated links.
 * @returns The NUL-framed `(link, outcome)` pairs.
 */
function removalStdout(tree: Map<string, string>, input: string | undefined): string {
  return pathsFromNulPayload(input)
    .flatMap((link) => [link, tree.delete(link) ? "removed" : "no longer a symlink"])
    .map((field) => `${field}\u0000`)
    .join("")
}

/**
 * Issue #219: an exec that rejects instead of returning a result, e.g. a
 * dropped connection.
 */
type ThrowingExec = { command: RegExp | string; error: Error }

/**
 * Issue #219: reject the exec when it is the one the harness should fail,
 * after recording it. The links the host gains during the merge still land
 * when the merge throws, as after a connection that dropped half-way through
 * the copy.
 *
 * @param mockSsh - The mock connection whose calls are recorded.
 * @param command - The command being executed.
 * @param harness - The optional host link model and the exec to reject.
 * @param harness.host - Host link model whose injected links the merge places.
 * @param harness.throwOn - The exec to reject; nothing is rejected when unset.
 */
function rejectMatchingExec(
  mockSsh: MockSsh,
  command: string,
  harness: { host?: HostLinkRun; throwOn?: ThrowingExec }
): void {
  const { host, throwOn } = harness
  if (throwOn === undefined) return
  const { command: expected, error } = throwOn
  const matches = typeof expected === "string" ? expected === command : expected.test(command)
  if (!matches) return
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

function applyHostSideEffects(host: HostLinkRun, command: string): void {
  if (archiveStageMovePattern.test(command)) {
    const merged = [...host.shipped, ...(host.injectedOnMerge ?? [])]
    for (const [link, target] of merged) host.tree.set(link, target)
  }
  const removedFile = flagFileRemovalPattern.exec(command)?.groups?.path
  if (removedFile !== undefined) host.files?.delete(removedFile)
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
  if (command === symlinkRemovalCommand && result.code === 0) {
    return { ...result, stdout: removalStdout(host.tree, input) }
  }
  if (command !== symlinkContainmentProbeCommand) return result
  return { ...result, stdout: containmentProbeStdout(host.tree, input ?? "") }
}

/**
 * Record the NUL-separated payload of every batched symlink probe and report
 * the given host paths as symlinks whenever a probe carries them.
 *
 * @param mockSsh - The mock connection to patch.
 * @param hostSymlinks - Absolute host paths the probe reports as symlinks.
 * @param harness - Optional host link model and exec to reject.
 * @param harness.host - Host link model that the merge updates and the containment probe reads.
 * @param harness.throwOn - Issue #219: an exec that rejects after being recorded.
 * @returns The recorded probes, in call order, with their position in `mockSsh.calls`.
 */
function recordSymlinkProbes(
  mockSsh: MockSsh,
  hostSymlinks: readonly string[] = [],
  harness: { host?: HostLinkRun; throwOn?: ThrowingExec } = {}
): SymlinkProbeRecord[] {
  const { host } = harness
  const originalExec = mockSsh.exec.bind(mockSsh)
  const probes: SymlinkProbeRecord[] = []
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    rejectMatchingExec(mockSsh, command, harness)
    const executed = await originalExec(command, options)
    const result =
      host === undefined
        ? executed
        : answerFromHostLinks(host, command, { input: options?.input, result: executed })
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

type TarListingApplyOptions = {
  /** `writeFile` rejects this path, e.g. to fail the containment-flag write. */
  failWrite?: string
  /** Host marker and flag files (see {@link HostLinkRun}); requires `hostLinks`. */
  files?: Map<string, string>
  hostLinks?: HostLinkTree
  hostSymlinks?: readonly string[]
  injectedOnMerge?: ReadonlyArray<readonly [string, string]>
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
      [`tar -tvzf '${source}'`]: { code: 0, stdout: `${lines.join("\n")}\n` },
      [stagedTarExtractCommandFor(source)]: { code: 0 },
      ...options.responses,
    },
    { responseStubs: options.responseStubs }
  )
  vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveShaFor(source))
  const writes: TarListingApplyRun["writes"] = []
  vi.spyOn(mockSsh, "writeFile").mockImplementation(async (remotePath, content) => {
    await Promise.resolve()
    writes.push({ callIndex: mockSsh.calls.length, remotePath })
    if (remotePath === failWrite) throw new Error("No space left on device")
    files?.set(remotePath, content)
  })
  // With a host link model, the pre-merge probes see the links earlier runs left.
  const hostSymlinks = options.hostSymlinks ?? [...(hostLinks?.keys() ?? [])]
  const host =
    hostLinks === undefined
      ? undefined
      : {
          files,
          injectedOnMerge: options.injectedOnMerge,
          shipped: shippedSymlinks(lines),
          tree: hostLinks,
        }
  const probes = recordSymlinkProbes(mockSsh, hostSymlinks, { host, throwOn: options.throwOn })
  const moduleOptions = options.owner === undefined ? {} : { owner: options.owner }
  let thrown: unknown
  const result = await archive
    .extract(source, destination, moduleOptions)
    .apply(mockSsh, emptyEnv)
    .catch((error: unknown): ModuleResult => {
      thrown = error
      return { status: "failed" }
    })
  return { markerWrites: () => writes.length, mockSsh, probes, result, thrown, writes }
}

/**
 * Issue #219: run `check` for a source against the marker and flag files an
 * earlier apply left in the host model. The combined marker test is answered
 * from the model, so a present containment-failure flag makes it fail.
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
  const markerTestPasses = files.has(sourceMarker) && !files.has(containmentFlag)
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
 * Collect the entries of every symlink probe issued after the archive listing
 * and before the staged `tar -x`, i.e. the pre-staging member probe.
 *
 * @param run - The recorded apply run.
 * @returns The probed host paths.
 */
function preStagingProbeEntries(run: TarListingApplyRun): string[] {
  const listingIndex = run.mockSsh.calls.indexOf(`tar -tvzf '${src}'`)
  const extractIndex = run.mockSsh.calls.indexOf(stagedTarExtractCommand)
  const endIndex = extractIndex === -1 ? Number.POSITIVE_INFINITY : extractIndex
  return run.probes
    .filter((probe) => probe.callIndex > listingIndex && probe.callIndex < endIndex)
    .flatMap((probe) => probe.entries)
}

function stagingMergeGuardPaths(mockSsh: MockSsh): string[] {
  const mergeCommand = mockSsh.calls.find((command) => archiveStageMovePattern.test(command))
  const guards = archiveStageMergeGuardPathsPattern.exec(mergeCommand ?? "")?.groups?.guards
  return guards === undefined ? [] : guards.split("\n")
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
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
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
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvf '${tarSrc}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvjf '${bz2Src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvJf '${xzSrc}'`]: { code: 0, stdout: safeTarListing },
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
  })

  it("extracts .tgz archive", async () => {
    const tgzSrc = "/tmp/app.tgz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${tgzSrc}'`]: { code: 0, stdout: safeTarListing },
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
      listingCommand: `tar -tvzf '${src}'`,
      memberLine: safeTarListing,
      source: src,
    },
    {
      extractCommand: `unzip -o '/tmp/app.zip' -d '${archiveStageDirectory}'`,
      format: "zip",
      listingCommand: "unzip -Zs '/tmp/app.zip'",
      memberLine: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file",
      source: "/tmp/app.zip",
    },
  ])("accepts a safe $format listing above the legacy capture limit", async (testCase) => {
    const listing = listingLargerThanLegacyCaptureLimit(testCase.memberLine)
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
    expectArchiveCaptureExecCall(mockSsh, testCase.listingCommand)
  })

  it("accepts a complete archive listing at the exact capture limit", async () => {
    const listing = singleMemberTarListingOfUtf8Size(archiveListingMaxOutputBytes)
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toMatchObject({ members: [{ format: "tar", kind: "file" }] })
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
  })

  it("treats the truncation marker as authoritative at the capture boundary", async () => {
    const listing = singleMemberTarListingOfUtf8Size(
      archiveListingMaxOutputBytes,
      CAPTURE_TRUNCATION_MARKER
    )
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toStrictEqual({
      failureReason: expect.stringMatching(/truncat/iv),
    })
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
  })

  it("reports an actionable failure when the archive listing is truncated", async () => {
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: {
        code: 0,
        stdout: `${safeTarListing}${CAPTURE_TRUNCATION_MARKER}`,
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
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
      memberCount: number
    ): Promise<{ containmentProbes: number; listingProbes: number; symlinkProbes: number }> => {
      const memberPaths = Array.from(
        { length: memberCount },
        (_value, index) => `app/file-${String(index)}`
      )
      const mockSsh = createMockSsh({
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
      })
      vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
      vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

      const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      const count = (probe: string): number =>
        mockSsh.calls.filter((command) => command === probe).length
      return {
        containmentProbes: count(symlinkContainmentProbeCommand),
        listingProbes: count(symlinkListingProbeCommand),
        symlinkProbes: count(symlinkProbeCommand),
      }
    }

    const few = await runWith(5)
    const many = await runWith(500)

    expect(many.symlinkProbes).toBe(few.symlinkProbes)
    expect(many.symlinkProbes).toBeLessThanOrEqual(4)
    // Issue #219: the post-merge containment check walks the whole tree in one
    // exec, so it adds exactly one round trip regardless of member count.
    expect(few.containmentProbes).toBe(1)
    expect(many.containmentProbes).toBe(1)
    // Issue #219: the pre-merge listing of host symlinks is one exec as well.
    expect(few.listingProbes).toBe(1)
    expect(many.listingProbes).toBe(1)
  })

  it("R-0000267: returns failed when chown of an extracted member fails", async () => {
    // chown errors (EPERM, ENOENT, quota) must surface as a maskable
    // failedCommand result instead of leaking past Promise.all in the
    // concurrency-limited mapper as an uncaught CommandError.
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: {
        code: 1,
        stderr: "chown: changing ownership of '/opt/app/app/file': Operation not permitted",
      },
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
    expect(vi.mocked(mockSsh.writeFile).mock.calls.map(([path]) => path)).toStrictEqual([
      containmentFlag,
    ])
  })

  it("rejects option-like owner specs before member chown", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
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
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
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
      [`tar -tvzf '${firstRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      [`tar -tvzf '${secondRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "ignored-by-spy" },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
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
        [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
        "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
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
    expect(mockSsh.calls).toContain(`tar -tvzf '${remoteTmp}'`)
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
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
    expect(mockSsh.writeFile).not.toHaveBeenCalled()
  })

  it("returns failed when writing the archive content marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the first write is the containment flag before the merge.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("disk full"))

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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the first write is the containment flag before the merge.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    // Issue #219: the first write is the containment flag before the merge.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member is an absolute path", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 /etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target points outside the destination", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target is an absolute path", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to /etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target traverses outside the destination", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
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
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction when an existing member ancestor is a symlink", async () => {
    const symlinkedMemberAncestor = `${destination}/app`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    stubSymlinkViolationFor(mockSsh, symlinkedMemberAncestor)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(JSON.stringify(symlinkedMemberAncestor))
    expect(String(result.error)).toContain("is a symlink")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeDefined()
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
        refusedBeforeExtraction(
          `link target of member "a/bin/x" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
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
        refusedBeforeExtraction(
          `link target of member "a/esc" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
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
      const firstContainment = firstCalls.indexOf(symlinkContainmentProbeCommand)
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
      // Issue #219: the containment flag is written before the merge; every
      // marker write comes after the containment backstop.
      const firstMarkerWrites = first.writes.filter(
        ({ remotePath }) => remotePath !== containmentFlag
      )
      for (const write of firstMarkerWrites) {
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
        // The only write is the containment-failure flag, not a marker.
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(preStagingProbeEntries(second)).not.toContain(escapingLink)
      const secondCalls = second.mockSsh.calls
      expect(secondCalls).toContain(symlinkListingProbeCommand)
      expect(secondCalls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
      expect(secondCalls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
      expect(secondCalls).not.toContain(symlinkContainmentProbeCommand)
      expect(secondCalls).not.toContain(batchedChownCommand)
      expect(second.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
      // Issue #219: the flag is established before the pre-merge listing.
      const flagDirectory = secondCalls.indexOf("mkdir -p '/var/lib/paratix/flags'")
      const secondListing = secondCalls.indexOf(symlinkListingProbeCommand)
      expect(flagDirectory).toBeLessThan(secondListing)
      expect(second.writes[0]?.callIndex).toBeGreaterThan(flagDirectory)
      expect(second.writes[0]?.callIndex).toBeLessThanOrEqual(secondListing)
      // Nothing of run 2 reached the destination.
      expect([...hostLinks]).toStrictEqual([[escapingLink, "up/.."]])
    })

    it("refuses the reverse order before the merge as well (a/up -> .., then a/esc -> up/..)", async () => {
      // Issue #219: run 1 ships `a/up -> ..`, contained on its own. Run 2 ships
      // `a/esc -> up/..`, whose target passes the non-member prefix `a/up`. The
      // pre-staging probe already reports that host symlink, so run 2 stops
      // before the listing probe and the merge. The host tree is untouched and
      // still contained, so no containment-failure flag is recorded and run 1's
      // marker keeps describing the destination.
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
        markerWritten: false,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(preStagingProbeEntries(second)).toContain(upLink)
      const secondCalls = second.mockSsh.calls
      expect(secondCalls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
      expect(secondCalls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
      expect(secondCalls).not.toContain(symlinkContainmentProbeCommand)
      expect(secondCalls).not.toContain(batchedChownCommand)
      expect([...hostLinks]).toStrictEqual([[upLink, ".."]])
      expect(files.has(containmentFlag)).toBe(false)
      await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })
    })

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
      // Issue #219: the flag is established before the merge and removed once
      // the apply has fully succeeded.
      expect(run.writes.map(({ remotePath }) => remotePath)).toContain(containmentFlag)
      expect(run.mockSsh.calls).toContain(`rm -f -- '${containmentFlag}'`)
      expect(Object.fromEntries(hostLinks)).toStrictEqual({
        [`${destination}/a/esc`]: "up/..",
        [`${destination}/a/up`]: "b",
      })
    })

    it("refuses a regular file member at the path of a host link before any merge", async () => {
      // Issue #219: a non-symlink member would remove the host link `a/up`
      // (`mergedArchiveSymlinks`), but the member path itself is a guard path,
      // so the pre-staging probe refuses the existing host symlink first. No
      // listing probe, no staging and no flag: nothing reached the host.
      const upLink = `${destination}/a/up`
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/a/esc`, "up/.."],
        [upLink, ".."],
      ])

      const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/up")], {
        hostLinks,
      })

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(`destination path ${JSON.stringify(upLink)} is a symlink`)
      )
      expect(preStagingProbeEntries(run)).toContain(upLink)
      expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
      expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(
        false
      )
      expect(run.writes).toStrictEqual([])
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

    it.each([
      { link: "etc", target: "/etc" },
      { link: "a/up", target: `${destination}/..` },
      { link: "a/deep-up", target: `${destination}/a/../..` },
      { link: "sibling", target: `${alternateDestination}/x` },
    ])(
      "refuses a host link whose absolute target $target leaves the destination before the merge",
      async ({ link, target }) => {
        const linkPath = `${destination}/${link}`
        const hostLinks: HostLinkTree = new Map([[linkPath, target]])

        const run = await applyTarListing([tarFileLine("f")], { hostLinks })

        expect(extractionSummary(run)).toStrictEqual({
          error: expect.stringContaining(
            `[archive.extract] refusing to extract ${src}: symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(target)} would resolve outside destination ${JSON.stringify(destination)} once this archive is merged`
          ),
          markerWritten: true,
          status: "failed",
          tarExtractCalls: [],
        })
        expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
        expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(
          false
        )
      }
    )

    it("refuses a host link cycle before the merge with the resolution-limit reason", async () => {
      const hostLinks: HostLinkTree = new Map([
        [`${destination}/loop-a`, "loop-b"],
        [`${destination}/loop-b`, "loop-a"],
      ])

      const run = await applyTarListing([tarFileLine("f")], { hostLinks })

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] refusing to extract ${src}: symlink "/opt/app/loop-a" -> "loop-b" would exceed the symlink resolution limit once this archive is merged; existing symlinks under the destination are checked together with the archive's links before anything is copied (and 1 more)`
        ),
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [],
      })
      expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
    })

    it.each([
      {
        detail: "find: '/opt/app/private': Permission denied",
        name: "a non-zero exit",
        response: { code: 1, stderr: "find: '/opt/app/private': Permission denied" },
      },
      {
        detail: `probe output exceeded the captured-output cap of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes; refusing to evaluate a truncated result`,
        name: "a truncated capture",
        response: {
          code: 0,
          stdout: `${destination}/a/up\u0000..\u0000${destination}/a/e${CAPTURE_TRUNCATION_MARKER}`,
        },
      },
      {
        detail: 'probe returned 3 fields, expected (link, target) or ("", directory) pairs',
        name: "an odd field count",
        response: { code: 0, stdout: `${destination}/a/up\u0000..\u0000${destination}/b\u0000` },
      },
      {
        detail: 'probe reported "/opt/other/l", which is not below the destination',
        name: "a link outside the destination",
        response: { code: 0, stdout: "/opt/other/l\u0000x\u0000" },
      },
      {
        detail: `probe reported "/opt/app-alt/l", which is not below the destination`,
        name: "a link in a sibling sharing the destination's prefix",
        response: { code: 0, stdout: `${alternateDestination}/l\u0000x\u0000` },
      },
      {
        detail: 'probe reported "/opt/app/", which is not below the destination',
        name: "the destination itself",
        response: { code: 0, stdout: `${destination}/\u0000x\u0000` },
      },
    ])(
      "fails closed before the merge on a listing probe with $name",
      async ({ detail, response }) => {
        const run = await applyTarListing([tarFileLine("f")], {
          responses: { [symlinkListingProbeCommand]: response },
        })

        expect(extractionSummary(run)).toStrictEqual({
          error: `Error: [archive.extract] refusing to extract ${src}: symlink listing before the merge failed: ${detail}`,
          markerWritten: true,
          status: "failed",
          tarExtractCalls: [],
        })
        expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
        expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(
          false
        )
        expect(run.mockSsh.execCalls).toContainEqual({
          command: symlinkListingProbeCommand,
          options: {
            ignoreExitCode: true,
            // Issue #219: the destination as `r` entry, the file member as `n` entry.
            input: `r:${destination}\u0000n:${destination}/f\u0000`,
            maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
            silent: true,
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
          `[archive.extract] refusing to complete extraction of ${src}: symlink ${JSON.stringify(escapingLink)} resolves to "/opt", outside destination ${JSON.stringify(destination)}`
        ),
        markerWritten: true,
        status: "failed",
        tarExtractCalls: [stagedTarExtractCommand],
      })
      const { calls } = run.mockSsh
      const listing = calls.indexOf(symlinkListingProbeCommand)
      const merge = calls.findIndex((command) => archiveStageMovePattern.test(command))
      const containment = calls.indexOf(symlinkContainmentProbeCommand)
      expect(listing).toBeGreaterThanOrEqual(0)
      expect(merge).toBeGreaterThan(listing)
      expect(containment).toBeGreaterThan(merge)
      expect(calls).not.toContain(batchedChownCommand)
      expect(calls).not.toContain(`rm -f -- '${containmentFlag}'`)
      expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
      // Issue #219: the flag is established before the pre-merge listing, and
      // the backstop removes the escaping link it found.
      expect(run.writes[0]?.callIndex).toBeLessThanOrEqual(listing)
      expect([...files.keys()]).toStrictEqual([containmentFlag])
      expect(calls.indexOf(symlinkRemovalCommand)).toBeGreaterThan(containment)
      expect([...hostLinks.keys()]).toStrictEqual([`${destination}/a/up`])
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a special file")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive with an unparsed listing line before invoking tar -x", async () => {
    const tarListing = `${safeTarListing}\nnot-a-member\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("could not parse tar listing line")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target contains a NUL byte", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> target\x00evil\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("link target contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member has the setgid bit set", async () => {
    const tarListing = "-rwxr-sr-x root/root 0 1970-01-01 00:00 app/sgid-bin\n"
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
    expect(vi.mocked(mockSsh.writeFile).mock.calls.map(([path]) => path)).toStrictEqual([
      containmentFlag,
    ])
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("rejects a destination that resolves elsewhere after guarded creation", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
      [batchedChownCommand]: { code: 0 },
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: driftedTarListing },
      [`test -d '${destination}'`]: { code: 0 },
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
    // The check must not consult the live archive listing when the marker is
    // available — that's the entire point of R-0000166.
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
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
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
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
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [`test -d '${destination}'`]: { code: 0 },
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
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
  const escapingHostLinks = (): HostLinkTree => new Map([[`${destination}/etc`, "/etc"]])
  const etcRefusal = `[archive.extract] refusing to extract ${src}: symlink "/opt/app/etc" -> "/etc" would resolve outside destination "/opt/app" once this archive is merged; existing symlinks under the destination are checked together with the archive's links before anything is copied`

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
    expect(applyB.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
    expect(files.get(markerA)).toBe(archiveSha)
    expect(files.has(markerB)).toBe(false)
    expect(files.has(containmentFlag)).toBe(true)

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
    const flagRemoval = reapplyA.mockSsh.calls.indexOf(`rm -f -- '${containmentFlag}'`)
    const markerWrites = reapplyA.writes.filter(({ remotePath }) => remotePath.startsWith(markerA))
    expect(markerWrites.map(({ remotePath }) => remotePath)).toStrictEqual([markerA, membersMarker])
    for (const write of markerWrites) expect(flagRemoval).toBeGreaterThanOrEqual(write.callIndex)
    expect(files.has(containmentFlag)).toBe(false)

    await expect(checkAgainstHostFiles(src, files)).resolves.toMatchObject({ result: "ok" })
  })

  it("leaves an existing flag in place when the apply is refused again", async () => {
    const files = new Map<string, string>([[containmentFlag, "stale"]])
    const hostLinks = escapingHostLinks()

    const run = await applyTarListing([tarFileLine("f")], { files, hostLinks })

    expect(run.result.status).toBe("failed")
    expect(run.mockSsh.calls).not.toContain(`rm -f -- '${containmentFlag}'`)
    expect(files.has(containmentFlag)).toBe(true)
  })

  it("writes the flag with the marker mode after creating the flags directory", async () => {
    const run = await applyTarListing([tarFileLine("f")], { hostLinks: escapingHostLinks() })

    expect(run.result.error?.message).toBe(etcRefusal)
    expect(run.mockSsh.writeFileCalls).toStrictEqual([])
    const writeSpy = vi.mocked(run.mockSsh.writeFile)
    expect(writeSpy.mock.calls).toStrictEqual([
      [containmentFlag, expect.any(String), { mode: "0644" }],
    ])
    // Issue #219: the flag is established before the pre-merge listing.
    const flagDirectory = run.mockSsh.calls.indexOf("mkdir -p '/var/lib/paratix/flags'")
    const listing = run.mockSsh.calls.indexOf(symlinkListingProbeCommand)
    expect(flagDirectory).toBeLessThan(listing)
    expect(run.writes[0]?.callIndex).toBeGreaterThan(flagDirectory)
    expect(run.writes[0]?.callIndex).toBeLessThanOrEqual(listing)
  })

  it("fails a fully extracted apply when the flag cannot be removed", async () => {
    const run = await applyTarListing([tarFileLine("f")], {
      responses: {
        [`rm -f -- '${containmentFlag}'`]: {
          code: 1,
          stderr: `rm: cannot remove '${containmentFlag}': Read-only file system`,
        },
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to remove containment-failure flag ${containmentFlag} (exit code 1)\nrm: cannot remove '${containmentFlag}': Read-only file system`
    )
    // The removal is the last step: every marker was already written. Issue
    // #219: the flag itself was written first, before the merge.
    const flagRemoval = run.mockSsh.calls.indexOf(`rm -f -- '${containmentFlag}'`)
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([
      containmentFlag,
      marker,
      membersMarker,
    ])
    for (const write of run.writes) expect(flagRemoval).toBeGreaterThanOrEqual(write.callIndex)
  })

  // Issue #219: the flag is established before the pre-merge listing, so a
  // flag that cannot be written stops the apply before anything is listed,
  // staged or copied.
  it("refuses before the listing and the merge when the flag write fails", async () => {
    const run = await applyTarListing([tarFileLine("f")], {
      failWrite: containmentFlag,
      hostLinks: escapingHostLinks(),
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: failed to write containment-failure flag ${containmentFlag}: No space left on device; the flag must be in place before anything is copied`
    )
    expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("refuses before the listing and the merge when the flags directory cannot be created", async () => {
    const run = await applyTarListing([tarFileLine("f")], {
      hostLinks: escapingHostLinks(),
      responses: {
        "mkdir -p '/var/lib/paratix/flags'": {
          code: 1,
          stderr: "mkdir: cannot create directory '/var/lib/paratix': Read-only file system",
        },
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] refusing to extract ${src}: failed to create archive marker directory for containment-failure flag ${containmentFlag}: mkdir: cannot create directory '/var/lib/paratix': Read-only file system; the flag must be in place before anything is copied`
    )
    expect(run.writes).toStrictEqual([])
    expect(run.mockSsh.calls).not.toContain(symlinkListingProbeCommand)
    expect(run.mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoTarExtractCalls(run.mockSsh)
  })

  it("never reaches the merge or the backstop when the flag write fails", async () => {
    const escapingLink = `${destination}/a/esc`
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")], {
      failWrite: containmentFlag,
      hostLinks,
      injectedOnMerge: [[escapingLink, "up/.."]],
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain("failed to write containment-failure flag")
    expect(run.mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expect(run.mockSsh.calls).not.toContain(symlinkContainmentProbeCommand)
    expect([...hostLinks]).toStrictEqual([])
  })
})

describe("validateSymlinkContainment (Issue #219)", () => {
  const refusal = `[archive.extract] refusing to complete extraction of ${src}: `
  const checkedAfterMerge =
    "every symlink under the destination is checked after the merge, including links this archive did not ship"

  async function validateWith(
    result: Partial<ExecResult>
  ): Promise<{ mockSsh: MockSsh; outcome: ModuleResult | null }> {
    const mockSsh = createMockSsh(
      {},
      { responseStubs: [{ command: symlinkContainmentProbeCommand, result }] }
    )
    const outcome = await validateSymlinkContainment(mockSsh, { destination, source: src })
    return { mockSsh, outcome }
  }

  it("probes the destination in one exec and accepts a tree that reports nothing", async () => {
    const { mockSsh, outcome } = await validateWith({ code: 0, stdout: "" })

    expect(outcome).toBeNull()
    expect(mockSsh.execCalls).toStrictEqual([
      {
        command: symlinkContainmentProbeCommand,
        options: { ignoreExitCode: true, input: `${destination}\u0000`, silent: true },
      },
    ])
  })

  it.each([
    {
      message: `symlink containment check failed: find: '/opt/app/x': Permission denied`,
      name: "a probe that exits non-zero",
      result: { code: 1, stderr: "find: '/opt/app/x': Permission denied\n" },
    },
    {
      message: `symlink containment check failed: probe output exceeded the captured-output cap of ${String(DEFAULT_MAX_OUTPUT_BYTES)} bytes; refusing to evaluate a truncated result`,
      name: "truncated output",
      result: {
        code: 0,
        stdout: `/opt/app/l\u0000/etc\u0000/opt/app/m${CAPTURE_TRUNCATION_MARKER}`,
      },
    },
    {
      message:
        "symlink containment check failed: probe returned 3 fields, expected (link, resolved) pairs",
      name: "an odd field count",
      result: { code: 0, stdout: "/opt/app/l\u0000/etc\u0000/opt/app/m\u0000" },
    },
    {
      message: `symlink "/opt/app/l" could not be resolved; ${checkedAfterMerge}`,
      name: "a link that could not be resolved",
      result: { code: 0, stdout: "/opt/app/l\u0000\u0000" },
    },
    {
      message: `symlink "/opt/app/l" resolves to "/etc", outside destination "/opt/app"; ${checkedAfterMerge} (and 1 more)`,
      name: "several escaping links",
      result: { code: 0, stdout: "/opt/app/l\u0000/etc\u0000/opt/app/m\u0000/root\u0000" },
    },
  ])("fails closed on $name", async ({ message, result }) => {
    const { outcome } = await validateWith(result)

    expect(outcome).toStrictEqual({ error: new Error(`${refusal}${message}`), status: "failed" })
  })
})

describe("archive.extract containment flag lifecycle (Issue #219)", () => {
  const owner = "www-data:www-data"
  const flagRemoval = `rm -f -- '${containmentFlag}'`

  it("writes the flag before the listing, staging, extract and merge, and clears it last", async () => {
    const files = new Map<string, string>()

    const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/f")], {
      files,
      hostLinks: new Map(),
      owner,
    })

    expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    const { calls } = run.mockSsh
    const [flagWrite, ...markerWrites] = run.writes
    expect(flagWrite.remotePath).toBe(containmentFlag)
    const [listing, mktemp, extract, merge, containment, chown] = [
      calls.indexOf(symlinkListingProbeCommand),
      calls.findIndex((command) => archiveStageMktempPattern.test(command)),
      calls.indexOf(stagedTarExtractCommand),
      calls.findIndex((command) => archiveStageMovePattern.test(command)),
      calls.indexOf(symlinkContainmentProbeCommand),
      calls.indexOf(batchedChownCommand),
    ]
    expect(listing).toBeGreaterThanOrEqual(0)
    expect([listing, mktemp, extract, merge, containment, chown]).toStrictEqual(
      [listing, mktemp, extract, merge, containment, chown].toSorted((left, right) => left - right)
    )
    // `callIndex` is the number of calls issued before the write.
    expect(flagWrite.callIndex).toBeLessThanOrEqual(listing)
    expect(markerWrites.map(({ remotePath }) => remotePath)).toStrictEqual(
      expect.arrayContaining([marker, membersMarker])
    )
    for (const write of markerWrites) expect(write.callIndex).toBeGreaterThan(chown)
    // The flag removal is the very last command, after every marker write.
    expect(calls.indexOf(flagRemoval)).toBe(calls.length - 1)
    for (const write of markerWrites) {
      expect(calls.indexOf(flagRemoval)).toBeGreaterThanOrEqual(write.callIndex)
    }
    expect(files.has(containmentFlag)).toBe(false)
  })

  it.each([
    {
      error: "would resolve outside destination",
      name: "a pre-merge refusal",
      options: (): TarListingApplyOptions => ({
        hostLinks: new Map([[`${destination}/etc`, "/etc"]]),
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
        injectedOnMerge: [[`${destination}/a/etc`, "/etc"]],
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

    const run = await applyTarListing([tarDirectoryLine("a/"), tarFileLine("a/f")], {
      ...options(),
      files,
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toContain(error)
    expect(run.writes[0]?.remotePath).toBe(containmentFlag)
    expect(run.mockSsh.calls).not.toContain(flagRemoval)
    expect(files.has(containmentFlag)).toBe(true)
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
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
    expect(calls).not.toContain(flagRemoval)
    expect(calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    // The staging directory is still cleaned up.
    expect(calls.some((command) => archiveStageCleanupPattern.test(command))).toBe(true)
    expect(files.has(containmentFlag)).toBe(true)
  })
})

/**
 * Issue #219: how often an apply run issued exactly this command.
 *
 * @param run - The recorded apply run.
 * @param command - The exact command to count.
 * @returns The number of matching calls.
 */
function countCalls(run: TarListingApplyRun, command: string): number {
  return run.mockSsh.calls.filter((call) => call === command).length
}

describe("archive.extract post-merge backstop (Issue #219)", () => {
  const escapingLink = `${destination}/a/etc`
  const lines = [tarDirectoryLine("a/"), tarFileLine("a/f")]
  const backstopRefusal = `[archive.extract] refusing to complete extraction of ${src}: `
  const checkedAfterMerge =
    "every symlink under the destination is checked after the merge, including links this archive did not ship"
  const removedEtc = `${backstopRefusal}symlink ${JSON.stringify(escapingLink)} resolves to "/etc", outside destination ${JSON.stringify(destination)}; ${checkedAfterMerge}; removed escaping symlinks: ${JSON.stringify(escapingLink)}; re-check found no escaping symlinks`
  const cpFailure = "cp: cannot overwrite directory '/opt/app/a/b' with non-directory"

  it("runs after a failed merge, removes the escaping link and joins both messages", async () => {
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing(lines, {
      hostLinks,
      injectedOnMerge: [[escapingLink, "/etc"]],
      owner: "www-data:www-data",
      responseStubs: [{ command: archiveStageMovePattern, result: { code: 1, stderr: cpFailure } }],
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination} (exit code 1)\n${cpFailure}; ${removedEtc}`
    )
    const { calls } = run.mockSsh
    const merge = calls.findIndex((command) => archiveStageMovePattern.test(command))
    expect(calls.indexOf(symlinkContainmentProbeCommand)).toBeGreaterThan(merge)
    expect(countCalls(run, symlinkContainmentProbeCommand)).toBe(2)
    expect(countCalls(run, symlinkRemovalCommand)).toBe(1)
    expect(calls).not.toContain(batchedChownCommand)
    expect(run.writes.map(({ remotePath }) => remotePath)).toStrictEqual([containmentFlag])
    expect([...hostLinks]).toStrictEqual([])
  })

  it("runs after a merge exec that threw and joins both messages", async () => {
    const hostLinks: HostLinkTree = new Map()

    const run = await applyTarListing(lines, {
      hostLinks,
      injectedOnMerge: [[escapingLink, "/etc"]],
      throwOn: { command: archiveStageMovePattern, error: new Error("channel closed") },
    })

    expect(run.thrown).toBeUndefined()
    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination}: channel closed; ${removedEtc}`
    )
    const { calls } = run.mockSsh
    const cleanup = calls.findIndex((command) => archiveStageCleanupPattern.test(command))
    expect(cleanup).toBeGreaterThan(
      calls.findIndex((command) => archiveStageMovePattern.test(command))
    )
    expect(calls.indexOf(symlinkContainmentProbeCommand)).toBeGreaterThan(cleanup)
    expect([...hostLinks]).toStrictEqual([])
  })

  it("reports only the merge failure when the backstop after it finds nothing", async () => {
    const run = await applyTarListing(lines, {
      hostLinks: new Map(),
      responseStubs: [{ command: archiveStageMovePattern, result: { code: 1, stderr: cpFailure } }],
    })

    expect(run.result.error?.message).toBe(
      `[archive.extract] failed to copy extracted files into ${destination} (exit code 1)\n${cpFailure}`
    )
    expect(countCalls(run, symlinkContainmentProbeCommand)).toBe(1)
    expect(countCalls(run, symlinkRemovalCommand)).toBe(0)
  })

  it("removes only the reported links in one exec and re-probes exactly once", async () => {
    const rootLink = `${destination}/a/root`
    const insideLink = `${destination}/a/inside`
    const hostLinks: HostLinkTree = new Map([[`${destination}/a/old`, "f"]])

    const run = await applyTarListing(lines, {
      hostLinks,
      injectedOnMerge: [
        [escapingLink, "/etc"],
        [insideLink, "../a/f"],
        [rootLink, "../.."],
      ],
    })

    expect(run.result.error?.message).toBe(
      `${backstopRefusal}symlink ${JSON.stringify(escapingLink)} resolves to "/etc", outside destination ${JSON.stringify(destination)}; ${checkedAfterMerge} (and 1 more); removed escaping symlinks: ${JSON.stringify(escapingLink)}, ${JSON.stringify(rootLink)}; re-check found no escaping symlinks`
    )
    const removals = run.mockSsh.execCalls.filter(
      ({ command }) => command === symlinkRemovalCommand
    )
    expect(removals).toStrictEqual([
      {
        command: symlinkRemovalCommand,
        options: {
          ignoreExitCode: true,
          input: `${escapingLink}\u0000${rootLink}\u0000`,
          silent: true,
        },
      },
    ])
    const { calls } = run.mockSsh
    const removal = calls.indexOf(symlinkRemovalCommand)
    expect(countCalls(run, symlinkContainmentProbeCommand)).toBe(2)
    expect(calls.indexOf(symlinkContainmentProbeCommand)).toBeLessThan(removal)
    expect(calls.lastIndexOf(symlinkContainmentProbeCommand)).toBeGreaterThan(removal)
    expect([...hostLinks.keys()].toSorted()).toStrictEqual([insideLink, `${destination}/a/old`])
    expect(calls).not.toContain(`rm -f -- '${containmentFlag}'`)
  })

  const twoEscapes = `${escapingLink}\u0000/etc\u0000${destination}/a/root\u0000/root\u0000`
  const stillReports = `re-check still reports symlink ${JSON.stringify(escapingLink)} resolves to "/etc", outside destination ${JSON.stringify(destination)} (and 1 more)`

  it.each([
    {
      name: "a failed removal exec",
      removal: { code: 1, stderr: "xargs: sh: not found" },
      summary: `could not remove: ${JSON.stringify(escapingLink)} (removal outcome unknown: xargs: sh: not found), "/opt/app/a/root" (removal outcome unknown: xargs: sh: not found)`,
    },
    {
      name: "a partial removal",
      removal: {
        code: 0,
        stdout: `${escapingLink}\u0000removed\u0000/opt/app/a/root\u0000rm failed\u0000`,
      },
      summary: `removed escaping symlinks: ${JSON.stringify(escapingLink)}; could not remove: "/opt/app/a/root" (rm failed)`,
    },
    {
      name: "removal output with broken framing",
      removal: { code: 0, stdout: `${escapingLink}\u0000removed\u0000/opt/app/a/root\u0000` },
      summary: `could not remove: ${JSON.stringify(escapingLink)} (removal outcome unknown: removal returned 3 fields, expected (link, outcome) pairs), "/opt/app/a/root" (removal outcome unknown: removal returned 3 fields, expected (link, outcome) pairs)`,
    },
  ])("fails and reports $name in the message", async ({ removal, summary }) => {
    const run = await applyTarListing(lines, {
      responses: {
        [symlinkContainmentProbeCommand]: { code: 0, stdout: twoEscapes },
        [symlinkRemovalCommand]: removal,
      },
    })

    expect(run.result.status).toBe("failed")
    expect(run.result.error?.message).toBe(
      `${backstopRefusal}symlink ${JSON.stringify(escapingLink)} resolves to "/etc", outside destination ${JSON.stringify(destination)}; ${checkedAfterMerge} (and 1 more); ${summary}; ${stillReports}`
    )
    expect(countCalls(run, symlinkRemovalCommand)).toBe(1)
    expect(countCalls(run, symlinkContainmentProbeCommand)).toBe(2)
    expect(run.mockSsh.calls).not.toContain(`rm -f -- '${containmentFlag}'`)
  })

  it("never hands a non-normalized or outside link to the removal exec", async () => {
    const dotted = `${destination}/../etc-link`
    const sibling = `${alternateDestination}/l`

    const run = await applyTarListing(lines, {
      responses: {
        [symlinkContainmentProbeCommand]: {
          code: 0,
          stdout: `${dotted}\u0000/etc-link\u0000${sibling}\u0000/etc\u0000`,
        },
      },
    })

    expect(run.result.error?.message).toContain(
      `; could not remove: ${JSON.stringify(dotted)} (path is not normalized), ${JSON.stringify(sibling)} (path is not strictly below the destination); re-check still reports`
    )
    expect(countCalls(run, symlinkRemovalCommand)).toBe(0)
  })
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
    expect(run.writes).toStrictEqual([])
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

describe("archive.extract round trips (Issue #219)", () => {
  it("keeps the total exec count of an apply constant as the member count grows", async () => {
    const runWith = async (memberCount: number): Promise<{ calls: number; writes: number }> => {
      const lines = Array.from({ length: memberCount }, (_value, index) => [
        tarDirectoryLine(`d${String(index)}/`),
        tarFileLine(`d${String(index)}/f`),
        tarSymlinkLine(`d${String(index)}/l`, "f"),
      ]).flat()
      const run = await applyTarListing(lines, { owner: "www-data:www-data" })
      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      return { calls: run.mockSsh.calls.length, writes: run.writes.length }
    }

    const few = await runWith(3)
    const many = await runWith(300)

    expect(many).toStrictEqual(few)
  })
})
