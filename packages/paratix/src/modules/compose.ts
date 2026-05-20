/* eslint-disable max-lines -- compose module intentionally keeps related lifecycle helpers together */
import { readFile } from "node:fs/promises"
import { basename, dirname, posix } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import {
  type ExecResult,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { renderGuardedChownCommand } from "./fileMetadataHelpers.js"
import { isRegularFileWithoutSymlink, isSymlink } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const COMPOSE_CONFIG_MODE = "0600"
const COMPOSE_CONFIG_STAGING_PREFIX = ".compose.yml.paratix-staging"
const SYSTEMD_UNIT_MODE = "0644"
const SYSTEMD_UNIT_STAGING_PREFIX = ".compose-systemd-unit.paratix-staging"

type ComposeSystemdMaskSnapshot = "masked" | "unmasked"

type ComposeSystemdUnitFileSnapshot =
  | {
      content: string
      exists: true
      mode: string
      owner: string
    }
  | { exists: false }

type ComposeSystemdTargetSnapshot = {
  mask: ComposeSystemdMaskSnapshot
  unitFile: ComposeSystemdUnitFileSnapshot
}

type ComposeRuntime = "docker" | "podman"

function requireComposeSsh(
  ssh: null | SshConnection,
  action: string,
  projectDirectory: string
): ModuleResult | SshConnection {
  return ssh ?? failed(`[compose.${action}] SSH connection is required for ${projectDirectory}`)
}

function assertComposeRuntime(runtime: unknown, action: string): ComposeRuntime {
  // R-0000556: TypeScript only enforces the `ComposeRuntime` union at compile
  // time. A JavaScript caller — or any path that bypasses the union — could
  // smuggle an attacker-controlled string like `"docker; rm -rf /"` into
  // `composeCommand`, which would then land verbatim in a shell command and
  // enable arbitrary remote code execution. Re-check the value against the
  // runtime whitelist before it can reach any shell expansion.
  if (runtime !== "docker" && runtime !== "podman") {
    throw new Error(
      `[compose.${action}] invalid container runtime: ${typeof runtime === "string" ? runtime : String(runtime)}`
    )
  }
  return runtime
}

async function requireComposeRuntime(parameters: {
  action: string
  explicitRuntime?: ComposeRuntime
  projectDirectory: string
  ssh: SshConnection
}): Promise<ComposeRuntime | ModuleResult> {
  const runtime = await getRuntime(parameters.ssh, parameters.action, parameters.explicitRuntime)
  if (runtime === null) {
    return failed(
      `[compose.${parameters.action}] no container runtime found for ${parameters.projectDirectory}`
    )
  }
  return runtime
}

// R-0000560: anchor compose action keywords at the start of a line. The
// previous `composeOutput.includes("Pulling")` matched anywhere in the
// merged stdout+stderr stream, so image names, registry paths or
// container logs containing words like `Creating`, `Starting` or
// `Pulling` produced false-positive "changed" results. compose prints
// action keywords as the first token of a log line, so we keep the
// `2>&1` capture and only tighten the keyword search to line starts via
// a multi-line regex.
const COMPOSE_UP_ACTION_KEYWORDS_REGEX = /^(?:Creating|Recreating|Starting|Started|Pulling)\s/mv

/**
 * R-0000078: when every service was already running, `compose up -d`
 * emits no action keywords and the run is a true no-op. Treat that as
 * status ok so apply does not always report "changed".
 *
 * @param composeOutput - The combined stdout/stderr returned by `compose up`.
 * @returns `true` when at least one action keyword was emitted at the
 *   start of a line.
 */
function composeUpReportedChange(composeOutput: string): boolean {
  return COMPOSE_UP_ACTION_KEYWORDS_REGEX.test(composeOutput)
}

// R-0000560: same anchoring for `compose pull`. The previous
// `output.includes("Pulling") || output.includes("Downloaded")` matched
// any substring in image names or container logs and produced false
// "changed" results when no image was actually pulled.
const COMPOSE_PULL_ACTION_REGEX = /^(?:Pulling|Downloaded)\s/mv

function composePullReportedChange(composeOutput: string): boolean {
  return COMPOSE_PULL_ACTION_REGEX.test(composeOutput)
}

function validateComposeUpServices(services: string[] | undefined): void {
  for (const service of services ?? []) {
    if (service === "") {
      throw new Error("compose.up services must not contain empty service names")
    }
    if (service.startsWith("-")) {
      throw new Error(`compose.up service names must not start with "-", got ${service}`)
    }
  }
}

function formatCaughtError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Detect whether `podman` or `docker` is available on the remote host.
 * Podman is preferred when both are installed.
 *
 * @param ssh - The SSH connection to the remote host.
 * @returns The first available runtime, or `null` if neither is found.
 */
async function detectRuntime(ssh: SshConnection): Promise<ComposeRuntime | null> {
  if (await ssh.test("command -v podman")) return "podman"
  if (await ssh.test("command -v docker")) return "docker"
  return null
}

/**
 * Resolve the container runtime to use, preferring the explicit override.
 *
 * R-0000592: every caller — both apply and check pathways — must funnel the
 * runtime value through `assertComposeRuntime` before it can reach the shell
 * via `composeCommand`. Centralizing the whitelist check here closes the
 * earlier gap where check-only callers (`checkComposeSystemdUnit`,
 * `compose.down.check`, `compose.up.check`, `composeProjectVolumesExist`)
 * bypassed validation and let a JavaScript caller smuggle a string like
 * `"docker; rm -rf /"` into `${runtime} compose --project-directory …`.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param action - The compose action name used in validation error messages.
 * @param explicit - An optional runtime override that skips auto-detection.
 * @returns The resolved runtime, or `null` if none could be determined.
 */
async function getRuntime(
  ssh: SshConnection,
  action: string,
  explicit?: ComposeRuntime
): Promise<ComposeRuntime | null> {
  if (explicit !== undefined) return assertComposeRuntime(explicit, action)
  return detectRuntime(ssh)
}

/**
 * Build the base `docker compose` or `podman compose` command string for a
 * given project directory.
 *
 * @param runtime - The container runtime to use.
 * @param projectDirectory - The project directory passed via `--project-directory`.
 * @returns The base compose command string, ready for subcommand concatenation.
 */
function composeCommand(runtime: ComposeRuntime, projectDirectory: string): string {
  return `${runtime} compose --project-directory ${shellQuote(projectDirectory)}`
}

function parseComposeProjectName(stdout: string, projectDirectory: string): null | string {
  try {
    const parsed: unknown = JSON.parse(stdout)
    if (typeof parsed === "object" && parsed !== null && "name" in parsed) {
      const name = parsed.name
      if (typeof name === "string" && name.trim() !== "") return name
    }
    return basename(projectDirectory)
  } catch {
    return null
  }
}

async function resolveComposeProjectName(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<null | string> {
  const result = await parameters.ssh.exec(
    `${composeCommand(parameters.runtime, parameters.projectDirectory)} config --format json`,
    EXEC_OPTS
  )
  if (result.code !== 0) return null
  return parseComposeProjectName(result.stdout, parameters.projectDirectory)
}

async function composeProjectVolumesExist(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<boolean> {
  const projectName = await resolveComposeProjectName(parameters)
  if (projectName === null) return true

  const composeProjectLabel = `label=com.docker.compose.project=${projectName}`
  const result = await parameters.ssh.exec(
    `${parameters.runtime} volume ls --filter ${shellQuote(composeProjectLabel)} -q`,
    EXEC_OPTS
  )
  if (result.code !== 0) return true
  return result.stdout.trim().length > 0
}

async function checkComposeDownNoContainers(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
  volumes?: boolean
}): Promise<"needs-apply" | "ok"> {
  if (parameters.volumes !== true) return "ok"
  return (await composeProjectVolumesExist(parameters)) ? NEEDS_APPLY : "ok"
}

// R-0000483: a non-existing compose project (missing compose.yml /
// project-directory absent) should be treated as already-down. Both Docker
// Compose and Podman Compose report different but consistently descriptive
// errors when the project cannot be located. The patterns below are
// conservative: they require a recognisable absent-signal in the failure
// output before we treat the failure as "project does not exist".
const COMPOSE_ABSENT_PROJECT_PATTERNS = [
  /no configuration file provided/iv,
  /no such file or directory/iv,
  /no such project/iv,
  /can't find a suitable configuration file/iv,
  /not found/iv,
]

function isComposeAbsentProject(parameters: { stderr: string; stdout: string }): boolean {
  const combined = `${parameters.stdout}\n${parameters.stderr}`
  return COMPOSE_ABSENT_PROJECT_PATTERNS.some((pattern) => pattern.test(combined))
}

async function resolveDesiredComposeContent(options: {
  content?: string
  src?: string
}): Promise<null | string> {
  if (options.src !== undefined && options.src !== "") {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path from module config, not user input
    return readFile(options.src, "utf8")
  }
  if (options.content !== undefined && options.content !== "") {
    return options.content
  }
  return null
}

/**
 * R-0000756: per-module cache helper for the desired compose content. The
 * runner calls `check()` and then `apply()` sequentially on the same Module
 * instance, but both used to re-read `options.src` from disk independently.
 * A local file that changes between those two reads would otherwise let
 * check observe one revision (and pass/fail accordingly) while apply
 * uploads or writes a different revision — analogous to file.template's
 * `cachedContent` pattern.
 *
 * The returned function caches its result on the first invocation and
 * resolves to `null` only when neither `src` nor `content` were provided.
 *
 * @param options - The compose-config source / content options.
 * @param options.content - Inline string content to use as the desired bytes.
 * @param options.src - Local file path whose content becomes the desired bytes.
 * @returns A zero-argument loader that resolves to the cached desired content.
 */
function createCachedComposeContentResolver(options: {
  content?: string
  src?: string
}): () => Promise<null | string> {
  let cachedContent: null | string | undefined
  return async () => {
    // eslint-disable-next-line require-atomic-updates -- runner invokes check() then apply() sequentially on the same Module instance
    cachedContent ??= await resolveDesiredComposeContent(options)
    return cachedContent
  }
}

/**
 * R-0000710/R-0000810: cap the size of stdout passed to `JSON.parse`. A
 * compromised remote (or a pathologically large compose project) could
 * otherwise feed arbitrarily large output into `compose ps --format json`
 * and force a multi-megabyte `JSON.parse` walk in-process. 1 MiB is well
 * above any realistic compose-project listing (a single `ps` entry is on
 * the order of a few hundred bytes, so 1 MiB still accommodates thousands
 * of services) and keeps the parser bounded much more tightly than the
 * previous 10 MiB threshold.
 */
const COMPOSE_PS_JSON_MAX_BYTES = 1_048_576

/**
 * Parse the container state strings from the JSON output of `compose ps --format json`.
 *
 * Both array JSON (Docker >= 2.x) and newline-delimited JSON (older Docker / Podman)
 * are supported. Each entry is expected to have a `State` property.
 *
 * R-0000710: stdout is rejected up-front when it exceeds
 * {@link COMPOSE_PS_JSON_MAX_BYTES}. Oversized input returns an empty array,
 * which propagates through the call sites in `compose.up.check` /
 * `compose.down.check` as `needs-apply` so the next run re-evaluates the
 * stack instead of letting an unbounded parse run in-process.
 *
 * @param stdout - The raw stdout string from the `compose ps` command.
 * @returns An array of state strings (e.g. `"running"`, `"exited"`). Returns an
 *   empty array when parsing fails, the output exceeds the size cap, or the
 *   output is not in a recognised format.
 */
function parseContainerStates(stdout: string): string[] {
  // R-0000710: use the UTF-8 byte length so multi-byte payloads cannot bypass
  // the cap via a character-count comparison. `Buffer.byteLength` avoids
  // materialising a Buffer copy of the entire stdout.
  if (Buffer.byteLength(stdout, "utf8") > COMPOSE_PS_JSON_MAX_BYTES) {
    return []
  }
  try {
    const parsed: unknown = stdout.startsWith("[")
      ? JSON.parse(stdout)
      : stdout
          .split("\n")
          .filter((line) => line.trim() !== "")
          .map((line) => JSON.parse(line) as unknown)

    if (!Array.isArray(parsed)) return []

    return parsed.map((entry: unknown) => {
      if (typeof entry === "object" && entry !== null && "State" in entry) {
        const state = entry.State
        return typeof state === "string" ? state : ""
      }
      return ""
    })
  } catch {
    return []
  }
}

/**
 * Strip injection-relevant characters from a value used inside a systemd unit
 * file. Removes:
 *
 * - all C0 control characters (`U+0000`–`U+001F`)
 * - the DEL control character (`U+007F`)
 *
 * Newlines and carriage returns are part of the C0 range, so they are
 * still removed alongside the rest of the control characters.
 *
 * R-0000562: additionally escape `%` so systemd specifiers like `%n`, `%t`,
 * `%h` or `%i` cannot be smuggled through a project directory or service
 * name and expanded by the unit parser. The systemd documented escape is
 * doubling: `%` becomes `%%`.
 *
 * @param value - The string to sanitize.
 * @returns The sanitized string, ready to be placed inside a unit value.
 */
function sanitizeUnitValue(value: string): string {
  /* eslint-disable-next-line regexp/no-control-character -- intentional C0 + DEL strip for defense-in-depth */ /* oxlint-disable-next-line no-control-regex */
  const withoutControlChars = value.replaceAll(/[\u0000-\u001F\u007F]/gv, "")
  return withoutControlChars.replaceAll("%", "%%")
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)
    if (codePoint != null && (codePoint <= 0x1f || codePoint === 0x7f)) return true
  }
  return false
}

function validateGeneratedSystemdUnitContent(
  content: string,
  unitFileName: string
): ModuleResult | null {
  if (content.trim() === "") {
    return failed(`[compose.systemd] generated empty unit content for ${unitFileName}`)
  }

  if (!content.includes("[Unit]") || !content.includes("[Service]")) {
    return failed(`[compose.systemd] generated invalid unit content for ${unitFileName}`)
  }

  return null
}

/**
 * R-0000562: refuse to generate a systemd unit when `projectDirectory` is not
 * an absolute POSIX path. systemd's `WorkingDirectory=` requires an absolute
 * path; a relative path would resolve against the runtime's working
 * directory at ExecStart time and silently break the unit — or, with a
 * crafted prefix like `../../tmp`, point ExecStart at a directory the
 * operator never intended.
 *
 * @param projectDirectory - The directory passed by the caller to be used
 *   as `WorkingDirectory=` in the generated unit.
 * @param unitFileName - The unit filename, used in the failure message so
 *   the operator can identify which unit triggered the validation.
 * @returns A failed `ModuleResult` when the path is not absolute, otherwise
 *   `null` to signal that the value is acceptable.
 */
function validateComposeProjectDirectory(
  projectDirectory: string,
  unitFileName: string
): ModuleResult | null {
  if (!posix.isAbsolute(projectDirectory)) {
    return failed(
      `[compose.systemd] projectDirectory must be an absolute path for ${unitFileName}, got: ${projectDirectory}`
    )
  }
  if (hasControlCharacter(projectDirectory)) {
    return failed(
      `[compose.systemd] projectDirectory must not contain control characters for ${unitFileName}`
    )
  }
  return null
}

async function verifyNonEmptySystemdUnit(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<"empty" | "matches" | "unexpected"> {
  const writtenContent = await parameters.connection.readFile(parameters.filePath)
  if (writtenContent.trim() === "") return "empty"
  return writtenContent.trim() === parameters.content.trim() ? "matches" : "unexpected"
}

async function cleanupComposeSystemdTemporaryPath(parameters: {
  connection: SshConnection
  temporaryPath: string
}): Promise<void> {
  // R-0000565: pass `--` so a future refactor that loosens the staging prefix
  // cannot let an attacker-controlled path that starts with `-` be
  // interpreted as an `rm` option.
  await parameters.connection.exec(`rm -f -- ${shellQuote(parameters.temporaryPath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function allocateComposeSystemdTemporaryPath(parameters: {
  connection: SshConnection
  filePath: string
  unitFileName: string
}): Promise<ModuleResult | string> {
  const directory = dirname(parameters.filePath)
  // R-0000565: pass the staging directory via `-p` and separate the template
  // with `--` so a future refactor that loosens the staging prefix cannot let
  // an attacker-controlled value be interpreted as a `mktemp` option.
  const template = `${SYSTEMD_UNIT_STAGING_PREFIX}.XXXXXX`
  const result = await parameters.connection.exec(
    `mktemp -p ${shellQuote(directory)} -- ${shellQuote(template)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[compose.systemd] mktemp failed for ${parameters.unitFileName}`, result)
  }

  try {
    return validateMktempPath(directory, result.stdout.trim(), SYSTEMD_UNIT_STAGING_PREFIX)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[compose.systemd] mktemp produced an unexpected path: ${reason}`)
  }
}

async function rewriteComposeSystemdUnitViaShell(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult | null> {
  const encodedContent = Buffer.from(parameters.content, "utf8").toString("base64")
  const temporaryPath = await allocateComposeSystemdTemporaryPath(parameters)
  if (typeof temporaryPath !== "string") return temporaryPath

  // R-0000565: pass `--` to both `rm -f` invocations inside the shell
  // pipeline so the temporary path cannot be parsed as an `rm` option.
  //
  // R-0000707: the `[ -L final ] && exit 73` probe and the subsequent
  // `mv -f -T temp final` run in the same shell invocation, but they are
  // still two separate syscalls. A privileged attacker that races a
  // symlink swap into the directory **between** the lstat issued by the
  // shell `test -L` and the kernel `rename(2)` syscall in `mv` can
  // therefore still redirect the write to an attacker-controlled target.
  //
  // POSIX `rename(2)` does not refuse to overwrite a symlink (it removes
  // the link entry and creates a new one in its place), and there is no
  // portable shell-level primitive equivalent to Linux's
  // `renameat2(RENAME_NOREPLACE)` or `O_NOFOLLOW` for the *destination*
  // of a directory rename. Until the runtime grows a syscall-level
  // wrapper that issues `renameat2(RENAME_NOREPLACE)` directly (or a
  // lock-directory pattern around `mv`), this race window remains
  // unavoidable through plain `sh + mv`. The same-shell guard already
  // closes the *vast* majority of attacks (cross-process scheduling
  // gaps), but operators with adversarial neighbours on the systemd unit
  // directory should rely on filesystem-level protections
  // (`/etc/systemd/system` owned by root, restrictive parent-directory
  // permissions) rather than this in-shell check alone.
  // R-0000806: pipe the base64-encoded unit content via stdin instead of
  // interpolating it into argv. The encoded payload can be many kilobytes;
  // moving it out of the rendered shell command avoids hitting the host's
  // ARG_MAX, keeps the command line readable in logs, and mirrors the
  // pattern apt.ts uses for `debconf-set-selections` (see apt.ts L770-775).
  const result = await parameters.connection.exec(
    `{ base64 -d > ${shellQuote(temporaryPath)} && chmod ${shellQuote(SYSTEMD_UNIT_MODE)} ${shellQuote(temporaryPath)} && chown ${shellQuote("root:root")} ${shellQuote(temporaryPath)} && if [ -L ${shellQuote(parameters.filePath)} ]; then rm -f -- ${shellQuote(temporaryPath)}; exit 73; fi && mv -f -T ${shellQuote(temporaryPath)} ${shellQuote(parameters.filePath)}; } || { status=$?; rm -f -- ${shellQuote(temporaryPath)}; exit "$status"; }`,
    { ...EXEC_OPTS, input: encodedContent }
  )
  if (result.code !== 0) {
    await cleanupComposeSystemdTemporaryPath({ connection: parameters.connection, temporaryPath })
    return failedCommand(
      `[compose.systemd] shell fallback write failed for ${parameters.unitFileName}`,
      result
    )
  }

  const fallbackVerification = await verifyNonEmptySystemdUnit(parameters)
  if (fallbackVerification === "matches") return null

  if (fallbackVerification === "empty") {
    return failed(
      `[compose.systemd] wrote empty unit file for ${parameters.unitFileName} even after shell fallback`
    )
  }
  return failed(
    `[compose.systemd] wrote unexpected unit content for ${parameters.unitFileName} even after shell fallback`
  )
}

async function writeComposeSystemdUnitFile(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult | null> {
  // R-0000192: refuse to write through a symlinked unit path. The check path
  // already rejects symlinks via isRegularFileWithoutSymlink; without the same
  // guard here, writeFile + chown root:root would follow the link and mutate
  // an attacker-controlled target. Mirrors the apt.key (R-0000134) hardening.
  if (await isSymlink(parameters.connection, parameters.filePath)) {
    return failed(`[compose.systemd] refuses to write through symlink at ${parameters.filePath}`)
  }
  try {
    await parameters.connection.writeFile(parameters.filePath, parameters.content, {
      mode: SYSTEMD_UNIT_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[compose.systemd] atomic write failed for ${parameters.unitFileName}: ${reason}`)
  }

  const writeVerification = await verifyNonEmptySystemdUnit(parameters)
  if (writeVerification !== "matches") {
    return rewriteComposeSystemdUnitViaShell(parameters)
  }
  return null
}

async function applyComposeSystemdUnit(parameters: {
  connection: SshConnection
  content: string
  filePath: string
  unitFileName: string
}): Promise<ModuleResult> {
  const snapshot = await snapshotComposeSystemdTarget(parameters)
  if ("status" in snapshot) return snapshot

  const prepareFailure = await prepareComposeSystemdTarget(parameters)
  if (prepareFailure != null) return prepareFailure

  const writeFailure = await writeComposeSystemdUnitFile(parameters)
  if (writeFailure != null) {
    return rollbackComposeSystemdTargetAfterFailure({
      ...parameters,
      needsDaemonReload: false,
      originalFailure: writeFailure,
      snapshot,
    })
  }

  // R-0000164: writeFile sets the file mode but not its owner/group, so an
  // owner drift introduced by a previous manual `chown` would persist.
  // R-0000988: guard the post-write chown because a symlink swap after
  // writeFile would otherwise make chown follow the attacker-controlled link.
  const ownerResult = await parameters.connection.exec(
    renderGuardedChownCommand("root:root", parameters.filePath),
    EXEC_OPTS
  )
  if (ownerResult.code !== 0) {
    const ownerFailure = failedCommand(
      `[compose.systemd] failed to set owner root:root on ${parameters.unitFileName}`,
      ownerResult
    )
    return rollbackComposeSystemdTargetAfterFailure({
      ...parameters,
      needsDaemonReload: false,
      originalFailure: ownerFailure,
      snapshot,
    })
  }

  const result = await parameters.connection.exec("systemctl daemon-reload", EXEC_OPTS)
  if (result.code === 0) return { status: "changed" }

  const reloadFailure = failedCommand(
    `[compose.systemd] daemon-reload failed for ${parameters.unitFileName}`,
    result
  )
  return rollbackComposeSystemdTargetAfterFailure({
    ...parameters,
    needsDaemonReload: true,
    originalFailure: reloadFailure,
    snapshot,
  })
}

async function checkComposeSystemdUnit(parameters: {
  detached: boolean
  explicitRuntime?: ComposeRuntime
  filePath: string
  projectDirectory: string
  serviceName: string
  ssh: SshConnection
}): Promise<"needs-apply" | "ok"> {
  const runtime = await getRuntime(parameters.ssh, "systemd", parameters.explicitRuntime)
  if (!runtime) return NEEDS_APPLY

  if (!(await isRegularFileWithoutSymlink(parameters.ssh, parameters.filePath))) {
    return NEEDS_APPLY
  }

  const content = generateSystemdUnit(parameters.projectDirectory, parameters.serviceName, {
    detached: parameters.detached,
    runtime,
  })
  const remoteContent = await parameters.ssh.readFile(parameters.filePath)
  if (remoteContent.trim() !== content.trim()) return NEEDS_APPLY

  // R-0000085: detect manual mode drift (e.g. an operator ran
  // `chmod 0600 compose-app.service`): even when the content matches, the
  // apply path would re-set the mode to SYSTEMD_UNIT_MODE, so check must
  // report needs-apply to keep the run idempotent — mirroring the same
  // pattern used by createComposeConfigCheck.
  //
  // R-0000595: route the stat call through ssh.exec with ignoreExitCode so a
  // transient stat failure (file removed mid-check, EACCES, EIO, …) collapses
  // to NEEDS_APPLY instead of throwing a raw CommandError out of check.
  // Matches the R-0000558 pattern used by createComposeConfigCheck.
  const modeResult = await parameters.ssh.exec(
    `stat -c '%a' ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (modeResult.code !== 0) return NEEDS_APPLY
  const remoteMode = modeResult.stdout.trim()
  if (remoteMode !== SYSTEMD_UNIT_MODE.replace(/^0+/v, "")) return NEEDS_APPLY

  // R-0000164: detect manual owner/group drift (e.g. an operator ran
  // `chown svc:svc compose-app.service`). The apply path explicitly runs
  // `chown root:root` on the unit, so a check that ignored ownership would
  // report "ok" while apply silently kept rewriting the unit on every run.
  // A non-root owner of a system-wide unit is also a hardening regression.
  //
  // R-0000595: same ignoreExitCode routing as the mode probe above so check
  // never throws a raw CommandError when the unit file disappears or stat
  // fails for a transient reason.
  const ownerResult = await parameters.ssh.exec(
    `stat -c '%U %G' ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (ownerResult.code !== 0) return NEEDS_APPLY
  if (ownerResult.stdout.trim() !== "root root") return NEEDS_APPLY

  return "ok"
}

function resolveComposeSystemdIdentity(options: { name?: string; projectDirectory: string }): {
  filePath: string
  serviceName: string
  unitFileName: string
} {
  const serviceName = options.name ?? `compose-${basename(options.projectDirectory)}`
  if (serviceName.startsWith("-")) {
    throw new Error(`compose.systemd: name must not start with '-', got: ${serviceName}`)
  }
  if (!UNIT_NAME_PATTERN.test(serviceName)) {
    throw new Error(
      `compose.systemd: name must match ${String(UNIT_NAME_PATTERN)}, got: ${serviceName}`
    )
  }

  const unitFileName = `${serviceName}.service`
  return {
    filePath: `/etc/systemd/system/${unitFileName}`,
    serviceName,
    unitFileName,
  }
}

async function snapshotComposeSystemdMaskState(parameters: {
  connection: SshConnection
  unitFileName: string
}): Promise<ComposeSystemdMaskSnapshot> {
  const result = await parameters.connection.exec(
    `systemctl is-enabled -- ${shellQuote(parameters.unitFileName)}`,
    EXEC_OPTS
  )
  return result.stdout.trim().includes("masked") ? "masked" : "unmasked"
}

async function snapshotComposeSystemdUnitFile(parameters: {
  connection: SshConnection
  filePath: string
  unitFileName: string
}): Promise<ComposeSystemdUnitFileSnapshot | ModuleResult> {
  if (!(await parameters.connection.exists(parameters.filePath))) return { exists: false }
  if (await isSymlink(parameters.connection, parameters.filePath)) return { exists: false }

  const content = await parameters.connection.readFile(parameters.filePath)
  const modeResult = await parameters.connection.exec(
    `stat -c '%a' ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (modeResult.code !== 0) {
    return failedCommand(
      `[compose.systemd] failed to snapshot mode for ${parameters.unitFileName}`,
      modeResult
    )
  }

  const ownerResult = await parameters.connection.exec(
    `stat -c '%U:%G' ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (ownerResult.code !== 0) {
    return failedCommand(
      `[compose.systemd] failed to snapshot owner for ${parameters.unitFileName}`,
      ownerResult
    )
  }

  return {
    content,
    exists: true,
    mode: modeResult.stdout.trim(),
    owner: ownerResult.stdout.trim(),
  }
}

async function snapshotComposeSystemdTarget(parameters: {
  connection: SshConnection
  filePath: string
  unitFileName: string
}): Promise<ComposeSystemdTargetSnapshot | ModuleResult> {
  const unitFile = await snapshotComposeSystemdUnitFile(parameters)
  if ("status" in unitFile) return unitFile
  const mask = await snapshotComposeSystemdMaskState(parameters)
  return { mask, unitFile }
}

async function prepareComposeSystemdTarget(parameters: {
  connection: SshConnection
  unitFileName: string
}): Promise<ModuleResult | null> {
  const result = await parameters.connection.exec(
    `systemctl unmask -- ${shellQuote(parameters.unitFileName)}`,
    EXEC_OPTS
  )
  return result.code === 0
    ? null
    : failedCommand(
        `[compose.systemd] systemctl unmask failed for ${parameters.unitFileName}`,
        result
      )
}

/**
 * R-0000559: return rollback failures as regular `ModuleResult` values
 * (instead of throwing). When a rollback step fails, the structured
 * `CommandError` carrying stdout/stderr propagates through the normal
 * `failed`-path so the central secret-masking still applies and the
 * stream payload is not flattened into the thrown `Error.message`.
 *
 * @param parameters - Bundle carrying the rollback inputs.
 * @param parameters.connection - The active SSH connection used to write
 *   or remove the unit file on the remote host.
 * @param parameters.filePath - Absolute path of the systemd unit file to
 *   restore.
 * @param parameters.snapshot - Captured snapshot describing the previous
 *   on-disk state of the unit file.
 * @returns A failed `ModuleResult` when the rollback itself failed, or one
 *   of the literals `"restored"` / `"removed"` so the caller knows whether
 *   a `daemon-reload` is required.
 */
async function restoreComposeSystemdUnitFileSnapshot(parameters: {
  connection: SshConnection
  filePath: string
  snapshot: ComposeSystemdUnitFileSnapshot
}): Promise<"removed" | "restored" | ModuleResult> {
  if (parameters.snapshot.exists) {
    await parameters.connection.writeFile(parameters.filePath, parameters.snapshot.content, {
      mode: parameters.snapshot.mode,
    })
    const ownerResult = await parameters.connection.exec(
      renderGuardedChownCommand(parameters.snapshot.owner, parameters.filePath),
      EXEC_OPTS
    )
    if (ownerResult.code !== 0) {
      return failedCommand(`[compose.systemd] rollback chown failed`, ownerResult)
    }
    return "restored"
  }

  // R-0000565: pass `--` so the rollback path cannot be parsed as an `rm`
  // option after a future refactor that loosens the file-path validation.
  const removeResult = await parameters.connection.exec(
    `rm -f -- ${shellQuote(parameters.filePath)}`,
    EXEC_OPTS
  )
  if (removeResult.code !== 0) {
    return failedCommand(`[compose.systemd] rollback remove failed`, removeResult)
  }
  return "removed"
}

async function restoreComposeSystemdMaskSnapshot(parameters: {
  connection: SshConnection
  snapshot: ComposeSystemdMaskSnapshot
  unitFileName: string
}): Promise<ModuleResult | null> {
  if (parameters.snapshot !== "masked") return null

  const result = await parameters.connection.exec(
    `systemctl mask -- ${shellQuote(parameters.unitFileName)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[compose.systemd] rollback systemctl mask failed`, result)
  }
  return null
}

function combineComposeSystemdRollbackFailure(
  originalFailure: ModuleResult,
  rollbackFailure: ModuleResult
): ModuleResult {
  // R-0000559: combine messages so the operator sees both the original
  // failure context and the rollback failure context. The structured
  // `CommandError` of the rollback failure is otherwise dropped, so we
  // append its rendered message — secret masking has already been applied
  // by `failedCommand` when the caller forwarded a `secrets` list.
  return failed(
    `${originalFailure.error?.message ?? "[compose.systemd] failed"}\nrollback failed: ${rollbackFailure.error?.message ?? "rollback failed"}`
  )
}

async function rollbackComposeSystemdTargetAfterFailure(parameters: {
  connection: SshConnection
  filePath: string
  needsDaemonReload: boolean
  originalFailure: ModuleResult
  snapshot: ComposeSystemdTargetSnapshot
  unitFileName: string
}): Promise<ModuleResult> {
  try {
    const unitFileOutcome = await restoreComposeSystemdUnitFileSnapshot({
      connection: parameters.connection,
      filePath: parameters.filePath,
      snapshot: parameters.snapshot.unitFile,
    })
    if (typeof unitFileOutcome !== "string") {
      return combineComposeSystemdRollbackFailure(parameters.originalFailure, unitFileOutcome)
    }
    const maskOutcome = await restoreComposeSystemdMaskSnapshot({
      connection: parameters.connection,
      snapshot: parameters.snapshot.mask,
      unitFileName: parameters.unitFileName,
    })
    if (maskOutcome != null) {
      return combineComposeSystemdRollbackFailure(parameters.originalFailure, maskOutcome)
    }

    // unitFileOutcome is "restored" or "removed" at this point (the
    // failure branch returns early above). In both cases the on-disk
    // unit file changed, so a `daemon-reload` is required for systemd to
    // pick up the rollback — equivalent to the previous behaviour where
    // the helper returned `true` on every successful restore. The
    // `parameters.needsDaemonReload` hint stays in the signature so callers
    // continue to document whether the failing branch had already mutated
    // systemd, but it is currently subsumed by the unit-file outcome.
    void parameters.needsDaemonReload
    void unitFileOutcome
    const reloadResult: ExecResult = await parameters.connection.exec(
      "systemctl daemon-reload",
      EXEC_OPTS
    )
    if (reloadResult.code !== 0) {
      return combineComposeSystemdRollbackFailure(
        parameters.originalFailure,
        failedCommand(`[compose.systemd] rollback daemon-reload failed`, reloadResult)
      )
    }
  } catch (rollbackError) {
    return failed(
      `${parameters.originalFailure.error?.message ?? "[compose.systemd] failed"}\nrollback failed: ${formatCaughtError(rollbackError)}`
    )
  }

  return parameters.originalFailure
}

/**
 * Generate the content of a systemd service unit file that manages a compose
 * stack via `ExecStart` / `ExecStop`.
 *
 * The generated unit depends on `docker.service` when the runtime is `docker`,
 * and only on `network-online.target` for `podman`.
 *
 * @param projectDirectory - The working directory for the compose commands.
 * @param name - The human-readable service description and unit name.
 * @param options - Unit generation parameters.
 * @param options.runtime - The container runtime (`docker` or `podman`).
 * @param options.detached - Whether `compose up` should run with `-d`.
 * @returns The full systemd unit file content as a string.
 */
function generateSystemdUnit(
  projectDirectory: string,
  name: string,
  options: { detached: boolean; runtime: ComposeRuntime }
): string {
  const safeName = sanitizeUnitValue(name)
  const safeDirectory = sanitizeUnitValue(projectDirectory)
  const composeUpCommand = options.detached
    ? `/usr/bin/env ${options.runtime} compose up -d --remove-orphans`
    : `/usr/bin/env ${options.runtime} compose up --remove-orphans`
  const lines = ["[Unit]", `Description=Compose stack: ${safeName}`, "Wants=network-online.target"]

  if (options.runtime === "docker") {
    lines.push("After=network-online.target docker.service")
    lines.push("Requires=docker.service")
  } else {
    lines.push("After=network-online.target")
  }

  lines.push(
    "",
    "[Service]",
    "Type=oneshot",
    "RemainAfterExit=yes",
    `WorkingDirectory=${safeDirectory}`,
    `ExecStart=${composeUpCommand}`,
    `ExecStop=/usr/bin/env ${options.runtime} compose down`,
    "TimeoutStartSec=0",
    "StandardOutput=journal",
    "StandardError=journal",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    ""
  )

  return lines.join("\n")
}

/**
 * Build the `check` function for `compose.config`.
 *
 * Reports `needs-apply` when:
 * - the connection is missing
 * - `compose.yml` is missing
 * - the desired content cannot be resolved
 * - the remote content differs from the desired content
 * - the remote mode has drifted from {@link COMPOSE_CONFIG_MODE}
 *
 * @param remotePath - Path to the remote `compose.yml`.
 * @param loadDesiredContent - Memoised loader for the desired compose
 *   content (R-0000756). Shared with apply so a local src change between
 *   check and apply cannot produce a check verdict that disagrees with
 *   the apply payload.
 * @returns A `check` callback for the module's `Module` object.
 */
function createComposeConfigCheck(
  remotePath: string,
  loadDesiredContent: () => Promise<null | string>
): (ssh: null | SshConnection) => Promise<"needs-apply" | "ok"> {
  return async (ssh) => {
    if (!ssh) return NEEDS_APPLY

    if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) return NEEDS_APPLY

    // R-0000756: share the cached desired content with apply so a local src
    // change between check and apply cannot produce a check verdict that
    // disagrees with the bytes apply later uploads.
    const desiredContent = await loadDesiredContent()
    if (desiredContent == null) return NEEDS_APPLY

    const remoteContent = await ssh.readFile(remotePath)
    if (remoteContent.trim() !== desiredContent.trim()) return NEEDS_APPLY

    // Detect manual mode drift (e.g. an operator ran `chmod 0644 compose.yml`):
    // even when the content matches, the apply path would re-set the mode,
    // so check must report needs-apply to keep the run idempotent.
    //
    // R-0000558: route the stat call through ssh.exec with ignoreExitCode so
    // a transient stat failure (file removed mid-check, EACCES, EIO, …)
    // collapses to NEEDS_APPLY instead of throwing a raw CommandError out of
    // check. Mirrors the crontab/R-0000272 pattern.
    const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(remotePath)}`, EXEC_OPTS)
    if (modeResult.code !== 0) return NEEDS_APPLY
    const remoteMode = modeResult.stdout.trim()
    return remoteMode === COMPOSE_CONFIG_MODE.replace(/^0+/v, "") ? "ok" : NEEDS_APPLY
  }
}

/**
 * Write the new compose.yml content to a staging path, leaving the active
 * `compose.yml` untouched until validation succeeds.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param stagingPath - Temporary destination for the new compose content.
 * @param desiredContent - R-0000756 cached desired content shared between
 *   check and apply so the staging file always carries the bytes that
 *   check inspected.
 */
async function writeComposeStagingFile(
  ssh: SshConnection,
  stagingPath: string,
  desiredContent: string
): Promise<void> {
  // R-0000756: write the cached desired content (resolved once via
  // `createCachedComposeContentResolver`) rather than re-reading
  // `options.src` here. Sharing one buffer between check and apply
  // prevents a local file change in the window between the two phases
  // from producing a check verdict that disagrees with the apply payload.
  await ssh.writeFile(stagingPath, desiredContent, { mode: COMPOSE_CONFIG_MODE })
}

async function validateStagedComposeFile(parameters: {
  projectDirectory: string
  runtime: ComposeRuntime
  ssh: SshConnection
  stagingPath: string
}): Promise<ModuleResult | null> {
  const { projectDirectory, runtime, ssh, stagingPath } = parameters
  // R-0000228: validate against the staging file with -f so a parallel
  // compose invocation reading <projectDirectory>/compose.yml never sees
  // a half-written or unvalidated revision.
  const validate = await ssh.exec(
    `${composeCommand(runtime, projectDirectory)} -f ${shellQuote(stagingPath)} config --quiet`,
    EXEC_OPTS
  )
  if (validate.code === 0) return null
  return failedCommand(`[compose.config] validation failed for ${projectDirectory}`, validate)
}

async function activateStagedComposeFile(
  ssh: SshConnection,
  stagingPath: string,
  remotePath: string
): Promise<ModuleResult | null> {
  // R-0000228: atomic rename so the active compose.yml flips from prior
  // to validated content in one syscall. mv -T refuses to descend into
  // an existing directory at remotePath, mirroring the safety we already
  // require for download.url destinations. The `--` stops option parsing
  // before path operands that may begin with "-".
  const move = await ssh.exec(
    `mv -T -- ${shellQuote(stagingPath)} ${shellQuote(remotePath)}`,
    EXEC_OPTS
  )
  if (move.code === 0) return null
  return failedCommand(`[compose.config] failed to activate validated compose file`, move)
}

async function removeComposeStagingFile(ssh: SshConnection, stagingPath: string): Promise<void> {
  // R-0000565: pass `--` so the staging path cannot be parsed as an `rm`
  // option if a future refactor weakens the staging-prefix validation.
  await ssh.exec(`rm -f -- ${shellQuote(stagingPath)}`, EXEC_OPTS)
}

async function createComposeStagingPath(parameters: {
  projectDirectory: string
  ssh: SshConnection
}): Promise<ModuleResult | string> {
  // R-0000565: pass the project directory via `-p` and separate the template
  // with `--` so a future refactor that loosens the staging prefix cannot let
  // an attacker-controlled value be interpreted as a `mktemp` option.
  const template = `${COMPOSE_CONFIG_STAGING_PREFIX}.XXXXXX`
  const result = await parameters.ssh.exec(
    `mktemp -p ${shellQuote(parameters.projectDirectory)} -- ${shellQuote(template)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[compose.config] mktemp failed for ${parameters.projectDirectory}`,
      result
    )
  }

  try {
    return validateMktempPath(
      parameters.projectDirectory,
      result.stdout.trim(),
      COMPOSE_CONFIG_STAGING_PREFIX
    )
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[compose.config] mktemp produced an unexpected path: ${reason}`)
  }
}

/**
 * R-0000530: refuse to stage into a project directory whose own path or any
 * ancestor is a symbolic link. Without this guard a symlinked
 * `projectDirectory` (or any ancestor in between) would let `mktemp` and the
 * subsequent `mv -T` write through the link, allowing an attacker who controls
 * the link target to steer the staged compose file — and the activated
 * compose.yml — into a directory of their choosing. Mirrors the ancestor
 * walk performed by `ensureDownloadDestinationNotSymlinked` in
 * `modules/download.ts`.
 *
 * @param ssh - The SSH connection.
 * @param projectDirectory - The compose project directory on the remote host.
 * @returns A failed ModuleResult on any symlink, or null when the path is safe.
 */
async function ensureComposeProjectDirectoryNotSymlinked(
  ssh: SshConnection,
  projectDirectory: string
): Promise<ModuleResult | null> {
  if (await isSymlink(ssh, projectDirectory)) {
    return failed(`[compose.config] projectDirectory is a symbolic link: ${projectDirectory}`)
  }
  let ancestor = dirname(projectDirectory)
  const seen = new Set<string>()
  while (ancestor !== "/" && ancestor !== "." && !seen.has(ancestor)) {
    seen.add(ancestor)
    // eslint-disable-next-line no-await-in-loop -- ancestor walk is sequential by nature
    if (await isSymlink(ssh, ancestor)) {
      return failed(
        `[compose.config] ancestor of projectDirectory ${projectDirectory} is a symbolic link: ${ancestor}`
      )
    }
    ancestor = dirname(ancestor)
  }
  return null
}

async function createSafeComposeStagingPath(parameters: {
  projectDirectory: string
  ssh: SshConnection
}): Promise<ModuleResult | string> {
  const symlinkFailure = await ensureComposeProjectDirectoryNotSymlinked(
    parameters.ssh,
    parameters.projectDirectory
  )
  if (symlinkFailure != null) return symlinkFailure
  return createComposeStagingPath(parameters)
}

async function applyComposeConfig(parameters: {
  loadDesiredContent: () => Promise<null | string>
  projectDirectory: string
  remotePath: string
  runtime: ComposeRuntime
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { loadDesiredContent, projectDirectory, remotePath, runtime, ssh } = parameters
  // R-0000530: validate symlink-free projectDirectory BEFORE creating the
  // staging path. createComposeStagingPath runs `mktemp` inside
  // projectDirectory; if the directory (or an ancestor) is a symlink, the
  // staging file lands in attacker-controlled territory and the subsequent
  // `mv -T` activates an unverified compose.yml at that location.
  const stagingPath = await createSafeComposeStagingPath({ projectDirectory, ssh })
  if (typeof stagingPath !== "string") return stagingPath

  // R-0000228: write into a staging file (not into compose.yml). The active
  // compose.yml is only replaced after validation succeeds, so a parallel
  // `compose up` cannot pick up an unvalidated config. The staging file is
  // also unique per apply and cleaned up if validation or anything else throws.
  try {
    // R-0000756: resolve the cached desired content after mktemp so the
    // existing failure ordering (mktemp-output validation, project-dir
    // symlink check) is preserved. The loader returns the same buffer
    // check() already observed, so the staging write and the check verdict
    // can never disagree about a local src file that mutated between phases.
    const desiredContent = await loadDesiredContent()
    if (desiredContent == null) {
      return failed(`[compose.config] content or src is required for ${projectDirectory}`)
    }
    await writeComposeStagingFile(ssh, stagingPath, desiredContent)
    const validationFailure = await validateStagedComposeFile({
      projectDirectory,
      runtime,
      ssh,
      stagingPath,
    })
    if (validationFailure != null) return validationFailure
    const activationFailure = await activateStagedComposeFile(ssh, stagingPath, remotePath)
    if (activationFailure != null) return activationFailure
  } finally {
    await removeComposeStagingFile(ssh, stagingPath)
  }

  return { status: "changed" }
}

/**
 * Modules for managing Docker Compose / Podman Compose stacks on a remote host.
 *
 * All methods auto-detect the container runtime (`docker` or `podman`) unless
 * an explicit `runtime` option is provided.
 */
export const compose = {
  /**
   * Ensure a compose-file is present at `<projectDirectory>/compose.yml`.
   *
   * Provide either `src` (a local file path to upload) or `content` (a string
   * to write). The check phase compares the remote file content with the
   * desired content and skips the apply if they match.
   *
   * @param options - Configuration for the compose file.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.src - Local file path to upload as `compose.yml`.
   * @param options.content - String content to write as `compose.yml`.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the compose file is present and valid.
   */
  config(options: {
    content?: string
    projectDirectory: string
    runtime?: ComposeRuntime
    src?: string
  }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options
    const remotePath = `${projectDirectory}/compose.yml`
    // R-0000756: cache the desired compose content once per Module instance
    // so check() and apply() always observe the same bytes — even when the
    // local `src` file is rewritten between the two phases. Mirrors
    // file.template's `cachedContent` pattern.
    const loadDesiredContent = createCachedComposeContentResolver(options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "config", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "config",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        if (
          (options.src === undefined || options.src === "") &&
          (options.content === undefined || options.content === "")
        ) {
          return failed(`[compose.config] content or src is required for ${projectDirectory}`)
        }

        return applyComposeConfig({
          loadDesiredContent,
          projectDirectory,
          remotePath,
          runtime,
          ssh: connection,
        })
      },
      check: createComposeConfigCheck(remotePath, loadDesiredContent),
      name: `compose.config: ${projectDirectory}`,
    }
  },

  /**
   * Tear down all containers in the compose stack. Optionally remove volumes.
   *
   * @param options - Configuration for the down operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.volumes - When `true`, also remove named volumes.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures all containers are stopped and removed.
   */
  down(options: { projectDirectory: string; runtime?: ComposeRuntime; volumes?: boolean }): Module {
    const { projectDirectory, runtime: explicitRuntime, volumes } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "down", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "down",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const volumesFlag = volumes === true ? " --volumes" : ""
        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} down${volumesFlag}`,
          EXEC_OPTS
        )
        if (result.code === 0) return { status: "changed" }
        // R-0000483: a non-existing compose project is equivalent to
        // already-down. The runtime exits non-zero with a recognisable
        // absent-signal — treat that as a successful no-op rather than a
        // failure that aborts the playbook.
        if (isComposeAbsentProject(result)) return { status: "ok" }
        return failedCommand(`[compose.down] failed for ${projectDirectory}`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, "down", explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} ps --format json`,
          EXEC_OPTS
        )
        if (result.code !== 0) {
          // R-0000483: treat a non-existing compose project as already-down so
          // the subsequent apply does not also fail. Without this guard a
          // missing compose.yml leaves apply to throw a hard failure.
          if (isComposeAbsentProject(result)) return "ok"
          return NEEDS_APPLY
        }

        const stdout = result.stdout.trim()
        if (stdout === "") {
          return checkComposeDownNoContainers({ projectDirectory, runtime: rt, ssh, volumes })
        }
        const states = parseContainerStates(stdout)
        if (states.length === 0 && stdout === "[]") {
          return checkComposeDownNoContainers({ projectDirectory, runtime: rt, ssh, volumes })
        }

        return NEEDS_APPLY
      },
      name: `compose.down: ${projectDirectory}`,
    }
  },

  /**
   * Pull the latest images for all services in the compose stack.
   * Signal-style: always applies since an efficient up-to-date check is not
   * feasible.
   *
   * @param options - Configuration for the pull operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that pulls the latest images.
   */
  pull(options: { projectDirectory: string; runtime?: ComposeRuntime }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "pull", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "pull",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} pull 2>&1`,
          EXEC_OPTS
        )
        if (result.code !== 0)
          return failedCommand(`[compose.pull] failed for ${projectDirectory}`, result)

        return { status: composePullReportedChange(result.stdout) ? "changed" : "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: `compose.pull: ${projectDirectory}`,
    }
  },

  /**
   * Restart all containers by running `down` followed by `up -d`.
   * Signal-style: always applies.
   *
   * @param options - Configuration for the restart operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that restarts the compose stack.
   */
  restart(options: { projectDirectory: string; runtime?: ComposeRuntime }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "restart", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "restart",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const cmd = composeCommand(runtime, projectDirectory)
        const result = await connection.exec(`${cmd} down && ${cmd} up -d`, EXEC_OPTS)
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[compose.restart] failed for ${projectDirectory}`, result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: `compose.restart: ${projectDirectory}`,
    }
  },

  /**
   * Generate and write a systemd service unit that manages the compose stack
   * via `ExecStart` / `ExecStop`.
   *
   * The service name defaults to `compose-<basename(projectDirectory)>` when not
   * explicitly provided.
   *
   * @param options - Configuration for the systemd unit.
   * @param options.detached - When true, use `compose up -d`; otherwise start attached.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.name - Optional service name (without `.service` suffix).
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the systemd unit file is present and up-to-date.
   */
  systemd(options: {
    detached?: boolean
    name?: string
    projectDirectory: string
    runtime?: ComposeRuntime
  }): Module {
    const { projectDirectory, runtime: explicitRuntime } = options
    const detached = options.detached ?? false
    const { filePath, serviceName, unitFileName } = resolveComposeSystemdIdentity({
      name: options.name,
      projectDirectory,
    })

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "systemd", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "systemd",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        // R-0000562: refuse non-absolute projectDirectory values before
        // generating the unit, so a relative path like `./srv` never
        // reaches `WorkingDirectory=` in a written unit file.
        const directoryFailure = validateComposeProjectDirectory(projectDirectory, unitFileName)
        if (directoryFailure != null) return directoryFailure

        const content = generateSystemdUnit(projectDirectory, serviceName, { detached, runtime })
        const validationFailure = validateGeneratedSystemdUnitContent(content, unitFileName)
        if (validationFailure != null) return validationFailure
        return applyComposeSystemdUnit({
          connection,
          content,
          filePath,
          unitFileName,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkComposeSystemdUnit({
          detached,
          explicitRuntime,
          filePath,
          projectDirectory,
          serviceName,
          ssh,
        })
      },
      name: `compose.systemd: ${unitFileName}`,
    }
  },

  /**
   * Ensure all services in the compose stack are running.
   *
   * The check phase inspects each container's state via `ps --format json`
   * and only skips when every service reports `"running"`.
   *
   * @param options - Configuration for the up operation.
   * @param options.projectDirectory - The project directory on the remote host.
   * @param options.services - Optional list of specific services to start.
   * @param options.runtime - Explicit container runtime override.
   * @returns A Module that ensures the compose stack is up.
   */
  up(options: { projectDirectory: string; runtime?: ComposeRuntime; services?: string[] }): Module {
    const { projectDirectory, runtime: explicitRuntime, services } = options
    validateComposeUpServices(services)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        const connection = requireComposeSsh(ssh, "up", projectDirectory)
        if ("status" in connection) return connection

        const runtime = await requireComposeRuntime({
          action: "up",
          explicitRuntime,
          projectDirectory,
          ssh: connection,
        })
        if (typeof runtime !== "string") return runtime

        const serviceArguments = services?.map((s) => shellQuote(s)).join(" ") ?? ""
        const suffix = serviceArguments === "" ? "" : ` ${serviceArguments}`
        // R-0000078: redirect stderr to stdout so the action keywords that
        // compose prints on stderr ("Creating", "Recreating", "Starting",
        // "Started", "Pulling") are observable, mirroring compose.pull's
        // approach.
        const result = await connection.exec(
          `${composeCommand(runtime, projectDirectory)} up -d${suffix} 2>&1`,
          EXEC_OPTS
        )
        if (result.code !== 0) {
          return failedCommand(`[compose.up] failed for ${projectDirectory}`, result)
        }

        return { status: composeUpReportedChange(result.stdout) ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const rt = await getRuntime(ssh, "up", explicitRuntime)
        if (!rt) return NEEDS_APPLY

        const serviceFilter = services?.map((s) => shellQuote(s)).join(" ") ?? ""
        const filterSuffix = serviceFilter === "" ? "" : ` ${serviceFilter}`
        const result = await ssh.exec(
          `${composeCommand(rt, projectDirectory)} ps --format json${filterSuffix}`,
          EXEC_OPTS
        )
        if (result.code !== 0) return NEEDS_APPLY

        const stdout = result.stdout.trim()
        if (stdout === "") return NEEDS_APPLY

        const states = parseContainerStates(stdout)
        if (states.length === 0) return NEEDS_APPLY

        return states.every((s) => s === "running") ? "ok" : NEEDS_APPLY
      },
      name: `compose.up: ${projectDirectory}`,
    }
  },
}
