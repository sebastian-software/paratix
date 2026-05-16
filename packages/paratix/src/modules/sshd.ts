/* eslint-disable max-lines -- sshd module keeps tightly coupled validation/restart helpers together */
import { randomUUID } from "node:crypto"

import { sshdPortMeta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { CommandError, shellQuote } from "../sshHelpers.js"
import {
  type ExecResult,
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  applySshdSettingToContent,
  collectTopLevelSshdDirectiveValues,
  findContradictingSshdMatchBlockOverride,
  findNonMatchingEffectiveSshdSetting,
  sshdSettingMatchesEverywhere,
} from "./sshdConfigHelpers.js"
import { classifyUfwAccessOrUnknown } from "./ufwStatus.js"

const DEFAULT_SSH_PORT = 22
const PRIVILEGE_SEPARATION_DIRECTORY = "/run/sshd"
const SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
const SSHD_CONFIG_MODE = "0644"
const SSHD_EFFECTIVE_CONFIG_COMMAND = "sshd -T"
const SYSTEMCTL = "systemctl"

type SshSocketState = { active: boolean; enabled: boolean; exists: true } | { exists: false }

type SshdServiceUnit = "ssh" | "sshd"

type SshdServiceBootState = { enabled: boolean; unit: SshdServiceUnit }

// sshd_config(5) directive names are alphabetic ASCII identifiers (the parser
// is case-insensitive). Constraining keys to this shape prevents callers from
// smuggling regex/shell metacharacters or whitespace into the rewriter.
const SSHD_DIRECTIVE_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9]*$/v

function validateSshdSettings(settings: Record<string, string>): void {
  for (const [key, value] of Object.entries(settings)) {
    if (!SSHD_DIRECTIVE_NAME_PATTERN.test(key)) {
      throw new Error(
        `sshd.config: invalid directive name ${JSON.stringify(key)} ` +
          `(expected an alphabetic ASCII identifier, e.g. "PasswordAuthentication")`
      )
    }
    if (key.toLowerCase() === "port") {
      throw new Error(
        `sshd.config: directive ${JSON.stringify(key)} is managed by sshd.port(...); ` +
          "use sshd.port(...) to change the SSH listen port safely"
      )
    }
    if (/[\n\r]/v.test(value)) {
      throw new Error(
        `sshd.config: value for ${key} must not contain newline characters: ${JSON.stringify(value)}`
      )
    }
  }
}

// R-0000539: validate the prospective sshd_config before /etc/ssh/sshd_config
// is overwritten. The previous flow wrote the new file first and ran `sshd -t`
// against it, then rolled back with a second write on failure. That approach
// is not atomic, has no mutex, and could leave the live config diverged when
// the rollback write itself failed (e.g. SFTP disconnect). Running
// `sshd -t -f <tempfile>` up front lets us reject syntactically invalid
// configurations without ever touching `/etc/ssh/sshd_config`.
async function validateProspectiveSshdConfigOrFailed(
  ssh: SshConnection,
  parameters: { newContent: string; settingNames: string }
): Promise<ModuleResult | undefined> {
  const failure = await validateProspectiveSshdConfig(ssh, parameters.newContent)
  if (failure == null) return undefined
  const stderr =
    failure.error instanceof CommandError
      ? failure.error.fullStderr
      : (failure.error?.message ?? "")
  return failed(
    `[sshd.config: ${parameters.settingNames}] sshd config validation failed ` +
      `(sshd -t against prospective config); not written:\n${stderr}`
  )
}

async function readEffectiveSshdConfig(ssh: SshConnection): Promise<ExecResult> {
  await ensurePrivilegeSeparationDirectory(ssh)
  return ssh.exec(SSHD_EFFECTIVE_CONFIG_COMMAND, { ignoreExitCode: true, silent: true })
}

// R-0000553: `sshd -T` aborts with non-zero exit codes for two very different
// classes of failure:
//   * Real drift: a syntax error or directive value sshd refuses to load.
//   * Permission denied: a non-root operator cannot read the host keys or the
//     privilege-separation directory.
// Silently mapping both to "first directive does not match" caused endless
// apply loops on hosts the runner could not properly inspect. Detect the
// permission-denied family up front so callers can surface it as a hard
// failure with a useful diagnostic instead of pretending the config drifted.
const SSHD_PERMISSION_ERROR_PATTERNS: RegExp[] = [
  /permission denied/iv,
  /must be run as root/iv,
  /could not (?:open|read).+host key/iv,
  /unable to open host key/iv,
  /unable to read.+host key/iv,
  /you are not root/iv,
  /operation not permitted/iv,
]

// `ssh` itself uses exit code 255 to signal connection or transport errors
// (the wrapped remote command never gets to choose this code). When `sshd -T`
// fails with 255 plus a non-empty stderr, the runner reached the host but the
// privileged sub-shell was rejected; treat it as a permission error.
const SSH_TRANSPORT_FAILURE_EXIT_CODE = 255

function sshdEffectiveConfigPermissionError(result: ExecResult): string | undefined {
  const haystack = `${result.stderr}\n${result.stdout}`
  if (result.code === SSH_TRANSPORT_FAILURE_EXIT_CODE && result.stderr.trim() !== "") {
    return result.stderr.trim()
  }
  for (const pattern of SSHD_PERMISSION_ERROR_PATTERNS) {
    if (pattern.test(haystack)) return result.stderr.trim() || result.stdout.trim()
  }
  return undefined
}

const PERMISSION_ERROR_KIND = "permission-error" as const

type EffectiveSshdConfigMismatch =
  | { detail: string; kind: typeof PERMISSION_ERROR_KIND }
  | { directive: string; kind: "mismatch" }
  | { kind: "match" }

async function findEffectiveSshdConfigMismatch(
  ssh: SshConnection,
  settings: Record<string, string>
): Promise<EffectiveSshdConfigMismatch> {
  const result = await readEffectiveSshdConfig(ssh)
  if (result.code !== 0) {
    const permissionDetail = sshdEffectiveConfigPermissionError(result)
    if (permissionDetail != null) {
      return { detail: permissionDetail, kind: PERMISSION_ERROR_KIND }
    }
    const firstDirective = Object.keys(settings)[0] ?? ""
    return { directive: firstDirective, kind: "mismatch" }
  }
  const directive = findNonMatchingEffectiveSshdSetting(result.stdout, settings)
  if (directive == null) return { kind: "match" }
  return { directive, kind: "mismatch" }
}

// R-0000542: retry the rollback write a small number of times so a single
// transient SFTP hiccup does not leave `/etc/ssh/sshd_config` diverged. Mirrors
// the lightweight retry shape used in other apply-then-rollback paths.
const SSHD_ROLLBACK_WRITE_ATTEMPTS = 3
const SSHD_ROLLBACK_WRITE_BACKOFF_MS = 200

async function writeSshdRollbackWithRetry(
  ssh: SshConnection,
  originalConfig: string
): Promise<string | undefined> {
  let lastError: unknown
  for (let attempt = 1; attempt <= SSHD_ROLLBACK_WRITE_ATTEMPTS; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop -- sequential retry by design
      await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig, { mode: SSHD_CONFIG_MODE })
      return undefined
    } catch (error) {
      lastError = error
      if (attempt === SSHD_ROLLBACK_WRITE_ATTEMPTS) break
      // eslint-disable-next-line no-await-in-loop -- sequential retry by design
      await new Promise<void>((resolve) => {
        setTimeout(resolve, SSHD_ROLLBACK_WRITE_BACKOFF_MS)
      })
    }
  }
  return lastError instanceof Error ? lastError.message : String(lastError)
}

async function verifySshdConfigMatchesRollback(
  ssh: SshConnection,
  originalConfig: string
): Promise<string | undefined> {
  try {
    const current = await ssh.readFile(SSHD_CONFIG_PATH)
    if (current === originalConfig) return undefined
    return "remote sshd_config content does not match the previous configuration after rollback"
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return `could not verify rollback content: ${message}`
  }
}

async function rollbackSshdConfigAfterEffectiveMismatch(
  ssh: SshConnection,
  parameters: { baseMessage: string; originalConfig: string }
): Promise<ModuleResult> {
  // R-0000542: previously this performed a single best-effort rollback write
  // with no verification. A second SFTP failure left sshd_config diverged
  // without surfacing the breakage. Retry the write a few times and then
  // re-read the file to confirm the rollback actually landed; surface the
  // divergence loudly otherwise.
  const writeError = await writeSshdRollbackWithRetry(ssh, parameters.originalConfig)
  if (writeError != null) {
    return failedCommand(
      `${parameters.baseMessage}; rollback write to ${SSHD_CONFIG_PATH} failed`,
      {
        code: -1,
        stderr: writeError,
        stdout: "",
      }
    )
  }
  const verifyError = await verifySshdConfigMatchesRollback(ssh, parameters.originalConfig)
  if (verifyError != null) {
    return failedCommand(
      `${parameters.baseMessage}; rollback wrote but verification failed ` +
        "(sshd_config may be diverged)",
      {
        code: -1,
        stderr: verifyError,
        stdout: "",
      }
    )
  }
  return failed(`${parameters.baseMessage}; rolled back to previous config`)
}

async function rejectNonMatchingEffectiveSshdConfig(
  ssh: SshConnection,
  parameters: { didChange: boolean; originalConfig: string; settings: Record<string, string> }
): Promise<ModuleResult | undefined> {
  const mismatch = await findEffectiveSshdConfigMismatch(ssh, parameters.settings)
  if (mismatch.kind === "match") return undefined
  if (mismatch.kind === PERMISSION_ERROR_KIND) {
    // R-0000553: `sshd -T` could not be evaluated (typically because the
    // operator lacks the privileges to read host keys). Surface the failure
    // explicitly so the apply loop terminates instead of repeatedly writing
    // and rolling back the same config.
    const settingNames = Object.keys(parameters.settings).join(", ")
    const permissionMessage =
      `[sshd.config: ${settingNames}] could not verify effective sshd configuration via ` +
      `\`${SSHD_EFFECTIVE_CONFIG_COMMAND}\` (insufficient privileges?): ${mismatch.detail}`
    if (!parameters.didChange) {
      return failed(permissionMessage)
    }
    // R-0000585: the prospective config has already been written to
    // /etc/ssh/sshd_config (`didChange === true`). Returning `failed(...)`
    // without rolling back would leave the new content active and the next
    // sshd reload would pick it up. Mirror the mismatch branch and restore
    // `originalConfig` first, then surface the permission failure.
    return rollbackSshdConfigAfterEffectiveMismatch(ssh, {
      baseMessage: permissionMessage,
      originalConfig: parameters.originalConfig,
    })
  }

  const mismatchMessage =
    `[sshd.config: ${mismatch.directive}] effective sshd configuration ` +
    "does not match the requested value after parsing includes"
  if (!parameters.didChange) {
    return failed(mismatchMessage)
  }

  return rollbackSshdConfigAfterEffectiveMismatch(ssh, {
    baseMessage: mismatchMessage,
    originalConfig: parameters.originalConfig,
  })
}

async function ensurePrivilegeSeparationDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${shellQuote(PRIVILEGE_SEPARATION_DIRECTORY)}`, {
    ignoreExitCode: false,
    silent: true,
  })
}

async function captureSshSocketState(ssh: SshConnection): Promise<SshSocketState> {
  // R-0000492: rely on `silent: true` to swallow stdout/stderr instead of
  // embedding shell redirects in the command string. Keeps the helper
  // consistent with the rest of the codebase and avoids shell-metacharacter
  // surprises.
  const socketExists = await ssh.exec("systemctl cat ssh.socket", {
    ignoreExitCode: true,
    silent: true,
  })
  if (socketExists.code !== 0) return { exists: false }

  const enabled = await ssh.exec("systemctl is-enabled --quiet ssh.socket", {
    ignoreExitCode: true,
    silent: true,
  })
  const active = await ssh.exec("systemctl is-active --quiet ssh.socket", {
    ignoreExitCode: true,
    silent: true,
  })

  return {
    active: active.code === 0,
    enabled: enabled.code === 0,
    exists: true,
  }
}

async function disableSocketActivatedSsh(ssh: SshConnection): Promise<SshSocketState> {
  const socketState = await captureSshSocketState(ssh)
  if (!socketState.exists) return socketState

  await ssh.exec("systemctl disable --now ssh.socket", {
    ignoreExitCode: false,
    silent: true,
  })
  return socketState
}

async function restoreSocketActivatedSsh(
  ssh: SshConnection,
  socketState: SshSocketState
): Promise<void> {
  if (!socketState.exists) return
  if (socketState.enabled && socketState.active) {
    await ssh.exec("systemctl enable --now ssh.socket", { ignoreExitCode: false, silent: true })
    return
  }
  if (socketState.enabled) {
    await ssh.exec("systemctl enable ssh.socket", { ignoreExitCode: false, silent: true })
  }
  if (socketState.active) {
    await ssh.exec("systemctl start ssh.socket", { ignoreExitCode: false, silent: true })
  }
}

async function resolveSshServiceUnit(ssh: SshConnection): Promise<SshdServiceUnit> {
  // R-0000492: drop shell redirects and rely on `silent: true` for output
  // suppression, matching the codebase convention.
  const sshdExists = await ssh.exec(`${SYSTEMCTL} cat sshd.service`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (sshdExists.code === 0) {
    return "sshd"
  }

  const sshExists = await ssh.exec(`${SYSTEMCTL} cat ssh.service`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (sshExists.code === 0) {
    return "ssh"
  }

  throw new Error(
    "[sshd] could not find a systemd SSH service unit (tried sshd.service and ssh.service)"
  )
}

async function sshServiceBootState(
  ssh: SshConnection,
  serviceUnit: SshdServiceUnit
): Promise<SshdServiceBootState> {
  const enabled = await ssh.exec(`${SYSTEMCTL} is-enabled --quiet ${serviceUnit}.service`, {
    ignoreExitCode: true,
    silent: true,
  })
  return { enabled: enabled.code === 0, unit: serviceUnit }
}

async function ensureSshServiceBootEnabled(
  ssh: SshConnection,
  parameters: { serviceUnit: SshdServiceUnit; socketState: SshSocketState }
): Promise<SshdServiceBootState> {
  const bootState = await sshServiceBootState(ssh, parameters.serviceUnit)
  if (parameters.socketState.exists && parameters.socketState.enabled && !bootState.enabled) {
    await ssh.exec(`${SYSTEMCTL} enable ${parameters.serviceUnit}.service`, {
      ignoreExitCode: false,
      silent: true,
    })
  }
  return bootState
}

async function restoreSshServiceBootState(
  ssh: SshConnection,
  bootState: SshdServiceBootState | undefined
): Promise<void> {
  if (bootState == null || bootState.enabled) return
  await ssh.exec(`${SYSTEMCTL} disable ${bootState.unit}.service`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function socketActivationBootPathNeedsApply(ssh: SshConnection): Promise<boolean> {
  const socketState = await captureSshSocketState(ssh)
  if (!socketState.exists || !socketState.enabled) return false
  const serviceUnit = await resolveSshServiceUnit(ssh)
  const bootState = await sshServiceBootState(ssh, serviceUnit)
  return !bootState.enabled
}

// R-0000284: wrap the rollback write so an SFTP failure cannot mask the
// original reload failure. validateSshdConfig already follows the same
// pattern (R-0000249) — surface a combined error that names both causes
// instead of letting the rollback exception bubble up.
async function rollbackSshdConfigAfterReloadFailure(
  ssh: SshConnection,
  parameters: { originalConfig: string; reloadResult: ModuleResult; settingNames: string }
): Promise<ModuleResult> {
  try {
    await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
    return parameters.reloadResult
  } catch (rollbackError) {
    const reloadMessage = parameters.reloadResult.error?.message ?? "sshd reload failed"
    const rollbackMessage =
      rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
    return failed(
      `[sshd.config: ${parameters.settingNames}] sshd reload failed; rollback also failed: ` +
        `${rollbackMessage}\n${reloadMessage}`
    )
  }
}

async function sshdUnitDefinesExecReload(
  ssh: SshConnection,
  serviceUnit: SshdServiceUnit
): Promise<boolean> {
  // `systemctl cat` prints the merged unit definition; grep for a top-level
  // `ExecReload=` directive. The check is best-effort: any non-zero exit
  // (e.g. the unit being absent) falls back to "no ExecReload".
  const result = await ssh.exec(
    `${SYSTEMCTL} cat ${shellQuote(serviceUnit)} | grep -E '^ExecReload='`,
    { ignoreExitCode: true, silent: true }
  )
  return result.code === 0 && result.stdout.trim().length > 0
}

async function reloadSshd(
  ssh: SshConnection,
  preflightServiceUnit?: SshdServiceUnit
): Promise<ModuleResult> {
  const serviceUnit = preflightServiceUnit ?? (await resolveSshServiceUnit(ssh))
  // R-0000496: when the unit has no `ExecReload=` directive, `systemctl reload`
  // exits non-zero and would trigger an unnecessary rollback. Fall back to
  // `reload-or-restart` so the daemon picks up the new config either way.
  // The rollback semantics are kept in case `reload-or-restart` itself fails
  // (e.g. sshd config syntax issue at startup).
  const hasExecReload = await sshdUnitDefinesExecReload(ssh, serviceUnit)
  const action = hasExecReload ? "reload" : "reload-or-restart"
  const result = await ssh.exec(`${SYSTEMCTL} ${action} ${serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? { status: "changed" }
    : failedCommand(`[sshd.config] systemctl ${action} ${serviceUnit} failed`, result)
}

async function preflightSshdReloadUnit(
  ssh: SshConnection,
  settingNames: string
): Promise<ModuleResult | SshdServiceUnit> {
  try {
    return await resolveSshServiceUnit(ssh)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return failed(`[sshd.config: ${settingNames}] ${message}`)
  }
}

// R-0000541: parse the `users:(("PROC",...))` entries from `ss -ltnp` instead
// of running a bare substring match against the entire row. Without the
// structural parse a user-level process called `sshd-fake` or a comment
// containing the literal text `sshd` would satisfy the regex even though no
// real sshd is bound. Only `sshd` (direct service) and `systemd` (socket
// activation hands the listening socket to systemd-pid-1) are accepted as
// owners.
const SS_USERS_PROCESS_PATTERN = /users:\(\("(?<name>[^"]+)"[^\)]*\)/gv
const SSHD_OWNER_NAMES = new Set(["sshd", "systemd"])

function extractSsListenerProcessNames(output: string): string[] {
  const names: string[] = []
  for (const match of output.matchAll(SS_USERS_PROCESS_PATTERN)) {
    const name = match.groups?.name
    if (name != null) names.push(name)
  }
  return names
}

async function liveSshdPortMatches(ssh: SshConnection, targetPort: number): Promise<boolean> {
  const result = await ssh.exec(`ss -H -ltnp 'sport = :${String(targetPort)}'`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return false
  const output = result.stdout.trim()
  if (output === "") return false
  const processNames = extractSsListenerProcessNames(output)
  if (processNames.length === 0) return false
  return processNames.some((name) => SSHD_OWNER_NAMES.has(name))
}

async function sshdPortConfigMatchesLive(ssh: SshConnection, targetPort: number): Promise<boolean> {
  if (await socketActivationBootPathNeedsApply(ssh)) return false
  return liveSshdPortMatches(ssh, targetPort)
}

async function restoreSshdPortRestartFailure(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
  }
): Promise<void> {
  await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
  await restoreSshServiceBootState(ssh, parameters.serviceBootState)
  await restoreSocketActivatedSsh(ssh, parameters.socketState)
  if (parameters.serviceUnit == null) return
  await ssh.exec(`${SYSTEMCTL} restart ${parameters.serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

// R-0000557: a successful `systemctl restart` may still fail the post-restart
// live-port verification (`waitForLiveSshdPort`). On socket-activated hosts
// the restart path has already disabled `ssh.socket` and, if necessary,
// enabled the service for boot. The verification rollback therefore needs the
// same `socketState`/`serviceBootState`/`serviceUnit` snapshot as
// `recoverFromRestartFailure` so it can restore all three layers — failing to
// do so leaves `ssh.socket` permanently disabled on Debian 12 / Ubuntu 22.04
// LTS and produces a reboot-time SSH lockout.
type SshdRestartSnapshot = {
  serviceBootState?: SshdServiceBootState
  serviceUnit?: SshdServiceUnit
  socketState: SshSocketState
}

type SshdRestartOutcome =
  | { kind: "completed"; snapshot: SshdRestartSnapshot }
  | { kind: "disconnected"; snapshot: SshdRestartSnapshot }

async function recoverFromRestartFailure(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
    targetPort: number
  }
): Promise<void> {
  // Drop the port marker first and unconditionally: if any subsequent restore
  // step throws (e.g. SFTP failure rewriting sshd_config), the runner still
  // needs to fall back to the previous port instead of staying on the new one
  // we never managed to activate.
  try {
    ssh.removePort(parameters.targetPort)
  } catch {
    // ssh.removePort is a synchronous in-memory bookkeeping call; we still
    // swallow defensively so an exotic implementation never blocks the
    // remaining restore steps.
  }
  try {
    await restoreSshdPortRestartFailure(ssh, {
      originalConfig: parameters.originalConfig,
      serviceBootState: parameters.serviceBootState,
      serviceUnit: parameters.serviceUnit,
      socketState: parameters.socketState,
    })
  } catch {
    // Best-effort recovery: the original restart failure (re-thrown by the
    // caller) is the actionable error. A nested restore failure must not
    // mask it nor leave the port marker in place.
  }
}

async function restartSshdOnNewPort(
  ssh: SshConnection,
  targetPort: number,
  originalConfig: string
): Promise<ModuleResult | SshdRestartOutcome> {
  ssh.addPort(targetPort)
  let socketState: SshSocketState = { exists: false }
  let serviceUnit: SshdServiceUnit | undefined
  let serviceBootState: SshdServiceBootState | undefined
  try {
    socketState = await disableSocketActivatedSsh(ssh)
    serviceUnit = await resolveSshServiceUnit(ssh)
    serviceBootState = await ensureSshServiceBootEnabled(ssh, { serviceUnit, socketState })
    await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, { silent: true })
    return {
      kind: "completed",
      snapshot: { serviceBootState, serviceUnit, socketState },
    }
  } catch (error) {
    // R-0000283: when the restart aborted the SSH session itself, treat the
    // disconnect as a successful restart. The runner reconnects on the new
    // port; downstream live-verification cannot run on a dead connection.
    if (isRestartDisconnect(error)) {
      return {
        kind: "disconnected",
        snapshot: { serviceBootState, serviceUnit, socketState },
      }
    }
    await recoverFromRestartFailure(ssh, {
      originalConfig,
      serviceBootState,
      serviceUnit,
      socketState,
      targetPort,
    })
    const message = error instanceof Error ? error.message : String(error)
    return failed(
      `[sshd.port: ${String(targetPort)}] sshd restart failed; ` +
        `rolled back to previous config and port: ${message}`
    )
  }
}

// R-0000283: poll `liveSshdPortMatches` for a short window so a slow systemd
// transition can settle before we declare the restart a failure. Bind
// conflicts and stale drop-ins make sshd come back without binding the
// target port; the polling loop catches that drift before the runner
// reconnects into the void.
const LIVE_VERIFY_TIMEOUT_MS = 5000
const LIVE_VERIFY_BACKOFF_MS = 250

async function waitForLiveSshdPort(ssh: SshConnection, targetPort: number): Promise<boolean> {
  const deadline = Date.now() + LIVE_VERIFY_TIMEOUT_MS
  for (;;) {
    // eslint-disable-next-line no-await-in-loop -- sequential probes by design
    if (await liveSshdPortMatches(ssh, targetPort)) return true
    if (Date.now() >= deadline) return false
    // eslint-disable-next-line no-await-in-loop -- sequential probes by design
    await new Promise<void>((resolve) => {
      setTimeout(resolve, LIVE_VERIFY_BACKOFF_MS)
    })
  }
}

async function runRollbackStep(step: () => Promise<void>): Promise<string | undefined> {
  try {
    await step()
    return undefined
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

async function rollbackSshdPortAfterFailedVerification(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    snapshot: SshdRestartSnapshot
    targetPort: number
  }
): Promise<string | undefined> {
  try {
    ssh.removePort(parameters.targetPort)
  } catch {
    // ssh.removePort is in-memory bookkeeping; never block rollback.
  }
  // R-0000557: `restartSshdOnNewPort` has already mutated `ssh.socket`
  // (disabled it) and may have flipped the service unit's boot state. The
  // post-restart verification rollback must restore both, otherwise a host
  // running socket-activated ssh (Debian 12, Ubuntu 22.04 LTS) reboots into a
  // disabled ssh.socket and locks the operator out. Mirror the recovery shape
  // used by `recoverFromRestartFailure` so all three rollback layers
  // (sshd_config, socket-state, service-boot-state) land before we kick the
  // service.
  const steps: Array<() => Promise<void>> = [
    async () => {
      await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
    },
    async () => {
      await restoreSshServiceBootState(ssh, parameters.snapshot.serviceBootState)
    },
    async () => {
      await restoreSocketActivatedSsh(ssh, parameters.snapshot.socketState)
    },
    async () => {
      const serviceUnit = parameters.snapshot.serviceUnit ?? (await resolveSshServiceUnit(ssh))
      await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, { ignoreExitCode: true, silent: true })
    },
  ]
  for (const step of steps) {
    // eslint-disable-next-line no-await-in-loop -- restore steps must run sequentially so each layer rolls back before the next.
    const failure = await runRollbackStep(step)
    if (failure !== undefined) return failure
  }
  return undefined
}

// R-0000586: known remote-mutation side-effects of the apply-time variant
// of this helper:
//   * `ensurePrivilegeSeparationDirectory` runs `mkdir -p /run/sshd` so
//     `sshd -t -f` can verify the privilege-separation directory exists. The
//     apply path is allowed to perform this (it is about to write the live
//     config anyway), and Debian/Ubuntu sshd packaging owns the directory.
//   * `ssh.writeFile` creates `/tmp/paratix-sshd-dry-run-<uuid>.conf`; the
//     `finally` block removes it again.
// The dry-run entry point (`dryRunSshdConfig`) must not perform either
// mutation — see `validateProspectiveSshdConfigForDryRun` below.
// R-0000587: prospective sshd_config tempfiles are created in world-readable
// `/tmp`. The live `/etc/ssh/sshd_config` is conventionally 0644, but the
// prospective copy may carry unreleased `AllowUsers` / `Match` /
// `AuthorizedKeysCommand` etc. directives that should not leak to other local
// users for the short window before the `rm -f` in the `finally` block runs.
// Pin the tempfile mode to 0600 so only root (and the writing identity) can
// read it; the live config keeps the conventional 0644 mode in
// guardedWriteFile callers.
const SSHD_DRY_RUN_TEMP_MODE = "0600"

async function validateProspectiveSshdConfig(
  ssh: SshConnection,
  content: string
): Promise<ModuleResult | undefined> {
  const temporaryConfigPath = `/tmp/paratix-sshd-dry-run-${randomUUID()}.conf`
  try {
    await ssh.writeFile(temporaryConfigPath, content, { mode: SSHD_DRY_RUN_TEMP_MODE })
    await ensurePrivilegeSeparationDirectory(ssh)
    const result = await ssh.exec(`sshd -t -f ${shellQuote(temporaryConfigPath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (result.code === 0) {
      return undefined
    }
    return failedCommand("[sshd dry-run] sshd -t failed for prospective config", result)
  } finally {
    await ssh.exec(`rm -f ${shellQuote(temporaryConfigPath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
  }
}

// R-0000586: probe whether `/run/sshd` already exists without mutating the
// remote filesystem. Used by the dry-run path so we never invoke `mkdir -p`
// from a non-mutating planning step.
async function privilegeSeparationDirectoryExists(ssh: SshConnection): Promise<boolean> {
  const result = await ssh.exec(`test -d ${shellQuote(PRIVILEGE_SEPARATION_DIRECTORY)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
}

// R-0000586: dry-run-safe variant of `validateProspectiveSshdConfig`. The
// regular variant performs `mkdir -p /run/sshd` to ensure sshd -t can read
// the privilege-separation directory. Dry-run must not mutate the host:
// probe `/run/sshd` non-destructively and skip the sshd -t step when it is
// absent, returning a `skipped` status so the operator sees the dry-run
// cannot verify the prospective config under the current host state.
async function validateProspectiveSshdConfigForDryRun(
  ssh: SshConnection,
  content: string
): Promise<ModuleResult | undefined> {
  if (!(await privilegeSeparationDirectoryExists(ssh))) {
    return {
      _dryRunDetail:
        "(dry-run skipped: /run/sshd missing — `sshd -t` cannot run without the " +
        "privilege-separation directory; not creating it from a dry-run)",
      status: "skipped",
    }
  }
  const temporaryConfigPath = `/tmp/paratix-sshd-dry-run-${randomUUID()}.conf`
  try {
    // R-0000587: same `0600` restriction as `validateProspectiveSshdConfig`.
    await ssh.writeFile(temporaryConfigPath, content, { mode: SSHD_DRY_RUN_TEMP_MODE })
    const result = await ssh.exec(`sshd -t -f ${shellQuote(temporaryConfigPath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (result.code === 0) {
      return undefined
    }
    return failedCommand("[sshd dry-run] sshd -t failed for prospective config", result)
  } finally {
    await ssh.exec(`rm -f ${shellQuote(temporaryConfigPath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
  }
}

async function dryRunSshdConfig(
  ssh: SshConnection,
  newContent: string,
  successDetail: string
): Promise<ModuleResult> {
  const validationFailure = await validateProspectiveSshdConfigForDryRun(ssh, newContent)
  if (validationFailure != null) {
    return validationFailure
  }

  return {
    _dryRunDetail: successDetail,
    status: "changed",
  }
}

function isRestartDisconnect(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return (
    message.includes("SSH connection closed") ||
    message.includes("ECONNRESET") ||
    message.includes("Connection reset")
  )
}

function buildSshdConfigContent(
  originalConfig: string,
  settings: Record<string, string>
): { didChange: boolean; newContent: string } {
  let newContent = originalConfig
  for (const [key, value] of Object.entries(settings)) {
    newContent = applySshdSettingToContent(newContent, key, value)
  }
  return { didChange: newContent !== originalConfig, newContent }
}

async function writeSshdConfigIfChanged(
  ssh: SshConnection,
  parameters: {
    didChange: boolean
    newContent: string
    originalConfig: string
    settingNames: string
  }
): Promise<ModuleResult | undefined> {
  if (!parameters.didChange) return undefined
  try {
    await guardedWriteFile(ssh, {
      mode: SSHD_CONFIG_MODE,
      newContent: parameters.newContent,
      originalContent: parameters.originalConfig,
      remotePath: SSHD_CONFIG_PATH,
    })
    return undefined
  } catch (error) {
    const writeMessage = error instanceof Error ? error.message : String(error)
    const rollbackDetail = await rollbackSshdConfigAfterWriteFailure(ssh, parameters)
    return failed(
      `[sshd.config: ${parameters.settingNames}] sshd config write failed; ` +
        `${rollbackDetail}: ${writeMessage}`
    )
  }
}

async function rollbackSshdConfigAfterWriteFailure(
  ssh: SshConnection,
  parameters: { newContent: string; originalConfig: string }
): Promise<string> {
  try {
    const currentConfig = await ssh.readFile(SSHD_CONFIG_PATH)
    if (currentConfig !== parameters.newContent) {
      return "remote config did not match the requested content after the failed write"
    }
  } catch (error) {
    const readMessage = error instanceof Error ? error.message : String(error)
    return `could not verify remote config after the failed write: ${readMessage}`
  }

  try {
    await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
    return "rolled back to previous config"
  } catch (error) {
    const rollbackMessage = error instanceof Error ? error.message : String(error)
    return `rollback also failed: ${rollbackMessage}`
  }
}

async function preflightSshdReloadUnitIfChanged(
  ssh: SshConnection,
  parameters: { didChange: boolean; settingNames: string }
): Promise<ModuleResult | SshdServiceUnit | undefined> {
  if (!parameters.didChange) return undefined
  return preflightSshdReloadUnit(ssh, parameters.settingNames)
}

async function reloadChangedSshdConfig(
  ssh: SshConnection,
  parameters: {
    didChange: boolean
    originalConfig: string
    serviceUnit?: SshdServiceUnit
    settingNames: string
  }
): Promise<ModuleResult> {
  if (!parameters.didChange) return { status: "ok" }
  const reloadResult = await reloadSshd(ssh, parameters.serviceUnit)
  if (reloadResult.status !== "failed") return reloadResult
  return rollbackSshdConfigAfterReloadFailure(ssh, {
    originalConfig: parameters.originalConfig,
    reloadResult,
    settingNames: parameters.settingNames,
  })
}

async function applySshdConfig(
  ssh: SshConnection,
  parameters: { settingNames: string; settings: Record<string, string> }
): Promise<ModuleResult> {
  const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
  const { didChange, newContent } = buildSshdConfigContent(originalConfig, parameters.settings)
  const nonConvergingMatchOverride = rejectNonConvergingSshdMatchOverrides(
    newContent,
    parameters.settings
  )
  if (nonConvergingMatchOverride != null) return nonConvergingMatchOverride

  const serviceUnit = await preflightSshdReloadUnitIfChanged(ssh, {
    didChange,
    settingNames: parameters.settingNames,
  })
  if (serviceUnit != null && typeof serviceUnit !== "string") return serviceUnit

  // R-0000539: validate the prospective config (in a tempfile) before
  // overwriting `/etc/ssh/sshd_config`. A syntactically invalid config is
  // rejected without ever touching the live file, eliminating the post-write
  // rollback path.
  if (didChange) {
    const prospectiveFailure = await validateProspectiveSshdConfigOrFailed(ssh, {
      newContent,
      settingNames: parameters.settingNames,
    })
    if (prospectiveFailure != null) return prospectiveFailure
  }

  const writeFailure = await writeSshdConfigIfChanged(ssh, {
    didChange,
    newContent,
    originalConfig,
    settingNames: parameters.settingNames,
  })
  if (writeFailure != null) return writeFailure

  const effectiveConfigFailure = await rejectNonMatchingEffectiveSshdConfig(ssh, {
    didChange,
    originalConfig,
    settings: parameters.settings,
  })
  if (effectiveConfigFailure != null) return effectiveConfigFailure

  return reloadChangedSshdConfig(ssh, {
    didChange,
    originalConfig,
    serviceUnit,
    settingNames: parameters.settingNames,
  })
}

function buildSshdPortContent(
  originalConfig: string,
  targetPort: number
): { didChange: boolean; newContent: string } {
  return buildSshdConfigContent(originalConfig, { Port: String(targetPort) })
}

function rejectNonConvergingSshdMatchOverrides(
  content: string,
  settings: Record<string, string>
): ModuleResult | undefined {
  const directive = findContradictingSshdMatchBlockOverride(content, settings)
  if (directive == null) return undefined

  return failed(
    `[sshd.config: ${directive}] conflicting security-relevant Match-block override ` +
      "would remain after apply; update or remove the override manually"
  )
}

function ufwBlocksPortFailure(targetPort: number): ModuleResult {
  return failed(
    `[sshd.port: ${String(targetPort)}] ufw is active but port ${String(targetPort)} is not ` +
      `allowed; add 'ufw.rule("allow", ${String(targetPort)})' before sshd.port to avoid lockout`
  )
}

function unknownUfwStatusFailure(targetPort: number): ModuleResult {
  return failed(
    `[sshd.port: ${String(targetPort)}] could not determine ufw status; verify the firewall ` +
      `state or add 'ufw.rule("allow", ${String(targetPort)})' before sshd.port to avoid lockout`
  )
}

async function rejectWhenUfwBlocksTargetPort(
  ssh: SshConnection,
  targetPort: number
): Promise<ModuleResult | undefined> {
  const access = await classifyUfwAccessOrUnknown(ssh, targetPort)
  if (access === "blocked") return ufwBlocksPortFailure(targetPort)
  if (access === "unknown") return unknownUfwStatusFailure(targetPort)
  return undefined
}

async function verifyLiveSshdPortOrRollback(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    snapshot: SshdRestartSnapshot
    targetPort: number
  }
): Promise<ModuleResult | undefined> {
  // R-0000283: poll the live socket so a successful restart is not declared
  // changed when bind conflicts or external drop-ins kept sshd from listening
  // on `targetPort`. Without this guard the runner would reconnect into the
  // void.
  if (await waitForLiveSshdPort(ssh, parameters.targetPort)) return undefined

  const rollbackError = await rollbackSshdPortAfterFailedVerification(ssh, parameters)
  const baseMessage =
    `[sshd.port: ${String(parameters.targetPort)}] sshd restart succeeded but no listener ` +
    `on port ${String(parameters.targetPort)} after ${String(LIVE_VERIFY_TIMEOUT_MS)}ms`
  if (rollbackError == null) {
    return failed(`${baseMessage}; rolled back to previous config and port`)
  }
  return failed(`${baseMessage}; rollback also failed: ${rollbackError}`)
}

async function restartAndVerifySshdPort(
  ssh: SshConnection,
  parameters: { originalConfig: string; originalPort: number; targetPort: number }
): Promise<ModuleResult | undefined> {
  const outcome = await restartSshdOnNewPort(ssh, parameters.targetPort, parameters.originalConfig)
  if (!isSshdRestartOutcome(outcome)) return outcome
  // A restart may close the current SSH session even when systemd accepted
  // the command. Reconnect immediately and run the same live-port verification
  // before reporting success; otherwise the runner could switch to an
  // unreachable target port with no rollback chance.
  if (outcome.kind !== "completed") {
    try {
      await ssh.reconnect()
    } catch (error) {
      return recoverFromReconnectFailureAfterDisconnect(ssh, {
        originalConfig: parameters.originalConfig,
        originalPort: parameters.originalPort,
        reconnectError: error,
        snapshot: outcome.snapshot,
        targetPort: parameters.targetPort,
      })
    }
  }
  // R-0000557: hand the restart snapshot (socket-state, service-boot-state,
  // service-unit) through to the verification rollback so it can restore the
  // same three layers that `recoverFromRestartFailure` does. Without this,
  // verification rollback restores only `sshd_config` and silently leaves
  // `ssh.socket` disabled on socket-activated hosts.
  return verifyLiveSshdPortOrRollback(ssh, { ...parameters, snapshot: outcome.snapshot })
}

// R-0000593: when the restart aborted the session and the immediate reconnect
// on the new candidate port fails, the previous behaviour returned `failed(...)`
// after only calling `ssh.removePort(targetPort)`. That left the on-disk
// `sshd_config`, the socket-state, and the service-boot-state pointing at the
// new port even though the runner could no longer reach the host on it —
// a near-certain lockout once systemd settles or the host reboots. We now
// best-effort the reconnect over `originalPort` so the rollback path can talk
// to the host again, then restore all three layers via the existing
// verification-rollback helper. Both the reconnect attempt and the rollback
// are best-effort; the original reconnect failure stays the primary error.
async function recoverFromReconnectFailureAfterDisconnect(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    reconnectError: unknown
    snapshot: SshdRestartSnapshot
    targetPort: number
  }
): Promise<ModuleResult> {
  // Remove the target port from the candidate list before re-attempting the
  // reconnect so the runner does not keep dialling the unreachable port we
  // just failed to reach. `reconnect()` honours `runtime.ports`, so the next
  // attempt iterates through the remaining (original) candidates.
  try {
    ssh.removePort(parameters.targetPort)
  } catch {
    // ssh.removePort is in-memory bookkeeping; never mask the reconnect failure.
  }
  // Ensure `originalPort` is on the candidate list; on the common case it is
  // already part of the static `configuredPorts` and was therefore present
  // before `addPort(targetPort)` ran, but a defensive re-add costs nothing and
  // guards against future changes to the candidate management.
  try {
    ssh.addPort(parameters.originalPort)
  } catch {
    // ssh.addPort is in-memory bookkeeping; tolerate exotic implementations
    // so the rollback path still runs.
  }
  const fallbackReconnectError = await runRollbackStep(async () => {
    await ssh.reconnect()
  })
  // Drop the original port marker again once we are back on the host so the
  // candidate list reflects the pre-apply state regardless of whether the
  // fallback reconnect succeeded.
  const reconnectErrorMessage = String(parameters.reconnectError)
  const baseMessage =
    `[sshd.port: ${String(parameters.targetPort)}] sshd restart disconnected the SSH ` +
    `session before the target port could be verified; reconnect failed: ${reconnectErrorMessage}`
  if (fallbackReconnectError != null) {
    return failed(
      `${baseMessage}; fallback reconnect on original port ${String(parameters.originalPort)} ` +
        `also failed: ${fallbackReconnectError}`
    )
  }
  const rollbackError = await rollbackSshdPortAfterFailedVerification(ssh, {
    originalConfig: parameters.originalConfig,
    originalPort: parameters.originalPort,
    snapshot: parameters.snapshot,
    targetPort: parameters.targetPort,
  })
  if (rollbackError == null) {
    return failed(`${baseMessage}; rolled back to previous config and port`)
  }
  return failed(`${baseMessage}; rollback also failed: ${rollbackError}`)
}

function isSshdRestartOutcome(
  candidate: ModuleResult | SshdRestartOutcome
): candidate is SshdRestartOutcome {
  // `ModuleResult` carries a `status` field, `SshdRestartOutcome` carries a
  // `snapshot` field — disambiguate on `snapshot` to keep the discriminant
  // independent of any future `kind` additions to `ModuleResult`. Both
  // union members are non-null object types, so a `typeof` / null guard
  // would be flagged as unnecessary by `@typescript-eslint`.
  return "snapshot" in candidate
}

async function applySshdPortWhenConfigUnchanged(
  ssh: SshConnection,
  parameters: { originalConfig: string; originalPort: number; targetPort: number }
): Promise<ModuleResult> {
  if (await liveSshdPortMatches(ssh, parameters.targetPort)) return { status: "ok" }
  // R-0000540: a TOCTOU gap exists between the first ufw guard run by
  // `applySshdPort` and this restart path. If the matching allow rule was
  // removed in between, restarting sshd onto the new port locks the runner
  // out. Re-run the same guard right before the restart.
  const ufwGuard = await rejectWhenUfwBlocksTargetPort(ssh, parameters.targetPort)
  if (ufwGuard != null) return ufwGuard
  // R-0000540: when sshd_config already contains the target port, the
  // captured `originalConfig` would map the rollback back to the target port
  // (identity rollback). Synthesise a rollback config that pins the live
  // pre-restart port instead, so a failed verification can actually restore
  // the previously listening port.
  const { newContent: rollbackConfig } = buildSshdPortContent(
    parameters.originalConfig,
    parameters.originalPort
  )
  const verificationFailure = await restartAndVerifySshdPort(ssh, {
    originalConfig: rollbackConfig,
    originalPort: parameters.originalPort,
    targetPort: parameters.targetPort,
  })
  if (verificationFailure != null) return verificationFailure
  return {
    meta: [sshdPortMeta(parameters.targetPort)],
    status: "changed",
  }
}

async function applyChangedSshdPort(
  ssh: SshConnection,
  parameters: {
    newContent: string
    originalConfig: string
    originalPort: number
    targetPort: number
  }
): Promise<ModuleResult> {
  const settingNames = `Port ${String(parameters.targetPort)}`
  // R-0000539: validate the prospective config (in a tempfile) before
  // overwriting `/etc/ssh/sshd_config` so a malformed port directive is
  // rejected without rollback.
  const prospectiveFailure = await validateProspectiveSshdConfigOrFailed(ssh, {
    newContent: parameters.newContent,
    settingNames,
  })
  if (prospectiveFailure != null) return prospectiveFailure
  const writeFailure = await writeSshdConfigIfChanged(ssh, {
    didChange: true,
    newContent: parameters.newContent,
    originalConfig: parameters.originalConfig,
    settingNames,
  })
  if (writeFailure != null) return writeFailure
  const verificationFailure = await restartAndVerifySshdPort(ssh, {
    originalConfig: parameters.originalConfig,
    originalPort: parameters.originalPort,
    targetPort: parameters.targetPort,
  })
  if (verificationFailure != null) return verificationFailure

  return {
    meta: [sshdPortMeta(parameters.targetPort)],
    status: "changed",
  }
}

async function applySshdPort(ssh: SshConnection, targetPort: number): Promise<ModuleResult> {
  const configuredPortGuard = rejectWhenTargetPortIsNotConfigured(ssh, targetPort)
  if (configuredPortGuard != null) return configuredPortGuard

  const ufwGuard = await rejectWhenUfwBlocksTargetPort(ssh, targetPort)
  if (ufwGuard != null) return ufwGuard

  const { port: originalPort } = ssh.getConnectionInfo()
  const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
  const { didChange, newContent } = buildSshdPortContent(originalConfig, targetPort)
  if (!didChange) {
    return applySshdPortWhenConfigUnchanged(ssh, { originalConfig, originalPort, targetPort })
  }

  return applyChangedSshdPort(ssh, {
    newContent,
    originalConfig,
    originalPort,
    targetPort,
  })
}

function rejectWhenTargetPortIsNotConfigured(
  ssh: SshConnection,
  targetPort: number
): ModuleResult | null {
  const { configuredPorts } = ssh.getConnectionInfo()
  if (configuredPorts.includes(targetPort)) return null
  return failed(
    `[sshd.port: ${String(targetPort)}] target port is not listed in static ssh.ports ` +
      `configuration; add ${String(targetPort)} to ssh.ports before changing sshd_config`
  )
}

/**
 * Modules for managing the OpenSSH daemon configuration (`/etc/ssh/sshd_config`).
 * All methods restart or reload `sshd` after applying changes.
 */
export const sshd = {
  /**
   * Apply one or more key-value settings to `sshd_config`.
   * Existing directives are updated in-place; missing directives are appended.
   *
   * @param settings - A map of sshd_config directive names to their desired values
   *   (e.g. `{ PasswordAuthentication: "no" }`).
   * @returns A Module that applies the sshd configuration settings.
   */
  config(settings: Record<string, string>): Module {
    validateSshdSettings(settings)
    const settingNames = Object.keys(settings).join(", ")
    return {
      async _applyDryRun(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[sshd.config: ${settingNames}] SSH connection is required`)

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
        const { didChange, newContent } = buildSshdConfigContent(originalConfig, settings)
        const nonConvergingMatchOverride = rejectNonConvergingSshdMatchOverrides(
          newContent,
          settings
        )
        if (nonConvergingMatchOverride != null) return nonConvergingMatchOverride
        if (!didChange) {
          return { status: "ok" }
        }

        return dryRunSshdConfig(ssh, newContent, "(dry-run, sshd -t ok; reload not executed)")
      },
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[sshd.config: ${settingNames}] SSH connection is required`)
        return applySshdConfig(ssh, { settingNames, settings })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(SSHD_CONFIG_PATH)
        // R-0000491: surface contradicting Match-block overrides during
        // check so the operator sees the cause of the eventual apply
        // failure (`rejectNonConvergingSshdMatchOverrides`) ahead of time
        // instead of only at apply.
        const conflictingDirective = findContradictingSshdMatchBlockOverride(content, settings)
        if (conflictingDirective != null) {
          process.stderr.write(
            `Warning: [sshd.config: ${conflictingDirective}] conflicting security-relevant ` +
              "Match-block override detected; apply will fail unless the override is updated " +
              "or removed manually\n"
          )
          return NEEDS_APPLY
        }
        for (const [key, value] of Object.entries(settings)) {
          if (!sshdSettingMatchesEverywhere(content, key, value)) {
            return NEEDS_APPLY
          }
        }
        const effectiveMismatch = await findEffectiveSshdConfigMismatch(ssh, settings)
        if (effectiveMismatch.kind === "match") return "ok"
        if (effectiveMismatch.kind === PERMISSION_ERROR_KIND) {
          // R-0000553: surface the permission failure once during check so the
          // operator sees why apply will hard-fail instead of silently spinning
          // through the apply path.
          process.stderr.write(
            `Warning: [sshd.config: ${settingNames}] could not verify effective sshd ` +
              `configuration via \`${SSHD_EFFECTIVE_CONFIG_COMMAND}\` ` +
              `(insufficient privileges?): ${effectiveMismatch.detail}\n`
          )
        }
        return NEEDS_APPLY
      },
      name: `sshd.config: ${settingNames}`,
    }
  },

  /**
   * Set the SSH daemon listen port.
   * Updates the `Port` directive in `sshd_config` and restarts `sshd`.
   * The new port is exported as `sshd.port` in the module result meta so
   * the runner can reconnect on the updated port.
   *
   * @param targetPort - The port number sshd should listen on.
   * @returns A Module that sets the sshd listen port.
   */
  port(targetPort: number): Module {
    if (!isValidTcpPort(targetPort)) {
      throw new Error(
        `sshd.port requires an integer port between 1 and 65535, got ${String(targetPort)}`
      )
    }

    return {
      async _applyDryRun(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[sshd.port: ${targetPort}] SSH connection is required`)

        const configuredPortGuard = rejectWhenTargetPortIsNotConfigured(ssh, targetPort)
        if (configuredPortGuard != null) return configuredPortGuard

        const ufwGuard = await rejectWhenUfwBlocksTargetPort(ssh, targetPort)
        if (ufwGuard != null) return ufwGuard

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
        const { didChange, newContent } = buildSshdPortContent(originalConfig, targetPort)
        if (!didChange) {
          return { status: "ok" }
        }

        return dryRunSshdConfig(
          ssh,
          newContent,
          "(dry-run, sshd -t ok; restart, port switch, firewall and reconnect not verified)"
        )
      },
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[sshd.port: ${targetPort}] SSH connection is required`)
        return applySshdPort(ssh, targetPort)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(SSHD_CONFIG_PATH)
        const portValues = collectTopLevelSshdDirectiveValues(content, "Port")
        if (portValues.length === 0) {
          // When no top-level Port directive exists, sshd defaults to port 22.
          if (targetPort !== DEFAULT_SSH_PORT) return NEEDS_APPLY
          return (await sshdPortConfigMatchesLive(ssh, targetPort)) ? "ok" : NEEDS_APPLY
        }
        if (portValues.every((portValue) => portValue === String(targetPort))) {
          return (await sshdPortConfigMatchesLive(ssh, targetPort)) ? "ok" : NEEDS_APPLY
        }
        return NEEDS_APPLY
      },
      name: `sshd.port: ${targetPort}`,
    }
  },
}
