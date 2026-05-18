/* eslint-disable max-lines -- sshd module keeps tightly coupled validation/restart helpers together */
import { sshdPortMeta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { CommandError, shellQuote } from "../sshHelpers.js"
import { validateMktempPath } from "../ssh.js"
import {
  type ExecResult,
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { flagLockDisplayPath, withMutexLock } from "./moduleHelpers.js"
import {
  applySshdSettingToContent,
  collectTopLevelSshdDirectiveValues,
  findContradictingSshdMatchBlockOverride,
  findNonMatchingEffectiveSshdSetting,
  sshdSettingMatchesEverywhere,
} from "./sshdConfigHelpers.js"
import {
  LIVE_PORT_PROBE_HARD_ERROR_KIND,
  liveSshdPortMatches as livePortMatchesProbe,
  LiveSshdPortProbeError,
} from "./sshdPortLivenessProbe.js"
import { classifyUfwAccessOrUnknown } from "./ufwStatus.js"

const DEFAULT_SSH_PORT = 22
const PRIVILEGE_SEPARATION_DIRECTORY = "/run/sshd"
const SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
const SSHD_CONFIG_MODE = "0644"
const SSHD_EFFECTIVE_CONFIG_COMMAND = "sshd -T"
const SYSTEMCTL = "systemctl"
// R-0000613: serialise all read-modify-write cycles against /etc/ssh/sshd_config
// so concurrent `sshd.config(...)` / `sshd.port(...)` applies cannot observe
// each other's intermediate writes. Without the mutex, a rollback in one apply
// can stomp on a successful write from a parallel apply (the rollback uses the
// previously captured `originalConfig`, not the now-current file content). The
// lock name mirrors `FSTAB_FILE_MUTEX` in `swapFileHelpers.ts`.
const SSHD_CONFIG_FILE_MUTEX = "etc-ssh-sshd-config-mutex"

// R-0000608: distribution-specific socket-activation units differ in name —
// Debian/Ubuntu ship `ssh.socket`, while Fedora/RHEL ship `sshd.socket`. The
// captured state therefore carries the resolved unit name so every downstream
// enable/disable/start command operates on the unit we actually probed instead
// of a hard-coded `ssh.socket` that may not exist on the host.
type SshdSocketUnit = "ssh.socket" | "sshd.socket"

type SshSocketState =
  | { active: boolean; enabled: boolean; exists: true; unit: SshdSocketUnit }
  | { exists: false }

// Resolution order mirrors `resolveSshServiceUnit`: probe the unit name
// commonly used by the matching service unit first, then fall back. Keep
// `ssh.socket` first so existing Debian/Ubuntu hosts (the historic default
// before R-0000608) keep the same probe-order they had before; Fedora/RHEL
// hosts simply fall through to the second probe.
const SSHD_SOCKET_UNIT_CANDIDATES: readonly SshdSocketUnit[] = ["ssh.socket", "sshd.socket"]

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

// R-0000608: probe both `ssh.socket` (Debian/Ubuntu) and `sshd.socket`
// (Fedora/RHEL) when capturing the socket-activation state. Returning the
// resolved unit name lets `disableSocketActivatedSsh` and
// `restoreSocketActivatedSsh` operate on the correct unit instead of
// hard-coding `ssh.socket` and silently skipping rollback on hosts that ship
// only `sshd.socket`.
async function resolveExistingSshdSocketUnit(
  ssh: SshConnection
): Promise<SshdSocketUnit | undefined> {
  for (const candidate of SSHD_SOCKET_UNIT_CANDIDATES) {
    // R-0000492: rely on `silent: true` to swallow stdout/stderr instead of
    // embedding shell redirects in the command string. Keeps the helper
    // consistent with the rest of the codebase and avoids shell-metacharacter
    // surprises.
    // eslint-disable-next-line no-await-in-loop -- sequential systemctl probes by design
    const exists = await ssh.exec(`systemctl cat ${candidate}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (exists.code === 0) return candidate
  }
  return undefined
}

async function captureSshSocketState(ssh: SshConnection): Promise<SshSocketState> {
  const unit = await resolveExistingSshdSocketUnit(ssh)
  if (unit == null) return { exists: false }

  const enabled = await ssh.exec(`systemctl is-enabled --quiet ${unit}`, {
    ignoreExitCode: true,
    silent: true,
  })
  const active = await ssh.exec(`systemctl is-active --quiet ${unit}`, {
    ignoreExitCode: true,
    silent: true,
  })

  return {
    active: active.code === 0,
    enabled: enabled.code === 0,
    exists: true,
    unit,
  }
}

async function disableSocketActivatedSsh(ssh: SshConnection): Promise<SshSocketState> {
  const socketState = await captureSshSocketState(ssh)
  if (!socketState.exists) return socketState

  await ssh.exec(`systemctl disable --now ${socketState.unit}`, {
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
    await ssh.exec(`systemctl enable --now ${socketState.unit}`, {
      ignoreExitCode: false,
      silent: true,
    })
    return
  }
  if (socketState.enabled) {
    await ssh.exec(`systemctl enable ${socketState.unit}`, {
      ignoreExitCode: false,
      silent: true,
    })
  }
  if (socketState.active) {
    await ssh.exec(`systemctl start ${socketState.unit}`, {
      ignoreExitCode: false,
      silent: true,
    })
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
  parameters: {
    originalConfig: string
    reloadResult: ModuleResult
    serviceUnit?: SshdServiceUnit
    settingNames: string
  }
): Promise<ModuleResult> {
  const originalReloadMessage = parameters.reloadResult.error?.message ?? "sshd reload failed"
  try {
    await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
  } catch (rollbackError) {
    const rollbackMessage =
      rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
    return failed(
      `[sshd.config: ${parameters.settingNames}] sshd reload failed; rollback also failed: ` +
        `${rollbackMessage}\n${originalReloadMessage}`
    )
  }
  // R-0000616: writing the original config back is necessary but not
  // sufficient — sshd is still running with the partially-loaded new content.
  // Reload the daemon again so the on-disk rollback actually becomes the live
  // config; otherwise the operator sees a "rolled back" status while sshd
  // continues to enforce the broken settings until the next manual reload.
  // R-0000621: restrict the post-rollback reload to pure `systemctl reload`
  // semantics — never fall back to `reload-or-restart`. The fallback would
  // kill the live SSH session on units without `ExecReload=` (e.g. Debian's
  // historical sshd.service), which is unacceptable in a rollback path that
  // the operator did not explicitly opt into to interrupt the session.
  return runPostRollbackReloadOrSurfaceManualRestart(ssh, {
    originalReloadMessage,
    originalReloadResult: parameters.reloadResult,
    serviceUnit: parameters.serviceUnit,
    settingNames: parameters.settingNames,
  })
}

async function runPostRollbackReloadOrSurfaceManualRestart(
  ssh: SshConnection,
  parameters: {
    originalReloadMessage: string
    originalReloadResult: ModuleResult
    serviceUnit?: SshdServiceUnit
    settingNames: string
  }
): Promise<ModuleResult> {
  // R-0000621: probe `ExecReload=` so we can fail loudly when the unit has no
  // reload semantics at all. Falling back to `reload-or-restart` here would
  // disconnect the SSH session as a side-effect of an unattended rollback.
  const serviceUnit = parameters.serviceUnit ?? (await resolveSshServiceUnit(ssh))
  const hasExecReload = await sshdUnitDefinesExecReload(ssh, serviceUnit)
  if (!hasExecReload) {
    return failed(
      `[sshd.config: ${parameters.settingNames}] sshd_config rolled back on disk, but the ` +
        `live daemon (unit ${serviceUnit}) defines no \`ExecReload=\` directive so the ` +
        "post-rollback reload could not run without restarting the service and killing the " +
        "active SSH session; manual `systemctl restart sshd` is required to make the rollback " +
        `take effect.\n${parameters.originalReloadMessage}`
    )
  }
  const restoreReloadResult = await reloadSshdWithoutRestartFallback(ssh, serviceUnit)
  if (restoreReloadResult.status === "failed") {
    const restoreReloadMessage =
      restoreReloadResult.error?.message ?? "post-rollback sshd reload failed"
    return failed(
      `[sshd.config: ${parameters.settingNames}] sshd reload failed and the post-rollback ` +
        `reload also failed: ${restoreReloadMessage}\n${parameters.originalReloadMessage}`
    )
  }
  // Surface the original reload failure even though the rollback succeeded
  // and the daemon is now back on `originalConfig`. The operator must still
  // know the requested change did not land.
  return parameters.originalReloadResult
}

// R-0000621: pure `systemctl reload` variant used by the post-rollback path.
// Unlike `reloadSshd` we never fall back to `reload-or-restart` here — the
// rollback caller must not terminate the live SSH session as a side-effect of
// the cleanup step.
async function reloadSshdWithoutRestartFallback(
  ssh: SshConnection,
  serviceUnit: SshdServiceUnit
): Promise<ModuleResult> {
  const result = await ssh.exec(`${SYSTEMCTL} reload ${serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? { status: "changed" }
    : failedCommand(`[sshd.config] systemctl reload ${serviceUnit} failed`, result)
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

// R-0000541 / R-0000609: the structural `ss -ltnp` parser and the
// hard-error classifier live in `sshdPortLivenessProbe.ts` so both
// `sshd.port` and `ufw.rule` (R-0000625) can share a single implementation
// instead of drifting into independent fail-open branches.
//
// `livePortMatchesProbe(ssh, { tag, targetPort })` throws
// `LiveSshdPortProbeError` for hard environmental failures (missing `ss`
// binary, permission denied) and returns `boolean` for the "listener
// matches / no listener yet" decision.
async function liveSshdPortMatches(ssh: SshConnection, targetPort: number): Promise<boolean> {
  return livePortMatchesProbe(ssh, {
    tag: `sshd.port: ${String(targetPort)}`,
    targetPort,
  })
}

async function sshdPortConfigMatchesLive(ssh: SshConnection, targetPort: number): Promise<boolean> {
  if (await socketActivationBootPathNeedsApply(ssh)) return false
  // R-0000609: the check-only path swallows the hard `ss` error and falls
  // back to "needs-apply" so the warning is visible to the operator on the
  // next apply pass instead of crashing the check run.
  try {
    return await liveSshdPortMatches(ssh, targetPort)
  } catch (error) {
    if (error instanceof LiveSshdPortProbeError) {
      process.stderr.write(`Warning: ${error.message}\n`)
      return false
    }
    throw error
  }
}

// R-0000628: run every restart-failure rollback step even if an earlier step
// fails, mirroring the per-step accumulator that
// `executeSshdPortRollbackSteps` already uses for the post-verification
// rollback path. Previously the four steps (sshd_config rewrite, service
// boot-state restore, socket-activation restore, systemctl restart) ran
// sequentially with no error accumulator; a failure in the first write threw
// past the remaining layers and `recoverFromRestartFailure` then swallowed
// the exception, leaving `ssh.socket` permanently disabled on socket-
// activated hosts and producing a reboot-time SSH lockout. Accumulate
// failures per step and return them to the caller so the apply-time error
// message can surface the secondary rollback failure alongside the primary
// restart failure.
type RestartFailureRollbackStep = { name: string; run: () => Promise<void> }

function buildRestartFailureRollbackSteps(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
  }
): RestartFailureRollbackStep[] {
  const steps: RestartFailureRollbackStep[] = [
    {
      name: "sshd_config rewrite",
      async run() {
        await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, {
          mode: SSHD_CONFIG_MODE,
        })
      },
    },
    {
      name: "service boot-state restore",
      async run() {
        await restoreSshServiceBootState(ssh, parameters.serviceBootState)
      },
    },
    {
      name: "socket activation restore",
      async run() {
        await restoreSocketActivatedSsh(ssh, parameters.socketState)
      },
    },
  ]
  // The post-rollback `systemctl restart` only runs when the restart path
  // had already resolved the service unit. Without it we have no unit name
  // to restart against; the other three layers still run unconditionally so
  // sshd_config, the service boot state, and ssh.socket land back on their
  // pre-apply values.
  if (parameters.serviceUnit != null) {
    const serviceUnit = parameters.serviceUnit
    steps.push({
      name: "ssh service restart",
      async run() {
        await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, {
          ignoreExitCode: true,
          silent: true,
        })
      },
    })
  }
  return steps
}

async function restoreSshdPortRestartFailure(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
  }
): Promise<string | undefined> {
  const steps = buildRestartFailureRollbackSteps(ssh, parameters)
  const failures: Array<{ message: string; name: string }> = []
  for (const step of steps) {
    // eslint-disable-next-line no-await-in-loop -- restore steps must run sequentially so each layer rolls back before the next.
    const failure = await runRollbackStep(step.run)
    if (failure !== undefined) failures.push({ message: failure, name: step.name })
  }
  if (failures.length === 0) return undefined
  const formatted = failures.map((entry) => `${entry.name} failed: ${entry.message}`)
  if (formatted.length === 1) return formatted[0]
  const [primary, ...secondaries] = formatted
  return `${primary}; further failures: ${secondaries.join("; ")}`
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
): Promise<string | undefined> {
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
  // R-0000628: surface a rollback failure to the caller instead of swallowing
  // it. The previous best-effort catch let a first-step write failure abort
  // the remaining socket-state / service-boot-state / restart layers without
  // any operator-visible warning, locking socket-activated hosts out at the
  // next reboot. The per-step accumulator in `restoreSshdPortRestartFailure`
  // now keeps every layer running even when an earlier step fails; the
  // returned message lists every failure so the caller can merge them into
  // the apply-time error.
  return restoreSshdPortRestartFailure(ssh, {
    originalConfig: parameters.originalConfig,
    serviceBootState: parameters.serviceBootState,
    serviceUnit: parameters.serviceUnit,
    socketState: parameters.socketState,
  })
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
    return handleRestartSshdOnNewPortFailure(ssh, {
      error,
      originalConfig,
      serviceBootState,
      serviceUnit,
      socketState,
      targetPort,
    })
  }
}

async function handleRestartSshdOnNewPortFailure(
  ssh: SshConnection,
  parameters: {
    error: unknown
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
    targetPort: number
  }
): Promise<ModuleResult | SshdRestartOutcome> {
  // R-0000283: when the restart aborted the SSH session itself, treat the
  // disconnect as a successful restart. The runner reconnects on the new
  // port; downstream live-verification cannot run on a dead connection.
  if (isRestartDisconnect(parameters.error)) {
    return {
      kind: "disconnected",
      snapshot: {
        serviceBootState: parameters.serviceBootState,
        serviceUnit: parameters.serviceUnit,
        socketState: parameters.socketState,
      },
    }
  }
  const rollbackFailure = await recoverFromRestartFailure(ssh, {
    originalConfig: parameters.originalConfig,
    serviceBootState: parameters.serviceBootState,
    serviceUnit: parameters.serviceUnit,
    socketState: parameters.socketState,
    targetPort: parameters.targetPort,
  })
  const message =
    parameters.error instanceof Error ? parameters.error.message : String(parameters.error)
  // R-0000628: surface a rollback failure alongside the primary restart
  // failure instead of pretending the rollback succeeded. A nested failure
  // (e.g. SFTP refusing the sshd_config rewrite) used to be swallowed and
  // reported as "rolled back to previous config and port", hiding the
  // lockout-critical state from the operator.
  if (rollbackFailure == null) {
    return failed(
      `[sshd.port: ${String(parameters.targetPort)}] sshd restart failed; ` +
        `rolled back to previous config and port: ${message}`
    )
  }
  return failed(
    `[sshd.port: ${String(parameters.targetPort)}] sshd restart failed; ` +
      `rollback also failed: ${rollbackFailure}: ${message}`
  )
}

// R-0000283: poll `liveSshdPortMatches` for a short window so a slow systemd
// transition can settle before we declare the restart a failure. Bind
// conflicts and stale drop-ins make sshd come back without binding the
// target port; the polling loop catches that drift before the runner
// reconnects into the void.
const LIVE_VERIFY_TIMEOUT_MS = 5000
const LIVE_VERIFY_BACKOFF_MS = 250

const WAIT_FOR_LIVE_PORT_MATCHED_KIND = "matched" as const
const WAIT_FOR_LIVE_PORT_TIMEOUT_KIND = "timeout" as const

type WaitForLiveSshdPortOutcome =
  | { kind: typeof LIVE_PORT_PROBE_HARD_ERROR_KIND; message: string }
  | { kind: typeof WAIT_FOR_LIVE_PORT_MATCHED_KIND }
  | { kind: typeof WAIT_FOR_LIVE_PORT_TIMEOUT_KIND }

async function waitForLiveSshdPort(
  ssh: SshConnection,
  targetPort: number
): Promise<WaitForLiveSshdPortOutcome> {
  const deadline = Date.now() + LIVE_VERIFY_TIMEOUT_MS
  for (;;) {
    try {
      // eslint-disable-next-line no-await-in-loop -- sequential probes by design
      if (await liveSshdPortMatches(ssh, targetPort)) {
        return { kind: WAIT_FOR_LIVE_PORT_MATCHED_KIND }
      }
    } catch (error) {
      // R-0000609: a hard `ss` failure (binary missing, permission denied)
      // returns the same non-zero exit on every retry. Stop polling and let
      // the caller surface the environmental error so the apply path neither
      // times out silently nor loops indefinitely.
      if (error instanceof LiveSshdPortProbeError) {
        return { kind: LIVE_PORT_PROBE_HARD_ERROR_KIND, message: error.message }
      }
      throw error
    }
    if (Date.now() >= deadline) return { kind: WAIT_FOR_LIVE_PORT_TIMEOUT_KIND }
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

// R-0000623: track whether the rollback path actually triggered another
// `systemctl restart` so callers reached via the R-0000593 fresh-reconnect
// path can warn the operator about a possible second disconnect, and so the
// normal verification-rollback caller can keep its existing "rolled back"
// language when no restart was needed.
type SshdPortRollbackOutcome = {
  error?: string
  restarted: boolean
}

async function rollbackSshdPortAfterFailedVerification(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    snapshot: SshdRestartSnapshot
    targetPort: number
  }
): Promise<SshdPortRollbackOutcome> {
  try {
    ssh.removePort(parameters.targetPort)
  } catch {
    // ssh.removePort is in-memory bookkeeping; never block rollback.
  }
  // R-0000557 / R-0000614 / R-0000623: see `buildSshdPortRollbackSteps` for
  // the rationale behind the per-layer rollback ordering and the live-port
  // probe that gates the final `systemctl restart`.
  const steps = buildSshdPortRollbackSteps(ssh, parameters)
  return executeSshdPortRollbackSteps(steps)
}

type SshdPortRollbackStep =
  | { kind: "restart"; name: string; run: () => Promise<RestartRollbackResult> }
  | { kind: "void"; name: string; run: () => Promise<void> }

function buildSshdPortRollbackSteps(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    snapshot: SshdRestartSnapshot
  }
): SshdPortRollbackStep[] {
  // R-0000557: `restartSshdOnNewPort` has already mutated `ssh.socket`
  // (disabled it) and may have flipped the service unit's boot state. The
  // post-restart verification rollback must restore both, otherwise a host
  // running socket-activated ssh (Debian 12, Ubuntu 22.04 LTS) reboots into a
  // disabled ssh.socket and locks the operator out. Mirror the recovery shape
  // used by `recoverFromRestartFailure` so all three rollback layers
  // (sshd_config, socket-state, service-boot-state) land before we kick the
  // service.
  // R-0000623: the final restart step now consults the live socket first and
  // only fires when sshd is actually drifted away from `originalPort`. When
  // sshd already listens on `originalPort` (e.g. because the previous restart
  // already settled, or because `restartSshdOnNewPort` never managed to swap
  // the port in the first place), another `systemctl restart` would re-kill
  // the freshly recovered SSH session for no functional benefit. The
  // "restart" step communicates whether the restart actually fired through a
  // dedicated `RestartRollbackResult` so callers can warn the operator about
  // the second session teardown on the R-0000593 reconnect path.
  return [
    {
      kind: "void",
      name: "sshd_config rewrite",
      async run() {
        await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, {
          mode: SSHD_CONFIG_MODE,
        })
      },
    },
    {
      kind: "void",
      name: "service boot-state restore",
      async run() {
        await restoreSshServiceBootState(ssh, parameters.snapshot.serviceBootState)
      },
    },
    {
      kind: "void",
      name: "socket activation restore",
      async run() {
        await restoreSocketActivatedSsh(ssh, parameters.snapshot.socketState)
      },
    },
    {
      kind: "restart",
      name: "ssh service restart",
      async run() {
        return restartSshdIfNotAlreadyOnOriginalPort(ssh, {
          originalPort: parameters.originalPort,
          serviceUnit: parameters.snapshot.serviceUnit,
        })
      },
    },
  ]
}

// R-0000614: run every rollback step even if an earlier step failed, so a
// transient sshd_config write failure cannot prevent the socket-state and
// service-boot-state rollback (or the gated service restart) from running.
// Accumulate failures and surface the first failure as the primary error,
// with any subsequent failures attached as annexed messages.
async function executeSshdPortRollbackSteps(
  steps: readonly SshdPortRollbackStep[]
): Promise<SshdPortRollbackOutcome> {
  let restartedDuringRollback = false
  const failures: Array<{ message: string; name: string }> = []
  for (const step of steps) {
    if (step.kind === "void") {
      // eslint-disable-next-line no-await-in-loop -- restore steps must run sequentially so each layer rolls back before the next.
      const failure = await runRollbackStep(step.run)
      if (failure !== undefined) failures.push({ message: failure, name: step.name })
      continue
    }
    // eslint-disable-next-line no-await-in-loop -- restart step must observe the prior layers landing.
    const outcome = await runRestartRollbackStep(step.run)
    if (outcome.failure !== undefined) {
      failures.push({ message: outcome.failure, name: step.name })
    }
    if (outcome.restarted) restartedDuringRollback = true
  }
  return formatSshdPortRollbackOutcome(failures, restartedDuringRollback)
}

function formatSshdPortRollbackOutcome(
  failures: ReadonlyArray<{ message: string; name: string }>,
  restartedDuringRollback: boolean
): SshdPortRollbackOutcome {
  if (failures.length === 0) return { restarted: restartedDuringRollback }
  const formatted = failures.map((entry) => `${entry.name} failed: ${entry.message}`)
  if (formatted.length === 1) {
    return { error: formatted[0], restarted: restartedDuringRollback }
  }
  const [primary, ...secondaries] = formatted
  return {
    error: `${primary}; further failures: ${secondaries.join("; ")}`,
    restarted: restartedDuringRollback,
  }
}

// R-0000623: structured outcome of the rollback restart step. `restarted`
// signals whether `systemctl restart` actually fired; callers use it to warn
// the operator about a possible second SSH disconnect on the recovered
// session.
type RestartRollbackResult = { restarted: boolean }

async function runRestartRollbackStep(
  step: () => Promise<RestartRollbackResult>
): Promise<{ failure?: string; restarted: boolean }> {
  try {
    const result = await step()
    return { restarted: result.restarted }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { failure: message, restarted: false }
  }
}

// R-0000623: probe whether sshd is already listening on `originalPort` and
// skip the rollback restart in that case. Issuing another `systemctl restart`
// when sshd already serves the original port costs us another SSH session
// teardown (the runner reconnected after the previous restart) without
// changing the daemon state. `liveSshdPortMatches` may throw on a hard `ss`
// failure (binary missing, permission denied); in that case we conservatively
// fall back to the restart so the rollback still converges.
async function restartSshdIfNotAlreadyOnOriginalPort(
  ssh: SshConnection,
  parameters: {
    originalPort: number
    serviceUnit?: SshdServiceUnit
  }
): Promise<RestartRollbackResult> {
  const alreadyOnOriginalPort = await probeAlreadyOnOriginalPortBestEffort(
    ssh,
    parameters.originalPort
  )
  if (alreadyOnOriginalPort) return { restarted: false }
  const serviceUnit = parameters.serviceUnit ?? (await resolveSshServiceUnit(ssh))
  await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return { restarted: true }
}

async function probeAlreadyOnOriginalPortBestEffort(
  ssh: SshConnection,
  originalPort: number
): Promise<boolean> {
  try {
    return await liveSshdPortMatches(ssh, originalPort)
  } catch {
    // Best-effort probe; on hard ss failures fall through to the restart so
    // the rollback path still drives sshd back to the rolled-back config.
    return false
  }
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

// R-0000766: allocate the prospective sshd_config dry-run path through
// `mktemp -p /tmp -- paratix-sshd-dry-run.XXXXXX` (with the trailing `--`
// guarding against template values being interpreted as options) and route
// the result through `validateMktempPath` so the kernel — not Node's PRNG —
// owns name collision avoidance and a hostile `mktemp` cannot smuggle an
// unexpected path back. Mirrors the pattern in `allocateRemoteScriptPath`
// in `modules/script.ts` and supersedes the legacy
// `/tmp/paratix-sshd-dry-run-${randomUUID()}.conf` scheme that relied on
// `ssh.writeFile` racing against any prior occupant of the path.
const SSHD_DRY_RUN_TEMP_PREFIX = "paratix-sshd-dry-run"
const SSHD_DRY_RUN_TEMP_DIRECTORY = "/tmp"

async function allocateProspectiveSshdConfigPath(
  ssh: SshConnection
): Promise<ModuleResult | string> {
  const template = `${SSHD_DRY_RUN_TEMP_PREFIX}.XXXXXX`
  // R-0000565: the trailing `--` separates the template from any future
  // `mktemp` options. R-0000766: matches `allocateRemoteScriptPath`.
  const mktempResult = await ssh.exec(
    `mktemp -p ${SSHD_DRY_RUN_TEMP_DIRECTORY} -- ${shellQuote(template)}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (mktempResult.code !== 0) {
    return failedCommand("[sshd dry-run] mktemp failed", mktempResult)
  }
  const remotePath = mktempResult.stdout.trim()
  if (remotePath.length === 0) {
    return failed("[sshd dry-run] mktemp returned an empty path")
  }
  try {
    return validateMktempPath(SSHD_DRY_RUN_TEMP_DIRECTORY, remotePath, SSHD_DRY_RUN_TEMP_PREFIX)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[sshd dry-run] mktemp returned an unsafe path: ${reason}`)
  }
}

async function validateProspectiveSshdConfig(
  ssh: SshConnection,
  content: string
): Promise<ModuleResult | undefined> {
  const allocation = await allocateProspectiveSshdConfigPath(ssh)
  if (typeof allocation !== "string") return allocation
  const temporaryConfigPath = allocation
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
  // R-0000766: same mktemp-based allocation as `validateProspectiveSshdConfig`.
  const allocation = await allocateProspectiveSshdConfigPath(ssh)
  if (typeof allocation !== "string") return allocation
  const temporaryConfigPath = allocation
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
    serviceUnit: parameters.serviceUnit,
    settingNames: parameters.settingNames,
  })
}

async function applySshdConfig(
  ssh: SshConnection,
  parameters: { settingNames: string; settings: Record<string, string> }
): Promise<ModuleResult> {
  // R-0000613: hold the sshd_config mutex across the full read-modify-write
  // cycle so a concurrent `sshd.port(...)` or `sshd.config(...)` apply on the
  // same host cannot interleave with our write or with the rollback path. The
  // mutex helper wraps both successful and failed sections with cleanup, so
  // the lock is released even when an inner step throws.
  // R-0000757: `withMutexLock` now returns a structured `MutexLockResult`.
  // Section throws are intentionally propagated via `propagateSectionThrows`
  // so the upstream apply layer can fall back to its reconnect/rollback path
  // when the sshd restart breaks the SSH transport mid-section.
  const lockResult = await withMutexLock(ssh, {
    failureMessage: `[${parameters.settingNames}] failed to acquire sshd_config mutex`,
    lockName: SSHD_CONFIG_FILE_MUTEX,
    propagateSectionThrows: true,
    section: async () => applySshdConfigUnderLock(ssh, parameters),
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
}

async function applySshdConfigUnderLock(
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
  const verifyOutcome = await waitForLiveSshdPort(ssh, parameters.targetPort)
  if (verifyOutcome.kind === WAIT_FOR_LIVE_PORT_MATCHED_KIND) return undefined

  const rollbackOutcome = await rollbackSshdPortAfterFailedVerification(ssh, parameters)
  // R-0000609: a hard `ss` failure (binary missing, permission denied) must
  // surface its own diagnostic so the operator sees the actionable error,
  // not the generic "no listener after Xms" message that hides the real
  // cause and triggers retry loops.
  const baseMessage =
    verifyOutcome.kind === LIVE_PORT_PROBE_HARD_ERROR_KIND
      ? `${verifyOutcome.message}; sshd restart succeeded but the live-port verification ` +
        "could not be evaluated"
      : `[sshd.port: ${String(parameters.targetPort)}] sshd restart succeeded but no listener ` +
        `on port ${String(parameters.targetPort)} after ${String(LIVE_VERIFY_TIMEOUT_MS)}ms`
  if (rollbackOutcome.error == null) {
    return failed(`${baseMessage}; rolled back to previous config and port`)
  }
  return failed(`${baseMessage}; rollback also failed: ${rollbackOutcome.error}`)
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
    // R-0000619: both the target-port reconnect and the fallback reconnect on
    // `originalPort` failed. The outer `withMutexLock` finally cannot release
    // the `/etc/ssh/sshd_config` mutex over the dead transport, so the lock
    // directory stays in place until the 4h stale-lock detection reclaims it.
    // Surface the on-host lock path in the operator-facing failure so the
    // operator can clean it up manually before that window expires — without
    // this hint the next `sshd.config`/`sshd.port` apply blocks for hours.
    const staleLockHint =
      `lock directory likely left behind at ${flagLockDisplayPath(SSHD_CONFIG_FILE_MUTEX)} ` +
      "on the remote host (release runs over the failed connection); remove it manually " +
      "before the next sshd apply if you cannot wait for the 4h stale-lock reclaim"
    return failed(
      `${baseMessage}; fallback reconnect on original port ${String(parameters.originalPort)} ` +
        `also failed: ${fallbackReconnectError}; ${staleLockHint}`
    )
  }
  const rollbackOutcome = await rollbackSshdPortAfterFailedVerification(ssh, {
    originalConfig: parameters.originalConfig,
    originalPort: parameters.originalPort,
    snapshot: parameters.snapshot,
    targetPort: parameters.targetPort,
  })
  // R-0000623: the rollback path ends with `systemctl restart` when sshd is
  // not already on `originalPort`. On the R-0000593 fresh-reconnect branch
  // that restart may disconnect the just-recovered session a second time.
  // Surface that risk in the operator-facing message rather than dressing the
  // outcome up as a clean "rolled back" status. When the rollback skipped the
  // restart (sshd was already on `originalPort`), the message stays the
  // historic "rolled back to previous config and port" wording.
  const disconnectWarning = rollbackOutcome.restarted
    ? " (rollback issued a second sshd restart from the recovered session; the SSH session " +
      "may disconnect again — reconnect manually on the original port if it does)"
    : ""
  if (rollbackOutcome.error == null) {
    return failed(`${baseMessage}; rolled back to previous config and port${disconnectWarning}`)
  }
  return failed(
    `${baseMessage}; rollback also failed: ${rollbackOutcome.error}${disconnectWarning}`
  )
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
  // R-0000609: surface hard `ss` failures (binary missing, permission denied)
  // before triggering a needless restart — the same probe runs again during
  // post-restart verification and would loop forever. Surfacing it here keeps
  // the apply path idempotent and gives the operator an actionable error.
  try {
    if (await liveSshdPortMatches(ssh, parameters.targetPort)) return { status: "ok" }
  } catch (error) {
    if (error instanceof LiveSshdPortProbeError) return failed(error.message)
    throw error
  }
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
  // R-0000620: when `originalPort` is not part of the static `configuredPorts`
  // list, the synthesised rollback config would have to fall back to the
  // captured `originalConfig` — which already pins `targetPort` here (we are
  // on the no-change apply path because the file already lists the target
  // port). That "rollback" would therefore not change anything and the runner
  // could not reach the host on `originalPort` either, leaving us with a
  // misleading "rolled back" status while the verification failure is
  // effectively unrecoverable. Refuse to restart sshd up front in that case
  // so the operator sees an actionable error before we touch the daemon.
  const { configuredPorts } = ssh.getConnectionInfo()
  if (!configuredPorts.includes(parameters.originalPort)) {
    return failed(
      `[sshd.port: ${String(parameters.targetPort)}] sshd_config already lists ` +
        `Port ${String(parameters.targetPort)} but the live socket is not on it; ` +
        `original port ${String(parameters.originalPort)} is not in the static ` +
        "ssh.ports configuration so we cannot synthesise a usable rollback port; " +
        "refusing to restart sshd because a verification failure would not be recoverable"
    )
  }
  const rollbackConfig = buildSshdPortContent(
    parameters.originalConfig,
    parameters.originalPort
  ).newContent
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
  // Reject obviously unsafe targets before acquiring the sshd_config mutex —
  // these guards do not touch the file at all and surface a meaningful error
  // even when the lockdir cannot be created (e.g. read-only /var/lib).
  const configuredPortGuard = rejectWhenTargetPortIsNotConfigured(ssh, targetPort)
  if (configuredPortGuard != null) return configuredPortGuard

  const ufwGuard = await rejectWhenUfwBlocksTargetPort(ssh, targetPort)
  if (ufwGuard != null) return ufwGuard

  // R-0000613: share the same `/etc/ssh/sshd_config` mutex with `sshd.config`
  // so two parallel apply paths cannot race on the read-modify-write cycle.
  // The lock is released through the helper's finally block, including when
  // the inner restart path throws or rolls back.
  // R-0000757: `withMutexLock` now returns a structured `MutexLockResult`.
  // Section throws propagate via `propagateSectionThrows` so the upstream
  // apply layer keeps owning reconnect / fallback recovery.
  const lockResult = await withMutexLock(ssh, {
    failureMessage: `[sshd.port: ${String(targetPort)}] failed to acquire sshd_config mutex`,
    lockName: SSHD_CONFIG_FILE_MUTEX,
    propagateSectionThrows: true,
    section: async () => applySshdPortUnderLock(ssh, targetPort),
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
}

async function applySshdPortUnderLock(
  ssh: SshConnection,
  targetPort: number
): Promise<ModuleResult> {
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
