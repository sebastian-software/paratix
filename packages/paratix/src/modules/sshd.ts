/* eslint-disable max-lines -- sshd module keeps tightly coupled validation/restart helpers together */
import { randomUUID } from "node:crypto"

import { sshdPortMeta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../sshHelpers.js"
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

async function validateSshdConfig(
  ssh: SshConnection,
  originalConfig: string
): Promise<ModuleResult | undefined> {
  await ensurePrivilegeSeparationDirectory(ssh)
  const result = await ssh.exec("sshd -t", { ignoreExitCode: true, silent: true })
  if (result.code === 0) return undefined

  // Best-effort rollback: if the recovery write itself fails (e.g. SFTP error),
  // we still want to surface the original validation failure rather than
  // letting the recovery error mask it or leave the apply path throwing.
  let rollbackError: unknown
  try {
    // Intentional: unguarded write — restoring the original config is more
    // important than concurrency safety during a failed validation rollback.
    await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig, { mode: SSHD_CONFIG_MODE })
  } catch (error) {
    rollbackError = error
  }
  const rollbackMessage =
    rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
  const rollbackSuffix =
    rollbackError == null
      ? "rolled back to previous config"
      : `rollback also failed: ${rollbackMessage}`
  return failed(`sshd config validation failed (sshd -t), ${rollbackSuffix}:\n${result.stderr}`)
}

async function readEffectiveSshdConfig(ssh: SshConnection): Promise<ExecResult> {
  await ensurePrivilegeSeparationDirectory(ssh)
  return ssh.exec(SSHD_EFFECTIVE_CONFIG_COMMAND, { ignoreExitCode: true, silent: true })
}

async function findEffectiveSshdConfigMismatch(
  ssh: SshConnection,
  settings: Record<string, string>
): Promise<string | undefined> {
  const result = await readEffectiveSshdConfig(ssh)
  if (result.code !== 0) return Object.keys(settings)[0]
  return findNonMatchingEffectiveSshdSetting(result.stdout, settings)
}

async function rollbackSshdConfigAfterEffectiveMismatch(
  ssh: SshConnection,
  parameters: { directive: string; originalConfig: string }
): Promise<ModuleResult> {
  try {
    await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
    return failed(
      `[sshd.config: ${parameters.directive}] effective sshd configuration does not match ` +
        "the requested value after parsing includes; rolled back to previous config"
    )
  } catch (rollbackError) {
    const rollbackMessage =
      rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
    return failed(
      `[sshd.config: ${parameters.directive}] effective sshd configuration does not match ` +
        `the requested value after parsing includes; rollback also failed: ${rollbackMessage}`
    )
  }
}

async function rejectNonMatchingEffectiveSshdConfig(
  ssh: SshConnection,
  parameters: { didChange: boolean; originalConfig: string; settings: Record<string, string> }
): Promise<ModuleResult | undefined> {
  const directive = await findEffectiveSshdConfigMismatch(ssh, parameters.settings)
  if (directive == null) return undefined

  if (!parameters.didChange) {
    return failed(
      `[sshd.config: ${directive}] effective sshd configuration ` +
        "does not match the requested value after parsing includes"
    )
  }

  return rollbackSshdConfigAfterEffectiveMismatch(ssh, {
    directive,
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

async function liveSshdPortMatches(ssh: SshConnection, targetPort: number): Promise<boolean> {
  const result = await ssh.exec(`ss -H -ltnp 'sport = :${String(targetPort)}'`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return false
  const output = result.stdout.trim()
  if (output === "") return false
  return /\b(?:sshd|ssh\.socket)\b/v.test(output)
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

type SshdRestartOutcome = "completed" | "disconnected"

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
    return "completed"
  } catch (error) {
    // R-0000283: when the restart aborted the SSH session itself, treat the
    // disconnect as a successful restart. The runner reconnects on the new
    // port; downstream live-verification cannot run on a dead connection.
    if (isRestartDisconnect(error)) return "disconnected"
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

async function rollbackSshdPortAfterFailedVerification(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    originalPort: number
    targetPort: number
  }
): Promise<string | undefined> {
  try {
    ssh.removePort(parameters.targetPort)
  } catch {
    // ssh.removePort is in-memory bookkeeping; never block rollback.
  }
  try {
    await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
  try {
    const serviceUnit = await resolveSshServiceUnit(ssh)
    await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, { ignoreExitCode: true, silent: true })
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
  return undefined
}

async function validateProspectiveSshdConfig(
  ssh: SshConnection,
  content: string
): Promise<ModuleResult | undefined> {
  const temporaryConfigPath = `/tmp/paratix-sshd-dry-run-${randomUUID()}.conf`
  try {
    await ssh.writeFile(temporaryConfigPath, content, { mode: SSHD_CONFIG_MODE })
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

async function dryRunSshdConfig(
  ssh: SshConnection,
  newContent: string,
  successDetail: string
): Promise<ModuleResult> {
  const validationFailure = await validateProspectiveSshdConfig(ssh, newContent)
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

  const writeFailure = await writeSshdConfigIfChanged(ssh, {
    didChange,
    newContent,
    originalConfig,
    settingNames: parameters.settingNames,
  })
  if (writeFailure != null) return writeFailure

  const validationFailure = await validateSshdConfig(ssh, originalConfig)
  if (validationFailure != null) return validationFailure

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
  if (typeof outcome !== "string") return outcome
  // A restart may close the current SSH session even when systemd accepted
  // the command. Reconnect immediately and run the same live-port verification
  // before reporting success; otherwise the runner could switch to an
  // unreachable target port with no rollback chance.
  if (outcome !== "completed") {
    try {
      await ssh.reconnect()
    } catch (error) {
      try {
        ssh.removePort(parameters.targetPort)
      } catch {
        // ssh.removePort is in-memory bookkeeping; never mask the reconnect failure.
      }
      return failed(
        `[sshd.port: ${String(parameters.targetPort)}] sshd restart disconnected the SSH ` +
          `session before the target port could be verified; reconnect failed: ${String(error)}`
      )
    }
  }
  return verifyLiveSshdPortOrRollback(ssh, parameters)
}

async function applySshdPortWhenConfigUnchanged(
  ssh: SshConnection,
  parameters: { originalConfig: string; originalPort: number; targetPort: number }
): Promise<ModuleResult> {
  if (await liveSshdPortMatches(ssh, parameters.targetPort)) return { status: "ok" }
  const verificationFailure = await restartAndVerifySshdPort(ssh, parameters)
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
  const writeFailure = await writeSshdConfigIfChanged(ssh, {
    didChange: true,
    newContent: parameters.newContent,
    originalConfig: parameters.originalConfig,
    settingNames: `Port ${String(parameters.targetPort)}`,
  })
  if (writeFailure != null) return writeFailure
  const validationFailure = await validateSshdConfig(ssh, parameters.originalConfig)
  if (validationFailure != null) return validationFailure
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
        const mismatchingEffectiveDirective = await findEffectiveSshdConfigMismatch(ssh, settings)
        if (mismatchingEffectiveDirective != null) return NEEDS_APPLY
        return "ok"
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
