/* eslint-disable max-lines -- sshd module keeps tightly coupled validation/restart helpers together */
import { randomUUID } from "node:crypto"

import { sshdPortMeta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../sshHelpers.js"
import {
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
  sshdSettingMatchesEverywhere,
} from "./sshdConfigHelpers.js"

const DEFAULT_SSH_PORT = 22
const PRIVILEGE_SEPARATION_DIRECTORY = "/run/sshd"
const SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
const SSHD_CONFIG_MODE = "0644"
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
    if (/[\n\r]/v.test(value)) {
      throw new Error(
        `sshd.config: value for ${key} must not contain newline characters: ${JSON.stringify(value)}`
      )
    }
  }
}

async function validateSshdConfig(ssh: SshConnection, originalConfig: string): Promise<void> {
  await ensurePrivilegeSeparationDirectory(ssh)
  const result = await ssh.exec("sshd -t", { ignoreExitCode: true, silent: true })
  if (result.code !== 0) {
    // Intentional: unguarded write — restoring the original config is more
    // important than concurrency safety during a failed validation rollback.
    await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig, { mode: SSHD_CONFIG_MODE })
    throw new Error(
      `sshd config validation failed (sshd -t), rolled back to previous config:\n${result.stderr}`
    )
  }
}

async function ensurePrivilegeSeparationDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${shellQuote(PRIVILEGE_SEPARATION_DIRECTORY)}`, {
    ignoreExitCode: false,
    silent: true,
  })
}

async function captureSshSocketState(ssh: SshConnection): Promise<SshSocketState> {
  const socketExists = await ssh.exec("systemctl cat ssh.socket >/dev/null 2>&1", {
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
  const sshdExists = await ssh.exec(`${SYSTEMCTL} cat sshd.service >/dev/null 2>&1`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (sshdExists.code === 0) {
    return "sshd"
  }

  const sshExists = await ssh.exec(`${SYSTEMCTL} cat ssh.service >/dev/null 2>&1`, {
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

async function reloadSshd(ssh: SshConnection): Promise<ModuleResult> {
  const serviceUnit = await resolveSshServiceUnit(ssh)
  const result = await ssh.exec(`${SYSTEMCTL} reload ${serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
    ? { status: "changed" }
    : failedCommand(`[sshd.config] systemctl reload ${serviceUnit} failed`, result)
}

async function liveSshdPortMatches(ssh: SshConnection, targetPort: number): Promise<boolean> {
  const result = await ssh.exec(`ss -H -ltn 'sport = :${String(targetPort)}'`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0 && result.stdout.trim() !== ""
}

async function restoreSshdPortRestartFailure(
  ssh: SshConnection,
  parameters: {
    originalConfig: string
    serviceBootState?: SshdServiceBootState
    serviceUnit?: SshdServiceUnit
    socketState: SshSocketState
    targetPort: number
  }
): Promise<void> {
  ssh.removePort(parameters.targetPort)
  await ssh.writeFile(SSHD_CONFIG_PATH, parameters.originalConfig, { mode: SSHD_CONFIG_MODE })
  await restoreSshServiceBootState(ssh, parameters.serviceBootState)
  await restoreSocketActivatedSsh(ssh, parameters.socketState)
  if (parameters.serviceUnit == null) return
  await ssh.exec(`${SYSTEMCTL} restart ${parameters.serviceUnit}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function restartSshdOnNewPort(
  ssh: SshConnection,
  targetPort: number,
  originalConfig: string
): Promise<void> {
  ssh.addPort(targetPort)
  let socketState: SshSocketState = { exists: false }
  let serviceUnit: SshdServiceUnit | undefined
  let serviceBootState: SshdServiceBootState | undefined
  try {
    socketState = await disableSocketActivatedSsh(ssh)
    serviceUnit = await resolveSshServiceUnit(ssh)
    serviceBootState = await ensureSshServiceBootEnabled(ssh, { serviceUnit, socketState })
    await ssh.exec(`${SYSTEMCTL} restart ${serviceUnit}`, { silent: true })
  } catch (error) {
    if (isRestartDisconnect(error)) return
    await restoreSshdPortRestartFailure(ssh, {
      originalConfig,
      serviceBootState,
      serviceUnit,
      socketState,
      targetPort,
    })
    throw error
  }
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

async function applySshdPort(ssh: SshConnection, targetPort: number): Promise<ModuleResult> {
  const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
  const { didChange, newContent } = buildSshdPortContent(originalConfig, targetPort)
  if (!didChange) {
    if (await liveSshdPortMatches(ssh, targetPort)) return { status: "ok" }
    await restartSshdOnNewPort(ssh, targetPort, originalConfig)
    return {
      meta: [sshdPortMeta(targetPort)],
      status: "changed",
    }
  }

  await guardedWriteFile(ssh, {
    mode: SSHD_CONFIG_MODE,
    newContent,
    originalContent: originalConfig,
    remotePath: SSHD_CONFIG_PATH,
  })
  await validateSshdConfig(ssh, originalConfig)
  await restartSshdOnNewPort(ssh, targetPort, originalConfig)

  return {
    meta: [sshdPortMeta(targetPort)],
    status: "changed",
  }
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

        const originalConfig = await ssh.readFile(SSHD_CONFIG_PATH)
        const { didChange, newContent } = buildSshdConfigContent(originalConfig, settings)
        const nonConvergingMatchOverride = rejectNonConvergingSshdMatchOverrides(
          newContent,
          settings
        )
        if (nonConvergingMatchOverride != null) return nonConvergingMatchOverride
        if (didChange) {
          await guardedWriteFile(ssh, {
            mode: SSHD_CONFIG_MODE,
            newContent,
            originalContent: originalConfig,
            remotePath: SSHD_CONFIG_PATH,
          })
        }

        await validateSshdConfig(ssh, originalConfig)

        if (!didChange) {
          return { status: "ok" }
        }

        const reloadResult = await reloadSshd(ssh)
        if (reloadResult.status === "failed") {
          await ssh.writeFile(SSHD_CONFIG_PATH, originalConfig, { mode: SSHD_CONFIG_MODE })
        }
        return reloadResult
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const content = await ssh.readFile(SSHD_CONFIG_PATH)
        for (const [key, value] of Object.entries(settings)) {
          if (!sshdSettingMatchesEverywhere(content, key, value)) {
            return NEEDS_APPLY
          }
        }
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
          if (await socketActivationBootPathNeedsApply(ssh)) return NEEDS_APPLY
          return (await liveSshdPortMatches(ssh, targetPort)) ? "ok" : NEEDS_APPLY
        }
        if (portValues.every((portValue) => portValue === String(targetPort))) {
          if (await socketActivationBootPathNeedsApply(ssh)) return NEEDS_APPLY
          return (await liveSshdPortMatches(ssh, targetPort)) ? "ok" : NEEDS_APPLY
        }
        return NEEDS_APPLY
      },
      name: `sshd.port: ${targetPort}`,
    }
  },
}
