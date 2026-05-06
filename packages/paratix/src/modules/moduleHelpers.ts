import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
const FLAG_LOCK_WAIT_SECONDS = 300

// Flag names land directly in shell commands like `[ -f /var/lib/paratix/flags/<name> ]`
// and `find ... -name '<prefix>*' -delete`. We therefore reject any name that could
// resolve to a directory traversal segment (`..`, leading dot, trailing dot) or
// contain a path separator. The pattern requires an alphanumeric leading
// character; afterwards each character must either be a word character / dash, or
// a dot that is immediately followed by an alphanumeric character. That single
// alternation forbids `..`, leading or trailing dots, and slashes without
// nesting quantifiers (which would trigger the unsafe-regex heuristic).
const FLAG_NAME_PATTERN = /^[A-Za-z0-9](?:[\w\-]|\.[A-Za-z0-9])*$/v

function validateFlagName(value: string, label: string): void {
  if (!FLAG_NAME_PATTERN.test(value)) {
    throw new Error(
      `${label} must match ${String(FLAG_NAME_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
}

export async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
}

export async function hasFlag(ssh: SshConnection, flagName: string): Promise<boolean> {
  validateFlagName(flagName, "flagName")
  return ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`)
}

export async function setVersionedFlag(
  ssh: SshConnection,
  flagName: string,
  flagPrefix: string
): Promise<void> {
  validateFlagName(flagName, "flagName")
  validateFlagName(flagPrefix, "flagPrefix")
  await ensureFlagsDirectory(ssh)
  const glob = shellQuote(`${flagPrefix}*`)
  await ssh.exec(
    `find ${FLAGS_DIRECTORY} -maxdepth 1 -name ${glob} ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
    { silent: true }
  )
}

export async function setFlag(ssh: SshConnection, flagName: string): Promise<void> {
  validateFlagName(flagName, "flagName")
  await ensureFlagsDirectory(ssh)
  await ssh.exec(`touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`, { silent: true })
}

function flagPath(flagName: string): string {
  return `${FLAGS_DIRECTORY}/${shellQuote(flagName)}`
}

function flagLockName(flagName: string): string {
  return `${flagName}.lock`
}

async function acquireFlagLock(ssh: SshConnection, lockName: string): Promise<boolean> {
  validateFlagName(lockName, "lockName")
  await ensureFlagsDirectory(ssh)
  const result = await ssh.exec(`mkdir ${flagPath(lockName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
}

async function releaseFlagLock(ssh: SshConnection, lockName: string): Promise<void> {
  validateFlagName(lockName, "lockName")
  await ssh.exec(`rmdir ${flagPath(lockName)}`, { ignoreExitCode: true, silent: true })
}

async function waitForFlagLockResolution(
  ssh: SshConnection,
  parameters: { flagName: string; lockName: string; waitSeconds: number }
): Promise<"resolved" | ModuleResult> {
  const flag = flagPath(parameters.flagName)
  const lock = flagPath(parameters.lockName)
  const waitSeconds = String(parameters.waitSeconds)
  const command =
    `i=0; while [ -d ${lock} ] && [ ! -f ${flag} ] && [ "$i" -lt ${waitSeconds} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ] || [ -f ${flag} ]`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  if (result.code === 0) return "resolved"
  return failedCommand(
    `[moduleHelpers] timed out waiting for flag lock ${parameters.lockName}`,
    result
  )
}

export async function applyWithFlagLock(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    shouldApply?: () => Promise<boolean>
    waitSeconds?: number
  }
): Promise<ModuleResult> {
  validateFlagName(parameters.flagName, "flagName")
  const lockName = flagLockName(parameters.flagName)
  validateFlagName(lockName, "lockName")

  return tryApplyWithFlagLock(ssh, { ...parameters, lockName })
}

async function runLockedFlagApply(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    lockName: string
    shouldApply?: () => Promise<boolean>
  }
): Promise<ModuleResult> {
  try {
    if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }
    return await parameters.apply()
  } finally {
    await releaseFlagLock(ssh, parameters.lockName)
  }
}

async function shouldRunFlagApply(
  ssh: SshConnection,
  parameters: {
    flagName: string
    shouldApply?: () => Promise<boolean>
  }
): Promise<boolean> {
  if (!(await hasFlag(ssh, parameters.flagName))) return true
  return parameters.shouldApply == null ? false : parameters.shouldApply()
}

async function tryApplyWithFlagLock(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    lockName: string
    shouldApply?: () => Promise<boolean>
    waitSeconds?: number
  }
): Promise<ModuleResult> {
  if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }

  if (await acquireFlagLock(ssh, parameters.lockName)) {
    return runLockedFlagApply(ssh, parameters)
  }

  const waitResult = await waitForFlagLockResolution(ssh, {
    flagName: parameters.flagName,
    lockName: parameters.lockName,
    waitSeconds: parameters.waitSeconds ?? FLAG_LOCK_WAIT_SECONDS,
  })
  if (waitResult !== "resolved") return waitResult
  return tryApplyWithFlagLock(ssh, parameters)
}
