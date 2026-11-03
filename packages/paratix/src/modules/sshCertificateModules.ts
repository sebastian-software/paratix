import { failed } from "../moduleFailure.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { buildCertificateConfig, scanCertificateSshdConfig } from "./sshCertificateConfig.js"
import {
  type CertificateFile,
  CertificateFileError,
  certificateFileMatches,
  inspectCertificateFile,
} from "./sshCertificateFiles.js"
import { CertificateFilesTransaction } from "./sshCertificateFileTransaction.js"
import {
  assertDistinctCertificatePaths,
  CERTIFICATE_SSHD_CONFIG_PATH,
  certificatePaths,
  certificateState,
  type CertificateState,
  normalizeCaKeys,
  TRUSTED_USER_CA_PATH,
  type TrustedUserCaOptions,
} from "./sshCertificateValidation.js"
import { type SshdConfigTransaction, withSshdConfigTransaction } from "./sshd.js"

type CaParameters = {
  content?: string
  principalsFile: string
  revokedKeys?: string
  state: CertificateState
}
type PreparedCa = {
  ca: CertificateFile
  config: { content: string } & CertificateFile
  configChanged: boolean
  expected: Record<string, string>
  revocation?: CertificateFile
}
export type CertificateRunMode = "apply" | "check" | "dry-run"

export async function activeCertificateConfig(
  ssh: SshConnection,
  targets: string[],
  rejectMatch: boolean
): Promise<{ caFiles: string[]; config: CertificateFile; content: string; revocations: string[] }> {
  const original = await inspectCertificateFile(ssh, CERTIFICATE_SSHD_CONFIG_PATH)
  if (original === null) throw new CertificateFileError("Active /etc/ssh/sshd_config is missing")
  const content = await ssh.readFile(CERTIFICATE_SSHD_CONFIG_PATH)
  const scan = await scanCertificateSshdConfig(ssh, {
    content,
    path: CERTIFICATE_SSHD_CONFIG_PATH,
    rejectMatch,
  })
  assertDistinctCertificatePaths([...targets, ...scan.files])
  return {
    caFiles: scan.caFiles,
    config: { original, path: CERTIFICATE_SSHD_CONFIG_PATH },
    content,
    revocations: scan.revocations,
  }
}

function caSettings(parameters: CaParameters): Record<string, string> {
  return {
    AuthorizedPrincipalsFile: parameters.principalsFile,
    ...(parameters.revokedKeys === undefined ? {} : { RevokedKeys: parameters.revokedKeys }),
    TrustedUserCAKeys: TRUSTED_USER_CA_PATH,
  }
}

async function prepareCa(ssh: SshConnection, parameters: CaParameters): Promise<PreparedCa> {
  const active = await activeCertificateConfig(
    ssh,
    [
      TRUSTED_USER_CA_PATH,
      parameters.principalsFile,
      ...(parameters.revokedKeys === undefined ? [] : [parameters.revokedKeys]),
    ],
    true
  )
  if (parameters.revokedKeys === undefined) {
    assertDistinctCertificatePaths([
      TRUSTED_USER_CA_PATH,
      parameters.principalsFile,
      ...active.revocations,
    ])
  }
  const settings = caSettings(parameters)
  const content = buildCertificateConfig(active.content, settings, parameters.state)
  const ca: CertificateFile = {
    content: parameters.content,
    original: await inspectCertificateFile(ssh, TRUSTED_USER_CA_PATH),
    path: TRUSTED_USER_CA_PATH,
  }
  const revocation =
    parameters.revokedKeys === undefined
      ? undefined
      : {
          content: "",
          original: await inspectCertificateFile(ssh, parameters.revokedKeys, { preserve: true }),
          path: parameters.revokedKeys,
          preserve: true,
        }
  return {
    ca,
    config: { ...active.config, content },
    configChanged: content !== active.content,
    expected:
      parameters.state === "present"
        ? settings
        : Object.fromEntries(Object.keys(settings).map((key) => [key, "none"])),
    revocation,
  }
}

function caConverged(prepared: PreparedCa, state: CertificateState): boolean {
  return (
    !prepared.configChanged &&
    certificateFileMatches(prepared.ca) &&
    (state === "absent" ||
      prepared.revocation === undefined ||
      certificateFileMatches(prepared.revocation))
  )
}

async function rollbackCa(
  files: CertificateFilesTransaction,
  transaction: SshdConfigTransaction,
  parameters: { error: unknown; reloadAttempted: boolean }
): Promise<ModuleResult> {
  const failures = await files.rollback()
  if (parameters.reloadAttempted) {
    try {
      await transaction.restoreReload()
    } catch (restoreError) {
      failures.push(`live sshd configuration: ${String(restoreError)}`)
    }
  }
  const suffix =
    failures.length === 0
      ? "; previous files and metadata restored"
      : `; rollback also failed: ${failures.join("; ")}`
  return failed(`[ssh.trustedUserCa] ${String(parameters.error)}${suffix}`)
}

async function prepareReferencedCaFiles(
  files: CertificateFilesTransaction,
  parameters: { prepared: PreparedCa; state: CertificateState }
): Promise<void> {
  if (parameters.state === "absent") return
  await files.write(parameters.prepared.ca)
  if (parameters.prepared.revocation !== undefined)
    await files.write(parameters.prepared.revocation)
}

async function applyCa(
  ssh: SshConnection,
  transaction: SshdConfigTransaction,
  parameters: { prepared: PreparedCa; state: CertificateState }
): Promise<ModuleResult> {
  const { prepared, state } = parameters
  const files = new CertificateFilesTransaction(ssh)
  let reloadAttempted = false
  try {
    // An active daemon reads trust files at login, so reject the complete
    // candidate before changing even an already-referenced CA or revocation file.
    await transaction.validate(prepared.config.content, prepared.expected)
    // Referenced files are ready before any live sshd directive points at them.
    await prepareReferencedCaFiles(files, parameters)
    if (prepared.configChanged) await files.write(prepared.config)
    await transaction.readEffective(prepared.expected)
    if (prepared.configChanged || state === "absent") {
      reloadAttempted = true
      await transaction.reload()
    }
    // Deactivation must have been validated, effectively checked and reloaded
    // before the CA trust file is deleted. Principal/revocation data is retained.
    if (state === "absent") await files.remove(prepared.ca)
  } catch (error) {
    return rollbackCa(files, transaction, { error, reloadAttempted })
  }
  const cleanup = await files.cleanup()
  return cleanup.length === 0
    ? { status: "changed" }
    : failed(`[ssh.trustedUserCa] temporary-file cleanup failed: ${cleanup.join("; ")}`)
}

async function runCa(
  ssh: null | SshConnection,
  parameters: CaParameters,
  mode: CertificateRunMode
): Promise<ModuleResult> {
  if (ssh === null) return failed("[ssh.trustedUserCa] SSH connection is required")
  try {
    return await withSshdConfigTransaction(ssh, {
      dryRun: mode !== "apply",
      name: "ssh.trustedUserCa",
      async section(transaction) {
        const connection = transaction.connection
        const prepared = await prepareCa(connection, parameters)
        const converged = caConverged(prepared, parameters.state)
        if (mode === "check") {
          if (!converged) return { status: "changed" }
          await transaction.readEffective(prepared.expected)
          return { status: "ok" }
        }
        if (mode === "dry-run" || converged) {
          await transaction.validate(prepared.config.content, prepared.expected)
          if (!prepared.configChanged) await transaction.readEffective(prepared.expected)
          return { status: converged ? "ok" : "changed" }
        }
        return applyCa(connection, transaction, { prepared, state: parameters.state })
      },
    })
  } catch (error) {
    return failed(`[ssh.trustedUserCa] ${String(error)}`)
  }
}

/**
 * Manage the fixed SSH user-CA file and global `sshd_config` directives.
 *
 * `state: "present"` is the default and requires at least one complete
 * OpenSSH public CA key; `state: "absent"` may omit `publicKey`. The optional
 * principals template defaults to `/etc/ssh/auth_principals/%u` and must be
 * identical to the template passed to `authorizedPrincipals`. Omitting
 * `revokedKeys` leaves `RevokedKeys` unmanaged; supplying it creates a missing
 * target as an empty text revocation list and preserves existing text or KRL
 * bytes and metadata. Enable this module after its principal files exist; on
 * removal, trust is disabled and reloaded before the CA file is deleted.
 *
 * @param options - The discriminated CA content, paths, and desired state.
 * @returns A module managing `/etc/ssh/trusted_user_ca_keys` and the related global directives.
 */
export function trustedUserCa(options: TrustedUserCaOptions): Module {
  const state = certificateState(options.state)
  const paths = certificatePaths(options)
  const content = state === "present" ? normalizeCaKeys(options.publicKey ?? "") : undefined
  const parameters: CaParameters = { ...paths, content, state }
  return {
    async _applyDryRun(ssh) {
      return runCa(ssh, parameters, "dry-run")
    },
    async apply(ssh) {
      return runCa(ssh, parameters, "apply")
    },
    async check(ssh) {
      const result = await runCa(ssh, parameters, "check")
      return result.status === "ok" ? "ok" : NEEDS_APPLY
    },
    name: `ssh.trustedUserCa (${state})`,
  }
}
