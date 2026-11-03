import type { SshConnection } from "../types.js"
import type { HostCertificatePolicy, ParsedHostCertificate } from "./sshHostCertificatePolicy.js"

import { shellQuote } from "../ssh.js"
import { scanCertificateSshdConfig } from "./sshCertificateConfig.js"
import {
  certificateCommand,
  type CertificateFileState,
  inspectCertificateFile,
  sameState,
} from "./sshCertificateFiles.js"
import { collectEffectiveSshdDirectiveValues } from "./sshdConfigHelpers.js"
import { certificateSatisfies, parseHostCertificate } from "./sshHostCertificatePolicy.js"
import { publicKeyIdentity } from "./sshHostCertificateWire.js"
import { HostCertificateError } from "./sshSignerProcess.js"

const NON_ROOT_PERMISSION_BITS = 0o077

export const HOST_SSHD_CONFIG = "/etc/ssh/sshd_config"
export type HostDependency = { path: string; state: CertificateFileState }
export type HostTarget = {
  certificate: null | ParsedHostCertificate
  certificateContent: null | string
  certificateState: CertificateFileState
  configContent: string
  configState: CertificateFileState
  dependencies: HostDependency[]
  desiredConfig: string
  effective: string
  hostKeyState: CertificateFileState
  publicKey: string
}

export async function readHostKey(
  ssh: SshConnection,
  policy: HostCertificatePolicy
): Promise<{ publicKey: string; state: CertificateFileState }> {
  const state = await inspectCertificateFile(ssh, policy.hostKeyPath, { preserve: true })
  if (
    state === null ||
    (Number.parseInt(state.metadata.split(" ")[0], 8) & NON_ROOT_PERMISSION_BITS) !== 0
  )
    throw new HostCertificateError(
      "Existing host private key must be root-owned and accessible only to root"
    )
  const links = await certificateCommand(ssh, `stat -c '%h' -- ${shellQuote(policy.hostKeyPath)}`)
  if (links !== "1") throw new HostCertificateError("Host private key must not have hard links")
  const publicKey = publicKeyIdentity(
    await certificateCommand(
      ssh,
      `ssh-keygen -y -P '' -f ${shellQuote(policy.hostKeyPath)} </dev/null`
    )
  )
  assertHostKeyType(publicKey, policy.keyType)
  if (!sameState(state, await inspectCertificateFile(ssh, policy.hostKeyPath, { preserve: true })))
    throw new HostCertificateError("Host key changed during inspection")
  return { publicKey, state }
}

function assertHostKeyType(publicKey: string, keyType: HostCertificatePolicy["keyType"]): void {
  const algorithm = publicKey.split(" ")[0]
  if (
    (keyType === "ed25519" && algorithm !== "ssh-ed25519") ||
    (keyType === "rsa" && algorithm !== "ssh-rsa") ||
    (keyType === "ecdsa" && !algorithm.startsWith("ecdsa-sha2-"))
  )
    throw new HostCertificateError("Existing host key does not match selected keyType")
}

function unquotePath(value: string): string {
  return value.replaceAll(/^["']|["']$/gv, "")
}

async function certificateFile(
  ssh: SshConnection,
  path: string
): Promise<{
  content: null | string
  parsed: null | ParsedHostCertificate
  state: CertificateFileState
}> {
  const state = await inspectCertificateFile(ssh, path, { preserve: true })
  if (state === null) return { content: null, parsed: null, state }
  if ((await certificateCommand(ssh, `stat -c '%h' -- ${shellQuote(path)}`)) !== "1")
    throw new HostCertificateError("Certificate file must not have hard links")
  const content = await ssh.readFile(path)
  try {
    return { content, parsed: parseHostCertificate(content), state }
  } catch {
    return { content, parsed: null, state }
  }
}

async function assertCertificateMapping(
  ssh: SshConnection,
  target: { effective: string; policy: HostCertificatePolicy; publicKey: string }
): Promise<boolean> {
  const paths = collectEffectiveSshdDirectiveValues(target.effective, "HostCertificate")
    .filter((path) => path !== "none")
    .map((value) => unquotePath(value))
  if (paths.filter((path) => path === target.policy.certificatePath).length > 1)
    throw new HostCertificateError("Ambiguous active HostCertificate mapping")
  for (const path of paths) {
    if (path === target.policy.certificatePath) continue
    // eslint-disable-next-line no-await-in-loop -- independently verify every foreign certificate mapping
    const foreign = await certificateFile(ssh, path)
    if (foreign.parsed?.publicKey === target.publicKey)
      throw new HostCertificateError(
        "Another active certificate already maps to the selected host key"
      )
  }
  return paths.includes(target.policy.certificatePath)
}

async function configDependencies(ssh: SshConnection, paths: string[]): Promise<HostDependency[]> {
  const dependencies: HostDependency[] = []
  for (const path of paths.filter((candidatePath) => candidatePath !== HOST_SSHD_CONFIG)) {
    // eslint-disable-next-line no-await-in-loop -- capture a deterministic dependency snapshot
    dependencies.push({ path, state: await inspectCertificateFile(ssh, path, { preserve: true }) })
  }
  return dependencies
}

function assertHostResourceMapping(
  effective: string,
  policy: HostCertificatePolicy,
  protectedFiles: string[]
): void {
  const keys = collectEffectiveSshdDirectiveValues(effective, "HostKey").map((value) =>
    unquotePath(value)
  )
  const protectedPaths = [
    ...protectedFiles,
    ...keys,
    ...collectEffectiveSshdDirectiveValues(effective, "AuthorizedPrincipalsFile"),
  ]
  if (protectedPaths.includes(policy.certificatePath))
    throw new HostCertificateError("Certificate destination overlaps another sshd resource")
  if (keys.filter((path) => path === policy.hostKeyPath).length !== 1)
    throw new HostCertificateError(
      "Selected host key must have one unambiguous effective HostKey mapping"
    )
}

export async function inspectHostTarget(
  ssh: SshConnection,
  policy: HostCertificatePolicy
): Promise<HostTarget> {
  const host = await readHostKey(ssh, policy)
  const configState = await inspectCertificateFile(ssh, HOST_SSHD_CONFIG, { preserve: true })
  if (configState === null) throw new HostCertificateError("Active sshd configuration is missing")
  const configContent = await ssh.readFile(HOST_SSHD_CONFIG)
  const scan = await scanCertificateSshdConfig(ssh, {
    content: configContent,
    path: HOST_SSHD_CONFIG,
    rejectMatch: false,
  })
  if (scan.files.includes(policy.certificatePath) || scan.files.includes(policy.hostKeyPath))
    throw new HostCertificateError("Host key/certificate overlaps sshd configuration")
  const dependencies = await configDependencies(ssh, scan.files)
  const effective = await certificateCommand(ssh, "sshd -T")
  assertHostResourceMapping(effective, policy, [
    ...scan.files,
    ...scan.caFiles,
    ...scan.revocations,
  ])
  const mapped = await assertCertificateMapping(ssh, {
    effective,
    policy,
    publicKey: host.publicKey,
  })
  const certificate = await certificateFile(ssh, policy.certificatePath)
  if (certificate.parsed !== null && certificate.parsed.publicKey !== host.publicKey && !mapped)
    throw new HostCertificateError("Certificate destination contains a foreign host certificate")
  return {
    certificate: certificate.parsed,
    certificateContent: certificate.content,
    certificateState: certificate.state,
    configContent,
    configState,
    dependencies,
    desiredConfig: mapped
      ? configContent
      : `HostCertificate ${policy.certificatePath}\n${configContent}`,
    effective,
    hostKeyState: host.state,
    publicKey: host.publicKey,
  }
}

export function targetConverged(
  target: HostTarget,
  policy: HostCertificatePolicy,
  now: number
): boolean {
  return (
    target.certificate !== null &&
    certificateSatisfies(target.certificate, { now, policy, publicKey: target.publicKey }) &&
    target.desiredConfig === target.configContent &&
    target.certificateState?.metadata === "644 0 0"
  )
}

export function assertHostAlgorithms(
  effective: string,
  certificate: ParsedHostCertificate,
  input: { policy: HostCertificatePolicy; stagedPath: string }
): void {
  const { policy, stagedPath } = input
  const certificates = collectEffectiveSshdDirectiveValues(effective, "HostCertificate").map(
    (value) => unquotePath(value)
  )
  const keys = collectEffectiveSshdDirectiveValues(effective, "HostKey").map((value) =>
    unquotePath(value)
  )
  const algorithms = collectEffectiveSshdDirectiveValues(effective, "HostKeyAlgorithms")
    .join(",")
    .split(",")
  const allowed =
    certificate.algorithm === "ssh-rsa-cert-v01@openssh.com"
      ? ["rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com"]
      : [certificate.algorithm]
  if (
    !certificates.includes(stagedPath) ||
    !keys.includes(policy.hostKeyPath) ||
    !allowed.some((value) => algorithms.includes(value))
  )
    throw new HostCertificateError(
      "Effective HostKey, HostCertificate or certificate HostKeyAlgorithms policy conflicts with this certificate"
    )
}

export function convergedHostTarget(
  target: HostTarget,
  policy: HostCertificatePolicy,
  now: number
): boolean {
  if (!targetConverged(target, policy, now) || target.certificate === null) return false
  assertHostAlgorithms(target.effective, target.certificate, {
    policy,
    stagedPath: policy.certificatePath,
  })
  return true
}

export function reusableHostCertificate(
  target: HostTarget,
  policy: HostCertificatePolicy,
  now: number
): null | string {
  if (
    target.certificate === null ||
    !certificateSatisfies(target.certificate, { now, policy, publicKey: target.publicKey })
  )
    return null
  return target.certificateContent
}
