import { isIP } from "node:net"
import { posix } from "node:path"

import type { HostCertificateOptions, HostCertificateRequest } from "./sshHostCertificateTypes.js"

import {
  hostCaIdentity,
  publicKeyIdentity,
  sshString,
  SshWireReader,
  verifyCertificateSignature,
} from "./sshHostCertificateWire.js"
import { HostCertificateError } from "./sshSignerProcess.js"

const MAX_HOSTNAME_LENGTH = 253
const MAX_HOST_LABEL_LENGTH = 63
const SSH_SERIAL_BYTES = 8

export type HostCertificatePolicy = {
  caPublicKey: string
  certificatePath: string
  hostKeyPath: string
  keyType: "ecdsa" | "ed25519" | "rsa"
  principals: string[]
  renewBefore: number
  validity: number
}
export type ParsedHostCertificate = {
  algorithm: string
  caPublicKey: string
  principals: string[]
  publicKey: string
  validAfter: number
  validBefore: number
}
const UNITS: Record<string, number> = { d: 86_400, h: 3600, m: 60, s: 1, w: 604_800 }

export function durationSeconds(value: number | string): number {
  let seconds = typeof value === "number" ? value : Number.NaN
  if (typeof value === "string") {
    const match = /^(?<count>\d+)(?<unit>[smhdw])$/v.exec(value)
    if (match?.groups !== undefined) seconds = Number(match.groups.count) * UNITS[match.groups.unit]
  }
  if (!Number.isSafeInteger(seconds) || seconds < 0)
    throw new HostCertificateError(
      "Certificate durations must be finite whole seconds or s/m/h/d/w durations"
    )
  return seconds
}

export function assertHostCertificatePath(value: string): void {
  if (!/^\/[\w.\/\-]+$/v.test(value) || posix.normalize(value) !== value || value.endsWith("/"))
    throw new HostCertificateError("Host certificate paths must be normalized absolute file paths")
}

function policyPaths(
  options: HostCertificateOptions
): Pick<HostCertificatePolicy, "certificatePath" | "hostKeyPath" | "keyType"> {
  const keyType = options.keyType ?? "ed25519"
  if (!["ecdsa", "ed25519", "rsa"].includes(keyType))
    throw new HostCertificateError("Unsupported host key type")
  const hostKeyPath = options.hostKeyPath ?? `/etc/ssh/ssh_host_${keyType}_key`
  const certificatePath = options.certificatePath ?? `${hostKeyPath}-cert.pub`
  assertHostCertificatePath(hostKeyPath)
  assertHostCertificatePath(certificatePath)
  if (
    hostKeyPath === certificatePath ||
    [hostKeyPath, certificatePath].some(
      (path) => path === "/etc/ssh/sshd_config" || path.startsWith("/var/lib/paratix/")
    )
  )
    throw new HostCertificateError("Host certificate paths overlap protected files")
  return { certificatePath, hostKeyPath, keyType }
}
function validHostPrincipal(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_HOSTNAME_LENGTH)
    return false
  if (isIP(value) !== 0) return true
  const hostname = value.endsWith(".") ? value.slice(0, -1) : value
  return hostname.split(".").every((label) => validHostLabel(label))
}
function validHostLabel(label: string): boolean {
  return (
    label.length > 0 &&
    label.length <= MAX_HOST_LABEL_LENGTH &&
    /^[A-Za-z0-9\-]+$/v.test(label) &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  )
}
function policyPrincipals(input: readonly string[]): string[] {
  const principals = [...new Set(input)].toSorted()
  if (principals.length === 0 || !principals.every((principal) => validHostPrincipal(principal)))
    throw new HostCertificateError(
      "Host certificates require explicit nonempty hostname or IP principals"
    )
  return principals
}
function assertSignerDescriptor(value: unknown): void {
  if (
    typeof value !== "object" ||
    value === null ||
    Reflect.get(value, "version") !== 1 ||
    typeof Reflect.get(value, "sign") !== "function"
  )
    throw new HostCertificateError("Unsupported host certificate signer")
}
export function hostCertificatePolicy(options: HostCertificateOptions): HostCertificatePolicy {
  const { certificatePath, hostKeyPath, keyType } = policyPaths(options)
  const principals = policyPrincipals(options.principals)
  const validity = durationSeconds(options.validity ?? "30d")
  const renewBefore = durationSeconds(options.renewBefore ?? "7d")
  if (validity === 0 || renewBefore >= validity)
    throw new HostCertificateError("Certificate policy requires 0 <= renewBefore < validity")
  assertSignerDescriptor(options.signer)
  const caPublicKey = hostCaIdentity(options.signer.caPublicKey)
  return { caPublicKey, certificatePath, hostKeyPath, keyType, principals, renewBefore, validity }
}

function publicFields(reader: SshWireReader, algorithm: string): Buffer[] {
  if (algorithm === "ssh-ed25519") return [reader.string()]
  if (algorithm === "ssh-rsa" || algorithm.startsWith("ecdsa-sha2-"))
    return [reader.string(), reader.string()]
  throw new HostCertificateError("Unsupported host certificate key algorithm")
}

function readHostCertificateKey(reader: SshWireReader, algorithm: string): string {
  reader.text()
  reader.string() // nonce
  const rawAlgorithm = algorithm.replace("-cert-v01@openssh.com", "")
  const fields = publicFields(reader, rawAlgorithm)
  reader.bytes(SSH_SERIAL_BYTES) // Public serials may use the complete uint64 range.
  if (reader.uint32() !== 2) throw new HostCertificateError("A host certificate is required")
  reader.string() // public key identity
  return `${rawAlgorithm} ${Buffer.concat([sshString(rawAlgorithm), ...fields.map((field) => sshString(field))]).toString("base64")}`
}
function readHostCertificateBody(
  reader: SshWireReader
): Pick<ParsedHostCertificate, "principals" | "validAfter" | "validBefore"> {
  const principalReader = new SshWireReader(reader.string())
  const principals: string[] = []
  while (principalReader.offset < principalReader.data.length)
    principals.push(principalReader.text())
  const validAfter = reader.uint64()
  const validBefore = reader.uint64()
  if (reader.string().length > 0)
    throw new HostCertificateError("Host certificate critical options are unsupported")
  reader.string() // Noncritical extensions do not change host identity.
  if (reader.string().length > 0)
    throw new HostCertificateError("Unexpected reserved certificate data")
  return { principals: principals.toSorted(), validAfter, validBefore }
}
function readCertificateAuthority(reader: SshWireReader): string {
  const ca = reader.string()
  const signed = reader.data.subarray(0, reader.offset)
  const signature = reader.string()
  reader.end()
  verifyCertificateSignature(ca, signature, signed)
  const caReader = new SshWireReader(ca)
  return `${caReader.text()} ${ca.toString("base64")}`
}
export function parseHostCertificate(value: string): ParsedHostCertificate {
  try {
    const [algorithm, encoded] = publicKeyIdentity(value).split(" ")
    if (!algorithm.endsWith("-cert-v01@openssh.com"))
      throw new HostCertificateError("Expected an OpenSSH certificate")
    const reader = new SshWireReader(Buffer.from(encoded, "base64"))
    const publicKey = readHostCertificateKey(reader, algorithm)
    const body = readHostCertificateBody(reader)
    const caPublicKey = readCertificateAuthority(reader)
    return { algorithm, caPublicKey, publicKey, ...body }
  } catch {
    throw new HostCertificateError("Invalid, unsupported or untrusted SSH host certificate")
  }
}

export function certificateSatisfies(
  certificate: ParsedHostCertificate,
  state: { now: number; policy: HostCertificatePolicy; publicKey: string }
): boolean {
  const { now, policy } = state
  return (
    certificate.publicKey === publicKeyIdentity(state.publicKey) &&
    certificate.caPublicKey === policy.caPublicKey &&
    JSON.stringify(certificate.principals) === JSON.stringify(policy.principals) &&
    certificate.validAfter <= now &&
    certificate.validBefore - now > policy.renewBefore &&
    certificate.validBefore > certificate.validAfter &&
    certificate.validBefore - certificate.validAfter <= policy.validity
  )
}

export function assertSignerCertificate(
  value: string,
  state: {
    now: number
    policy: HostCertificatePolicy
    publicKey: string
    request: HostCertificateRequest
  }
): ParsedHostCertificate {
  const certificate = parseHostCertificate(value)
  if (
    !certificateSatisfies(certificate, state) ||
    certificate.validAfter < state.request.validAfter ||
    certificate.validBefore > state.request.validBefore
  )
    throw new HostCertificateError(
      "Signer certificate does not satisfy the requested host identity or validity bounds"
    )
  return certificate
}
