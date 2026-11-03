import type { CertificateFileState } from "./sshCertificateFiles.js"
import type { HostDependency } from "./sshHostCertificateTarget.js"

import {
  assertHostCertificatePath,
  hostCertificatePolicy,
  type HostCertificatePolicy,
} from "./sshHostCertificatePolicy.js"
import { HOST_SSHD_CONFIG } from "./sshHostCertificateTarget.js"
import { publicKeyIdentity } from "./sshHostCertificateWire.js"
import { HostCertificateError } from "./sshSignerProcess.js"

export type PendingFile = {
  candidate: CertificateFileState
  original: CertificateFileState
  path: string
  role: "certificate" | "config"
}
export type HostPending = {
  dependencies: HostDependency[]
  files: PendingFile[]
  hostKeyState: CertificateFileState
  id: string
  phase: "complete-new" | "complete-old" | "prepared" | "rollback"
  policy: HostCertificatePolicy
  publicKey: string
  version: 1
}
export type PendingState = { hash: string; manifest: HostPending }

function recoveryError(): never {
  throw new HostCertificateError(
    "Host certificate recovery state is unsafe, incomplete or conflicting; retained for inspection"
  )
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
function state(value: unknown): value is CertificateFileState {
  return (
    value === null ||
    (record(value) &&
      typeof value.hash === "string" &&
      /^[a-f0-9]{64}$/v.test(value.hash) &&
      typeof value.metadata === "string" &&
      /^[0-7]{3,4} 0 \d+$/v.test(value.metadata))
  )
}
function dependency(value: unknown): value is HostDependency {
  return record(value) && typeof value.path === "string" && state(value.state)
}
function pendingFile(value: unknown): value is PendingFile {
  return (
    record(value) &&
    (value.role === "certificate" || value.role === "config") &&
    typeof value.path === "string" &&
    state(value.original) &&
    state(value.candidate) &&
    value.candidate !== null &&
    (value.role !== "certificate" || value.candidate.metadata === "644 0 0")
  )
}

function policyShape(value: unknown): value is {
  caPublicKey: string
  certificatePath: string
  hostKeyPath: string
  keyType: "ecdsa" | "ed25519" | "rsa"
  principals: string[]
  renewBefore: number
  validity: number
} {
  if (!record(value)) return false
  return validPolicyPaths(value) && validPolicyIdentity(value)
}
function validPolicyPaths(value: Record<string, unknown>): boolean {
  return (
    typeof value.caPublicKey === "string" &&
    typeof value.certificatePath === "string" &&
    typeof value.hostKeyPath === "string"
  )
}
function validPolicyIdentity(value: Record<string, unknown>): boolean {
  return (
    ["ecdsa", "ed25519", "rsa"].includes(String(value.keyType)) &&
    Array.isArray(value.principals) &&
    value.principals.every((item: unknown) => typeof item === "string") &&
    typeof value.validity === "number" &&
    typeof value.renewBefore === "number"
  )
}
function parsePolicy(value: unknown): HostCertificatePolicy {
  if (!policyShape(value)) return recoveryError()
  const policy = hostCertificatePolicy({
    certificatePath: value.certificatePath,
    hostKeyPath: value.hostKeyPath,
    keyType: value.keyType,
    principals: value.principals,
    renewBefore: value.renewBefore,
    signer: {
      caPublicKey: value.caPublicKey,
      async sign() {
        return new Promise<never>((_resolve, reject) => {
          reject(new Error("Unreachable"))
        })
      },
      version: 1,
    },
    validity: value.validity,
  })
  if (JSON.stringify(policy) !== JSON.stringify(value)) return recoveryError()
  return policy
}

function pendingPhase(value: unknown): value is HostPending["phase"] {
  return (
    value === "prepared" ||
    value === "rollback" ||
    value === "complete-new" ||
    value === "complete-old"
  )
}
function pendingHeader(value: Record<string, unknown>): boolean {
  return (
    value.version === 1 &&
    typeof value.id === "string" &&
    /^[a-f0-9\-]{36}$/v.test(value.id) &&
    typeof value.publicKey === "string"
  )
}
function pendingCollections(value: Record<string, unknown>): boolean {
  return (
    Array.isArray(value.dependencies) &&
    value.dependencies.every(dependency) &&
    Array.isArray(value.files) &&
    value.files.length === 2 &&
    value.files.every(pendingFile)
  )
}
function pendingShape(value: unknown): value is { policy: unknown } & Omit<HostPending, "policy"> {
  return (
    record(value) &&
    pendingHeader(value) &&
    pendingPhase(value.phase) &&
    state(value.hostKeyState) &&
    value.hostKeyState !== null &&
    pendingCollections(value)
  )
}
export function parsePending(value: unknown): HostPending {
  if (!pendingShape(value)) return recoveryError()
  const policy = parsePolicy(value.policy)
  const files = value.files
  if (
    files[0].role !== "certificate" ||
    files[0].path !== policy.certificatePath ||
    files[1].role !== "config" ||
    files[1].path !== HOST_SSHD_CONFIG
  )
    return recoveryError()
  for (const item of value.dependencies) assertHostCertificatePath(item.path)
  return {
    dependencies: value.dependencies,
    files,
    hostKeyState: value.hostKeyState,
    id: value.id,
    phase: value.phase,
    policy,
    publicKey: publicKeyIdentity(value.publicKey),
    version: 1,
  }
}
