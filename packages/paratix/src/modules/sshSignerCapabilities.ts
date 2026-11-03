import { writeFile } from "node:fs/promises"
import { join } from "node:path"

import type { HostCertificateRequest } from "./sshHostCertificateTypes.js"

import { parseHostCertificate } from "./sshHostCertificatePolicy.js"
import { hostCaIdentity, publicKeyIdentity } from "./sshHostCertificateWire.js"
import { openSshUtc, readSignerCertificate } from "./sshSignerFiles.js"
import { HostCertificateError, signerProcess } from "./sshSignerProcess.js"

const MILLISECONDS_PER_SECOND = 1000
const PROBE_DURATION_SECONDS = 3617

const SSH_KEYGEN = "ssh-keygen"
const PROBE_AFTER = Date.parse("2001-02-03T04:05:06Z") / MILLISECONDS_PER_SECOND
const PROBE_BEFORE = PROBE_AFTER + PROBE_DURATION_SECONDS
const PROBE_ID = "paratix-controller-capability"
const PROBE_PRINCIPAL = "paratix-controller-capability.invalid"
const STEP_FLAGS = [
  "--ca-url",
  "--force",
  "--host",
  "--no-agent",
  "--not-after",
  "--not-before",
  "--principal",
  "--provisioner",
  "--provisioner-password-file",
  "--root",
  "--sign",
] as const

function probeCaArguments(caPublicKey: string, path: string): string[] {
  const algorithm = hostCaIdentity(caPublicKey).split(" ")[0]
  if (algorithm === "ssh-ed25519") return ["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path]
  const bits = algorithm === "ssh-rsa" ? "2048" : algorithm.slice("ecdsa-sha2-nistp".length)
  return [
    "-q",
    "-t",
    algorithm === "ssh-rsa" ? "rsa" : "ecdsa",
    "-b",
    bits,
    "-N",
    "",
    "-C",
    "",
    "-f",
    path,
  ]
}

/**
 * Real facility proof, independent of vendor version strings or help wording.
 * @param directory - Protected directory for disposable public capability probes.
 * @param request - Public host key and cancellation signal for the signing operation.
 * @param expectedCaPublicKey - Public trust anchor selecting the probe CA algorithm.
 */
export async function checkOpenSshCapabilities(
  directory: string,
  request: HostCertificateRequest,
  expectedCaPublicKey: string
): Promise<void> {
  try {
    const paths = {
      ca: join(directory, "capability-ca"),
      key: join(directory, "capability-subject.pub"),
    }
    const options = { directory, signal: request.signal, stage: "OpenSSH capability preflight" }
    await signerProcess(SSH_KEYGEN, probeCaArguments(expectedCaPublicKey, paths.ca), options)
    const caPublicKey = hostCaIdentity(
      await signerProcess(SSH_KEYGEN, ["-y", "-P", "", "-f", paths.ca], options)
    )
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed public probe file in this invocation's protected directory
    await writeFile(paths.key, `${publicKeyIdentity(request.publicKey)}\n`, { mode: 0o600 })
    await signerProcess(
      SSH_KEYGEN,
      [
        "-q",
        "-s",
        paths.ca,
        "-I",
        PROBE_ID,
        "-h",
        "-n",
        PROBE_PRINCIPAL,
        "-V",
        `${openSshUtc(PROBE_AFTER)}:${openSshUtc(PROBE_BEFORE)}`,
        paths.key,
      ],
      options
    )
    const certificatePath = join(directory, "capability-subject-cert.pub")
    const certificate = parseHostCertificate(await readSignerCertificate(certificatePath))
    const listing = await signerProcess(SSH_KEYGEN, ["-L", "-f", certificatePath], options)
    if (
      certificate.publicKey !== publicKeyIdentity(request.publicKey) ||
      certificate.caPublicKey !== caPublicKey ||
      certificate.principals.join(",") !== PROBE_PRINCIPAL ||
      certificate.validAfter !== PROBE_AFTER ||
      certificate.validBefore !== PROBE_BEFORE ||
      !listing.includes(`Key ID: "${PROBE_ID}"`)
    )
      throw new Error("Unsupported certificate facilities")
  } catch {
    // A substituted or incompatible binary can emit arbitrary text, including sensitive data.
    throw new HostCertificateError(
      "Controller ssh-keygen lacks required noninteractive host-certificate, principal or absolute UTC facilities"
    )
  }
}

/**
 * The documented version command and exact SSH certificate flags are required; no numeric floor.
 * @param directory - Isolated CLI state directory for this invocation.
 * @param signal - Cancellation signal shared with the signing operation.
 */
export async function checkStepCapabilities(directory: string, signal: AbortSignal): Promise<void> {
  const options = { directory, signal, stage: "Step CLI capability preflight" }
  const version = await signerProcess("step", ["version"], options)
  if (!/^Smallstep CLI\/\S+/mv.test(version))
    throw new HostCertificateError("Controller step CLI version could not be identified")
  const help = await signerProcess("step", ["ssh", "certificate", "--help"], options)
  const flags = new Set(help.match(/--[a-z][a-z\-]*/gv) ?? [])
  const missing = STEP_FLAGS.filter((flag) => !flags.has(flag))
  if (missing.length > 0)
    throw new HostCertificateError(
      `Controller step CLI lacks required SSH certificate options: ${missing.join(", ")}`
    )
}
