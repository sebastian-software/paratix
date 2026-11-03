import { writeFile } from "node:fs/promises"
import { isAbsolute, join } from "node:path"

import type {
  HostCertificateRequest,
  HostCertificateSigner,
  LocalHostCertificateSignerOptions,
  StepCaHostCertificateSignerOptions,
} from "./sshHostCertificateTypes.js"

import { assertSecretHandle, withDeferredSecret } from "./deferredSecret.js"
import { hostCaIdentity, publicKeyIdentity } from "./sshHostCertificateWire.js"
import { checkOpenSshCapabilities, checkStepCapabilities } from "./sshSignerCapabilities.js"
import { openSshUtc, readSignerCertificate } from "./sshSignerFiles.js"
import { HostCertificateError, signerProcess, withSignerDirectory } from "./sshSignerProcess.js"

const MILLISECONDS_PER_SECOND = 1000

function controllerPath(path: string): string {
  if (!isAbsolute(path) || /[\r\n\0]/v.test(path))
    throw new HostCertificateError("Signer requires an explicit absolute controller path")
  return path
}

function local(options: LocalHostCertificateSignerOptions): HostCertificateSigner {
  const caKey = controllerPath(options.caKey)
  const caPublicKey = hostCaIdentity(options.caPublicKey)
  return Object.freeze({
    caPublicKey,
    async sign(request: HostCertificateRequest): Promise<string> {
      return withSignerDirectory(async (directory) => {
        await checkOpenSshCapabilities(directory, request, caPublicKey)
        const processOptions = { directory, signal: request.signal, stage: "local CA preflight" }
        const actual = await signerProcess(
          "ssh-keygen",
          ["-y", "-P", "", "-f", caKey],
          processOptions
        )
        if (publicKeyIdentity(actual) !== caPublicKey)
          throw new HostCertificateError(
            "Local CA private key does not match the configured public CA"
          )
        const key = join(directory, "host.pub")
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed file names inside the private per-call signer directory
        await writeFile(key, `${publicKeyIdentity(request.publicKey)}\n`, { mode: 0o600 })
        await signerProcess(
          "ssh-keygen",
          [
            "-q",
            "-s",
            caKey,
            "-I",
            request.requestId,
            "-h",
            "-n",
            request.principals.join(","),
            "-V",
            `${openSshUtc(request.validAfter)}:${openSshUtc(request.validBefore)}`,
            key,
          ],
          { ...processOptions, stage: "local signing" }
        )
        return readSignerCertificate(join(directory, "host-cert.pub"))
      })
    },
    version: 1 as const,
  })
}

function stepCa(options: StepCaHostCertificateSignerOptions): HostCertificateSigner {
  const caPublicKey = hostCaIdentity(options.caPublicKey)
  const root = controllerPath(options.root)
  let url: URL
  try {
    url = new URL(options.caUrl)
  } catch {
    throw new HostCertificateError("Step CA requires a valid explicit HTTPS URL")
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  )
    throw new HostCertificateError("Step CA requires an explicit HTTPS URL without credentials")
  if (options.provisioner.length === 0 || /[\0\r\n]/v.test(options.provisioner))
    throw new HostCertificateError("An explicit JWK provisioner is required")
  assertSecretHandle(options.password)
  const { password, provisioner } = options
  return Object.freeze({
    caPublicKey,
    async sign(request: HostCertificateRequest): Promise<string> {
      const principals = request.principals.flatMap((principal) => ["--principal", principal])
      return withSignerDirectory(async (directory) => {
        await checkOpenSshCapabilities(directory, request, caPublicKey)
        await checkStepCapabilities(directory, request.signal)
        request.signal.throwIfAborted()
        return withDeferredSecret(password, async (credential) => {
          const key = join(directory, "host.pub")
          const passwordFile = join(directory, "password")
          // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed file names inside the private per-call signer directory
          await writeFile(key, `${publicKeyIdentity(request.publicKey)}\n`, { mode: 0o600 })
          // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed file names inside the private per-call signer directory
          await writeFile(passwordFile, credential, { mode: 0o600 })
          await signerProcess(
            "step",
            [
              "ssh",
              "certificate",
              request.requestId,
              key,
              "--host",
              "--sign",
              "--no-agent",
              "--force",
              "--ca-url",
              url.href,
              "--root",
              root,
              "--provisioner",
              provisioner,
              "--provisioner-password-file",
              passwordFile,
              "--not-before",
              new Date(request.validAfter * MILLISECONDS_PER_SECOND).toISOString(),
              "--not-after",
              new Date(request.validBefore * MILLISECONDS_PER_SECOND).toISOString(),
              ...principals,
            ],
            { directory, signal: request.signal, stage: "JWK signing" }
          )
          return readSignerCertificate(join(directory, "host-cert.pub"))
        })
      })
    },
    version: 1 as const,
  })
}

/** Controller signers never spawn or resolve credentials during construction. */
export const hostCertificateSigner = Object.freeze({
  /** Sign with an existing unencrypted CA key through the controller's ssh-keygen. */
  local,
  /** Sign through an explicitly configured step-ca JWK provisioner over verified HTTPS. */
  stepCa,
})
