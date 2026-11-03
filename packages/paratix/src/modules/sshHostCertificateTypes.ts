import type { SecretHandle } from "./deferredSecret.js"

/** Public controller-only signing request. Times are absolute whole UTC seconds. */
export type HostCertificateRequest = {
  /** Exact, normalized host names/IP addresses to encode as certificate principals. */
  readonly principals: readonly string[]
  /** Public key derived from the existing target host key; no private key crosses the boundary. */
  readonly publicKey: string
  /** Stable per-request identity for the OpenSSH certificate identity field. */
  readonly requestId: string
  /** Aborts the signer process when the bounded apply operation is cancelled or times out. */
  readonly signal: AbortSignal
  /** Inclusive lower certificate bound, expressed as a controller UTC epoch second. */
  readonly validAfter: number
  /** Exclusive upper certificate bound, expressed as a controller UTC epoch second. */
  readonly validBefore: number
  /** Versioned contract discriminator for future signer compatibility. */
  readonly version: 1
}

/**
 * A controller-only signer contract. Implementations return exactly one validated OpenSSH host
 * certificate and must not mutate the target or expose credentials in errors or output.
 */
export type HostCertificateSigner = {
  /** Independently configured OpenSSH CA public key expected in signer output. */
  readonly caPublicKey: string
  /** Sign one request; construction, check, and dry-run must not call this function. */
  readonly sign: (request: HostCertificateRequest) => Promise<string>
  /** Versioned contract discriminator for custom signer implementations. */
  readonly version: 1
}

/** Options for the local, non-interactive ssh-keygen signer. The CA private key stays on the controller. */
export type LocalHostCertificateSignerOptions = {
  /** Absolute controller path to an unencrypted CA private key. */
  caKey: string
  /** OpenSSH CA public key corresponding to the configured `caKey` path. */
  caPublicKey: string
}

/** Options for the controller-side step-ca JWK provisioner signer. */
export type StepCaHostCertificateSignerOptions = {
  /** OpenSSH CA public key expected from step-ca. */
  caPublicKey: string
  /** Explicit HTTPS step-ca endpoint; credentials in the URL are rejected. */
  caUrl: string
  /** Deferred provider-bound provisioner password; resolved only when signing is required. */
  password: SecretHandle
  /** Explicit JWK provisioner name. */
  provisioner: string
  /** Absolute controller path to the PEM TLS root used to verify step-ca. */
  root: string
}

/** Desired host-certificate policy for an existing target host key. */
export type HostCertificateOptions = {
  /** Target certificate path; defaults to `<hostKeyPath>-cert.pub`. */
  certificatePath?: string
  /** Existing target private host-key path; no key is generated or replaced. */
  hostKeyPath?: string
  /** Existing host-key type; defaults to `ed25519`. */
  keyType?: "ecdsa" | "ed25519" | "rsa"
  /** Non-empty explicit hostname/IP principal set; order is normalized. */
  principals: readonly string[]
  /** Renew when remaining lifetime is at or below this threshold; defaults to `7d`. */
  renewBefore?: number | string
  /** Controller-only signer used when a new certificate is required. */
  signer: HostCertificateSigner
  /** Maximum total signed duration, defaulting to `30d`, in whole seconds or s/m/h/d/w notation. */
  validity?: number | string
}
