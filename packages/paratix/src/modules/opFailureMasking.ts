/** 1Password-specific captured-output handling for the shared sanitizer. */
import { maskSecrets } from "../sshHelpers.js"
import { maskKnownSecretPrefixes } from "./opOutputCapture.js"
import { collectOpFailureOutputs, OpSpawnError } from "./opSpawnError.js"
import {
  buildSecretFailure,
  buildSecretFailureDetail,
  type SecretFailurePolicy,
} from "./secretFailureMasking.js"

export const opFailurePolicy: SecretFailurePolicy = {
  cloneError(error, message, secrets) {
    if (!(error instanceof OpSpawnError)) return
    return new OpSpawnError(message, {
      stderr: maskOpText(error.opStderr, secrets),
      stdout: maskOpText(error.opStdout, secrets),
    })
  },
  collectCandidates: collectOpFailureOutputs,
  maskText: maskOpText,
  prefix: "Failed to resolve 1Password references",
}

export const buildOpFailureDetail = buildSecretFailureDetail

export function maskOpText(text: string, secrets: string[]): string {
  return maskKnownSecretPrefixes(maskSecrets(text, secrets), secrets)
}

export function buildPrewarmFailure(error: unknown, secrets: string[]): Error {
  return buildSecretFailure(error, secrets, opFailurePolicy)
}
