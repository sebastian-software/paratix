import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

// cspell:ignore OPENPGP
const OPENPGP_FINGERPRINT_RE = /^[A-F0-9]{40,64}$/v

export function normalizeOpenPgpFingerprint(fingerprint: string): string {
  const normalized = fingerprint.replaceAll(/\s+/gv, "").toUpperCase()
  if (!OPENPGP_FINGERPRINT_RE.test(normalized)) {
    throw new Error(
      `apt.key requires an OpenPGP fingerprint with 40-64 hexadecimal characters, got: ${fingerprint}`
    )
  }
  return normalized
}

function parseOpenPgpFingerprint(stdout: string): null | string {
  for (const line of stdout.split("\n")) {
    const parts = line.trim().split(":")
    const fingerprint = parts[0] === "fpr" ? parts[9] : null
    if (fingerprint != null && fingerprint.length > 0) {
      return normalizeOpenPgpFingerprint(fingerprint)
    }
  }
  return null
}

export function validateAptKeyUrl(url: string): void {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(url)
  } catch {
    throw new Error(`apt.key requires a valid URL, got: ${url}`)
  }
  if (parsedUrl.protocol !== "https:") {
    throw new Error(`apt.key requires an https URL, got: ${url}`)
  }
}

async function inspectOpenPgpFingerprint(
  ssh: SshConnection,
  path: string
): Promise<{ fingerprint: string; result: ModuleResult }> {
  const fingerprintResult = await ssh.exec(`gpg --show-keys --with-colons ${shellQuote(path)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (fingerprintResult.code !== 0) {
    return {
      fingerprint: "",
      result: failedCommand("[apt.key] failed to inspect key material", fingerprintResult),
    }
  }
  const fingerprint = parseOpenPgpFingerprint(fingerprintResult.stdout)
  if (fingerprint == null) {
    return { fingerprint: "", result: failed("[apt.key] failed to parse key fingerprint") }
  }
  return { fingerprint, result: { status: "changed" } }
}

export async function verifyAptKeyFingerprint(parameters: {
  expectedFingerprint: string
  name: string
  path: string
  ssh: SshConnection
}): Promise<"ok" | ModuleResult> {
  const { expectedFingerprint, name, path, ssh } = parameters
  const inspection = await inspectOpenPgpFingerprint(ssh, path)
  if (inspection.result.status === "failed") return inspection.result
  if (inspection.fingerprint !== expectedFingerprint) {
    return failed(
      `[apt.key] fingerprint mismatch for ${name}: expected ${expectedFingerprint}, got ${inspection.fingerprint}`
    )
  }
  return "ok"
}

export async function applyAptKey(
  ssh: SshConnection,
  parameters: {
    expectedFingerprint: string
    keyringPath: string
    name: string
    url: string
  }
): Promise<ModuleResult> {
  const { expectedFingerprint, keyringPath, name, url } = parameters
  const temporaryTemplate = `/tmp/apt-key-${name}.XXXXXX`
  const temporaryPath = await ssh.output(`mktemp ${shellQuote(temporaryTemplate)}`)
  try {
    const download = await ssh.exec(
      `curl -fsSL ${shellQuote(url)} -o ${shellQuote(temporaryPath)}`,
      {
        ignoreExitCode: true,
        silent: true,
      }
    )
    if (download.code !== 0) return failedCommand(`[apt.key] failed to download ${name}`, download)
    const fingerprintCheck = await verifyAptKeyFingerprint({
      expectedFingerprint,
      name,
      path: temporaryPath,
      ssh,
    })
    if (fingerprintCheck !== "ok") return fingerprintCheck
    const importResult = await ssh.exec(
      `gpg --dearmor --yes -o ${shellQuote(keyringPath)} ${shellQuote(temporaryPath)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (importResult.code !== 0) {
      return failedCommand(`[apt.key] failed to import ${name}`, importResult)
    }
    return { status: "changed" }
  } finally {
    await ssh.exec(`rm -f ${shellQuote(temporaryPath)}`, { silent: true })
  }
}
