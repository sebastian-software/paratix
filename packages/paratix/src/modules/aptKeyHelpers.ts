import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import {
  buildCurlConfigPayload,
  hasSensitiveQueryParameters,
  validateCurlConfigValue,
} from "./curlHelpers.js"

const OPENPGP_FINGERPRINT_RE = /^[A-F0-9]{40,64}$/v
const REDACTED_URL_VALUE = "REDACTED"

export function normalizeOpenPgpFingerprint(fingerprint: string): string {
  const normalized = fingerprint.replaceAll(/\s+/gv, "").toUpperCase()
  if (!OPENPGP_FINGERPRINT_RE.test(normalized)) {
    throw new Error(
      `apt.key requires an OpenPGP fingerprint with 40-64 hexadecimal characters, got: ${fingerprint}`
    )
  }
  return normalized
}

function parseOpenPgpPrimaryKeyFingerprints(stdout: string): string[] {
  const fingerprints: string[] = []
  let currentKeyRecord: null | string = null

  for (const line of stdout.split("\n")) {
    const parts = line.trim().split(":")
    if (parts[0] === "pub" || parts[0] === "sub") {
      currentKeyRecord = parts[0]
      continue
    }
    const fingerprint = parts[0] === "fpr" && currentKeyRecord === "pub" ? parts[9] : null
    if (fingerprint != null && fingerprint.length > 0) {
      fingerprints.push(normalizeOpenPgpFingerprint(fingerprint))
    }
  }
  return fingerprints
}

export function validateAptKeyUrl(url: string): void {
  validateCurlConfigValue("apt.key URL", url)
  let parsedUrl: URL
  try {
    parsedUrl = new URL(url)
  } catch {
    throw new Error("apt.key requires a valid URL")
  }
  if (parsedUrl.protocol !== "https:") {
    throw new Error(`apt.key requires an https URL, got: ${redactAptKeyUrlForDisplay(parsedUrl)}`)
  }
}

function redactAptKeyUrlForDisplay(url: URL): string {
  const displayUrl = new URL(url)
  if (displayUrl.username.length > 0) displayUrl.username = REDACTED_URL_VALUE
  if (displayUrl.password.length > 0) displayUrl.password = REDACTED_URL_VALUE
  if (hasSensitiveQueryParameters(displayUrl)) {
    for (const [name] of displayUrl.searchParams) {
      displayUrl.searchParams.set(name, REDACTED_URL_VALUE)
    }
  }
  return displayUrl.toString()
}

function extractAptKeyUrlSecrets(url: string): string[] {
  const parsedUrl = new URL(url)
  const secrets: string[] = []
  if (
    parsedUrl.username.length > 0 ||
    parsedUrl.password.length > 0 ||
    hasSensitiveQueryParameters(parsedUrl)
  ) {
    secrets.push(url)
  }
  if (parsedUrl.username.length > 0) secrets.push(decodeURIComponent(parsedUrl.username))
  if (parsedUrl.password.length > 0) secrets.push(decodeURIComponent(parsedUrl.password))
  return secrets
}

function buildShowKeysCommand(parameters: { homedir: string; path: string }): string {
  // R-0000704: mirror buildDearmorCommand and force `gpg --show-keys` through
  // a dedicated temp homedir with `--no-default-keyring --no-options`. Without
  // these flags `gpg` lazily materialises a `~/.gnupg/trustdb.gpg` for the
  // invoking user and may consume options from the user's `~/.gnupg/gpg.conf`,
  // which pollutes the running account and risks loading attacker-friendly
  // defaults during what is supposed to be a read-only fingerprint probe.
  return [
    "gpg",
    "--no-default-keyring",
    "--no-options",
    "--homedir",
    shellQuote(parameters.homedir),
    "--show-keys",
    "--with-colons",
    shellQuote(parameters.path),
  ].join(" ")
}

async function inspectOpenPgpFingerprint(
  ssh: SshConnection,
  name: string,
  path: string
): Promise<{ fingerprint: string; result: ModuleResult }> {
  // R-0000704: allocate a throwaway homedir before invoking `gpg --show-keys`
  // so the probe cannot pollute the default trustdb and cannot read the
  // invoking user's `gpg.conf`. The homedir is removed in the finally branch
  // even when the probe fails.
  const homedirResult = await allocateGpgHomedir(ssh, name)
  if ("failure" in homedirResult) {
    return { fingerprint: "", result: homedirResult.failure }
  }
  const { homedir } = homedirResult
  try {
    const fingerprintResult = await ssh.exec(buildShowKeysCommand({ homedir, path }), {
      ignoreExitCode: true,
      silent: true,
    })
    if (fingerprintResult.code !== 0) {
      return {
        fingerprint: "",
        result: failedCommand("[apt.key] failed to inspect key material", fingerprintResult),
      }
    }
    const fingerprints = parseOpenPgpPrimaryKeyFingerprints(fingerprintResult.stdout)
    if (fingerprints.length === 0) {
      return { fingerprint: "", result: failed("[apt.key] failed to parse key fingerprint") }
    }
    if (fingerprints.length > 1) {
      return {
        fingerprint: "",
        result: failed(
          `[apt.key] key material for ${name} contains ${fingerprints.length} primary keys`
        ),
      }
    }
    const [fingerprint] = fingerprints
    return { fingerprint, result: { status: "changed" } }
  } finally {
    await ssh.exec(`rm -rf -- ${shellQuote(homedir)}`, { ignoreExitCode: true, silent: true })
  }
}

export async function verifyAptKeyFingerprint(parameters: {
  expectedFingerprint: string
  name: string
  path: string
  ssh: SshConnection
}): Promise<"ok" | ModuleResult> {
  const { expectedFingerprint, name, path, ssh } = parameters
  const inspection = await inspectOpenPgpFingerprint(ssh, name, path)
  if (inspection.result.status === "failed") return inspection.result
  if (inspection.fingerprint !== expectedFingerprint) {
    return failed(
      `[apt.key] fingerprint mismatch for ${name}: expected ${expectedFingerprint}, got ${inspection.fingerprint}`
    )
  }
  return "ok"
}

/**
 * R-0000066: create the temp file via `mktemp` and validate the returned
 * path before any other subcommand consumes it. Mirrors the pattern used
 * by createRemoteTempPath in ssh.ts so locale warnings, multi-line output
 * or a modified `mktemp` cannot smuggle an unexpected path into the curl,
 * gpg --dearmor or rm -f calls that follow.
 *
 * @param ssh - The active SSH connection.
 * @param name - Logical apt.key name used in the temp file prefix.
 * @returns Either the validated temp path or a `failed` ModuleResult.
 */
async function createValidatedAptKeyTemporaryPath(
  ssh: SshConnection,
  name: string
): Promise<{ failure: ModuleResult } | { temporaryPath: string }> {
  const temporaryPrefix = `apt-key-${name}`
  const temporaryTemplate = `/tmp/${temporaryPrefix}.XXXXXX`
  const rawTemporaryPath = await ssh.output(`mktemp ${shellQuote(temporaryTemplate)}`)
  try {
    return { temporaryPath: validateMktempPath("/tmp", rawTemporaryPath, temporaryPrefix) }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return {
      failure: failed(`[apt.key] mktemp produced an unexpected path for ${name}: ${reason}`),
    }
  }
}

async function allocateGpgHomedir(
  ssh: SshConnection,
  name: string
): Promise<{ failure: ModuleResult } | { homedir: string }> {
  const rawHomedir = await ssh.output(`mktemp -d /tmp/apt-key-gpg-home.XXXXXX`)
  try {
    return { homedir: validateMktempPath("/tmp", rawHomedir, "apt-key-gpg-home") }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return {
      failure: failed(`[apt.key] mktemp produced an unexpected gpg homedir for ${name}: ${reason}`),
    }
  }
}

function buildDearmorCommand(parameters: {
  homedir: string
  keyringPath: string
  temporaryPath: string
}): string {
  return [
    "gpg",
    "--no-default-keyring",
    "--no-options",
    "--homedir",
    shellQuote(parameters.homedir),
    "--dearmor",
    "--yes",
    "-o",
    shellQuote(parameters.keyringPath),
    shellQuote(parameters.temporaryPath),
  ].join(" ")
}

/**
 * Run `gpg --dearmor` against a temp homedir (rather than the invoking user's
 * `~/.gnupg`) and `chmod 0644` the resulting keyring so `_apt` can read it.
 * R-0000225: the previous implementation polluted the running user's home
 * with a `~/.gnupg/trustdb.gpg` and left the keyring at a default mode that
 * `_apt` could not always read.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - dearmor inputs.
 * @param parameters.keyringPath - Destination path for the dearmored keyring.
 * @param parameters.name - Logical apt.key name used in error messages.
 * @param parameters.temporaryPath - Source temp file holding the downloaded armored key.
 * @returns A failed ModuleResult on any error, or null on success.
 */
async function dearmorAptKeyToKeyring(
  ssh: SshConnection,
  parameters: { keyringPath: string; name: string; temporaryPath: string }
): Promise<ModuleResult | null> {
  const { keyringPath, name, temporaryPath } = parameters
  const homedirResult = await allocateGpgHomedir(ssh, name)
  if ("failure" in homedirResult) return homedirResult.failure
  const { homedir } = homedirResult
  try {
    const importResult = await ssh.exec(
      buildDearmorCommand({ homedir, keyringPath, temporaryPath }),
      { ignoreExitCode: true, silent: true }
    )
    if (importResult.code !== 0) {
      return failedCommand(`[apt.key] failed to import ${name}`, importResult)
    }
    // R-0000225: gpg --dearmor leaves the keyring at the umask-default mode,
    // which on systems with restrictive umasks renders it unreadable for the
    // unprivileged `_apt` user. Force 0644 so apt can always read the keyring.
    const chmodResult = await ssh.exec(`chmod 0644 ${shellQuote(keyringPath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (chmodResult.code !== 0) {
      return failedCommand(
        `[apt.key] failed to chmod 0644 the keyring at ${keyringPath}`,
        chmodResult
      )
    }
    return null
  } finally {
    await ssh.exec(`rm -rf -- ${shellQuote(homedir)}`, { ignoreExitCode: true, silent: true })
  }
}

async function downloadVerifyAndImportAptKey(
  ssh: SshConnection,
  parameters: {
    expectedFingerprint: string
    keyringPath: string
    name: string
    temporaryPath: string
    url: string
  }
): Promise<ModuleResult> {
  const { expectedFingerprint, keyringPath, name, temporaryPath, url } = parameters
  const urlSecrets = extractAptKeyUrlSecrets(url)
  const curlConfig = buildCurlConfigPayload({ routeUrlThroughConfig: true, url })
  const download = await ssh.exec(
    `curl -fsSL -o ${shellQuote(temporaryPath)} --proto '=https' --proto-redir '=https' --config -`,
    {
      ignoreExitCode: true,
      input: curlConfig.configInput,
      secrets: urlSecrets,
      silent: true,
    }
  )
  if (download.code !== 0)
    return failedCommand(`[apt.key] failed to download ${name}`, download, urlSecrets)
  const fingerprintCheck = await verifyAptKeyFingerprint({
    expectedFingerprint,
    name,
    path: temporaryPath,
    ssh,
  })
  if (fingerprintCheck !== "ok") return fingerprintCheck
  // R-0000134: refuse to dearmor into a symlinked keyring path. `gpg --dearmor
  // --yes -o` follows symlinks and would truncate or overwrite whatever the
  // link points at before we can validate the destination. We deliberately do
  // not unlink the symlink automatically; the operator must decide.
  const keyringIsSymlink = await ssh.test(`[ -L ${shellQuote(keyringPath)} ]`)
  if (keyringIsSymlink) {
    return failed(`[apt.key] refuses to write through symlink at ${keyringPath}`)
  }
  const dearmorFailure = await dearmorAptKeyToKeyring(ssh, { keyringPath, name, temporaryPath })
  if (dearmorFailure != null) return dearmorFailure
  return { status: "changed" }
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
  const temporaryResult = await createValidatedAptKeyTemporaryPath(ssh, name)
  if ("failure" in temporaryResult) return temporaryResult.failure
  const { temporaryPath } = temporaryResult
  try {
    return await downloadVerifyAndImportAptKey(ssh, {
      expectedFingerprint,
      keyringPath,
      name,
      temporaryPath,
      url,
    })
  } finally {
    await ssh.exec(`rm -f ${shellQuote(temporaryPath)}`, { ignoreExitCode: true, silent: true })
  }
}
