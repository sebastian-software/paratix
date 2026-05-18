import { posix } from "node:path"

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
// R-0000709: staging-file prefix used in `<keyring-dir>/<prefix>.XXXXXX`. The
// dot-prefix keeps the staging file out of routine `ls` output and the unique
// `XXXXXX` suffix prevents collisions when two apt.key modules race for the
// same keyring directory.
const APT_KEY_STAGING_PREFIX = ".apt-key.paratix-staging"

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
  outputPath: string
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
    shellQuote(parameters.outputPath),
    shellQuote(parameters.temporaryPath),
  ].join(" ")
}

/**
 * R-0000709: allocate a per-keyring staging path next to `keyringPath`. The
 * staging file lives in the same directory so the final atomic rename uses
 * the same filesystem (a cross-device `mv -T` would otherwise fall back to a
 * non-atomic copy + unlink). Returns a validated path or a `failed` result.
 */
async function allocateAptKeyStagingPath(
  ssh: SshConnection,
  name: string,
  keyringPath: string
): Promise<{ failure: ModuleResult } | { stagingPath: string }> {
  const directory = posix.dirname(keyringPath)
  const template = `${APT_KEY_STAGING_PREFIX}.XXXXXX`
  const rawStagingPath = await ssh.output(
    `mktemp -p ${shellQuote(directory)} -- ${shellQuote(template)}`
  )
  try {
    return {
      stagingPath: validateMktempPath(directory, rawStagingPath, APT_KEY_STAGING_PREFIX),
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return {
      failure: failed(
        `[apt.key] mktemp produced an unexpected keyring staging path for ${name}: ${reason}`
      ),
    }
  }
}

async function cleanupAptKeyStagingPath(ssh: SshConnection, stagingPath: string): Promise<void> {
  // R-0000709: pass `--` so a future refactor that loosens the staging prefix
  // cannot let an attacker-controlled path that starts with `-` be parsed as
  // an `rm` option.
  await ssh.exec(`rm -f -- ${shellQuote(stagingPath)}`, { ignoreExitCode: true, silent: true })
}

/**
 * R-0000709: publish the dearmored keyring atomically. The shell pipeline
 * performs the symlink guard and the `mv -T -- staging final` in the same
 * shell invocation so a symlink that materialises between an earlier
 * `[ -L final ]` probe and the rename cannot redirect the write into an
 * attacker-controlled target. The staging file is removed on any error so
 * leftovers do not accumulate in the keyring directory.
 *
 * Exit codes:
 * - `73` — final path turned into a symlink between snapshot and publish.
 * - any other non-zero code — surfaced via `failedCommand` so the operator
 *   sees the exact shell stderr.
 */
async function publishAptKeyStagingAtomically(
  ssh: SshConnection,
  parameters: { keyringPath: string; name: string; stagingPath: string }
): Promise<ModuleResult | null> {
  const { keyringPath, name, stagingPath } = parameters
  const publish = await ssh.exec(
    `{ if [ -L ${shellQuote(keyringPath)} ]; then rm -f -- ${shellQuote(stagingPath)}; exit 73; fi && mv -T -- ${shellQuote(stagingPath)} ${shellQuote(keyringPath)}; } || { status=$?; rm -f -- ${shellQuote(stagingPath)}; exit "$status"; }`,
    { ignoreExitCode: true, silent: true }
  )
  if (publish.code === 0) return null
  if (publish.code === 73) {
    return failed(`[apt.key] refuses to write through symlink at ${keyringPath}`)
  }
  return failedCommand(
    `[apt.key] failed to publish the keyring at ${keyringPath} for ${name}`,
    publish
  )
}

/**
 * Run `gpg --dearmor` against a temp homedir (rather than the invoking user's
 * `~/.gnupg`) and `chmod 0644` the resulting keyring so `_apt` can read it.
 * R-0000225: the previous implementation polluted the running user's home
 * with a `~/.gnupg/trustdb.gpg` and left the keyring at a default mode that
 * `_apt` could not always read.
 *
 * R-0000709: the dearmor output is written to a staging file in the same
 * directory as the final keyring, then atomically promoted via `mv -T -- …`
 * with an inline symlink guard. The previous implementation wrote `gpg
 * --dearmor -o keyringPath` directly, so a symlink swap or a partial write
 * could leave `_apt` reading either an attacker-controlled target or a
 * half-written file between gpg's truncate and the subsequent `chmod`.
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
    const stagingResult = await allocateAptKeyStagingPath(ssh, name, keyringPath)
    if ("failure" in stagingResult) return stagingResult.failure
    const { stagingPath } = stagingResult
    try {
      const importResult = await ssh.exec(
        buildDearmorCommand({ homedir, outputPath: stagingPath, temporaryPath }),
        { ignoreExitCode: true, silent: true }
      )
      if (importResult.code !== 0) {
        await cleanupAptKeyStagingPath(ssh, stagingPath)
        return failedCommand(`[apt.key] failed to import ${name}`, importResult)
      }
      // R-0000225: gpg --dearmor leaves the keyring at the umask-default mode,
      // which on systems with restrictive umasks renders it unreadable for the
      // unprivileged `_apt` user. Force 0644 on the staging file *before* the
      // atomic publish so apt sees the final mode the moment the rename lands.
      const chmodResult = await ssh.exec(`chmod 0644 ${shellQuote(stagingPath)}`, {
        ignoreExitCode: true,
        silent: true,
      })
      if (chmodResult.code !== 0) {
        await cleanupAptKeyStagingPath(ssh, stagingPath)
        return failedCommand(
          `[apt.key] failed to chmod 0644 the keyring at ${keyringPath}`,
          chmodResult
        )
      }
      return await publishAptKeyStagingAtomically(ssh, { keyringPath, name, stagingPath })
    } catch (error) {
      // R-0000709: best-effort cleanup if any helper above throws; the
      // staging file must never leak into the keyring directory.
      await cleanupAptKeyStagingPath(ssh, stagingPath)
      throw error
    }
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
