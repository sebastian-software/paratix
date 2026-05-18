import { posix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"

// R-0000709: staging-file prefix used in `<keyring-dir>/<prefix>.XXXXXX`. The
// dot-prefix keeps the staging file out of routine `ls` output and the unique
// `XXXXXX` suffix prevents collisions when two apt.key modules race for the
// same keyring directory.
const APT_KEY_STAGING_PREFIX = ".apt-key.paratix-staging"

// R-0000709: exit code emitted by the inline shell guard in
// `publishAptKeyStagingAtomically` when the keyring path turned into a symlink
// between snapshot and publish. Surfaced as a named constant so callers can
// distinguish the symlink-refusal branch from a generic publish failure.
const APT_KEY_PUBLISH_SYMLINK_EXIT_CODE = 73

/**
 * Allocate a throwaway gpg homedir so `gpg --show-keys` and `gpg --dearmor`
 * never touch the invoking user's `~/.gnupg`. The homedir is removed by the
 * caller in a `finally` block.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param name - Logical apt.key name used in error messages.
 * @returns Either the validated homedir path or a `failed` ModuleResult.
 */
export async function allocateGpgHomedir(
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

/**
 * Build the `gpg --dearmor` command line used by {@link dearmorAptKeyToKeyring}.
 *
 * @param parameters - dearmor inputs.
 * @param parameters.homedir - Temp homedir passed to `--homedir`.
 * @param parameters.outputPath - Staging output path passed to `-o`.
 * @param parameters.temporaryPath - Source temp file holding the downloaded armored key.
 * @returns The shell command string.
 */
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
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param name - Logical apt.key name used in error messages.
 * @param keyringPath - Final keyring destination path.
 * @returns Either the validated staging path or a `failed` ModuleResult.
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
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param parameters - Publish inputs.
 * @param parameters.keyringPath - Final keyring destination path.
 * @param parameters.name - Logical apt.key name used in error messages.
 * @param parameters.stagingPath - Staging file path to promote atomically.
 * @returns A failed ModuleResult on any error, or null on success.
 */
async function publishAptKeyStagingAtomically(
  ssh: SshConnection,
  parameters: { keyringPath: string; name: string; stagingPath: string }
): Promise<ModuleResult | null> {
  const { keyringPath, name, stagingPath } = parameters
  const publish = await ssh.exec(
    `{ if [ -L ${shellQuote(keyringPath)} ]; then rm -f -- ${shellQuote(stagingPath)}; exit ${String(APT_KEY_PUBLISH_SYMLINK_EXIT_CODE)}; fi && mv -T -- ${shellQuote(stagingPath)} ${shellQuote(keyringPath)}; } || { status=$?; rm -f -- ${shellQuote(stagingPath)}; exit "$status"; }`,
    { ignoreExitCode: true, silent: true }
  )
  if (publish.code === 0) return null
  if (publish.code === APT_KEY_PUBLISH_SYMLINK_EXIT_CODE) {
    return failed(`[apt.key] refuses to write through symlink at ${keyringPath}`)
  }
  return failedCommand(
    `[apt.key] failed to publish the keyring at ${keyringPath} for ${name}`,
    publish
  )
}

/**
 * Run `gpg --dearmor` and then `chmod 0644` against the staging file. Cleans
 * the staging file on any non-zero step so callers do not leak leftovers in
 * the keyring directory.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - dearmor inputs.
 * @param parameters.homedir - Temp gpg homedir used for the dearmor invocation.
 * @param parameters.keyringPath - Final keyring destination path (only used in error messages).
 * @param parameters.name - Logical apt.key name used in error messages.
 * @param parameters.stagingPath - Staging file path to dearmor into.
 * @param parameters.temporaryPath - Source temp file holding the downloaded armored key.
 * @returns A failed ModuleResult on any error, or null on success.
 */
async function dearmorAndChmodStagingFile(
  ssh: SshConnection,
  parameters: {
    homedir: string
    keyringPath: string
    name: string
    stagingPath: string
    temporaryPath: string
  }
): Promise<ModuleResult | null> {
  const { homedir, keyringPath, name, stagingPath, temporaryPath } = parameters
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
  return null
}

/**
 * Run the staging-aware dearmor pipeline: dearmor into a staging file, chmod
 * 0644, then atomically promote to the keyring path. Cleans the staging file
 * up on any failure so leftovers do not accumulate.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - dearmor inputs.
 * @param parameters.homedir - Temp gpg homedir used for the dearmor invocation.
 * @param parameters.keyringPath - Destination path for the dearmored keyring.
 * @param parameters.name - Logical apt.key name used in error messages.
 * @param parameters.temporaryPath - Source temp file holding the downloaded armored key.
 * @returns A failed ModuleResult on any error, or null on success.
 */
async function dearmorAndPublishKeyring(
  ssh: SshConnection,
  parameters: { homedir: string; keyringPath: string; name: string; temporaryPath: string }
): Promise<ModuleResult | null> {
  const { homedir, keyringPath, name, temporaryPath } = parameters
  const stagingResult = await allocateAptKeyStagingPath(ssh, name, keyringPath)
  if ("failure" in stagingResult) return stagingResult.failure
  const { stagingPath } = stagingResult
  try {
    const stagingFailure = await dearmorAndChmodStagingFile(ssh, {
      homedir,
      keyringPath,
      name,
      stagingPath,
      temporaryPath,
    })
    if (stagingFailure != null) return stagingFailure
    return await publishAptKeyStagingAtomically(ssh, { keyringPath, name, stagingPath })
  } catch (error) {
    // R-0000709: best-effort cleanup if any helper above throws; the
    // staging file must never leak into the keyring directory.
    await cleanupAptKeyStagingPath(ssh, stagingPath)
    throw error
  }
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
export async function dearmorAptKeyToKeyring(
  ssh: SshConnection,
  parameters: { keyringPath: string; name: string; temporaryPath: string }
): Promise<ModuleResult | null> {
  const { keyringPath, name, temporaryPath } = parameters
  const homedirResult = await allocateGpgHomedir(ssh, name)
  if ("failure" in homedirResult) return homedirResult.failure
  const { homedir } = homedirResult
  try {
    return await dearmorAndPublishKeyring(ssh, { homedir, keyringPath, name, temporaryPath })
  } finally {
    await ssh.exec(`rm -rf -- ${shellQuote(homedir)}`, { ignoreExitCode: true, silent: true })
  }
}
