import { posix as posixPath } from "node:path"

import type { ExecResult, ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const KIBI = 1024
const MEBI = KIBI * KIBI

type SwapFileCreationParameters = {
  mode: string
  path: string
  size: string
  sizeBytes: number
  ssh: SshConnection
}

export function safeParentCommand(parentDirectory: string): string {
  return `find ${shellQuote(parentDirectory)} -maxdepth 0 -type d -user root ! -perm /022 | grep -Fx ${shellQuote(parentDirectory)}`
}

function buildEmptyMktempResult(stdout: string): ExecResult {
  return {
    code: 1,
    stderr: "mktemp did not return a path",
    stdout,
  }
}

async function ensureSwapParentDirectory(
  parameters: SwapFileCreationParameters,
  parentDirectory: string
): Promise<ModuleResult | true> {
  const createDirectoryResult = await parameters.ssh.exec(
    `mkdir -p ${shellQuote(parentDirectory)}`,
    EXEC_OPTS
  )
  if (createDirectoryResult.code !== 0) {
    return failedCommand(`[swap.file: ${parameters.path}] mkdir failed`, createDirectoryResult)
  }

  const safeParentResult = await parameters.ssh.exec(safeParentCommand(parentDirectory), EXEC_OPTS)
  return safeParentResult.code === 0
    ? true
    : failedCommand(
        `[swap.file: ${parameters.path}] parent directory is not safe for swap file creation`,
        safeParentResult
      )
}

async function createSwapTemporaryPath(
  parameters: SwapFileCreationParameters,
  parentDirectory: string
): Promise<ModuleResult | string> {
  const temporaryTemplate = `.${posixPath.basename(parameters.path)}.paratix.XXXXXX`
  const temporaryPathResult = await parameters.ssh.exec(
    `mktemp -p ${shellQuote(parentDirectory)} ${shellQuote(temporaryTemplate)}`,
    EXEC_OPTS
  )
  if (temporaryPathResult.code !== 0) {
    return failedCommand(
      `[swap.file: ${parameters.path}] swap temp file creation failed`,
      temporaryPathResult
    )
  }

  const temporaryPath = temporaryPathResult.stdout.trim()
  return temporaryPath === ""
    ? failedCommand(
        `[swap.file: ${parameters.path}] swap temp file creation failed`,
        buildEmptyMktempResult(temporaryPathResult.stdout)
      )
    : temporaryPath
}

async function cleanupSwapTemporaryPath(ssh: SshConnection, temporaryPath: string): Promise<void> {
  await ssh.exec(`rm -f ${shellQuote(temporaryPath)}`, EXEC_OPTS)
}

export async function cleanupSwapTemporaryFile(
  ssh: SshConnection,
  temporaryPath: string
): Promise<void> {
  await cleanupSwapTemporaryPath(ssh, temporaryPath)
}

async function initializeSwapTemporaryFile(
  parameters: SwapFileCreationParameters,
  temporaryPath: string
): Promise<ModuleResult | true> {
  const ddBlockCount = Math.ceil(parameters.sizeBytes / MEBI)
  const quotedTemporaryPath = shellQuote(temporaryPath)
  const createFileResult = await parameters.ssh.exec(
    `fallocate -l ${shellQuote(parameters.size)} ${quotedTemporaryPath} || { dd if=/dev/zero of=${quotedTemporaryPath} bs=1M count=${String(ddBlockCount)} status=none && truncate -s ${String(parameters.sizeBytes)} ${quotedTemporaryPath}; }`,
    EXEC_OPTS
  )
  if (createFileResult.code !== 0) {
    await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
    return failedCommand(
      `[swap.file: ${parameters.path}] swap file creation failed`,
      createFileResult
    )
  }

  const chmodResult = await parameters.ssh.exec(
    `chmod ${shellQuote(parameters.mode)} ${shellQuote(temporaryPath)}`,
    EXEC_OPTS
  )
  if (chmodResult.code !== 0) {
    await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
    return failedCommand(`[swap.file: ${parameters.path}] chmod failed`, chmodResult)
  }

  const makeSwapResult = await parameters.ssh.exec(`mkswap ${shellQuote(temporaryPath)}`, EXEC_OPTS)
  if (makeSwapResult.code === 0) return true
  await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
  return failedCommand(`[swap.file: ${parameters.path}] mkswap failed`, makeSwapResult)
}

async function publishSwapTemporaryFile(
  parameters: SwapFileCreationParameters,
  parentDirectory: string,
  temporaryPath: string
): Promise<ModuleResult | true> {
  const temporaryIdentityResult = await parameters.ssh.exec(
    `stat -c '%d:%i' ${shellQuote(temporaryPath)}`,
    EXEC_OPTS
  )
  if (temporaryIdentityResult.code !== 0) {
    await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
    return failedCommand(
      `[swap.file: ${parameters.path}] swap temp file identity failed`,
      temporaryIdentityResult
    )
  }

  const temporaryIdentity = temporaryIdentityResult.stdout.trim()
  // R-0000180: `mv -T -n` performs an atomic rename(2) that REFUSES to
  // overwrite an existing target. The previous `[ ! -e ] && mv -T` had a
  // TOCTOU window where another process could place a file at the
  // destination between the test and the move; with `-n` the kernel-level
  // atomicity of rename(2) closes that window.
  const publishResult = await parameters.ssh.exec(
    `${safeParentCommand(parentDirectory)} && mv -T -n ${shellQuote(temporaryPath)} ${shellQuote(parameters.path)}`,
    EXEC_OPTS
  )
  if (publishResult.code !== 0) {
    await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
    return failedCommand(`[swap.file: ${parameters.path}] swap file publish failed`, publishResult)
  }

  // R-0000680: re-check that the final path is still a regular file and not
  // a symlink before running `find -type f` / `swaplabel` against it. Without
  // this leading `[ ! -L ]` guard the verification could follow a symlink
  // planted between `mv -T -n` and stat — mirroring the paired
  // `[ ! -L ]` checks `moveSwapToBackup` and `restoreSwapBackup` already
  // emit on their destination paths (R-0000647).
  const verificationResult = await parameters.ssh.exec(
    `[ ! -L ${shellQuote(parameters.path)} ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -e ${shellQuote(temporaryPath)} ] && find ${shellQuote(parameters.path)} -maxdepth 0 -type f | grep -Fx ${shellQuote(parameters.path)} && [ "$(stat -c '%d:%i' ${shellQuote(parameters.path)})" = ${shellQuote(temporaryIdentity)} ] && swaplabel ${shellQuote(parameters.path)} >/dev/null 2>&1`,
    EXEC_OPTS
  )
  if (verificationResult.code === 0) return true

  await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
  return failedCommand(
    `[swap.file: ${parameters.path}] swap file publish verification failed`,
    verificationResult
  )
}

export type InitializedSwapTemporaryFile = {
  parentDirectory: string
  temporaryPath: string
}

export async function createInitializedSwapTemporaryFile(
  parameters: SwapFileCreationParameters
): Promise<InitializedSwapTemporaryFile | ModuleResult> {
  const parentDirectory = posixPath.dirname(parameters.path)
  const parentResult = await ensureSwapParentDirectory(parameters, parentDirectory)
  if (parentResult !== true) return parentResult

  const temporaryPath = await createSwapTemporaryPath(parameters, parentDirectory)
  if (typeof temporaryPath !== "string") return temporaryPath

  const initializeResult = await initializeSwapTemporaryFile(parameters, temporaryPath)
  if (initializeResult !== true) return initializeResult

  return { parentDirectory, temporaryPath }
}

export async function publishInitializedSwapTemporaryFile(
  parameters: SwapFileCreationParameters,
  temporaryFile: InitializedSwapTemporaryFile
): Promise<ModuleResult | true> {
  return publishSwapTemporaryFile(
    parameters,
    temporaryFile.parentDirectory,
    temporaryFile.temporaryPath
  )
}

export async function ensureSwapFilePresent(
  parameters: SwapFileCreationParameters
): Promise<ModuleResult | true> {
  const temporaryFile = await createInitializedSwapTemporaryFile(parameters)
  if ("status" in temporaryFile) return temporaryFile
  return publishInitializedSwapTemporaryFile(parameters, temporaryFile)
}
