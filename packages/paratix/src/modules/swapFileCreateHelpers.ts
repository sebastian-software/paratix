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

function safeParentCommand(parentDirectory: string): string {
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

async function initializeSwapTemporaryFile(
  parameters: SwapFileCreationParameters,
  temporaryPath: string
): Promise<ModuleResult | true> {
  const ddBlockCount = Math.ceil(parameters.sizeBytes / MEBI)
  const createFileResult = await parameters.ssh.exec(
    `fallocate -l ${shellQuote(parameters.size)} ${shellQuote(temporaryPath)} || dd if=/dev/zero of=${shellQuote(temporaryPath)} bs=1M count=${String(ddBlockCount)} status=none`,
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
  const publishResult = await parameters.ssh.exec(
    `${safeParentCommand(parentDirectory)} && [ ! -e ${shellQuote(parameters.path)} ] && [ ! -L ${shellQuote(parameters.path)} ] && mv -T ${shellQuote(temporaryPath)} ${shellQuote(parameters.path)}`,
    EXEC_OPTS
  )
  if (publishResult.code === 0) return true
  await cleanupSwapTemporaryPath(parameters.ssh, temporaryPath)
  return failedCommand(`[swap.file: ${parameters.path}] swap file publish failed`, publishResult)
}

export async function ensureSwapFilePresent(
  parameters: SwapFileCreationParameters
): Promise<ModuleResult | true> {
  const parentDirectory = posixPath.dirname(parameters.path)
  const parentResult = await ensureSwapParentDirectory(parameters, parentDirectory)
  if (parentResult !== true) return parentResult

  const temporaryPath = await createSwapTemporaryPath(parameters, parentDirectory)
  if (typeof temporaryPath !== "string") return temporaryPath

  const initializeResult = await initializeSwapTemporaryFile(parameters, temporaryPath)
  if (initializeResult !== true) return initializeResult

  return publishSwapTemporaryFile(parameters, parentDirectory, temporaryPath)
}
