import type { SshConnection } from "../../src/types.js"

export type DownloadFileCall = { localPath: string; remotePath: string }
export type UploadFileCall = {
  localPath: string
  options: Parameters<SshConnection["uploadFile"]>[2]
  remotePath: string
}
export type WriteFileCall = {
  content: string
  options: Parameters<SshConnection["writeFile"]>[2]
  remotePath: string
}

type PathAllowlistEntry = RegExp | string
export type DownloadFileAllowlistEntry = {
  localPath: PathAllowlistEntry
  remotePath: PathAllowlistEntry
}
export type UploadFileAllowlistEntry = {
  localPath: PathAllowlistEntry
  options: Parameters<SshConnection["uploadFile"]>[2]
  remotePath: PathAllowlistEntry
}
export type WriteFileAllowlistEntry = {
  options: Parameters<SshConnection["writeFile"]>[2]
  remotePath: PathAllowlistEntry
}

export type SideEffectOptions = {
  allowDisconnect?: boolean
  allowDownloads?: DownloadFileAllowlistEntry[]
  allowProbeSudo?: boolean
  allowUploads?: UploadFileAllowlistEntry[]
  allowWrites?: WriteFileAllowlistEntry[]
  strict?: boolean
}

export type SideEffectRecorder = {
  disconnect: SshConnection["disconnect"]
  disconnectCalls: Array<Record<never, never>>
  downloadFile: SshConnection["downloadFile"]
  downloadFileCalls: DownloadFileCall[]
  probeSudo: SshConnection["probeSudo"]
  probeSudoCalls: Array<Record<never, never>>
  uploadFile: SshConnection["uploadFile"]
  uploadFileCalls: UploadFileCall[]
  writeFile: SshConnection["writeFile"]
  writeFileCalls: WriteFileCall[]
}

function unstubbed(kind: string, summary: string): Error {
  return new Error(`createMockSsh: unstubbed ${kind} call: ${summary}`)
}

function sameUploadOptions(
  actual: UploadFileCall["options"],
  expected: UploadFileCall["options"]
): boolean {
  return actual?.mode === expected?.mode
}

function sameWriteOptions(
  actual: WriteFileCall["options"],
  expected: WriteFileCall["options"]
): boolean {
  return actual.mode === expected.mode
}

function matchesPath(actual: string, expected: PathAllowlistEntry): boolean {
  return typeof expected === "string" ? actual === expected : expected.test(actual)
}

function assertAllowed(input: {
  allowed: boolean
  kind: string
  options?: SideEffectOptions
  summary: string
}): void {
  if (input.options?.strict === false || input.allowed) return
  throw unstubbed(input.kind, input.summary)
}

function createDownloadFile(
  calls: DownloadFileCall[],
  options?: SideEffectOptions
): SshConnection["downloadFile"] {
  return async (remotePath, localPath) => {
    const call = { localPath, remotePath }
    calls.push(call)
    assertAllowed({
      allowed:
        options?.allowDownloads?.some(
          (allowed) =>
            matchesPath(call.localPath, allowed.localPath) &&
            matchesPath(call.remotePath, allowed.remotePath)
        ) ?? false,
      kind: "downloadFile",
      options,
      summary: `${remotePath} -> ${localPath}`,
    })
    await Promise.resolve()
  }
}

function createUploadFile(
  calls: UploadFileCall[],
  options?: SideEffectOptions
): SshConnection["uploadFile"] {
  return async (localPath, remotePath, uploadOptions) => {
    const call = { localPath, options: uploadOptions, remotePath }
    calls.push(call)
    assertAllowed({
      allowed:
        options?.allowUploads?.some(
          (allowed) =>
            matchesPath(call.localPath, allowed.localPath) &&
            matchesPath(call.remotePath, allowed.remotePath) &&
            sameUploadOptions(call.options, allowed.options)
        ) ?? false,
      kind: "uploadFile",
      options,
      summary: `${localPath} -> ${remotePath}`,
    })
    await Promise.resolve()
  }
}

function createWriteFile(
  calls: WriteFileCall[],
  options?: SideEffectOptions
): SshConnection["writeFile"] {
  return async (remotePath, content, writeOptions) => {
    const call = { content, options: writeOptions, remotePath }
    calls.push(call)
    assertAllowed({
      allowed:
        options?.allowWrites?.some(
          (allowed) =>
            matchesPath(call.remotePath, allowed.remotePath) &&
            sameWriteOptions(call.options, allowed.options)
        ) ?? false,
      kind: "writeFile",
      options,
      summary: `${remotePath} (content redacted, ${content.length} bytes)`,
    })
    await Promise.resolve()
  }
}

export function createSideEffectRecorder(options?: SideEffectOptions): SideEffectRecorder {
  const disconnectCalls: Array<Record<never, never>> = []
  const downloadFileCalls: DownloadFileCall[] = []
  const probeSudoCalls: Array<Record<never, never>> = []
  const uploadFileCalls: UploadFileCall[] = []
  const writeFileCalls: WriteFileCall[] = []
  return {
    disconnect: () => {
      disconnectCalls.push({})
      assertAllowed({
        allowed: options?.allowDisconnect === true,
        kind: "disconnect",
        options,
        summary: "disconnect()",
      })
    },
    disconnectCalls,
    downloadFile: createDownloadFile(downloadFileCalls, options),
    downloadFileCalls,
    async probeSudo() {
      probeSudoCalls.push({})
      assertAllowed({
        allowed: options?.allowProbeSudo === true,
        kind: "probeSudo",
        options,
        summary: "probeSudo()",
      })
      await Promise.resolve()
    },
    probeSudoCalls,
    uploadFile: createUploadFile(uploadFileCalls, options),
    uploadFileCalls,
    writeFile: createWriteFile(writeFileCalls, options),
    writeFileCalls,
  }
}
