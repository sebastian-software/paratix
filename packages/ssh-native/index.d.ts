// THROWAWAY SPIKE (issue #254): hand-written types of the JS wrapper in index.js.
import type { EventEmitter } from "node:events"
import type { PassThrough, Writable } from "node:stream"

export type ErrorCode =
  | "AUTH_FAILED"
  | "HOST_KEY_REJECTED"
  | "TIMEOUT"
  | "ABORTED"
  | "CONNECT_FAILED"
  | "PROTOCOL"
  | "CHANNEL_OPEN_FAILED"
  | "DISCONNECTED"
  | "SFTP_STATUS"
  | "UNSUPPORTED_KEY"
  | "ENCRYPTED_KEY"
  | "INTERNAL"

export interface NativeSshError extends Error {
  code: ErrorCode
  detail?: string
  errno?: number
  syscallCode?: string
  sftpStatus?: number
}

export interface HostKeyInfo {
  kind: "key" | "certificate"
  algorithm: string
  keyBase64: string
  fingerprintSha256: string
  caKeyBase64?: string
  caFingerprintSha256?: string
  certType?: "host" | "user"
  principals?: string[]
  validAfter?: number
  validBefore?: number
  keyId?: string
  caSignatureValid?: boolean
}

export interface ScanOptions {
  host: string
  port: number
  timeoutMs?: number
  hostCertificates?: boolean
}

export interface ConnectOptions {
  host: string
  port: number
  user: string
  readyTimeoutMs?: number
  agent?: string
  /** Zero-filled by `connect` right after it was handed to Rust. */
  privateKey?: Buffer
  password?: string
  agentForward?: boolean
  hostCertificates?: boolean
}

export interface AuthInfo {
  method: "agent" | "publickey" | "password" | "keyboard-interactive"
  identityKind?: "key" | "certificate"
  algorithm?: string
  attempts: number
}

export interface ExecResult {
  code: number | null
  signal: string | null
  execRefused: boolean
}

export interface ExecChannel {
  stdout: PassThrough
  stderr: PassThrough
  stdin: Writable
  done: Promise<ExecResult>
  close(): Promise<void>
}

export interface ChannelStats {
  rejected: string[]
  agentChannelsBridged: number
}

export interface Session extends EventEmitter {
  readonly authInfo: AuthInfo
  readonly closed: boolean
  channelStats(): ChannelStats
  exec(command: string): Promise<ExecChannel>
  sftpWrite(
    remotePath: string,
    options?: { mode?: number; highWaterMark?: number }
  ): Promise<Writable & { bytesWritten?: number }>
  close(): Promise<void>
  destroy(): void
}

export declare function scan(options: ScanOptions): Promise<HostKeyInfo>
/**
 * Host key verdict (fail closed): accepted only if `verifyHost` returns or
 * resolves exactly `true` or `undefined`; any other value rejects.
 */
export declare function connect(
  options: ConnectOptions,
  verifyHost: (info: HostKeyInfo) => Promise<boolean | void> | boolean | void
): Promise<Session>
export declare function cryptoBackend(): string
export declare function internalPanicProbe(): Promise<void>
export declare function currentTarget(): string
export declare const SUPPORTED_TARGETS: readonly string[]
