import type { Readable, Writable } from "node:stream"

export type TransportErrorCode =
  | "ABORTED"
  | "AUTH_FAILED"
  | "CHANNEL_OPEN_FAILED"
  | "CONNECT_FAILED"
  | "DISCONNECTED"
  | "ENCRYPTED_KEY"
  | "HOST_KEY_REJECTED"
  | "INTERNAL"
  | "PROTOCOL"
  | "SFTP_STATUS"
  | "TIMEOUT"
  | "UNSUPPORTED_KEY"

/** Internal failure classification; the original transport value remains the cause. */
export class TransportError extends Error {
  public constructor(
    public readonly transportCode: TransportErrorCode,
    cause: unknown
  ) {
    super(cause instanceof Error ? cause.message : String(cause), { cause })
    this.name = "TransportError"
  }
}

/**
 * Restore the existing public error contract at the policy boundary.
 * @param error - An internal rejection value.
 * @returns The original lower-level value, or the unchanged policy error.
 */
export function unwrapTransportError(error: unknown): unknown {
  return error instanceof TransportError ? error.cause : error
}

export type TransportConnectOptions = {
  agent?: string
  agentForward?: boolean
  host: string
  password?: string
  port: number
  privateKey?: Buffer | string
  readyTimeout: number
  signal?: AbortSignal
  username: string
  verifyHostKey: (key: Buffer) => boolean | Promise<boolean>
}

export type TransportExit = { code: null | number; signal: null | string }
export type TransportExecChannel = {
  close: () => void
  onExit: (listener: (exit: TransportExit) => void) => () => void
  stderr: Readable
  stdin: Writable
  stdout: Readable
}
export type TransportSftpSession = {
  createReadStream: (path: string) => Readable
  createWriteStream: (path: string, options: { mode: number }) => Writable
  end: () => void
}
/**
 * Optional handoff callbacks preserve same-tick stream collection when available.
 * Implementations may ignore them: consumers must also accept the Promise result,
 * deduplicate delivery, and observe buffered data and exit for late subscribers.
 */
export type TransportConnection = {
  close: () => Promise<void>
  destroy: () => void
  exec: (
    command: string,
    onChannel?: (channel: TransportExecChannel) => void
  ) => Promise<TransportExecChannel>
  onDisconnect: (listener: (error: TransportError) => void) => () => void
  sftp: (onSession?: (session: TransportSftpSession) => void) => Promise<TransportSftpSession>
}
export type Transport = {
  connect: (options: TransportConnectOptions) => Promise<TransportConnection>
}
