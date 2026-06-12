/* eslint-disable max-lines -- SFTP transfer helpers keep stream lifecycle wiring local */
import type { Writable } from "node:stream"
import type { Client, SFTPWrapper } from "ssh2"

import { randomUUID } from "node:crypto"
import { createReadStream, createWriteStream } from "node:fs"
import { rename, unlink } from "node:fs/promises"
import { dirname, join } from "node:path"
import { Readable } from "node:stream"

import type { PreparedSecrets } from "./sshHelpers.js"

import { maskPreparedSecrets } from "./sshHelpers.js"

/** Default timeout for SFTP transfers in milliseconds (2 minutes). */
export const SFTP_TIMEOUT = 120_000

/**
 * R-0000689: helper that masks a remote-path interpolation against the
 * prepared secret variants. When `secrets` is `undefined` the input is
 * returned unchanged so existing callers that do not know about the
 * masking pipeline continue to receive the raw text.
 *
 * @param value - The string about to be embedded in an error message.
 * @param secrets - Optional prepared secrets used to redact the text.
 * @returns The masked variant or the original value when no secrets are set.
 */
function maskInterpolatedValue(value: string, secrets: PreparedSecrets | undefined): string {
  if (secrets === undefined) return value
  return maskPreparedSecrets(value, secrets)
}

type TransferSettlement = {
  rejectOnce: (reason: Error) => void
  resolveOnce: () => void
}

type TransferStreams = {
  readStream: Readable
  writeStream: Writable
}

function normalizeTransferError(error: unknown, message: string): Error {
  return error instanceof Error ? error : new Error(`${message}: ${String(error)}`)
}

function noopAbortCleanup(): void {
  // No subscription installed.
}

/**
 * R-0000600: defensive noop installed in place of the real `error` listeners
 * once a transfer has settled. Detaching the original handlers is what
 * allows the closures over readStream/writeStream/sftp to be released, but a
 * late `error` event emitted after settle (e.g. when both streams error
 * back-to-back and the second emit races the cleanup) would otherwise
 * become an unhandled `error` and crash the process. The noop swallows that
 * straggler emit while still letting the original closures be GC'd. Hoisted
 * to module scope so the same shared reference can be attached and later
 * removed across every wireStreams invocation without capturing any
 * per-call state.
 */
function noopStreamError(): void {
  /* swallow late stream errors after the transfer has settled */
}

/**
 * R-0000687: register a one-shot `error` listener on the SFTP wrapper before
 * we call `sftp.end()`. Without this sink, ssh2 may emit `error` on the
 * wrapper after the surrounding Promise has already settled (e.g. when the
 * underlying channel reports a teardown error post-close). Node would treat
 * that emit as an unhandled `error` and crash the process. The once-listener
 * absorbs that straggler emit without keeping the SFTPWrapper alive. The
 * runtime guard accommodates lightweight test doubles that do not implement
 * the full EventEmitter surface.
 *
 * @param sftp - The SFTP wrapper to silence on late errors.
 */
function silenceLateSftpErrors(sftp: SFTPWrapper): void {
  const maybeOnce = (sftp as { once?: unknown }).once
  if (typeof maybeOnce !== "function") return
  sftp.once("error", () => {
    /* swallow late SFTP wrapper errors after the transfer has settled */
  })
}

/**
 * R-0000255: short-circuit the openSftp wait when the SSH connection is torn
 * down externally (e.g. the SIGINT path in runner.ts). Without this, the
 * session-open promise would idle until the default timeout fires even
 * though the underlying transport is already gone. Returns a cleanup
 * function the caller invokes once the open path settles, plus an `aborted`
 * flag indicating that the abort already fired and the caller must return.
 *
 * @param connectionAbortSignal - Optional connection-level abort signal.
 * @param onAbort - Called synchronously when the abort fires before settle.
 * @returns Cleanup helper and aborted flag.
 */
function subscribeToConnectionAbort(
  connectionAbortSignal: AbortSignal | undefined,
  onAbort: () => void
): { aborted: boolean; cleanup: () => void } {
  if (connectionAbortSignal == null) {
    return { aborted: false, cleanup: noopAbortCleanup }
  }
  if (connectionAbortSignal.aborted) {
    onAbort()
    return { aborted: true, cleanup: noopAbortCleanup }
  }
  const handleAbort = (): void => {
    onAbort()
  }
  connectionAbortSignal.addEventListener("abort", handleAbort, { once: true })
  const cleanup = (): void => {
    connectionAbortSignal.removeEventListener("abort", handleAbort)
  }
  return { aborted: false, cleanup }
}

function openSftp(options: {
  client: Client
  connectionAbortSignal?: AbortSignal
  onOpen: (sftp: SFTPWrapper) => void
  reject: (reason: Error) => void
  timeout: number
  timeoutMessage: string
}): void {
  const { client, connectionAbortSignal, onOpen, reject, timeout, timeoutMessage } = options
  let settled = false
  // Holder so the timer / sftp callback can call into a still-mutable cleanup
  // reference once `subscribeToConnectionAbort` returns the real one below.
  const abortHandle: { cleanup: () => void } = { cleanup: noopAbortCleanup }
  const timer = setTimeout(() => {
    if (settled) return
    settled = true
    abortHandle.cleanup()
    client.end()
    reject(new Error(timeoutMessage))
  }, timeout)
  const subscription = subscribeToConnectionAbort(connectionAbortSignal, () => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    reject(new Error("SFTP session aborted: ssh disconnect"))
  })
  abortHandle.cleanup = subscription.cleanup
  if (subscription.aborted) return
  try {
    client.sftp((error: Error | undefined, sftp: SFTPWrapper | undefined) => {
      if (settled) {
        if (sftp !== undefined) {
          silenceLateSftpErrors(sftp)
          sftp.end()
        }
        return
      }
      clearTimeout(timer)
      abortHandle.cleanup()
      settled = true
      if (error) {
        reject(error)
        return
      }
      if (sftp === undefined) {
        reject(new Error("Failed to open SFTP session: missing SFTP session"))
        return
      }
      onOpen(sftp)
    })
  } catch (openError) {
    clearTimeout(timer)
    abortHandle.cleanup()
    settled = true
    reject(normalizeTransferError(openError, "Failed to open SFTP session"))
  }
}

function createTransferSettlement(options: {
  clearTimer: () => void
  reject: (reason: Error) => void
  resolve: () => void
  sftp: SFTPWrapper
}): TransferSettlement {
  let settled = false

  return {
    rejectOnce(reason: Error) {
      options.clearTimer()
      if (settled) return
      settled = true
      silenceLateSftpErrors(options.sftp)
      options.sftp.end()
      options.reject(reason)
    },
    resolveOnce() {
      options.clearTimer()
      if (settled) return
      settled = true
      silenceLateSftpErrors(options.sftp)
      options.sftp.end()
      options.resolve()
    },
  }
}

function openDownloadStreams(
  sftp: SFTPWrapper,
  remotePath: string,
  temporaryPath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    readStream = sftp.createReadStream(remotePath)
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const writeStream = createWriteStream(temporaryPath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP download streams")
  }
}

function openUploadStreams(
  sftp: SFTPWrapper,
  localPath: string,
  remotePath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    readStream = createReadStream(localPath)
    const writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP upload streams")
  }
}

function openContentUploadStreams(
  sftp: SFTPWrapper,
  content: string,
  remotePath: string
): TransferStreams {
  let readStream: Readable | undefined
  try {
    readStream = Readable.from([Buffer.from(content, "utf8")])
    const writeStream = sftp.createWriteStream(remotePath, { mode: 0o600 })
    return { readStream, writeStream }
  } catch (streamError) {
    if (readStream !== undefined && typeof readStream.destroy === "function") {
      readStream.destroy()
    }
    throw normalizeTransferError(streamError, "Failed to create SFTP content upload streams")
  }
}

/**
 * Wire up stream event handlers with a timeout guard, then pipe.
 *
 * @param options - Stream piping options including timeout configuration.
 * @param options.completionEvents - Stream events that mark a successful transfer.
 * @param options.connectionAbortSignal - Optional connection-level abort signal that destroys the streams when fired (R-0000255).
 * @param options.prematureCloseMessage - Error message for a close before a successful transfer.
 * @param options.readStream - The source stream to read from.
 * @param options.reject - Promise reject callback.
 * @param options.resolve - Promise resolve callback.
 * @param options.sftp - The SFTP wrapper to close on completion.
 * @param options.timeout - Maximum time in ms before the transfer is aborted.
 * @param options.timeoutMessage - Error message to use when the transfer times out.
 * @param options.writeStream - The destination stream to write to.
 */
type StreamListeners = {
  onClose: () => void
  onFinish: () => void
  onReadError: (readError: Error) => void
  onWriteError: (writeError: Error) => void
}

/**
 * R-0000600: build the set of named stream listeners used by
 * {@link wireStreams}. Extracted so the listener functions stay close
 * together and `wireStreams` can simply attach and later `off(...)` them as
 * a unit. The `getSettlement` indirection lets the listeners be created
 * before the settlement holder is populated — the listeners are only
 * invoked after `pipe()` starts the transfer, which always happens after
 * the settlement has been assigned.
 *
 * @param parameters - Stream wiring inputs shared with `wireStreams`.
 * @param parameters.getSettlement - Late binding for the `TransferSettlement`
 *   that the listeners forward `resolveOnce` / `rejectOnce` calls to.
 * @param parameters.prematureCloseMessage - Error message used by the close
 *   listener when a premature close is observed. `undefined` disables it.
 * @param parameters.readStream - The source stream to subscribe to for `error` events.
 * @param parameters.writeStream - The destination stream to subscribe to for `error`
 *   and completion events.
 * @returns Named listener functions keyed by the event they handle.
 */
function buildStreamListeners(parameters: {
  getSettlement: () => TransferSettlement
  prematureCloseMessage: string | undefined
  readStream: Readable
  writeStream: Writable
}): StreamListeners {
  const { getSettlement, prematureCloseMessage, readStream, writeStream } = parameters
  return {
    onClose(): void {
      if (prematureCloseMessage === undefined) return
      // Issue #37: for small in-memory payloads, ssh2's SFTP WriteStream may
      // emit "close" before (or in the same micro-task as) "finish". When
      // `writableFinished` is true the writable side has already flushed
      // everything, so the close is the regular end-of-life and the transfer
      // was successful. Settling here resolves the promise even when "finish"
      // is swallowed by the racing "close".
      if (writeStream.writableFinished) {
        getSettlement().resolveOnce()
        return
      }
      readStream.destroy()
      if (typeof writeStream.destroy === "function") writeStream.destroy()
      getSettlement().rejectOnce(new Error(prematureCloseMessage))
    },
    onFinish(): void {
      getSettlement().resolveOnce()
    },
    onReadError(readError: Error): void {
      if (typeof readStream.destroy === "function") readStream.destroy()
      if (typeof writeStream.destroy === "function") writeStream.destroy()
      getSettlement().rejectOnce(readError)
    },
    onWriteError(writeError: Error): void {
      readStream.destroy()
      if (typeof writeStream.destroy === "function") writeStream.destroy()
      getSettlement().rejectOnce(writeError)
    },
  }
}

/**
 * R-0000600: detach the stream listeners attached by {@link attachStreamListeners}
 * and replace the `error` handlers with the shared {@link noopStreamError} noop
 * so a late stream error fired after settle does not crash the process.
 *
 * @param parameters - Stream and listener references mirroring the attach call.
 * @param parameters.completionEvents - Events that mark a successful transfer
 *   and were registered with `listeners.onFinish`.
 * @param parameters.listeners - Listener bundle returned by {@link buildStreamListeners}.
 * @param parameters.prematureCloseMessage - Same value supplied to the attach
 *   call; controls whether `onClose` was registered.
 * @param parameters.readStream - Source stream the read-side listeners were attached to.
 * @param parameters.writeStream - Destination stream the write-side listeners were attached to.
 */
function detachStreamListeners(parameters: {
  completionEvents: Array<"close" | "finish">
  listeners: StreamListeners
  prematureCloseMessage: string | undefined
  readStream: Readable
  writeStream: Writable
}): void {
  const { completionEvents, listeners, prematureCloseMessage, readStream, writeStream } = parameters
  for (const completionEvent of completionEvents) {
    writeStream.off(completionEvent, listeners.onFinish)
  }
  if (prematureCloseMessage !== undefined) {
    writeStream.off("close", listeners.onClose)
  }
  writeStream.off("error", listeners.onWriteError)
  readStream.off("error", listeners.onReadError)
  // R-0000841: register the post-settlement noop with `{ once: true }`.
  // The previous persistent listener stayed attached for the lifetime of
  // the underlying streams, which kept the streams (and their internal
  // buffers) reachable long after the transfer had finished. Stream errors
  // in this window are rare and only need to be absorbed once; further
  // straggler emits would already pass through Node's normal unhandled
  // error machinery after the stream has been destroyed and forgotten.
  writeStream.once("error", noopStreamError)
  readStream.once("error", noopStreamError)
}

/**
 * R-0000600: attach the stream listeners returned by {@link buildStreamListeners}
 * onto the read/write streams.
 *
 * @param parameters - Stream and listener references.
 * @param parameters.completionEvents - Stream events that mark a successful transfer.
 * @param parameters.listeners - Listener bundle returned by {@link buildStreamListeners}.
 * @param parameters.prematureCloseMessage - When defined, `onClose` is wired to
 *   the write stream's `"close"` event.
 * @param parameters.readStream - Source stream that receives the read-side `error` listener.
 * @param parameters.writeStream - Destination stream that receives the write-side listeners.
 */
function attachStreamListeners(parameters: {
  completionEvents: Array<"close" | "finish">
  listeners: StreamListeners
  prematureCloseMessage: string | undefined
  readStream: Readable
  writeStream: Writable
}): void {
  const { completionEvents, listeners, prematureCloseMessage, readStream, writeStream } = parameters
  for (const completionEvent of completionEvents) {
    writeStream.on(completionEvent, listeners.onFinish)
  }
  if (prematureCloseMessage !== undefined) {
    writeStream.on("close", listeners.onClose)
  }
  writeStream.on("error", listeners.onWriteError)
  readStream.on("error", listeners.onReadError)
}

function wireStreams(options: {
  completionEvents?: Array<"close" | "finish">
  connectionAbortSignal?: AbortSignal
  prematureCloseMessage?: string
  readStream: Readable
  reject: (reason: Error) => void
  resolve: () => void
  sftp: SFTPWrapper
  timeout: number
  timeoutMessage: string
  writeStream: Writable
}): void {
  const {
    completionEvents = ["finish"],
    connectionAbortSignal,
    prematureCloseMessage,
    readStream,
    reject,
    resolve,
    sftp,
    timeout,
    timeoutMessage,
    writeStream,
  } = options

  const timer = setTimeout(() => {
    readStream.destroy()
    writeStream.destroy()
    settlement.rejectOnce(new Error(timeoutMessage))
  }, timeout)
  // R-0000600: keep the stream listeners as named functions so the settle
  // path can detach them via `off(...)`. The previous inline-arrow form
  // retained closure references on both readStream and writeStream long
  // after the transfer had settled — for a long-lived SSH session holding
  // many transient SFTP streams this leaked memory proportional to the
  // number of completed transfers. The listeners read the settlement via a
  // getter so the cyclic reference between `settlement.clearTimer` (which
  // calls `off(...)` with these listeners) and the listeners themselves
  // (which call `settlement.rejectOnce`) resolves without a `let`.
  const listeners = buildStreamListeners({
    getSettlement: () => settlement,
    prematureCloseMessage,
    readStream,
    writeStream,
  })

  // R-0000688 / R-0000255: declare `handleConnectionAbort` as a hoisted
  // function declaration BEFORE `createTransferSettlement`. The previous
  // `const` form lived after the settlement and produced a temporal-dead-zone
  // hazard: `clearTimer` (passed into the settlement) references
  // `handleConnectionAbort`, so an early teardown — e.g. the timer firing
  // before the `const` initializer ran — would hit a ReferenceError. A
  // function declaration is hoisted to the top of the enclosing function so
  // the reference is always defined when `clearTimer` runs. When the
  // underlying SSH transport is torn down (e.g. the SIGINT handler in
  // runner.ts) any in-flight SFTP transfer would otherwise sit idle until
  // the default 120 s timeout fires, because client.sftp() does NOT emit a
  // stream error on its own when the parent connection closes. Couple the
  // transfer to a connection-level abort signal so an external disconnect
  // destroys the streams immediately.
  function handleConnectionAbort(): void {
    readStream.destroy()
    if (typeof writeStream.destroy === "function") writeStream.destroy()
    settlement.rejectOnce(new Error("SFTP transfer aborted: ssh disconnect"))
  }

  const settlement = createTransferSettlement({
    clearTimer() {
      clearTimeout(timer)
      // R-0000600: drop the listeners that were attached below so the
      // closures over readStream/writeStream/sftp can be garbage-collected
      // immediately after the transfer settles. A defensive
      // `noopStreamError` replaces the real error listeners so a late
      // `error` event still has a handler and does not crash the process.
      detachStreamListeners({
        completionEvents,
        listeners,
        prematureCloseMessage,
        readStream,
        writeStream,
      })
      if (connectionAbortSignal != null) {
        connectionAbortSignal.removeEventListener("abort", handleConnectionAbort)
      }
    },
    reject,
    resolve,
    sftp,
  })

  attachStreamListeners({
    completionEvents,
    listeners,
    prematureCloseMessage,
    readStream,
    writeStream,
  })

  // R-0000584: handle the connection-abort signal AFTER the read/write
  // listeners are attached but BEFORE `pipe` starts the transfer. When the
  // signal is already aborted on entry we used to schedule the handler via
  // `queueMicrotask`, but a synchronous `pipe` finish could call
  // `resolveOnce` before that microtask ran and the abort would be swallowed.
  // Invoking `handleConnectionAbort` synchronously here guarantees the abort
  // is observed first, regardless of how quickly `pipe` settles.
  if (connectionAbortSignal != null) {
    if (connectionAbortSignal.aborted) {
      handleConnectionAbort()
    } else {
      connectionAbortSignal.addEventListener("abort", handleConnectionAbort, { once: true })
    }
  }

  readStream.pipe(writeStream)
}

/**
 * Transfer a remote file to a local path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param remotePath - Source path on the remote host.
 * @param localPath - Destination path on the local filesystem.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down. Triggers immediate stream
 *   destruction (R-0000255) so a SIGINT-driven `ssh.disconnect()` does not
 *   leave the transfer waiting for the default 120 s timeout.
 * @param secrets - R-0000689: optional prepared secrets routed through
 *   `maskPreparedSecrets` for every error reason that interpolates the
 *   remote path. Without this bridge an attacker-shaped remote path could
 *   leak credentials embedded in path templates into operator logs.
 */
// eslint-disable-next-line max-params -- timeout / abort / secrets parameters extend the existing signature; cleanup/finalize logic is intentionally kept together
export async function sftpDownload(
  client: Client,
  remotePath: string,
  localPath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal,
  secrets?: PreparedSecrets
): Promise<void> {
  return new Promise((resolve, reject) => {
    const temporaryPath = join(dirname(localPath), `.paratix-download-${randomUUID()}.tmp`)
    const maskedRemotePath = maskInterpolatedValue(remotePath, secrets)
    let shouldCleanupTemporaryFile = false

    const rejectWithCleanup = (reason: Error): void => {
      if (shouldCleanupTemporaryFile) {
        // R-0000666: detach the temp-file unlink from the reject path so the
        // rejection reason surfaces without waiting for the network filesystem
        // (NFS/SMB) to ack the unlink. The previous sync unlinkSync blocked
        // the event loop and accumulated under parallel sftpDownload failures.
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        unlink(temporaryPath).catch(() => {
          // Best effort cleanup: preserve the original transfer error.
        })
      }
      reject(reason)
    }

    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openDownloadStreams(sftp, remotePath, temporaryPath)
          shouldCleanupTemporaryFile = true
        } catch (streamError) {
          silenceLateSftpErrors(sftp)
          sftp.end()
          rejectWithCleanup(normalizeTransferError(streamError, "Failed to create SFTP download"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          readStream: streams.readStream,
          reject: rejectWithCleanup,
          resolve() {
            // R-0000148: use async rename so the event loop is not blocked on
            // network filesystems or large files. After a successful rename,
            // disable the cleanup flag so a late stray rejection cannot
            // unlink the freshly renamed final file.
            // eslint-disable-next-line security/detect-non-literal-fs-filename
            rename(temporaryPath, localPath).then(
              () => {
                shouldCleanupTemporaryFile = false
                resolve()
              },
              (finalizeError: unknown) => {
                rejectWithCleanup(
                  finalizeError instanceof Error
                    ? finalizeError
                    : new Error(`Failed to finalize SFTP download: ${String(finalizeError)}`)
                )
              }
            )
          },
          sftp,
          timeout,
          timeoutMessage: `SFTP download timed out after ${timeout}ms: ${maskedRemotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject: rejectWithCleanup,
      timeout,
      timeoutMessage: `SFTP download session timed out after ${timeout}ms: ${maskedRemotePath}`,
    })
  })
}

/**
 * Transfer a local file to a remote path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param localPath - Source path on the local filesystem.
 * @param remotePath - Destination path on the remote host.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down (R-0000255).
 * @param secrets - R-0000689: optional prepared secrets routed through
 *   `maskPreparedSecrets` for every error reason that interpolates the
 *   remote path.
 */
// eslint-disable-next-line max-params -- timeout / abort / secrets parameters extend the existing signature
export async function sftpUpload(
  client: Client,
  localPath: string,
  remotePath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal,
  secrets?: PreparedSecrets
): Promise<void> {
  return new Promise((resolve, reject) => {
    const maskedRemotePath = maskInterpolatedValue(remotePath, secrets)
    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openUploadStreams(sftp, localPath, remotePath)
        } catch (streamError) {
          silenceLateSftpErrors(sftp)
          sftp.end()
          reject(normalizeTransferError(streamError, "Failed to create SFTP upload"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          prematureCloseMessage: `SFTP upload closed before finish: ${maskedRemotePath}`,
          readStream: streams.readStream,
          reject,
          resolve,
          sftp,
          timeout,
          timeoutMessage: `SFTP upload timed out after ${timeout}ms: ${maskedRemotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject,
      timeout,
      timeoutMessage: `SFTP upload session timed out after ${timeout}ms: ${maskedRemotePath}`,
    })
  })
}

/**
 * Transfer string content directly to a remote path via SFTP.
 *
 * @param client - The connected ssh2 client.
 * @param content - UTF-8 string content to transfer.
 * @param remotePath - Destination path on the remote host.
 * @param timeout - Maximum time in ms before the transfer is aborted.
 * @param connectionAbortSignal - Optional abort signal that fires when the
 *   underlying SSH transport is torn down (R-0000255).
 * @param secrets - R-0000689: optional prepared secrets routed through
 *   `maskPreparedSecrets` for every error reason that interpolates the
 *   remote path.
 */
// eslint-disable-next-line max-params -- timeout / abort / secrets parameters mirror sftpUpload
export async function sftpUploadContent(
  client: Client,
  content: string,
  remotePath: string,
  timeout = SFTP_TIMEOUT,
  connectionAbortSignal?: AbortSignal,
  secrets?: PreparedSecrets
): Promise<void> {
  return new Promise((resolve, reject) => {
    const maskedRemotePath = maskInterpolatedValue(remotePath, secrets)
    openSftp({
      client,
      connectionAbortSignal,
      onOpen(sftp) {
        let streams: TransferStreams
        try {
          streams = openContentUploadStreams(sftp, content, remotePath)
        } catch (streamError) {
          silenceLateSftpErrors(sftp)
          sftp.end()
          reject(normalizeTransferError(streamError, "Failed to create SFTP content upload"))
          return
        }

        wireStreams({
          completionEvents: ["finish"],
          connectionAbortSignal,
          prematureCloseMessage: `SFTP content upload closed before finish: ${maskedRemotePath}`,
          readStream: streams.readStream,
          reject,
          resolve,
          sftp,
          timeout,
          timeoutMessage: `SFTP content upload timed out after ${timeout}ms: ${maskedRemotePath}`,
          writeStream: streams.writeStream,
        })
      },
      reject,
      timeout,
      timeoutMessage: `SFTP content upload session timed out after ${timeout}ms: ${maskedRemotePath}`,
    })
  })
}
