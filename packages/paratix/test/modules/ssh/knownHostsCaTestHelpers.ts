import type { ExecOptions, ExecResult } from "../../../src/types.js"

import { createMockSsh } from "../../helpers/mockSsh.js"

const SSH_STRING_LENGTH_BYTES = 4
const ED25519_KEY_BYTES = 32

export const HOME = "/home/alice"
export const FILE = `${HOME}/.ssh/known_hosts`
export const TEMPORARY = `${HOME}/.ssh/.paratix-known-hosts.ABC123`
export const DIRECTORY_METADATA = "1:2 700 alice developers"
export const FILE_METADATA = "1:3:10:mtime:ctime 600 alice developers"

function sshString(value: Buffer | string): Buffer {
  const bytes = Buffer.from(value)
  const length = Buffer.alloc(SSH_STRING_LENGTH_BYTES)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

export function publicKey(seed = 1): string {
  return `ssh-ed25519 ${Buffer.concat([sshString("ssh-ed25519"), sshString(Buffer.alloc(ED25519_KEY_BYTES, seed))]).toString("base64")}`
}

// RSA supplies real padding so the strict roundtrip cases exercise valid blobs.
export function paddedPublicKey(): string {
  return `ssh-rsa ${Buffer.concat([sshString("ssh-rsa"), sshString(Buffer.from([1, 0, 1])), sshString(Buffer.from([1, 2, 0]))]).toString("base64")}`
}

export type FileState = {
  content: string
  directory: null | string
  file: null | string
}

export function encodedSnapshot(state: FileState): string {
  const encoded =
    state.file === null ? "" : Buffer.from(`${state.content}\n0`, "latin1").toString("base64")
  return `${state.directory ?? "missing"}\n${state.file ?? "missing"}\n${encoded}`
}

export function isInspection(command: string): boolean {
  return command.startsWith("set -e\n") && command.includes("directory_before=missing")
}

export function isStage(command: string): boolean {
  return command.startsWith("set -e\n") && command.includes(`dd of='${TEMPORARY}'`)
}

export function isPublication(command: string): boolean {
  return command.startsWith("set -e\n") && command.includes(`if ! mv -T -- '${TEMPORARY}'`)
}

export function isDirectoryPreparation(command: string): boolean {
  return command.startsWith("set -e\n") && command.includes("changed during prepare")
}

export function isMutation(command: string): boolean {
  return /^mkdir |\bchmod |\bchown |^mktemp |\bmv -T|\brm -f|\/var\/lib\/paratix\/flags/v.test(
    command
  )
}

export type Interceptor = (command: string, state: FileState) => Partial<ExecResult> | undefined

type CaSshParameters = {
  content?: string
  directory?: null | string
  file?: null | string
  intercept?: Interceptor
}

/**
 * Remote exec double for decision/failure tests. It understands only the module's
 * explicit command families and fails closed for others. Real shell safety and
 * OpenSSH behavior are covered by the Docker integration fixture.
 *
 * @param parameters - Initial snapshot and optional remote command failure injector.
 * @returns The connection, observable snapshot and publication indicator.
 */
export function createCaSsh(parameters: CaSshParameters = {}): {
  connection: ReturnType<typeof createMockSsh>
  published: () => boolean
  state: FileState
} {
  const state: FileState = {
    content: parameters.content ?? "",
    directory: parameters.directory === undefined ? DIRECTORY_METADATA : parameters.directory,
    file: parameters.file === undefined ? FILE_METADATA : parameters.file,
  }
  const base = createMockSsh(
    {
      "getent passwd 'alice'": { stdout: `alice:x:1001:2001::${HOME}:/bin/sh\n` },
      hostname: { stdout: "controller-user" },
      "id -gn 'alice'": { stdout: "developers\n" },
      "printf '%s' \"$HOME\"": { stdout: HOME },
    },
    {
      allowFlagLockInternalDefaults: true,
      responseStubs: [
        { command: /^mkdir \/var\/lib\/paratix\/flags\/'ssh-known-hosts-[a-f0-9]+'$/v, result: {} },
        { command: /\nreadlink -m -- '[^']+\/\.ssh\/known_hosts'$/v, result: { stdout: FILE } },
      ],
    }
  )
  let staged = ""
  let published = false
  const observed = (command: string, options?: ExecOptions): void => {
    base.calls.push(command)
    base.execCalls.push({ command, options })
  }
  function inspectionResponse(command: string): Partial<ExecResult> | undefined {
    if (isInspection(command)) return { stdout: encodedSnapshot(state) }
    if (isDirectoryPreparation(command)) {
      state.directory = DIRECTORY_METADATA
      return {}
    }
    if (command === `mktemp -p '${HOME}/.ssh' -- '.paratix-known-hosts.XXXXXX'`) {
      return { stdout: TEMPORARY }
    }
  }
  function transactionResponse(command: string): Partial<ExecResult> | undefined {
    if (isStage(command)) {
      const encoded = /printf '%s' '(?<payload>[^']*)' \| base64 -d/v.exec(command)?.groups?.payload
      if (encoded === undefined) throw new Error("Missing staged base64 payload")
      staged = Buffer.from(encoded, "base64").toString("latin1")
      return {}
    }
    if (isPublication(command)) {
      state.content = staged
      state.file = FILE_METADATA.replace("1:3:", "1:4:")
      published = true
      return {}
    }
    if (command === `rm -f -- '${TEMPORARY}'`) return {}
  }
  const connection = {
    ...base,
    async exec(command: string, options?: ExecOptions): Promise<ExecResult> {
      const response =
        parameters.intercept?.(command, state) ??
        inspectionResponse(command) ??
        transactionResponse(command)
      if (response === undefined) return base.exec(command, options)
      observed(command, options)
      return { code: 0, stderr: "", stdout: "", ...response }
    },
  }
  return { connection, published: () => published, state }
}

export function respondWhen(
  matches: (command: string) => boolean,
  response: Partial<ExecResult>
): Interceptor {
  return (command) => {
    if (matches(command)) return response
  }
}

export function snapshotOnRead(
  round: number,
  patch: Partial<FileState>,
  replace = false
): Interceptor {
  let reads = 0
  return (command, state) => {
    if (!isInspection(command)) return
    reads += 1
    if (reads !== round) return
    if (replace) Object.assign(state, patch)
    return { stdout: encodedSnapshot({ ...state, ...patch }) }
  }
}
