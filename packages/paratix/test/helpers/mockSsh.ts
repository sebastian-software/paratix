import type { SshConnection } from "../../src/types.js"

import { shellQuote } from "../../src/ssh.js"
import {
  createExec,
  createOutput,
  createTest,
  type ExecCall,
  type MockCommandOptions,
  type MockResponses,
} from "./mockSshCommandResponses.js"
import {
  createRecordingSpies,
  createSideEffectRecorder,
  type DownloadFileCall,
  type SideEffectOptions,
  type UploadFileCall,
  type WriteFileCall,
} from "./mockSshSideEffects.js"

export type { ExecCall } from "./mockSshCommandResponses.js"

const DEFAULT_SSH_PORT = 22

type MockSshOptions = MockCommandOptions & SideEffectOptions

type MockSsh = {
  addPortCalls: number[]
  calls: string[]
  disconnectCalls: Array<Record<never, never>>
  downloadFileCalls: DownloadFileCall[]
  execCalls: ExecCall[]
  probeSudoCalls: Array<Record<never, never>>
  reconnectCalls: Array<Record<never, never>>
  removePortCalls: number[]
  updateHostCalls: string[]
  uploadFileCalls: UploadFileCall[]
  writeFileCalls: WriteFileCall[]
} & SshConnection

function getMockConnectionInfo(): ReturnType<SshConnection["getConnectionInfo"]> {
  return {
    authMethod: "privateKey",
    configuredPorts: [DEFAULT_SSH_PORT],
    host: "1.2.3.4",
    port: 22,
    privateKeyPath: "~/.ssh/id",
    user: "root",
    // R-0000714: production SSH sessions used by Paratix always have a
    // verified host trust anchor (`expectedHostFingerprint` /
    // `expectedHostPublicKey`). The default mock advertises one so modules
    // such as `rsync.sync` — which refuse to transfer without a trust
    // anchor — can exercise their normal flow. Tests that need to cover
    // the "no anchor" failure mode override `getConnectionInfo` to drop
    // `verifiedHostPublicKey`.
    verifiedHostPublicKey: "ssh-ed25519 AAAAMOCKVERIFIEDKEY",
  }
}

export function createMockSsh(responses?: MockResponses, options?: MockSshOptions): MockSsh {
  const calls: string[] = []
  const execCalls: ExecCall[] = []
  const exec = createExec({ calls, execCalls }, responses, options)
  const spies = createRecordingSpies(options)
  const sideEffects = createSideEffectRecorder(options)
  return {
    addPort: spies.addPort,
    addPortCalls: spies.addPortCalls,
    calls,
    disconnect: sideEffects.disconnect,
    disconnectCalls: sideEffects.disconnectCalls,
    downloadFile: sideEffects.downloadFile,
    downloadFileCalls: sideEffects.downloadFileCalls,
    exec,
    execCalls,
    async exists(path) {
      return this.test(`[ -e ${shellQuote(path)} ]`)
    },
    getConnectionInfo: getMockConnectionInfo,
    async lines(command) {
      const out = await this.output(command)
      return out.length > 0 ? out.split("\n") : []
    },
    output: createOutput(calls, responses, options),
    probeSudo: sideEffects.probeSudo,
    probeSudoCalls: sideEffects.probeSudoCalls,
    async readFile(path) {
      const result = await exec(`cat ${shellQuote(path)}`, { silent: true })
      return result.stdout
    },
    reconnect: sideEffects.reconnect,
    reconnectCalls: sideEffects.reconnectCalls,
    removePort: spies.removePort,
    removePortCalls: spies.removePortCalls,
    async sha256(path) {
      const exists = await this.test(`[ -f ${shellQuote(path)} ]`)
      if (!exists) return null
      const output = await this.output(`sha256sum ${shellQuote(path)}`)
      return output.split(/\s+/v)[0] ?? null
    },
    test: createTest(calls, responses, options),
    updateHost: spies.updateHost,
    updateHostCalls: spies.updateHostCalls,
    uploadFile: sideEffects.uploadFile,
    uploadFileCalls: sideEffects.uploadFileCalls,
    writeFile: sideEffects.writeFile,
    writeFileCalls: sideEffects.writeFileCalls,
  }
}

export function createStrictMockSsh(
  responses?: MockResponses,
  options?: Omit<MockSshOptions, "strict">
): MockSsh {
  return createMockSsh(responses, { ...options, strict: true })
}
