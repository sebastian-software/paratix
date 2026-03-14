import type { ExecResult, SshConnection } from "../../src/types.js"

import { shellQuote } from "../../src/ssh.js"

const noop = async (): Promise<void> => {
  /* mock noop */
}

export function createMockSsh(
  responses?: Record<string, Partial<ExecResult>>
): { calls: string[] } & SshConnection {
  const calls: string[] = []
  return {
    addPort() {
      /* noop */
    },
    calls,
    disconnect() {
      /* noop */
    },
    downloadFile: noop,
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    async exec(command, _options) {
      calls.push(command)
      const match = responses?.[command] ?? { code: 0, stderr: "", stdout: "" }
      return { code: match.code ?? 0, stderr: match.stderr ?? "", stdout: match.stdout ?? "" }
    },
    async exists(path) {
      return this.test(`[ -e ${shellQuote(path)} ]`)
    },
    getConnectionInfo() {
      return { host: "1.2.3.4", port: 22, privateKeyPath: "~/.ssh/id", user: "root" }
    },
    async lines(command) {
      const out = await this.output(command)
      return out.length > 0 ? out.split("\n") : []
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    async output(command) {
      calls.push(command)
      return responses?.[command]?.stdout?.trim() ?? ""
    },
    probeSudo: noop,
    async readFile(path) {
      return this.output(`cat ${shellQuote(path)}`)
    },
    async sha256(path) {
      const exists = await this.test(`[ -f ${shellQuote(path)} ]`)
      if (!exists) return null
      return responses?.[`sha256sum ${shellQuote(path)}`]?.stdout?.split(/\s+/v)[0] ?? "abc123"
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Mock implementation
    async test(command) {
      calls.push(command)
      const match = responses?.[command]
      return match ? match.code === 0 : true
    },
    updateHost() {
      /* noop */
    },
    uploadFile: noop,
    writeFile: noop,
  }
}
