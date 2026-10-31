// Hard proofs against an in-process ssh2 server (lib/ssh2-server.mjs);
// they need neither Docker nor sshd and run with both targets:
// - H4 backpressure: while the server holds WRITE replies, the binding
//   accepts at most 1 MiB and keeps at most 16 writes outstanding; after the
//   release all 32 MiB arrive and the mode was sent.
// - H6: server-opened channels are refused (reason 1, administratively
//   prohibited) and the connection stays usable; with `agentForward: true`
//   the agent channel is bridged to a real ssh-agent.
import assert from "node:assert/strict"
import { randomBytes } from "node:crypto"
import { once } from "node:events"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { finished } from "node:stream/promises"
import { describe } from "node:test"
import { setTimeout as sleep } from "node:timers/promises"

import { binding, collect } from "../helpers/binding.mjs"
import { clientKey } from "../helpers/server.mjs"
import { startAgent } from "./lib/agent.mjs"
import { descriptor, hardProof } from "./lib/context.mjs"
import {
  openAgentChannel,
  openForwardedTcpip,
  openX11,
  startChannelServer,
} from "./lib/ssh2-server.mjs"

const MIB = 1024 * 1024
const CHUNK = 64 * 1024
const IN_FLIGHT_BOUND = MIB
const MAX_OUTSTANDING_WRITES = 16
const ADMINISTRATIVELY_PROHIBITED = 1
const SSH_AGENTC_REQUEST_IDENTITIES = 11
const SSH_AGENT_IDENTITIES_ANSWER = 12
const STALL_MS = 1500

/**
 * @param server the channel server
 * @param options credentials and agent forwarding
 * @returns the session
 */
function connectTo(server, options) {
  return binding.connect(
    { host: "127.0.0.1", port: server.port, user: "tester", ...options },
    (info) => info.keyBase64 === server.hostKeyBase64
  )
}

/**
 * Writes `data` with backpressure; `progress.produced` counts bytes handed
 * to `write()`.
 *
 * @param stream the SFTP write stream
 * @param data content
 * @param progress counters (mutated)
 * @returns resolves once the stream finished
 */
async function pump(stream, data, progress) {
  const counters = progress
  while (counters.produced < data.length) {
    const chunk = data.subarray(counters.produced, counters.produced + CHUNK)
    counters.produced += chunk.length
    // eslint-disable-next-line no-await-in-loop -- backpressure: wait for drain
    if (!stream.write(chunk)) await once(stream, "drain")
  }
  stream.end()
  await finished(stream)
}

/**
 * @param stream the bridged agent channel
 * @returns the first complete agent message
 */
function readAgentMessage(stream) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)
    stream.on("data", (/** @type {Buffer} */ data) => {
      buffer = Buffer.concat([buffer, data])
      if (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) resolve(buffer)
    })
    stream.on("error", reject)
    setTimeout(() => reject(new Error("no answer from the agent")), 5000).unref()
  })
}

describe("in-process ssh2 server", () => {
  hardProof(
    {
      id: "H4-sftp-bounded-in-flight",
      name: "SFTP writes stay bounded while the server holds WRITE replies",
      needs: [],
    },
    async (t) => {
      const key = clientKey()
      const server = await startChannelServer([key.publicKey])
      const session = await connectTo(server, { privateKey: Buffer.from(key.privateKey) })
      try {
        const sftp = await session.sftp()
        const data = randomBytes(32 * MIB)
        const stream = sftp.createWriteStream("/stall.bin", { mode: 0o600 })
        server.sftp.stalled = true
        const progress = { produced: 0 }
        const pumping = pump(stream, data, progress)
        await sleep(STALL_MS)
        const accepted = progress.produced - stream.writableLength
        const snapshot = {
          accepted,
          maxOutstanding: server.sftp.maxOutstanding,
          outstanding: server.sftp.outstanding,
          produced: progress.produced,
          serverReceived: server.sftp.received,
        }
        t.diagnostic(`after ${STALL_MS} ms stalled: ${JSON.stringify(snapshot)}`)
        assert.ok(progress.produced < data.length, "the producer is blocked")
        assert.ok(accepted <= IN_FLIGHT_BOUND, `${accepted} bytes in flight`)
        assert.ok(snapshot.outstanding <= MAX_OUTSTANDING_WRITES)
        assert.ok(snapshot.outstanding > 0, "writes are waiting for replies")
        server.sftp.stalled = false
        server.release()
        await pumping
        assert.equal(server.sftp.received, data.length)
        assert.ok(server.sftp.maxOutstanding <= MAX_OUTSTANDING_WRITES)
        assert.deepEqual(server.sftp.modes, [0o600, 0o600], "mode on open and through fchmod")
        await sftp.end()
      } finally {
        session.destroy()
        await server.close()
      }
    }
  )

  hardProof(
    {
      id: "H6-server-opened-channels-rejected",
      name: "server-opened agent, forwarded-tcpip and x11 channels are refused",
      needs: [],
    },
    async () => {
      const key = clientKey()
      const server = await startChannelServer([key.publicKey])
      const session = await connectTo(server, { privateKey: Buffer.from(key.privateKey) })
      try {
        const client = await server.client()
        const opened = [
          await openAgentChannel(client),
          await openForwardedTcpip(client),
          await openX11(client),
        ]
        for (const { error } of opened) {
          assert.ok(error, "the channel is refused")
          assert.equal(error.reason, ADMINISTRATIVELY_PROHIBITED)
        }
        const stats = session.channelStats()
        assert.deepEqual([...stats.rejected].sort(), [
          "auth-agent@openssh.com",
          "forwarded-tcpip",
          "x11",
        ])
        assert.equal(stats.agentChannelsBridged, 0)
        const channel = await session.exec("echo alive")
        const [stdout, exit] = await Promise.all([collect(channel.stdout), channel.exit])
        assert.equal(stdout.toString(), "ran: echo alive\n")
        assert.equal(exit.code, 0)
      } finally {
        session.destroy()
        await server.close()
      }
    }
  )

  hardProof(
    {
      id: "H6-server-opened-agent-channel-bridged",
      name: "with agentForward: true the agent channel is bridged to the agent",
      needs: ["agent"],
    },
    async () => {
      const key = clientKey("ec")
      const dir = mkdtempSync(join(descriptor.runDir || tmpdir(), "k-"))
      const keyPath = join(dir, "agent_key")
      writeFileSync(keyPath, key.privateKey, { mode: 0o600 })
      const agent = await startAgent([keyPath])
      const server = await startChannelServer([key.publicKey])
      try {
        assert.equal(agent.added[keyPath], "added")
        const session = await connectTo(server, { agent: agent.socket, agentForward: true })
        try {
          const { error, stream } = await openAgentChannel(await server.client())
          assert.ifError(error)
          const answer = readAgentMessage(stream)
          stream.write(Buffer.from([0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES]))
          const message = await answer
          stream.end()
          assert.equal(message[4], SSH_AGENT_IDENTITIES_ANSWER)
          assert.equal(message.readUInt32BE(5), 1, "one identity")
          assert.equal(session.channelStats().agentChannelsBridged, 1)
        } finally {
          session.destroy()
        }
      } finally {
        await server.close()
        await agent.stop()
        rmSync(dir, { force: true, recursive: true })
      }
    }
  )
})
