// THROWAWAY SPIKE (issue #254): agent forwarding proofs (H6).
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { join } from "node:path"
import { after, before } from "node:test"

import { native, pinnedVerifier, readFixture, run, setupTarget, startAgent } from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"
import {
  latestClient,
  openAgentChannel,
  openForwardedTcpip,
  openX11,
  startSsh2Server,
} from "./lib/ssh2-server.mjs"

let target
let agent
before(async () => {
  target = await setupTarget()
  agent = await startAgent(target.fixtureDir, ["key_ed25519_openssh"])
})
after(async () => {
  await agent?.stop()
  await target?.stop()
})

function fingerprint(file) {
  return execFileSync("ssh-keygen", ["-lf", file]).toString().split(" ")[1]
}

async function agentSession(agentForward) {
  return await native.connect(
    { host: target.host, port: target.port, user: target.user, agent: agent.socket, agentForward },
    pinnedVerifier(target.fixtureDir)
  )
}

proof(
  "H6-agent-forward-remote-ssh-add",
  "hard",
  "agentForward: true → remote `ssh-add -l` lists the forwarded key",
  async () => {
    const expected = fingerprint(join(target.fixtureDir, "key_ed25519_openssh.pub"))
    const session = await agentSession(true)
    try {
      const result = await run(session, 'echo "sock=${SSH_AUTH_SOCK}"; ssh-add -l')
      assert.equal(result.code, 0, `ssh-add -l failed: ${result.stderr}`)
      assert.match(result.stdout, /sock=\S+/)
      assert.ok(result.stdout.includes(expected), "remote agent must list the forwarded key")
      const stats = session.channelStats()
      assert.ok(stats.agentChannelsBridged >= 1)
      return {
        remoteOutput: result.stdout.trim(),
        expectedFingerprint: expected,
        channelStats: stats,
      }
    } finally {
      await session.close()
    }
  }
)

proof(
  "H6-no-agent-forward-by-default",
  "hard",
  "without agentForward no agent reaches the remote side",
  async () => {
    const probe = 'echo "sock=${SSH_AUTH_SOCK}"; ssh-add -l'
    // 1) AGENT login with agentForward: false. The agent is in use for auth,
    //    yet nothing may be forwarded.
    const agentLogin = await agentSession(false)
    let viaAgent
    try {
      assert.equal(
        agentLogin.authInfo.method,
        "agent",
        "this control must authenticate via the agent"
      )
      const result = await run(agentLogin, probe)
      assert.match(result.stdout, /^sock=$/m, "SSH_AUTH_SOCK must be empty remotely")
      assert.equal(result.code, 2, "ssh-add exits 2 when it cannot reach an agent")
      viaAgent = {
        authInfo: agentLogin.authInfo,
        remoteOutput: result.stdout.trim(),
        sshAddExit: result.code,
        channelStats: agentLogin.channelStats(),
      }
      assert.equal(viaAgent.channelStats.agentChannelsBridged, 0)
    } finally {
      await agentLogin.close()
    }
    // 2) Key-file login (agentForward defaults to false).
    const keyLogin = await native.connect(
      {
        host: target.host,
        port: target.port,
        user: target.user,
        privateKey: readFixture(target.fixtureDir, "key_ed25519_openssh"),
      },
      pinnedVerifier(target.fixtureDir)
    )
    try {
      const result = await run(keyLogin, probe)
      assert.match(result.stdout, /^sock=$/m)
      assert.equal(result.code, 2)
      return {
        agentLoginWithoutForward: viaAgent,
        keyFileLogin: { remoteOutput: result.stdout.trim(), sshAddExit: result.code },
      }
    } finally {
      await keyLogin.close()
    }
  }
)

proof(
  "H6-server-opened-agent-channel-rejected",
  "hard",
  "a server-initiated auth-agent@openssh.com channel is rejected without agentForward",
  async () => {
    const server = await startSsh2Server()
    const session = await native.connect(
      {
        host: "127.0.0.1",
        port: server.port,
        user: "spike",
        privateKey: Buffer.from(server.privateKey),
      },
      async (info) => info.keyBase64 === server.hostKeyBase64
    )
    try {
      const client = await latestClient(server)
      const agentChannel = await openAgentChannel(client)
      const tcpip = await openForwardedTcpip(client)
      const x11 = await openX11(client)
      assert.ok(agentChannel.error, "auth-agent channel must be rejected")
      assert.ok(tcpip.error, "forwarded-tcpip must be rejected")
      assert.ok(x11.error, "x11 must be rejected")
      const stats = session.channelStats()
      assert.deepEqual([...stats.rejected].sort(), [
        "auth-agent@openssh.com",
        "forwarded-tcpip",
        "x11",
      ])
      assert.equal(stats.agentChannelsBridged, 0)
      // The connection survives the rejections.
      const still = await run(session, "echo alive")
      assert.match(still.stdout, /alive/)
      return {
        agent: { message: agentChannel.error.message, reason: agentChannel.error.reason },
        forwardedTcpip: { message: tcpip.error.message, reason: tcpip.error.reason },
        x11: { message: x11.error.message, reason: x11.error.reason },
        channelStats: stats,
      }
    } finally {
      await session.close()
      await server.close()
    }
  }
)

proof(
  "H6-server-opened-agent-channel-bridged",
  "hard",
  "with agentForward the server-opened agent channel is bridged to the agent",
  async () => {
    const server = await startSsh2Server()
    const session = await native.connect(
      {
        host: "127.0.0.1",
        port: server.port,
        user: "spike",
        agent: agent.socket,
        agentForward: true,
      },
      async (info) => info.keyBase64 === server.hostKeyBase64
    )
    try {
      const client = await latestClient(server)
      const { error, stream } = await openAgentChannel(client)
      assert.ifError(error)
      // SSH_AGENTC_REQUEST_IDENTITIES (11) → expect SSH_AGENT_IDENTITIES_ANSWER (12).
      stream.write(Buffer.from([0, 0, 0, 1, 11]))
      const answer = await new Promise((resolve, reject) => {
        let buffer = Buffer.alloc(0)
        stream.on("data", (d) => {
          buffer = Buffer.concat([buffer, d])
          if (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) resolve(buffer)
        })
        stream.on("error", reject)
        setTimeout(() => reject(new Error("no agent answer")), 5000)
      })
      stream.end()
      assert.equal(answer[4], 12)
      const identities = answer.readUInt32BE(5)
      assert.equal(identities, 1)
      return { answerType: answer[4], identities, channelStats: session.channelStats() }
    } finally {
      await session.close()
      await server.close()
    }
  }
)
