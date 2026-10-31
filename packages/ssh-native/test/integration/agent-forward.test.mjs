// H6 against the real sshd: with `agentForward: true` the remote `ssh-add -l`
// lists the forwarded key; without it, an agent login forwards nothing.
// The server-opened channel proofs of H6 run against an in-process ssh2
// server (in-process.test.mjs).
import assert from "node:assert/strict"
import { after, before, describe } from "node:test"

import { startAgent } from "./lib/agent.mjs"
import { descriptor, fixtures, hardProof } from "./lib/context.mjs"
import { connectWithAgent, fingerprint, run } from "./lib/remote.mjs"

// Prints the remote SSH_AUTH_SOCK, then asks the remote agent for its keys.
// eslint-disable-next-line no-template-curly-in-string -- a remote shell expansion
const PROBE = 'echo "sock=${SSH_AUTH_SOCK}"; ssh-add -l'
const NO_AGENT_EXIT = 2

describe("agent forwarding (sshd)", () => {
  /** @type {import("./lib/agent.mjs").Agent | undefined} */
  let agent

  before(async () => {
    if (descriptor.unavailable === null) agent = await startAgent([fixtures().keys.ed25519])
  })
  after(() => agent?.stop())

  /** @returns the agent socket */
  const socket = () => /** @type {import("./lib/agent.mjs").Agent} */ (agent).socket

  hardProof(
    {
      id: "H6-agent-forward-remote-ssh-add",
      name: "agentForward: true lets the remote ssh-add list the forwarded key",
    },
    async (t) => {
      const expected = fingerprint(`${fixtures().keys.ed25519}.pub`)
      const session = await connectWithAgent(socket(), { agentForward: true })
      try {
        assert.equal(session.authInfo.method, "agent")
        const result = await run(session, PROBE)
        t.diagnostic(result.stdout.trim())
        assert.equal(result.code, 0, `remote ssh-add -l failed: ${result.stderr}`)
        assert.match(result.stdout, /^sock=\S+$/mv)
        assert.ok(result.stdout.includes(expected), `remote agent lists ${expected}`)
        assert.equal(session.channelStats().agentChannelsBridged, 1)
      } finally {
        await session.close()
      }
    }
  )

  hardProof(
    {
      id: "H6-no-agent-forward-by-default",
      name: "an agent login with agentForward: false forwards nothing",
    },
    async () => {
      const session = await connectWithAgent(socket(), { agentForward: false })
      try {
        assert.equal(session.authInfo.method, "agent", "the control logs in through the agent")
        const result = await run(session, PROBE)
        assert.match(result.stdout, /^sock=$/mv, "SSH_AUTH_SOCK is empty remotely")
        assert.equal(result.code, NO_AGENT_EXIT, "ssh-add cannot reach an agent")
        assert.deepEqual(session.channelStats(), { agentChannelsBridged: 0, rejected: [] })
      } finally {
        await session.close()
      }
    }
  )
})
