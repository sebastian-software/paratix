// In-process ssh2 Server for the proofs that need a server OpenSSH cannot
// be made to act as: an SFTP subsystem that holds WRITE replies (H4
// backpressure) and server-opened channels (H6). No Docker, no sshd.
import { generateKeyPairSync } from "node:crypto"
import { once } from "node:events"
import { createRequire } from "node:module"
import { setTimeout as sleep } from "node:timers/promises"

import { verifyPublicKey } from "../../helpers/server.mjs"

const require = createRequire(import.meta.url)
const { Server, utils } = require("ssh2")
const { STATUS_CODE } = utils.sftp

const AGENT_WINDOW = 2 * 1024 * 1024
const AGENT_PACKET = 32 * 1024
const CLIENT_WAIT_MS = 5000
const POLL_MS = 10

/**
 * @typedef {object} SftpState
 * @property {boolean} stalled hold WRITE replies while set
 * @property {(() => void)[]} held held replies
 * @property {number} received WRITE bytes received
 * @property {number} outstanding WRITE requests without reply
 * @property {number} maxOutstanding the highest `outstanding` seen
 * @property {number[]} modes modes from OPEN attributes and FSETSTAT
 */

/**
 * @param sftp the ssh2 SFTP server stream
 * @param state counters (mutated)
 */
function serveSftp(sftp, state) {
  const sftpState = state
  sftp.on("OPEN", (...args) => {
    const [requestId] = args
    const attrs = args[3]
    if (attrs?.mode !== undefined) sftpState.modes.push(attrs.mode)
    sftp.handle(requestId, Buffer.from("h1"))
  })
  sftp.on("FSETSTAT", (...args) => {
    const [requestId, , attrs] = args
    if (attrs?.mode !== undefined) sftpState.modes.push(attrs.mode)
    sftp.status(requestId, STATUS_CODE.OK)
  })
  sftp.on("WRITE", (...args) => {
    const [requestId] = args
    const data = args[3]
    sftpState.received += data.length
    sftpState.outstanding += 1
    sftpState.maxOutstanding = Math.max(sftpState.maxOutstanding, sftpState.outstanding)
    const reply = () => {
      sftpState.outstanding -= 1
      sftp.status(requestId, STATUS_CODE.OK)
    }
    if (sftpState.stalled) sftpState.held.push(reply)
    else setImmediate(reply)
  })
  sftp.on("CLOSE", (/** @type {number} */ requestId) => sftp.status(requestId, STATUS_CODE.OK))
}

/**
 * Answers every exec with `ran: <command>` and exit code 0.
 *
 * @param acceptExec accepts the exec request
 * @param _reject unused
 * @param info the exec request
 */
function answerExec(acceptExec, _reject, info) {
  const stream = acceptExec()
  stream.on("error", () => {})
  stream.write(`ran: ${info.command}\n`)
  stream.exit(0)
  stream.end()
}

/**
 * @param client the ssh2 client connection
 * @param state SFTP counters
 */
function serveSessions(client, state) {
  client.on("session", (accept) => {
    const session = accept()
    session.on("exec", answerExec)
    session.on("sftp", (acceptSftp) => serveSftp(acceptSftp(), state))
  })
}

/**
 * @typedef {object} ChannelServer
 * @property {number} port listen port on 127.0.0.1
 * @property {string} hostKeyBase64 base64 of the host key blob
 * @property {SftpState} sftp SFTP counters and stall switch
 * @property {() => void} release replies to every held WRITE
 * @property {() => Promise<object>} client waits for the first client and returns it
 * @property {() => Promise<void>} close stops the server
 */

/**
 * Starts the server; publickey logins with one of `keys` (signature verified).
 *
 * @param keys PublicKeyInfo values of test/helpers/server.mjs
 * @returns the running server
 */
export async function startChannelServer(keys) {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  /** @type {SftpState} */
  const sftp = {
    held: [],
    maxOutstanding: 0,
    modes: [],
    outstanding: 0,
    received: 0,
    stalled: false,
  }
  const clients = []
  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    client.on("error", () => {})
    client.on("authentication", (context) => {
      if (context.method === "publickey" && verifyPublicKey(context, keys)) context.accept()
      else context.reject(["publickey"])
    })
    client.on("ready", () => {
      clients.push(client)
      serveSessions(client, sftp)
    })
  })
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  return {
    async client() {
      const deadline = Date.now() + CLIENT_WAIT_MS
      while (clients.length === 0) {
        if (Date.now() > deadline) throw new Error("no client became ready")
        // eslint-disable-next-line no-await-in-loop -- polling
        await sleep(POLL_MS)
      }
      return clients[0]
    },
    async close() {
      for (const client of clients) client.end()
      server.close()
      await once(server, "close")
    },
    hostKeyBase64: utils.parseKey(privateKey).getPublicSSH().toString("base64"),
    port: server.address().port,
    release() {
      for (const reply of sftp.held.splice(0)) reply()
    },
    sftp,
  }
}

/**
 * @typedef {object} OpenResult
 * @property {(Error & { reason?: number }) | undefined} error the refusal
 * @property {import("node:stream").Duplex} stream the channel, if accepted
 */

/**
 * Opens an `auth-agent@openssh.com` channel towards the client. ssh2's
 * public API has no method for it; its protocol layer does.
 *
 * @param client the ssh2 client connection
 * @returns the refusal or the channel
 */
export function openAgentChannel(client) {
  return new Promise((resolve) => {
    /**
     * @param error the refusal
     * @param stream the accepted channel
     * @returns nothing; settles the promise
     */
    const callback = (error, stream) => resolve({ error, stream })
    callback.type = "auth-agent@openssh.com"
    const localChannel = client._chanMgr.add(callback)
    client._protocol.openssh_authAgent(localChannel, AGENT_WINDOW, AGENT_PACKET)
  })
}

/**
 * @param client the ssh2 client connection
 * @returns the refusal or the channel of a `forwarded-tcpip` open
 */
export function openForwardedTcpip(client) {
  return new Promise((resolve) => {
    client.forwardOut("127.0.0.1", 9, "127.0.0.1", 40_000, (error, stream) =>
      resolve({ error, stream })
    )
  })
}

/**
 * @param client the ssh2 client connection
 * @returns the refusal or the channel of an `x11` open
 */
export function openX11(client) {
  return new Promise((resolve) => {
    client.x11("127.0.0.1", 40_001, (error, stream) => resolve({ error, stream }))
  })
}
