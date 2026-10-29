// THROWAWAY SPIKE (issue #254): in-process ssh2 Server, modelled on
// startTestSshServer in packages/paratix/test/postbuild/cli.dist.test.ts
// (RSA PKCS#1 host key, publickey auth), extended with an SFTP subsystem
// whose WRITE replies can be stalled, and helpers that open server-initiated
// channels (forwarded-tcpip, x11, auth-agent@openssh.com).
import { generateKeyPairSync } from "node:crypto"
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
const { Server, utils } = require("ssh2")

const SFTP_OK = 0

export async function startSsh2Server() {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  const hostPublic = utils.parseKey(privateKey)
  const state = {
    clients: [],
    sftp: { stalled: false, held: [], received: 0, outstanding: 0, maxOutstanding: 0, modes: [] },
  }
  const releaseHeld = () => {
    const held = state.sftp.held.splice(0)
    for (const reply of held) reply()
  }
  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    state.clients.push(client)
    client.on("error", () => {})
    client.on("authentication", (context) => {
      if (context.method === "publickey") context.accept()
      else context.reject()
    })
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept()
        session.on("exec", (acceptExec, _reject, info) => {
          const stream = acceptExec()
          stream.write(`ssh2-server ran: ${info.command}\n`)
          stream.exit(0)
          stream.end()
        })
        session.on("sftp", (acceptSftp) => {
          const sftp = acceptSftp()
          const s = state.sftp
          sftp.on("OPEN", (reqid, _filename, _flags, attrs) => {
            if (attrs && attrs.mode !== undefined) s.modes.push(attrs.mode)
            sftp.handle(reqid, Buffer.from("h1"))
          })
          sftp.on("FSETSTAT", (reqid, _handle, attrs) => {
            if (attrs && attrs.mode !== undefined) s.modes.push(attrs.mode)
            sftp.status(reqid, SFTP_OK)
          })
          sftp.on("WRITE", (reqid, _handle, _offset, data) => {
            s.received += data.length
            s.outstanding += 1
            s.maxOutstanding = Math.max(s.maxOutstanding, s.outstanding)
            const reply = () => {
              s.outstanding -= 1
              sftp.status(reqid, SFTP_OK)
            }
            if (s.stalled) s.held.push(reply)
            else setImmediate(reply)
          })
          sftp.on("CLOSE", (reqid) => sftp.status(reqid, SFTP_OK))
        })
      })
    })
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject)
      resolve()
    })
  })
  return {
    port: server.address().port,
    privateKey,
    hostKeyBase64: hostPublic.getPublicSSH().toString("base64"),
    state,
    releaseHeld,
    async close() {
      for (const client of state.clients) client.end()
      await new Promise((resolve) => server.close(() => resolve()))
    },
  }
}

/** Waits until the server saw `count` ready clients and returns the last one. */
export async function latestClient(server, count = 1) {
  const deadline = Date.now() + 5000
  while (server.state.clients.length < count) {
    if (Date.now() > deadline) throw new Error("ssh2 server saw no client")
    await new Promise((r) => setTimeout(r, 10))
  }
  return server.state.clients.at(-1)
}

/**
 * Opens an `auth-agent@openssh.com` channel towards the client. ssh2's public
 * `openChannel` does not support this type; Protocol#openssh_authAgent does.
 * Resolves `{ error }` (with `.reason`) on rejection or `{ stream }` on accept.
 */
export function openAgentChannel(client) {
  return new Promise((resolve) => {
    const callback = (error, stream) => resolve({ error, stream })
    callback.type = "auth-agent@openssh.com"
    const localChan = client._chanMgr.add(callback)
    if (localChan === -1) {
      resolve({ error: new Error("no free channels") })
      return
    }
    client._protocol.openssh_authAgent(localChan, 2 * 1024 * 1024, 32 * 1024)
  })
}

export function openForwardedTcpip(client) {
  return new Promise((resolve) => {
    client.forwardOut("127.0.0.1", 9, "127.0.0.1", 40000, (error, stream) =>
      resolve({ error, stream })
    )
  })
}

export function openX11(client) {
  return new Promise((resolve) => {
    client.x11("127.0.0.1", 40001, (error, stream) => resolve({ error, stream }))
  })
}
