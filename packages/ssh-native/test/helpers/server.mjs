// In-process ssh2 Server for the Node unit tests of the binding.
//
// RSA host key, publickey login (signature verified here) and password
// login, a small exec command table and an in-memory SFTP file system with
// failure injection. No Docker, no network beyond 127.0.0.1.
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto"
import { once } from "node:events"
import { createRequire } from "node:module"

const require = createRequire(import.meta.url)
const { Server, utils } = require("ssh2")
const { OPEN_MODE, STATUS_CODE } = utils.sftp

export const TEST_USER = "tester"
export const TEST_PASSWORD = "correct horse"
const WRITE_CHUNK = 32 * 1024
const PATTERN = Buffer.alloc(WRITE_CHUNK)
for (let index = 0; index < PATTERN.length; index += 1) PATTERN[index] = (index * 31 + 7) % 251

/**
 * @typedef {object} PublicKeyInfo
 * @property {import("node:crypto").KeyObject} key the Node public key
 * @property {string} algorithm SSH algorithm name
 * @property {Buffer} blob SSH public key blob
 * @property {string | null} hash signature hash (`null` for ed25519)
 */

/**
 * @typedef {object} RemoteFile
 * @property {Buffer} data content
 * @property {number} mode current mode
 * @property {number[]} modes every mode the client sent (open attrs and fchmod)
 */

/**
 * @param size bytes
 * @returns the deterministic test payload
 */
export function payload(size) {
  const chunks = []
  for (let offset = 0; offset < size; offset += WRITE_CHUNK) {
    chunks.push(PATTERN.subarray(0, Math.min(WRITE_CHUNK, size - offset)))
  }
  return Buffer.concat(chunks)
}

/**
 * @param buffer data
 * @returns hex SHA-256
 */
export function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex")
}

/**
 * @param buffer data
 * @returns the SSH wire string
 */
function sshString(buffer) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(buffer.length)
  return Buffer.concat([length, buffer])
}

/** @type {Record<string, { name: string, hash: string }>} */
const CURVES = {
  "P-256": { hash: "sha256", name: "nistp256" },
  "P-384": { hash: "sha384", name: "nistp384" },
  "P-521": { hash: "sha512", name: "nistp521" },
}

/**
 * @param key an ed25519 or ECDSA public key
 * @returns SSH blob and signature hash
 */
function describePublicKey(key) {
  const jwk = key.export({ format: "jwk" })
  if (jwk.kty === "OKP") {
    const raw = Buffer.from(String(jwk.x), "base64url")
    return {
      algorithm: "ssh-ed25519",
      blob: Buffer.concat([sshString(Buffer.from("ssh-ed25519")), sshString(raw)]),
      hash: null,
      key,
    }
  }
  const curve = CURVES[String(jwk.crv)]
  const point = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(String(jwk.x), "base64url"),
    Buffer.from(String(jwk.y), "base64url"),
  ])
  const algorithm = `ecdsa-sha2-${curve.name}`
  const blob = Buffer.concat([
    sshString(Buffer.from(algorithm)),
    sshString(Buffer.from(curve.name)),
    sshString(point),
  ])
  return { algorithm, blob, hash: curve.hash, key }
}

/**
 * A client key pair: `privateKey` is a PKCS#8 PEM string (which russh
 * parses), `publicKey` describes the key for the server.
 *
 * @param [type] `ed25519` (default) or `ec`
 * @param [options] curve for `ec`
 * @returns the PEM private key and the server-side description of the public key
 */
export function clientKey(type = "ed25519", options = {}) {
  const { privateKey, publicKey } = generateKeyPairSync(/** @type {"ec"} */ (type), {
    namedCurve: options.namedCurve ?? "P-256",
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  return { privateKey, publicKey: describePublicKey(createPublicKey(publicKey)) }
}

/** @returns an RSA PKCS#1 host key, as in packages/paratix/test/postbuild */
function hostKey() {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  })
  return privateKey
}

/**
 * Writes `size` bytes of `payload()` with backpressure; `done` runs once the
 * last chunk was handed to the connection (ssh2 drops still-buffered data
 * when the channel ends).
 *
 * @param writable stdout or stderr of a channel
 * @param size bytes to write
 * @param done called after the last chunk
 */
function pump(writable, size, done) {
  let offset = 0
  const step = () => {
    while (!writable.destroyed && offset < size) {
      const chunk = PATTERN.subarray(0, Math.min(WRITE_CHUNK, size - offset))
      offset += chunk.length
      const last = offset >= size
      const accepted = writable.write(chunk, last ? () => done() : undefined)
      if (!accepted && !last) {
        writable.once("drain", step)
        return
      }
    }
  }
  if (size === 0) done()
  else step()
}

/**
 * @param stream the server channel
 * @param code exit status
 */
function finish(stream, code) {
  stream.exit(code)
  stream.end()
}

/**
 * @param stream the server channel
 * @param done receives the complete stdin
 */
function readAll(stream, done) {
  /** @type {Buffer[]} */
  const chunks = []
  stream.on("data", (/** @type {Buffer} */ chunk) => chunks.push(chunk))
  stream.on("end", () => done(Buffer.concat(chunks)))
}

const COMMANDS = {
  drop(stream, _argument, client) {
    // Output, then the connection vanishes without CHANNEL_CLOSE.
    stream.write("before-drop\n", () => setTimeout(() => client._sock.destroy(), 50))
  },
  echoStdin(stream) {
    readAll(stream, (data) => {
      stream.write(data)
      finish(stream, 0)
    })
  },
  exit(stream, argument) {
    stream.write("out\n")
    stream.stderr.write("err\n")
    finish(stream, Number(argument))
  },
  floodThenDrop(stream, argument, client) {
    // stdout data, then the connection vanishes without CHANNEL_CLOSE.
    pump(stream, Number(argument), () => setTimeout(() => client._sock.destroy(), 50))
  },
  signal(stream, argument) {
    stream.write("terminated\n")
    stream.exit(argument, false, "")
    stream.end()
  },
  sleep() {
    // Stays open and silent.
  },
  status(stream, argument) {
    // Reports an exit status but never closes the channel.
    stream.write("status sent\n")
    stream.exit(Number(argument))
  },
  stderrFlood(stream, argument) {
    stream.write("stdout-before\n")
    pump(stream.stderr, Number(argument), () => {
      stream.write("stdout-after\n")
      finish(stream, 0)
    })
  },
  stdoutFlood(stream, argument) {
    pump(stream, Number(argument), () => finish(stream, 0))
  },
}

/**
 * @param command the exec request
 * @param stream the server channel
 * @param client the ssh2 client connection
 */
function runCommand(command, stream, client) {
  const [name, argument = ""] = command.split(" ")
  // `stdout-flood` runs COMMANDS.stdoutFlood.
  const handler =
    COMMANDS[name.replaceAll(/-(?<letter>[a-z])/gv, (_match, letter) => letter.toUpperCase())]
  if (handler) {
    handler(stream, argument, client)
    return
  }
  stream.stderr.write(`unknown command: ${command}\n`)
  finish(stream, 127)
}

/**
 * @param files the file system
 * @param filename path to open for writing
 * @param attrs open attributes
 */
function createForWriting(files, filename, attrs) {
  const existing = files.get(filename)
  const sent = attrs?.mode === undefined ? [] : [attrs.mode]
  files.set(filename, {
    data: Buffer.alloc(0),
    mode: existing?.mode ?? attrs?.mode ?? 0o644,
    modes: [...(existing?.modes ?? []), ...sent],
  })
}

/**
 * @param file target file (mutated)
 * @param offset byte position in the file
 * @param data bytes to place at `offset`
 */
function writeAt(file, offset, data) {
  const end = offset + data.length
  const target = file
  if (target.data.length < end) {
    const grown = Buffer.alloc(end)
    target.data.copy(grown)
    target.data = grown
  }
  data.copy(target.data, offset)
}

/**
 * Serves SFTP from `files`. Paths starting with `/denied` refuse OPEN,
 * `/write-fails` refuses every WRITE, `/close-fails` refuses CLOSE.
 *
 * @param sftp the ssh2 SFTP server stream
 * @param files the file system
 */
function handleSftp(sftp, files) {
  /** @type {Map<string, string>} */
  const handles = new Map()
  let nextHandle = 0
  const fileOf = (handle) => handles.get(String(handle)) ?? ""
  sftp.on("OPEN", (...args) => {
    const [requestId, filename, flags, attrs] = args
    if (filename.startsWith("/denied")) return sftp.status(requestId, STATUS_CODE.PERMISSION_DENIED)
    const writing = (flags & OPEN_MODE.WRITE) !== 0
    if (!writing && !files.has(filename)) return sftp.status(requestId, STATUS_CODE.NO_SUCH_FILE)
    if (writing) createForWriting(files, filename, attrs)
    nextHandle += 1
    handles.set(String(nextHandle), filename)
    return sftp.handle(requestId, Buffer.from(String(nextHandle)))
  })
  sftp.on("FSETSTAT", (...args) => {
    const [requestId, handle, attrs] = args
    const file = files.get(fileOf(handle))
    if (!file) return sftp.status(requestId, STATUS_CODE.FAILURE)
    if (attrs?.mode !== undefined) {
      file.mode = attrs.mode
      file.modes.push(attrs.mode)
    }
    return sftp.status(requestId, STATUS_CODE.OK)
  })
  sftp.on("WRITE", (...args) => {
    const [requestId, handle, offset, data] = args
    const filename = fileOf(handle)
    if (filename.startsWith("/write-fails")) return sftp.status(requestId, STATUS_CODE.FAILURE)
    writeAt(/** @type {RemoteFile} */ (files.get(filename)), offset, data)
    return sftp.status(requestId, STATUS_CODE.OK)
  })
  sftp.on("READ", (...args) => {
    const [requestId, handle, offset, length] = args
    const file = files.get(fileOf(handle))
    if (!file || offset >= file.data.length) return sftp.status(requestId, STATUS_CODE.EOF)
    return sftp.data(
      requestId,
      file.data.subarray(offset, Math.min(file.data.length, offset + length))
    )
  })
  sftp.on("CLOSE", (...args) => {
    const [requestId, handle] = args
    const filename = fileOf(handle)
    handles.delete(String(handle))
    const refused = filename.startsWith("/close-fails")
    return sftp.status(requestId, refused ? STATUS_CODE.PERMISSION_DENIED : STATUS_CODE.OK)
  })
}

/**
 * @param context ssh2 publickey authentication context
 * @param allowedKeys keys allowed to log in
 * @returns whether the key is allowed (and the signature valid)
 */
function verifyPublicKey(context, allowedKeys) {
  const matching = allowedKeys.find(
    (allowed) => allowed.algorithm === context.key.algo && allowed.blob.equals(context.key.data)
  )
  if (!matching) return false
  if (!context.signature) return true
  return verify(matching.hash, context.blob, matching.key, context.signature)
}

/**
 * @param context ssh2 authentication context
 * @param keys keys allowed to log in
 * @returns whether to accept
 */
function accepts(context, keys) {
  if (context.username !== TEST_USER) return false
  if (context.method === "publickey") return verifyPublicKey(context, keys)
  return context.method === "password" && context.password === TEST_PASSWORD
}

/**
 * @typedef {object} ServerStats
 * @property {number} connections TCP connections accepted
 * @property {number} authAttempts authentication requests seen
 * @property {number} stdoutSent channel data bytes handed to the connection
 */

/**
 * Counts the stdout bytes the server hands to the connection.
 *
 * @param client the ssh2 client connection
 * @param stats counters (mutated)
 */
function countStdout(client, stats) {
  const counters = stats
  const protocol = client._protocol
  const channelData = protocol.channelData.bind(protocol)
  /**
   * @param id channel id
   * @param data channel data
   * @returns what ssh2 returns
   */
  protocol.channelData = (id, data) => {
    counters.stdoutSent += data.length
    return channelData(id, data)
  }
}

/**
 * @typedef {object} TestServer
 * @property {string} host listen address
 * @property {number} port listen port
 * @property {Map<string, RemoteFile>} files the SFTP file system
 * @property {ServerStats} stats counters
 * @property {string} hostKeyBase64 base64 of the host key blob
 * @property {() => Promise<void>} close stops the server
 * @property {{ refuseSftp: boolean }} behaviour switches read on each request
 */

/**
 * Starts the server.
 *
 * @param [options] public keys allowed to log in as TEST_USER
 * @returns the running server
 */
export async function startServer(options = {}) {
  const { keys = [] } = options
  /** @type {Map<string, RemoteFile>} */
  const files = new Map()
  const hostPrivateKey = hostKey()
  const behaviour = { refuseSftp: false }
  /** @type {ServerStats} */
  const stats = { authAttempts: 0, connections: 0, stdoutSent: 0 }
  const clients = []
  const onSession = (client, accept) => {
    const session = accept()
    session.on("exec", (...args) => {
      const [acceptExec, , info] = args
      const stream = acceptExec()
      stream.on("error", () => {})
      runCommand(info.command, stream, client)
    })
    session.on("sftp", (acceptSftp, rejectSftp) => {
      if (behaviour.refuseSftp) rejectSftp()
      else handleSftp(acceptSftp(), files)
    })
  }
  const server = new Server({ hostKeys: [hostPrivateKey] }, (client) => {
    stats.connections += 1
    clients.push(client)
    client.on("error", () => {})
    client.on("authentication", (context) => {
      stats.authAttempts += 1
      if (accepts(context, keys)) context.accept()
      else context.reject(["publickey", "password"])
    })
    client.on("ready", () => {
      countStdout(client, stats)
      client.on("session", (accept) => onSession(client, accept))
    })
  })
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  return {
    behaviour,
    async close() {
      for (const client of clients) client.end()
      server.close()
      await once(server, "close")
    },
    files,
    host: "127.0.0.1",
    hostKeyBase64: utils.parseKey(hostPrivateKey).getPublicSSH().toString("base64"),
    port: server.address().port,
    stats,
  }
}
