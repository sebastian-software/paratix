// THROWAWAY SPIKE (issue #254): authentication proofs (H1, other, soft matrix).
import assert from "node:assert/strict"
import { copyFileSync, mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after, before } from "node:test"

import {
  native,
  pinnedVerifier,
  publicKeyBase64,
  readFixture,
  run,
  setupTarget,
  startAgent,
  TARGET,
} from "./lib/env.mjs"
import { proof, SkipProof } from "./lib/results.mjs"

let target
before(async () => {
  target = await setupTarget()
})
after(async () => {
  await target?.stop()
})

async function agentConnect(socket, extra = {}) {
  return await native.connect(
    { host: target.host, port: target.port, user: target.user, agent: socket, ...extra },
    pinnedVerifier(target.fixtureDir)
  )
}

proof(
  "H1-agent-user-certificate",
  "hard",
  "agent login with key + user certificate (CA-only trust)",
  async () => {
    const certKey = publicKeyBase64(target.fixtureDir, "cert_user_ed25519.pub")
    const authorized = readFileSync(join(target.fixtureDir, "authorized_keys"), "utf8")
    assert.ok(!authorized.includes(certKey), "the certificate key must not be in authorized_keys")

    // Negative control: the bare key without its certificate must be refused.
    const bareDir = mkdtempSync(join(tmpdir(), "paratix-spike-bare-"))
    copyFileSync(join(target.fixtureDir, "cert_user_ed25519"), join(bareDir, "cert_user_ed25519"))
    const bareKeyPath = join(bareDir, "cert_user_ed25519")
    const bareAgent = await startAgent(target.fixtureDir, [bareKeyPath])
    const bareListing = bareAgent.listing.trim().split("\n").filter(Boolean)
    try {
      // The control is only meaningful if the agent really holds the bare key
      // (and only that): otherwise an empty agent would also fail.
      assert.equal(bareAgent.added[bareKeyPath], "added", "bare key must be added to the agent")
      assert.equal(bareListing.length, 1, "agent must hold exactly one identity")
      assert.equal(bareListing[0].split(" ")[1], certKey, "agent identity must be the bare key")
      assert.ok(!bareAgent.listing.includes("cert-v01"), "agent must not hold the certificate")
    } catch (error) {
      await bareAgent.stop()
      throw error
    }
    let bareError
    try {
      const s = await agentConnect(bareAgent.socket)
      s.destroy()
    } catch (error) {
      bareError = error
    } finally {
      await bareAgent.stop()
    }
    assert.equal(bareError?.code, "AUTH_FAILED", "bare certificate key must not authenticate")
    // AUTH_FAILED from the server, not from the agent side (agent-unavailable,
    // agent-protocol, agent-empty carry an `agent-*` detail).
    assert.ok(
      !String(bareError.detail ?? "").startsWith("agent-"),
      `unexpected agent error: ${bareError.detail}`
    )

    const agent = await startAgent(target.fixtureDir, ["cert_user_ed25519"])
    try {
      assert.match(agent.listing, /cert-v01@openssh\.com/, "agent must hold the certificate")
      const session = await agentConnect(agent.socket)
      try {
        assert.equal(session.authInfo.method, "agent")
        assert.equal(session.authInfo.identityKind, "certificate")
        const whoami = await run(session, "id -un")
        assert.equal(whoami.code, 0)
        return {
          authInfo: session.authInfo,
          remoteUser: whoami.stdout.trim(),
          agentIdentities: agent.listing
            .trim()
            .split("\n")
            .map((l) => l.split(" ")[0]),
          negativeControl: {
            bareKeyAdded: bareAgent.added[bareKeyPath],
            bareAgentIdentities: bareListing.map((l) => l.split(" ")[0]),
            code: bareError.code,
            detail: bareError.detail ?? null,
            message: bareError.message,
          },
        }
      } finally {
        await session.close()
      }
    } finally {
      await agent.stop()
    }
  }
)

proof("O-agent-key-without-certificate", "other", "agent login with a plain key", async () => {
  const agent = await startAgent(target.fixtureDir, ["key_ed25519_openssh"])
  try {
    const session = await agentConnect(agent.socket)
    try {
      assert.equal(session.authInfo.identityKind, "key")
      assert.equal((await run(session, "true")).code, 0)
      return { authInfo: session.authInfo }
    } finally {
      await session.close()
    }
  } finally {
    await agent.stop()
  }
})

proof(
  "O-key-file-login",
  "other",
  "key file login; JS key buffer is zeroed after handover",
  async () => {
    const key = readFixture(target.fixtureDir, "key_ed25519_openssh")
    const session = await native.connect(
      { host: target.host, port: target.port, user: target.user, privateKey: key },
      pinnedVerifier(target.fixtureDir)
    )
    try {
      assert.ok(
        key.every((b) => b === 0),
        "key buffer must be zero-filled"
      )
      assert.equal(session.authInfo.method, "publickey")
      return { authInfo: session.authInfo, jsBufferZeroed: true }
    } finally {
      await session.close()
    }
  }
)

proof("O-password-login", "other", "password authentication", async () => {
  if (!target.passwordPort)
    throw new SkipProof("non-root local sshd cannot do password auth (no PAM); Docker only")
  const session = await native.connect(
    { host: target.host, port: target.passwordPort, user: target.user, password: target.password },
    pinnedVerifier(target.fixtureDir)
  )
  try {
    assert.equal(session.authInfo.method, "password")
    return { authInfo: session.authInfo }
  } finally {
    await session.close()
  }
})

proof("O-keyboard-interactive-login", "other", "keyboard-interactive authentication", async () => {
  if (!target.kbdintPort)
    throw new SkipProof("non-root local sshd cannot do keyboard-interactive (no PAM); Docker only")
  const session = await native.connect(
    { host: target.host, port: target.kbdintPort, user: target.user, password: target.password },
    pinnedVerifier(target.fixtureDir)
  )
  try {
    assert.equal(session.authInfo.method, "keyboard-interactive")
    return { authInfo: session.authInfo }
  } finally {
    await session.close()
  }
})

proof("O-wrong-password", "other", "wrong password yields AUTH_FAILED", async () => {
  if (!target.passwordPort) throw new SkipProof("needs a PAM-enabled sshd; Docker only")
  await assert.rejects(
    native.connect(
      { host: target.host, port: target.port, user: target.user, password: "definitely-wrong" },
      pinnedVerifier(target.fixtureDir)
    ),
    (error) => error.code === "AUTH_FAILED"
  )
  return { code: "AUTH_FAILED" }
})

proof(
  "O-error-codes-auth",
  "other",
  "AUTH_FAILED, ENCRYPTED_KEY, UNSUPPORTED_KEY, CONNECT_FAILED",
  async () => {
    const base = { host: target.host, port: target.port, user: target.user }
    const verifier = pinnedVerifier(target.fixtureDir)
    const codes = {}
    const capture = async (name, options) => {
      try {
        const s = await native.connect({ ...base, ...options }, verifier)
        s.destroy()
        codes[name] = "connected"
      } catch (error) {
        codes[name] = { code: error.code, message: error.message, syscallCode: error.syscallCode }
      }
    }
    await capture("unauthorizedKey", {
      privateKey: readFixture(target.fixtureDir, "key_unauthorized"),
    })
    await capture("encryptedKey", {
      privateKey: readFixture(target.fixtureDir, "key_ed25519_encrypted"),
    })
    await capture("garbageKey", { privateKey: Buffer.from("not a key at all") })
    await capture("closedPort", {
      port: 1,
      privateKey: readFixture(target.fixtureDir, "key_ed25519_openssh"),
    })
    assert.equal(codes.unauthorizedKey.code, "AUTH_FAILED")
    assert.equal(codes.encryptedKey.code, "ENCRYPTED_KEY")
    assert.equal(codes.garbageKey.code, "UNSUPPORTED_KEY")
    assert.equal(codes.closedPort.code, "CONNECT_FAILED")
    assert.equal(codes.closedPort.syscallCode, "ECONNREFUSED")
    for (const entry of Object.values(codes))
      assert.ok(!/spike-passphrase|PRIVATE KEY/.test(entry.message))
    return codes
  }
)

// Soft criterion: key-format matrix, each from file and from agent.
const manifest = JSON.parse(
  readFileSync(
    join(
      process.env.SPIKE_FIXTURE_DIR ?? (await import("./lib/env.mjs")).ensureFixtures(),
      "manifest.json"
    ),
    "utf8"
  )
)
for (const entry of manifest.matrix) {
  proof(`S-format-${entry.id}-file`, "soft", `key format ${entry.id} from file`, async () => {
    let key
    try {
      key = readFixture(target.fixtureDir, entry.file)
    } catch {
      throw new SkipProof(`fixture ${entry.file} not generated (tool missing)`)
    }
    const session = await native.connect(
      { host: target.host, port: target.port, user: target.user, privateKey: key },
      pinnedVerifier(target.fixtureDir)
    )
    try {
      return {
        authInfo: session.authInfo,
        header: readFixture(target.fixtureDir, entry.file).toString().split("\n")[0],
      }
    } finally {
      await session.close()
    }
  })
  proof(`S-format-${entry.id}-agent`, "soft", `key format ${entry.id} from agent`, async () => {
    const agent = await startAgent(target.fixtureDir, [entry.file])
    try {
      if (agent.added[entry.file] !== "added")
        throw new SkipProof(`ssh-add rejected the format: ${agent.added[entry.file]}`)
      const session = await agentConnect(agent.socket)
      try {
        return { authInfo: session.authInfo }
      } finally {
        await session.close()
      }
    } finally {
      await agent.stop()
    }
  })
}

void TARGET
