// Generates every key, CA and certificate of one integration run into a
// private temp directory. Nothing here is checked in; the runner removes
// the directory after the run.
import { randomBytes } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"

import { generateDsaKey } from "./dsa-key.mjs"
import { runTool } from "./tools.mjs"

const PRIVATE = 0o600
const PUBLIC = 0o644

/**
 * @typedef {object} Fixtures
 * @property {string} dir the fixture directory
 * @property {string} hostKey host key (ed25519) path
 * @property {string} hostKeyBase64 base64 of the host key blob, for the verifier
 * @property {string} userCaPublic user CA public key path (TrustedUserCAKeys)
 * @property {string} certKey key with `<certKey>-cert.pub`, never in authorized_keys
 * @property {string} bareCertKey copy of `certKey` without its certificate
 * @property {string} certPrincipal principal of the user certificate
 * @property {Record<"ed25519" | "p384" | "p521", string>} keys authorized key paths
 * @property {string} unauthorizedKey a valid key that is not authorized
 * @property {string} encryptedKey a passphrase-protected ed25519 key
 * @property {string} encryptedKeyPassphrase its passphrase
 * @property {string} dsaOpensshKey DSA key in openssh-key-v1 format
 * @property {string} dsaPkcs8Key DSA key as PKCS#8 PEM
 * @property {string} authorizedKeys the authorized_keys file
 */

/**
 * @param path private key path
 * @param args extra ssh-keygen arguments (type, size, passphrase)
 * @returns resolves once the key pair exists
 */
function keygen(path, args) {
  return runTool("ssh-keygen", ["-q", ...args, "-C", "ssh-native-it", "-f", path])
}

/**
 * @param path a `.pub` file
 * @returns the base64 blob (second field)
 */
export async function publicKeyBase64(path) {
  const line = await readFile(path, "utf8")
  const [, blob] = line.trim().split(/\s+/v)
  return blob
}

/**
 * @param dir fixture directory
 * @returns host key and user CA paths
 */
async function generateAuthorities(dir) {
  const hostKey = join(dir, "host_ed25519")
  const userCa = join(dir, "user_ca")
  await keygen(hostKey, ["-t", "ed25519", "-N", ""])
  await keygen(userCa, ["-t", "ed25519", "-N", ""])
  return { hostKey, userCa }
}

/**
 * H1: a key that is only usable through its user certificate.
 *
 * @param dir fixture directory
 * @param userCa CA private key path
 * @param principal the certificate principal (the target user)
 * @returns the certified key and a bare copy without certificate
 */
async function generateCertificateKey(dir, userCa, principal) {
  const certKey = join(dir, "cert_user_ed25519")
  await keygen(certKey, ["-t", "ed25519", "-N", ""])
  const identity = ["-I", "ssh-native-it-user", "-n", principal, "-V", "-5m:+1d"]
  await runTool("ssh-keygen", ["-q", "-s", userCa, ...identity, `${certKey}.pub`])
  // ssh-add loads `<key>-cert.pub` next to a key; the bare copy has none.
  await mkdir(join(dir, "bare"), { mode: 0o700 })
  const bareCertKey = join(dir, "bare", "cert_user_ed25519")
  await writeFile(bareCertKey, await readFile(certKey), { mode: PRIVATE })
  return { bareCertKey, certKey }
}

/**
 * @param dir fixture directory
 * @returns paths of the authorized and the other client keys
 */
async function generateClientKeys(dir) {
  const keys = {
    ed25519: join(dir, "key_ed25519"),
    p384: join(dir, "key_ecdsa_p384"),
    p521: join(dir, "key_ecdsa_p521"),
  }
  await keygen(keys.ed25519, ["-t", "ed25519", "-N", ""])
  await keygen(keys.p384, ["-t", "ecdsa", "-b", "384", "-N", ""])
  await keygen(keys.p521, ["-t", "ecdsa", "-b", "521", "-N", ""])
  const unauthorizedKey = join(dir, "key_unauthorized")
  await keygen(unauthorizedKey, ["-t", "ed25519", "-N", ""])
  const encryptedKey = join(dir, "key_encrypted")
  const encryptedKeyPassphrase = randomBytes(18).toString("base64url")
  await keygen(encryptedKey, ["-t", "ed25519", "-N", encryptedKeyPassphrase])
  return { encryptedKey, encryptedKeyPassphrase, keys, unauthorizedKey }
}

/**
 * @param dir fixture directory
 * @returns paths of the two DSA encodings
 */
async function writeDsaKeys(dir) {
  const dsa = generateDsaKey()
  const dsaOpensshKey = join(dir, "key_dsa_openssh")
  const dsaPkcs8Key = join(dir, "key_dsa_pkcs8")
  await writeFile(dsaOpensshKey, dsa.openssh, { mode: PRIVATE })
  await writeFile(dsaPkcs8Key, dsa.pkcs8, { mode: PRIVATE })
  return { dsaOpensshKey, dsaPkcs8Key }
}

/**
 * Generates the fixtures of one run.
 *
 * @param dir an empty private directory
 * @param principal the login user, written into the user certificate
 * @returns the fixture paths
 */
export async function generateFixtures(dir, principal) {
  const { hostKey, userCa } = await generateAuthorities(dir)
  const cert = await generateCertificateKey(dir, userCa, principal)
  const client = await generateClientKeys(dir)
  const dsa = await writeDsaKeys(dir)
  const authorizedKeys = join(dir, "authorized_keys")
  const lines = await Promise.all(
    Object.values(client.keys).map((path) => readFile(`${path}.pub`, "utf8"))
  )
  await writeFile(authorizedKeys, lines.join(""), { mode: PUBLIC })
  return {
    ...cert,
    ...client,
    ...dsa,
    authorizedKeys,
    certPrincipal: principal,
    dir,
    hostKey,
    hostKeyBase64: await publicKeyBase64(`${hostKey}.pub`),
    userCaPublic: `${userCa}.pub`,
  }
}
