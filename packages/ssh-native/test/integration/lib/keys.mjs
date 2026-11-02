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
const SSH_KEYGEN = "ssh-keygen"

/**
 * @typedef {object} Fixtures
 * @property {string} dir the fixture directory
 * @property {string} hostKey host key (ed25519) path
 * @property {string} hostKeyBase64 base64 of the host key blob, for the verifier
 * @property {string} userCaPublic user CA public key path (TrustedUserCAKeys)
 * @property {string} certKey key with `<certKey>-cert.pub`, never in authorized_keys
 * @property {string} bareCertKey copy of `certKey` without its certificate
 * @property {string} certPrincipal principal of the user certificate
 * @property {string} authorizedPrincipals server-approved certificate principals
 * @property {string} filePrincipal a permitted principal different from the login user
 * @property {Record<"rsa" | "p384" | "p521", string>} fileCertKeys certified private key paths
 * @property {Record<"expired" | "future" | "host" | "untrusted" | "wrongPrincipal", string>} invalidCertificates certificate paths
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
  return runTool(SSH_KEYGEN, ["-q", ...args, "-C", "ssh-native-it", "-f", path])
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
  await runTool(SSH_KEYGEN, ["-q", "-s", userCa, ...identity, `${certKey}.pub`])
  // ssh-add loads `<key>-cert.pub` next to a key; the bare copy has none.
  await mkdir(join(dir, "bare"), { mode: 0o700 })
  const bareCertKey = join(dir, "bare", "cert_user_ed25519")
  await writeFile(bareCertKey, await readFile(certKey), { mode: PRIVATE })
  return { bareCertKey, certKey }
}

/**
 * File credentials include RSA user and CA keys, ECDSA curves, a different
 * authorized principal and locally invalid material. Only the server decides
 * whether a well-formed certificate's CA and principal are authorized.
 *
 * @param dir fixture directory
 * @param userCa existing ed25519 CA private key
 * @param principal the login user
 * @returns the file certificate fixtures and combined CA trust file
 */
async function generateFileCertificates(dir, userCa, principal) {
  const rsaCa = join(dir, "user_ca_rsa")
  const untrustedCa = join(dir, "untrusted_ca")
  await keygen(rsaCa, ["-t", "rsa", "-b", "2048", "-N", ""])
  await keygen(untrustedCa, ["-t", "ed25519", "-N", ""])
  const filePrincipal = "ssh-native-authorized-principal"
  const authorizedPrincipals = join(dir, "authorized_principals")
  await writeFile(authorizedPrincipals, `${principal}\n${filePrincipal}\n`, { mode: PUBLIC })
  const userCaPublic = join(dir, "user_cas.pub")
  await writeFile(
    userCaPublic,
    (await readFile(`${userCa}.pub`, "utf8")) + (await readFile(`${rsaCa}.pub`, "utf8")),
    { mode: PUBLIC }
  )
  const fileCertKeys = await generateFileCertificateKeys(dir, { filePrincipal, rsaCa, userCa })
  const invalidCertificates = await generateInvalidCertificates(dir, {
    filePrincipal,
    keyPath: fileCertKeys.p384,
    untrustedCa,
    userCa,
  })
  return { authorizedPrincipals, fileCertKeys, filePrincipal, invalidCertificates, userCaPublic }
}

/**
 * @param dir fixture directory
 * @param options trusted authorities and approved principal
 * @returns the three private key paths, with certificates beside them
 */
async function generateFileCertificateKeys(dir, options) {
  const { filePrincipal, rsaCa, userCa } = options
  const fileCertKeys = {
    p384: join(dir, "cert_file_p384"),
    p521: join(dir, "cert_file_p521"),
    rsa: join(dir, "cert_file_rsa"),
  }
  await keygen(fileCertKeys.rsa, ["-t", "rsa", "-b", "2048", "-N", ""])
  await keygen(fileCertKeys.p384, ["-t", "ecdsa", "-b", "384", "-N", ""])
  await keygen(fileCertKeys.p521, ["-t", "ecdsa", "-b", "521", "-N", ""])
  for (const [kind, path] of Object.entries(fileCertKeys)) {
    // eslint-disable-next-line no-await-in-loop -- ssh-keygen writes each certificate beside its key
    await runTool(SSH_KEYGEN, [
      "-q",
      "-s",
      kind === "rsa" ? rsaCa : userCa,
      "-I",
      "ssh-native-it-file",
      "-n",
      filePrincipal,
      "-V",
      "-5m:+1d",
      `${path}.pub`,
    ])
  }
  return fileCertKeys
}

/**
 * @param dir fixture directory
 * @param options authorities, approved principal and matching private key
 * @returns paths for local failures and server rejection cases
 */
async function generateInvalidCertificates(dir, options) {
  const { filePrincipal, keyPath, untrustedCa, userCa } = options
  const invalidCertificates = {}
  for (const [name, ca, validity, certPrincipal, extra] of [
    ["expired", userCa, "-2d:-1d", filePrincipal, []],
    ["future", userCa, "+1d:+2d", filePrincipal, []],
    ["host", userCa, "-5m:+1d", filePrincipal, ["-h"]],
    ["untrusted", untrustedCa, "-5m:+1d", filePrincipal, []],
    ["wrongPrincipal", userCa, "-5m:+1d", "ssh-native-not-authorized", []],
  ]) {
    const path = join(dir, `cert_${name}`)
    // eslint-disable-next-line no-await-in-loop -- each public key gets its own output path
    await writeFile(`${path}.pub`, await readFile(`${keyPath}.pub`), { mode: PUBLIC })
    // eslint-disable-next-line no-await-in-loop -- ssh-keygen writes the next fixture
    await runTool(SSH_KEYGEN, [
      "-q",
      "-s",
      ca,
      "-I",
      "ssh-native-it-private-id",
      "-n",
      certPrincipal,
      "-V",
      validity,
      ...extra,
      `${path}.pub`,
    ])
    invalidCertificates[name] = `${path}-cert.pub`
  }
  return invalidCertificates
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
  const fileCertificates = await generateFileCertificates(dir, userCa, principal)
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
    ...fileCertificates,
    authorizedKeys,
    certPrincipal: principal,
    dir,
    hostKey,
    hostKeyBase64: await publicKeyBase64(`${hostKey}.pub`),
  }
}
