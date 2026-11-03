/* oxlint-disable no-magic-numbers -- Fixed SSH protocol widths and explicit fixture time bounds form the independent wire-format oracle. */
import { execFile } from "node:child_process"
import { sign } from "node:crypto"
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"

import type { HostCertificateRequest } from "../../src/modules/sshHostCertificateTypes.js"

export const CERTIFICATE_NOW = 2_000_000_000
export const DAY = 86_400
export type FixtureKey = { path: string; publicKey: string }

export async function fixtureCommand(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { encoding: "utf8", timeout: 15_000 }, (error, stdout) => {
      if (error === null) resolve(stdout)
      else reject(new Error("Host certificate fixture command failed", { cause: error }))
    })
  })
}

// eslint-disable-next-line max-params -- Fixture key name, algorithm and optional key size mirror the OpenSSH generation inputs.
export async function fixtureKey(
  directory: string,
  name: string,
  algorithm: string,
  bits?: string
): Promise<FixtureKey> {
  const path = join(directory, name)
  await fixtureCommand("ssh-keygen", [
    "-q",
    "-t",
    algorithm,
    "-N",
    "",
    ...(algorithm === "rsa" ? ["-m", "PEM"] : []),
    ...(bits === undefined ? [] : ["-b", bits]),
    "-f",
    path,
  ])
  return { path, publicKey: await readFile(`${path}.pub`, "utf8") }
}

export function fixtureRequest(
  publicKey: string,
  overrides: Partial<HostCertificateRequest> = {}
): HostCertificateRequest {
  return {
    principals: ["192.0.2.1", "host.test"],
    publicKey,
    requestId: "unit-certificate-contract",
    signal: new AbortController().signal,
    validAfter: CERTIFICATE_NOW,
    validBefore: CERTIFICATE_NOW + 14 * DAY,
    version: 1,
    ...overrides,
  }
}

// Independent fixture formatter: do not reuse the production UTC conversion under test.
function utc(seconds: number): string {
  return `${new Date(seconds * 1000).toISOString().slice(0, 19).replaceAll(/\D/gv, "")}Z`
}

// eslint-disable-next-line max-params -- A certificate fixture may add explicit OpenSSH signing options for negative contract cases.
export async function fixtureCertificate(
  directory: string,
  ca: FixtureKey,
  request: HostCertificateRequest,
  extra: string[] = []
): Promise<string> {
  const key = join(directory, "fixture-subject.pub")
  await writeFile(key, request.publicKey, { mode: 0o600 })
  await fixtureCommand("ssh-keygen", [
    "-q",
    "-s",
    ca.path,
    "-I",
    request.requestId,
    "-h",
    "-n",
    request.principals.join(","),
    "-V",
    `${utc(request.validAfter)}:${utc(request.validBefore)}`,
    ...extra,
    key,
  ])
  return readFile(join(directory, "fixture-subject-cert.pub"), "utf8")
}

export function wireString(value: Buffer | string): Buffer {
  const bytes = Buffer.from(value)
  const length = Buffer.alloc(4)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

/**
 * Change Ed25519 certificate fields and re-sign with a real RSA CA.
 * @param certificate - Original OpenSSH host certificate.
 * @param ca - Existing RSA fixture signing key.
 * @param changes - Encoded replacement wire fields.
 * @param signatureAlgorithm - Signature format to exercise, including disallowed algorithms.
 * @returns A genuinely signed certificate carrying the selected fields.
 */
// eslint-disable-next-line max-params -- Negative wire fixtures require an independently selected signature algorithm.
export async function resignFixture(
  certificate: string,
  ca: FixtureKey,
  changes: Record<string, Buffer>,
  signatureAlgorithm = "rsa-sha2-512"
): Promise<string> {
  const [algorithm, encoded] = certificate.trim().split(/\s+/v)
  const wire = Buffer.from(encoded, "base64")
  const fields: Array<[string, Buffer]> = []
  let offset = 0
  for (const [name, width] of [
    ["algorithm", 0],
    ["nonce", 0],
    ["key", 0],
    ["serial", 8],
    ["type", 4],
    ["identity", 0],
    ["principals", 0],
    ["after", 8],
    ["before", 8],
    ["critical", 0],
    ["extensions", 0],
    ["reserved", 0],
    ["ca", 0],
  ] as const) {
    const length = width === 0 ? 4 + wire.readUInt32BE(offset) : width
    fields.push([name, wire.subarray(offset, offset + length)])
    offset += length
  }
  const data = Buffer.concat(fields.map(([name, bytes]) => changes[name] ?? bytes))
  const signature = sign(
    signatureAlgorithm === "ssh-rsa" ? "sha1" : "sha512",
    data,
    await readFile(ca.path)
  )
  const result = Buffer.concat([
    data,
    wireString(Buffer.concat([wireString(signatureAlgorithm), wireString(signature)])),
  ])
  return `${algorithm} ${result.toString("base64")} fixture-comment`
}
