import { readdirSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { basename, join, resolve } from "node:path"

import type { SelectFunction, SelectOption } from "./promptUi.js"

import { hasValidOpenSshPublicKeyWireBlob } from "./openSshPublicKeyWire.js"

export type LocalPublicKey = {
  key: string
  label: string
  path: string
}

type ExitWithMessage = (message: string) => never

type PublicKeyChoice = "local" | "placeholder"
type ParsedPublicKey = { algorithm: string; encodedKey: string }

const PUBLIC_KEY_PROMPT_OPTIONS: Array<SelectOption<PublicKeyChoice>> = [
  {
    description:
      "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
    label: "Use local public key",
    value: "local",
  },
  {
    description:
      "Keep the placeholder in server.ts and paste your public key manually before the first apply.",
    label: "Keep placeholder",
    value: "placeholder",
  },
]

const supportedOpenSshAlgorithms = new Set([
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ecdsa-sha2-nistp256@openssh.com",
  "sk-ssh-ed25519@openssh.com",
  "ssh-ed25519",
  "ssh-rsa",
])

// PEM/OpenSSH markers that unambiguously identify private keys. The check is
// case-sensitive because real PEM headers are always upper-case; relaxing to
// case-insensitive would only enable bypasses without catching additional
// legitimate inputs. R-0000126 requires validateAdminPublicKey to fail hard
// when any of these markers appears in the value, so a leaked private key
// cannot be embedded into server.ts even if parseOpenSshPublicKey would
// otherwise accept the first line.
const PRIVATE_KEY_MARKERS = [
  "BEGIN OPENSSH PRIVATE KEY",
  "BEGIN RSA PRIVATE KEY",
  "BEGIN DSA PRIVATE KEY",
  "BEGIN EC PRIVATE KEY",
  "BEGIN PRIVATE KEY",
  "BEGIN ENCRYPTED PRIVATE KEY",
]

function containsPrivateKeyMarker(value: string): boolean {
  return PRIVATE_KEY_MARKERS.some((marker) => value.includes(marker))
}

function parseOpenSshPublicKey(value: string): null | ParsedPublicKey {
  if (value.length === 0 || /[\r\n]/v.test(value)) {
    return null
  }

  const parts = value.split(/\s+/v)
  if (parts.length < 2) {
    return null
  }

  const algorithm = parts[0]
  const encodedKey = parts[1]

  if (!supportedOpenSshAlgorithms.has(algorithm)) {
    return null
  }

  return {
    algorithm,
    encodedKey,
  }
}

function trimBase64Padding(value: string): string {
  let endIndex = value.length
  while (endIndex > 0 && value[endIndex - 1] === "=") {
    endIndex--
  }
  return value.slice(0, endIndex)
}

function isBase64AlphaNumeric(character: string): boolean {
  return (
    (character >= "A" && character <= "Z") ||
    (character >= "a" && character <= "z") ||
    (character >= "0" && character <= "9")
  )
}

function isBase64DataCharacter(character: string): boolean {
  return isBase64AlphaNumeric(character) || character === "+" || character === "/"
}

function updatePaddingState(
  character: string,
  state: { paddingCount: number; sawPadding: boolean }
): { paddingCount: number; sawPadding: boolean } | null {
  if (character !== "=") {
    return null
  }

  const nextState = {
    paddingCount: state.paddingCount + 1,
    sawPadding: true,
  }

  return nextState.paddingCount <= 2 ? nextState : null
}

function hasValidBase64Alphabet(value: string): boolean {
  if (value.length === 0) {
    return false
  }

  const state = { paddingCount: 0, sawPadding: false }

  for (const character of value) {
    if (isBase64DataCharacter(character)) {
      if (state.sawPadding) {
        return false
      }
      continue
    }

    const nextState = updatePaddingState(character, state)
    if (nextState != null) {
      state.paddingCount = nextState.paddingCount
      state.sawPadding = nextState.sawPadding
      continue
    }

    return false
  }

  return true
}

function isCanonicalBase64(value: string): boolean {
  if (!hasValidBase64Alphabet(value)) {
    return false
  }

  try {
    const decoded = Buffer.from(value, "base64")
    if (decoded.length === 0) {
      return false
    }

    const normalizedValue = trimBase64Padding(value)
    const encodedAgain = trimBase64Padding(decoded.toString("base64"))
    return encodedAgain === normalizedValue
  } catch {
    return false
  }
}

export function isValidAdminPublicKey(value: string): boolean {
  const parsedKey = parseOpenSshPublicKey(value.trim())
  return (
    parsedKey != null &&
    isCanonicalBase64(parsedKey.encodedKey) &&
    hasValidOpenSshPublicKeyWireBlob(parsedKey.algorithm, parsedKey.encodedKey)
  )
}

export function validateAdminPublicKey(
  exitWithMessage: ExitWithMessage,
  value: string,
  optionName = "--admin-public-key"
): string {
  // R-0000126: detect a private-key embed before any other validation.
  if (containsPrivateKeyMarker(value)) {
    exitWithMessage(
      `Error: "${optionName}" contains a private key marker. Provide the matching OpenSSH public key (.pub) instead.`
    )
  }

  const normalizedValue = value.trim()
  if (!isValidAdminPublicKey(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid value for "${optionName}" — provide a valid single-line OpenSSH public key.`
    )
  }
  return normalizedValue
}

export function readAdminPublicKeyFile(exitWithMessage: ExitWithMessage, path: string): string {
  // R-0000126: resolve relative paths against cwd; emit neutral errors.
  const resolvedPath = resolve(path)

  let value: string

  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    value = readFileSync(resolvedPath, "utf8")
  } catch {
    exitWithMessage(`Error: Failed to read admin public key file.`)
  }

  return validateAdminPublicKey(exitWithMessage, value, "--admin-public-key-file")
}

export function discoverLocalPublicKeys(sshDirectory = join(homedir(), ".ssh")): LocalPublicKey[] {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return readdirSync(sshDirectory)
      .filter((entry) => entry.endsWith(".pub"))
      .sort((left, right) => left.localeCompare(right))
      .flatMap((entry) => {
        const path = join(sshDirectory, entry)

        try {
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          const key = readFileSync(path, "utf8").trim()
          if (!isValidAdminPublicKey(key)) {
            return []
          }

          return [{ key, label: basename(entry), path }]
        } catch {
          return []
        }
      })
  } catch {
    return []
  }
}

function createPublicKeyOptions(publicKeys: LocalPublicKey[]): Array<SelectOption<string>> {
  return publicKeys.map((publicKey) => ({
    description: publicKey.path,
    label: publicKey.label,
    value: publicKey.path,
  }))
}

export async function promptForAdminPublicKey(
  select: SelectFunction<string>,
  publicKeys = discoverLocalPublicKeys()
): Promise<string | undefined> {
  const publicKeyMode = await select(
    "How should create-paratix configure the admin SSH public key?",
    PUBLIC_KEY_PROMPT_OPTIONS
  )

  if (publicKeyMode !== "local") {
    return undefined
  }

  if (publicKeys.length === 0) {
    console.error(
      "No readable public keys were found in ~/.ssh. Keeping the placeholder in server.ts."
    )
    return undefined
  }

  if (publicKeys.length === 1) {
    return publicKeys[0]?.key
  }

  const selectedPath = await select(
    "Select the public key to embed into server.ts:",
    createPublicKeyOptions(publicKeys)
  )

  return publicKeys.find((publicKey) => publicKey.path === selectedPath)?.key
}
