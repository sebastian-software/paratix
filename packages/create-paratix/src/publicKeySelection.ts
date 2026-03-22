import { readdirSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { basename, join } from "node:path"

import type { SelectFunction, SelectOption } from "./promptUi.js"

export type LocalPublicKey = {
  key: string
  label: string
  path: string
}

type ExitWithMessage = (message: string) => never

type PublicKeyChoice = "local" | "placeholder"

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

function isLikelyPublicKey(value: string): boolean {
  return value.length > 0 && !value.includes("\n")
}

export function isValidAdminPublicKey(value: string): boolean {
  return isLikelyPublicKey(value.trim())
}

export function validateAdminPublicKey(
  exitWithMessage: ExitWithMessage,
  value: string,
  optionName = "--admin-public-key"
): string {
  const normalizedValue = value.trim()
  if (!isValidAdminPublicKey(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid value for "${optionName}" — provide a single-line SSH public key.`
    )
  }
  return normalizedValue
}

export function readAdminPublicKeyFile(exitWithMessage: ExitWithMessage, path: string): string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const value = readFileSync(path, "utf8")
    return validateAdminPublicKey(exitWithMessage, value, "--admin-public-key-file")
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    exitWithMessage(`Error: Failed to read "--admin-public-key-file" from "${path}": ${message}`)
  }
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
          if (!isLikelyPublicKey(key)) {
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
