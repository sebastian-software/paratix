import type { Stats } from "node:fs"

import { lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { basename, join, resolve } from "node:path"

import type { SelectFunction, SelectOption } from "./promptUi.js"

import { CliExitError } from "./cliExitError.js"
import { hasValidOpenSshPublicKeyWireBlob } from "./openSshPublicKeyWire.js"
import { isCanonicalBase64 } from "./publicKeyBase64.js"
import { containsUnsafeCodepoint } from "./unsafeCodepoints.js"

export type LocalPublicKey = {
  key: string
  label: string
  path: string
}

type ExitWithMessage = (message: string) => never
type AdminPublicKeyFileSystem = {
  lstatSync: (path: string) => Stats
  readFileSync: (path: string, encoding: "utf8") => string
  realpathSync: (path: string) => string
  statSync: (path: string) => Stats
}

type PublicKeyChoice = "local" | "placeholder"
type ParsedPublicKey = { algorithm: string; encodedKey: string }
type PromptForAdminPublicKeyOptions = {
  allowPlaceholder?: boolean
}

const adminPublicKeyFileSystem: AdminPublicKeyFileSystem = {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
}

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

const MAX_PUBLIC_KEY_FILE_BYTES = 16_384

function containsPrivateKeyMarker(value: string): boolean {
  return PRIVATE_KEY_MARKERS.some((marker) => value.includes(marker))
}

function parseOpenSshPublicKey(value: string): null | ParsedPublicKey {
  if (value.length === 0 || /[\r\n]/v.test(value)) {
    return null
  }

  // R-0000233: the third "comment" field (and any surrounding whitespace)
  // would otherwise be embedded into server.ts as-is. Reject control
  // characters and Unicode bidi formatting codepoints anywhere in the key
  // string so an attacker-supplied .pub file cannot smuggle a comment that
  // visually rewrites the surrounding server.ts source.
  if (containsUnsafeCodepoint(value)) {
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

// R-0000831: PATH_MAX on Linux is 4096 bytes (sys/limits.h: PATH_MAX) and
// the corresponding macOS limit is 1024 bytes; pick the higher value so the
// pre-validation does not reject paths the OS would otherwise accept on
// Linux. The literal is kept as a named constant to make the intent
// obvious and to give a single place to revisit if the limit changes.
const ADMIN_PUBLIC_KEY_FILE_PATH_MAX_BYTES = 4096

// R-0000831: validate the raw path bytes before handing them to
// `resolve` or any fs call. Two failure modes need a deterministic,
// operator-friendly error instead of the cryptic syscall message Node
// would produce later:
//   1. NUL byte in the path. Node's path APIs reject this with
//      `ERR_INVALID_ARG_VALUE`, but the message points at internal
//      argument indices rather than the offending option. Surfacing it
//      via CliExitError keeps the diagnostic actionable.
//   2. Path length above PATH_MAX. Even when Node accepts the string,
//      the underlying syscall (`open(2)`/`stat(2)`) will fail with
//      `ENAMETOOLONG`; rejecting it up front makes the cause obvious
//      and avoids exposing a partial buffer of a pathological input in
//      the eventual log line.
function preValidateAdminPublicKeyFilePath(exitWithMessage: ExitWithMessage, path: string): void {
  if (path.includes("\0")) {
    exitWithMessage(
      "Error: admin public key file path contains a NUL byte; provide a clean filesystem path."
    )
    throw new Error("admin public key file path contains a NUL byte")
  }
  // Byte length is the relevant comparand because PATH_MAX is a byte
  // budget at the syscall boundary; a UTF-8 path with multi-byte code
  // points may already exceed the limit while its character length is
  // still well below 4096.
  const pathByteLength = Buffer.byteLength(path, "utf8")
  if (pathByteLength > ADMIN_PUBLIC_KEY_FILE_PATH_MAX_BYTES) {
    exitWithMessage(
      `Error: admin public key file path is too long (${String(pathByteLength)} bytes, ` +
        `limit ${String(ADMIN_PUBLIC_KEY_FILE_PATH_MAX_BYTES)}); provide a shorter path.`
    )
    throw new Error("admin public key file path exceeds PATH_MAX")
  }
}

export function readAdminPublicKeyFile(
  exitWithMessage: ExitWithMessage,
  path: string,
  fileSystem: AdminPublicKeyFileSystem = adminPublicKeyFileSystem
): string {
  preValidateAdminPublicKeyFilePath(exitWithMessage, path)

  // R-0000126: resolve relative paths against cwd; emit neutral errors.
  const resolvedPath = resolve(path)

  // R-0000185: ExitWithMessage is typed `never`, but TypeScript does not
  // enforce that at runtime — a caller may pass a stub that returns or whose
  // thrown error is caught upstream. After every exitWithMessage invocation
  // we therefore guarantee a return/throw locally so we never reach a state
  // where stat/value are read uninitialised.
  const failWithReadError = (): never => {
    exitWithMessage(`Error: Failed to read admin public key file.`)
    throw new Error(`Error: Failed to read admin public key file.`)
  }

  // R-0000665: probe with `lstatSync` first so a symlinked path is
  // detected without following it. `statSync` later follows the link to
  // validate the eventual file's size/isFile, but the operator-facing
  // log line below names the real target so a planted link in a shared
  // CI home cannot embed a different key into server.ts without the
  // operator noticing.
  const linkStat = (() => {
    try {
      return fileSystem.lstatSync(resolvedPath)
    } catch {
      return failWithReadError()
    }
  })()
  // R-0000726 (was R-0000665): resolve the realpath unconditionally so
  // ancestor symlinks (e.g. a planted `~/.ssh -> /tmp/attacker-ssh`)
  // surface in the operator-facing log even when the leaf entry itself
  // is a regular file. The previous implementation only logged when the
  // leaf was a symbolic link, leaving the ancestor-symlink case silent.
  // R-0000731: resolve the realpath once up front and reuse it for the
  // subsequent stat/readFile calls so the link target cannot be swapped
  // between the steps (TOCTOU). When realpath fails we fall back to the
  // originally resolved path; the statSync below will then surface any
  // remaining failure via failWithReadError.
  const materialisedPath = (() => {
    try {
      const realPath = fileSystem.realpathSync(resolvedPath)
      if (realPath !== resolvedPath) {
        if (linkStat.isSymbolicLink()) {
          console.log(`Reading public key from ${realPath} (symlink target of ${resolvedPath}).`)
        } else {
          console.log(
            `Reading public key from ${realPath} (resolved via ancestor symlink of ${resolvedPath}).`
          )
        }
      }
      return realPath
    } catch {
      // A dangling or unreadable symlink falls through to the regular
      // statSync read path, which will surface the failure via
      // failWithReadError below.
      return resolvedPath
    }
  })()

  // R-0000186: statSync follows symbolic links so that legitimate operator
  // setups (e.g. ~/.ssh/id_ed25519.pub linked into a password-manager vault)
  // are accepted. The downstream readFileSync also follows the link, so the
  // size and isFile() guards remain meaningful for the eventual file.
  // R-0000731: stat/readFile both operate on the already-resolved
  // materialisedPath so the link target cannot be swapped between
  // realpath and stat or between stat and readFile.
  const stat = (() => {
    try {
      return fileSystem.statSync(materialisedPath)
    } catch {
      return failWithReadError()
    }
  })()

  if (!stat.isFile() || stat.size > MAX_PUBLIC_KEY_FILE_BYTES) {
    failWithReadError()
  }

  const value = (() => {
    try {
      return fileSystem.readFileSync(materialisedPath, "utf8")
    } catch {
      return failWithReadError()
    }
  })()

  return validateAdminPublicKey(exitWithMessage, value, "--admin-public-key-file")
}

// R-0000665: build the operator-facing label for a discovered public key
// so symlinked entries reveal the realpath alongside the basename. A
// planted link under a shared CI home (e.g. /tmp/-style `.ssh/`) would
// otherwise show only `id_ed25519.pub` while the underlying file lives
// in an attacker-controlled directory. R-0000725: the caller resolves
// the realpath once during discovery and threads it in here so the
// label and the subsequent stat/readFile reference the same materialised
// target — eliminating the TOCTOU window where the label could describe
// a different file than the one whose contents were embedded.
function buildLocalPublicKeyLabel(entry: string, path: string, realPath: string): string {
  if (realPath === path) return basename(entry)
  return `${basename(entry)} -> ${realPath}`
}

// R-0000725: resolve the entry through `realpathSync` once per discovery
// loop and reuse the resulting path for stat, readFile and the operator
// label. Falls back to the original path when `realpath` is unavailable
// (dangling link, EACCES) so the downstream statSync still surfaces the
// failure through the regular catch arm.
function resolveDiscoveredEntryPath(path: string): string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return realpathSync(path)
  } catch {
    return path
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
          // R-0000725: resolve the realpath once per entry and reuse it
          // for the size/isFile guard, the file read, and the label
          // below — eliminating the TOCTOU window where the label could
          // describe a different file than the one whose contents were
          // embedded into server.ts. Resolving unconditionally also
          // surfaces ancestor symlinks (e.g. `~/.ssh -> /tmp/attacker-ssh`)
          // in the operator-facing label even when the leaf entry itself
          // is a regular file.
          const resolvedPath = resolveDiscoveredEntryPath(path)

          // R-0000186: follow symlinks so ~/.ssh/*.pub entries that point to
          // a password-manager vault (or similar) are still discovered.
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          const stat = statSync(resolvedPath)
          if (!stat.isFile() || stat.size > MAX_PUBLIC_KEY_FILE_BYTES) {
            return []
          }
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          const key = readFileSync(resolvedPath, "utf8").trim()
          if (!isValidAdminPublicKey(key)) {
            return []
          }

          // R-0000665: surface the symlink-target via the label so the
          // operator can see the effective file at a glance during the
          // interactive prompt. R-0000725: the label is derived from the
          // already-resolved path so it stays in sync with the file the
          // contents were read from.
          return [{ key, label: buildLocalPublicKeyLabel(entry, path, resolvedPath), path }]
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

function createPublicKeyModeOptions(
  allowPlaceholder: boolean
): Array<SelectOption<PublicKeyChoice>> {
  if (allowPlaceholder) return PUBLIC_KEY_PROMPT_OPTIONS
  return PUBLIC_KEY_PROMPT_OPTIONS.filter((option) => option.value !== "placeholder")
}

function printNoLocalPublicKeysMessage(): void {
  console.error(
    "No readable public keys were found in ~/.ssh. Keeping the placeholder in server.ts."
  )
}

export async function promptForAdminPublicKey(
  select: SelectFunction<string>,
  publicKeys = discoverLocalPublicKeys(),
  options?: PromptForAdminPublicKeyOptions
): Promise<string | undefined> {
  const allowPlaceholder = options?.allowPlaceholder ?? true
  const publicKeyMode = await select(
    "How should create-paratix configure the admin SSH public key?",
    createPublicKeyModeOptions(allowPlaceholder)
  )

  if (publicKeyMode !== "local") {
    return undefined
  }

  if (publicKeys.length === 0) {
    if (!allowPlaceholder) {
      throw new CliExitError(
        "Error: Root bootstrap requires an admin SSH public key, but no readable public keys were found in ~/.ssh. Provide one via --admin-public-key or --admin-public-key-file."
      )
    }
    printNoLocalPublicKeysMessage()
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
