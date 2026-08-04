import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"
import { shellQuote } from "./sshHelpers.js"

/** Options for controlling template rendering behavior. */
export type RenderOptions = {
  /** When `true`, every placeholder must use an explicit modifier (e.g. `|shell` or `|raw`). */
  strict?: boolean
}

/** Standard base64 alphabet with padding only at the very end. */
const BASE64_PATTERN = /^[A-Za-z0-9+\/]*={0,2}$/v

/** Base64 encodes three bytes per four characters, so input length is a multiple of four. */
const BASE64_GROUP_LENGTH = 4

/** Rejects any byte sequence that is not well-formed UTF-8. */
const utf8Decoder = new TextDecoder("utf-8", { fatal: true })

/**
 * Strip whitespace from a base64 value and restore canonical padding.
 *
 * @param value - The raw resolved value, possibly wrapped across lines or trimmed of padding.
 * @param location - Message prefix naming the modifier and placeholder.
 * @returns The compacted, padded base64 string, ready to decode.
 * @throws {Error} When the value uses a foreign alphabet or has an impossible length.
 */
function normalizeBase64(value: string, location: string): string {
  const compact = value.replaceAll(/\s+/gv, "")
  if (!BASE64_PATTERN.test(compact)) {
    throw new Error(`${location} received a value that is not standard base64`)
  }

  const stripped = compact.replace(/={1,2}$/v, "")
  // A remainder of one leaves six bits, too few to form a byte.
  if (stripped.length % BASE64_GROUP_LENGTH === 1) {
    throw new Error(`${location} received a value of invalid base64 length`)
  }

  const groups = Math.ceil(stripped.length / BASE64_GROUP_LENGTH)
  return stripped.padEnd(groups * BASE64_GROUP_LENGTH, "=")
}

/**
 * Decode a base64-encoded value into the text it represents.
 *
 * Secrets that span multiple lines — PEM and OpenSSH private keys, certificates —
 * are commonly stored base64-encoded on a single line because secret managers
 * mangle embedded newlines. This modifier turns such a value back into the bytes
 * the target file expects.
 *
 * The decoder is deliberately strict: whitespace is stripped and missing padding
 * is normalized, but a foreign alphabet (including base64url), a non-canonical
 * final group, or bytes that are not valid UTF-8 throw instead of producing
 * silently corrupted output.
 *
 * **Security:** no error message may contain the value or the decoded bytes — the
 * input is a secret and error messages end up in logs.
 *
 * @param value - The stringified resolved value, expected to be standard base64.
 * @param varName - Placeholder name, used only to make the error message locatable.
 * @returns The decoded UTF-8 text.
 * @throws {Error} When the value is not standard base64 or does not decode to UTF-8.
 */
function decodeBase64(value: string, varName: string): string {
  const location = `Template modifier "b64decode" on placeholder "{{${varName}}}"`
  const padded = normalizeBase64(value, location)
  if (padded === "") return ""

  const bytes = Buffer.from(padded, "base64")
  // Buffer.from() ignores trailing bits that no byte can carry, so "QR==" and
  // "QQ==" both decode to "A". Re-encoding is what tells them apart.
  if (bytes.toString("base64") !== padded) {
    throw new Error(`${location} received a value that is not canonical base64`)
  }

  try {
    return utf8Decoder.decode(bytes)
  } catch {
    throw new Error(`${location} decoded to bytes that are not valid UTF-8`)
  }
}

/** Registry of supported template modifiers. */
const modifiers: Partial<Record<string, (value: string, varName: string) => string>> = {
  b64decode: decodeBase64,
  raw: (value: string) => value,
  shell: shellQuote,
}

const MALFORMED_PLACEHOLDER_SNIPPET_LIMIT = 40

/** Token kinds emitted by the template tokenizer. */
type Token =
  | { kind: "escaped" }
  | { kind: "literal"; text: string }
  | { kind: "placeholder"; modifiers: string[]; varName: string }

/**
 * Pattern that matches a single placeholder anchored at a specific position.
 *
 * Anchored variant of the legacy template pattern; the sticky `y` flag lets the
 * tokenizer attempt the match at the current cursor position only.
 *
 * The modifier group accepts either a chain of named modifiers (`|a|b|c`) or the
 * single legacy trailing pipe (`{{KEY|}}`), which is parsed and then rejected as
 * an unknown modifier. An empty segment *inside* a chain (`{{KEY||raw}}`) matches
 * neither alternative and therefore stays malformed syntax, as before chaining.
 */
// eslint-disable-next-line security/detect-unsafe-regex -- modifier group is consumed via match.groups
const placeholderPattern = /\{\{(?<varName>\w+(?:\.\w+)*)(?<modifiers>\||(?:\|\w+)*)\}\}/vy

/**
 * Single-pass tokenizer that walks a template string and emits an ordered
 * list of escaped, placeholder, and literal tokens.
 */
class TemplateTokenizer {
  private cursor = 0
  private literalBuffer = ""
  private readonly strict: boolean
  private readonly template: string
  private readonly tokens: Token[] = []

  public constructor(template: string, strict: boolean) {
    this.template = template
    this.strict = strict
  }

  public tokenize(): Token[] {
    while (this.cursor < this.template.length) {
      if (this.consumeEscapedBrace()) continue
      if (this.consumePlaceholder()) continue
      this.literalBuffer += this.template[this.cursor]
      this.cursor += 1
    }
    this.flushLiteral()
    return this.tokens
  }

  private consumeEscapedBrace(): boolean {
    if (!this.template.startsWith("\\{{", this.cursor)) return false
    this.flushLiteral()
    this.tokens.push({ kind: "escaped" })
    this.cursor += "\\{{".length
    return true
  }

  private consumePlaceholder(): boolean {
    if (!this.template.startsWith("{{", this.cursor)) return false
    placeholderPattern.lastIndex = this.cursor
    const match = placeholderPattern.exec(this.template)
    if (match === null) {
      if (this.strict) throw new Error(this.formatMalformedPlaceholderError())
      return false
    }
    this.flushLiteral()
    const rawModifiers = match.groups?.modifiers ?? ""
    this.tokens.push({
      kind: "placeholder",
      // "" -> no modifier, "|" -> the legacy empty one, "|a|b" -> a chain.
      modifiers: rawModifiers === "" ? [] : rawModifiers.slice(1).split("|"),
      varName: match.groups?.varName ?? "",
    })
    this.cursor += match[0].length
    return true
  }

  private flushLiteral(): void {
    if (this.literalBuffer.length > 0) {
      this.tokens.push({ kind: "literal", text: this.literalBuffer })
      this.literalBuffer = ""
    }
  }

  private formatMalformedPlaceholderError(): string {
    const closingIndex = this.template.indexOf("}}", this.cursor + "{{".length)
    const endIndex =
      closingIndex === -1
        ? Math.min(this.template.length, this.cursor + MALFORMED_PLACEHOLDER_SNIPPET_LIMIT)
        : closingIndex + "}}".length
    const snippet = this.template.slice(this.cursor, endIndex)
    const suffix = endIndex < this.template.length && closingIndex === -1 ? "..." : ""
    return `Malformed template placeholder near "${snippet}${suffix}"`
  }
}

/**
 * Tokenize a template string into escaped, placeholder, and literal segments.
 *
 * The tokenizer walks the template once and emits a flat list of tokens that
 * preserves the input order. Literal text between placeholders is coalesced
 * into a single `literal` token to keep the resulting list small.
 *
 * @param template - The raw template string to tokenize.
 * @param strict - When `true`, malformed unescaped placeholder syntax throws.
 * @returns An ordered list of tokens that, when rendered, reproduces the template.
 */
function tokenizeTemplate(template: string, strict: boolean): Token[] {
  return new TemplateTokenizer(template, strict).tokenize()
}

/**
 * Apply a placeholder's modifier chain to a resolved value, left to right.
 *
 * @param value - The stringified resolved value.
 * @param names - The modifier names extracted from the placeholder, in source order.
 * @param varName - Placeholder name, passed to modifiers for locatable error messages.
 * @returns The value after applying every modifier in order.
 */
function applyModifiers(value: string, names: string[], varName: string): string {
  let current = value
  for (const name of names) {
    const transform = modifiers[name]
    if (!transform) throw new Error(`Unknown template modifier "${name}"`)
    current = transform(current, varName)
  }
  return current
}

/**
 * Throw if any placeholder token lacks an explicit modifier.
 *
 * @param tokens - The full token list produced by {@link tokenizeTemplate}.
 */
function enforceStrictModifiers(tokens: Token[]): void {
  for (const token of tokens) {
    if (token.kind === "placeholder" && token.modifiers.length === 0) {
      throw new Error(
        `Strict mode: placeholder "{{${token.varName}}}" requires an explicit modifier (e.g. |shell or |raw)`
      )
    }
  }
}

/**
 * Render a template string by replacing all `\{\{key\}\}` (or `\{\{key|modifier\}\}`)
 * placeholders with the corresponding resolved env values.
 *
 * **Security: No default escaping.** Values are inserted verbatim unless a modifier
 * is applied. When the rendered output is used in a shell context (e.g. a script or
 * shell config file), always use the `|shell` modifier on every user-controlled
 * placeholder to prevent shell injection: `\{\{VALUE|shell\}\}`.
 *
 * Supported modifiers:
 * - `shell` — wraps the resolved value with {@link shellQuote} for safe shell interpolation.
 * - `raw` — passes the value through unchanged (explicit verbatim insertion).
 * - `b64decode` — decodes a base64-encoded value into the text it represents, for
 *   multi-line secrets (private keys, certificates) stored on a single line.
 *
 * Modifiers can be chained and are applied left to right:
 * `\{\{KEY|b64decode|shell\}\}` decodes first and quotes the result. `b64decode` is a
 * transform, not an escape — a chain without `shell` inserts the decoded value verbatim.
 *
 * When `options.strict` is `true` (the default), every placeholder **must** specify
 * at least one modifier; bare `\{\{KEY\}\}` placeholders will throw an error. Pass
 * `strict: false` to disable this check.
 *
 * The renderer tokenizes the template once into escaped/placeholder/literal segments
 * and concatenates the resolved segments without performing a second `replaceAll`
 * over the merged output. Resolved values that happen to contain template syntax
 * or any internal sentinel string are therefore preserved verbatim.
 *
 * Placeholders are resolved concurrently via Promise.all; insertion order is preserved.
 *
 * @param template - The template string containing placeholders.
 * @param environment - The env map used to resolve placeholder values.
 * @param options - Optional rendering options.
 * @returns The rendered string with all placeholders replaced.
 * @throws {Error} When a placeholder key is not found in `environment`.
 * @throws {Error} When `strict` is `true` and a placeholder has no modifier.
 */
export async function renderTemplate(
  template: string,
  environment: Environment,
  options?: RenderOptions
): Promise<string> {
  const strict = options?.strict ?? true
  const tokens = tokenizeTemplate(template, strict)

  // In strict mode, validate that all placeholders have explicit modifiers
  // before resolving any values.
  if (strict) enforceStrictModifiers(tokens)

  // Resolve all placeholder values concurrently, preserving token order.
  const placeholderTokens = tokens.filter(
    (token): token is Extract<Token, { kind: "placeholder" }> => token.kind === "placeholder"
  )
  const resolvedValues = await Promise.all(
    placeholderTokens.map(async (token) => resolveEnvironment(environment, token.varName))
  )

  // Build the output by concatenating segments in order. No second-pass replace
  // is performed, so resolved values can never collide with sentinel strings.
  let output = ""
  let placeholderIndex = 0
  for (const token of tokens) {
    if (token.kind === "literal") {
      output += token.text
    } else if (token.kind === "escaped") {
      output += "{{"
    } else {
      const resolved = String(resolvedValues[placeholderIndex])
      output += applyModifiers(resolved, token.modifiers, token.varName)
      placeholderIndex += 1
    }
  }

  return output
}
