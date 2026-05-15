import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"
import { shellQuote } from "./sshHelpers.js"

/** Options for controlling template rendering behavior. */
export type RenderOptions = {
  /** When `true`, every placeholder must use an explicit modifier (e.g. `|shell` or `|raw`). */
  strict?: boolean
}

/** Registry of supported template modifiers. */
const modifiers: Partial<Record<string, (value: string) => string>> = {
  raw: (value: string) => value,
  shell: shellQuote,
}

const MALFORMED_PLACEHOLDER_SNIPPET_LIMIT = 40

/** Token kinds emitted by the template tokenizer. */
type Token =
  | { kind: "escaped" }
  | { kind: "literal"; text: string }
  | { kind: "placeholder"; modifier: string | undefined; varName: string }

/**
 * Pattern that matches a single placeholder anchored at a specific position.
 *
 * Anchored variant of the legacy template pattern; the sticky `y` flag lets the
 * tokenizer attempt the match at the current cursor position only.
 */
// eslint-disable-next-line security/detect-unsafe-regex -- modifier group is consumed via match.groups
const placeholderPattern = /\{\{(?<varName>\w+(?:\.\w+)*)(?:\|(?<modifier>\w*))?\}\}/vy

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
    this.tokens.push({
      kind: "placeholder",
      modifier: match.groups?.modifier,
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
 * Apply a template modifier to a resolved value.
 *
 * @param value - The stringified resolved value.
 * @param modifier - The modifier name extracted from the placeholder, or `undefined` if none.
 * @returns The value after applying the modifier transformation.
 */
function applyModifier(value: string, modifier: string | undefined): string {
  if (modifier === undefined) return value
  const transform = modifiers[modifier]
  if (!transform) throw new Error(`Unknown template modifier "${modifier}"`)
  return transform(value)
}

/**
 * Throw if any placeholder token lacks an explicit modifier.
 *
 * @param tokens - The full token list produced by {@link tokenizeTemplate}.
 */
function enforceStrictModifiers(tokens: Token[]): void {
  for (const token of tokens) {
    if (token.kind === "placeholder" && token.modifier === undefined) {
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
 *
 * When `options.strict` is `true` (the default), every placeholder **must** specify
 * a modifier; bare `\{\{KEY\}\}` placeholders will throw an error. Pass `strict: false`
 * to disable this check.
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
      output += applyModifier(resolved, token.modifier)
      placeholderIndex += 1
    }
  }

  return output
}
