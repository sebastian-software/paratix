import { describe, expect, it, vi } from "vitest"

import type { Environment } from "../src/types.js"

import { renderTemplate } from "../src/template.js"

describe("renderTemplate", () => {
  it("replaces {{key}} with the corresponding env value", async () => {
    const env: Environment = { HOST: "example.com" }
    const view = await renderTemplate("Server: {{HOST}}", env)
    expect(view).toBe("Server: example.com")
  })

  it("throws an error when the key is not present in env", async () => {
    const env: Environment = {}
    await expect(renderTemplate("Value: {{MISSING}}", env)).rejects.toThrow(
      'Env key "MISSING" is not defined'
    )
  })

  it("keeps escaped \\{{ as a literal {{ in the output", async () => {
    const env: Environment = {}
    const view = await renderTemplate("Escaped: \\{{not-a-key}}", env)
    expect(view).toBe("Escaped: {{not-a-key}}")
  })

  it("replaces multiple different keys in a single template", async () => {
    const env: Environment = { FIRST: "hello", SECOND: "world" }
    const view = await renderTemplate("{{FIRST}} {{SECOND}}!", env)
    expect(view).toBe("hello world!")
  })

  it("returns an empty string when the template is empty", async () => {
    const env: Environment = {}
    const view = await renderTemplate("", env)
    expect(view).toBe("")
  })

  it("supports number values in env", async () => {
    const env: Environment = { PORT: 8080 }
    const view = await renderTemplate("Port: {{PORT}}", env)
    expect(view).toBe("Port: 8080")
  })

  it("replaces the same placeholder used twice", async () => {
    const env: Environment = { A: "x" }
    const view = await renderTemplate("{{A}} and {{A}}", env)
    expect(view).toBe("x and x")
  })

  it("inserts a value containing placeholder syntax verbatim (single-pass)", async () => {
    const env: Environment = { A: "{{B}}", B: "SHOULD_NOT_APPEAR" }
    const view = await renderTemplate("result: {{A}}", env)
    expect(view).toBe("result: {{B}}")
  })

  // String.prototype.replace() treats $&, $`, $', and $1–$9 in the
  // replacement string as special sequences.  The cursor-based assembly in
  // renderTemplate avoids this pitfall so dollar signs pass through verbatim.
  it("preserves dollar signs in resolved values", async () => {
    const env: Environment = { PRICE: "$100" }
    const view = await renderTemplate("Cost: {{PRICE}}", env)
    expect(view).toBe("Cost: $100")
  })

  it("calls a lazy function value once per placeholder occurrence", async () => {
    const lazy = vi.fn(() => "val")
    const env: Environment = { A: lazy }
    const view = await renderTemplate("{{A}} and {{A}}", env)
    expect(view).toBe("val and val")
    expect(lazy).toHaveBeenCalledTimes(2)
  })

  it("applies the shell modifier to wrap the value in single quotes", async () => {
    const env: Environment = { CMD: "hello world" }
    const view = await renderTemplate("run {{CMD|shell}}", env)
    expect(view).toBe("run 'hello world'")
  })

  it("escapes single quotes inside a shell-modified value", async () => {
    const env: Environment = { MSG: "it's done" }
    const view = await renderTemplate("echo {{MSG|shell}}", env)
    expect(view).toBe("echo 'it'\\''s done'")
  })

  it("throws on an unknown template modifier", async () => {
    const env: Environment = { A: "x" }
    await expect(renderTemplate("{{A|unknown}}", env)).rejects.toThrow(
      'Unknown template modifier "unknown"'
    )
  })

  it("throws on an empty modifier (trailing pipe)", async () => {
    const env: Environment = { A: "x" }
    await expect(renderTemplate("{{A|}}", env)).rejects.toThrow('Unknown template modifier ""')
  })

  it("leaves value unchanged when no modifier is used", async () => {
    const env: Environment = { VAL: "raw" }
    const view = await renderTemplate("{{VAL}}", env)
    expect(view).toBe("raw")
  })

  it("applies the raw modifier as an identity function", async () => {
    const env: Environment = { VAL: "hello" }
    const view = await renderTemplate("{{VAL|raw}}", env)
    expect(view).toBe("hello")
  })

  it("passes special characters through unchanged with raw modifier", async () => {
    const env: Environment = { VAL: "it's $100" }
    const view = await renderTemplate("{{VAL|raw}}", env)
    expect(view).toBe("it's $100")
  })

  it("throws in strict mode when placeholder has no modifier", async () => {
    const env: Environment = { A: "x" }
    await expect(renderTemplate("{{A}}", env, { strict: true })).rejects.toThrow(
      /Strict mode.*explicit modifier/v
    )
  })

  it("allows |shell modifier in strict mode", async () => {
    const env: Environment = { A: "hello world" }
    const view = await renderTemplate("{{A|shell}}", env, { strict: true })
    expect(view).toBe("'hello world'")
  })

  it("allows |raw modifier in strict mode", async () => {
    const env: Environment = { A: "hello" }
    const view = await renderTemplate("{{A|raw}}", env, { strict: true })
    expect(view).toBe("hello")
  })

  it("works without strict option (backwards compatibility)", async () => {
    const env: Environment = { A: "x" }
    const view = await renderTemplate("{{A}}", env)
    expect(view).toBe("x")
  })

  it("works with strict explicitly set to false", async () => {
    const env: Environment = { A: "x" }
    const view = await renderTemplate("{{A}}", env, { strict: false })
    expect(view).toBe("x")
  })

  it("throws in strict mode when one of multiple placeholders lacks a modifier", async () => {
    const env: Environment = { A: "x", B: "y" }
    await expect(renderTemplate("{{A|shell}} {{B}}", env, { strict: true })).rejects.toThrow(
      /Strict mode.*"\{\{B\}\}"/v
    )
  })
})
