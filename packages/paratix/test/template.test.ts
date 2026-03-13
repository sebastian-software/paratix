import { describe, expect, it } from "vitest"

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
})
