import { describe, expect, it, vi } from "vitest"

import type { Environment } from "../src/types.js"

import { renderTemplate } from "../src/template.js"

describe("renderTemplate", () => {
  it("replaces {{key}} with the corresponding env value", async () => {
    const env: Environment = { HOST: "example.com" }
    const view = await renderTemplate("Server: {{HOST}}", env, { strict: false })
    expect(view).toBe("Server: example.com")
  })

  it("throws an error when the key is not present in env", async () => {
    const env: Environment = {}
    await expect(renderTemplate("Value: {{MISSING}}", env, { strict: false })).rejects.toThrow(
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
    const view = await renderTemplate("{{FIRST}} {{SECOND}}!", env, { strict: false })
    expect(view).toBe("hello world!")
  })

  it("returns an empty string when the template is empty", async () => {
    const env: Environment = {}
    const view = await renderTemplate("", env)
    expect(view).toBe("")
  })

  it("supports number values in env", async () => {
    const env: Environment = { PORT: 8080 }
    const view = await renderTemplate("Port: {{PORT}}", env, { strict: false })
    expect(view).toBe("Port: 8080")
  })

  it("replaces the same placeholder used twice", async () => {
    const env: Environment = { A: "x" }
    const view = await renderTemplate("{{A}} and {{A}}", env, { strict: false })
    expect(view).toBe("x and x")
  })

  it("inserts a value containing placeholder syntax verbatim (single-pass)", async () => {
    const env: Environment = { A: "{{B}}", B: "SHOULD_NOT_APPEAR" }
    const view = await renderTemplate("result: {{A}}", env, { strict: false })
    expect(view).toBe("result: {{B}}")
  })

  // String.prototype.replace() treats $&, $`, $', and $1–$9 in the
  // replacement string as special sequences.  The cursor-based assembly in
  // renderTemplate avoids this pitfall so dollar signs pass through verbatim.
  it("preserves dollar signs in resolved values", async () => {
    const env: Environment = { PRICE: "$100" }
    const view = await renderTemplate("Cost: {{PRICE}}", env, { strict: false })
    expect(view).toBe("Cost: $100")
  })

  it("calls a lazy function value once per placeholder occurrence", async () => {
    const lazy = vi.fn(() => "val")
    const env: Environment = { A: lazy }
    const view = await renderTemplate("{{A}} and {{A}}", env, { strict: false })
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

  describe("b64decode modifier", () => {
    const pem =
      "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg\nkqhkiG9w0B\n-----END PRIVATE KEY-----\n"
    const encodedPem = Buffer.from(pem, "utf8").toString("base64")

    it("restores a multi-line secret stored as single-line base64", async () => {
      const env: Environment = { DEPLOY_KEY: encodedPem }
      const view = await renderTemplate("{{DEPLOY_KEY|b64decode}}", env)
      expect(view).toBe(pem)
    })

    it("decodes an empty value to an empty string", async () => {
      const env: Environment = { EMPTY: "" }
      const view = await renderTemplate("[{{EMPTY|b64decode}}]", env)
      expect(view).toBe("[]")
    })

    it("tolerates surrounding and embedded whitespace", async () => {
      const wrapped = `\n  ${encodedPem.slice(0, 20)}\n${encodedPem.slice(20)}  \n`
      const env: Environment = { DEPLOY_KEY: wrapped }
      const view = await renderTemplate("{{DEPLOY_KEY|b64decode}}", env)
      expect(view).toBe(pem)
    })

    it("accepts a value whose padding was trimmed away", async () => {
      // "YWJjZGU=" with its padding trimmed off.
      const env: Environment = { A: "YWJjZGU" }
      const view = await renderTemplate("{{A|b64decode}}", env)
      expect(view).toBe("abcde")
    })

    it("rejects the base64url alphabet instead of normalizing it", async () => {
      const env: Environment = { A: "a-b_c" }
      await expect(renderTemplate("{{A|b64decode}}", env)).rejects.toThrow(
        'Template modifier "b64decode" on placeholder "{{A}}" received a value that is not standard base64'
      )
    })

    it("rejects a value of invalid base64 length", async () => {
      // Five characters leave a remainder of one: six bits, too few for a byte.
      const env: Environment = { A: "QUJDR" }
      await expect(renderTemplate("{{A|b64decode}}", env)).rejects.toThrow(/invalid base64 length/v)
    })

    // "QR==" carries trailing bits that no byte can hold; Buffer.from() drops them
    // and would silently decode it to the same "A" as the canonical "QQ==".
    it("rejects a non-canonical final group", async () => {
      const env: Environment = { A: "QR==" }
      await expect(renderTemplate("{{A|b64decode}}", env)).rejects.toThrow(
        /is not canonical base64/v
      )
    })

    it("rejects base64 whose bytes are not valid UTF-8", async () => {
      const env: Environment = { A: Buffer.from([0xff, 0xfe, 0xfd]).toString("base64") }
      await expect(renderTemplate("{{A|b64decode}}", env)).rejects.toThrow(
        /decoded to bytes that are not valid UTF-8/v
      )
    })

    // The decoded payload is a secret: an error message that echoed the input or
    // the decoded bytes would leak it into every log that captures the failure.
    it("never exposes the value or the decoded bytes in an error message", async () => {
      const secret = "SUPER-SECRET-KEY-MATERIAL"
      const env: Environment = { A: `${Buffer.from(secret, "utf8").toString("base64")}!!` }
      const message = String(
        await renderTemplate("{{A|b64decode}}", env).catch((error: unknown) => error)
      )
      expect(message).toContain("b64decode")
      expect(message).toContain("{{A}}")
      expect(message).not.toContain(secret)
      expect(message).not.toContain("SUPER")
      expect(message).not.toContain(Buffer.from(secret, "utf8").toString("base64"))
    })

    it("satisfies strict mode on its own, without an escaping modifier", async () => {
      const env: Environment = { A: Buffer.from("plain", "utf8").toString("base64") }
      const view = await renderTemplate("{{A|b64decode}}", env, { strict: true })
      expect(view).toBe("plain")
    })
  })

  describe("modifier chains", () => {
    it("applies a chain left to right", async () => {
      const env: Environment = { A: Buffer.from("it's here", "utf8").toString("base64") }
      const view = await renderTemplate("run {{A|b64decode|shell}}", env)
      expect(view).toBe("run 'it'\\''s here'")
    })

    it("fails on a reversed chain instead of emitting garbage", async () => {
      const env: Environment = { A: Buffer.from("plain", "utf8").toString("base64") }
      await expect(renderTemplate("{{A|shell|b64decode}}", env)).rejects.toThrow(
        /is not standard base64/v
      )
    })

    it("treats raw inside a chain as an identity step", async () => {
      const env: Environment = { A: Buffer.from("hello", "utf8").toString("base64") }
      const view = await renderTemplate("{{A|raw|b64decode|raw}}", env)
      expect(view).toBe("hello")
    })

    it("rejects an unknown modifier anywhere in the chain", async () => {
      const env: Environment = { A: "x" }
      await expect(renderTemplate("{{A|raw|nope|shell}}", env)).rejects.toThrow(
        'Unknown template modifier "nope"'
      )
    })

    it("stops the chain at the first failing modifier", async () => {
      const env: Environment = { A: "!!!" }
      await expect(renderTemplate("{{A|b64decode|shell}}", env)).rejects.toThrow(
        /is not standard base64/v
      )
    })
  })

  it("leaves value unchanged when no modifier is used", async () => {
    const env: Environment = { VAL: "raw" }
    const view = await renderTemplate("{{VAL}}", env, { strict: false })
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

  it("defaults to strict mode when no strict option is provided", async () => {
    const env: Environment = { A: "x" }
    await expect(renderTemplate("{{A}}", env)).rejects.toThrow(/Strict mode.*explicit modifier/v)
  })

  it("does not resolve lazy env values before default strict mode rejects", async () => {
    const lazy = vi.fn(() => "x")
    const env: Environment = { A: lazy }

    await expect(renderTemplate("{{A}}", env)).rejects.toThrow(/Strict mode.*explicit modifier/v)
    expect(lazy).not.toHaveBeenCalled()
  })

  it.each(["{{TOKEN|raw", "{{BAD-NAME|raw}}", "{{TOKEN|raw!}}", "{{TOKEN||raw}}"])(
    "throws in strict mode when placeholder syntax is malformed: %s",
    async (template) => {
      const env: Environment = { BAD: "bad", TOKEN: "token" }
      await expect(renderTemplate(template, env, { strict: true })).rejects.toThrow(
        /Malformed template placeholder near/v
      )
    }
  )

  it("does not resolve lazy env values before strict mode rejects malformed syntax", async () => {
    const lazy = vi.fn(() => "token")
    const env: Environment = { TOKEN: lazy }

    await expect(renderTemplate("{{TOKEN|raw!", env)).rejects.toThrow(
      /Malformed template placeholder near/v
    )
    expect(lazy).not.toHaveBeenCalled()
  })

  it("keeps malformed placeholder-like text literal when strict mode is disabled", async () => {
    const env: Environment = {}
    const view = await renderTemplate("Value: {{BAD-NAME|raw}}", env, { strict: false })
    expect(view).toBe("Value: {{BAD-NAME|raw}}")
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

  // Regression for R-0000033: the previous implementation replaced "\{{" with the
  // sentinel string "\x00ESCAPED_BRACE\x00" and reverted it via replaceAll() over
  // the merged output. A resolved value that happened to contain the sentinel
  // would therefore be re-substituted to "{{" after rendering. The tokenizer-based
  // implementation must emit resolved values verbatim, regardless of their
  // contents.
  it("preserves the legacy sentinel string in resolved values verbatim", async () => {
    const sentinel = "\x00ESCAPED_BRACE\x00"
    const env: Environment = { SECRET: `prefix${sentinel}suffix` }
    const view = await renderTemplate("value: {{SECRET|raw}}", env, { strict: true })
    expect(view).toBe(`value: prefix${sentinel}suffix`)
    expect(view).not.toContain("{{")
  })

  it("preserves the legacy sentinel string in resolved values when escapes are also present", async () => {
    const sentinel = "\x00ESCAPED_BRACE\x00"
    const env: Environment = { S: `${sentinel}done` }
    const view = await renderTemplate("\\{{kept}} and {{S|raw}}", env, { strict: true })
    expect(view).toBe(`{{kept}} and ${sentinel}done`)
  })
})
