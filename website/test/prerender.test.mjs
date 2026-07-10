import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { test } from "node:test"

const html = await readFile(new URL("../build/client/index.html", import.meta.url), "utf8")

test("prerendered homepage contains content instead of an SPA shell", () => {
  assert.ok(html.includes("Your server,"))
  assert.ok(html.includes("Scaffold. Inspect. Apply."))
  assert.ok(html.includes("When not to use Paratix"))
  assert.ok(html.includes("Preparing for open source"))
  assert.ok(html.includes("No YAML and no server-side agent"))
  assert.ok(html.includes("Read the 5-minute guide"))
  assert.ok(html.includes('<a href="#status">GitHub · planned</a>'))
  assert.ok(html.includes("Hardening can close the door"))
  assert.ok(html.includes("GitHub and npm publication are planned"))
  assert.ok(html.includes("Package changelogs record releases"))
  assert.ok(html.includes("Scoped secrets are redacted"))
  assert.ok(html.split("pnpm create paratix my-server").length - 1 >= 2)
})

test("prerendered homepage contains domain-independent social metadata", () => {
  assert.ok(html.includes("<title>Paratix | TypeScript server automation over SSH</title>"))
  assert.ok(html.includes('name="description"'))
  assert.ok(html.includes('<meta content="/paratix-og.png" property="og:image"/>'))
  assert.ok(html.includes('<meta content="summary_large_image" name="twitter:card"/>'))
  assert.ok(!html.includes('rel="canonical"'))
  assert.ok(!html.includes('property="og:url"'))
})
