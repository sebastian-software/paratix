import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

import { recipe, server } from "../src/index.js"
import { file, package as pkg, service } from "../src/modules/index.js"

function extractServerExportJSDoc(entryPointSource: string): string {
  const matches = [
    ...entryPointSource.matchAll(
      /(?<jsdoc>\/\*\*(?:(?!\/\*\*)[\s\S])*?\*\/)\s*export \{ server \} from "\.\/server\.js"/gv
    ),
  ]
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one server export JSDoc block, got ${matches.length}`)
  }
  const jsdoc = matches[0]?.groups?.jsdoc
  if (jsdoc == null) throw new Error("Could not extract the server export JSDoc")
  return jsdoc
}

// ---------------------------------------------------------------------------
// Drift guard for the published JSDoc @example blocks.
//
// These snippets are copied verbatim (minus the leading `import` lines) from
// the @example blocks of `server()` in src/server.ts and `recipe()` in
// src/recipe.ts. They ship in the generated .d.ts files and Editor hovers, so
// a user may copy-paste them directly. The `apt` module never exposed an
// `installed` method (only debconf/distUpgrade/key/repository) -- package
// installation lives on `package.installed` (`import { package as pkg }`).
// Compiling and running the examples here fails the suite the moment either
// JSDoc block drifts back to a non-existent API such as `apt.installed(...)`.
// See paratix#69.
// ---------------------------------------------------------------------------

describe("JSDoc @example blocks", () => {
  it("documents the supported two-entry-point import contract", () => {
    const entryPointSource = readFileSync(resolve(import.meta.dirname, "../src/index.ts"), "utf8")
    const serverExportJSDoc = extractServerExportJSDoc(entryPointSource)

    const exampleLines = serverExportJSDoc
      .slice(serverExportJSDoc.indexOf("@example") + "@example".length)
      .replaceAll("*/", "")
      .split("\n")
      .map((line) => line.replace(/^\s*\* ?/v, "").trim())
      .filter((line) => line.length > 0)

    expect(exampleLines).toStrictEqual([
      'import { server, recipe } from "paratix";',
      'import { apt, file, service } from "paratix/modules";',
    ])
  })

  it("server() example constructs a valid definition with pkg.installed", () => {
    // Mirrors the @example block of server() in src/server.ts (keys sorted to
    // satisfy perfectionist/sort-objects; the example itself is unordered).
    const definition = server({
      host: "10.0.0.1",
      name: "web-01",
      run: [pkg.installed("nginx")],
      ssh: { ports: [22], privateKey: "~/.ssh/id_ed25519", user: "root" },
    })

    expect(definition.name).toBe("web-01")
    expect(definition.host).toBe("10.0.0.1")
    expect(definition.run).toHaveLength(1)
    expect(definition.run[0]?.name).toBe("package.installed: nginx")
  })

  it("recipe() example groups modules built with pkg.installed", () => {
    // Mirrors the @example block of recipe() in src/recipe.ts.
    const nginxRecipe = recipe(
      "nginx",
      [
        pkg.installed("nginx"),
        file.template("/etc/nginx/nginx.conf", "./files/nginx.conf.tmpl"),
        service.enabled("nginx"),
      ],
      {
        signals: [service.reload("nginx")],
      }
    )

    expect(nginxRecipe.kind).toBe("recipe")
    expect(nginxRecipe._modules).toHaveLength(3)
    expect(nginxRecipe._modules[0]?.name).toBe("package.installed: nginx")
    expect(nginxRecipe._signals).toHaveLength(1)
  })
})
