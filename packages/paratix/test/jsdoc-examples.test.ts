import { describe, expect, it } from "vitest"

import { file } from "../src/modules/file.js"
import { pkg } from "../src/modules/package.js"
import { service } from "../src/modules/service.js"
import { recipe } from "../src/recipe.js"
import { server } from "../src/server.js"

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
