import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ServerDefinition } from "../src/types.js"

import {
  applyModuleFilter,
  collectModuleNames,
  createSkipModule,
  parseFilterNames,
  subtreeHasFilterMatch,
} from "../src/moduleFilter.js"
import { recipe } from "../src/recipe.js"
import { installRunnerTestHooks, makeMockSshClass } from "./helpers/runnerMocks.js"

installRunnerTestHooks()

type RecipeView = {
  _modules: Module[]
  _signals?: Module[]
} & Module

const emptyEnv = {}

function asRecipe(module: Module): RecipeView {
  return module as RecipeView
}

function isRecipe(module: Module): boolean {
  return module.kind === "recipe"
}

// Minimal leaf module whose behaviour is irrelevant to filter transformation.
function leaf(name: string): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- interface requires async
    async apply() {
      return { status: "ok" }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- interface requires async
    async check() {
      return "ok"
    },
    name,
  }
}

describe("parseFilterNames", () => {
  it("splits comma-separated values", () => {
    expect(parseFilterNames(["rybbit,palamedes-examples"])).toStrictEqual([
      "rybbit",
      "palamedes-examples",
    ])
  })

  it("flattens repeated occurrences and comma lists together", () => {
    expect(parseFilterNames(["a,b", "c"])).toStrictEqual(["a", "b", "c"])
  })

  it("trims whitespace and drops empty entries", () => {
    expect(parseFilterNames([" a , , b ", "  "])).toStrictEqual(["a", "b"])
  })

  it("de-duplicates while preserving first-seen order", () => {
    expect(parseFilterNames(["b,a", "a,b,c"])).toStrictEqual(["b", "a", "c"])
  })

  it("returns an empty list when nothing but whitespace is given", () => {
    expect(parseFilterNames(["", "  ", ","])).toStrictEqual([])
  })
})

describe("collectModuleNames", () => {
  it("collects recipe and leaf names recursively", () => {
    const tree = [
      leaf("base-setup"),
      recipe("service-layer", [recipe("rybbit", [leaf("rybbit-file")]), leaf("mailcow")]),
    ]
    expect(collectModuleNames(tree)).toStrictEqual(
      new Set(["base-setup", "mailcow", "rybbit", "rybbit-file", "service-layer"])
    )
  })
})

describe("subtreeHasFilterMatch", () => {
  const tree = recipe("service-layer", [recipe("rybbit", [leaf("rybbit-file")]), leaf("mailcow")])

  it("matches a deeply nested descendant", () => {
    expect(subtreeHasFilterMatch(tree, new Set(["rybbit-file"]))).toBe(true)
  })

  it("matches the node itself", () => {
    expect(subtreeHasFilterMatch(tree, new Set(["service-layer"]))).toBe(true)
  })

  it("returns false when neither the node nor a descendant matches", () => {
    expect(subtreeHasFilterMatch(tree, new Set(["unknown"]))).toBe(false)
  })
})

describe("createSkipModule", () => {
  it("renders as skipped without side effects", async () => {
    const skip = createSkipModule("base-setup")
    expect(skip.name).toBe("base-setup")
    expect(skip.local).toBe(true)
    expect(skip._dryRunBlocker).toBe(true)
    await expect(skip.check(null, emptyEnv)).resolves.toBe("needs-apply")
    // eslint-disable-next-line prefer-spread -- calling the module's apply method, not Function.prototype.apply
    await expect(skip.apply(null, emptyEnv)).resolves.toStrictEqual({ status: "skipped" })
  })

  it("reports skipped during a dry-run via _applyDryRun", async () => {
    const skip = createSkipModule("base-setup")
    await expect(skip._applyDryRun?.(null, emptyEnv)).resolves.toStrictEqual({
      _dryRunDetail: "filtered out",
      status: "skipped",
    })
  })
})

describe("applyModuleFilter", () => {
  function buildTree(serviceLayerSignals?: Module[]): {
    baseSetup: Module
    containerRuntimes: Module
    palamedes: Module
    rybbit: Module
    serviceLayer: Module
    tree: Module[]
  } {
    const baseSetup = leaf("base-setup")
    const containerRuntimes = recipe("container-runtimes", [leaf("docker")])
    const rybbit = recipe("rybbit", [leaf("rybbit-file")])
    const palamedes = recipe("palamedes-examples", [leaf("pe-file")])
    const serviceLayer = recipe(
      "service-layer",
      [containerRuntimes, rybbit, palamedes],
      serviceLayerSignals == null ? undefined : { signals: serviceLayerSignals }
    )
    return {
      baseSetup,
      containerRuntimes,
      palamedes,
      rybbit,
      serviceLayer,
      tree: [baseSetup, serviceLayer],
    }
  }

  it("descends into an unselected recipe that holds selected children", () => {
    const { baseSetup, palamedes, rybbit, serviceLayer, tree } = buildTree()
    const filtered = applyModuleFilter(tree, new Set(["palamedes-examples", "rybbit"]))

    // base-setup is not selected → replaced by a skip module.
    expect(filtered[0]).not.toBe(baseSetup)
    expect(filtered[0].name).toBe("base-setup")
    expect(filtered[0].local).toBe(true)
    expect(isRecipe(filtered[0])).toBe(false)

    // service-layer is rebuilt (new reference) but stays a recipe.
    expect(filtered[1]).not.toBe(serviceLayer)
    expect(isRecipe(filtered[1])).toBe(true)

    const children = asRecipe(filtered[1])._modules
    // container-runtimes has no match → skip module.
    expect(children[0].name).toBe("container-runtimes")
    expect(isRecipe(children[0])).toBe(false)
    expect(children[0].local).toBe(true)
    // selected recipes are kept by reference so their whole subtree runs.
    expect(children[1]).toBe(rybbit)
    expect(children[2]).toBe(palamedes)
  })

  it("rebuilds every recipe level down to a selected deep leaf", () => {
    const docker = leaf("docker")
    const podman = leaf("podman")
    const containerRuntimes = recipe("container-runtimes", [docker, podman])
    const rybbit = recipe("rybbit", [leaf("rybbit-file")])
    const serviceLayer = recipe("service-layer", [containerRuntimes, rybbit])

    const filtered = applyModuleFilter([serviceLayer], new Set(["docker"]))

    // Outer recipe holds the match → rebuilt, still a recipe.
    expect(filtered[0]).not.toBe(serviceLayer)
    expect(isRecipe(filtered[0])).toBe(true)

    const level1 = asRecipe(filtered[0])._modules
    // container-runtimes holds the match → rebuilt; rybbit has none → skip module.
    expect(level1[0]).not.toBe(containerRuntimes)
    expect(isRecipe(level1[0])).toBe(true)
    expect(level1[1].name).toBe("rybbit")
    expect(isRecipe(level1[1])).toBe(false)
    expect(level1[1].local).toBe(true)

    // Deepest level: the selected leaf is kept by reference, its sibling skipped.
    const level2 = asRecipe(level1[0])._modules
    expect(level2[0]).toBe(docker)
    expect(level2[1].name).toBe("podman")
    expect(level2[1].local).toBe(true)
  })

  it("keeps the whole subtree when the recipe itself is selected", () => {
    const { baseSetup, serviceLayer, tree } = buildTree()
    const filtered = applyModuleFilter(tree, new Set(["service-layer"]))

    expect(filtered[1]).toBe(serviceLayer)
    expect(filtered[0]).not.toBe(baseSetup)
    expect(filtered[0].local).toBe(true)
  })

  it("keeps a selected leaf and skips a recipe without a match", () => {
    const { baseSetup, serviceLayer, tree } = buildTree()
    const filtered = applyModuleFilter(tree, new Set(["base-setup"]))

    expect(filtered[0]).toBe(baseSetup)
    // service-layer has no matching descendant → skip module, not descended.
    expect(filtered[1]).not.toBe(serviceLayer)
    expect(isRecipe(filtered[1])).toBe(false)
    expect(filtered[1].name).toBe("service-layer")
    expect(filtered[1].local).toBe(true)
  })

  it("never changes the length of the top-level run array", () => {
    const { tree } = buildTree()
    const filtered = applyModuleFilter(tree, new Set(["rybbit"]))
    expect(filtered).toHaveLength(tree.length)
  })

  it("preserves the signals of a rebuilt descend recipe", () => {
    const signals = [leaf("reload")]
    const { serviceLayer, tree } = buildTree(signals)
    const filtered = applyModuleFilter(tree, new Set(["rybbit"]))

    expect(filtered[1]).not.toBe(serviceLayer)
    expect(asRecipe(filtered[1])._signals).toBe(signals)
  })
})

function spyModule(name: string): { apply: ReturnType<typeof vi.fn>; module: Module } {
  const apply = vi.fn().mockResolvedValue({ status: "changed" })
  return {
    apply,
    module: { apply, check: vi.fn().mockResolvedValue("needs-apply"), name },
  }
}

describe("applyModuleFilter end-to-end via runPlaybook", () => {
  beforeEach(() => {
    vi.resetModules()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("runs only selected nodes, renders the rest as skipped, and counts top-level skips", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (value: string) => `'${value}'`,
      SshConnectionImpl: makeMockSshClass([], { lifecycle: "permissive" }),
    }))
    const logs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "))
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })

    const { runPlaybook } = await import("../src/runner.js")

    const base = spyModule("base-setup")
    const docker = spyModule("docker")
    const rybbitFile = spyModule("rybbit-file")
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "s1",
      run: applyModuleFilter(
        [
          base.module,
          recipe("service-layer", [
            recipe("container-runtimes", [docker.module]),
            recipe("rybbit", [rybbitFile.module]),
          ]),
        ],
        new Set(["rybbit"])
      ),
      ssh: { ports: [22], user: "root" },
    }

    await runPlaybook(definition)

    // Selected subtree ran; every skipped node was never applied.
    expect(rybbitFile.apply).toHaveBeenCalledTimes(1)
    expect(base.apply).not.toHaveBeenCalled()
    expect(docker.apply).not.toHaveBeenCalled()

    const output = logs.join("\n")
    // Skipped nodes are still rendered — both top-level and nested.
    expect(output).toContain("base-setup")
    expect(output).toContain("container-runtimes")
    expect(output).toContain("skipped")
    // The top-level skip is counted in the summary; the nested skip is only rendered.
    expect(output).toContain("1 skipped")
    expect(output).toContain("1 changed")
    expect(process.exitCode).toBe(0)
  })

  it("renders a nested skip as skipped with a filtered-out detail during a dry-run", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (value: string) => `'${value}'`,
      SshConnectionImpl: makeMockSshClass([], { lifecycle: "permissive" }),
    }))
    const logs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "))
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })

    const { runPlaybook } = await import("../src/runner.js")

    const rybbitFile = spyModule("rybbit-file")
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "s1",
      run: applyModuleFilter(
        [
          leaf("base-setup"),
          recipe("service-layer", [
            recipe("container-runtimes", [leaf("docker")]),
            recipe("rybbit", [rybbitFile.module]),
          ]),
        ],
        new Set(["rybbit"])
      ),
      ssh: { ports: [22], user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    const output = logs.join("\n")
    // The nested container-runtimes skip is rendered as skipped with the detail.
    expect(output).toContain("container-runtimes")
    expect(output).toContain("filtered out")
    expect(output).toContain("skipped")
    expect(process.exitCode).toBe(0)
  })
})
