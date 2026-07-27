import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { fail, firstRun, when } from "../src/builtins.js"
import { createConditionalModule } from "../src/conditionalModules.js"
import { dryRunRecipeModule } from "../src/dryRunRecipe.js"
import { resetLiveOutputForTests } from "../src/output.js"
import { recipe } from "../src/recipe.js"
import { createMockSsh } from "./helpers/mockSsh.js"
import { makeMockSshClass } from "./helpers/runnerMocks.js"

const emptyEnv: Environment = {}
const SOURCE_DIRECTORY = join(import.meta.dirname, "..", "src")

// A plain leaf step: no `_applyDryRun`, no `_dryRunBlocker`, no
// `_dryRunMetaProducer`. Itemization of a marker-free subtree is the whole
// point of these tests, so every helper module here stays marker-free unless a
// test explicitly opts into a marker.
function makeSpyModule(name: string): Module {
  return {
    apply: vi.fn().mockResolvedValue({ status: "changed" }),
    check: vi.fn().mockResolvedValue("needs-apply"),
    name,
  }
}

function expectMarkerFree(module: Module): void {
  expect(module._applyDryRun).toBeUndefined()
  expect(module._dryRunBlocker).toBeUndefined()
  expect(module._dryRunMetaProducer).toBeUndefined()
}

// Force the non-animated output path so every result line lands on console.log
// and can be asserted verbatim, including its indentation.
async function withoutTty<T>(body: () => Promise<T>): Promise<T> {
  const originalIsTTY = process.stdout.isTTY
  Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })
  try {
    return await body()
  } finally {
    Object.defineProperty(process.stdout, "isTTY", {
      configurable: true,
      value: originalIsTTY,
    })
  }
}

describe("when(...) block itemization", () => {
  let consoleLogs: string[]
  let consoleErrors: string[]

  beforeEach(() => {
    consoleLogs = []
    consoleErrors = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
  })

  it("itemizes a marker-free block in a dry run", async () => {
    const leafOne = makeSpyModule("leaf-one")
    const leafTwo = makeSpyModule("leaf-two")
    // Pin the repro to a marker-free subtree: a block whose children carry any
    // of _applyDryRun / _dryRunBlocker / _dryRunMetaProducer used to receive a
    // dry-run hook and would pass this assertion against the old source too.
    expectMarkerFree(leafOne)
    expectMarkerFree(leafTwo)
    const block = createConditionalModule({
      condition: () => true,
      modules: [leafOne, leafTwo],
      name: "guard-block",
    })

    const result = await withoutTty(async () =>
      dryRunRecipeModule({
        environment: emptyEnv,
        recipeModule: recipe("outer-recipe", [block]),
        ssh: createMockSsh(),
      })
    )

    const output = consoleLogs.join("\n")
    expect(result.status).toBe("changed")
    expect(output).toContain("\n  · [guard-block]")
    expect(output).toContain("\n  · · ↺  leaf-one")
    expect(output).toContain("\n  · · ↺  leaf-two")
    expect(output).toContain("\n  · ↺  guard-block")
  })

  it("exposes _applyDryRun unconditionally on a marker-free block", () => {
    const leaf = makeSpyModule("leaf")
    expectMarkerFree(leaf)
    const block = createConditionalModule({
      condition: () => true,
      modules: [leaf],
      name: "guard-block",
    })

    // Without the hook the caller's shouldExecuteApplyDuringDryRun would refuse
    // to descend and the block's output layer would never run.
    expect(block._applyDryRun).toStrictEqual(expect.any(Function))
  })

  it("itemizes a marker-free block in apply mode", async () => {
    const changedLeaf = makeSpyModule("changed-leaf")
    const okLeaf: Module = {
      apply: vi.fn(),
      check: vi.fn().mockResolvedValue("ok"),
      name: "ok-leaf",
    }
    const block = createConditionalModule({
      condition: () => true,
      modules: [changedLeaf, okLeaf],
      name: "guard-block",
    })

    const applyOuterRecipe = recipe("outer-recipe", [block]).apply
    const result = await withoutTty(async () => applyOuterRecipe(null, emptyEnv))

    const output = consoleLogs.join("\n")
    expect(result.status).toBe("changed")
    expect(output).toContain("\n  · [guard-block]")
    expect(output).toContain("\n  · · ↺  changed-leaf")
    expect(output).toContain("\n  · · ✓  ok-leaf")
    expect(output).toContain("\n  · ↺  guard-block")
    expect(okLeaf.apply).not.toHaveBeenCalled()
  })

  it("opens a top-level block at the same depth a top-level recipe header uses", async () => {
    const leaf = makeSpyModule("leaf")
    const block = createConditionalModule({
      condition: () => true,
      modules: [leaf],
      name: "guard-block",
    })

    await withoutTty(async () => block._applyDryRun?.(createMockSsh(), emptyEnv))

    // The block's own closing line belongs to the caller, so a directly
    // dispatched block prints exactly its header plus one line per child.
    expect(consoleLogs).toStrictEqual(["  [guard-block]", expect.stringContaining("  · ↺  leaf")])
  })

  it("nests a recipe inside the block one level deeper than the block's own line", async () => {
    const leaf = makeSpyModule("leaf")
    const block = createConditionalModule({
      condition: () => true,
      modules: [recipe("inner-recipe", [leaf])],
      name: "guard-block",
    })

    await withoutTty(async () =>
      dryRunRecipeModule({
        environment: emptyEnv,
        recipeModule: recipe("outer-recipe", [block]),
        ssh: createMockSsh(),
      })
    )

    const output = consoleLogs.join("\n")
    expect(output).toContain("\n  · [guard-block]")
    expect(output).toContain("\n  · · [inner-recipe]")
    expect(output).toContain("\n  · · · ↺  leaf")
    expect(output).toContain("\n  · · ↺  inner-recipe")
    expect(output).toContain("\n  · ↺  guard-block")
  })

  it("compounds the indentation of a block nested inside a block", async () => {
    const leaf = makeSpyModule("leaf")
    const innerBlock = createConditionalModule({
      condition: () => true,
      modules: [leaf],
      name: "inner-block",
    })
    const outerBlock = createConditionalModule({
      condition: () => true,
      modules: [innerBlock],
      name: "outer-block",
    })

    await withoutTty(async () =>
      dryRunRecipeModule({
        environment: emptyEnv,
        recipeModule: recipe("outer-recipe", [outerBlock]),
        ssh: createMockSsh(),
      })
    )

    const output = consoleLogs.join("\n")
    expect(output).toContain("\n  · [outer-block]")
    expect(output).toContain("\n  · · [inner-block]")
    expect(output).toContain("\n  · · · ↺  leaf")
    expect(output).toContain("\n  · · ↺  inner-block")
    expect(output).toContain("\n  · ↺  outer-block")
  })

  it("renders a false guard as a single skipped line without a header", async () => {
    const leaf = makeSpyModule("leaf")
    const block = createConditionalModule({
      condition: () => false,
      modules: [leaf],
      name: "guard-block",
    })

    await withoutTty(async () =>
      dryRunRecipeModule({
        environment: emptyEnv,
        recipeModule: recipe("outer-recipe", [block]),
        ssh: createMockSsh(),
      })
    )

    const blockLines = consoleLogs.filter((line) => line.includes("guard-block"))
    expect(blockLines).toHaveLength(1)
    expect(blockLines[0]).toContain("skipped")
    expect(consoleLogs.some((line) => line.includes("[guard-block]"))).toBe(false)
    expect(leaf.check).not.toHaveBeenCalled()
  })

  it("prints a header and no child lines for an empty block and aggregates it as ok", async () => {
    const block = createConditionalModule({
      condition: () => true,
      modules: [],
      name: "guard-block",
    })

    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await withoutTty(async () => block.apply(null, emptyEnv))

    expect(result.status).toBe("ok")
    expect(consoleLogs).toStrictEqual(["  [guard-block]"])
  })

  it("reports a failing child once and does not repeat its diagnostics in a dry run", async () => {
    const laterSibling = makeSpyModule("later-sibling")
    const block = createConditionalModule({
      condition: () => true,
      modules: [fail("stop here"), laterSibling],
      name: "guard-block",
    })

    const result = await withoutTty(async () =>
      dryRunRecipeModule({
        environment: emptyEnv,
        recipeModule: recipe("outer-recipe", [block]),
        ssh: createMockSsh(),
      })
    )

    expect(result.status).toBe("failed")
    expect(consoleLogs.findLast((line) => line.includes("guard-block"))).toContain("failed")
    // The failing child already reported the error itself; the block's closing
    // line must not repeat it.
    expect(consoleErrors.filter((line) => line.includes("[fail] stop here"))).toHaveLength(1)
    expect(laterSibling.check).not.toHaveBeenCalled()
  })

  it("propagates a failing child's error out of an apply so the caller reports it", async () => {
    const block = createConditionalModule({
      condition: () => true,
      modules: [fail("stop here")],
      name: "guard-block",
    })

    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await withoutTty(async () => block.apply(null, emptyEnv))

    expect(result.status).toBe("failed")
    expect(result.error?.message).toBe("[fail] stop here")
    // Nothing was printed to stderr inside the block: the surrounding runner or
    // recipe prints the propagated error exactly once.
    expect(consoleErrors).toStrictEqual([])
  })

  it("breaks out of the child loop and propagates _stopRun from a dry-run blocker", async () => {
    const laterSibling = makeSpyModule("later-sibling")
    const block = createConditionalModule({
      condition: () => true,
      modules: [firstRun.stop(), laterSibling],
      name: "guard-block",
    })

    const result = await withoutTty(async () =>
      dryRunRecipeModule({
        environment: { PARATIX_FIRST_RUN: "true" },
        recipeModule: recipe("outer-recipe", [block]),
        ssh: createMockSsh(),
      })
    )

    expect(result.stopRun).toBe(true)
    expect(laterSibling.check).not.toHaveBeenCalled()
  })

  it("stops the child loop when a shutdown signal arrives mid-block", async () => {
    let receivedSignal: NodeJS.Signals | null = null
    const firstStep: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        receivedSignal = "SIGINT"
        return "needs-apply"
      },
      name: "first-step",
    }
    const secondStep = makeSpyModule("second-step")
    const block = createConditionalModule({
      condition: () => true,
      modules: [firstStep, secondStep],
      name: "guard-block",
    })

    await withoutTty(async () =>
      block.apply(null, emptyEnv, { shutdownSignal: () => receivedSignal })
    )

    expect(firstStep.apply).not.toHaveBeenCalled()
    expect(secondStep.check).not.toHaveBeenCalled()
  })
})

describe("when(...) per-child dry-run dispatch", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
  })

  it("runs a _dryRunDiffProducer child only with diff enabled and never a marker-free child", async () => {
    const diffProducer: Module = {
      _applyDryRun: vi.fn().mockResolvedValue({ diff: "-old\n+new", status: "changed" }),
      _dryRunDiffProducer: true,
      apply: vi.fn(),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "diff-producer",
    }
    const plainStep = makeSpyModule("plain-step")
    const block = createConditionalModule({
      condition: () => true,
      modules: [diffProducer, plainStep],
      name: "guard-block",
    })

    await withoutTty(async () => block._applyDryRun?.(createMockSsh(), emptyEnv, { diff: false }))
    expect(diffProducer._applyDryRun).not.toHaveBeenCalled()

    await withoutTty(async () => block._applyDryRun?.(createMockSsh(), emptyEnv, { diff: true }))
    expect(diffProducer._applyDryRun).toHaveBeenCalledTimes(1)

    // The marker-free child is itemized but never applied in either mode.
    expect(diffProducer.apply).not.toHaveBeenCalled()
    expect(plainStep.apply).not.toHaveBeenCalled()
    expect(plainStep.check).toHaveBeenCalledTimes(2)
  })

  it("keeps the per-child marker gate in the shared dispatch module only", async () => {
    const sources = await Promise.all(
      ["conditionalModules.ts", "conditionalExecution.ts"].map(async (fileName) =>
        readFile(join(SOURCE_DIRECTORY, fileName), "utf8")
      )
    )

    // A private copy of the marker gate inside the conditional path is exactly
    // how the itemization gaps of #160 and #163 arose. The gate lives in
    // dryRunDispatch.ts and is reached through executeDryRunChildModule.
    for (const source of sources) {
      expect(source).not.toContain("_dryRunBlocker")
      expect(source).not.toContain("_dryRunMetaProducer")
      expect(source).not.toContain("_dryRunDiffProducer")
    }
    expect(sources.join("\n")).toContain("executeDryRunChildModule")
  })
})

describe("when(...) guard evaluation", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
  })

  it("evaluates a false guard exactly once across check and apply", async () => {
    const condition = vi.fn(() => false)
    const block = createConditionalModule({
      condition,
      modules: [makeSpyModule("leaf")],
      name: "guard-block",
    })

    await expect(block.check(null, emptyEnv)).resolves.toBe("needs-apply")
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await block.apply(null, emptyEnv)

    expect(result.status).toBe("skipped")
    expect(condition).toHaveBeenCalledTimes(1)
  })

  it("never serves a stale guard result to a later run", async () => {
    let guardResult = false
    const leaf = makeSpyModule("leaf")
    const block = createConditionalModule({
      condition: () => guardResult,
      modules: [leaf],
      name: "guard-block",
    })

    await block.check(null, emptyEnv)
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const firstRunResult = await block.apply(null, emptyEnv)
    expect(firstRunResult.status).toBe("skipped")

    guardResult = true
    await block.check(null, emptyEnv)
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const secondRunResult = await withoutTty(async () => block.apply(null, emptyEnv))

    expect(secondRunResult.status).toBe("changed")
    expect(leaf.apply).toHaveBeenCalledTimes(1)
  })

  it("writes no memo when the guard condition throws", async () => {
    const condition = vi
      .fn<() => boolean>()
      .mockImplementationOnce(() => {
        throw new Error("guard exploded")
      })
      .mockReturnValue(false)
    const block = createConditionalModule({
      condition,
      modules: [makeSpyModule("leaf")],
      name: "guard-block",
    })

    await expect(block.check(null, emptyEnv)).rejects.toThrow("guard exploded")

    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await block.apply(null, emptyEnv)

    expect(result.status).toBe("skipped")
    expect(condition).toHaveBeenCalledTimes(2)
  })

  it("names a single-module block in the singular", () => {
    expect(when(() => true, makeSpyModule("leaf")).name).toBe("when: conditional (1 module)")
    expect(when(() => true, makeSpyModule("a"), makeSpyModule("b")).name).toBe(
      "when: conditional (2 modules)"
    )
    expect(when(() => true).name).toBe("when: conditional (0 modules)")
  })
})

describe("when(...) run summary", () => {
  beforeEach(() => {
    vi.resetModules()
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("counts a false-condition block under skipped instead of ok", async () => {
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

    const [{ runPlaybook }, builtins] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const guarded: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "guarded-step",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [builtins.when(() => false, guarded)],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await withoutTty(async () => runPlaybook(definition, { dryRun: true }))

    const output = logs.join("\n")
    expect(output).toContain("1 skipped")
    expect(output).toContain("0 ok")
    expect(guarded.check).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(0)
  })
})
