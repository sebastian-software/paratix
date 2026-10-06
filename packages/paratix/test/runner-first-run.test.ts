import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type * as RunnerModule from "../src/runner.js"
import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

// #201: deliberately a STATIC import. The runner is re-imported after
// `vi.resetModules()` below, so it gets its own copy of `firstRunContext`.
// This helper can only observe the runner's scope when the store is a
// process-wide singleton — the same split the published bundles have.
import { isFirstRun, runWithFirstRunFlag } from "../src/firstRunContext.js"
import { resetLiveOutputForTests } from "../src/output.js"
import { getSignalBus, installRunnerTestHooks, makeMockSshClass } from "./helpers/runnerMocks.js"

installRunnerTestHooks()

type Deferred = {
  promise: Promise<undefined>
  resolve: () => void
}

function createDeferred(): Deferred {
  const { promise, resolve } = Promise.withResolvers<undefined>()
  return {
    promise,
    resolve() {
      resolve(undefined)
    },
  }
}

function interleavingModule(input: {
  name: string
  observations: string[]
  reached: Deferred
  release: Deferred
}): Module {
  const { name, observations, reached, release } = input
  return {
    async apply(): Promise<ModuleResult> {
      await Promise.resolve()
      observations.push(`${name}:apply:${String(isFirstRun())}`)
      return { status: "changed" }
    },
    async check(): Promise<"needs-apply"> {
      observations.push(`${name}:check-before-wait:${String(isFirstRun())}`)
      reached.resolve()
      await release.promise
      observations.push(`${name}:check-after-wait:${String(isFirstRun())}`)
      return "needs-apply"
    },
    name,
  }
}

function recordingModule(name: string, observations: string[]): Module {
  return {
    async apply(): Promise<ModuleResult> {
      await Promise.resolve()
      observations.push(`${name}:apply:${String(isFirstRun())}`)
      return { status: "changed" }
    },
    async check(): Promise<"needs-apply"> {
      await Promise.resolve()
      observations.push(`${name}:check:${String(isFirstRun())}`)
      return "needs-apply"
    },
    name,
  }
}

function makeDefinition(run: Module[]): ServerDefinition {
  return {
    host: "1.2.3.4",
    name: "test-server",
    run,
    ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
  }
}

function mockPermissiveSsh(overrides: Parameters<typeof makeMockSshClass>[1] = {}): void {
  vi.doMock("../src/ssh.js", () => ({
    shellQuote: (value: string) => `'${value}'`,
    SshConnectionImpl: makeMockSshClass([], { lifecycle: "permissive", ...overrides }),
  }))
}

async function importRunner(): Promise<typeof RunnerModule> {
  return import("../src/runner.js")
}

describe("runPlaybook first-run scope (#201)", () => {
  let originalFirstRunEnvironment: string | undefined

  beforeEach(() => {
    originalFirstRunEnvironment = process.env.PARATIX_FIRST_RUN
    delete process.env.PARATIX_FIRST_RUN
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
    if (originalFirstRunEnvironment === undefined) {
      delete process.env.PARATIX_FIRST_RUN
    } else {
      process.env.PARATIX_FIRST_RUN = originalFirstRunEnvironment
    }
  })

  describe("opt-in", () => {
    it("exposes firstRun: true to module check and apply, recipe children, and when predicates", async () => {
      mockPermissiveSsh()
      const [{ runPlaybook }, { recipe }, { when }] = await Promise.all([
        importRunner(),
        import("../src/recipe.js"),
        import("../src/builtins.js"),
      ])
      const observations: string[] = []
      const definition = makeDefinition([
        recordingModule("top", observations),
        recipe("bootstrap-recipe", [recordingModule("recipe-child", observations)]),
        when(
          () => {
            observations.push(`when-predicate:${String(isFirstRun())}`)
            return true
          },
          recordingModule("guarded", observations)
        ),
      ])

      await runPlaybook(definition, { firstRun: true })

      // Recipes and `when(...)` re-check their children, so a child may report
      // the same observation more than once; only the distinct values matter.
      expect([...new Set(observations)]).toStrictEqual([
        "top:check:true",
        "top:apply:true",
        "recipe-child:check:true",
        "recipe-child:apply:true",
        "when-predicate:true",
        "guarded:check:true",
        "guarded:apply:true",
      ])
      expect(process.exitCode).toBe(0)
    })

    it("does not write process.env.PARATIX_FIRST_RUN while or after running with firstRun: true", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observedEnvironment: Array<string | undefined> = []
      const observations: string[] = []
      const probe: Module = {
        async apply(): Promise<ModuleResult> {
          await Promise.resolve()
          observedEnvironment.push(process.env.PARATIX_FIRST_RUN)
          observations.push(`probe:apply:${String(isFirstRun())}`)
          return { status: "changed" }
        },
        async check(): Promise<"needs-apply"> {
          await Promise.resolve()
          observedEnvironment.push(process.env.PARATIX_FIRST_RUN)
          return "needs-apply"
        },
        name: "env-probe",
      }

      await runPlaybook(makeDefinition([probe]), { firstRun: true })

      expect(observations).toStrictEqual(["probe:apply:true"])
      expect(observedEnvironment).toStrictEqual([undefined, undefined])
      expect(process.env).not.toHaveProperty("PARATIX_FIRST_RUN")
    })
  })

  describe("default and explicit false", () => {
    it.each([
      ["omitted", undefined],
      ["false", { firstRun: false }],
    ] as const)(
      "keeps isFirstRun() false in check and apply when the option is %s",
      async (_label, options) => {
        mockPermissiveSsh()
        const { runPlaybook } = await importRunner()
        const observations: string[] = []

        await runPlaybook(makeDefinition([recordingModule("plain", observations)]), options)

        expect(observations).toStrictEqual(["plain:check:false", "plain:apply:false"])
      }
    )

    it("does not let a run without the option inherit a surrounding first-run scope", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []

      const callerAfterRun = await runWithFirstRunFlag(async () => {
        await runPlaybook(makeDefinition([recordingModule("masked", observations)]))
        return isFirstRun()
      })

      expect(observations).toStrictEqual(["masked:check:false", "masked:apply:false"])
      expect(callerAfterRun).toBe(true)
    })
  })

  describe("scope lifetime", () => {
    it("returns false in the caller continuation after a firstRun: true run resolves", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []

      await runPlaybook(makeDefinition([recordingModule("settled", observations)]), {
        firstRun: true,
      })

      expect(observations).toStrictEqual(["settled:check:true", "settled:apply:true"])
      expect(isFirstRun()).toBe(false)
    })

    it("masks a nested runPlaybook without the option and restores true for the outer module", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []
      const outer: Module = {
        async apply(): Promise<ModuleResult> {
          observations.push(`outer:before-nested:${String(isFirstRun())}`)
          await runPlaybook(makeDefinition([recordingModule("inner-omitted", observations)]))
          observations.push(`outer:between-nested:${String(isFirstRun())}`)
          await runPlaybook(makeDefinition([recordingModule("inner-false", observations)]), {
            firstRun: false,
          })
          observations.push(`outer:after-nested:${String(isFirstRun())}`)
          return { status: "changed" }
        },
        async check(): Promise<"needs-apply"> {
          await Promise.resolve()
          return "needs-apply"
        },
        name: "outer",
      }

      await runPlaybook(makeDefinition([outer]), { firstRun: true })

      expect(observations).toStrictEqual([
        "outer:before-nested:true",
        "inner-omitted:check:false",
        "inner-omitted:apply:false",
        "outer:between-nested:true",
        "inner-false:check:false",
        "inner-false:apply:false",
        "outer:after-nested:true",
      ])
      expect(isFirstRun()).toBe(false)
    })

    it("isolates two concurrent runs with different firstRun values", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const firstRunObservations: string[] = []
      const regularObservations: string[] = []
      const firstRunReached = createDeferred()
      const regularReached = createDeferred()
      const releaseFirstRun = createDeferred()
      const releaseRegular = createDeferred()

      const firstRunPromise = runPlaybook(
        makeDefinition([
          interleavingModule({
            name: "first",
            observations: firstRunObservations,
            reached: firstRunReached,
            release: releaseFirstRun,
          }),
        ]),
        { firstRun: true }
      )
      const regularPromise = runPlaybook(
        makeDefinition([
          interleavingModule({
            name: "regular",
            observations: regularObservations,
            reached: regularReached,
            release: releaseRegular,
          }),
        ]),
        { firstRun: false }
      )

      // Both runs are suspended inside their check at the same time before
      // either is released, so their async chains genuinely interleave.
      await Promise.all([firstRunReached.promise, regularReached.promise])
      releaseRegular.resolve()
      await regularPromise
      releaseFirstRun.resolve()
      await firstRunPromise

      expect(firstRunObservations).toStrictEqual([
        "first:check-before-wait:true",
        "first:check-after-wait:true",
        "first:apply:true",
      ])
      expect(regularObservations).toStrictEqual([
        "regular:check-before-wait:false",
        "regular:check-after-wait:false",
        "regular:apply:false",
      ])
      expect(isFirstRun()).toBe(false)
    })
  })

  describe("failure paths", () => {
    it("keeps the scope for a throwing apply and returns false to the caller afterwards", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []
      const throwing: Module = {
        async apply(): Promise<ModuleResult> {
          await Promise.resolve()
          observations.push(`throwing:apply:${String(isFirstRun())}`)
          throw new Error("apply exploded")
        },
        async check(): Promise<"needs-apply"> {
          await Promise.resolve()
          return "needs-apply"
        },
        name: "throwing",
      }

      await expect(
        runPlaybook(makeDefinition([throwing]), { firstRun: true })
      ).resolves.toBeUndefined()

      expect(observations).toStrictEqual(["throwing:apply:true"])
      expect(process.exitCode).toBe(1)
      expect(isFirstRun()).toBe(false)
    })

    it("keeps the scope for an apply that returns failed and returns false to the caller afterwards", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []
      const failing: Module = {
        async apply(): Promise<ModuleResult> {
          await Promise.resolve()
          observations.push(`failing:apply:${String(isFirstRun())}`)
          return { error: new Error("declined"), status: "failed" }
        },
        async check(): Promise<"needs-apply"> {
          await Promise.resolve()
          return "needs-apply"
        },
        name: "failing",
      }

      await runPlaybook(makeDefinition([failing]), { firstRun: true })

      expect(observations).toStrictEqual(["failing:apply:true"])
      expect(process.exitCode).toBe(1)
      expect(isFirstRun()).toBe(false)
    })

    it("returns false to the caller continuation after a firstRun: true run rejects", async () => {
      mockPermissiveSsh({ connect: vi.fn().mockRejectedValue(new Error("connect refused")) })
      const { runPlaybook } = await importRunner()

      const callerAfterRejection = await runPlaybook(makeDefinition([]), { firstRun: true }).then(
        () => "resolved",
        (error: unknown) => `${(error as Error).message}:${String(isFirstRun())}`
      )

      expect(callerAfterRejection).toBe("connect refused:false")
      expect(isFirstRun()).toBe(false)
    })

    it("keeps the scope until a shutdown signal ends the run and returns false afterwards", async () => {
      mockPermissiveSsh()
      const { runPlaybook } = await importRunner()
      const observations: string[] = []
      const interrupting: Module = {
        async apply(): Promise<ModuleResult> {
          await Promise.resolve()
          observations.push(`interrupting:apply:${String(isFirstRun())}`)
          return { status: "changed" }
        },
        async check(): Promise<"needs-apply"> {
          observations.push(`interrupting:check:${String(isFirstRun())}`)
          getSignalBus().emit("SIGINT")
          await Promise.resolve()
          return "needs-apply"
        },
        name: "interrupting",
      }

      await runPlaybook(makeDefinition([interrupting]), { firstRun: true })

      expect(observations[0]).toBe("interrupting:check:true")
      expect(process.exitCode).toBe(130)
      expect(isFirstRun()).toBe(false)
    })
  })
})
