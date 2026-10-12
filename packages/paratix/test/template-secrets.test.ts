import { describe, expect, it, vi } from "vitest"

import { environmentMeta, mergeEnvironmentFromMeta } from "../src/meta.js"
import { renderTemplate } from "../src/template.js"

async function markedEnvironment() {
  const code = vi.fn<() => Promise<string>>().mockResolvedValue("001234")
  const ordinary = vi.fn<() => Promise<string>>().mockResolvedValue("ordinary")
  const environment = await mergeEnvironmentFromMeta({ ORDINARY: ordinary }, [
    { ...environmentMeta("CODE", code), resolution: "per-access" },
  ])
  return { code, environment, ordinary }
}

describe("templates with per-access secrets", () => {
  it.each([
    "{{CODE|raw}} {{MISSING|raw}}",
    "{{CODE|raw}} {{ORDINARY|unknown}}",
    "{{CODE|raw}} {{ORDINARY}}",
    "{{CODE|raw}} {{ORDINARY|b64decode}}",
  ])(
    "rejects invalid names, modifiers or ordinary values before a code prompt: %s",
    async (template) => {
      const { code, environment, ordinary } = await markedEnvironment()
      ordinary.mockResolvedValue("%%% invalid base64")
      await expect(renderTemplate(template, environment)).rejects.toThrow(Error)
      expect(code).not.toHaveBeenCalled()
    }
  )

  it("fully awaits ordinary failure before starting any marked resolver in direct library use", async () => {
    const { code, environment, ordinary } = await markedEnvironment()
    const pending = Promise.withResolvers<string>()
    ordinary.mockReturnValue(pending.promise)
    const view = renderTemplate("{{CODE|raw}} {{ORDINARY|raw}}", environment)
    await vi.waitFor(() => {
      expect(ordinary).toHaveBeenCalledOnce()
    })
    expect(code).not.toHaveBeenCalled()
    pending.reject(new Error("ordinary read failed"))
    await expect(view).rejects.toThrow("ordinary read failed")
    expect(code).not.toHaveBeenCalled()
  })

  it("reads each marked key once per render, finishes keys sequentially, and reads afresh on the next render", async () => {
    const pending = Promise.withResolvers<string>()
    const first = vi
      .fn<() => Promise<string>>()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce("fresh-first")
    const second = vi
      .fn<() => Promise<string>>()
      .mockResolvedValueOnce("second")
      .mockResolvedValueOnce("fresh-second")
    const ordinary = vi.fn<() => Promise<string>>().mockResolvedValue("ordinary")
    const environment = await mergeEnvironmentFromMeta({ ORDINARY: ordinary }, [
      { ...environmentMeta("FIRST", first), resolution: "per-access" },
      { ...environmentMeta("SECOND", second), resolution: "per-access" },
    ])
    const template = "{{FIRST|raw}}/{{SECOND|raw}}/{{FIRST|shell}}/{{ORDINARY|raw}}"
    const view = renderTemplate(template, environment)
    await vi.waitFor(() => {
      expect(first).toHaveBeenCalledOnce()
    })
    expect(ordinary).toHaveBeenCalledOnce()
    expect(second).not.toHaveBeenCalled()
    pending.resolve("001234")
    await expect(view).resolves.toBe("001234/second/'001234'/ordinary")
    await expect(renderTemplate(template, environment)).resolves.toBe(
      "fresh-first/fresh-second/'fresh-first'/ordinary"
    )
    expect(first).toHaveBeenCalledTimes(2)
    expect(second).toHaveBeenCalledTimes(2)
  })

  it("retains concurrent per-occurrence reads for ordinary templates", async () => {
    const pending = Promise.withResolvers<string>()
    const ordinary = vi.fn<() => Promise<string>>().mockReturnValue(pending.promise)
    const view = renderTemplate("{{VALUE|raw}}/{{VALUE|raw}}", { VALUE: ordinary })
    await vi.waitFor(() => {
      expect(ordinary).toHaveBeenCalledTimes(2)
    })
    pending.resolve("ordinary")
    await expect(view).resolves.toBe("ordinary/ordinary")
  })
})
