import { afterEach, describe, expect, it, vi } from "vitest"

// Fakes of the native module: no test loads the real binary.
describe("loadNativeBinding", () => {
  afterEach(() => {
    vi.doUnmock("@paratix/ssh-native")
    vi.resetModules()
  })

  it("reads the API from the CommonJS default export once", async () => {
    const api = { connect: vi.fn(), scan: vi.fn() }
    const factory = vi.fn(() => ({ default: api }))
    vi.doMock("@paratix/ssh-native", factory)
    const { assertNativeBindingAvailable, loadNativeBinding } =
      await import("../src/nativeBinding.js")
    await expect(assertNativeBindingAvailable()).resolves.toBeUndefined()
    const [first, second] = await Promise.all([loadNativeBinding(), loadNativeBinding()])
    expect(first).toBe(api)
    expect(second).toBe(api)
    expect(await loadNativeBinding()).toBe(api)
    expect(factory).toHaveBeenCalledOnce()
  })

  it("keeps a failed load cached and rejects every caller with the loader error", async () => {
    const loaderError = new Error("no native binary for linux-riscv64")
    const factory = vi.fn(() => {
      throw loaderError
    })
    vi.doMock("@paratix/ssh-native", factory)
    const { loadNativeBinding } = await import("../src/nativeBinding.js")
    const first = await loadNativeBinding().catch((error: unknown) => error)
    const second = await loadNativeBinding().catch((error: unknown) => error)
    expect(second).toBe(first)
    // Vitest wraps a throwing mock factory; the loader error stays the cause.
    expect((first as Error).cause).toBe(loaderError)
    expect(factory).toHaveBeenCalledOnce()
  })
  it("adds platform guidance while keeping the loader failure as cause", async () => {
    vi.doMock("@paratix/ssh-native", () => {
      throw new Error("loader installation details")
    })
    const { assertNativeBindingAvailable, loadNativeBinding } =
      await import("../src/nativeBinding.js")
    const cause = await loadNativeBinding().catch((error: unknown) => error)
    await expect(assertNativeBindingAvailable()).rejects.toMatchObject({
      cause,
      message: expect.stringContaining(
        `platform ${process.platform}, architecture ${process.arch}`
      ),
    })
    await expect(assertNativeBindingAvailable()).rejects.toThrow("linux-x64-gnu")
    await expect(assertNativeBindingAvailable()).rejects.toThrow("glibc >= 2.35")
    await expect(assertNativeBindingAvailable()).rejects.toThrow("#supported-platforms")
  })
})
