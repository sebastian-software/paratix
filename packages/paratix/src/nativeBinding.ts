// Issue #257: the single place that loads the native SSH binding.
import type * as SshNative from "@paratix/ssh-native"

import { createRequire } from "node:module"

import { NativeBindingUnavailableError } from "./nativeBindingError.js"

/** The public API of `@paratix/ssh-native`: the CommonJS `module.exports` object. */
export type NativeBinding = Omit<typeof SshNative, "default">

let pendingBinding: Promise<NativeBinding> | undefined

/**
 * Load `@paratix/ssh-native` once per process.
 *
 * The package is CommonJS, so the API is read from the default export of the
 * dynamic import. Every caller shares one cached promise, including a
 * rejected one: the loader picks the binary from platform, architecture and
 * libc, none of which change while the process runs, and Node does not
 * re-evaluate a CommonJS module whose first evaluation threw, so a retry
 * would only repeat the same failure.
 *
 * @returns The binding API; rejects with the loader's error when no binary
 *   for this platform can be loaded.
 */
export async function loadNativeBinding(): Promise<NativeBinding> {
  pendingBinding ??= import("@paratix/ssh-native").then((module: unknown) => {
    if (typeof module !== "object" || module === null || !("default" in module)) {
      throw new TypeError("Native SSH module has no CommonJS default export")
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Node wraps the typed CommonJS API in default; Bundler resolution does not model that wrapper.
    return module.default as NativeBinding
  })
  return pendingBinding
}

/** Check platform support before resolving any playbook secrets. */
export async function assertNativeBindingAvailable(): Promise<void> {
  try {
    await loadNativeBinding()
  } catch (error) {
    // Read binary-free loader metadata, without evaluating the package entrypoint.
    const loader: unknown = createRequire(import.meta.url)("@paratix/ssh-native/loader.js")
    if (
      typeof loader !== "object" ||
      loader === null ||
      !("SUPPORTED_TARGETS" in loader) ||
      !Array.isArray(loader.SUPPORTED_TARGETS) ||
      !loader.SUPPORTED_TARGETS.every((target: unknown) => typeof target === "string")
    ) {
      throw new Error("Invalid native SSH loader metadata", { cause: error })
    }
    throw new NativeBindingUnavailableError(
      `Paratix could not load its native SSH binding for platform ${process.platform}, architecture ${process.arch}. Supported targets: ${loader.SUPPORTED_TARGETS.join(", ")}. Linux glibc targets require glibc >= 2.35. See https://github.com/sebastian-software/paratix/blob/main/docs/user-guide/README.md#supported-platforms`,
      { cause: error }
    )
  }
}
