// Issue #257: the single place that loads the native SSH binding.
import type * as SshNative from "@paratix/ssh-native"

/** The public API of `@paratix/ssh-native`: the CommonJS `module.exports` object. */
export type NativeBinding = (typeof SshNative)["default"]

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
  pendingBinding ??= import("@paratix/ssh-native").then((module) => module.default)
  return pendingBinding
}
