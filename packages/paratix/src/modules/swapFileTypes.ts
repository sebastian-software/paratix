// Shared type definitions for the swap.file module helpers. Lives in its
// own file so `swapFileHelpers` and `swapFstabHelpers` can both import it
// without creating an import cycle.

export type NormalizedSwapFileOptions = {
  expectedFstabLine: null | string
  mode: string
  path: string
  sizeBytes: number
  sizeForCommand: string
  state: "absent" | "present"
}

export type SwapFilePathClassification =
  { reason: string; state: "unsafe" } | { state: "managed-swap-file" } | { state: "missing" }
