import type { SelectFunction, SelectOption } from "./promptUi.js"

import { escapeCliControlCharacters } from "./cliFormat.js"
import {
  type HostFingerprintScanResult,
  loadHostKeyScanner,
  readHostFingerprint,
} from "./hostFingerprintBootstrap.js"

export type HostFingerprintScanner = (host: string) => Promise<HostFingerprintScanResult>
export type HostFingerprintPromptOptions = {
  loadScanner?: () => Promise<HostFingerprintScanner>
  scanner?: HostFingerprintScanner
}

const HOST_FINGERPRINT_OPTIONS: Array<SelectOption<"placeholder" | "scan">> = [
  {
    description:
      "Read the currently presented host key from SSH port 22 and pin its fingerprint in server.ts.",
    label: "Scan host key",
    value: "scan",
  },
  {
    description:
      "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified expectedHostFingerprint/PublicKey is added.",
    label: "Skip pinning",
    value: "placeholder",
  },
]

// R-0000122: after scanning the live host key we must not silently pin the
// fingerprint (blind TOFU). The operator confirms the scanned value out of
// band before it is written into server.ts.
const HOST_FINGERPRINT_CONFIRM_OPTIONS: Array<SelectOption<"discard" | "pin">> = [
  {
    description:
      "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified host-key pin is added.",
    label: "Discard and skip",
    value: "discard",
  },
  {
    description:
      "Pin the scanned fingerprint into server.ts. Only choose this if the algorithm and fingerprint match an out-of-band reference (server console, provider dashboard, ssh-keyscan over a trusted network).",
    label: "Pin this fingerprint",
    value: "pin",
  },
]

// R-0000122: render the scanned host key on isolated lines so an operator
// can copy it cleanly for an out-of-band comparison.
function describeScanResult(host: string, result: HostFingerprintScanResult): string {
  const escapedHost = escapeCliControlCharacters(host)
  return [
    "",
    `Scanned SSH host key for ${escapedHost}:22`,
    `  algorithm:   ${escapeCliControlCharacters(result.algorithm)}`,
    `  fingerprint:`,
    `    ${escapeCliControlCharacters(result.fingerprint)}`,
    "",
    "Compare this value against an out-of-band reference before pinning it.",
    "",
  ].join("\n")
}

// R-0000128: explicit type for the host-fingerprint prompt so callers and
// tests can express any combination of select responses while keeping the
// internal call sites strongly typed.
export type HostFingerprintSelectValue = "discard" | "pin" | "placeholder" | "scan"

/**
 * Run a typed select on a chooser parameterised over a wider value set.
 * The chooser is contravariant in `TValue` for the options parameter, so
 * passing a narrow `Array<SelectOption<TNarrow>>` is sound, but the
 * returned `TWide` must be narrowed to `TNarrow` at runtime.
 *
 * R-0000231: validate the returned value against the offered options at
 * runtime before casting. A stubbed or buggy chooser that returns a value
 * outside the options array would otherwise let an unrelated branch run
 * (silent type-confusion). We surface a hard error so the failure mode is
 * obvious instead of masquerading as a different option.
 *
 * @param choose - The chooser parameterised over a wider value set.
 * @param prompt - The prompt text to display.
 * @param options - The options offered to the operator.
 * @returns The selected value, narrowed to `TNarrow`.
 */
async function chooseFrom<TWide extends string, TNarrow extends TWide>(
  choose: SelectFunction<TWide>,
  prompt: string,
  options: Array<SelectOption<TNarrow>>
): Promise<TNarrow> {
  const result = await choose(prompt, options)
  // R-0000231: runtime narrowing. A chooser that returns a value not present
  // in the offered options is treated as a programming error. We emit a
  // generic diagnostic so attacker-controlled labels cannot leak into the
  // message.
  const matchedOption = options.find((option) => option.value === result)
  if (matchedOption == null) {
    throw new Error(
      `Internal error: select returned an unexpected option for prompt ${JSON.stringify(prompt)}.`
    )
  }
  return matchedOption.value
}

function failAfterScanFailure(host: string, error: unknown): never {
  const reason = escapeCliControlCharacters(error instanceof Error ? error.message : String(error))
  const escapedHost = escapeCliControlCharacters(host)
  // R-0000128: word the failure as an explicit MITM-warning so an operator
  // does not dismiss it as a transient network glitch.
  console.error(
    [
      "",
      `Warning: failed to scan SSH host key for ${escapedHost}.`,
      `  reason: ${reason}`,
      "  This may indicate a man-in-the-middle attempt or a firewall blocking",
      "  the SSH handshake. Verify the host key out of band before pinning",
      "  any fingerprint into server.ts.",
      "",
    ].join("\n")
  )

  throw new Error(
    `Aborting scaffolding: host-key scan for ${escapedHost} failed (${reason}). ` +
      `Re-run create-paratix once the SSH handshake to ${escapedHost}:22 succeeds, ` +
      `or pass --expected-host-fingerprint with an out-of-band verified fingerprint.`
  )
}

/**
 * Run the scan-and-confirm flow for a host fingerprint.
 *
 * @param parameters - Scan flow parameters.
 * @param parameters.choose - Interactive select function.
 * @param parameters.host - The remote host to scan.
 * @param parameters.scanner - Implementation of the SSH host-key scan.
 * @returns The pinned fingerprint, or `undefined` when the operator
 *   declines to pin.
 */
async function scanAndConfirmFingerprint(parameters: {
  choose: SelectFunction<HostFingerprintSelectValue>
  host: string
  scanner: (host: string) => Promise<HostFingerprintScanResult>
}): Promise<string | undefined> {
  const { choose, host, scanner } = parameters

  let result: HostFingerprintScanResult
  try {
    result = await scanner(host)
  } catch (error) {
    // R-0000128: do not silently swallow scan failures. The helper
    // returns `never` and unconditionally throws (R-0000735 — no
    // second throw needed), so `result` is guaranteed to be assigned
    // for the remainder of the function.
    failAfterScanFailure(host, error)
  }

  // R-0000122: surface the scanned material on isolated lines so the
  // operator can copy and compare it against an out-of-band reference
  // before pinning it into server.ts.
  console.log(describeScanResult(host, result))

  const confirmation = await chooseFrom(
    choose,
    `Pin the scanned host fingerprint for ${escapeCliControlCharacters(host)}?`,
    HOST_FINGERPRINT_CONFIRM_OPTIONS
  )
  if (confirmation !== "pin") {
    const escapedHost = escapeCliControlCharacters(host)
    throw new Error(
      `Aborting scaffolding: scanned host fingerprint for ${escapedHost} was not pinned. ` +
        `Re-run create-paratix and pin a verified fingerprint, or pass --expected-host-fingerprint.`
    )
  }
  return result.fingerprint
}

async function loadFingerprintScanner(): Promise<HostFingerprintScanner> {
  const nativeScanner = await loadHostKeyScanner()
  return async (host) =>
    readHostFingerprint(host, {
      allowHostKeyScan: true,
      scanner: nativeScanner,
    })
}

async function resolveScanner(
  options: HostFingerprintPromptOptions | HostFingerprintScanner | undefined
): Promise<HostFingerprintScanner | undefined> {
  if (typeof options === "function") return options
  if (options?.scanner != null) return options.scanner
  try {
    return await (options?.loadScanner ?? loadFingerprintScanner)()
  } catch {
    console.log(
      "Host-key scanning is unavailable on this system. " +
        "Pass --expected-host-fingerprint with an out-of-band verified value, " +
        "or keep the placeholder and configure a verified host key before connecting."
    )
    return undefined
  }
}

export async function selectHostFingerprint(
  host: string,
  choose: SelectFunction<HostFingerprintSelectValue>,
  options?: HostFingerprintPromptOptions | HostFingerprintScanner
): Promise<string | undefined> {
  const scanner = await resolveScanner(options)
  const hostKeyMode = await chooseFrom(
    choose,
    `How should create-paratix bootstrap the SSH host key for ${escapeCliControlCharacters(host)}?`,
    scanner == null
      ? HOST_FINGERPRINT_OPTIONS.filter((option) => option.value !== "scan")
      : HOST_FINGERPRINT_OPTIONS
  )
  if (hostKeyMode !== "scan" || scanner == null) return undefined
  return scanAndConfirmFingerprint({ choose, host, scanner })
}
