/**
 * Shared helper for the `resolveHost` callback used by reboot-style modules
 * (`system.reboot`, `releaseUpgrade.upgrade`). Wraps the caller-supplied
 * resolver in a wall-clock timeout so a hanging DNS/cloud lookup cannot
 * stall the entire playbook indefinitely.
 *
 * R-0000243: previously the resolver was awaited unconditionally — a stuck
 * cloud-metadata or DNS request would keep the module pending forever
 * because the runner has no inherent timeout for module callbacks.
 */
import type { ModuleMetaEntry, ModuleResult } from "../types.js"

import { meta } from "../meta.js"
import { failed } from "../moduleFailure.js"

const MILLISECONDS_PER_SECOND = 1000
const SECONDS_PER_HALF_MINUTE = 30
export const RESOLVE_HOST_DEFAULT_TIMEOUT_MS = SECONDS_PER_HALF_MINUTE * MILLISECONDS_PER_SECOND

/**
 * R-0000575: callable shape for `resolveHost`. The optional `AbortSignal`
 * argument lets callers like `resolveHostWithTimeout` signal cancellation
 * when the wall-clock timeout elapses, so a long-running DNS/cloud lookup
 * can drop its in-flight work instead of running to completion in the
 * background. The argument is optional to keep existing zero-arg callbacks
 * source-compatible — callers that don't care can keep their current
 * signature.
 */
export type ResolveHostCallback = (signal?: AbortSignal) => Promise<string>

// The resolved host flows into SSH reconnect handling after reboot-style
// modules have already triggered a remote reboot. Keep validation local to
// this helper so only resolveHost-driven reconnect targets are constrained;
// do not tighten global `meta.systemHost` emission.
const REBOOT_HOST_MAX_LENGTH = 253
const REBOOT_HOST_MAX_LABEL_LENGTH = 63
const REBOOT_HOST_HOSTNAME_LABEL_PATTERN = /^[a-z0-9\x2d]+$/iv
const REBOOT_HOST_HOSTNAME_LABEL_EDGE_PATTERN = /^[a-z0-9]$/iv
const REBOOT_HOST_IPV6_CHARSET_PATTERN = /^[0-9a-f:]+$/iv

function isValidRebootHostLabel(label: string): boolean {
  if (label === "" || label.length > REBOOT_HOST_MAX_LABEL_LENGTH) return false
  if (!REBOOT_HOST_HOSTNAME_LABEL_PATTERN.test(label)) return false
  const first = label.at(0)
  const last = label.at(-1)
  return (
    first !== undefined &&
    last !== undefined &&
    REBOOT_HOST_HOSTNAME_LABEL_EDGE_PATTERN.test(first) &&
    REBOOT_HOST_HOSTNAME_LABEL_EDGE_PATTERN.test(last)
  )
}

function isValidRebootHost(host: string): boolean {
  if (host.length === 0 || host.length > REBOOT_HOST_MAX_LENGTH) return false
  if (/\s/v.test(host)) return false
  // IPv6 is identified by the presence of `:`; strip optional brackets
  // before checking the charset so `[2001:db8::1]` is accepted as well.
  if (host.includes(":")) {
    const stripped = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host
    return REBOOT_HOST_IPV6_CHARSET_PATTERN.test(stripped)
  }
  const labels = host.split(".")
  return labels.every((label) => isValidRebootHostLabel(label))
}

/**
 * Run `resolveHost` with a wall-clock timeout. Rejects with a descriptive
 * Error when the resolver does not settle in time so callers can surface a
 * `failed` module result instead of stalling.
 *
 * R-0000575: the resolver receives an `AbortSignal` which is aborted when
 * the timeout fires. Resolver implementations that honor the signal can
 * release any in-flight resources (DNS queries, HTTP requests) instead of
 * running to completion in the background.
 *
 * @param resolveHost - The user-supplied resolver callback. Will be invoked
 *   with an `AbortSignal` that fires once the timeout elapses.
 * @param timeoutMs - Optional override; defaults to
 *   {@link RESOLVE_HOST_DEFAULT_TIMEOUT_MS}.
 * @returns The resolved host string.
 * @throws {Error} When the resolver throws, or when the timeout elapses
 *   before the resolver settles.
 */
export async function resolveHostWithTimeout(
  resolveHost: ResolveHostCallback,
  timeoutMs: number = RESOLVE_HOST_DEFAULT_TIMEOUT_MS
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const controller = new AbortController()
    const timer = setTimeout(() => {
      // R-0000575: signal cancellation to the resolver before rejecting so
      // any abortable work (DNS, HTTP) tied to the supplied signal stops
      // promptly. Resolvers that ignore the signal still get the historical
      // behaviour: they keep running, just without anyone observing the
      // eventual result.
      controller.abort()
      reject(new Error(`resolveHost timed out after ${String(timeoutMs)}ms`))
    }, timeoutMs)
    // R-0000849: allow the event loop to exit cleanly while the timer is
    // pending. Without `unref`, a long timeout would keep the process alive
    // even when the resolver has already settled via a different code path
    // that does not run inside this Promise (e.g. process shutdown).
    timer.unref()
    resolveHost(controller.signal).then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (error: unknown) => {
        clearTimeout(timer)
        reject(error instanceof Error ? error : new Error(String(error)))
      }
    )
  })
}

/**
 * Build the `[system.reboot, system.host?]` meta entry list and bound the
 * optional resolver in {@link resolveHostWithTimeout} so failures surface
 * as a {@link ModuleResult} with `status: "failed"` instead of propagating
 * as unhandled rejections. Resolver failures preserve the `system.reboot`
 * meta entry because the reboot trigger already succeeded before host
 * resolution runs.
 *
 * @param options - Caller-supplied resolver, error label and override.
 * @param options.failurePrefix - Module label prepended to the failure message.
 * @param options.resolveHost - Optional resolver returning the new host address.
 * @param options.timeoutMs - Wall-clock timeout (ms) for the resolver.
 * @returns The meta entries on success, or a failure result on resolver error.
 */
export async function buildRebootMetaEntriesWithTimeout(options: {
  failurePrefix: string
  resolveHost?: ResolveHostCallback
  timeoutMs?: number
}): Promise<ModuleMetaEntry[] | ModuleResult> {
  const entries: ModuleMetaEntry[] = [meta.systemReboot()]
  if (options.resolveHost == null) return entries
  try {
    const newHost = await resolveHostWithTimeout(options.resolveHost, options.timeoutMs)
    if (!isValidRebootHost(newHost)) {
      return {
        ...failed(
          `${options.failurePrefix} resolveHost returned an invalid host that cannot be reconnected to: ${newHost}`
        ),
        meta: entries,
      }
    }
    entries.push(meta.systemHost(newHost))
    return entries
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return {
      ...failed(`${options.failurePrefix} resolveHost failed\n${message}`),
      meta: entries,
    }
  }
}
