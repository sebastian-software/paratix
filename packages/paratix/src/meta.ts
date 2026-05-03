import type {
  Environment,
  EnvironmentMetaEntry,
  MetaEnvironmentValue,
  ModuleMetaEntry,
  SshdPortMetaEntry,
  SystemHostMetaEntry,
  SystemRebootMetaEntry,
} from "./types.js"

import { createNullPrototypeEnvironment, ENVIRONMENT_FORBIDDEN_KEYS } from "./environment.js"
import { isValidTcpPort } from "./serverDefinitionValidation.js"

const SYSTEM_HOST_KIND = "system.host"
const SYSTEM_REBOOT_KIND = "system.reboot"

export type BooleanEnvironmentMetaEntry = { valueType: "boolean" } & EnvironmentMetaEntry
export type LazyEnvironmentMetaEntry = EnvironmentMetaEntry
export type NumberEnvironmentMetaEntry = { valueType: "number" } & EnvironmentMetaEntry
export type StringEnvironmentMetaEntry = { valueType: "string" } & EnvironmentMetaEntry

function hasValidMetaName(name: unknown): name is string {
  return typeof name === "string" && name.length > 0
}

function inferMetaValueType(
  value: MetaEnvironmentValue,
  explicitValueType?: "boolean" | "number" | "string"
): "boolean" | "number" | "string" {
  if (explicitValueType != null) return explicitValueType
  if (typeof value === "boolean") return "boolean"
  if (typeof value === "number") return "number"
  return "string"
}

function normalizeMetaValueResolver(
  value: MetaEnvironmentValue
): () => Promise<boolean | number | string> {
  if (typeof value === "function") {
    return async () => {
      await Promise.resolve()
      return value()
    }
  }
  return async () => {
    await Promise.resolve()
    return value
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function assertValidEnvironmentMetaEntry(candidate: Record<string, unknown>): void {
  if (!hasValidMetaName(candidate.name)) {
    throw new TypeError("Invalid env meta entry: name must be a non-empty string")
  }

  if (typeof candidate.resolve !== "function") {
    throw new TypeError("Invalid env meta entry: resolve must be a function returning a Promise")
  }

  if (
    candidate.valueType !== "boolean" &&
    candidate.valueType !== "number" &&
    candidate.valueType !== "string"
  ) {
    throw new TypeError("Invalid env meta entry: valueType must be boolean, number, or string")
  }
}

function assertValidSshdPortMetaEntry(candidate: Record<string, unknown>): void {
  if (!isValidTcpPort(candidate.port)) {
    throw new TypeError("Invalid sshd.port meta entry: port must be an integer between 1 and 65535")
  }
}

function assertValidSystemHostMetaEntry(candidate: Record<string, unknown>): void {
  if (typeof candidate.host !== "string" || candidate.host.length === 0) {
    throw new TypeError("Invalid system.host meta entry: host must be a non-empty string")
  }
}

export function environmentMeta(
  name: string,
  value: MetaEnvironmentValue,
  valueType?: "boolean" | "number" | "string"
): EnvironmentMetaEntry {
  if (!hasValidMetaName(name)) {
    throw new TypeError("Meta env entry name must be a non-empty string")
  }
  return {
    kind: "env",
    name,
    resolve: normalizeMetaValueResolver(value),
    valueType: inferMetaValueType(value, valueType),
  }
}

export function sshdPortMeta(port: number): SshdPortMetaEntry {
  if (!isValidTcpPort(port)) {
    throw new TypeError("Meta entry sshd.port requires an integer port between 1 and 65535")
  }
  return { kind: "sshd.port", port }
}

export function systemHostMeta(host: string): SystemHostMetaEntry {
  if (host.length === 0) {
    throw new TypeError("Meta entry system.host requires a non-empty host")
  }
  return { host, kind: SYSTEM_HOST_KIND }
}

export function systemRebootMeta(): SystemRebootMetaEntry {
  return { kind: SYSTEM_REBOOT_KIND }
}

export const meta = {
  env: environmentMeta,
  sshdPort: sshdPortMeta,
  systemHost: systemHostMeta,
  systemReboot: systemRebootMeta,
} as const

export function isEnvironmentMetaEntry(entry: ModuleMetaEntry): entry is EnvironmentMetaEntry {
  return entry.kind === "env"
}

export function isStringEnvironmentMetaEntry(
  entry: ModuleMetaEntry
): entry is StringEnvironmentMetaEntry {
  return isEnvironmentMetaEntry(entry) && entry.valueType === "string"
}

export function isNumberEnvironmentMetaEntry(
  entry: ModuleMetaEntry
): entry is NumberEnvironmentMetaEntry {
  return isEnvironmentMetaEntry(entry) && entry.valueType === "number"
}

export function isBooleanEnvironmentMetaEntry(
  entry: ModuleMetaEntry
): entry is BooleanEnvironmentMetaEntry {
  return isEnvironmentMetaEntry(entry) && entry.valueType === "boolean"
}

export function isLazyEnvironmentMetaEntry(
  entry: ModuleMetaEntry
): entry is LazyEnvironmentMetaEntry {
  return isEnvironmentMetaEntry(entry)
}

export function isSshdPortMetaEntry(entry: ModuleMetaEntry): entry is SshdPortMetaEntry {
  return entry.kind === "sshd.port"
}

export function isSystemHostMetaEntry(entry: ModuleMetaEntry): entry is SystemHostMetaEntry {
  return entry.kind === SYSTEM_HOST_KIND
}

export function isSystemRebootMetaEntry(entry: ModuleMetaEntry): entry is SystemRebootMetaEntry {
  return entry.kind === SYSTEM_REBOOT_KIND
}

export function assertValidModuleMetaEntry(entry: unknown): asserts entry is ModuleMetaEntry {
  if (!isRecord(entry)) {
    throw new TypeError(`Invalid meta entry: expected object, got ${typeof entry}`)
  }

  switch (entry.kind) {
    case "env": {
      assertValidEnvironmentMetaEntry(entry)
      return
    }
    case "sshd.port": {
      assertValidSshdPortMetaEntry(entry)
      return
    }
    case SYSTEM_HOST_KIND: {
      assertValidSystemHostMetaEntry(entry)
      return
    }
    case SYSTEM_REBOOT_KIND: {
      return
    }
    default: {
      throw new TypeError(`Invalid meta entry kind: ${String(entry.kind)}`)
    }
  }
}

export function assertValidModuleMetaEntries(entries: ModuleMetaEntry[] | undefined): void {
  if (entries == null) return
  for (const entry of entries) {
    assertValidModuleMetaEntry(entry)
  }
}

export async function mergeEnvironmentFromMeta(
  environment: Environment,
  entries: ModuleMetaEntry[] | undefined
): Promise<Environment> {
  if (entries == null || entries.length === 0) {
    await Promise.resolve()
    return environment
  }

  // R-0000074: preserve the null-prototype guarantee that R-0000070
  // introduced in mergeEnvironment by routing through
  // createNullPrototypeEnvironment instead of `{ ...environment }`, and
  // explicitly reject reserved property names that could leak into
  // prototype semantics on a plain object.
  const nextEnvironment = Object.assign(createNullPrototypeEnvironment(), environment)
  for (const entry of entries) {
    if (!isEnvironmentMetaEntry(entry)) continue
    if (ENVIRONMENT_FORBIDDEN_KEYS.has(entry.name)) {
      throw new Error(
        `Forbidden env meta entry name: ${JSON.stringify(entry.name)} (reserved JavaScript identifier)`
      )
    }
    nextEnvironment[entry.name] = async () => entry.resolve()
  }
  await Promise.resolve()
  return nextEnvironment
}

export function environmentToMetaEntries(environment: Environment): ModuleMetaEntry[] {
  return Object.entries(environment).map(([name, value]) => environmentMeta(name, value))
}

export function diffEnvironmentToMetaEntries(
  original: Environment,
  current: Environment
): ModuleMetaEntry[] | undefined {
  const entries: ModuleMetaEntry[] = []
  for (const key of Object.keys(current)) {
    if (!(key in original) || current[key] !== original[key]) {
      entries.push(environmentMeta(key, current[key]))
    }
  }
  return entries.length === 0 ? undefined : entries
}
