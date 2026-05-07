const IMPLICIT_MOUNT_OPTIONS = new Set(
  "async auto defaults dev errors=remount-ro exec inode64 nouser relatime rw suid".split(" ")
)

const STRICT_OPTION_GROUPS = [
  ["async", "sync"],
  ["auto", "noauto"],
  ["dev", "nodev"],
  ["exec", "noexec"],
  ["relatime", "norelatime"],
  ["ro", "rw"],
  ["suid", "nosuid"],
  ["user", "nouser", "users", "owner", "group"],
]

const FSTAB_ONLY_OPTIONS = new Set(["_netdev", "noauto", "nofail"])

type NormalizedMountOptions = {
  normalized: Set<string>
  raw: Set<string>
}

export function mountOptionsMatch(liveOptions: string, desiredOptions: string): boolean {
  const live = normalizeMountOptions(liveOptions)
  const desired = normalizeMountOptions(desiredOptions)

  return normalizedMountOptionsMatch(live, desired)
}

export function liveMountOptionsMatch(liveOptions: string, desiredOptions: string): boolean {
  const live = normalizeMountOptions(liveOptions)
  const desired = normalizeMountOptions(desiredOptions, { ignoreFstabOnly: true })

  return normalizedMountOptionsMatch(live, desired)
}

function normalizedMountOptionsMatch(
  live: NormalizedMountOptions,
  desired: NormalizedMountOptions
): boolean {
  if (!strictOptionsMatch(live.raw, desired.raw)) return false

  for (const option of desired.normalized) {
    if (!live.normalized.has(option)) return false
  }
  for (const option of live.normalized) {
    if (!desired.normalized.has(option)) return false
  }
  return true
}

function normalizeMountOptions(
  options: string,
  behavior: { ignoreFstabOnly?: boolean } = {}
): NormalizedMountOptions {
  const result: NormalizedMountOptions = {
    normalized: new Set<string>(),
    raw: new Set<string>(),
  }

  for (const option of options.split(",")) {
    const trimmed = option.trim()
    if (trimmed.length === 0) continue

    const normalizedOption = normalizeOption(trimmed)
    if (behavior.ignoreFstabOnly === true && isFstabOnlyOption(normalizedOption)) continue
    result.raw.add(normalizedOption)
    if (!IMPLICIT_MOUNT_OPTIONS.has(normalizedOption)) {
      result.normalized.add(normalizedOption)
    }
  }

  return result
}

function isFstabOnlyOption(option: string): boolean {
  return FSTAB_ONLY_OPTIONS.has(option) || option.startsWith("x-systemd.")
}

function normalizeOption(option: string): string {
  const separatorIndex = option.indexOf("=")
  if (separatorIndex === -1) return option.toLowerCase()

  const key = option.slice(0, separatorIndex).toLowerCase()
  const value = option.slice(separatorIndex + 1)
  if (key === "size") {
    const normalizedSize = normalizeSizeValue(value)
    if (normalizedSize != null) return `${key}=${normalizedSize}`
  }
  return `${key}=${value}`
}

function strictOptionsMatch(liveOptions: Set<string>, desiredOptions: Set<string>): boolean {
  for (const group of STRICT_OPTION_GROUPS) {
    if (
      effectiveStrictOption(liveOptions, group) !== effectiveStrictOption(desiredOptions, group)
    ) {
      return false
    }
  }
  return true
}

function effectiveStrictOption(options: Set<string>, group: string[]): string | undefined {
  for (const option of group) {
    if (options.has(option)) return option
  }
  if (group.includes("nouser")) return "nouser"
  return group.find((option) => IMPLICIT_MOUNT_OPTIONS.has(option))
}

function normalizeSizeValue(value: string): null | string {
  const match = /^(?<amount>\d+)(?<unit>[kmgtp]?)i?b?$/iv.exec(value)
  if (match?.groups == null) return null

  const amount = BigInt(match.groups.amount)
  const unit = match.groups.unit.toLowerCase()
  const exponent = ["", "k", "m", "g", "t", "p"].indexOf(unit)
  if (exponent === -1) return null

  return String(amount * 1024n ** BigInt(exponent))
}
