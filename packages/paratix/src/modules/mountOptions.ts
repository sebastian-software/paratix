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

// ─── bind mounts ─────────────────────────────────────────────────────────────

const BIND_OPTIONS = new Set(["bind", "rbind"])

/** Per-mount VFS flag dimensions compared for bind mounts, in canonical order. */
const VFS_FLAG_DIMENSIONS = [
  "access",
  "suid",
  "dev",
  "exec",
  "atime",
  "nodiratime",
  "nosymfollow",
] as const

type VfsFlagDimension = (typeof VFS_FLAG_DIMENSIONS)[number]

type VfsFlagState = Map<VfsFlagDimension, string>

/**
 * Option token → [dimension, canonical token]. Only these tokens are per-mount
 * VFS flags; every other option (`bind`/`rbind`, fstab-only options such as
 * `_netdev`/`nofail`/`noauto`/`x-systemd.*`, propagation options such as
 * `private`/`rshared`/`unbindable`, `defaults`, and all superblock or
 * filesystem-specific options) is ignored by the bind comparison.
 *
 * The atime dimension models the kernel's three atime states: `noatime`,
 * `relatime`, and `strictatime` (also spelled `norelatime`), where the last
 * one shows up in findmnt's VFS-OPTIONS as neither `noatime` nor `relatime`.
 */
const VFS_FLAG_TOKENS = new Map<string, readonly [VfsFlagDimension, string]>([
  ["dev", ["dev", "dev"]],
  ["diratime", ["nodiratime", "diratime"]],
  ["exec", ["exec", "exec"]],
  ["noatime", ["atime", "noatime"]],
  ["nodev", ["dev", "nodev"]],
  ["nodiratime", ["nodiratime", "nodiratime"]],
  ["noexec", ["exec", "noexec"]],
  ["norelatime", ["atime", "strictatime"]],
  ["nosuid", ["suid", "nosuid"]],
  ["nosymfollow", ["nosymfollow", "nosymfollow"]],
  ["relatime", ["atime", "relatime"]],
  ["ro", ["access", "ro"]],
  ["rw", ["access", "rw"]],
  ["strictatime", ["atime", "strictatime"]],
  ["suid", ["suid", "suid"]],
  ["symfollow", ["nosymfollow", "symfollow"]],
])

function optionTokens(options: string): string[] {
  return options
    .split(",")
    .map((option) => option.trim())
    .filter((option) => option.length > 0)
    .map((option) => normalizeOption(option))
}

/**
 * Whether `opts` requests a bind mount: the comma-separated options contain
 * the token `bind` or `rbind`, compared case-insensitively like every other
 * option token.
 *
 * @param opts - The desired mount options string.
 * @returns `true` for a bind or rbind mount.
 */
export function isBindMountOptions(opts: string): boolean {
  return optionTokens(opts).some((option) => BIND_OPTIONS.has(option))
}

/**
 * Collect the VFS flags that `opts` names explicitly. Later tokens override
 * earlier ones in the same dimension, as with mount(8). Unnamed dimensions
 * stay absent ("don't care").
 *
 * @param opts - The desired mount options string.
 * @returns The explicitly requested VFS flag state.
 */
function explicitVfsFlags(opts: string): VfsFlagState {
  const state: VfsFlagState = new Map()
  for (const option of optionTokens(opts)) {
    const flag = VFS_FLAG_TOKENS.get(option)
    if (flag != null) state.set(flag[0], flag[1])
  }
  return state
}

/**
 * Derive the full VFS flag state from findmnt's VFS-OPTIONS column, which
 * always lists `ro` or `rw` and lists every other flag only when it is set.
 *
 * @param vfsOptions - The live VFS-OPTIONS value.
 * @returns The live VFS flag state for every dimension.
 */
function liveVfsFlags(vfsOptions: string): VfsFlagState {
  const live = new Set(optionTokens(vfsOptions))
  const pick = (setToken: string, unsetToken: string): string =>
    live.has(setToken) ? setToken : unsetToken
  let atime = "strictatime"
  if (live.has("noatime")) atime = "noatime"
  else if (live.has("relatime")) atime = "relatime"
  return new Map<VfsFlagDimension, string>([
    ["access", pick("ro", "rw")],
    ["atime", atime],
    ["dev", pick("nodev", "dev")],
    ["exec", pick("noexec", "exec")],
    ["nodiratime", pick("nodiratime", "diratime")],
    ["nosymfollow", pick("nosymfollow", "symfollow")],
    ["suid", pick("nosuid", "suid")],
  ])
}

/**
 * Compare only the VFS flags that the desired bind `opts` names explicitly
 * against the live VFS-OPTIONS. Flags not named in `opts` are inherited from
 * the source mount by a new bind and are therefore "don't care".
 *
 * @param liveVfsOptions - The live VFS-OPTIONS value of the top-most mount.
 * @param desiredOpts - The desired bind mount options string.
 * @returns `true` when every explicitly named flag matches.
 */
export function bindVfsFlagsMatch(liveVfsOptions: string, desiredOpts: string): boolean {
  const live = liveVfsFlags(liveVfsOptions)
  for (const [dimension, desiredFlag] of explicitVfsFlags(desiredOpts)) {
    if (live.get(dimension) !== desiredFlag) return false
  }
  return true
}

/**
 * Render a complete VFS flag state as canonical tokens in a stable order
 * (access, suid, dev, exec, atime, nodiratime, nosymfollow), with an explicit
 * token for every dimension, including the clearing tokens `rw`, `suid`,
 * `dev`, `exec`, `diratime` and an atime state.
 *
 * On the legacy mount API (util-linux < 2.39), `MS_REMOUNT | MS_BIND` sets the
 * per-mount flags to exactly the given set, while `mount_setattr` (util-linux
 * >= 2.39) changes only the named attributes. Naming every dimension makes
 * both APIs produce the same state. The one exception is `symfollow`: it is
 * omitted while neither the target nor the current state is `nosymfollow`,
 * because both APIs then leave the flag cleared anyway, and `mount_setattr` on
 * kernels without `MOUNT_ATTR_NOSYMFOLLOW` (before 5.14) rejects the token.
 *
 * @param target - The VFS flag state the remount must produce.
 * @param current - The VFS flag state of the mount before the remount.
 * @returns The comma-separated canonical flag tokens.
 */
function renderVfsFlagState(target: VfsFlagState, current: VfsFlagState): string {
  return VFS_FLAG_DIMENSIONS.flatMap((dimension) => {
    const flag = target.get(dimension)
    if (flag == null) return []
    if (flag === "symfollow" && current.get(dimension) === "symfollow") return []
    return [flag]
  }).join(",")
}

function overrideVfsFlags(base: VfsFlagState, overrides: VfsFlagState): VfsFlagState {
  const result: VfsFlagState = new Map(base)
  for (const [dimension, flag] of overrides) result.set(dimension, flag)
  return result
}

/**
 * Render the flags for the `mount -o remount,bind,<flags>` convergence
 * command: the complete resulting VFS flag state, i.e. the live flags with the
 * flags that `opts` names explicitly overriding their dimension. Flags that
 * `opts` does not name therefore keep their live value (e.g. an inherited
 * `nosuid,nodev,noexec`) on every mount API; see {@link renderVfsFlagState}.
 *
 * @param liveVfsOptions - The live VFS-OPTIONS value of the top-most mount.
 * @param desiredOpts - The desired bind mount options string.
 * @returns The comma-separated canonical flag tokens.
 */
export function renderBindRemountVfsFlags(liveVfsOptions: string, desiredOpts: string): string {
  const live = liveVfsFlags(liveVfsOptions)
  return renderVfsFlagState(overrideVfsFlags(live, explicitVfsFlags(desiredOpts)), live)
}

/**
 * Keep only the known VFS flag tokens of a live VFS-OPTIONS value, in their
 * original order, so a rollback remount never passes unexpected tokens from
 * remote output to mount(8).
 *
 * @param vfsOptions - The live VFS-OPTIONS value.
 * @returns The comma-separated known VFS flag tokens.
 */
export function knownLiveVfsFlags(vfsOptions: string): string {
  return optionTokens(vfsOptions)
    .filter((option) => VFS_FLAG_TOKENS.has(option))
    .join(",")
}
