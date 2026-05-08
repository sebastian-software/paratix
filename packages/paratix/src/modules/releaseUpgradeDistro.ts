/**
 * Helpers that parse the remote host's `/etc/os-release` into one of the
 * release-upgrade module's supported {@link Distro} values.
 *
 * Lives in its own module so the comparison is exercised by unit tests
 * without spinning up an SSH mock.
 */

/**
 * Distributions the release-upgrade module knows how to upgrade.
 */
export type Distro = "debian" | "ubuntu"

/**
 * Map a normalized os-release token to a supported {@link Distro}.
 *
 * Comparison is case-insensitive (R-0000239) — `/etc/os-release` allows
 * arbitrary casing for `ID=` and `ID_LIKE=` (e.g. `ID=Ubuntu`), and
 * Debian-derived forks frequently carry a custom `ID=` while still listing
 * `debian` or `ubuntu` via `ID_LIKE=`.
 *
 * @param value - A single token (already lowercased) from `ID` or `ID_LIKE`.
 * @returns The matching distro, or `null` when the token is unsupported.
 */
function matchDistroToken(value: string): Distro | null {
  if (value === "ubuntu") return "ubuntu"
  if (value === "debian") return "debian"
  return null
}

/**
 * Resolve the first supported distro token from a raw `ID_LIKE=` value.
 *
 * @param raw - The raw value of the `ID_LIKE=` line.
 * @returns The first matching distro, or `null` when no token matches.
 */
function matchIdLikeValue(raw: string): Distro | null {
  const tokens = raw.replaceAll('"', "").trim().toLowerCase().split(/\s+/v)
  for (const token of tokens) {
    const candidate = matchDistroToken(token)
    if (candidate != null) return candidate
  }
  return null
}

/**
 * Parse the contents of `/etc/os-release` into a supported {@link Distro}.
 *
 * Compares the `ID=` field case-insensitively and falls back to the
 * `ID_LIKE=` field so distributions that derive from Debian or Ubuntu
 * (for example `ID=mint` with `ID_LIKE=ubuntu`) are still recognised.
 *
 * @param osRelease - The full content of `/etc/os-release`.
 * @returns The detected distro, or `null` when none of the supported
 *   identifiers appear in `ID=` or `ID_LIKE=`.
 */
export function parseOsReleaseDistro(osRelease: string): Distro | null {
  let idLikeMatch: Distro | null = null
  for (const line of osRelease.split("\n")) {
    const idMatch = /^ID=(?<value>.*)$/v.exec(line)
    if (idMatch?.groups) {
      const id = idMatch.groups.value.replaceAll('"', "").trim().toLowerCase()
      const direct = matchDistroToken(id)
      if (direct != null) return direct
      continue
    }
    const idLikeRawMatch = /^ID_LIKE=(?<value>.*)$/v.exec(line)
    if (idLikeRawMatch?.groups && idLikeMatch == null) {
      idLikeMatch = matchIdLikeValue(idLikeRawMatch.groups.value)
    }
  }
  return idLikeMatch
}
