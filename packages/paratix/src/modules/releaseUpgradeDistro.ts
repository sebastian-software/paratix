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
 * arbitrary casing for `ID=` (e.g. `ID=Ubuntu`).
 *
 * @param value - A single token (already lowercased) from `ID`.
 * @returns The matching distro, or `null` when the token is unsupported.
 */
function matchDistroToken(value: string): Distro | null {
  if (value === "ubuntu") return "ubuntu"
  if (value === "debian") return "debian"
  return null
}

/**
 * Parse the contents of `/etc/os-release` into a supported {@link Distro}.
 *
 * Compares only the explicit `ID=` field case-insensitively. Debian or Ubuntu
 * derivatives may advertise compatibility via `ID_LIKE=`, but the
 * release-upgrade module performs mutating distribution upgrades and only
 * supports hosts that identify themselves directly as Debian or Ubuntu.
 *
 * @param osRelease - The full content of `/etc/os-release`.
 * @returns The detected distro, or `null` when none of the supported
 *   identifiers appear in `ID=`.
 */
export function parseOsReleaseDistro(osRelease: string): Distro | null {
  for (const line of osRelease.split("\n")) {
    const idMatch = /^ID=(?<value>.*)$/v.exec(line)
    if (idMatch?.groups) {
      const id = idMatch.groups.value.replaceAll('"', "").trim().toLowerCase()
      const direct = matchDistroToken(id)
      if (direct != null) return direct
    }
  }
  return null
}
