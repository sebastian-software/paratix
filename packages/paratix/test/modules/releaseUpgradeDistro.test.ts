import { describe, expect, it } from "vitest"

import { parseOsReleaseDistro } from "../../src/modules/releaseUpgradeDistro.js"

describe("parseOsReleaseDistro", () => {
  it("returns ubuntu for the canonical lowercase ID", () => {
    expect(parseOsReleaseDistro('ID=ubuntu\nVERSION_ID="22.04"\n')).toBe("ubuntu")
  })

  it("returns debian for the canonical lowercase ID", () => {
    expect(parseOsReleaseDistro("ID=debian\nVERSION_CODENAME=bookworm\n")).toBe("debian")
  })

  it("R-0000239: matches ID values regardless of case", () => {
    expect(parseOsReleaseDistro('ID=Ubuntu\nVERSION_ID="22.04"\n')).toBe("ubuntu")
    expect(parseOsReleaseDistro("ID=DEBIAN\nVERSION_CODENAME=bookworm\n")).toBe("debian")
  })

  it("R-0000239: strips surrounding double quotes from ID before matching", () => {
    expect(parseOsReleaseDistro('ID="Ubuntu"\nVERSION_ID="22.04"\n')).toBe("ubuntu")
  })

  it("returns null for a Debian-derived fork that only declares Debian via ID_LIKE", () => {
    const osRelease = ["ID=raspbian", "ID_LIKE=debian", "VERSION_CODENAME=bookworm"].join("\n")
    expect(parseOsReleaseDistro(osRelease)).toBeNull()
  })

  it("returns null for an Ubuntu-derived fork that only declares Ubuntu via ID_LIKE", () => {
    const osRelease = ["ID=mint", 'ID_LIKE="ubuntu debian"', 'VERSION_ID="22"'].join("\n")
    expect(parseOsReleaseDistro(osRelease)).toBeNull()
  })

  it("returns null for entirely unsupported distributions", () => {
    expect(parseOsReleaseDistro("ID=arch\n")).toBeNull()
    expect(parseOsReleaseDistro("ID=fedora\nID_LIKE=rhel\n")).toBeNull()
  })

  it("returns null for empty content", () => {
    expect(parseOsReleaseDistro("")).toBeNull()
  })
})
