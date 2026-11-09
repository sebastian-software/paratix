import { describe, expect, it } from "vitest"

import type { SshdMatchDirectives } from "../../../src/modules/sshd.js"

import { sshd } from "../../../src/modules/sshd.js"
import { buildSshdMatchSpec, sshdMatchCriteriaMatch } from "../../../src/modules/sshdMatchSpec.js"

function build(
  criteria: Parameters<typeof sshd.match>[1],
  directives: SshdMatchDirectives = { PermitTTY: "no" },
  options: Parameters<typeof sshd.match>[3] = {}
) {
  return buildSshdMatchSpec("ops-ro", criteria, { directives, options })
}

describe("sshd.match construction", () => {
  it("renders one marked Match block with directives in allowlist order", () => {
    const spec = build(
      { group: "ops", user: ["ops-ro", "alice"] },
      {
        AllowTcpForwarding: "local",
        AuthenticationMethods: "publickey,keyboard-interactive:pam publickey",
        DisableForwarding: "yes",
        ForceCommand: "/usr/local/bin/ops-ro-shell --read-only",
      },
      { verifyUser: "alice" }
    )
    expect(spec.path).toBe("/etc/ssh/sshd_config.d/ops-ro.conf")
    expect(spec.moduleName).toBe("sshd.match: ops-ro (present)")
    expect(spec.verifyUser).toBe("alice")
    expect(spec.content).toBe(
      [
        "# Managed by Paratix sshd.match: ops-ro",
        "Match User ops-ro,alice Group ops",
        "    AllowTcpForwarding local",
        "    AuthenticationMethods publickey,keyboard-interactive:pam publickey",
        "    DisableForwarding yes",
        "    ForceCommand /usr/local/bin/ops-ro-shell --read-only",
        "",
      ].join("\n")
    )
  })

  it("defaults the verify user to the first user and the state to present", () => {
    const spec = build({ user: ["ops-ro", "bob"] })
    expect(spec.verifyUser).toBe("ops-ro")
    expect(spec.state).toBe("present")
    expect(sshd.match("ops-ro", { user: "ops-ro" }, {}, { state: "absent" }).name).toBe(
      "sshd.match: ops-ro (absent)"
    )
  })

  it.each([
    [
      "an invalid name",
      () =>
        buildSshdMatchSpec("Ops", { user: "a" }, { directives: { PermitTTY: "no" }, options: {} }),
    ],
    [
      "a leading dash",
      () =>
        buildSshdMatchSpec("-x", { user: "a" }, { directives: { PermitTTY: "no" }, options: {} }),
    ],
    ["missing criteria", () => build({})],
    ["an empty user list", () => build({ user: [] })],
    ["a wildcard pattern", () => build({ user: "ops*" })],
    ["a negated pattern", () => build({ user: "!root" })],
    ["a comma list", () => build({ user: "a,b" })],
    ["duplicate users", () => build({ user: ["a", "a"] })],
    ["a group without verifyUser", () => build({ group: "ops" })],
    [
      "a verifyUser outside the user criterion",
      () => build({ group: "ops", user: "a" }, undefined, { verifyUser: "b" }),
    ],
    [
      "a verifyUser outside a user-only criterion",
      () => build({ user: "a" }, undefined, { verifyUser: "b" }),
    ],
    ["no directives", () => build({ user: "a" }, {})],
    ["a non-canonical value", () => build({ user: "a" }, { PermitTTY: "No" as "no" })],
    [
      "the non-canonical forwarding value all",
      () => build({ user: "a" }, { AllowTcpForwarding: "all" as "yes" }),
    ],
    ["a newline in a value", () => build({ user: "a" }, { ForceCommand: "x\nPermitTTY yes" })],
    ["a tab in a value", () => build({ user: "a" }, { ForceCommand: "x\ty" })],
    ["a padded ForceCommand", () => build({ user: "a" }, { ForceCommand: " x" })],
    [
      "an invalid AuthenticationMethods list",
      () => build({ user: "a" }, { AuthenticationMethods: "publickey,,password" }),
    ],
    ["an unknown option", () => build({ user: "a" }, undefined, { force: true } as never)],
    ["an unknown state", () => build({ user: "a" }, undefined, { state: "gone" as "absent" })],
  ])("rejects %s", (_label, create) => {
    expect(create).toThrow(/^sshd\.match: /v)
  })

  it.each([
    ["TrustedUserCAKeys", /ssh\.trustedUserCa/v],
    ["AuthorizedPrincipalsFile", /ssh\.trustedUserCa/v],
    ["RevokedKeys", /ssh\.trustedUserCa/v],
    ["HostCertificate", /ssh\.hostCertificate/v],
    ["Port", /sshd\.port/v],
    ["port", /sshd\.port/v],
  ])("names the owning module for managed directive %s", (directive, owner) => {
    expect(() => build({ user: "a" }, { [directive]: "x" })).toThrow(owner)
  })

  it("rejects unknown directives and accepts weakening values", () => {
    expect(() => build({ user: "a" }, { Banner: "/etc/issue" } as SshdMatchDirectives)).toThrow(
      /unsupported directive "Banner"/v
    )
    expect(build({ user: "a" }, { PasswordAuthentication: "yes" }).settings).toStrictEqual({
      PasswordAuthentication: "yes",
    })
  })

  it("evaluates sshd's AND semantics for user and group criteria", () => {
    const spec = build({ group: ["ops", "audit"], user: ["alice"] }, undefined, {
      verifyUser: "alice",
    })
    expect(sshdMatchCriteriaMatch(spec, { groups: ["audit"], user: "alice" })).toBe(true)
    expect(sshdMatchCriteriaMatch(spec, { groups: ["staff"], user: "alice" })).toBe(false)
    expect(sshdMatchCriteriaMatch(spec, { groups: ["ops"], user: "root" })).toBe(false)
    expect(sshdMatchCriteriaMatch(spec, { groups: null, user: "alice" })).toBeUndefined()
  })
})
