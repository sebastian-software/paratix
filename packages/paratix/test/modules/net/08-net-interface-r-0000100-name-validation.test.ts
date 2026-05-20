import { describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"

describe("net.interface — R-0000100 name validation", () => {
  it("throws when the name contains path traversal segments", () => {
    expect(() => net.interface("../../etc/passwd", {})).toThrow(/invalid interface name/v)
  })

  it("throws when the name is the empty string", () => {
    expect(() => net.interface("", {})).toThrow(/invalid interface name/v)
  })

  it("throws when the name contains a forward slash", () => {
    expect(() => net.interface("eth0/../foo", {})).toThrow(/invalid interface name/v)
  })

  it("accepts valid POSIX interface names", () => {
    expect(() => net.interface("eth0", {})).not.toThrow()
    expect(() => net.interface("enp3s0", {})).not.toThrow()
    expect(() => net.interface("br-lan", {})).not.toThrow()
    expect(() => net.interface("vlan.100", {})).not.toThrow()
  })
})

describe("net.route — device name validation", () => {
  it("throws when the device contains path traversal segments", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "../../eth0" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains a forward slash", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0/../foo" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains whitespace", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth 0" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains shell metacharacters", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0;touch" })).toThrow(
      /invalid route device/v
    )
  })

  it("accepts valid POSIX device names", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })).not.toThrow()
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "br-lan" })).not.toThrow()
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "vlan.100" })).not.toThrow()
  })
})
