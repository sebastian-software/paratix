import { describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"

describe("net.hosts — validation", () => {
  it("accepts valid IPv4 hosts entries", () => {
    expect(() => net.hosts("1.2.3.4", ["myhost", "myhost.local"])).not.toThrow()
  })

  it("accepts valid IPv6 hosts entries", () => {
    expect(() => net.hosts("2001:db8::1", ["myhost", "myhost.local"])).not.toThrow()
  })

  it("rejects an empty hostname list", () => {
    expect(() => net.hosts("1.2.3.4", [])).toThrow(
      "[net.hosts] invalid hostnames: at least one hostname is required"
    )
  })

  it("rejects empty tokens", () => {
    expect(() => net.hosts("", ["myhost"])).toThrow("[net.hosts] invalid IP address")
    expect(() => net.hosts("1.2.3.4", [""])).toThrow("[net.hosts] invalid hostname")
  })

  it("rejects LF injection in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4\n5.6.7.8", ["myhost"])).toThrow(
      "[net.hosts] invalid IP address"
    )
    expect(() => net.hosts("1.2.3.4", ["myhost\n5.6.7.8 injected"])).toThrow(
      "[net.hosts] invalid hostname"
    )
  })

  it("rejects CR injection in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4\r5.6.7.8", ["myhost"])).toThrow(
      "[net.hosts] invalid IP address"
    )
    expect(() => net.hosts("1.2.3.4", ["myhost\r5.6.7.8 injected"])).toThrow(
      "[net.hosts] invalid hostname"
    )
  })

  it("rejects whitespace in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4 5.6.7.8", ["myhost"])).toThrow("[net.hosts] invalid IP address")
    expect(() => net.hosts("1.2.3.4", ["myhost injected"])).toThrow("[net.hosts] invalid hostname")
  })
})
