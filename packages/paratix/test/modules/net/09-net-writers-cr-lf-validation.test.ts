import { describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"

describe("net writers — CR/LF validation", () => {
  it("rejects interface addresses containing line breaks", () => {
    expect(() =>
      net.interface("eth0", { addresses: ["192.168.1.10/24\n      dhcp4: true"] })
    ).toThrow(/interface address.*CR or LF/v)
  })

  it("rejects interface gateways containing line breaks", () => {
    // R-0000485: the interface gateway now routes through the shared
    // `validateInterfaceIpToken("gateway", ...)` helper, which surfaces the
    // CR/LF error with the bare `gateway` label instead of the previous
    // `interface gateway` label used by the dedicated writer.
    expect(() => net.interface("eth0", { gateway: "192.168.1.1\nDNS=1.1.1.1" })).toThrow(
      /invalid gateway.*CR or LF/v
    )
  })

  it("rejects resolv nameservers containing line breaks", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1\nsearch injected.local"] })).toThrow(
      /resolv nameserver.*CR or LF/v
    )
  })

  it("rejects empty resolv nameservers", () => {
    expect(() => net.resolv({ nameservers: [] })).toThrow(/at least one nameserver/v)
  })

  it("rejects invalid resolv nameserver addresses", () => {
    expect(() => net.resolv({ nameservers: [""] })).toThrow(/valid IPv4 or IPv6 address/v)
    expect(() => net.resolv({ nameservers: ["999.999.999.999"] })).toThrow(
      /valid IPv4 or IPv6 address/v
    )
    expect(() => net.resolv({ nameservers: ["not-an-ip"] })).toThrow(/valid IPv4 or IPv6 address/v)
  })

  it("accepts IPv4 and IPv6 resolv nameservers", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1", "2001:4860:4860::8888"] })).not.toThrow()
  })

  it("rejects resolv search domains containing line breaks", () => {
    expect(() =>
      net.resolv({
        nameservers: ["1.1.1.1"],
        search: ["example.com\nnameserver 9.9.9.9"],
      })
    ).toThrow(/resolv search domain.*CR or LF/v)
  })

  it("rejects invalid resolv search domains", () => {
    const invalidDomains = [
      "",
      "bad domain",
      "_srv.example",
      "-example.com",
      "example-.com",
      "a..b",
    ]
    for (const domain of invalidDomains) {
      expect(() => net.resolv({ nameservers: ["1.1.1.1"], search: [domain] })).toThrow(
        /invalid search domain/v
      )
    }
  })

  it("accepts single-label resolv search domains", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1"], search: ["local"] })).not.toThrow()
  })

  it("rejects route destinations containing line breaks", () => {
    // R-0000486: `net.route` requires `options.device` before validating the
    // destination, so the fixture must provide a device so the CR/LF
    // validation (R-0000488) is the assertion under test rather than the
    // missing-device guard.
    expect(() =>
      net.route("10.0.0.0/24\nGateway=1.2.3.4", "192.168.1.1", { device: "eth0" })
    ).toThrow(/route destination.*CR or LF/v)
  })

  it("rejects route devices containing line breaks", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0\n[Route]" })).toThrow(
      /route device.*CR or LF/v
    )
  })
})
