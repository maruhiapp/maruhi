// Unit tests for rate-limit key normalization (worker-env.ts).
// The point is IPv6 /64 aggregation: if rotating the low bits inside the
// standard /64 allocation produced a new key per request, per-source-IP rate
// limit windows would never take effect.

import { describe, expect, it } from "vitest";

import { rateLimitKeyOf } from "../src/worker-env.ts";

describe("rateLimitKeyOf (source IP -> limit key)", () => {
  it("passes IPv4 through unchanged", () => {
    expect(rateLimitKeyOf("203.0.113.7")).toBe("203.0.113.7");
  });

  it("rounds IPv6 down to its /64 prefix (low-64-bit rotation folds into the same key)", () => {
    expect(rateLimitKeyOf("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKeyOf("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    // Compressed forms normalize to the same prefix too
    expect(rateLimitKeyOf("2001:db8:1:2::9")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKeyOf("2001:DB8:0001:2::9")).toBe("2001:db8:1:2::/64");
    // Leading compression and full compression
    expect(rateLimitKeyOf("::1")).toBe("0:0:0:0::/64");
    expect(rateLimitKeyOf("fe80::")).toBe("fe80:0:0:0::/64");
  });

  it("uses the embedded IPv4 as the key for IPv4-mapped (::ffff:a.b.c.d) (does not fold into a shared bucket)", () => {
    expect(rateLimitKeyOf("::ffff:192.0.2.1")).toBe("192.0.2.1");
    expect(rateLimitKeyOf("::ffff:c000:201")).toBe("192.0.2.1");
    // IPv4 embedding other than v4-mapped (NAT64 etc.) takes the normal /64
    // aggregation
    expect(rateLimitKeyOf("64:ff9b:1:2::192.0.2.1")).toBe("64:ff9b:1:2::/64");
  });

  it("falls back to the raw string key for unparseable values (per-address limiting still applies)", () => {
    expect(rateLimitKeyOf("not:an:ip:::")).toBe("not:an:ip:::");
    expect(rateLimitKeyOf("2001:db8:1:2:3:4:5:6:7:8")).toBe("2001:db8:1:2:3:4:5:6:7:8");
  });

  it("accepts only strict decimal octets in embedded IPv4", () => {
    // Shapes that would slip through a Number() coercion fall back to the raw
    // string key (= they neither become a different bucket nor fold a
    // malformed notation into a valid address)
    for (const malformed of [
      "::ffff:0x1.2.3.4",
      "::ffff:1.2.3.",
      "::ffff:1.2.3.4.5",
      "::ffff:1e2.2.3.4",
      "::ffff:1.2.3. 4",
      "::ffff:01.2.3.4",
      "::ffff:1.2.3.256",
      "::ffff:1.2.3.-1",
    ]) {
      expect(rateLimitKeyOf(malformed)).toBe(malformed);
    }
    // Valid forms still fold as before (including the 0 and 255 boundaries)
    expect(rateLimitKeyOf("::ffff:0.0.0.0")).toBe("0.0.0.0");
    expect(rateLimitKeyOf("::ffff:255.255.255.255")).toBe("255.255.255.255");
  });

  it("treats IPv4 embedding as only the address's last piece (RFC 4291 §2.2 (3))", () => {
    expect(rateLimitKeyOf("::ffff:1.2.3.4:0")).toBe("::ffff:1.2.3.4:0");
    expect(rateLimitKeyOf("1.2.3.4::")).toBe("1.2.3.4::");
    // Placing it at the end of an uncompressed form is valid (6 groups +
    // IPv4 = 8 groups)
    expect(rateLimitKeyOf("2001:db8:1:2:0:0:192.0.2.1")).toBe("2001:db8:1:2::/64");
  });
});
