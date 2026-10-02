// Tests for the host-local guard of sandbox mode (proxy-guard.ts — §21 R-12)
// and the authority formatting (§21 R-11).

import { describe, expect, it } from "vitest";

import {
  formatAuthority,
  checkHostLocal,
  isHostLocalAddress,
  isHostLocalName,
  isLoopbackBind,
} from "../src/proxy-guard.ts";

describe("proxy-guard", () => {
  it("classifies loopback, link-local, unspecified, and IPv4-mapped addresses as host-local", () => {
    for (const ip of [
      "127.0.0.1",
      "127.255.0.9",
      "0.0.0.0",
      "169.254.169.254",
      "::1",
      "::",
      "fe80::1",
      "FE80::abcd",
      "::ffff:127.0.0.1",
      "::ffff:169.254.1.1",
      // By value, not by text (§21 R-16): expanded, compressed elsewhere, hex-mapped, bracketed, zoned
      "0:0:0:0:0:0:0:1",
      "::0:1",
      "0::1",
      "::ffff:7f00:1",
      "::ffff:a9fe:a9fe",
      "::ffff:0:1",
      "[::1]",
      "fe80::1%eth0",
      // The AWS IPv6 metadata service, and the shared address space (Alibaba Cloud's endpoint)
      "fd00:ec2::254",
      "100.100.100.200",
      "100.64.0.1",
      "::ffff:100.100.100.200",
    ]) {
      expect(isHostLocalAddress(ip), ip).toBe(true);
    }
    for (const ip of [
      "10.0.0.1",
      "172.16.5.5",
      "192.168.1.1",
      "203.0.113.7",
      "100.63.255.255",
      "100.128.0.1",
      "fd00::2",
      "fd00:ec2::253",
      "2001:db8::1",
      "::ffff:8.8.8.8",
      "::ffff:808:808",
      "not-an-ip",
    ]) {
      expect(isHostLocalAddress(ip), ip).toBe(false);
    }
  });

  it("knows the loopback names and the loopback bindings", () => {
    expect(isHostLocalName("localhost")).toBe(true);
    expect(isHostLocalName("app.LOCALHOST")).toBe(true);
    expect(isHostLocalName("localhost.example")).toBe(false);
    expect(isLoopbackBind("127.0.0.1")).toBe(true);
    expect(isLoopbackBind("127.0.1.1")).toBe(true);
    expect(isLoopbackBind("::1")).toBe(true);
    expect(isLoopbackBind("localhost")).toBe(true);
    expect(isLoopbackBind("0.0.0.0")).toBe(false);
    expect(isLoopbackBind("192.168.1.10")).toBe(false);
  });

  it("refuses with a reason, clears a literal as its own address, and clears a name with the address it checked (§21 R-19)", async () => {
    expect(await checkHostLocal("169.254.169.254")).toEqual({
      refused:
        "169.254.169.254 is a host-local destination (this machine's loopback or link-local, shared address space, or the cloud metadata service)",
    });
    // Alibaba Cloud's metadata endpoint sits in the shared address space (§21 R-20)
    expect("refused" in (await checkHostLocal("100.100.100.200"))).toBe(true);
    expect(await checkHostLocal("203.0.113.7")).toEqual({ address: null });
    const lookup = (host: string) =>
      host === "meta.example"
        ? Promise.resolve([
            { address: "2001:db8::1", family: 6 },
            { address: "169.254.169.254", family: 4 },
          ])
        : Promise.resolve([{ address: "203.0.113.7", family: 4 }]);
    expect(await checkHostLocal("meta.example", lookup)).toEqual({
      refused:
        "meta.example resolves to a host-local address (169.254.169.254 — loopback or link-local, where the cloud metadata service lives)",
    });
    // The checked address travels with the clearance: the connection goes there, not to a second lookup
    expect(await checkHostLocal("api.example", lookup)).toEqual({ address: "203.0.113.7" });
    expect(
      await checkHostLocal("gone.example", () => Promise.reject(new Error("ENOTFOUND"))),
    ).toEqual({
      refused: "gone.example cannot be resolved",
    });
    expect(await checkHostLocal("empty.example", () => Promise.resolve([]))).toEqual({
      refused: "empty.example cannot be resolved",
    });
    // A literal in any form never reaches the resolver (and is classified by value)
    expect(
      "refused" in (await checkHostLocal("::ffff:7f00:1", () => Promise.reject(new Error("no")))),
    ).toBe(true);
    expect(await checkHostLocal("[2001:db8::1]", () => Promise.reject(new Error("no")))).toEqual({
      address: null,
    });
  });

  it("brackets IPv6 literals in an authority", () => {
    expect(formatAuthority("127.0.0.1", 8080)).toBe("127.0.0.1:8080");
    expect(formatAuthority("host.docker.internal", 3128)).toBe("host.docker.internal:3128");
    expect(formatAuthority("::1", 8080)).toBe("[::1]:8080");
    expect(formatAuthority("fd00::2", 1)).toBe("[fd00::2]:1");
  });
});
