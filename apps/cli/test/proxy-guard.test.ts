// Tests for the host-local guard of sandbox mode (proxy-guard.ts — §21 R-12)
// and the authority formatting (§21 R-11).

import { describe, expect, it } from "vitest";

import {
  formatAuthority,
  hostLocalReason,
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
    ]) {
      expect(isHostLocalAddress(ip), ip).toBe(true);
    }
    for (const ip of [
      "10.0.0.1",
      "172.16.5.5",
      "192.168.1.1",
      "203.0.113.7",
      "fd00::2",
      "2001:db8::1",
      "::ffff:8.8.8.8",
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

  it("explains why a destination is refused, and resolves names before deciding", async () => {
    expect(await hostLocalReason("169.254.169.254")).toBe(
      "169.254.169.254 is a host-local destination (this machine's loopback)",
    );
    expect(await hostLocalReason("203.0.113.7")).toBeNull();
    const lookup = (host: string) =>
      host === "meta.example"
        ? Promise.resolve([
            { address: "2001:db8::1", family: 6 },
            { address: "169.254.169.254", family: 4 },
          ])
        : Promise.resolve([{ address: "203.0.113.7", family: 4 }]);
    expect(await hostLocalReason("meta.example", lookup)).toBe(
      "meta.example resolves to a host-local address (169.254.169.254 — loopback or link-local, where the cloud metadata service lives)",
    );
    expect(await hostLocalReason("api.example", lookup)).toBeNull();
    expect(
      await hostLocalReason("gone.example", () => Promise.reject(new Error("ENOTFOUND"))),
    ).toBe("gone.example cannot be resolved");
  });

  it("brackets IPv6 literals in an authority", () => {
    expect(formatAuthority("127.0.0.1", 8080)).toBe("127.0.0.1:8080");
    expect(formatAuthority("host.docker.internal", 3128)).toBe("host.docker.internal:3128");
    expect(formatAuthority("::1", 8080)).toBe("[::1]:8080");
    expect(formatAuthority("fd00::2", 1)).toBe("[fd00::2]:1");
  });
});
