// The chain-read grants of issued leases (do/lease-chain-grants.ts —
// AUTH_SPEC §14-2): a token opens exactly its own head, once, until the
// TTL runs out.

import { describe, expect, it } from "vitest";

import { LeaseChainGrants } from "../src/do/lease-chain-grants.ts";

const HEAD_A = { seq: 7, hashHex: "aa".repeat(32) };
const HEAD_B = { seq: 9, hashHex: "bb".repeat(32) };

describe("LeaseChainGrants (AUTH_SPEC §14-2)", () => {
  it("a grant opens its own head once, before the TTL runs out", () => {
    const grants = new LeaseChainGrants(1_000);
    const a = grants.grant(HEAD_A, 0);
    const b = grants.grant(HEAD_B, 0);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(grants.take("00".repeat(32), 10)).toBeUndefined();
    expect(grants.take(a, 999)).toEqual(HEAD_A);
    expect(grants.take(a, 999)).toBeUndefined();
    expect(grants.take(b, 999)).toEqual(HEAD_B);
  });

  it("an expired grant opens nothing", () => {
    const grants = new LeaseChainGrants(1_000);
    const a = grants.grant(HEAD_A, 0);
    expect(grants.take(a, 1_000)).toBeUndefined();
    const b = grants.grant(HEAD_B, 5_000);
    expect(grants.take(b, 7_000)).toBeUndefined();
  });
});
