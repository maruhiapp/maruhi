// Decision logic of the four-eyes admission policy (AUTH_SPEC §12-8 /
// CRYPTO_SPEC §6.4 — pure functions in quotas.ts). Wiring into the admission
// path is covered by approval-accept.test.ts (over HTTP, via the DO's
// appendProgram).

import type { PendingProposal } from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vitest";

import { MAX_PENDING_PROPOSALS, MAX_PROPOSAL_LIFETIME_MS } from "../src/policy.ts";
import {
  countLivePendingProposals,
  pendingProposalsExceeded,
  proposalIsLive,
  proposalLifetimeExceeded,
} from "../src/quotas.ts";

const NOW = 1_800_000_000_000;

const pendingAt = (expiresAtMs: number): PendingProposal => ({
  proposalSeq: 1,
  proposalHashHex: "ab".repeat(32),
  proposerUserId: testUserId("user-owner-0001"),
  proposerKeyFingerprintHex: "cd".repeat(16),
  proposerRoleAtProposal: "owner",
  inner: { op: "remove_member", payload: { targetUserId: testUserId("user-member-0002") } },
  expiresAtMs,
  approvals: [],
});

describe("proposalIsLive / countLivePendingProposals (expired ones are not counted — server clock)", () => {
  it("counts a proposal while expires_at_ms >= now (equality counts as within the period — same direction as §6.2's ≤)", () => {
    expect(proposalIsLive(NOW, NOW)).toBe(true);
    expect(proposalIsLive(NOW + 1, NOW)).toBe(true);
    expect(proposalIsLive(NOW - 1, NOW)).toBe(false);
    const pending = new Map<string, PendingProposal>([
      ["a", pendingAt(NOW - 1)],
      ["b", pendingAt(NOW)],
      ["c", pendingAt(NOW + 1)],
    ]);
    expect(countLivePendingProposals(pending, NOW)).toBe(2);
    expect(countLivePendingProposals(new Map(), NOW)).toBe(0);
  });
});

describe("proposalLifetimeExceeded (upper bound of expires_at_ms = now + 30 days)", () => {
  it("admits up to the bound inclusive and rejects beyond it", () => {
    expect(MAX_PROPOSAL_LIFETIME_MS).toBe(30 * 24 * 60 * 60 * 1000);
    expect(proposalLifetimeExceeded(NOW + MAX_PROPOSAL_LIFETIME_MS, NOW)).toBe(false);
    expect(proposalLifetimeExceeded(NOW + MAX_PROPOSAL_LIFETIME_MS + 1, NOW)).toBe(true);
    // A past expiry does not hit the upper bound (expired proposals are
    // admitted — design record §11 K5-C)
    expect(proposalLifetimeExceeded(0, NOW)).toBe(false);
  });
});

describe("pendingProposalsExceeded (pending cap 32)", () => {
  it("rejects the 33rd live proposal only", () => {
    expect(MAX_PENDING_PROPOSALS).toBe(32);
    expect(pendingProposalsExceeded(MAX_PENDING_PROPOSALS - 1)).toBe(false);
    expect(pendingProposalsExceeded(MAX_PENDING_PROPOSALS)).toBe(true);
  });
});
