// 四眼の受理ポリシーの判定(AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — quotas.ts の純関数)。
// 受理経路への結線は approval-accept.test.ts(HTTP 経由・DO の appendProgram)。

import type { PendingProposal } from "@maruhi/crypto";
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
  proposerUserId: "user-owner-0001",
  proposerKeyFingerprintHex: "cd".repeat(16),
  proposerRoleAtProposal: "owner",
  inner: { op: "remove_member", payload: { targetUserId: "user-member-0002" } },
  expiresAtMs,
  approvals: [],
});

describe("proposalIsLive / countLivePendingProposals(期限切れは数えない — サーバー時計)", () => {
  it("counts a proposal while expires_at_ms >= now (等号は期限内 — §6.2 の ≤ と同じ向き)", () => {
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

describe("proposalLifetimeExceeded(expires_at_ms の上界 = now + 30 日)", () => {
  it("admits up to the bound inclusive and rejects beyond it", () => {
    expect(MAX_PROPOSAL_LIFETIME_MS).toBe(30 * 24 * 60 * 60 * 1000);
    expect(proposalLifetimeExceeded(NOW + MAX_PROPOSAL_LIFETIME_MS, NOW)).toBe(false);
    expect(proposalLifetimeExceeded(NOW + MAX_PROPOSAL_LIFETIME_MS + 1, NOW)).toBe(true);
    // 過去の期限は上界に掛からない(失効済み提案は受理する — 設計録 §11 K5-C)
    expect(proposalLifetimeExceeded(0, NOW)).toBe(false);
  });
});

describe("pendingProposalsExceeded(pending 上限 32)", () => {
  it("rejects the 33rd live proposal only", () => {
    expect(MAX_PENDING_PROPOSALS).toBe(32);
    expect(pendingProposalsExceeded(MAX_PENDING_PROPOSALS - 1)).toBe(false);
    expect(pendingProposalsExceeded(MAX_PENDING_PROPOSALS)).toBe(true);
  });
});
