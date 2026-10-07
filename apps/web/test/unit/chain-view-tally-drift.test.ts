// Drift test of the four-eyes tally (issue #13): the web fold's copy
// (`signersOf` / `countedVoters` in chain-view-proposals.ts) against
// crypto's one definition (`approvalSignersOf` / `ownerVotersOf` —
// CRYPTO_SPEC §6.2 principle 2).
//
// The web bundle may not contain crypto code (ADR-0018 — the
// `@maruhi/crypto` tripwire in endpoints.test.ts scans apps/web/src
// only), so the copy stays. This test is not part of the shipped
// bundle: it runs both tallies over the same valid chains and requires
// them to agree. Every point is a prefix of a valid chain, so each
// prefix is itself valid: crypto verifies it and tallies each pending
// proposal over the verified members, and the web fold folds the same
// entries "as reported". Comparing the pending sets as well as the
// voters also pins that both sides apply a proposal at the same
// approve (the quorum judgment uses the same tally).
//
// The corpus: every prefix of every positive chain vector that carries
// a proposal (chain-entries.json — the canonical chain and each
// extended chain), plus chains built here for the shapes the vectors
// leave out (a pending proposal holding two or more counted votes, a
// vote lost to a demotion or a device revocation and cast again, a
// proposal signed from an owner's admin-capped device, an ambiguous
// vote from one of several fingerprint-unbound owner-capped devices).
//
// Structural difference with the same result: crypto's signer set takes
// the proposer's vote when the proposing device's **effective** role
// was owner; the web's `signersOf` takes it when the proposer's member
// role was owner (the signing device may be unbound at that point), and
// `countedVoters`' per-device cap check then drops a signature from a
// device capped below owner. The counted voters agree (the built chain
// proposes from an admin-capped device to pin this).
//
// Intentional difference: when a member has two or more devices whose
// fingerprints the reported bytes cannot bind (the `add_device` wire
// carries no FP — dk-design.md K5-1), the web counts a vote signed by
// one of them only while **every** unbound device of that member is
// owner-capped, and drops it after any revocation the bytes cannot
// attribute (K5-2). Crypto knows the signing device exactly. So the web
// may show fewer voters than crypto (fail-closed), never more; the last
// two cases pin that direction on valid chains.

import {
  approvalSignersOf,
  type ChainActor,
  type ChainEntry as VerifiedChainEntry,
  type ChainOperation,
  computeChainEntryHash,
  computeUserKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  ownerVotersOf,
  signChainEntry,
  SUITE_ID,
  type UserId,
  verifyChain,
} from "@maruhi/crypto";
import {
  BASE_TIME_MS,
  testKeyFingerprintHex,
  testUserId,
  toTypedEntry,
  unwrapResult,
  vectorEntries,
  vectorExtendedChains,
} from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vitest";

import { deriveReportedView } from "../../src/dashboard/chain-view.ts";
import type { ChainEntry } from "../../src/dashboard/types.ts";

/** proposal hash → sorted counted voter ids. */
type Tally = Record<string, ReadonlyArray<string>>;

interface TallyPair {
  crypto: Tally;
  web: Tally;
}

async function talliesAt(entries: ReadonlyArray<VerifiedChainEntry>): Promise<TallyPair> {
  const state = unwrapResult(await verifyChain(entries), "verifyChain");
  const crypto: Tally = {};
  for (const [hash, pending] of state.pendingProposals) {
    crypto[hash] = [...ownerVotersOf(state.members, approvalSignersOf(pending))].toSorted();
  }
  // The verified entry type and the wire type are the same shape (the
  // api-schema static check); the cast only crosses the two type names
  const view = deriveReportedView(entries as ReadonlyArray<ChainEntry>, state.headHashHex);
  const web = Object.fromEntries(
    view.proposals.map((p) => [p.proposalHashHex, [...p.voterUserIds].toSorted()]),
  );
  return { crypto, web };
}

/** Counts of what a comparison saw (guards against a vacuous pass). */
interface Coverage {
  pointsWithPending: number;
  pendingCompared: number;
  multiVoterTallies: number;
}

/** Compares the prefixes of length `fromLength`..all (shorter ones are compared elsewhere). */
async function expectAgreementAtEveryPrefix(
  name: string,
  entries: ReadonlyArray<VerifiedChainEntry>,
  coverage: Coverage,
  fromLength = 1,
): Promise<void> {
  for (let length = fromLength; length <= entries.length; length += 1) {
    const { crypto, web } = await talliesAt(entries.slice(0, length));
    expect(web, `${name} @ seq ${length}`).toEqual(crypto);
    const tallies = Object.values(crypto);
    if (tallies.length > 0) coverage.pointsWithPending += 1;
    coverage.pendingCompared += tallies.length;
    coverage.multiVoterTallies += tallies.filter((voters) => voters.length >= 2).length;
  }
}

// ---------------------------------------------------------------------------
// Built chains (public @maruhi/crypto API only — fresh keys each run)
// ---------------------------------------------------------------------------

interface TestKey {
  actor: ChainActor;
  encPubHex: string;
  sigPubHex: string;
  signingKey: CryptoKey;
}

async function makeKey(userId: string): Promise<TestKey> {
  const enc = await generateEncryptionKeyPair();
  const sig = await generateSigningKeyPair();
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const fingerprint = unwrapResult(await computeUserKeyFingerprint(encPub, sigPub), "fingerprint");
  return {
    actor: {
      userId: testUserId(userId),
      keyFingerprintHex: testKeyFingerprintHex(encodeHex(fingerprint)),
    },
    encPubHex: encodeHex(encPub),
    sigPubHex: encodeHex(sigPub),
    signingKey: sig.privateKey,
  };
}

/** Appends signed entries one at a time (an approve needs the hash of an earlier propose). */
class ChainBuilder {
  readonly entries: VerifiedChainEntry[] = [];
  private prevHashHex = "0".repeat(64);

  /** Appends and returns the new entry's hash. */
  async append(signer: TestKey, operation: ChainOperation): Promise<string> {
    const seq = this.entries.length + 1;
    const entry = unwrapResult(
      await signChainEntry({
        entry: {
          ...operation,
          suite: SUITE_ID,
          seq,
          prevHashHex: this.prevHashHex,
          actor: signer.actor,
          timestampMs: BASE_TIME_MS + seq * 1000,
        },
        signingKey: signer.signingKey,
      }),
      "signChainEntry",
    );
    this.entries.push(entry);
    this.prevHashHex = await computeChainEntryHash(entry);
    return this.prevHashHex;
  }
}

const EXPIRES_AT_MS = BASE_TIME_MS + 1_000_000_000;
const ALL = { scopeKind: "all", scopeEnvironmentIds: [] } as const;

const genesisOp = (key: TestKey): ChainOperation => ({
  op: "genesis",
  payload: { encPubHex: key.encPubHex, sigPubHex: key.sigPubHex },
});
const addMemberOp = (key: TestKey, role: "owner" | "member"): ChainOperation => ({
  op: "add_member",
  payload: {
    targetUserId: key.actor.userId,
    encPubHex: key.encPubHex,
    sigPubHex: key.sigPubHex,
    role,
    ...ALL,
  },
});
const addDeviceOp = (key: TestKey, roleCap: "owner" | "admin" | "member"): ChainOperation => ({
  op: "add_device",
  payload: { encPubHex: key.encPubHex, sigPubHex: key.sigPubHex, roleCap, ...ALL },
});
const revokeDeviceOp = (target: UserId, key: TestKey): ChainOperation => ({
  op: "revoke_device",
  payload: { targetUserId: target, deviceFingerprintsHex: [key.actor.keyFingerprintHex] },
});
const policyOp = (requiredApprovals: number): ChainOperation => ({
  op: "set_approval_policy",
  payload: { ops: ["remove_member"], requiredApprovals },
});
const proposeRemoveOp = (target: UserId): ChainOperation => ({
  op: "propose",
  payload: {
    inner: { op: "remove_member", payload: { targetUserId: target } },
    expiresAtMs: EXPIRES_AT_MS,
  },
});
const approveOp = (proposalHashHex: string): ChainOperation => ({
  op: "approve",
  payload: { proposalHashHex },
});

/**
 * Required 3 among four owners: an approver demoted (the vote stops
 * counting); a vote cast from an approver's second device, that device
 * revoked (the vote dies) and the vote cast again from the first
 * device; quorum reached by the remaining owners; and a second proposal
 * left pending with two counted votes.
 */
async function demotionAndRevocationChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, o2, a, b, b2, c, m, n] = await Promise.all(
    ["user_o", "user_o", "user_a", "user_b", "user_b", "user_c", "user_m", "user_n"].map(makeKey),
  );
  const chain = new ChainBuilder();
  await chain.append(o!, genesisOp(o!));
  for (const owner of [a!, b!, c!]) await chain.append(o!, addMemberOp(owner, "owner"));
  await chain.append(o!, addMemberOp(m!, "member"));
  await chain.append(b!, addDeviceOp(b2!, "owner"));
  await chain.append(o!, policyOp(3));
  const removeM = await chain.append(o!, proposeRemoveOp(m!.actor.userId));
  await chain.append(a!, approveOp(removeM));
  // change_role is not a policy target here, so the demotion is direct
  // (the owner count stays at the required 3)
  await chain.append(o!, {
    op: "change_role",
    payload: { targetUserId: a!.actor.userId, newRole: "member", ...ALL },
  });
  await chain.append(b2!, approveOp(removeM));
  await chain.append(b!, revokeDeviceOp(b!.actor.userId, b2!));
  await chain.append(b!, approveOp(removeM));
  await chain.append(c!, approveOp(removeM));
  await chain.append(o!, addMemberOp(n!, "member"));
  // An owner proposing from an admin-capped device: crypto's signer set
  // leaves the proposal out (effective role admin); the web's keeps it
  // and its per-device cap check does not count it
  await chain.append(o!, addDeviceOp(o2!, "admin"));
  const removeN = await chain.append(o2!, proposeRemoveOp(n!.actor.userId));
  await chain.append(c!, approveOp(removeN));
  await chain.append(b!, approveOp(removeN));
  return chain.entries;
}

/**
 * An owner with two fingerprint-unbound owner-capped devices votes from
 * one of them (the web counts it: every unbound device is owner-capped —
 * K5-2), then votes again on a second proposal from the other.
 */
async function ambiguousOwnerCappedChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, a, a2, a3, b, m, n] = await Promise.all(
    ["user_o", "user_a", "user_a", "user_a", "user_b", "user_m", "user_n"].map(makeKey),
  );
  const chain = new ChainBuilder();
  await chain.append(o!, genesisOp(o!));
  for (const owner of [a!, b!]) await chain.append(o!, addMemberOp(owner, "owner"));
  for (const member of [m!, n!]) await chain.append(o!, addMemberOp(member, "member"));
  await chain.append(a!, addDeviceOp(a2!, "owner"));
  await chain.append(a!, addDeviceOp(a3!, "owner"));
  await chain.append(o!, policyOp(3));
  const removeM = await chain.append(o!, proposeRemoveOp(m!.actor.userId));
  await chain.append(a2!, approveOp(removeM));
  const removeN = await chain.append(o!, proposeRemoveOp(n!.actor.userId));
  await chain.append(a3!, approveOp(removeN));
  return chain.entries;
}

describe("four-eyes tally drift (web fold vs crypto ownerVotersOf)", () => {
  it("agrees at every prefix of every positive chain vector that carries a proposal", async () => {
    const coverage: Coverage = { pointsWithPending: 0, pendingCompared: 0, multiVoterTallies: 0 };
    const canonical = vectorEntries.map(toTypedEntry);
    // An extended chain's prefixes up to its base_seq are canonical
    // prefixes (compared once, with the canonical chain)
    const chains = [
      { name: "canonical", entries: canonical, fromLength: 1 },
      ...Object.entries(vectorExtendedChains).map(([name, extended]) => ({
        name,
        entries: [...canonical.slice(0, extended.base_seq), ...extended.entries.map(toTypedEntry)],
        fromLength: extended.base_seq + 1,
      })),
    ];
    for (const chain of chains) {
      if (!chain.entries.some((entry) => entry.op === "propose")) continue;
      await expectAgreementAtEveryPrefix(chain.name, chain.entries, coverage, chain.fromLength);
    }
    expect(coverage.pointsWithPending).toBeGreaterThanOrEqual(100);
    expect(coverage.pendingCompared).toBeGreaterThanOrEqual(120);
  }, 60_000);

  it("agrees at every prefix of built chains with multi-vote pending proposals, lost and recast votes, and second-device votes", async () => {
    const coverage: Coverage = { pointsWithPending: 0, pendingCompared: 0, multiVoterTallies: 0 };
    await expectAgreementAtEveryPrefix(
      "demotion-and-revocation",
      await demotionAndRevocationChain(),
      coverage,
    );
    await expectAgreementAtEveryPrefix(
      "ambiguous-owner-capped",
      await ambiguousOwnerCappedChain(),
      coverage,
    );
    // The vectors hold no pending proposal with two or more counted
    // votes (their proposals run under a required-2 policy, so a second
    // counted vote applies them); these chains supply them
    expect(coverage.multiVoterTallies).toBeGreaterThanOrEqual(8);
  }, 60_000);

  describe("the intentional difference: the web shows fewer voters than crypto, never more, when an unbound vote's device cannot be told apart (K5-2)", () => {
    /**
     * Owners o, a, b (required 3) and member m; a registers a2 and a3
     * (both unbound in the reported bytes) with the given caps, o
     * proposes removing m and a approves from a2.
     */
    async function ambiguousVoteChain(a3Cap: "owner" | "member") {
      const [o, a, a2, a3, b, m] = await Promise.all(
        ["user_o", "user_a", "user_a", "user_a", "user_b", "user_m"].map(makeKey),
      );
      const chain = new ChainBuilder();
      await chain.append(o!, genesisOp(o!));
      for (const owner of [a!, b!]) await chain.append(o!, addMemberOp(owner, "owner"));
      await chain.append(o!, addMemberOp(m!, "member"));
      await chain.append(a!, addDeviceOp(a2!, "owner"));
      await chain.append(a!, addDeviceOp(a3!, a3Cap));
      await chain.append(o!, policyOp(3));
      const removeM = await chain.append(o!, proposeRemoveOp(m!.actor.userId));
      await chain.append(a2!, approveOp(removeM));
      return { chain, removeM, a: a!, a3: a3! };
    }

    /** At every prefix: the same pending set, and the web's voters ⊆ crypto's. */
    async function expectWebSubsetAtEveryPrefix(
      entries: ReadonlyArray<VerifiedChainEntry>,
    ): Promise<void> {
      for (let length = 1; length <= entries.length; length += 1) {
        const { crypto, web } = await talliesAt(entries.slice(0, length));
        expect(Object.keys(web), `pending @ seq ${length}`).toEqual(Object.keys(crypto));
        for (const [hash, voters] of Object.entries(web)) {
          expect(crypto[hash], `subset @ seq ${length}`).toEqual(
            expect.arrayContaining([...voters]),
          );
        }
      }
    }

    it("does not count a vote from one of several unbound devices when one of them is below owner", async () => {
      // a2 is owner-capped and a3 member-capped: crypto knows the vote
      // came from a2; the web cannot tell a2 from a3
      const { chain, removeM } = await ambiguousVoteChain("member");
      await expectWebSubsetAtEveryPrefix(chain.entries);
      const { crypto, web } = await talliesAt(chain.entries);
      expect(crypto[removeM]).toEqual(["user_a", "user_o"]);
      expect(web[removeM]).toEqual(["user_o"]);
    }, 60_000);

    it("drops an unbound vote once a revocation the bytes cannot attribute may have hit its device", async () => {
      // Both unbound devices are owner-capped, so the vote counts on both
      // sides; revoking a3 (never bound) may have been a revocation of
      // a2 as far as the reported bytes tell, so the web drops the vote
      const { chain, removeM, a, a3 } = await ambiguousVoteChain("owner");
      expect((await talliesAt(chain.entries)).web[removeM]).toEqual(["user_a", "user_o"]);
      await chain.append(a, revokeDeviceOp(a.actor.userId, a3));
      await expectWebSubsetAtEveryPrefix(chain.entries);
      const { crypto, web } = await talliesAt(chain.entries);
      expect(crypto[removeM]).toEqual(["user_a", "user_o"]);
      expect(web[removeM]).toEqual(["user_o"]);
    }, 60_000);
  });
});
