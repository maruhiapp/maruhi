import {
  approvalSignersOf,
  type ChainActor,
  type ChainEntry as VerifiedChainEntry,
  type ChainHistoryIndex,
  type ChainOperation,
  computeChainEntryHash,
  computeDekCommitment,
  computeServerKeyFingerprint,
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
  verifyChainWithHistory,
} from "@maruhi/crypto";
import {
  BASE_TIME_MS,
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  toTypedEntry,
  unwrapResult,
  vectorEntries,
  vectorExtendedChains,
} from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vite-plus/test";

import { deriveReportedView } from "../../src/dashboard/chain-view.ts";
import type { ChainEntry } from "../../src/dashboard/types.ts";

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
  const view = deriveReportedView(entries as ReadonlyArray<ChainEntry>, state.headHashHex);
  const web = Object.fromEntries(
    view.proposals.map((p) => [p.proposalHashHex, [...p.voterUserIds].toSorted()]),
  );
  return { crypto, web };
}

function vectorChains(): ReadonlyArray<{
  name: string;
  entries: ReadonlyArray<VerifiedChainEntry>;
  fromLength: number;
}> {
  const canonical = vectorEntries.map(toTypedEntry);
  return [
    { name: "canonical", entries: canonical, fromLength: 1 },
    ...Object.entries(vectorExtendedChains).map(([name, extended]) => ({
      name,
      entries: [...canonical.slice(0, extended.base_seq), ...extended.entries.map(toTypedEntry)],
      fromLength: extended.base_seq + 1,
    })),
  ];
}

interface Coverage {
  pointsWithPending: number;
  pendingCompared: number;
  multiVoterTallies: number;
}

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

class ChainBuilder {
  readonly entries: VerifiedChainEntry[] = [];
  private prevHashHex = "0".repeat(64);

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
  await chain.append(o!, {
    op: "change_role",
    payload: { targetUserId: a!.actor.userId, newRole: "member", ...ALL },
  });
  await chain.append(b2!, approveOp(removeM));
  await chain.append(b!, revokeDeviceOp(b!.actor.userId, b2!));
  await chain.append(b!, approveOp(removeM));
  await chain.append(b!, addDeviceOp(b2!, "owner"));
  await chain.append(c!, approveOp(removeM));
  await chain.append(o!, addMemberOp(n!, "member"));
  await chain.append(o!, addDeviceOp(o2!, "admin"));
  const removeN = await chain.append(o2!, proposeRemoveOp(n!.actor.userId));
  await chain.append(c!, approveOp(removeN));
  await chain.append(b!, approveOp(removeN));
  return chain.entries;
}

async function reenrolledProposerChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, o2, a, b, m] = await Promise.all(
    ["user_o", "user_o", "user_a", "user_b", "user_m"].map(makeKey),
  );
  const chain = new ChainBuilder();
  await chain.append(o!, genesisOp(o!));
  for (const owner of [a!, b!]) await chain.append(o!, addMemberOp(owner, "owner"));
  await chain.append(o!, addMemberOp(m!, "member"));
  await chain.append(o!, addDeviceOp(o2!, "admin"));
  await chain.append(o!, policyOp(3));
  const removeM = await chain.append(o2!, proposeRemoveOp(m!.actor.userId));
  await chain.append(o!, revokeDeviceOp(o!.actor.userId, o2!));
  await chain.append(o!, addDeviceOp(o2!, "owner"));
  await chain.append(a!, approveOp(removeM));
  await chain.append(b!, approveOp(removeM));
  return chain.entries;
}

async function reenrolledUnboundProposerChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, d1, d2, a, b, m, n] = await Promise.all(
    ["user_o", "user_o", "user_o", "user_a", "user_b", "user_m", "user_n"].map(makeKey),
  );
  const chain = new ChainBuilder();
  await chain.append(o!, genesisOp(o!));
  for (const owner of [a!, b!]) await chain.append(o!, addMemberOp(owner, "owner"));
  await chain.append(o!, addMemberOp(m!, "member"));
  await chain.append(o!, addDeviceOp(d1!, "owner"));
  await chain.append(o!, addDeviceOp(d2!, "admin"));
  await chain.append(o!, policyOp(3));
  const removeM = await chain.append(d2!, proposeRemoveOp(m!.actor.userId));
  await chain.append(o!, revokeDeviceOp(o!.actor.userId, d2!));
  await chain.append(o!, addDeviceOp(d2!, "owner"));
  await chain.append(d2!, addMemberOp(n!, "member"));
  await chain.append(a!, approveOp(removeM));
  await chain.append(b!, approveOp(removeM));
  return chain.entries;
}

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
    for (const chain of vectorChains()) {
      if (!chain.entries.some((entry) => entry.op === "propose")) continue;
      await expectAgreementAtEveryPrefix(chain.name, chain.entries, coverage, chain.fromLength);
    }
    expect(coverage.pointsWithPending).toBeGreaterThanOrEqual(105);
    expect(coverage.pendingCompared).toBeGreaterThanOrEqual(125);
  }, 60_000);

  it("agrees at every prefix of built chains with multi-vote pending proposals, lost and recast votes, second-device votes, and a proposer key re-enrolled owner-capped", async () => {
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
    const reenrolled = await reenrolledProposerChain();
    await expectAgreementAtEveryPrefix("reenrolled-proposer", reenrolled, coverage);
    expect(Object.values((await talliesAt(reenrolled)).web)).toEqual([["user_a", "user_b"]]);
    const reenrolledUnbound = await reenrolledUnboundProposerChain();
    await expectAgreementAtEveryPrefix("reenrolled-unbound-proposer", reenrolledUnbound, coverage);
    expect(Object.values((await talliesAt(reenrolledUnbound)).web)).toEqual([["user_a", "user_b"]]);
    expect(coverage.multiVoterTallies).toBeGreaterThanOrEqual(9);
  }, 60_000);

  describe("the intentional difference: the web shows fewer voters than crypto, never more, when an unbound vote's device cannot be told apart (K5-2)", () => {
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
      const { chain, removeM } = await ambiguousVoteChain("member");
      await expectWebSubsetAtEveryPrefix(chain.entries);
      const { crypto, web } = await talliesAt(chain.entries);
      expect(crypto[removeM]).toEqual(["user_a", "user_o"]);
      expect(web[removeM]).toEqual(["user_o"]);
    }, 60_000);

    it("does not count a proposal signature from one of several unbound devices when one of them is below owner", async () => {
      const [o, d1, d2, a, b, m] = await Promise.all(
        ["user_o", "user_o", "user_o", "user_a", "user_b", "user_m"].map(makeKey),
      );
      const chain = new ChainBuilder();
      await chain.append(o!, genesisOp(o!));
      for (const owner of [a!, b!]) await chain.append(o!, addMemberOp(owner, "owner"));
      await chain.append(o!, addMemberOp(m!, "member"));
      await chain.append(o!, addDeviceOp(d1!, "owner"));
      await chain.append(o!, addDeviceOp(d2!, "admin"));
      await chain.append(o!, policyOp(3));
      const removeM = await chain.append(d1!, proposeRemoveOp(m!.actor.userId));
      await chain.append(a!, approveOp(removeM));
      await expectWebSubsetAtEveryPrefix(chain.entries);
      const { crypto, web } = await talliesAt(chain.entries);
      expect(crypto[removeM]).toEqual(["user_a", "user_o"]);
      expect(web[removeM]).toEqual(["user_a"]);
    }, 60_000);

    it("drops an unbound vote once a revocation the bytes cannot attribute may have hit its device", async () => {
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

function scopeKey(kind: "all" | "listed", ids: ReadonlyArray<string>): string {
  return kind === "all" ? "all" : `listed:${ids.toSorted().join(",")}`;
}

interface DeviceRow {
  key: string;
  fingerprint: string | null;
  cap: string;
  addedSeq: number;
}

interface MemberRow {
  userId: string;
  role: string;
  scope: string;
  sinceSeq: number;
  devices: ReadonlyArray<DeviceRow> | null;
}

function roleAndScopeAt(history: ChainHistoryIndex, userId: string, seq: number): string | null {
  const at = history.memberStateAt(userId, seq);
  if (at === undefined) return null;
  const ids = at.scope.kind === "all" ? [] : at.scope.environmentIds;
  return `${at.role}/${scopeKey(at.scope.kind, ids)}`;
}

function sinceSeqOf(history: ChainHistoryIndex, userId: string): number {
  const current = roleAndScopeAt(history, userId, history.headSeq);
  let seq = history.headSeq;
  while (seq > 1 && roleAndScopeAt(history, userId, seq - 1) === current) seq -= 1;
  return seq;
}

interface ServerRow {
  fingerprint: string;
  scope: string;
  sinceSeq: number;
}

const byKey = (a: DeviceRow, b: DeviceRow) => a.key.localeCompare(b.key);
const byUser = (a: MemberRow, b: MemberRow) => a.userId.localeCompare(b.userId);
const byServer = (a: ServerRow, b: ServerRow) => a.fingerprint.localeCompare(b.fingerprint);

async function membershipAt(entries: ReadonlyArray<VerifiedChainEntry>) {
  const { state, history } = unwrapResult(
    await verifyChainWithHistory(entries),
    "verifyChainWithHistory",
  );
  const view = deriveReportedView(entries as ReadonlyArray<ChainEntry>, state.headHashHex);
  const webFingerprints = new Map<string, string | null>();
  const unresolved = new Set<string>();
  const web: MemberRow[] = view.members.map((member) => {
    if (member.unresolvedRevocations > 0) unresolved.add(member.userId);
    const devices = member.devices.map((device) => {
      const key = `${member.userId}:${device.encPubHex}:${device.sigPubHex}`;
      webFingerprints.set(key, device.keyFingerprintHex);
      return {
        key,
        fingerprint: device.keyFingerprintHex,
        cap: `${device.roleCap}/${scopeKey(device.scopeKind, device.scopeEnvironmentIds)}`,
        addedSeq: device.addedSeq,
      };
    });
    return {
      userId: member.userId,
      role: member.role,
      scope: scopeKey(member.scopeKind, member.scopeEnvironmentIds),
      sinceSeq: member.sinceSeq,
      devices: member.unresolvedRevocations > 0 ? null : devices.toSorted(byKey),
    };
  });
  const crypto: MemberRow[] = [...state.members.values()].map((member) => {
    const devices = [...member.devices.values()].map((device) => {
      const key = `${member.userId}:${device.encPubHex}:${device.sigPubHex}`;
      return {
        key,
        fingerprint: webFingerprints.get(key) === null ? null : device.keyFingerprintHex,
        cap: `${device.roleCap}/${scopeKey(device.scope.kind, device.scope.kind === "all" ? [] : device.scope.environmentIds)}`,
        addedSeq: device.addedSeq,
      };
    });
    return {
      userId: member.userId,
      role: member.role,
      scope: scopeKey(
        member.scope.kind,
        member.scope.kind === "all" ? [] : member.scope.environmentIds,
      ),
      sinceSeq: sinceSeqOf(history, member.userId),
      devices: unresolved.has(member.userId) ? null : devices.toSorted(byKey),
    };
  });
  const webServers: ServerRow[] = view.servers.map((server) => ({
    fingerprint: server.keyFingerprintHex,
    scope: scopeKey("listed", server.scopeEnvironmentIds),
    sinceSeq: server.sinceSeq,
  }));
  const cryptoServers: ServerRow[] = [...state.serverGrants.values()].map((grant) => ({
    fingerprint: grant.serverKeyFingerprintHex,
    scope: scopeKey("listed", grant.scopeEnvironmentIds),
    sinceSeq: grant.grantSeq,
  }));
  return {
    web: { members: web.toSorted(byUser), servers: webServers.toSorted(byServer) },
    crypto: { members: crypto.toSorted(byUser), servers: cryptoServers.toSorted(byServer) },
    skippedDevices: unresolved.size,
  };
}

interface MembershipCoverage {
  points: number;
  listedScopes: number;
  skippedDevices: number;
}

async function expectMembershipAgreementAtEveryPrefix(
  name: string,
  entries: ReadonlyArray<VerifiedChainEntry>,
  coverage: MembershipCoverage,
  fromLength = 1,
): Promise<void> {
  for (let length = fromLength; length <= entries.length; length += 1) {
    const { web, crypto, skippedDevices } = await membershipAt(entries.slice(0, length));
    expect(web, `${name} @ seq ${length}`).toEqual(crypto);
    coverage.points += 1;
    coverage.listedScopes += crypto.members.filter((m) => m.scope !== "all").length;
    coverage.skippedDevices += skippedDevices;
  }
}

async function deletionChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, o2, a, a2, l] = await Promise.all(
    ["user_o", "user_o", "user_a", "user_a", "user_l"].map(makeKey),
  );
  const chain = new ChainBuilder();
  const projectId = testProjectId(await chain.append(o!, genesisOp(o!)));
  for (const environmentId of ["dev", "prod"].map(testEnvironmentId)) {
    const dekCommitmentHex = unwrapResult(
      await computeDekCommitment({
        context: { suite: SUITE_ID, projectId, environmentId, epoch: 1 },
        dek: new Uint8Array(32).fill(7),
      }),
      "computeDekCommitment",
    );
    await chain.append(o!, {
      op: "create_environment",
      payload: { environmentId, dekCommitmentHex },
    });
  }
  const listed = (ids: string[]) => ({
    scopeKind: "listed" as const,
    scopeEnvironmentIds: ids.map(testEnvironmentId),
  });
  await chain.append(o!, {
    op: "add_member",
    payload: {
      targetUserId: l!.actor.userId,
      encPubHex: l!.encPubHex,
      sigPubHex: l!.sigPubHex,
      role: "member",
      ...listed(["dev"]),
    },
  });
  await chain.append(o!, {
    op: "add_member",
    payload: {
      targetUserId: a!.actor.userId,
      encPubHex: a!.encPubHex,
      sigPubHex: a!.sigPubHex,
      role: "admin",
      ...listed(["dev", "prod"]),
    },
  });
  await chain.append(a!, {
    op: "add_device",
    payload: {
      encPubHex: a2!.encPubHex,
      sigPubHex: a2!.sigPubHex,
      roleCap: "member",
      ...listed(["dev"]),
    },
  });
  await chain.append(o!, {
    op: "add_device",
    payload: {
      encPubHex: o2!.encPubHex,
      sigPubHex: o2!.sigPubHex,
      roleCap: "owner",
      ...listed(["dev", "prod"]),
    },
  });
  for (const ids of [["dev"], ["dev", "prod"]]) {
    const server = await generateEncryptionKeyPair();
    const serverEncPub = await exportEncryptionPublicKey(server.publicKey);
    const fingerprint = unwrapResult(
      await computeServerKeyFingerprint(serverEncPub),
      "computeServerKeyFingerprint",
    );
    await chain.append(o!, {
      op: "grant_server",
      payload: {
        serverEncPubHex: encodeHex(serverEncPub),
        serverKeyFingerprintHex: testKeyFingerprintHex(encodeHex(fingerprint)),
        scopeEnvironmentIds: ids.map(testEnvironmentId),
        leasePolicy: [],
      },
    });
  }
  await chain.append(o!, {
    op: "delete_environment",
    payload: { environmentId: testEnvironmentId("dev") },
  });
  return chain.entries;
}

describe("members and servers drift (web fold vs crypto verifyChain)", () => {
  it("agrees on roles, scopes, device caps and server scopes at every prefix of every positive chain vector", async () => {
    const coverage: MembershipCoverage = { points: 0, listedScopes: 0, skippedDevices: 0 };
    for (const chain of vectorChains()) {
      await expectMembershipAgreementAtEveryPrefix(
        chain.name,
        chain.entries,
        coverage,
        chain.fromLength,
      );
    }
    expect(coverage.points).toBeGreaterThanOrEqual(200);
    expect(coverage.listedScopes).toBeGreaterThanOrEqual(450);
    expect(coverage.skippedDevices).toBeGreaterThanOrEqual(1);
    expect(coverage.skippedDevices).toBeLessThan(coverage.points / 10);
  }, 60_000);

  it("agrees on sinceSeq when a change_role restates the current role and scope", async () => {
    const [o, a] = await Promise.all(["user_o", "user_a"].map(makeKey));
    const chain = new ChainBuilder();
    await chain.append(o!, genesisOp(o!));
    await chain.append(o!, addMemberOp(a!, "member"));
    const restate = (newRole: "member" | "admin"): ChainOperation => ({
      op: "change_role",
      payload: { targetUserId: a!.actor.userId, newRole, ...ALL },
    });
    await chain.append(o!, restate("member"));
    await chain.append(o!, restate("admin"));
    await chain.append(o!, restate("admin"));
    const coverage: MembershipCoverage = { points: 0, listedScopes: 0, skippedDevices: 0 };
    await expectMembershipAgreementAtEveryPrefix("restated-role", chain.entries, coverage);
    const sinceSeqAt = async (length: number) =>
      (await membershipAt(chain.entries.slice(0, length))).web.members.find(
        (member) => member.userId === "user_a",
      )?.sinceSeq;
    expect(await sinceSeqAt(3)).toBe(2);
    expect(await sinceSeqAt(5)).toBe(4);
  }, 60_000);

  it("agrees at every prefix of a built chain deleting an environment named by member scopes, device caps and server grants", async () => {
    const coverage: MembershipCoverage = { points: 0, listedScopes: 0, skippedDevices: 0 };
    const entries = await deletionChain();
    await expectMembershipAgreementAtEveryPrefix("deletion", entries, coverage);
    const { crypto } = await membershipAt(entries);
    expect(crypto.members.map((m) => m.scope)).toContain("listed:");
    expect(crypto.members.flatMap((m) => m.devices ?? []).map((d) => d.cap)).toContain(
      "member/listed:",
    );
    expect(crypto.servers.map((s) => s.scope)).toEqual(
      expect.arrayContaining(["listed:", "listed:prod"]),
    );
  }, 60_000);
});

interface ProposalRecord {
  hash: string;
  seq: number;
  proposer: string;
  innerOp: string;
  expiresAtMs: number;
}

async function recordsAt(entries: ReadonlyArray<VerifiedChainEntry>) {
  const state = unwrapResult(await verifyChain(entries), "verifyChain");
  const view = deriveReportedView(entries as ReadonlyArray<ChainEntry>, state.headHashHex);
  const policyOf = (policy: { requiredApprovals: number; ops: ReadonlyArray<string> } | null) =>
    policy === null ? null : `${policy.requiredApprovals}:${policy.ops.toSorted().join(",")}`;
  const bySeq = (a: ProposalRecord, b: ProposalRecord) => a.seq - b.seq;
  return {
    web: {
      policy: policyOf(view.policy),
      proposals: view.proposals.map((p) => ({
        hash: p.proposalHashHex,
        seq: p.proposalSeq,
        proposer: p.proposerUserId,
        innerOp: p.innerOp,
        expiresAtMs: p.expiresAtMs,
      })),
      unreadableEntries: view.unreadableEntries,
    },
    crypto: {
      policy: policyOf(state.approvalPolicy),
      proposals: [...state.pendingProposals.values()]
        .map((p) => ({
          hash: p.proposalHashHex,
          seq: p.proposalSeq,
          proposer: p.proposerUserId,
          innerOp: p.inner.op,
          expiresAtMs: p.expiresAtMs,
        }))
        .toSorted(bySeq),
      unreadableEntries: 0,
    },
  };
}

interface RecordCoverage {
  points: number;
  policyPoints: number;
  policies: Set<string>;
  proposals: number;
  innerOps: Set<string>;
}

async function expectRecordAgreementAtEveryPrefix(
  name: string,
  entries: ReadonlyArray<VerifiedChainEntry>,
  coverage: RecordCoverage,
  fromLength = 1,
): Promise<void> {
  for (let length = fromLength; length <= entries.length; length += 1) {
    const { web, crypto } = await recordsAt(entries.slice(0, length));
    expect(web, `${name} @ seq ${length}`).toEqual(crypto);
    coverage.points += 1;
    if (crypto.policy !== null) {
      coverage.policyPoints += 1;
      coverage.policies.add(crypto.policy);
    }
    coverage.proposals += crypto.proposals.length;
    for (const proposal of crypto.proposals) coverage.innerOps.add(proposal.innerOp);
  }
}

async function policyOffChain(): Promise<ReadonlyArray<VerifiedChainEntry>> {
  const [o, a, m] = await Promise.all(["user_o", "user_a", "user_m"].map(makeKey));
  const chain = new ChainBuilder();
  await chain.append(o!, genesisOp(o!));
  await chain.append(o!, addMemberOp(a!, "owner"));
  await chain.append(o!, addMemberOp(m!, "member"));
  await chain.append(o!, {
    op: "set_approval_policy",
    payload: { ops: ["remove_member", "grant_server", "remove_member"], requiredApprovals: 2 },
  });
  await chain.append(o!, proposeRemoveOp(m!.actor.userId));
  const off = await chain.append(o!, {
    op: "propose",
    payload: {
      inner: { op: "set_approval_policy", payload: { ops: [], requiredApprovals: 0 } },
      expiresAtMs: EXPIRES_AT_MS,
    },
  });
  await chain.append(a!, approveOp(off));
  return chain.entries;
}

const emptyRecordCoverage = (): RecordCoverage => ({
  points: 0,
  policyPoints: 0,
  policies: new Set(),
  proposals: 0,
  innerOps: new Set(),
});

describe("policy, proposal record and readability drift (web fold vs crypto verifyChain)", () => {
  it("agrees on the policy and each pending proposal's record, and reads every entry, at every prefix of every positive chain vector", async () => {
    const coverage = emptyRecordCoverage();
    for (const chain of vectorChains()) {
      await expectRecordAgreementAtEveryPrefix(
        chain.name,
        chain.entries,
        coverage,
        chain.fromLength,
      );
    }
    expect(coverage.points).toBeGreaterThanOrEqual(200);
    expect(coverage.policyPoints).toBeGreaterThanOrEqual(150);
    expect(coverage.policies.size).toBeGreaterThanOrEqual(4);
    expect(coverage.proposals).toBeGreaterThanOrEqual(125);
    expect(coverage.innerOps.size).toBeGreaterThanOrEqual(6);
  }, 60_000);

  it("agrees at every prefix of the built chains, including a policy turned off with a proposal pending", async () => {
    const coverage = emptyRecordCoverage();
    for (const [name, entries] of [
      ["demotion-and-revocation", await demotionAndRevocationChain()],
      ["ambiguous-owner-capped", await ambiguousOwnerCappedChain()],
      ["deletion", await deletionChain()],
      ["policy-off", await policyOffChain()],
      ["reenrolled-proposer", await reenrolledProposerChain()],
      ["reenrolled-unbound-proposer", await reenrolledUnboundProposerChain()],
    ] as const) {
      await expectRecordAgreementAtEveryPrefix(name, entries, coverage);
    }
    expect(coverage.policies).toEqual(new Set(["3:remove_member", "2:grant_server,remove_member"]));
    expect(coverage.proposals).toBeGreaterThanOrEqual(18);
    const offAtHead = await recordsAt(await policyOffChain());
    expect(offAtHead.crypto.policy).toBeNull();
    expect(offAtHead.crypto.proposals).toHaveLength(1);
  }, 60_000);
});
