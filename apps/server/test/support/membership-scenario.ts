// Shared scenario for membership-log integration tests (the same
// "shared fixture + register" pattern as data-scenario.ts).
//
// History of the split: vitest-pool-workers 0.22.0 had a harness-side bug
// where the per-request cost of SELF.fetch grows in proportion to the
// cumulative request count (workers-sdk#15092 / #15446); the split by
// describe exploited the fact that workerd is rebuilt per file to reset the
// degradation. The bug was fixed in @cloudflare/vitest-plugin 1.1.2
// (already migrated), so this split is no longer required for performance.
// It is kept for cross-file parallelism (one per core) and readability.
//
// Reuse of the test vectors (packages/crypto/test-vectors/chain-entries.json):
// - Replay the happy path seq 1-12 as server acceptance tests (each actor's
//   real PAT auth. create_environment / rotate_epoch go through the
//   composite endpoint — §12-4). Because the composite inserts a boundary
//   checkpoint (H+2), the head drifts from the vector's fixed seq / prev
//   after the first composite. Subsequent entries keep op / payload / actor
//   and are re-signed at the real head to follow it (byte pinning is the job
//   of the crypto layer's 4-runtime tests; here we pin that the same op
//   sequence is accepted by the API)
// - Replay all authz negatives as rejection tests (re-signed at the real
//   head in the same way)
//
// Auth obtains PATs via the real issuance path (CLI login handoff). The
// vectors' fixed user_ids are aligned by seeding D1 directly (users +
// linked_identities) (AUTH_SPEC §11-1 ruling).

import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { vectorEnvironmentDeks } from "@maruhi/crypto/test-support";
import { SELF } from "cloudflare:test";
import { beforeEach, expect } from "vitest";

import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./auth.ts";
import {
  toWireEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
  type VectorEntry,
} from "./chain-vectors.ts";
import type { WireEnvironmentManifest } from "./data-crypto.ts";
import {
  checkpointOperation,
  digestOf,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  resignEntryAt,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekToServer,
} from "./data-crypto.ts";
import { resetProjectDo } from "./project-do.ts";

export const VECTOR_ORG = "org-vector-0001";

const GITHUB_IDS: Record<string, number> = {
  "user-owner-0001": 9001,
  "user-member-0002": 9002,
  "user-admin-0003": 9003,
  // 2026-09-14 ES + PF1: the listed / all members and owner joining at seq 13-19 of the canonical chain
  "user-devmember-0010": 9010,
  "user-devadmin-0011": 9011,
  "user-prodreader-0012": 9012,
  "user-allmember-0013": 9013,
  "user-owner-0014": 9014,
  "user-owner-0015": 9015,
};

let tokens: Record<string, string> = {};

export function tokenFor(userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no seeded token for ${userId}`);
  }
  return token;
}

export const initChain = (
  entry: ChainEntry,
  options?: { readonly headers?: Record<string, string>; readonly orgId?: string },
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(options?.headers ?? bearer(tokenFor("user-owner-0001"))) },
    body: JSON.stringify({ orgId: options?.orgId ?? VECTOR_ORG, entry }),
  });

export const appendEntry = (
  projectId: string,
  parentHeadHashHex: string,
  entry: ChainEntry,
  headers?: Record<string, string>,
): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify({ parentHeadHashHex, entry }),
  });

export const getChain = (projectId: string, headers?: Record<string, string>): Promise<Response> =>
  SELF.fetch(`${BASE}/projects/${projectId}/chain`, {
    headers: headers ?? bearer(tokenFor("user-owner-0001")),
  });

/**
 * The vector's dummy DEK for (environment, epoch) (paired with the
 * computed commitment). For a negative's invalid coordinates (a
 * nonexistent epoch etc.) there is no vector DEK, so a random value
 * substitutes — their rejection does not depend on wrap contents (they fail
 * on consensus rules / check order).
 */
function vectorDek(environmentId: string, epoch: number): Uint8Array {
  const dekHex = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_hex;
  return dekHex === undefined ? makeDek() : hexBytes(dekHex);
}

/** Tracking of valid grants (for replayVectorChain): FP → enc public key + disclosure scope. */
interface TrackedServerGrant {
  readonly encPubHex: string;
  readonly scope: readonly string[];
}

/**
 * Latest-manifest tracking per environment (material for the composite's
 * manifestVersion CAS / prev chain — §12-5). Cleared at the start of
 * replayVectorChain (every test begins with a replay). envMeta is pinned
 * by the creation composite's bundled statement (metaVersion 1).
 */
const replayManifests = new Map<
  string,
  {
    manifest: WireEnvironmentManifest;
    issuerUserId: string;
    envMeta: { metaVersion: number; sigHashHex: string };
  }
>();

/**
 * The composite's wrap set (all current members + the server keys of valid
 * grants in the disclosure scope — the complete set of AUTH_SPEC §12-4).
 */
async function compositeWraps(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
  recipients: readonly string[],
  serverRecipients: readonly { readonly fpHex: string; readonly encPubHex: string }[],
) {
  const deks = await wrapDekForAll({
    projectId: vectorProjectId,
    environmentId,
    epoch,
    dek,
    recipientUserIds: recipients,
    signerUserId: entry.actor.userId,
  });
  for (const server of serverRecipients) {
    deks.push(
      await wrapDekToServer({
        projectId: vectorProjectId,
        environmentId,
        epoch,
        dek,
        serverKeyFingerprintHex: server.fpHex,
        serverEncPubHex: server.encPubHex,
        signerUserId: entry.actor.userId,
      }),
    );
  }
  return deks;
}

/**
 * The composite's bundled statement (creation only) + envMeta + manifest
 * (§12-4 / §12-5): the declared head is the current head before the
 * append; epoch is the one the bundled entry establishes. When there is no
 * tracking in a negative (e.g. rotate on a never-created environment), a
 * dummy-envMeta v1 is used (the rejection is decided by earlier checks).
 * The creation composite pins the wire shape at manifestVersion 1 with
 * empty prev (a negative's duplicate creation is sent in the same shape;
 * the rejection is the consensus rule's job).
 */
async function compositeManifestParts(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  environmentId: string,
  epoch: number,
) {
  const tracked = replayManifests.get(environmentId);
  const statement =
    entry.op === "create_environment"
      ? await signMetaStatementAs(entry.actor.userId, vectorProjectId, {
          suite: "maruhi/v1" as const,
          environmentId,
          name: environmentId,
          status: "active" as const,
          metaVersion: 1,
          prevMetaSigHashHex: "",
          chainHeadHashHex: entry.prevHashHex,
          chainHeadSeq: entry.seq - 1,
        })
      : null;
  const envMeta =
    statement !== null
      ? {
          metaVersion: 1,
          sigHashHex: await metaSignedBytesHashOf(vectorProjectId, statement, entry.actor.userId),
        }
      : (tracked?.envMeta ?? { metaVersion: 1, sigHashHex: "ab".repeat(32) });
  const chainlike =
    entry.op === "create_environment"
      ? { manifestVersion: 1, prevManifestSigHashHex: "" }
      : {
          manifestVersion: (tracked?.manifest.manifestVersion ?? 0) + 1,
          prevManifestSigHashHex:
            tracked === undefined
              ? ""
              : await manifestSignedBytesHashOf(
                  vectorProjectId,
                  tracked.manifest,
                  tracked.issuerUserId,
                ),
        };
  const manifest = await signEnvManifestAs(entry.actor.userId, vectorProjectId, {
    suite: "maruhi/v1",
    environmentId,
    epoch,
    ...chainlike,
    variablesDigestHex: await digestOf([]),
    envMetaVersion: envMeta.metaVersion,
    envMetaSigHashHex: envMeta.sigHashHex,
    chainHeadHashHex: entry.prevHashHex,
    chainHeadSeq: entry.seq - 1,
  });
  return { statement, envMeta, manifest };
}

/**
 * Send a create_environment / rotate_epoch vector entry to the composite
 * endpoint (AUTH_SPEC §12-4). The generic append rejects the two ops with
 * CompositeRequired, so both replay and negatives go through the
 * composite. The wrap set wraps the vector's dummy DEK to the current
 * member set (recipients) with real HPKE, signed by the actor itself.
 */
export async function submitComposite(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  recipients: readonly string[],
  headers?: Record<string, string>,
  serverRecipients?: readonly { readonly fpHex: string; readonly encPubHex: string }[],
): Promise<Response> {
  const environmentId = entry.payload.environmentId;
  const epoch = entry.op === "create_environment" ? 1 : entry.payload.newEpoch;
  const dek = vectorDek(environmentId, epoch);
  const deks = await compositeWraps(
    entry,
    environmentId,
    epoch,
    dek,
    recipients,
    serverRecipients ?? [],
  );
  const url =
    entry.op === "create_environment"
      ? `${BASE}/projects/${vectorProjectId}/environments`
      : `${BASE}/projects/${vectorProjectId}/environments/${environmentId}/rotate`;
  const { statement, envMeta, manifest } = await compositeManifestParts(
    entry,
    environmentId,
    epoch,
  );
  // Boundary checkpoint (H+2 — the mandatory bundled item of §12-4).
  // Membership tests create no data-plane variables, so values_digest is
  // always the empty set's enumeration
  const { entry: checkpoint } = await signEntryAt({
    seq: entry.seq + 1,
    prevHashHex: await computeChainEntryHash(entry),
    actorUserId: entry.actor.userId,
    operation: checkpointOperation({
      environmentId,
      epoch,
      manifestVersion: manifest.manifestVersion,
      manifestSigHashHex: await manifestSignedBytesHashOf(
        vectorProjectId,
        manifest,
        entry.actor.userId,
      ),
      valuesDigestHex: await valuesDigestOf([]),
    }),
  });
  const body =
    entry.op === "create_environment"
      ? { parentHeadHashHex: entry.prevHashHex, entry, statement, deks, manifest, checkpoint }
      : { parentHeadHashHex: entry.prevHashHex, entry, deks, manifest, checkpoint };
  const response = await SELF.fetch(url, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...(headers ?? bearer(tokenFor(entry.actor.userId))) },
    body: JSON.stringify(body),
  });
  if (response.status === 200) {
    replayManifests.set(environmentId, {
      manifest,
      issuerUserId: entry.actor.userId,
      envMeta,
    });
  }
  return response;
}

/** Update the current members / valid grants while tracking the replayed ops (deriving the composite's wrap set). */
function trackReplayState(
  entry: ReturnType<typeof toWireEntry>,
  members: string[],
  serverGrants: Map<string, TrackedServerGrant>,
): void {
  if (entry.op === "add_member") {
    members.push(entry.payload.targetUserId);
  } else if (entry.op === "remove_member") {
    const index = members.indexOf(entry.payload.targetUserId);
    if (index >= 0) {
      members.splice(index, 1);
    }
  } else if (entry.op === "grant_server") {
    serverGrants.set(entry.payload.serverKeyFingerprintHex, {
      encPubHex: entry.payload.serverEncPubHex,
      scope: entry.payload.scopeEnvironmentIds,
    });
  } else if (entry.op === "revoke_server") {
    serverGrants.delete(entry.payload.serverKeyFingerprintHex);
  }
}

/** The real head after a replay (it drifts from the vector's fixed seq because the composite inserts a boundary checkpoint). */
export interface ReplayHead {
  readonly seq: number;
  readonly hashHex: string;
}

export interface ReplayResult {
  readonly members: readonly string[];
  readonly head: ReplayHead;
}

/**
 * Replay the vector's seq 1..upTo against the server (init + append +
 * composite, with each actor's PAT). The current member set needed for a
 * composite's wrap set is derived while tracking the ops.
 *
 * Because the composite inserts a boundary checkpoint (H+2), the head
 * drifts from the vector's fixed seq / prev after the first composite.
 * Subsequent entries keep op / payload / actor and are re-signed at the
 * real head to follow it (byte pinning of the canonical chain is the job
 * of the crypto layer's 4-runtime tests; here we pin that "the same op
 * sequence is accepted by the API").
 */
/**
 * Mapping of proposal hashes (the entry_hash of a vector's propose entry
 * → the entry_hash of the same entry re-signed at the real head). Because
 * inserting a boundary checkpoint drifts seq / prev and changes propose
 * hashes too, the `proposal_hash_hex` referenced by approve / withdraw
 * (§6.2 — the proposal entry's entry_hash) is remapped to the real hash
 * at replay time. An unknown hash (a nonexistent proposal in a negative)
 * is not in the mapping and passes through unchanged (preserving the
 * semantics)
 */
const replayProposalHashes = new Map<string, string>();

/** Remap the reference target of approve / withdraw to the real hash at replay time (anything but propose passes through). */
export function remapProposalRef(entry: ChainEntry): ChainEntry {
  if (entry.op !== "approve" && entry.op !== "withdraw") {
    return entry;
  }
  const actual = replayProposalHashes.get(entry.payload.proposalHashHex);
  return actual === undefined ? entry : { ...entry, payload: { proposalHashHex: actual } };
}

/** Re-sign while keeping consistency between the vector and the real head (remap the reference → re-sign → record the propose hash). */
async function resignForReplay(
  vector: VectorEntry,
  head: ReplayHead,
): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const wire = remapProposalRef(toWireEntry(vector));
  const signed =
    head.seq === vector.seq - 1 && head.hashHex === vector.prev_hash_hex
      ? { entry: wire, hash: vector.entry_hash_hex }
      : await resignEntryAt(wire, head.seq + 1, head.hashHex);
  if (signed.entry.op === "propose") {
    replayProposalHashes.set(vector.entry_hash_hex, signed.hash);
  }
  return signed;
}

export async function replayVectorChain(upTo: number): Promise<ReplayResult> {
  const members: string[] = [];
  const serverGrants = new Map<string, TrackedServerGrant>();
  let head: ReplayHead = { seq: 0, hashHex: "" };
  // Manifest / proposal-hash tracking is redone per replay (beforeEach wipes the DO)
  replayManifests.clear();
  replayProposalHashes.clear();
  for (const vector of vectorEntries) {
    if (vector.seq > upTo) {
      break;
    }
    const wire = toWireEntry(vector);
    if (wire.op === "genesis") {
      const response = await initChain(wire);
      expect(response.status).toBe(200);
      members.push(wire.actor.userId);
      head = { seq: 1, hashHex: vector.entry_hash_hex };
      continue;
    }
    // When the head matches the vector, the entry stays the original bytes (re-signing is deterministically identical)
    const { entry, hash } = await resignForReplay(vector, head);
    if (entry.op === "create_environment" || entry.op === "rotate_epoch") {
      const environmentId = entry.payload.environmentId;
      const serverRecipients = [...serverGrants.entries()]
        .filter(([, grant]) => grant.scope.includes(environmentId))
        .map(([fpHex, grant]) => ({ fpHex, encPubHex: grant.encPubHex }));
      const response = await submitComposite(entry, members, undefined, serverRecipients);
      expect(response.status).toBe(200);
      const body = (await response.json()) as { headSeq: number; headHashHex: string };
      head = { seq: body.headSeq, hashHex: body.headHashHex };
      continue;
    }
    const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    expect(response.status).toBe(200);
    head = { seq: entry.seq, hashHex: hash };
    trackReplayState(entry, members, serverGrants);
  }
  return { members, head };
}

/**
 * Replay the precondition chain of an authz negative: when a chain is
 * specified, replay the canonical chain up to base_seq, then have the
 * derived chain's (extended_chains) entries accepted via the generic
 * append (the fact that they are accepted is itself a pinning of §6.2's
 * allowed side; the part where the real head drifted from the vector is
 * followed by re-signing — the same discipline as replayVectorChain).
 */
export async function replayNegativePrefix(negative: {
  readonly entry: { readonly seq: number };
  readonly chain?: string;
}): Promise<ReplayResult> {
  if (negative.chain === undefined) {
    return replayVectorChain(negative.entry.seq - 1);
  }
  const extended = vectorExtendedChains[negative.chain];
  if (extended === undefined) {
    throw new Error(`missing extended chain ${negative.chain}`);
  }
  const base = await replayVectorChain(extended.base_seq);
  let head = base.head;
  for (const vector of extended.entries) {
    const { entry, hash } = await resignForReplay(vector, head);
    const response = await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    expect(response.status).toBe(200);
    head = { seq: entry.seq, hashHex: hash };
  }
  return { members: base.members, head };
}

/**
 * Called once at the top of each test file: registers the fixture's
 * beforeEach.
 *
 * The storage-isolation unit of this @cloudflare/vitest-plugin config is
 * the worker (isolate: false — apps/server/vitest.config.ts), so DO
 * SQLite / D1 carry over not only across tests in a file but also from
 * other files processed by the same worker. Every test explicitly resets
 * to empty, re-seeds the vector users, and re-issues the PATs.
 */
export function registerMembershipScenario(): void {
  beforeEach(async () => {
    await resetProjectDo(vectorProjectId);
    await resetAuthDb();
    tokens = {};
    for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
      await seedUser(userId, githubId);
      tokens[userId] = await cliToken(githubId);
    }
    await seedOrgMember(VECTOR_ORG, "user-owner-0001", "member");
  });
}
