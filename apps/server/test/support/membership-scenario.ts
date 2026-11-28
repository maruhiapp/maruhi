import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, generateDek } from "@maruhi/crypto";
import { vectorEnvironmentDeks } from "@maruhi/crypto/test-support";
import type { WireEnvironmentManifest } from "@maruhi/test-kit";
import {
  checkpointOp,
  hexBytes,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  resignEntryAt,
  signEntryAt,
  signManifest,
  signMetaStatement,
  valuesDigestOf,
  variablesDigestOf,
  wrapDekTo,
} from "@maruhi/test-kit";
import { SELF } from "cloudflare:test";
import { beforeEach, expect } from "vite-plus/test";

import { BASE, bearer, JSON_HEADERS, reseedAuthDb } from "./auth.ts";
import {
  toWireEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
  type VectorEntry,
} from "./chain-vectors.ts";
import { identityOf, signerOf, wrapDekForAll } from "./data-crypto.ts";
import { resetProjectDo } from "./project-do.ts";

export const VECTOR_ORG = "org-vector-0001";

const GITHUB_IDS: Record<string, number> = {
  "user-owner-0001": 9001,
  "user-member-0002": 9002,
  "user-admin-0003": 9003,
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

function vectorDek(environmentId: string, epoch: number): Uint8Array {
  const dekHex = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_hex;
  return dekHex === undefined ? generateDek() : hexBytes(dekHex);
}

interface TrackedServerGrant {
  readonly encPubHex: string;
  readonly scope: readonly string[];
}

const replayManifests = new Map<
  string,
  {
    manifest: WireEnvironmentManifest;
    issuerUserId: string;
    envMeta: { metaVersion: number; sigHashHex: string };
  }
>();

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
      await wrapDekTo({
        projectId: vectorProjectId,
        environmentId,
        epoch,
        dek,
        recipient: { userId: server.fpHex, encPubHex: server.encPubHex },
        recipientClass: "server",
        signer: identityOf(entry.actor.userId),
      }),
    );
  }
  return deks;
}

async function compositeManifestParts(
  entry: ChainEntry & { readonly op: "create_environment" | "rotate_epoch" },
  environmentId: string,
  epoch: number,
) {
  const tracked = replayManifests.get(environmentId);
  const statement =
    entry.op === "create_environment"
      ? await signMetaStatement(identityOf(entry.actor.userId), vectorProjectId, {
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
  const manifest = await signManifest(identityOf(entry.actor.userId), vectorProjectId, {
    suite: "maruhi/v1",
    environmentId,
    epoch,
    ...chainlike,
    variablesDigestHex: await variablesDigestOf([]),
    envMetaVersion: envMeta.metaVersion,
    envMetaSigHashHex: envMeta.sigHashHex,
    chainHeadHashHex: entry.prevHashHex,
    chainHeadSeq: entry.seq - 1,
  });
  return { statement, envMeta, manifest };
}

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
  const { entry: checkpoint } = await signEntryAt({
    seq: entry.seq + 1,
    prevHashHex: await computeChainEntryHash(entry),
    actor: identityOf(entry.actor.userId),
    operation: checkpointOp({
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

export function submitDeletion(
  entry: ChainEntry & { readonly op: "delete_environment" },
  urlEnvironmentId?: string,
): Promise<Response> {
  const environmentId = urlEnvironmentId ?? entry.payload.environmentId;
  return SELF.fetch(`${BASE}/projects/${vectorProjectId}/environments/${environmentId}`, {
    method: "DELETE",
    headers: { ...JSON_HEADERS, ...bearer(tokenFor(entry.actor.userId)) },
    body: JSON.stringify({ parentHeadHashHex: entry.prevHashHex, entry }),
  });
}

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

export interface ReplayHead {
  readonly seq: number;
  readonly hashHex: string;
}

export interface ReplayResult {
  readonly members: readonly string[];
  readonly head: ReplayHead;
}

const replayProposalHashes = new Map<string, string>();

export function remapProposalRef(entry: ChainEntry): ChainEntry {
  if (entry.op !== "approve" && entry.op !== "withdraw") {
    return entry;
  }
  const actual = replayProposalHashes.get(entry.payload.proposalHashHex);
  return actual === undefined ? entry : { ...entry, payload: { proposalHashHex: actual } };
}

async function resignForReplay(
  vector: VectorEntry,
  head: ReplayHead,
): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const wire = remapProposalRef(toWireEntry(vector));
  const signed =
    head.seq === vector.seq - 1 && head.hashHex === vector.prev_hash_hex
      ? { entry: wire, hash: vector.entry_hash_hex }
      : await resignEntryAt(wire, head.seq + 1, head.hashHex, signerOf(wire));
  if (signed.entry.op === "propose") {
    replayProposalHashes.set(vector.entry_hash_hex, signed.hash);
  }
  return signed;
}

export async function replayVectorChain(upTo: number): Promise<ReplayResult> {
  const members: string[] = [];
  const serverGrants = new Map<string, TrackedServerGrant>();
  let head: ReplayHead = { seq: 0, hashHex: "" };
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
    const response =
      entry.op === "delete_environment"
        ? await submitDeletion(entry)
        : await appendEntry(vectorProjectId, entry.prevHashHex, entry);
    expect(response.status).toBe(entry.op === "delete_environment" ? 204 : 200);
    head = { seq: entry.seq, hashHex: hash };
  }
  return { members: base.members, head };
}

export function registerMembershipScenario(): void {
  beforeEach(async () => {
    const [issued] = await Promise.all([
      reseedAuthDb(GITHUB_IDS, { orgId: VECTOR_ORG, userId: "user-owner-0001" }),
      resetProjectDo(vectorProjectId),
    ]);
    tokens = issued;
  });
}
