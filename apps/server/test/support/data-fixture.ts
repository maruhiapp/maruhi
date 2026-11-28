import type { ChainEntry, ChainOperation, EnvValuesDigestEntry } from "@maruhi/crypto";
import { generateDek } from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import type {
  WireDigestEntry,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
  WireWrappedDek,
} from "@maruhi/test-kit";
import {
  addMemberOp,
  buildChain,
  checkpointOp,
  createEnvironmentOp,
  genesisOp,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  rotateEpochOp,
  signEntryAt,
  signManifest,
  signMetaStatement,
  testDekCommitmentHex,
  testEnvironmentId,
  testVariableId,
  valuesDigestOf,
  variablesDigestOf,
} from "@maruhi/test-kit";
import { SELF } from "cloudflare:test";
import { expect } from "vite-plus/test";

import { BASE, bearer, cliToken, JSON_HEADERS, reseedAuthDb, seedUser } from "./auth.ts";
import { identityOf, wrapDekForAll } from "./data-crypto.ts";
import { queryProjectDo, resetProjectDo } from "./project-do.ts";

type WireEnvironmentMetaStatement = Omit<
  WireVariableMetaStatement,
  "variableId" | "layoutVersion" | "varType" | "required" | "description" | "maxAgeDays" | "status"
> & { readonly status: "active" | "deleted" };

export const OWNER = testUserId("user-owner-0001");
export const MEMBER = testUserId("user-member-0002");
export const READER = testUserId("user-reader-0003");
export const STRANGER = testUserId("user-stranger-0009");
const DATA_ORG = "org-data-0001";

const GITHUB_IDS: Record<string, number> = {
  [OWNER]: 9001,
  [MEMBER]: 9002,
  [READER]: 9003,
  [STRANGER]: 9009,
};

const baseChain = await buildChain([
  { actor: identityOf(OWNER), operation: genesisOp(identityOf(OWNER)) },
  { actor: identityOf(OWNER), operation: addMemberOp(identityOf(MEMBER), "member") },
  { actor: identityOf(OWNER), operation: addMemberOp(identityOf(READER), "reader") },
]);

export const projectId = baseChain.projectId;

export const ALL_MEMBERS = [OWNER, MEMBER, READER] as const;

export interface EnvManifestState {
  manifest: WireEnvironmentManifest;
  issuerUserId: string;
  epoch: number;
  entries: readonly WireDigestEntry[];
}

export interface DataFixture {
  readonly tokens: Record<string, string>;
  head: { seq: number; hashHex: string };
  readonly envStatements: Map<
    string,
    { statement: WireEnvironmentMetaStatement; authorUserId: string }
  >;
  readonly manifests: Map<string, EnvManifestState>;
}

export async function setupDataProject(): Promise<DataFixture> {
  const [tokens] = await Promise.all([
    reseedAuthDb(GITHUB_IDS, { orgId: DATA_ORG, userId: OWNER }),
    resetProjectDo(projectId),
  ]);

  const [genesis, ...rest] = baseChain.entries;
  const init = await SELF.fetch(`${BASE}/projects`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(tokens, OWNER)) },
    body: JSON.stringify({ orgId: DATA_ORG, entry: genesis }),
  });
  expect(init.status).toBe(200);
  let prevHash = baseChain.hashes[0] ?? "";
  for (const [index, entry] of rest.entries()) {
    const response = await SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(tokenOf(tokens, entry.actor.userId)) },
      body: JSON.stringify({ parentHeadHashHex: prevHash, entry }),
    });
    expect(response.status).toBe(200);
    prevHash = baseChain.hashes[index + 1] ?? "";
  }
  return {
    tokens,
    head: { seq: baseChain.entries.length, hashHex: prevHash },
    envStatements: new Map(),
    manifests: new Map(),
  };
}

export async function seedMemberToken(
  fixture: DataFixture,
  userId: string,
  githubId: number,
): Promise<void> {
  await seedUser(userId, githubId);
  fixture.tokens[userId] = await cliToken(githubId);
}

export function tokenOf(tokens: Record<string, string>, userId: string): string {
  const token = tokens[userId];
  if (token === undefined) {
    throw new Error(`no token for ${userId}`);
  }
  return token;
}

export async function appendOperation(
  fixture: DataFixture,
  actorUserId: string,
  operation: ChainOperation,
): Promise<void> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(actorUserId),
    operation,
  });
  const response = await SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
  expect(response.status).toBe(200);
  fixture.head = { seq: entry.seq, hashHex: hash };
}

export const dataUrl = (path: string): string => `${BASE}/projects/${projectId}${path}`;

export function requestJson(
  method: string,
  path: string,
  token: string,
  body?: unknown,
): Promise<Response> {
  return SELF.fetch(dataUrl(path), {
    method,
    headers: { ...JSON_HEADERS, ...bearer(token) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function advanceHead(fixture: DataFixture, body: { headSeq: number; headHashHex: string }): void {
  fixture.head = { seq: body.headSeq, hashHex: body.headHashHex };
}

export async function createEnvironmentStatement(input: {
  readonly authorUserId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly head: { readonly seq: number; readonly hashHex: string };
}): Promise<WireEnvironmentMetaStatement> {
  return signMetaStatement(identityOf(input.authorUserId), projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

export async function nextEnvironmentManifest(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly entries: readonly WireDigestEntry[];
    readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
    readonly issuerUserId: string;
    readonly head: { readonly seq: number; readonly hashHex: string };
  },
): Promise<WireEnvironmentManifest> {
  const last = fixture.manifests.get(input.environmentId);
  const prevManifestSigHashHex =
    last === undefined
      ? ""
      : await manifestSignedBytesHashOf(projectId, last.manifest, last.issuerUserId);
  return signManifest(identityOf(input.issuerUserId), projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion: (last?.manifest.manifestVersion ?? 0) + 1,
    variablesDigestHex: await variablesDigestOf(input.entries),
    envMetaVersion: input.envMeta.metaVersion,
    envMetaSigHashHex: input.envMeta.sigHashHex,
    prevManifestSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

export async function envMetaOf(
  fixture: DataFixture,
  environmentId: string,
): Promise<{ metaVersion: number; sigHashHex: string }> {
  const last = fixture.envStatements.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${environmentId}`);
  }
  return {
    metaVersion: last.statement.metaVersion,
    sigHashHex: await metaSignedBytesHashOf(projectId, last.statement, last.authorUserId),
  };
}

export async function manifestForVariableOp(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly issuerUserId: string;
    readonly entry: WireDigestEntry;
  },
): Promise<{ manifest: WireEnvironmentManifest; state: EnvManifestState }> {
  const last = fixture.manifests.get(input.environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for environment ${input.environmentId}`);
  }
  const entries = [
    ...last.entries.filter((candidate) => candidate.variableId !== input.entry.variableId),
    input.entry,
  ];
  const manifest = await nextEnvironmentManifest(fixture, {
    environmentId: input.environmentId,
    epoch: last.epoch,
    entries,
    envMeta: await envMetaOf(fixture, input.environmentId),
    issuerUserId: input.issuerUserId,
    head: fixture.head,
  });
  return {
    manifest,
    state: { manifest, issuerUserId: input.issuerUserId, epoch: last.epoch, entries },
  };
}

export async function storedCheckpointValues(
  environmentId: string,
): Promise<readonly EnvValuesDigestEntry[]> {
  const rows = await queryProjectDo(
    projectId,
    `SELECT v.variable_id, vv.version, vv.signed_bytes_hash_hex
     FROM variables v
     JOIN variable_versions vv
       ON vv.environment_id = v.environment_id
      AND vv.variable_id = v.variable_id
      AND vv.version = v.latest_version
     WHERE v.environment_id = ? AND v.deleted_at IS NULL
     ORDER BY v.variable_id`,
    environmentId,
  );
  return rows.map((row) => ({
    variableId: testVariableId(String(row["variable_id"])),
    version: Number(row["version"]),
    valueSigHashHex: String(row["signed_bytes_hash_hex"]),
  }));
}

async function signBoundaryCheckpointEntry(input: {
  readonly actorUserId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifest: WireEnvironmentManifest;
  readonly compositeSeq: number;
  readonly compositeHashHex: string;
  readonly values: readonly EnvValuesDigestEntry[];
  readonly auditHeadHashHex?: string;
}): Promise<ChainEntry> {
  const { entry } = await signEntryAt({
    seq: input.compositeSeq + 1,
    prevHashHex: input.compositeHashHex,
    actor: identityOf(input.actorUserId),
    operation: checkpointOp({
      environmentId: input.environmentId,
      epoch: input.epoch,
      manifestVersion: input.manifest.manifestVersion,
      manifestSigHashHex: await manifestSignedBytesHashOf(
        projectId,
        input.manifest,
        input.actorUserId,
      ),
      valuesDigestHex: await valuesDigestOf(input.values),
      ...(input.auditHeadHashHex === undefined ? {} : { auditHeadHashHex: input.auditHeadHashHex }),
    }),
  });
  return entry;
}

export async function createEnvironmentComposite(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly name: string;
    readonly deks: readonly WireWrappedDek[];
    readonly dekCommitmentHex: string;
    readonly actorUserId?: string;
    readonly parentHeadHashHex?: string;
    readonly statement?: WireEnvironmentMetaStatement;
    readonly manifest?: WireEnvironmentManifest;
    readonly checkpoint?: ChainEntry;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? OWNER;
  const { entry, hash: entryHash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actor: identityOf(actorUserId),
    operation: createEnvironmentOp(input.environmentId, input.dekCommitmentHex),
  });
  const statement =
    input.statement ??
    (await createEnvironmentStatement({
      authorUserId: actorUserId,
      environmentId: input.environmentId,
      name: input.name,
      head: {
        seq: fixture.head.seq,
        hashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      },
    }));
  const manifest =
    input.manifest ??
    (await signManifest(identityOf(actorUserId), projectId, {
      suite: "maruhi/v1",
      environmentId: input.environmentId,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await variablesDigestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, actorUserId),
      prevManifestSigHashHex: "",
      chainHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    }));
  const checkpoint =
    input.checkpoint ??
    (await signBoundaryCheckpointEntry({
      actorUserId,
      environmentId: input.environmentId,
      epoch: 1,
      manifest,
      compositeSeq: fixture.head.seq + 1,
      compositeHashHex: entryHash,
      values: [],
    }));
  const response = await requestJson(
    "POST",
    "/environments",
    tokenOf(fixture.tokens, actorUserId),
    {
      parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      entry,
      statement,
      deks: input.deks,
      manifest,
      checkpoint,
    },
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
    fixture.envStatements.set(input.environmentId, { statement, authorUserId: actorUserId });
    fixture.manifests.set(input.environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: 1,
      entries: [],
    });
  }
  return response;
}

async function nextEnvironmentStatement(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly name: string;
    readonly status: "active" | "deleted";
    readonly authorUserId: string;
  },
): Promise<WireEnvironmentMetaStatement> {
  const last = fixture.envStatements.get(input.environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${input.environmentId}`);
  }
  const prevMetaSigHashHex = await metaSignedBytesHashOf(
    projectId,
    last.statement,
    last.authorUserId,
  );
  return signMetaStatement(identityOf(input.authorUserId), projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

export async function renameEnvironmentRequest(
  fixture: DataFixture,
  environmentId: string,
  name: string,
  actorUserId: string,
): Promise<Response> {
  const statement = await nextEnvironmentStatement(fixture, {
    environmentId,
    name,
    status: "active",
    authorUserId: actorUserId,
  });
  const last = fixture.manifests.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for environment ${environmentId}`);
  }
  const manifest = await nextEnvironmentManifest(fixture, {
    environmentId,
    epoch: last.epoch,
    entries: last.entries,
    envMeta: {
      metaVersion: statement.metaVersion,
      sigHashHex: await metaSignedBytesHashOf(projectId, statement, actorUserId),
    },
    issuerUserId: actorUserId,
    head: fixture.head,
  });
  const response = await requestJson(
    "PATCH",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    fixture.envStatements.set(environmentId, { statement, authorUserId: actorUserId });
    fixture.manifests.set(environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: last.epoch,
      entries: last.entries,
    });
  }
  return response;
}

export function unsignedDeleteEnvironmentBody(
  fixture: DataFixture,
  environmentId: string,
  actorUserId: string,
  keyFingerprintHex = "ab".repeat(16),
): { readonly parentHeadHashHex: string; readonly entry: Record<string, unknown> } {
  return {
    parentHeadHashHex: fixture.head.hashHex,
    entry: {
      suite: "maruhi/v1",
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      op: "delete_environment",
      actor: { userId: actorUserId, keyFingerprintHex },
      payload: { environmentId },
      timestampMs: 1754006400000,
      signatureHex: "00".repeat(64),
    },
  };
}

export async function deleteEnvironmentRequest(
  fixture: DataFixture,
  environmentId: string,
  actorUserId: string,
  options: {
    readonly parentHeadHashHex?: string;
    readonly entryEnvironmentId?: string;
    readonly entryPrevHashHex?: string;
  } = {},
): Promise<Response> {
  const parentHeadHashHex = options.parentHeadHashHex ?? fixture.head.hashHex;
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: options.entryPrevHashHex ?? parentHeadHashHex,
    actor: identityOf(actorUserId),
    operation: {
      op: "delete_environment",
      payload: { environmentId: testEnvironmentId(options.entryEnvironmentId ?? environmentId) },
    },
  });
  const response = await requestJson(
    "DELETE",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { parentHeadHashHex, entry },
  );
  if (response.status === 204) {
    fixture.head = { seq: entry.seq, hashHex: hash };
  }
  return response;
}

export async function createEnvironmentOk(
  fixture: DataFixture,
  environmentId: string,
  name: string,
): Promise<Uint8Array> {
  const dek = generateDek();
  const deks = await wrapDekForAll({
    projectId,
    environmentId,
    epoch: 1,
    dek,
    recipientUserIds: ALL_MEMBERS,
    signerUserId: OWNER,
  });
  const response = await createEnvironmentComposite(fixture, {
    environmentId,
    name,
    deks,
    dekCommitmentHex: await testDekCommitmentHex(projectId, environmentId, 1, dek),
  });
  expect(response.status).toBe(200);
  return dek;
}

export async function createEnvironmentWith(
  fixture: DataFixture,
  environmentId: string,
  name: string,
  deks: readonly WireWrappedDek[],
  dekCommitmentHex?: string,
): Promise<Response> {
  return createEnvironmentComposite(fixture, {
    environmentId,
    name,
    deks,
    dekCommitmentHex:
      dekCommitmentHex ?? (await testDekCommitmentHex(projectId, environmentId, 1, generateDek())),
  });
}

interface RotateCompositeInput {
  readonly environmentId: string;
  readonly newEpoch: number;
  readonly deks: readonly WireWrappedDek[];
  readonly dekCommitmentHex: string;
  readonly actorUserId?: string;
  readonly parentHeadHashHex?: string;
  readonly urlEnvironmentId?: string;
  readonly manifest?: WireEnvironmentManifest;
  readonly checkpoint?: ChainEntry;
  readonly checkpointValues?: readonly EnvValuesDigestEntry[];
  readonly checkpointAuditHeadHashHex?: string;
}

export async function rotateCompositeBody(fixture: DataFixture, input: RotateCompositeInput) {
  const actorUserId = input.actorUserId ?? MEMBER;
  const { entry, hash: entryHash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actor: identityOf(actorUserId),
    operation: rotateEpochOp(input.environmentId, input.newEpoch, input.dekCommitmentHex),
  });
  const last = fixture.manifests.get(input.environmentId);
  const manifest =
    input.manifest ??
    (await nextEnvironmentManifest(fixture, {
      environmentId: input.urlEnvironmentId ?? input.environmentId,
      epoch: input.newEpoch,
      entries: last?.entries ?? [],
      envMeta: fixture.envStatements.has(input.environmentId)
        ? await envMetaOf(fixture, input.environmentId)
        : { metaVersion: 1, sigHashHex: "ab".repeat(32) },
      issuerUserId: actorUserId,
      head: {
        seq: fixture.head.seq,
        hashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      },
    }));
  const checkpoint =
    input.checkpoint ??
    (await signBoundaryCheckpointEntry({
      actorUserId,
      environmentId: input.environmentId,
      epoch: input.newEpoch,
      manifest,
      compositeSeq: fixture.head.seq + 1,
      compositeHashHex: entryHash,
      values: input.checkpointValues ?? (await storedCheckpointValues(input.environmentId)),
      ...(input.checkpointAuditHeadHashHex === undefined
        ? {}
        : { auditHeadHashHex: input.checkpointAuditHeadHashHex }),
    }));
  return {
    parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    entry,
    deks: input.deks,
    manifest,
    checkpoint,
  };
}

export async function rotateEnvironmentComposite(
  fixture: DataFixture,
  input: RotateCompositeInput,
): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const last = fixture.manifests.get(input.environmentId);
  const body = await rotateCompositeBody(fixture, input);
  const response = await requestJson(
    "POST",
    `/environments/${input.urlEnvironmentId ?? input.environmentId}/rotate`,
    tokenOf(fixture.tokens, actorUserId),
    body,
  );
  if (response.status === 200) {
    advanceHead(
      fixture,
      (await response.clone().json()) as { headSeq: number; headHashHex: string },
    );
    fixture.manifests.set(input.environmentId, {
      manifest: body.manifest,
      issuerUserId: actorUserId,
      epoch: input.newEpoch,
      entries: last?.entries ?? [],
    });
  }
  return response;
}

export async function rotateEnvironmentOk(
  fixture: DataFixture,
  actorUserId: string,
  environmentId: string,
  newEpoch: number,
): Promise<Uint8Array> {
  const dek = generateDek();
  const deks = await wrapDekForAll({
    projectId,
    environmentId,
    epoch: newEpoch,
    dek,
    recipientUserIds: ALL_MEMBERS,
    signerUserId: actorUserId,
  });
  const response = await rotateEnvironmentComposite(fixture, {
    environmentId,
    newEpoch,
    deks,
    dekCommitmentHex: await testDekCommitmentHex(projectId, environmentId, newEpoch, dek),
    actorUserId,
  });
  expect(response.status).toBe(200);
  return dek;
}
