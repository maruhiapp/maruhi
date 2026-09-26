// Shared fixture for data-plane integration tests (run inside workerd).
//
// Base setup: a test-time-signed 3-entry chain (owner / member / reader) is
// replayed through the API and each user's real PAT is obtained. Chain
// extensions (rotate_epoch / add_member) are all done through the API too.

import type { ChainEntry, ChainOperation, EnvValuesDigestEntry } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { expect } from "vitest";

import {
  BASE,
  bearer,
  cliToken,
  JSON_HEADERS,
  resetAuthDb,
  seedOrgMember,
  seedUser,
} from "./auth.ts";
import type {
  WireDigestEntry,
  WireEnvironmentManifest,
  WireEnvironmentMetaStatement,
  WireWrappedDek,
} from "./data-crypto.ts";
import {
  addMemberOperation,
  buildChain,
  checkpointOperation,
  commitmentOf,
  createEnvironmentOperation,
  digestOf,
  genesisOperation,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  rotateEpochOperation,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  wrapDekForAll,
} from "./data-crypto.ts";
import { evictProjectDo, queryProjectDo, resetProjectDo } from "./project-do.ts";

export const OWNER = "user-owner-0001";
export const MEMBER = "user-member-0002";
// A member with the reader role. Its signing key borrows the third vector key
// (user-admin-0003) (VECTOR_KEY_ALIASES in data-crypto.ts — binding between a
// key and a user ID is done by the chain's add_member, so the key may be
// independent of the key set's nominal owner)
export const READER = "user-reader-0003";
export const STRANGER = "user-stranger-0009";
const DATA_ORG = "org-data-0001";

const GITHUB_IDS: Record<string, number> = {
  [OWNER]: 9001,
  [MEMBER]: 9002,
  [READER]: 9003,
  [STRANGER]: 9009,
};

/** Base chain: genesis(owner) → add_member(member) → add_member(reader). */
const baseChain = await buildChain([
  { actorUserId: OWNER, operation: genesisOperation(OWNER) },
  { actorUserId: OWNER, operation: addMemberOperation(MEMBER, "member") },
  { actorUserId: OWNER, operation: addMemberOperation(READER, "reader") },
]);

export const projectId = baseChain.projectId;

/** All members (the default recipients of a complete DEK wrap set). */
export const ALL_MEMBERS = [OWNER, MEMBER, READER] as const;

/**
 * Per-environment manifest tracking (material for the §4.3 prev chain, CAS,
 * and digest sets — advanced by the helpers on acceptance). entries is the
 * latest form of every variable, tombstones included.
 */
export interface EnvManifestState {
  manifest: WireEnvironmentManifest;
  issuerUserId: string;
  epoch: number;
  entries: readonly WireDigestEntry[];
}

export interface DataFixture {
  readonly tokens: Record<string, string>;
  /** The chain's current head (advanced by appendOperation). */
  head: { seq: number; hashHex: string };
  /**
   * Latest statement + author per environment (material for the prev chain
   * of renames / deletions — advanced by the helpers on acceptance).
   */
  readonly envStatements: Map<
    string,
    { statement: WireEnvironmentMetaStatement; authorUserId: string }
  >;
  /** Latest manifest per environment (material for the prev chain, CAS, and digest sets). */
  readonly manifests: Map<string, EnvManifestState>;
}

/** Reset DO / D1 + seed users and PATs + replay the base chain through the API. */
export async function setupDataProject(): Promise<DataFixture> {
  await resetProjectDo(projectId);
  await resetAuthDb();
  const tokens: Record<string, string> = {};
  for (const [userId, githubId] of Object.entries(GITHUB_IDS)) {
    await seedUser(userId, githubId);
    tokens[userId] = await cliToken(githubId);
  }
  await seedOrgMember(DATA_ORG, OWNER, "member");

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

/**
 * Seed a user outside the base chain into D1 and get a PAT (a listed member
 * in scope tests — a vector-key user such as user-devmember-0010). Re-seeding
 * the same user_id fails on a D1 primary key, so call this only once per
 * test.
 */
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

/** Append one entry to the chain via a test-time signature + API append, and advance the fixture head. */
export async function appendOperation(
  fixture: DataFixture,
  actorUserId: string,
  operation: ChainOperation,
): Promise<void> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
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

// ---------------------------------------------------------------------------
// Small wrappers for the data-plane API
// ---------------------------------------------------------------------------

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

/** Advance the head from a composite result (§12-4). */
function advanceHead(fixture: DataFixture, body: { headSeq: number; headHashHex: string }): void {
  fixture.head = { seq: body.headSeq, hashHex: body.headHashHex };
}

/**
 * Build the environment-creation composite bundled statement (metaVersion 1)
 * with a test-time signature. The declared head is the current head before
 * the append (= the bundled entry's prev — §12-4).
 */
export async function createEnvironmentStatement(input: {
  readonly authorUserId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly head: { readonly seq: number; readonly hashHex: string };
}): Promise<WireEnvironmentMetaStatement> {
  return signMetaStatementAs(input.authorUserId, projectId, {
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

/**
 * Build the next manifest (§4.3) with a test-time signature:
 * manifestVersion = latest recorded + 1 (unrecorded = 1), prev = the
 * signed_bytes hash of the latest recorded manifest, digest = the canonical
 * form of entries. The declared head is caller-specified (composite = the
 * current head before the append, meta op = the current head).
 */
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
  return signEnvManifestAs(input.issuerUserId, projectId, {
    suite: "maruhi/v1",
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion: (last?.manifest.manifestVersion ?? 0) + 1,
    variablesDigestHex: await digestOf(input.entries),
    envMetaVersion: input.envMeta.metaVersion,
    envMetaSigHashHex: input.envMeta.sigHashHex,
    prevManifestSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

/** The latest form of the recorded environment meta statement (the manifest's expected envMeta). */
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

/**
 * Sign the manifest bundled with a variable meta op (create / rename /
 * delete): the recorded digest set with the variable's entry applied. Also
 * returns the EnvManifestState needed to advance the record on success.
 */
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

/**
 * Remove the boundary checkpoint entry at the chain tail and the
 * environment's snapshot rows, reproducing the shape of an old-generation
 * chain with no checkpoint tuples (pre-boundary-checkpoint) — for manifest
 * migration-path tests. The real migration targets are environments created
 * before manifests / checkpoints were introduced, whose chains have no
 * tuples — the current API always inserts a checkpoint in the composite, so
 * the test removes it directly, outside the append-only invariant (same
 * handling as membership's canonical_bytes modification). After the
 * modification, evict the DO back to a full load and rewind the fixture head
 * to the new tail.
 */
export async function stripTrailingCheckpoint(
  fixture: DataFixture,
  environmentId: string,
): Promise<void> {
  const tail = await queryProjectDo(
    projectId,
    "SELECT seq, entry_json FROM chain_entries ORDER BY seq DESC LIMIT 1",
  );
  const tailSeq = Number(tail[0]?.["seq"]);
  const tailEntry = JSON.parse(String(tail[0]?.["entry_json"])) as { op?: string };
  if (tailEntry.op !== "checkpoint") {
    throw new Error("chain tail is not a boundary checkpoint entry");
  }
  await queryProjectDo(projectId, "DELETE FROM chain_entries WHERE seq = ?", tailSeq);
  await queryProjectDo(
    projectId,
    "DELETE FROM environment_checkpoints WHERE environment_id = ?",
    environmentId,
  );
  await queryProjectDo(
    projectId,
    "DELETE FROM checkpoint_snapshot_values WHERE environment_id = ?",
    environmentId,
  );
  await evictProjectDo(projectId);
  const newTail = await queryProjectDo(
    projectId,
    "SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq DESC LIMIT 1",
  );
  fixture.head = {
    seq: Number(newTail[0]?.["seq"]),
    hashHex: String(newTail[0]?.["entry_hash_hex"]),
  };
}

/**
 * Read the stored value-level latest form (each active variable's
 * latest_version + value-signature signed_bytes hash — the §6.2
 * values_digest enumeration) directly from the DO's SQLite. The same query
 * as the server's checkpointValueEntries (the reference for comparing a
 * rotate's boundary checkpoint).
 */
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
    variableId: String(row["variable_id"]),
    version: Number(row["version"]),
    valueSigHashHex: String(row["signed_bytes_hash_hex"]),
  }));
}

/**
 * Build a boundary checkpoint (H+2 — §12-4) with a test-time signature:
 * prev = the hash of the H+1 composite entry, tuple = the bundled manifest's
 * coordinates + signed_bytes hash (issuer = actor — §12-5 (1)) + the values
 * digest.
 */
async function signBoundaryCheckpointEntry(input: {
  readonly actorUserId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifest: WireEnvironmentManifest;
  readonly compositeSeq: number;
  readonly compositeHashHex: string;
  readonly values: readonly EnvValuesDigestEntry[];
  /** Notarization of the audit head (§16-2 — default is empty = no notarization). */
  readonly auditHeadHashHex?: string;
}): Promise<ChainEntry> {
  const { entry } = await signEntryAt({
    seq: input.compositeSeq + 1,
    prevHashHex: input.compositeHashHex,
    actorUserId: input.actorUserId,
    operation: checkpointOperation({
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

/**
 * Assemble and send a composite environment-creation request (§12-4):
 * create_environment entry (with commitment) + EnvironmentMetaStatement
 * (metaVersion 1; declared head = the current head before the append) +
 * EnvironmentManifest (manifestVersion 1, empty variable set, epoch 1) +
 * boundary checkpoint (H+2), all test-time-signed and POSTed together with
 * the wrap set and a parent-head CAS. On 200, advances the fixture's head.
 */
export async function createEnvironmentComposite(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly name: string;
    readonly deks: readonly WireWrappedDek[];
    readonly dekCommitmentHex: string;
    readonly actorUserId?: string;
    /** Parent-head override for CAS-failure tests. */
    readonly parentHeadHashHex?: string;
    /** Statement override for composite-consistency negatives. */
    readonly statement?: WireEnvironmentMetaStatement;
    /** Manifest override for composite-consistency negatives. */
    readonly manifest?: WireEnvironmentManifest;
    /** Boundary checkpoint override for composite-consistency negatives. */
    readonly checkpoint?: ChainEntry;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? OWNER;
  const { entry, hash: entryHash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actorUserId,
    operation: createEnvironmentOperation(input.environmentId, input.dekCommitmentHex),
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
  // manifestVersion 1 (empty variable set, epoch 1). envMeta is the bundled statement itself
  const manifest =
    input.manifest ??
    (await signEnvManifestAs(actorUserId, projectId, {
      suite: "maruhi/v1",
      environmentId: input.environmentId,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, actorUserId),
      prevManifestSigHashHex: "",
      chainHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    }));
  // Boundary checkpoint (H+2 — §12-4): creation = values_digest of the empty variable set
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

/**
 * Build the environment's next statement (rename / delete) with a test-time
 * signature: prev = the signed_bytes hash of the latest recorded statement,
 * metaVersion = latest + 1, declared head = the current head.
 */
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
  return signMetaStatementAs(input.authorUserId, projectId, {
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

/** Environment rename (PATCH with statement + manifest). On 204, advances the record. */
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
  // An environment rename's manifest copies the new envMetaSigHashHex (§12-4)
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

/** Environment deletion (DELETE with a status-deleted statement). On 204, advances the record. */
export async function deleteEnvironmentRequest(
  fixture: DataFixture,
  environmentId: string,
  actorUserId: string,
): Promise<Response> {
  const last = fixture.envStatements.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded statement for environment ${environmentId}`);
  }
  // A deleted statement's name keeps the immediately preceding active name (§4.2)
  const statement = await nextEnvironmentStatement(fixture, {
    environmentId,
    name: last.statement.name,
    status: "deleted",
    authorUserId: actorUserId,
  });
  const response = await requestJson(
    "DELETE",
    `/environments/${environmentId}`,
    tokenOf(fixture.tokens, actorUserId),
    { statement },
  );
  if (response.status === 204) {
    fixture.envStatements.set(environmentId, { statement, authorUserId: actorUserId });
  }
  return response;
}

/** Environment creation (bundles the epoch-1 complete wrap set via real crypto). Returns the DEK. */
export async function createEnvironmentOk(
  fixture: DataFixture,
  environmentId: string,
  name: string,
): Promise<Uint8Array> {
  const dek = makeDek();
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
    dekCommitmentHex: await commitmentOf(projectId, environmentId, 1, dek),
  });
  expect(response.status).toBe(200);
  return dek;
}

/**
 * Send an environment-creation request with an arbitrary wrap set. When
 * dekCommitmentHex is omitted it is computed from a throwaway DEK (for
 * negative tests — the contents cannot be verified by the server, and the
 * §5.2 check is the recipient's responsibility and does not affect
 * acceptance). **Positive cases that proceed to acceptance (200) must pass
 * the commitment of the wrapped DEK itself** (a positive case with a
 * throwaway commitment would freeze into the test suite a shape where the
 * distributed DEK does not match the chain commitment and peer CLIs reject
 * it).
 */
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
      dekCommitmentHex ?? (await commitmentOf(projectId, environmentId, 1, makeDek())),
  });
}

/**
 * Assemble and send a composite rotation request (§12-4): rotate_epoch
 * entry (with the new epoch's commitment) + wrap set. On 200, advances the
 * head.
 */
export async function rotateEnvironmentComposite(
  fixture: DataFixture,
  input: {
    readonly environmentId: string;
    readonly newEpoch: number;
    readonly deks: readonly WireWrappedDek[];
    readonly dekCommitmentHex: string;
    readonly actorUserId?: string;
    readonly parentHeadHashHex?: string;
    /** For URL-vs-entry-payload mismatch tests (default is the same environment as the entry). */
    readonly urlEnvironmentId?: string;
    /** Manifest override for composite-consistency negatives. */
    readonly manifest?: WireEnvironmentManifest;
    /** Boundary checkpoint override for composite-consistency negatives. */
    readonly checkpoint?: ChainEntry;
    /**
     * Override of the values_digest material (default = the actual
     * enumeration of the rows stored in the DO; used by concurrent-push
     * mismatch negatives etc.).
     */
    readonly checkpointValues?: readonly EnvValuesDigestEntry[];
    /** Audit-head notarization for the boundary checkpoint (§16-2 — default is empty = no notarization). */
    readonly checkpointAuditHeadHashHex?: string;
  },
): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const { entry, hash: entryHash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
    actorUserId,
    operation: rotateEpochOperation(input.environmentId, input.newEpoch, input.dekCommitmentHex),
  });
  // A manifest with the new epoch baked in (the meta set is unchanged — §4.3).
  // The declared head is the current head before the append (§12-4). An
  // unrecorded environment (e.g. the never-created environment in a negative
  // test) is given only the shape, with an empty set + dummy envMeta (it is
  // expected to fail at an earlier check in the acceptance stage)
  const last = fixture.manifests.get(input.environmentId);
  const manifest =
    input.manifest ??
    (await nextEnvironmentManifest(fixture, {
      // In a URL-vs-entry mismatch negative, the DO's entry-vs-URL check
      // must be reached before the worker's manifest-coordinate check
      // (manifestEnvironmentId), so the manifest is signed with the URL-side
      // coordinates
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
  // Boundary checkpoint (H+2 — §12-4): rotate = the enumeration of stored
  // value-level latest forms (not re-encrypted = the old epoch's current
  // values — the legitimate state of §12-7)
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
  const response = await requestJson(
    "POST",
    `/environments/${input.urlEnvironmentId ?? input.environmentId}/rotate`,
    tokenOf(fixture.tokens, actorUserId),
    {
      parentHeadHashHex: input.parentHeadHashHex ?? fixture.head.hashHex,
      entry,
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
    fixture.manifests.set(input.environmentId, {
      manifest,
      issuerUserId: actorUserId,
      epoch: input.newEpoch,
      entries: last?.entries ?? [],
    });
  }
  return response;
}

/** Rotation (with the new epoch's complete wrap set). Returns the new epoch's DEK. */
export async function rotateEnvironmentOk(
  fixture: DataFixture,
  actorUserId: string,
  environmentId: string,
  newEpoch: number,
): Promise<Uint8Array> {
  const dek = makeDek();
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
    dekCommitmentHex: await commitmentOf(projectId, environmentId, newEpoch, dek),
    actorUserId,
  });
  expect(response.status).toBe(200);
  return dek;
}
