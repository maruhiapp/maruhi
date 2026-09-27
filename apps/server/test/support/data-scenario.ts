// Shared scenario for data-plane integration tests.
//
// fixture / varStatements are exported as ESM live bindings; each test file
// registers its beforeEach (reset + re-seed) via registerDataScenario() and
// then writes its describe blocks.

import { beforeEach, expect } from "vitest";

import type {
  WireEncryptedPayload,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
} from "./data-crypto.ts";
import {
  createVariableStatement,
  encryptValue,
  metaSignedBytesHashOf,
  signMetaStatementAs,
  signValueAs,
} from "./data-crypto.ts";
import { makeDek, resetDeviceKeys, wrapDekForAll } from "./data-crypto.ts";
import type { DataFixture, EnvManifestState } from "./data-fixture.ts";
import {
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  setupDataProject,
  tokenOf,
} from "./data-fixture.ts";
import { queryProjectDo } from "./project-do.ts";

export const ENV = "env-app-0001";
export const VAR = "var-database-url";

export let fixture: DataFixture;

/** Latest statement + author per variable (material for the prev chain of renames / deletions). */
export let varStatements: Map<
  string,
  { statement: WireVariableMetaStatement; authorUserId: string }
>;

/** Called once at the top of each test file: registers the fixture's beforeEach. */
export function registerDataScenario(): void {
  beforeEach(async () => {
    // Device-key substitution (useDeviceKey) does not carry over across tests
    resetDeviceKeys();
    fixture = await setupDataProject();
    varStatements = new Map();
  });
}

export const token = (userId: string): string => tokenOf(fixture.tokens, userId);

/**
 * Sign and return the manifest bundled with a variable meta op (create /
 * rename / delete) (§12-5), computed from the verified statement's hash (on
 * success, `record` advances the record). issuer must match the actor
 * performing the op (§12-5 (1)).
 */
export async function manifestForStatement(
  statement: WireVariableMetaStatement,
  authorUserId: string,
  environmentId = ENV,
): Promise<{ manifest: WireEnvironmentManifest; record: () => void }> {
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId,
    issuerUserId: authorUserId,
    entry: {
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, authorUserId),
    },
  });
  return { manifest, record: () => recordManifestState(environmentId, state) };
}

function recordManifestState(environmentId: string, state: EnvManifestState): void {
  fixture.manifests.set(environmentId, state);
}

/** Sign and record the statement bundled with variable creation (metaVersion 1). */
export async function variableStatementFor(
  authorUserId: string,
  variableId: string,
  name: string,
  environmentId = ENV,
): Promise<WireVariableMetaStatement> {
  return createVariableStatement({
    authorUserId,
    projectId,
    environmentId,
    variableId,
    name,
    head: fixture.head,
  });
}

/** Layout-v2 schema fields (wire shape — required is a boolean). */
export interface WireSchemaFields {
  readonly varType: "" | "string" | "number" | "boolean" | "url";
  readonly required: boolean;
  readonly description: string;
}

/** Carrier fields for a v2 statement (layoutVersion 2 + the schema fields). */
export function v2Fields(schema: Partial<WireSchemaFields> = {}): {
  readonly layoutVersion: number;
  readonly varType: WireSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
} {
  return {
    layoutVersion: 2,
    varType: schema.varType ?? "string",
    required: schema.required ?? true,
    description: schema.description ?? "",
  };
}

/** Sign a variable's next statement (rename / schema re-issuance / deletion / activation) from the latest recorded one. */
export async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly authorUserId: string;
  readonly environmentId?: string;
  /** Layout-v2 carrier fields (v2Fields(...) — omitted = v1 statement). */
  readonly v2?: ReturnType<typeof v2Fields>;
}): Promise<WireVariableMetaStatement> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${input.variableId}`);
  }
  const prevMetaSigHashHex = await metaSignedBytesHashOf(
    projectId,
    last.statement,
    last.authorUserId,
  );
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex,
    ...input.v2,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

/** Variable rename (PATCH with statement). On 204, advances the record. */
export async function renameVariableRequest(
  variableId: string,
  name: string,
  actorUserId: string,
): Promise<Response> {
  const statement = await nextVariableStatement({
    variableId,
    name,
    status: "active",
    authorUserId: actorUserId,
  });
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson(
    "PATCH",
    `/environments/${ENV}/variables/${variableId}`,
    token(actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    varStatements.set(variableId, { statement, authorUserId: actorUserId });
    record();
  }
  return response;
}

/** Variable deletion (DELETE with a status-deleted statement). On 204, advances the record. */
export async function deleteVariableRequest(
  variableId: string,
  actorUserId: string,
): Promise<Response> {
  const last = varStatements.get(variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${variableId}`);
  }
  const statement = await nextVariableStatement({
    variableId,
    // A deleted statement's name keeps the immediately preceding active name (§4.2)
    name: last.statement.name,
    status: "deleted",
    authorUserId: actorUserId,
  });
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson(
    "DELETE",
    `/environments/${ENV}/variables/${variableId}`,
    token(actorUserId),
    { statement, manifest },
  );
  if (response.status === 204) {
    varStatements.set(variableId, { statement, authorUserId: actorUserId });
    record();
  }
  return response;
}

/**
 * Unsigned dummy statement for tests that only need to pass Schema (400 /
 * 403 / 404 are decided before signature verification) — a formally valid
 * zero signature.
 */
export function unsignedVariableStatement(
  variableId: string,
  name: string,
): WireVariableMetaStatement {
  return {
    suite: "maruhi/v1",
    environmentId: ENV,
    variableId,
    name,
    status: "active",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

/**
 * Unsigned dummy manifest for tests that only need to pass Schema (400 /
 * 403 / 404 are decided before signature verification) — a formally valid
 * zero signature.
 */
export function unsignedManifest(environmentId = ENV): WireEnvironmentManifest {
  return {
    suite: "maruhi/v1",
    environmentId,
    epoch: 1,
    manifestVersion: 1,
    variablesDigestHex: "ab".repeat(32),
    envMetaVersion: 1,
    envMetaSigHashHex: "ab".repeat(32),
    prevManifestSigHashHex: "",
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

/**
 * Fake ciphertext for acceptance-policy tests (the server cannot decrypt
 * the contents). The value signature (§12-5) is verified by the server, so
 * even a fake is signed correctly with the caller's real key (writerUserId
 * must match the subject of the PAT used for the request). The declared
 * head is the current head (fixture.head).
 */
export function fakePayload(
  writerUserId: string,
  aad: WireEncryptedPayload["aad"],
  options?: {
    readonly ciphertextBytes?: number;
    readonly prevValueSigHashHex?: string;
  },
): Promise<WireEncryptedPayload> {
  return signValueAs(
    writerUserId,
    {
      suite: "maruhi/v1",
      aad,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(options?.ciphertextBytes ?? 48),
      // The default prev for version > 1 is a dummy 64-hex (for tests
      // rejected at an earlier stage than the prev check — CAS etc. Tests
      // that reach the prev check pass a real hash)
      prevValueSigHashHex:
        options?.prevValueSigHashHex ?? (aad.version === 1 ? "" : "cd".repeat(32)),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    },
    fixture.head,
  );
}

/**
 * Unsigned fake for tests that are certain never to reach signature
 * verification (Schema 400 / AAD 422 / non-member 404). STRANGER has no
 * vector key and cannot sign for real — carry a formally valid zero
 * signature.
 */
export function unsignedPayload(aad: WireEncryptedPayload["aad"]): WireEncryptedPayload {
  return {
    suite: "maruhi/v1",
    aad,
    nonceHex: "00".repeat(12),
    ciphertextHex: "ab".repeat(48),
    prevValueSigHashHex: aad.version === 1 ? "" : "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

export const aadFor = (
  epoch: number,
  version: number,
  overrides?: Partial<WireEncryptedPayload["aad"]>,
) => ({
  projectId,
  environmentId: ENV,
  epoch,
  variableId: VAR,
  version,
  ...overrides,
});

/** Variable creation (real encryption + MEMBER's value signature + bundled metaVersion-1 statement). */
export async function createVariableOk(
  dek: Uint8Array,
  variableId: string,
  name: string,
  plaintext: string,
): Promise<WireEncryptedPayload> {
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId, version: 1 },
    plaintext,
    { writerUserId: MEMBER, head: fixture.head },
  );
  const statement = await variableStatementFor(MEMBER, variableId, name);
  const { manifest, record } = await manifestForStatement(statement, MEMBER);
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    statement,
    value,
    manifest,
  });
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toEqual({ variableId, version: 1, epoch: 1 });
  varStatements.set(variableId, { statement, authorUserId: MEMBER });
  record();
  return value;
}

/**
 * Sign and return a layout-v2 creation statement (metaVersion 1 — active =
 * with bundled value / declared = valueless declaration).
 */
export async function variableStatementV2For(input: {
  readonly authorUserId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "declared";
  readonly schema?: Partial<WireSchemaFields>;
  readonly environmentId?: string;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...v2Fields(input.schema),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

/** declared creation (the valueless declaration composite — §12-5). On a 204/200-equivalent success, advances the record. */
export async function declareVariableRequest(input: {
  readonly variableId: string;
  readonly name: string;
  readonly actorUserId: string;
  readonly schema?: Partial<WireSchemaFields>;
}): Promise<Response> {
  const statement = await variableStatementV2For({
    authorUserId: input.actorUserId,
    variableId: input.variableId,
    name: input.name,
    status: "declared",
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  const { manifest, record } = await manifestForStatement(statement, input.actorUserId);
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables`,
    token(input.actorUserId),
    {
      statement,
      manifest,
    },
  );
  if (response.status === 200) {
    varStatements.set(input.variableId, { statement, authorUserId: input.actorUserId });
    record();
  }
  return response;
}

/** The success shape of declared creation (§12-5 — stored version 0). */
export async function declareVariableOk(input: {
  readonly variableId: string;
  readonly name: string;
  readonly actorUserId?: string;
  readonly schema?: Partial<WireSchemaFields>;
}): Promise<void> {
  const response = await declareVariableRequest({
    variableId: input.variableId,
    name: input.name,
    actorUserId: input.actorUserId ?? MEMBER,
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  expect(response.status).toBe(200);
  await expect(response.clone().json()).resolves.toMatchObject({
    variableId: input.variableId,
    version: 0,
  });
}

/**
 * The activation composite (§12-5 — declared → active: value version 1 +
 * status-active v2 statement + manifest). On 200, advances the record.
 */
export async function activateVariableRequest(input: {
  readonly variableId: string;
  readonly actorUserId: string;
  readonly dek: Uint8Array;
  readonly plaintext: string;
  readonly epoch?: number;
  readonly name?: string;
  readonly schema?: Partial<WireSchemaFields>;
  /**
   * The value's version (default 1 = a legitimate activation). Anything
   * other than 1 is for negatives — reproducing the bypass shape "send
   * latest + 1 to an active variable" (if the helper pinned 1, the property
   * "cannot target an active variable" could not be verified).
   */
  readonly version?: number;
  readonly prevValueSigHashHex?: string;
}): Promise<Response> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) {
    throw new Error(`no recorded statement for variable ${input.variableId}`);
  }
  const statement = await nextVariableStatement({
    variableId: input.variableId,
    name: input.name ?? last.statement.name,
    status: "active",
    authorUserId: input.actorUserId,
    v2: v2Fields(input.schema),
  });
  const value = await encryptValue(
    input.dek,
    {
      projectId,
      environmentId: ENV,
      epoch: input.epoch ?? 1,
      variableId: input.variableId,
      version: input.version ?? 1,
    },
    input.plaintext,
    {
      writerUserId: input.actorUserId,
      head: fixture.head,
      ...(input.prevValueSigHashHex === undefined
        ? {}
        : { prevValueSigHashHex: input.prevValueSigHashHex }),
    },
  );
  const { manifest, record } = await manifestForStatement(statement, input.actorUserId);
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${input.variableId}/activate`,
    token(input.actorUserId),
    { value, statement, manifest },
  );
  if (response.status === 200) {
    varStatements.set(input.variableId, { statement, authorUserId: input.actorUserId });
    record();
  }
  return response;
}

/** Set schemaPolicy (PUT — §12-11. The default actor is OWNER = chain role owner). */
export async function setSchemaPolicyOk(
  policy: "disabled" | "enabled" | "locked",
  actorUserId = OWNER,
): Promise<void> {
  const response = await requestJson("PUT", "/schema-policy", token(actorUserId), {
    schemaPolicy: policy,
  });
  expect(response.status).toBe(204);
}

/** A complete wrap set for a dummy DEK (recipients, epoch, and signer selectable). */
export const wrapsFor = (
  environmentId: string,
  recipients: readonly string[],
  epoch = 1,
  signerUserId = OWNER,
) =>
  wrapDekForAll({
    projectId,
    environmentId,
    epoch,
    dek: makeDek(),
    recipientUserIds: recipients,
    signerUserId,
  });

/** The entry hash of a stored chain row (for building the declared head's exact pair). */
export async function hashOf(seq: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT entry_hash_hex FROM chain_entries WHERE seq = ?",
    seq,
  );
  return String(rows[0]?.["entry_hash_hex"]);
}
