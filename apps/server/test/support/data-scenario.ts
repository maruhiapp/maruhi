import type { EncryptedPayload } from "@maruhi/api-schema";
import { generateDek } from "@maruhi/crypto";
import type {
  WireEncryptedPayload,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
} from "@maruhi/test-kit";
import {
  createVariableStatement,
  encryptValue,
  metaSignedBytesHashOf,
  signMetaStatement,
  signValueAt,
  testEnvironmentId,
  testProjectId,
  testVariableId,
} from "@maruhi/test-kit";
import { beforeEach, expect } from "vite-plus/test";

import { identityOf, resetDeviceKeys, wrapDekForAll } from "./data-crypto.ts";
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
export const VAR = testVariableId("var-database-url");

export let fixture: DataFixture;

export let varStatements: Map<
  string,
  { statement: WireVariableMetaStatement; authorUserId: string }
>;

export function registerDataScenario(): void {
  beforeEach(async () => {
    resetDeviceKeys();
    fixture = await setupDataProject();
    varStatements = new Map();
  });
}

export const token = (userId: string): string => tokenOf(fixture.tokens, userId);

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

export async function variableStatementFor(
  authorUserId: string,
  variableId: string,
  name: string,
  environmentId = ENV,
): Promise<WireVariableMetaStatement> {
  return createVariableStatement({
    author: identityOf(authorUserId),
    projectId,
    environmentId,
    variableId,
    name,
    head: fixture.head,
  });
}

export interface WireSchemaFields {
  readonly varType: "" | "string" | "number" | "boolean" | "url";
  readonly required: boolean;
  readonly description: string;
  readonly maxAgeDays: number | null;
}

export function v3Fields(schema: Partial<WireSchemaFields> = {}): {
  readonly layoutVersion: number;
  readonly varType: WireSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
  readonly maxAgeDays: number | null;
} {
  return {
    layoutVersion: 3,
    varType: schema.varType ?? "string",
    required: schema.required ?? true,
    description: schema.description ?? "",
    maxAgeDays: schema.maxAgeDays ?? null,
  };
}

export async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly authorUserId: string;
  readonly environmentId?: string;
  readonly v3?: ReturnType<typeof v3Fields>;
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
  return signMetaStatement(identityOf(input.authorUserId), projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex,
    ...input.v3,
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

async function sendVariableStatement(
  method: "PATCH" | "DELETE",
  variableId: string,
  actorUserId: string,
  statement: WireVariableMetaStatement,
): Promise<Response> {
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson(
    method,
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
  return sendVariableStatement("PATCH", variableId, actorUserId, statement);
}

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
    name: last.statement.name,
    status: "deleted",
    authorUserId: actorUserId,
  });
  return sendVariableStatement("DELETE", variableId, actorUserId, statement);
}

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

export async function fakePayload(
  writerUserId: string,
  aad: WireEncryptedPayload["aad"],
  options?: {
    readonly ciphertextBytes?: number;
    readonly prevValueSigHashHex?: string;
  },
): Promise<EncryptedPayload> {
  return (await signValueAt(
    identityOf(writerUserId),
    {
      suite: "maruhi/v1",
      aad: brandedAad(aad),
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(options?.ciphertextBytes ?? 48),
      prevValueSigHashHex:
        options?.prevValueSigHashHex ?? (aad.version === 1 ? "" : "cd".repeat(32)),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    },
    fixture.head,
  )) as EncryptedPayload;
}

export function unsignedPayload(aad: WireEncryptedPayload["aad"]): EncryptedPayload {
  return {
    suite: "maruhi/v1",
    aad: brandedAad(aad),
    nonceHex: "00".repeat(12),
    ciphertextHex: "ab".repeat(48),
    prevValueSigHashHex: aad.version === 1 ? "" : "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

const brandedAad = (aad: WireEncryptedPayload["aad"]): EncryptedPayload["aad"] => ({
  projectId: testProjectId(aad.projectId),
  environmentId: testEnvironmentId(aad.environmentId),
  epoch: aad.epoch,
  variableId: testVariableId(aad.variableId),
  version: aad.version,
});

export const aadFor = (
  epoch: number,
  version: number,
  overrides?: Partial<WireEncryptedPayload["aad"]>,
) => ({
  projectId: testProjectId(projectId),
  environmentId: testEnvironmentId(ENV),
  epoch,
  variableId: testVariableId(VAR),
  version,
  ...overrides,
});

export async function createVariableOk(
  dek: Uint8Array,
  variableId: string,
  name: string,
  plaintext: string,
): Promise<WireEncryptedPayload> {
  const value = await encryptValue({
    dek,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(ENV),
    epoch: 1,
    variableId: testVariableId(variableId),
    version: 1,
    plaintext,
    writer: identityOf(MEMBER),
    head: fixture.head,
  });
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

export async function variableStatementV3For(input: {
  readonly authorUserId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "declared";
  readonly schema?: Partial<WireSchemaFields>;
  readonly environmentId?: string;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatement(identityOf(input.authorUserId), projectId, {
    suite: "maruhi/v1" as const,
    environmentId: input.environmentId ?? ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    ...v3Fields(input.schema),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
}

export async function declareVariableRequest(input: {
  readonly variableId: string;
  readonly name: string;
  readonly actorUserId: string;
  readonly schema?: Partial<WireSchemaFields>;
}): Promise<Response> {
  const statement = await variableStatementV3For({
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

export async function activateVariableRequest(input: {
  readonly variableId: string;
  readonly actorUserId: string;
  readonly dek: Uint8Array;
  readonly plaintext: string;
  readonly epoch?: number;
  readonly name?: string;
  readonly schema?: Partial<WireSchemaFields>;
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
    v3: v3Fields(input.schema),
  });
  const value = await encryptValue({
    dek: input.dek,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(ENV),
    epoch: input.epoch ?? 1,
    variableId: testVariableId(input.variableId),
    version: input.version ?? 1,
    plaintext: input.plaintext,
    writer: identityOf(input.actorUserId),
    head: fixture.head,
    ...(input.prevValueSigHashHex === undefined
      ? {}
      : { prevValueSigHashHex: input.prevValueSigHashHex }),
  });
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

export async function setSchemaPolicyOk(
  policy: "enabled" | "locked",
  actorUserId = OWNER,
): Promise<void> {
  const response = await requestJson("PUT", "/schema-policy", token(actorUserId), {
    schemaPolicy: policy,
  });
  expect(response.status).toBe(204);
}

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
    dek: generateDek(),
    recipientUserIds: recipients,
    signerUserId,
  });

export async function hashOf(seq: number): Promise<string> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT entry_hash_hex FROM chain_entries WHERE seq = ?",
    seq,
  );
  return String(rows[0]?.["entry_hash_hex"]);
}

export async function cloneVariableRows(input: {
  readonly source: string;
  readonly count: number;
  readonly prefix: string;
  readonly valueBytes?: number;
}): Promise<void> {
  for (let index = 0; index < input.count; index += 1) {
    const variableId = `${input.prefix}-${String(index).padStart(4, "0")}`;
    await queryProjectDo(
      projectId,
      `INSERT INTO variables SELECT environment_id, ?, name || ?, latest_meta_version,
         latest_version, created_at + ?, deleted_at FROM variables
       WHERE environment_id = ? AND variable_id = ?`,
      variableId,
      `_${index}`,
      index + 1,
      ENV,
      input.source,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_meta_statements SELECT environment_id, ?, meta_version, suite,
         name || ?, status, prev_meta_sig_hash_hex, chain_head_hash_hex, chain_head_seq,
         signature_hex, signed_bytes_hash_hex, author_user_id, author_key_fingerprint, created_at,
         layout_version, var_type, required, description, max_age_days
       FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?`,
      variableId,
      `_${index}`,
      ENV,
      input.source,
    );
    if (input.valueBytes !== undefined) {
      await queryProjectDo(
        projectId,
        `INSERT INTO variable_versions SELECT environment_id, ?, version, suite, epoch, nonce_hex,
           lower(hex(randomblob(?))), ?, prev_value_sig_hash_hex, chain_head_hash_hex,
           chain_head_seq, signature_hex, signed_bytes_hash_hex, writer_user_id,
           writer_key_fingerprint, created_at
         FROM variable_versions WHERE environment_id = ? AND variable_id = ?`,
        variableId,
        input.valueBytes,
        input.valueBytes,
        ENV,
        input.source,
      );
    }
  }
}
