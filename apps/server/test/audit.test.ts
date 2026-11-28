import { decodeKeyFingerprintHex } from "@maruhi/core";
import { computeServerKeyFingerprint, encodeHex, generateDek } from "@maruhi/crypto";
import { testKeyFingerprintHex } from "@maruhi/crypto/test-support";
import type { WireEnvironmentManifest, WireVariableMetaStatement } from "@maruhi/test-kit";
import {
  checkpointOp,
  createVariableStatement,
  encryptValue,
  hexBytes,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signManifest,
  signMetaStatement,
  testDekCommitmentHex,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  valuesDigestOf,
  variablesDigestOf,
  wrapDekTo,
} from "@maruhi/test-kit";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { brandOrNull, toAuditHeadRow } from "../src/audit-store-rows.ts";
import { type AuditEventInput, makeAuditStore } from "../src/audit-store.ts";
import { dataEvent } from "../src/data.package/index.ts";
import { JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import { identityOf, vectorKeyOf, wrapDekForAll } from "./support/data-crypto.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  dataUrl,
  deleteEnvironmentRequest,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  rotateEnvironmentOk,
  setupDataProject,
  tokenOf,
} from "./support/data-fixture.ts";
import { readAuditEvents } from "./support/project-do.ts";

const ENV = "env-audit-0001";
const VAR = "var-api-key";

let fixture: DataFixture;
let varStatements: Map<string, { statement: WireVariableMetaStatement; authorUserId: string }>;

beforeEach(async () => {
  fixture = await setupDataProject();
  varStatements = new Map();
});

const token = (userId: string): string => tokenOf(fixture.tokens, userId);

async function createVariableOk(dek: Uint8Array, variableId: string, name: string): Promise<void> {
  const value = await encryptValue({
    dek,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(ENV),
    epoch: 1,
    variableId: testVariableId(variableId),
    version: 1,
    plaintext: `secret-${variableId}`,
    writer: identityOf(MEMBER),
    head: fixture.head,
  });
  const statement = await createVariableStatement({
    author: identityOf(MEMBER),
    projectId,
    environmentId: ENV,
    variableId,
    name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: ENV,
    issuerUserId: MEMBER,
    entry: {
      variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
    },
  });
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    statement,
    value,
    manifest,
  });
  expect(response.status).toBe(200);
  varStatements.set(variableId, { statement, authorUserId: MEMBER });
  fixture.manifests.set(ENV, state);
}

async function manifestForNext(
  statement: WireVariableMetaStatement,
  issuerUserId: string,
): Promise<WireEnvironmentManifest> {
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: ENV,
    issuerUserId,
    entry: {
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, issuerUserId),
    },
  });
  fixture.manifests.set(ENV, state);
  return manifest;
}

async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly authorUserId: string;
}): Promise<WireVariableMetaStatement> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) throw new Error(`no recorded statement for ${input.variableId}`);
  const statement = await signMetaStatement(identityOf(input.authorUserId), projectId, {
    suite: "maruhi/v1" as const,
    environmentId: ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, last.statement, last.authorUserId),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
  varStatements.set(input.variableId, { statement, authorUserId: input.authorUserId });
  return statement;
}

function expectMetaAuthorFingerprints(events: readonly Record<string, unknown>[]): void {
  const tail = events.filter((row) => !String(row["event"]).startsWith("chain.")).slice(-5);
  const memberFp = vectorKeyOf(MEMBER).key_fingerprint_hex;
  const ownerFp = vectorKeyOf(OWNER).key_fingerprint_hex;
  expect(tail.map((row) => [row["event"], row["actor_key_fingerprint"]])).toEqual([
    ["env.renamed", memberFp],
    ["var.renamed", memberFp],
    ["var.deleted", memberFp],
    ["var.deleted", ownerFp],
    ["env.deleted", ownerFp],
  ]);
  expect(JSON.parse(String(tail[0]?.["payload"]))).toMatchObject({ name: "App2" });
  expect(JSON.parse(String(tail[1]?.["payload"]))).toMatchObject({ name: "API_KEY_V2" });
}

const seqTestEvent = (tag: string): AuditEventInput => ({
  event: "var.deleted",
  serverTs: 1,
  actorType: "user",
  actorUserId: OWNER,
  variableId: tag,
});

describe("chain mirror (§3.4)", () => {
  it("mirrors accepted chain entries with actor identity, chain_seq and both timestamps", async () => {
    const events = await readAuditEvents(projectId);
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
    ]);

    const genesis = events[0];
    if (genesis === undefined) throw new Error("missing genesis mirror");
    expect(genesis["seq"]).toBe(1);
    expect(genesis["chain_seq"]).toBe(1);
    expect(genesis["actor_type"]).toBe("user");
    expect(genesis["actor_user_id"]).toBe(OWNER);
    expect(genesis["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    expect(genesis["target_user_id"]).toBe(OWNER);
    expect(genesis["client_ts"]).toBeTypeOf("number");
    expect(genesis["server_ts"]).toBeTypeOf("number");

    const addMember = events[1];
    if (addMember === undefined) throw new Error("missing add_member mirror");
    expect(addMember["target_user_id"]).toBe(MEMBER);
    expect(JSON.parse(String(addMember["payload"]))).toEqual({
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
  });

  it("mirrors create_environment / rotate_epoch with the dek commitment (§3.4)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const commitment1 = await testDekCommitmentHex(projectId, ENV, 1, dek1);
    const commitment2 = await testDekCommitmentHex(projectId, ENV, 2, dek2);
    const events = await readAuditEvents(projectId);
    const rotated = events.find((event) => event["event"] === "chain.epoch_rotated");
    const created = events.find((event) => event["event"] === "chain.environment_created");
    if (rotated === undefined || created === undefined) throw new Error("missing mirrors");

    expect(created["environment_id"]).toBe(ENV);
    expect(created["epoch"]).toBe(1);
    expect(created["chain_seq"]).toBe(4);
    expect(created["actor_user_id"]).toBe(OWNER);
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    expect(JSON.parse(String(created["payload"]))).toEqual({ dekCommitmentHex: commitment1 });

    expect(rotated["event"]).toBe("chain.epoch_rotated");
    expect(rotated["environment_id"]).toBe(ENV);
    expect(rotated["epoch"]).toBe(2);
    expect(rotated["chain_seq"]).toBe(6);
    expect(JSON.parse(String(rotated["payload"]))).toEqual({
      reason: "scheduled",
      dekCommitmentHex: commitment2,
    });

    const checkpoints = events.filter((event) => event["event"] === "chain.checkpointed");
    expect(checkpoints.map((event) => event["chain_seq"])).toEqual([5, 7]);
    const rotateCheckpoint = JSON.parse(String(checkpoints[1]?.["payload"])) as {
      environments: { environmentId: string; epoch: number; manifestVersion: number }[];
    };
    expect(rotateCheckpoint.environments).toHaveLength(1);
    expect(rotateCheckpoint.environments[0]).toMatchObject({
      environmentId: ENV,
      epoch: 2,
      manifestVersion: 2,
    });
  });

  it("mirrors change_role / remove_member with the target user id (the §4.1 Q1 input)", async () => {
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: {
        targetUserId: READER,
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const events = await readAuditEvents(projectId);
    const roleChanged = events.at(-2);
    const removed = events.at(-1);
    if (roleChanged === undefined || removed === undefined) throw new Error("missing mirrors");
    expect(roleChanged["event"]).toBe("chain.role_changed");
    expect(roleChanged["target_user_id"]).toBe(READER);
    expect(JSON.parse(String(roleChanged["payload"]))).toEqual({
      newRole: "admin",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(removed["event"]).toBe("chain.member_removed");
    expect(removed["target_user_id"]).toBe(MEMBER);
    expect(removed["actor_user_id"]).toBe(OWNER);
    expect(removed["chain_seq"]).toBe(5);
  });

  it("mirrors grant_server / revoke_server with the server key fingerprint (the §4.1 Q6 input)", async () => {
    const serverEncPubHex = "ab".repeat(32);
    const fpResult = await computeServerKeyFingerprint(hexBytes(serverEncPubHex));
    if (!fpResult.ok) throw new Error("fingerprint failed");
    const serverKeyFingerprintHex = testKeyFingerprintHex(encodeHex(fpResult.value));
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex,
        serverKeyFingerprintHex,
        scopeEnvironmentIds: [testEnvironmentId(ENV)],
        leasePolicy: [],
      },
    });
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex },
    });
    const events = await readAuditEvents(projectId);
    const granted = events.at(-2);
    const revoked = events.at(-1);
    if (granted === undefined || revoked === undefined) throw new Error("missing mirrors");
    expect(granted["event"]).toBe("chain.server_granted");
    expect(granted["target_key_fingerprint"]).toBe(serverKeyFingerprintHex);
    expect(granted["target_user_id"]).toBeNull();
    expect(JSON.parse(String(granted["payload"]))).toEqual({ scopeEnvironmentIds: [ENV] });
    expect(revoked["event"]).toBe("chain.server_revoked");
    expect(revoked["target_key_fingerprint"]).toBe(serverKeyFingerprintHex);
  });
});

describe("data events (§3.3) and gapless seq (§5.1)", () => {
  it("records the full lifecycle with gapless seq and one aggregated var.read row per value pull", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "API_KEY");
    await createVariableOk(dek, "var-second", "SECOND");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);

    const metadataPull = await requestJson(
      "GET",
      `/environments/${ENV}/pull/metadata`,
      token(READER),
    );
    expect(metadataPull.status).toBe(200);

    const envRenamed = await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER);
    expect(envRenamed.status).toBe(204);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      await (async () => {
        const statement = await nextVariableStatement({
          variableId: VAR,
          name: "API_KEY_V2",
          status: "active",
          authorUserId: MEMBER,
        });
        return { statement, manifest: await manifestForNext(statement, MEMBER) };
      })(),
    );
    expect(renamed.status).toBe(204);
    const removedVar = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      await (async () => {
        const statement = await nextVariableStatement({
          variableId: VAR,
          name: "API_KEY_V2",
          status: "deleted",
          authorUserId: MEMBER,
        });
        return { statement, manifest: await manifestForNext(statement, MEMBER) };
      })(),
    );
    expect(removedVar.status).toBe(204);
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);

    const events = await readAuditEvents(projectId);
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
      "chain.environment_created",
      "chain.checkpointed",
      "env.created",
      "dek.registered",
      "dek.registered",
      "dek.registered",
      "var.created",
      "var.version_pushed",
      "var.created",
      "var.version_pushed",
      "var.read",
      "env.renamed",
      "var.renamed",
      "var.deleted",
      "chain.environment_deleted",
      "var.deleted",
      "env.deleted",
    ]);
    expect(events.slice(-3).map((event) => event["environment_id"])).toEqual([ENV, ENV, ENV]);

    const created = events[9];
    const pushed = events[10];
    const read = events[13];
    const envRenamedRow = events[14];
    if (
      created === undefined ||
      pushed === undefined ||
      read === undefined ||
      envRenamedRow === undefined
    ) {
      throw new Error("missing audit rows");
    }
    expect(created["variable_id"]).toBe(VAR);
    expect(created["environment_id"]).toBe(ENV);
    expect(JSON.parse(String(created["payload"]))).toEqual({ name: "API_KEY" });
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(pushed["epoch"]).toBe(1);
    expect(pushed["version"]).toBe(1);
    expect(pushed["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(read["actor_user_id"]).toBe(READER);
    expect(read["environment_id"]).toBe(ENV);
    expect(read["variable_id"]).toBeNull();
    expect(read["epoch"]).toBeNull();
    expect(read["version"]).toBeNull();
    expect(JSON.parse(String(read["payload"]))).toEqual({
      variables: [
        { variableId: VAR, epoch: 1, version: 1 },
        { variableId: "var-second", epoch: 1, version: 1 },
      ],
    });
    expect(read["actor_key_fingerprint"]).toBeNull();
    expect(envRenamedRow["event"]).toBe("env.renamed");

    expectMetaAuthorFingerprints(events);
  });

  it("discards the numbering cache on insert failure, and the next append continues from a MAX(seq) re-read", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const baseRow = sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0];
      const base = Number(baseRow?.["m"] ?? 0);
      store.appendSync(seqTestEvent("test.one"));
      sql.exec(
        "INSERT INTO audit_events (seq, row_id, server_ts, event, actor_type) VALUES (?, lower(hex(randomblob(16))), ?, ?, ?)",
        base + 9,
        1,
        "test.direct",
        "user",
      );
      expect(() =>
        store.appendManySync(
          Array.from({ length: 12 }, (_e, index) => seqTestEvent(`test.b${index}`)),
        ),
      ).toThrow();
      store.appendSync(seqTestEvent("test.after"));
      const last = sql
        .exec("SELECT seq, variable_id FROM audit_events ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      expect(last?.["variable_id"]).toBe("test.after");
      expect(last?.["seq"]).toBe(base + 10);
    });
    await evictDurableObject(stub);
  });

  it("chain_seq cannot be appended to non-chain.* events, and a bulk append rejects all rows before numbering", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const before = Number(
        sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0]?.["m"] ?? 0,
      );
      const invalid: AuditEventInput = { ...seqTestEvent("test.invalid"), chainSeq: 1 };

      expect(() => store.appendSync(invalid)).toThrow("chain_seq is reserved for chain.* events");
      expect(() =>
        store.appendManySync([
          ...Array.from({ length: 6 }, (_e, index) => seqTestEvent(`test.before-invalid${index}`)),
          invalid,
        ]),
      ).toThrow("chain_seq is reserved for chain.* events");

      const after = Number(
        sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0]?.["m"] ?? 0,
      );
      expect(after).toBe(before);
    });
  });

  it("refuses a payload key AUDIT_SPEC does not list, before numbering (the identity rule's payload gate)", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const maxSeq = () =>
        Number(
          sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0]?.["m"] ?? 0,
        );
      const before = maxSeq();
      const snapshot = { name: "production", login: "octocat" };
      const widened: AuditEventInput = {
        event: "env.renamed",
        serverTs: 1,
        actorType: "user",
        actorUserId: OWNER,
        payload: snapshot,
      };
      expect(() => store.appendSync(widened)).toThrow(
        "the env.renamed payload is not the AUDIT_SPEC §3 shape",
      );
      expect(() =>
        store.appendManySync([
          ...Array.from({ length: 6 }, (_e, index) => seqTestEvent(`test.before-widened${index}`)),
          widened,
        ]),
      ).toThrow("the env.renamed payload is not the AUDIT_SPEC §3 shape");
      expect(maxSeq()).toBe(before);
    });
  });

  it("a user actor's dek.deleted carries no payload: the cause-naming one is the system's cleanup (§3.3)", () => {
    const actor = { userId: OWNER };
    const fields = { event: "dek.deleted", environmentId: "env-1", epoch: 1 } as const;
    expect(dataEvent(actor, 1, fields).payload).toBeUndefined();
    dataEvent(actor, 1, {
      ...fields,
      // @ts-expect-error -- the re-add cleanup payload is written by the system actor only
      payload: { cause: "member-readded", triggerChainSeq: 2 },
    });
  });

  it("merges a session actor's auth method into the stored payload (§2 / §5.1), and stores NULL for an empty one", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const lastPayload = () =>
        sql.exec("SELECT payload FROM audit_events ORDER BY seq DESC LIMIT 1").toArray()[0]?.[
          "payload"
        ];
      store.appendSync({
        event: "env.renamed",
        serverTs: 1,
        actorType: "user",
        actorUserId: OWNER,
        actorAuthMethod: "github_oauth",
        payload: { name: "production" },
      });
      expect(lastPayload()).toBe('{"name":"production","authMethod":"github_oauth"}');
      store.appendSync({ ...seqTestEvent("test.session"), actorAuthMethod: "github_oauth" });
      expect(lastPayload()).toBe('{"authMethod":"github_oauth"}');
      store.appendSync(seqTestEvent("test.token"));
      expect(lastPayload()).toBeNull();
    });
    await evictDurableObject(stub);
  });

  it("seq stays gapless across a chunk-split bulk append and a DO restart (§5.1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    for (let index = 0; index < 8; index += 1) {
      await createVariableOk(dek, `var-batch-${index}`, `BATCH_${index}`);
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);

    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await evictDurableObject(stub);
    await createEnvironmentOk(fixture, "env-after-restart", "Other");

    const events = await readAuditEvents(projectId);
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.filter((event) => event["event"] === "var.read").length).toBe(1);
    expect(events.filter((event) => event["event"] === "var.deleted").length).toBe(8);
    expect(
      events.some(
        (event) =>
          event["event"] === "env.created" && event["environment_id"] === "env-after-restart",
      ),
    ).toBe(true);
  });

  it("attributes actors: PAT ops carry the token id; session mutations are rejected and leave no row (§2 / AUTH_SPEC §5)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    const envCreated = events.find((event) => event["event"] === "env.created");
    if (envCreated === undefined) throw new Error("missing env.created");
    expect(envCreated["actor_user_id"]).toBe(OWNER);
    expect(envCreated["actor_api_token_id"]).toBeTypeOf("string");
    expect(envCreated["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    const session = await loginSession(9002);
    const dek = generateDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-audit-0002",
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const { entry, hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actor: identityOf(MEMBER),
      operation: {
        op: "create_environment",
        payload: {
          environmentId: testEnvironmentId("env-audit-0002"),
          dekCommitmentHex: await testDekCommitmentHex(projectId, "env-audit-0002", 1, dek),
        },
      },
    });
    const sessionStatement = await createEnvironmentStatement({
      authorUserId: MEMBER,
      environmentId: "env-audit-0002",
      name: "Session",
      head: fixture.head,
    });
    const sessionManifest = await signManifest(identityOf(MEMBER), projectId, {
      suite: "maruhi/v1",
      environmentId: "env-audit-0002",
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await variablesDigestOf([]),
      envMetaVersion: sessionStatement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, sessionStatement, MEMBER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const { entry: sessionCheckpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actor: identityOf(MEMBER),
      operation: checkpointOp({
        environmentId: "env-audit-0002",
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: await manifestSignedBytesHashOf(projectId, sessionManifest, MEMBER),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const created = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...sessionHeaders(session) },
      body: JSON.stringify({
        parentHeadHashHex: fixture.head.hashHex,
        entry,
        statement: sessionStatement,
        deks,
        manifest: sessionManifest,
        checkpoint: sessionCheckpoint,
      }),
    });
    expect(created.status).toBe(403);
    expect(((await created.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const after = await readAuditEvents(projectId);
    expect(
      after.find(
        (event) => event["event"] === "env.created" && event["environment_id"] === "env-audit-0002",
      ),
    ).toBeUndefined();
  });

  it("records dek.registered / dek.deleted per recipient with actor, epoch and target (§3.3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const initial = await readAuditEvents(projectId);
    const epoch1 = initial.filter((event) => event["event"] === "dek.registered");
    expect(epoch1.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch1) {
      expect(event["environment_id"]).toBe(ENV);
      expect(event["epoch"]).toBe(1);
      expect(event["actor_user_id"]).toBe(OWNER);
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      expect(event["actor_api_token_id"]).toBeTypeOf("string");
      expect(event["variable_id"]).toBeNull();
    }

    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);

    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      {
        wraps: [
          {
            epoch: 2,
            recipientClass: "member",
            recipientUserId: READER,
            recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          },
        ],
      },
    );
    expect(removed.status).toBe(204);

    const removedEpoch1 = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      {
        wraps: [
          {
            epoch: 1,
            recipientClass: "member",
            recipientUserId: READER,
            recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          },
        ],
      },
    );
    expect(removedEpoch1.status).toBe(204);
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipient: identityOf(READER),
      signer: identityOf(MEMBER),
    });
    const reRegistered = await requestJson(
      "POST",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, MEMBER),
      { deks: [reWrap] },
    );
    expect(reRegistered.status).toBe(204);

    const events = await readAuditEvents(projectId);
    const epoch2 = events.filter(
      (event) => event["event"] === "dek.registered" && event["epoch"] === 2,
    );
    expect(epoch2.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch2) {
      expect(event["actor_user_id"]).toBe(MEMBER);
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    }
    const repair = events.at(-1);
    if (repair === undefined) throw new Error("missing repair registration event");
    expect(repair["event"]).toBe("dek.registered");
    expect(repair["epoch"]).toBe(1);
    expect(repair["target_user_id"]).toBe(READER);
    expect(repair["actor_user_id"]).toBe(MEMBER);
    expect(repair["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted.length).toBe(2);
    const deletion = deleted[0];
    if (deletion === undefined) throw new Error("missing dek.deleted");
    expect(deletion["environment_id"]).toBe(ENV);
    expect(deletion["epoch"]).toBe(2);
    expect(deletion["target_user_id"]).toBe(READER);
    expect(deletion["actor_user_id"]).toBe(OWNER);
    expect(deletion["actor_key_fingerprint"]).toBeNull();
  });

  it("never records provider identifiers or emails (§1-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    for (const event of events) {
      for (const [column, value] of Object.entries(event)) {
        if (column === "server_ts" || column === "client_ts" || value === null) {
          continue;
        }
        const text = String(value).replace(/[0-9a-f]{16,}/g, "");
        for (const forbidden of ["9001", "9002", "9003", "9009", "user900", "@"]) {
          expect(text).not.toContain(forbidden);
        }
      }
    }
  });
});

describe("stored-row brand decoders (audit-store-rows.ts)", () => {
  it("brandOrNull reads NULL and a valid fingerprint, and reads a malformed one as null instead of throwing", () => {
    expect(brandOrNull(null, decodeKeyFingerprintHex)).toBeNull();
    expect(brandOrNull("ab".repeat(16), decodeKeyFingerprintHex)).toBe("ab".repeat(16));
    expect(brandOrNull("not-a-fingerprint", decodeKeyFingerprintHex)).toBeNull();
    expect(brandOrNull("AB".repeat(16), decodeKeyFingerprintHex)).toBeNull();
  });

  it("toAuditHeadRow maps a malformed fingerprint column to null instead of throwing", () => {
    const row = toAuditHeadRow({
      seq: 1,
      row_id: "cd".repeat(16),
      server_ts: 1_700_000_000_000,
      client_ts: null,
      event: "var.read",
      actor_type: "user",
      actor_user_id: null,
      actor_key_fingerprint: "not-a-fingerprint",
      actor_api_token_id: null,
      target_user_id: null,
      target_key_fingerprint: "ab".repeat(16),
      environment_id: null,
      variable_id: null,
      epoch: null,
      version: null,
      chain_seq: null,
      payload: null,
    });
    expect(row.actorKeyFingerprintHex).toBeNull();
    expect(row.targetKeyFingerprintHex).toBe("ab".repeat(16));
  });
});
