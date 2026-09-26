// Integration tests for the audit log (AUDIT_SPEC §3.3 data events / §3.4
// chain mirror / §5.1 schema).
//
// - seq is monotonic and gapless (§5.1 / §6)
// - The chain mirror carries actor (user_id + key FP), chain_seq, and both
//   client / server timestamps (§3.4)
// - Identity rule (§1-2): provider info and emails must not appear in any
//   row

import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { makeAuditStore } from "../src/audit-store.ts";
import { JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEnvironmentManifest, WireVariableMetaStatement } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  commitmentOf,
  createVariableStatement,
  digestOf,
  encryptValue,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
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
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId, version: 1 },
    `secret-${variableId}`,
    { writerUserId: MEMBER, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: MEMBER,
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

/** Sign the manifest bundled with a variable meta op (rename / delete) (§12-5) and advance the record. */
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

/** Sign a variable's next statement (rename / delete) from the latest recorded one. */
async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly authorUserId: string;
}): Promise<WireVariableMetaStatement> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) throw new Error(`no recorded statement for ${input.variableId}`);
  const statement = await signMetaStatementAs(input.authorUserId, projectId, {
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

/**
 * Check the author key FPs of the last 5 lifecycle rows (env.renamed →
 * var.renamed → var.deleted → cascade var.deleted → env.deleted)
 * (AUDIT_SPEC §3.3): ops accompanied by a meta statement copy the author's
 * key FP, and the environment-deletion cascade var.deleted copies the
 * author FP of the env deletion statement.
 */
function expectMetaAuthorFingerprints(events: readonly Record<string, unknown>[]): void {
  const tail = events.slice(-5);
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

/** Minimal event for the numbering-reset check (test input for audit-store.ts's reset-on-failure). */
const seqTestEvent = (name: string) =>
  ({ event: name, serverTs: 1, actorType: "user", actorUserId: OWNER }) as const;

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
    // §3.4: genesis's target is the creator (the start of the membership interval)
    expect(genesis["target_user_id"]).toBe(OWNER);
    expect(genesis["client_ts"]).toBeTypeOf("number");
    expect(genesis["server_ts"]).toBeTypeOf("number");

    const addMember = events[1];
    if (addMember === undefined) throw new Error("missing add_member mirror");
    expect(addMember["target_user_id"]).toBe(MEMBER);
    // scope is also copied (AUDIT_SPEC §3.4 — 2026-09-14 ES)
    expect(JSON.parse(String(addMember["payload"]))).toEqual({
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
  });

  it("mirrors create_environment / rotate_epoch with the dek commitment (§3.4)", async () => {
    // Both creation and rotation land on the chain via composite requests
    // (§12-4). The commitment in the mirror payload matches the §5.2
    // computed value of the bundled DEK (pinning the value, not just the
    // shape: rejects mutants that copy a different epoch's value or a
    // constant)
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const commitment1 = await commitmentOf(projectId, ENV, 1, dek1);
    const commitment2 = await commitmentOf(projectId, ENV, 2, dek2);
    const events = await readAuditEvents(projectId);
    const rotated = events.find((event) => event["event"] === "chain.epoch_rotated");
    const created = events.find((event) => event["event"] === "chain.environment_created");
    if (rotated === undefined || created === undefined) throw new Error("missing mirrors");

    expect(created["environment_id"]).toBe(ENV);
    expect(created["epoch"]).toBe(1);
    expect(created["chain_seq"]).toBe(4);
    expect(created["actor_user_id"]).toBe(OWNER);
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    // dek_commitment is copied into the payload (AUDIT_SPEC §3.4)
    expect(JSON.parse(String(created["payload"]))).toEqual({ dekCommitmentHex: commitment1 });

    expect(rotated["event"]).toBe("chain.epoch_rotated");
    expect(rotated["environment_id"]).toBe(ENV);
    expect(rotated["epoch"]).toBe(2);
    // The composite appends a boundary checkpoint (H+2) right after create /
    // rotate (H+1) (§12-4), so the rotate's chain seq is 6
    expect(rotated["chain_seq"]).toBe(6);
    expect(JSON.parse(String(rotated["payload"]))).toEqual({
      reason: "scheduled",
      dekCommitmentHex: commitment2,
    });

    // The boundary checkpoint mirror (chain.checkpointed — AUDIT_SPEC §3.4)
    // is recorded at the H+2 seq (creation = 5, rotate = 7) and copies the
    // environment tuple into the payload
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
    // FP = SHA-256(enc public key)[:16] (CRYPTO_SPEC §9). Chain verification requires them to match
    const serverEncPubHex = "ab".repeat(32);
    const fpResult = await computeServerKeyFingerprint(hexBytes(serverEncPubHex));
    if (!fpResult.ok) throw new Error("fingerprint failed");
    const serverKeyFingerprintHex = encodeHex(fpResult.value);
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex,
        serverKeyFingerprintHex,
        scopeEnvironmentIds: [ENV],
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

    // Metadata-only mode (AUTH_SPEC §12-7) does not distribute values, so
    // it adds no audit rows at all, including var.read ("do not record
    // reading what was not read" — §3.3; the check is that no row
    // originating from this request appears in the expected event list
    // below)
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
          // A deleted statement's name keeps the immediately preceding active name (§4.2)
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
    // seq is gapless starting at 1 (a gap = a trace of deletion — §6)
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
      // A composite environment creation (§12-4) atomically writes the
      // chain mirror (2 entries: create + boundary checkpoint) +
      // env.created + the bundled wraps' dek.registered (one row per
      // recipient — §3.3)
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
      // A bulk pull with values is one row per environment (aggregated
      // form — §3.3). The enumeration of returned variables is carried by
      // the payload
      "var.read",
      "env.renamed",
      "var.renamed",
      "var.deleted",
      // Environment deletion is accompanied by var.deleted for the remaining variables (§12-4)
      "var.deleted",
      "env.deleted",
    ]);

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
    // var.created / var.version_pushed are ops accompanied by signatures
    // (CRYPTO_SPEC §4.1 / §4.2), so they copy the chain-derived key FP at
    // acceptance time (AUDIT_SPEC §3.3 — signatures, signed bytes, hashes,
    // nonces, and ciphertexts are not put on the audit log). On creation,
    // the bundled v1's writer FP = the statement's author FP (same subject
    // — §12-5)
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(pushed["epoch"]).toBe(1);
    expect(pushed["version"]).toBe(1);
    expect(pushed["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(read["actor_user_id"]).toBe(READER);
    // Aggregated form (§3.3): a per-environment row where variable-grained
    // columns are NULL, and the payload holds the enumeration of returned
    // variables (ascending variableId, with epoch / version)
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
    // var.read is not accompanied by a signature, so it has no FP (the §3.3 semantics)
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
      // Trigger the failure by directly inserting a colliding row at a seq in the middle of chunk 2 (row 7 onwards)
      sql.exec(
        "INSERT INTO audit_events (seq, server_ts, event, actor_type) VALUES (?, ?, ?, ?)",
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
      // The failure discards the numbering cache, and the next append
      // continues from the live DB's MAX(seq)+1 (if it had kept advancing,
      // it would number at base+14 and produce a gap against the
      // post-rollback DB). Note: in production the task failure rolls back
      // chunk 1 too — here only the numbering cache's behavior is pinned
      store.appendSync(seqTestEvent("test.after"));
      const last = sql
        .exec("SELECT seq, event FROM audit_events ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      expect(last?.["event"]).toBe("test.after");
      expect(last?.["seq"]).toBe(base + 10);
    });
    // Restore the DO to its initial state so the directly-inserted row does not survive past this test
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
      const invalid = { ...seqTestEvent("var.read"), chainSeq: 1 };

      expect(() => store.appendSync(invalid)).toThrow("chain_seq is reserved for chain.* events");
      // Even with a violation in the back half, the valid front-half rows
      // are not partially appended (crossing the APPEND_CHUNK_ROWS=5
      // boundary, with the violation placed in the second chunk)
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

  it("seq stays gapless across a chunk-split bulk append and a DO restart (§5.1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // Create 8 variables — more than the per-statement row count of a
    // multi-row INSERT (5 rows in audit-store.ts) — so that the
    // environment-deletion cascade (8 var.deleted rows + env.deleted —
    // §12-4) is appended split across multiple chunks (a pull with values
    // is a single aggregated row — §3.3 — so the bulk-append path is
    // exercised via the deletion cascade)
    for (let index = 0; index < 8; index += 1) {
      await createVariableOk(dek, `var-batch-${index}`, `BATCH_${index}`);
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);

    // Equivalent to a DO restart: discard the in-instance-memory next seq
    // and confirm the next append numbers continuing from a MAX(seq)
    // re-read
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
    // env.created is an op accompanied by a meta statement (CRYPTO_SPEC
    // §4.2), so it copies the author's key FP (AUDIT_SPEC §3.3)
    expect(envCreated["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    // A data mutation via session auth is rejected with 403 by the §5
    // capability restriction and leaves no audit row (the session-actor
    // attribution of the D1-side auth.* / invite.* events is covered by the
    // audit-d1 / invites tests)
    const session = await loginSession(9002);
    const dek = makeDek();
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
      actorUserId: MEMBER,
      operation: {
        op: "create_environment",
        payload: {
          environmentId: "env-audit-0002",
          dekCommitmentHex: await commitmentOf(projectId, "env-audit-0002", 1, dek),
        },
      },
    });
    const sessionStatement = await createEnvironmentStatement({
      authorUserId: MEMBER,
      environmentId: "env-audit-0002",
      name: "Session",
      head: fixture.head,
    });
    const sessionManifest = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: "env-audit-0002",
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: sessionStatement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, sessionStatement, MEMBER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // Boundary checkpoint (H+2 — the mandatory bundled item of §12-4)
    const { entry: sessionCheckpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actorUserId: MEMBER,
      operation: checkpointOperation({
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
    // The bundled epoch-1 wraps at environment creation: one row per recipient (one row, one target)
    const initial = await readAuditEvents(projectId);
    const epoch1 = initial.filter((event) => event["event"] === "dek.registered");
    expect(epoch1.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch1) {
      expect(event["environment_id"]).toBe(ENV);
      expect(event["epoch"]).toBe(1);
      expect(event["actor_user_id"]).toBe(OWNER);
      // Copies the signer FP of the registration signature (CRYPTO_SPEC §5.1) (§3.3 — for reconciliation)
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      // Registered via a PAT, so it carries the token id (§2 actor attribution)
      expect(event["actor_api_token_id"]).toBeTypeOf("string");
      expect(event["variable_id"]).toBeNull();
    }

    // The bundled wraps of a composite rotation (§12-4) are recorded in the same shape
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);

    // Deletion (the §12-6 repair path) records dek.deleted per recipient
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      {
        wraps: [{ epoch: 2, recipientUserId: READER }],
      },
    );
    expect(removed.status).toBe(204);

    // Repair re-registration (the path remaining on the registration API — §12-6) is also recorded in the same shape
    const removedEpoch1 = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      { wraps: [{ epoch: 1, recipientUserId: READER }] },
    );
    expect(removedEpoch1.status).toBe(204);
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
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
    // Deletion is not accompanied by a signature, so it has no FP (AUDIT_SPEC §3.3)
    expect(deletion["actor_key_fingerprint"]).toBeNull();
  });

  it("never records provider identifiers or emails (§1-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    // The seeded GitHub numeric IDs (provider_user_id), logins, and email
    // forms must not appear as substrings in any column or payload
    // (timestamp columns are excluded to avoid accidental numeric matches)
    for (const event of events) {
      for (const [column, value] of Object.entries(event)) {
        if (column === "server_ts" || column === "client_ts" || value === null) {
          continue;
        }
        // Random hex (DEK commitments, key FPs, etc.) can coincidentally
        // contain digit runs like "9001", so long hex runs are removed
        // before scanning (a real provider-ID leak would appear as a short
        // standalone value, so detection power is not lost)
        const text = String(value).replace(/[0-9a-f]{16,}/g, "");
        for (const forbidden of ["9001", "9002", "9003", "9009", "user900", "@"]) {
          expect(text).not.toContain(forbidden);
        }
      }
    }
  });
});
