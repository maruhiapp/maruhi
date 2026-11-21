import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { testUserId } from "@maruhi/crypto/test-support";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { MAX_VERSION_VALUES_PAGE_BYTES } from "../src/policy.ts";
import { withinByteBudget } from "../src/programs/programs-history.ts";
import { JSON_HEADERS } from "./support/auth.ts";
import {
  createVariableStatement,
  encryptValue,
  makeDek,
  metaSignedBytesHashOf,
  signMetaStatementAs,
  valueSignedBytesHashOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
  type WireEncryptedPayload,
  type WireVariableMetaStatement,
} from "./support/data-crypto.ts";
import { commitmentOf } from "./support/data-crypto.ts";
import {
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testVariableId,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  readonly trigger?: "remove_member" | "change_role" | "revoke_server";
  readonly reopenedByVersion?: number;
}

async function readFlags(asUserId: string = READER): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(asUserId));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

async function removeMember(targetUserId: string): Promise<number> {
  await appendOperation(fixture, OWNER, {
    op: "remove_member",
    payload: { targetUserId: testUserId(targetUserId) },
  });
  return fixture.head.seq;
}

async function readdWithSameKeys(targetUserId: string, role: "member" | "reader"): Promise<void> {
  const keys = vectorKeyOf(targetUserId);
  await appendOperation(fixture, OWNER, {
    op: "add_member",
    payload: {
      targetUserId: testUserId(targetUserId),
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  });
}

async function pullAs(userId: string): Promise<void> {
  const response = await requestJson("GET", `/environments/${ENV}/pull`, token(userId));
  expect(response.status).toBe(200);
}

async function createVariableAsOwner(input: {
  readonly dek: Uint8Array;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
}): Promise<WireVariableMetaStatement> {
  const value = await encryptValue(
    input.dek,
    {
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(input.environmentId),
      epoch: 1,
      variableId: testVariableId(input.variableId),
      version: 1,
    },
    `${input.name}-plaintext`,
    { writerUserId: OWNER, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: OWNER,
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: OWNER,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(OWNER),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
  return statement;
}

async function pushNextVersion(input: {
  readonly dek: Uint8Array;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly sameValueAs?: number;
  readonly epoch?: number;
}): Promise<WireEncryptedPayload> {
  const value = await encryptValue(
    input.dek,
    {
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: input.epoch ?? 1,
      variableId: testVariableId(VAR),
      version: input.version,
    },
    `value-v${input.version}`,
    { writerUserId: OWNER, head: fixture.head, prevValueSigHashHex: input.prevValueSigHashHex },
  );
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${VAR}/versions`,
    token(OWNER),
    { value, ...(input.sameValueAs === undefined ? {} : { sameValueAs: input.sameValueAs }) },
  );
  expect(response.status).toBe(200);
  return value;
}

async function rotateTo(
  newEpoch: number,
  recipientUserIds: readonly string[],
): Promise<Uint8Array> {
  const dek = makeDek();
  const response = await rotateEnvironmentComposite(fixture, {
    environmentId: ENV,
    newEpoch,
    deks: await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: newEpoch,
      dek,
      recipientUserIds,
      signerUserId: OWNER,
    }),
    dekCommitmentHex: await commitmentOf(projectId, ENV, newEpoch, dek),
    actorUserId: OWNER,
  });
  expect(response.status).toBe(200);
  return dek;
}

describe("rotation-needed detection: remove_member (AUDIT_SPEC §4.1)", () => {
  it("records one aggregate row per environment — read for a variable read inside the interval, readable for unread candidates", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await pullAs(MEMBER);
    await createVariableOk(dek, "var-api-key", "API_KEY", "sk-alpha");
    const removalSeq = await removeMember(MEMBER);

    const flags = await readFlags();
    expect(flags).toHaveLength(2);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
      trigger: "remove_member",
    });
    expect(byVariable.get("var-api-key")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
      trigger: "remove_member",
    });

    const events = await readAuditEvents(projectId);
    const recommended = events.filter((event) => event["event"] === "rotation.recommended");
    expect(recommended).toHaveLength(1);
    const row = recommended[0];
    if (row === undefined) throw new Error("missing rotation.recommended row");
    expect(row["actor_type"]).toBe("system");
    expect(row["actor_user_id"]).toBeNull();
    expect(row["chain_seq"]).toBeNull();
    expect(row["target_user_id"]).toBe(MEMBER);
    expect(row["variable_id"]).toBeNull();
    expect(row["environment_id"]).toBe(ENV);
    const payload = JSON.parse(String(row["payload"])) as Record<string, unknown>;
    expect(payload["triggerChainSeq"]).toBe(removalSeq);
    expect(payload["trigger"]).toBe("remove_member");
    expect(payload["variables"]).toEqual([
      { variableId: "var-api-key", basis: "readable" },
      { variableId: VAR, basis: "read" },
    ]);
    const mirror = events.find((event) => event["event"] === "chain.member_removed");
    expect(mirror).toBeDefined();
    expect(Number(row["seq"])).toBe(Number(mirror?.["seq"]) + 1);
  });

  it("deleted variables are still candidates, only dismissal resolves, and re-detection after a dismissal revives (§4.1-2 / -5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await pullAs(MEMBER);
    expect((await deleteVariableRequest(VAR, OWNER)).status).toBe(204);
    await removeMember(MEMBER);
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({ variableId: VAR, basis: "read" });

    const dismissed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    expect(await readFlags()).toHaveLength(0);
    const events = await readAuditEvents(projectId);
    const dismissedRows = events.filter((event) => event["event"] === "rotation.dismissed");
    expect(dismissedRows).toHaveLength(1);
    expect(dismissedRows[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      environment_id: ENV,
      variable_id: VAR,
    });

    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);
  });

  it("the interval union of a re-add: candidates cover every interval; a variable overlapping none is excluded (§4.1-1 / -2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);

    const gapVar = "var-gap-secret";
    const gapStatement = await createVariableAsOwner({
      dek,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
    });
    const gapDeleteStatement = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, gapStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const gapDelete = await manifestForVariableOp(fixture, {
      environmentId: ENV,
      issuerUserId: OWNER,
      entry: {
        variableId: gapVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, gapDeleteStatement, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${ENV}/variables/${gapVar}`, token(OWNER), {
          statement: gapDeleteStatement,
          manifest: gapDelete.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(ENV, gapDelete.state);

    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);

    const flags = await readFlags();
    expect(flags.filter((flag) => flag.variableId === VAR)).toHaveLength(2);
    expect(flags.filter((flag) => flag.variableId === gapVar)).toHaveLength(0);
  });

  it("resolution derivation: only a value first encrypted after the mandated rotation resolves; a pre-rotation push and a re-encryption do not (§4.1-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);
    const recommended = (await readAuditEvents(projectId)).find(
      (event) => event["event"] === "rotation.recommended",
    );
    expect(Number(recommended?.["epoch"])).toBe(1);

    const v2 = await pushNextVersion({
      dek,
      version: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
    });
    expect(await readFlags()).toHaveLength(1);

    const dek2 = await rotateTo(2, [OWNER, READER]);
    const v3 = await pushNextVersion({
      dek: dek2,
      version: 3,
      epoch: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, OWNER),
      sameValueAs: 2,
    });
    expect(await readFlags()).toHaveLength(1);
    const events = await readAuditEvents(projectId);
    const markedPush = events.find(
      (event) => event["event"] === "var.version_pushed" && Number(event["version"]) === 3,
    );
    expect(JSON.parse(String(markedPush?.["payload"])) as Record<string, unknown>).toMatchObject({
      sameValueAs: 2,
    });

    await pushNextVersion({
      dek: dek2,
      version: 4,
      epoch: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v3, OWNER),
    });
    expect(await readFlags()).toHaveLength(0);
  });

  it("visibility: the flag view is class 1 (reader allowed); a non-member gets 404 (§6 / §11-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    expect(await readFlags(READER)).toHaveLength(1);
    const stranger = await requestJson("GET", "/rotation/flags", token(STRANGER));
    expect(stranger.status).toBe(404);
  });
});

describe("the dismissal operation (AUDIT_SPEC §3.3 / §7)", () => {
  it("denies below admin with 403, rejects any pair without a live flag with 404 and all-or-nothing, and folds duplicate pairs into one row", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(READER);
    expect(await readFlags(OWNER)).toHaveLength(1);

    const asMember = await requestJson("POST", "/rotation/dismissals", token(MEMBER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(asMember.status).toBe(403);

    const mixed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: "var-not-flagged" },
      ],
    });
    expect(mixed.status).toBe(404);
    await expect(mixed.json()).resolves.toMatchObject({
      _tag: "RotationFlagNotFound",
      variableId: "var-not-flagged",
    });
    expect(await readFlags(OWNER)).toHaveLength(1);
    const before = await readAuditEvents(projectId);
    expect(before.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(0);

    const deduped = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: VAR },
      ],
    });
    expect(deduped.status).toBe(204);
    const after = await readAuditEvents(projectId);
    expect(after.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(1);
    expect(await readFlags(OWNER)).toHaveLength(0);

    const empty = await requestJson("POST", "/rotation/dismissals", token(OWNER), { targets: [] });
    expect(empty.status).toBe(400);
  });
});

describe("rotation-needed detection: the revoke_server variant (AUDIT_SPEC §4.1)", () => {
  it("candidates stay within the grant scope; the variables active at lease issuance become read", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const outEnv = "env-out-of-scope";
    const outDek = makeDek();
    const outDeks = await wrapDekForAll({
      projectId,
      environmentId: outEnv,
      epoch: 1,
      dek: outDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: outEnv,
          name: "Out",
          deks: outDeks,
          dekCommitmentHex: await commitmentOf(projectId, outEnv, 1, outDek),
        })
      ).status,
    ).toBe(200);
    const outVar = "var-out-of-scope";
    await createVariableAsOwner({
      dek: outDek,
      environmentId: outEnv,
      variableId: outVar,
      name: "OUT_SECRET",
    });

    const key = await deploymentKey();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [testEnvironmentId(ENV)],
        leasePolicy: [
          {
            issuerUrl: OIDC_ISSUER,
            audience: LEASE_AUDIENCE,
            claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
          },
        ],
      },
    });
    const serverWrap = await wrapDekToServer({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      serverKeyFingerprintHex: key.fingerprintHex,
      serverEncPubHex: key.encPubHex,
      signerUserId: OWNER,
    });
    expect(
      (await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), { deks: [serverWrap] }))
        .status,
    ).toBe(204);
    const workload = await generateEncryptionKeyPair();
    const ephemeralPubHex = encodeHex(await exportEncryptionPublicKey(workload.publicKey));
    const lease = await SELF.fetch(
      `https://maruhi.test/projects/${projectId}/environments/${ENV}/lease`,
      {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ oidcToken: await makeOidcToken(), ephemeralPubHex }),
      },
    );
    expect(lease.status).toBe(200);

    await createVariableOk(dek, "var-after-lease", "AFTER_LEASE", "later-secret");

    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });
    const revokeSeq = fixture.head.seq;

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetServerKeyFingerprintHex: key.fingerprintHex,
      triggerChainSeq: revokeSeq,
      trigger: "revoke_server",
    });
    expect(byVariable.get("var-after-lease")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
      trigger: "revoke_server",
    });
    expect(byVariable.has(outVar)).toBe(false);
    expect(flags.every((flag) => flag.targetUserId === undefined)).toBe(true);
  });

  it("an environment added by an expanded re-grant is detected under a 'disclosure window from the widening seq' (the §4.1 variant)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const widenEnv = "env-widened";
    const widenDek = makeDek();
    const widenDeks = await wrapDekForAll({
      projectId,
      environmentId: widenEnv,
      epoch: 1,
      dek: widenDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: widenEnv,
          name: "Widened",
          deks: widenDeks,
          dekCommitmentHex: await commitmentOf(projectId, widenEnv, 1, widenDek),
        })
      ).status,
    ).toBe(200);
    const preVar = "var-deleted-before-widen";
    const preStatement = await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
    });

    const key = await deploymentKey();
    const leasePolicy = [
      {
        issuerUrl: OIDC_ISSUER,
        audience: LEASE_AUDIENCE,
        claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
      },
    ];
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [testEnvironmentId(ENV)],
        leasePolicy,
      },
    });
    const preDelete = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, preStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const preDeleteManifest = await manifestForVariableOp(fixture, {
      environmentId: widenEnv,
      issuerUserId: OWNER,
      entry: {
        variableId: preVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, preDelete, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${widenEnv}/variables/${preVar}`, token(OWNER), {
          statement: preDelete,
          manifest: preDeleteManifest.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(widenEnv, preDeleteManifest.state);
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [testEnvironmentId(ENV), testEnvironmentId(widenEnv)],
        leasePolicy,
      },
    });
    const widenVar = "var-in-window";
    await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: widenVar,
      name: "IN_WINDOW",
    });
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(widenVar)).toMatchObject({
      environmentId: widenEnv,
      basis: "readable",
      targetServerKeyFingerprintHex: key.fingerprintHex,
    });
    expect(byVariable.get(VAR)).toMatchObject({ environmentId: ENV, basis: "readable" });
    expect(byVariable.has(preVar)).toBe(false);
  });
});

describe("recipient-key consistency (AUTH_SPEC §12-6 — the B1a addendum)", () => {
  it("an overwrite-forbidden 409 carries the occupied wrap's stored recipient enc public key", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const duplicate = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserId: MEMBER,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [duplicate],
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "DekWrapExists",
      epoch: 1,
      recipientUserId: MEMBER,
      storedRecipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
    });
  });

  it("accepting a re-add under different keys sweeps the old-key wraps and records dek.deleted (system + cause)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, OWNER, ENV, 2);
    await removeMember(MEMBER);
    const wrapsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsBefore[0]?.["n"])).toBe(2);

    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: MEMBER,
        encPubHex: "11".repeat(32),
        sigPubHex: "22".repeat(32),
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const readdSeq = fixture.head.seq;
    const wrapsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsAfter[0]?.["n"])).toBe(0);
    const others = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id != ?",
      MEMBER,
    );
    expect(Number(others[0]?.["n"])).toBe(2 * (ALL_MEMBERS.length - 1));

    const events = await readAuditEvents(projectId);
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted).toHaveLength(2);
    for (const event of deleted) {
      expect(event["actor_type"]).toBe("system");
      expect(event["target_user_id"]).toBe(MEMBER);
      expect(JSON.parse(String(event["payload"])) as Record<string, unknown>).toEqual({
        cause: "member-readded",
        triggerChainSeq: readdSeq,
      });
    }
  });

  it("a re-add under the same key sweeps nothing (the existing wraps return to live use as-is)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await removeMember(READER);
    await readdWithSameKeys(READER, "reader");
    const wraps = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      READER,
    );
    expect(Number(wraps[0]?.["n"])).toBe(1);
    const events = await readAuditEvents(projectId);
    expect(events.filter((event) => event["event"] === "dek.deleted")).toHaveLength(0);
  });
});

interface WireHistoryEntry {
  readonly version: number;
  readonly epoch: number;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
  readonly pushedAtMs: number;
  readonly sameValueAs?: number;
  readonly flagsIfCurrent: number;
}

async function readHistory(asUserId: string = READER): Promise<readonly WireHistoryEntry[]> {
  const response = await requestJson(
    "GET",
    `/environments/${ENV}/variables/${VAR}/versions`,
    token(asUserId),
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    variableId: string;
    versions: readonly WireHistoryEntry[];
  };
  expect(body.variableId).toBe(VAR);
  return body.versions;
}

const varReadCount = async (): Promise<number> =>
  (await readAuditEvents(projectId)).filter((event) => event["event"] === "var.read").length;

describe("value history and rollback (AUTH_SPEC §12-5 / §12-7, AUDIT_SPEC §4.1-5 — VH)", () => {
  it("a rollback to a value the subject could read re-opens a resolved flag, a later fresh push resolves it again, and a rollback among post-rotation values changes nothing", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    const dek2 = await rotateTo(2, [OWNER, READER]);
    const push = (input: {
      version: number;
      prev: WireEncryptedPayload;
      writer?: string;
      sameValueAs?: number;
    }) =>
      valueSignedBytesHashOf(input.prev, input.writer ?? OWNER).then((prevValueSigHashHex) =>
        pushNextVersion({
          dek: dek2,
          version: input.version,
          epoch: 2,
          prevValueSigHashHex,
          ...(input.sameValueAs === undefined ? {} : { sameValueAs: input.sameValueAs }),
        }),
      );
    const v2 = await push({ version: 2, prev: v1, writer: MEMBER, sameValueAs: 1 });
    const v3 = await push({ version: 3, prev: v2 });
    expect(await readFlags()).toHaveLength(0);

    const v4 = await push({ version: 4, prev: v3, sameValueAs: 2 });
    const reopened = await readFlags();
    expect(reopened).toHaveLength(1);
    expect(reopened[0]).toMatchObject({ variableId: VAR, reopenedByVersion: 4 });

    const v5 = await push({ version: 5, prev: v4, sameValueAs: 4 });
    expect(await readFlags()).toEqual([expect.objectContaining({ reopenedByVersion: 4 })]);

    const readsBefore = await varReadCount();
    const history = await readHistory();
    expect(await varReadCount()).toBe(readsBefore);
    expect(
      history.map(({ version, epoch, sameValueAs, flagsIfCurrent }) => ({
        version,
        epoch,
        sameValueAs,
        flagsIfCurrent,
      })),
    ).toEqual([
      { version: 1, epoch: 1, sameValueAs: undefined, flagsIfCurrent: 1 },
      { version: 2, epoch: 2, sameValueAs: 1, flagsIfCurrent: 1 },
      { version: 3, epoch: 2, sameValueAs: undefined, flagsIfCurrent: 0 },
      { version: 4, epoch: 2, sameValueAs: 2, flagsIfCurrent: 1 },
      { version: 5, epoch: 2, sameValueAs: 4, flagsIfCurrent: 1 },
    ]);
    expect(history[0]).toMatchObject({ writerUserId: MEMBER });
    expect(history[4]).toMatchObject({ writerUserId: OWNER });
    expect(history.every((entry) => entry.pushedAtMs > 0)).toBe(true);

    const v6 = await push({ version: 6, prev: v5, sameValueAs: 3 });
    expect(await readFlags()).toHaveLength(0);
    const v7 = await push({ version: 7, prev: v6, sameValueAs: 1 });
    expect(await readFlags()).toEqual([expect.objectContaining({ reopenedByVersion: 7 })]);
    await push({ version: 8, prev: v7 });
    expect(await readFlags()).toHaveLength(0);
  });

  it("a dismissal covers only the flags effective at the time: a dismissed flag stays dismissed, a resolved one can still re-open", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    const dek2 = await rotateTo(2, [OWNER, READER]);
    const v2 = await pushNextVersion({
      dek: dek2,
      version: 2,
      epoch: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
    });
    expect(await readFlags()).toHaveLength(0);
    await removeMember(READER);
    expect(await readFlags(OWNER)).toEqual([expect.objectContaining({ targetUserId: READER })]);
    const dismissed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    expect(await readFlags(OWNER)).toHaveLength(0);
    const dek3 = await rotateTo(3, [OWNER]);
    await pushNextVersion({
      dek: dek3,
      version: 3,
      epoch: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, OWNER),
      sameValueAs: 1,
    });
    expect(await readFlags(OWNER)).toEqual([
      expect.objectContaining({ targetUserId: MEMBER, reopenedByVersion: 3 }),
    ]);
    expect((await readHistory(OWNER)).map((entry) => entry.flagsIfCurrent)).toEqual([1, 0, 1]);
  });

  it("two variables flagged in one aggregate row keep independent per-variable history (§3.3 Sc-5 / §12-7)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-api-key", "API_KEY", "sk-alpha");
    await pullAs(MEMBER);
    await removeMember(MEMBER);
    const recommended = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "rotation.recommended",
    );
    expect(recommended).toHaveLength(1);
    const apiKeyHistory = async (): Promise<readonly WireHistoryEntry[]> => {
      const response = await requestJson(
        "GET",
        `/environments/${ENV}/variables/var-api-key/versions`,
        token(OWNER),
      );
      expect(response.status).toBe(200);
      return ((await response.json()) as { versions: readonly WireHistoryEntry[] }).versions;
    };
    expect((await readHistory(OWNER)).at(-1)?.flagsIfCurrent).toBe(1);
    expect((await apiKeyHistory()).at(-1)?.flagsIfCurrent).toBe(1);
    const dek2 = await rotateTo(2, [OWNER, READER]);
    await pushNextVersion({
      dek: dek2,
      version: 2,
      epoch: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
    });
    expect((await readHistory(OWNER)).at(-1)?.flagsIfCurrent).toBe(0);
    expect((await apiKeyHistory()).at(-1)?.flagsIfCurrent).toBe(1);
  });

  it("sameValueAs must name an earlier version (422 payload-mismatch — §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const value = await encryptValue(
      dek,
      {
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: 1,
        variableId: testVariableId(VAR),
        version: 2,
      },
      "value-v2",
      {
        writerUserId: OWNER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(OWNER),
      { value, sameValueAs: 2 },
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ field: "sameValueAs" });
    expect((await readHistory()).map((entry) => entry.version)).toEqual([1]);
  });

  it("the version value range returns ascending payloads from fromVersion with one var.read enumerating each, and refuses out-of-range starts", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const v2 = await pushNextVersion({
      dek,
      version: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
    });
    await pushNextVersion({
      dek,
      version: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, OWNER),
    });
    const readsBefore = await varReadCount();
    const response = await requestJson(
      "GET",
      `/environments/${ENV}/variables/${VAR}/versions/values?fromVersion=2`,
      token(READER),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      variableId: string;
      latestVersion: number;
      values: readonly WireEncryptedPayload[];
    };
    expect(body.latestVersion).toBe(3);
    expect(body.values.map((value) => value.aad.version)).toEqual([2, 3]);
    expect(body.values[0]).toMatchObject({
      ciphertextHex: v2.ciphertextHex,
      signatureHex: v2.signatureHex,
      writerUserId: OWNER,
    });
    const reads = (await readAuditEvents(projectId)).filter(
      (event) => event["event"] === "var.read",
    );
    expect(reads).toHaveLength(readsBefore + 1);
    expect(JSON.parse(String(reads.at(-1)?.["payload"])) as unknown).toMatchObject({
      variables: [
        { variableId: VAR, epoch: 1, version: 2 },
        { variableId: VAR, epoch: 1, version: 3 },
      ],
    });

    for (const fromVersion of [4, 0]) {
      const refused = await requestJson(
        "GET",
        `/environments/${ENV}/variables/${VAR}/versions/values?fromVersion=${fromVersion}`,
        token(READER),
      );
      expect(refused.status).toBe(fromVersion === 0 ? 400 : 422);
    }
    const stranger = await requestJson(
      "GET",
      `/environments/${ENV}/variables/${VAR}/versions/values?fromVersion=1`,
      token(STRANGER),
    );
    expect(stranger.status).toBe(404);
  });
});

describe("the value range's ciphertext byte budget (§12-7 — VH)", () => {
  const row = (version: number, bytes: number) => ({
    variableId: testVariableId(VAR),
    version,
    suite: "maruhi/v1" as const,
    epoch: 1,
    nonceHex: "00".repeat(12),
    ciphertextHex: "ab".repeat(bytes),
    prevValueSigHashHex: "",
    chainHeadHashHex: "00".repeat(32),
    chainHeadSeq: 1,
    signatureHex: "00".repeat(64),
    writerUserId: OWNER,
    writerKeyFingerprintHex: testKeyFingerprintHex("00".repeat(16)),
  });

  it("stops before the version that would exceed the budget, and always keeps the first", () => {
    const big = 64 * 1024;
    const rows = Array.from({ length: 30 }, (_, index) => row(index + 1, big));
    const page = withinByteBudget(rows);
    expect(page).toHaveLength(Math.floor(MAX_VERSION_VALUES_PAGE_BYTES / big));
    expect(page.map((value) => value.version)).toEqual(
      Array.from({ length: page.length }, (_, index) => index + 1),
    );
    expect(withinByteBudget([row(1, MAX_VERSION_VALUES_PAGE_BYTES + 1)])).toHaveLength(1);
    expect(
      withinByteBudget(rows.slice(0, 3).map((value) => ({ ...value, ciphertextHex: "ab" }))),
    ).toHaveLength(3);
  });
});
