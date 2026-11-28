import type { TokenScope } from "@maruhi/core";
import {
  decryptVariable,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateDek,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  unwrapDek,
} from "@maruhi/crypto";
import type { WireEncryptedPayload } from "@maruhi/test-kit";
import {
  checkpointOp,
  hexBytes,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signManifest,
  testEnvironmentId,
  testProjectId,
  testVariableId,
  unwrapAndDecrypt,
  valuesDigestOf,
  variablesDigestOf,
  wrapDekTo,
} from "@maruhi/test-kit";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { MAX_DEK_WRAPS_PER_REQUEST } from "../src/policy.ts";
import { bearer, cliToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import { identityOf, vectorKeyOf, wrapDekForAll } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("DEK distribution and backfill for new members (§12-6 / CRYPTO_SPEC §7)", () => {
  it("distributes only the caller's wraps", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { deks: { epoch: number }[] };
    expect(body.deks.length).toBe(1);
    expect(body.deks[0]?.epoch).toBe(1);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(3);
  });

  it("backfills historical epoch DEKs for a newly added member, who can then decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const encPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex,
        sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    const backfill = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipient: { userId: STRANGER, encPubHex },
      signer: identityOf(OWNER),
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [backfill],
    });
    expect(registered.status).toBe(204);

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(STRANGER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    const unwrapped = await unwrapDek({
      recipientKeyPair: encPair,
      wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
      context: {
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: 1,
        recipientUserId: STRANGER,
      },
    });
    if (!unwrapped.ok) throw new Error("unwrap failed");
    const decrypted = await decryptVariable({
      dek: unwrapped.value,
      context: {
        projectId: testProjectId(pulled.value.aad.projectId),
        environmentId: testEnvironmentId(pulled.value.aad.environmentId),
        epoch: pulled.value.aad.epoch,
        variableId: testVariableId(pulled.value.aad.variableId),
        version: pulled.value.aad.version,
      },
      nonce: hexBytes(pulled.value.nonceHex),
      ciphertext: hexBytes(pulled.value.ciphertextHex),
    });
    if (!decrypted.ok) throw new Error("decrypt failed");
    expect(new TextDecoder().decode(decrypted.value)).toBe("postgres://alpha");
  });

  it("rejects session-principal data writes uniformly (the §5 capability restriction)", async () => {
    const session = await loginSession(9001);
    const dek = generateDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const { entry, hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actor: identityOf(OWNER),
      operation: {
        op: "create_environment",
        payload: { environmentId: testEnvironmentId(ENV), dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const statement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: ENV,
      name: "App",
      head: fixture.head,
    });
    const manifest = await signManifest(identityOf(OWNER), projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await variablesDigestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const { entry: checkpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actor: identityOf(OWNER),
      operation: checkpointOp({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: await manifestSignedBytesHashOf(projectId, manifest, OWNER),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const body = JSON.stringify({
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement,
      deks,
      manifest,
      checkpoint,
    });
    const headers = sessionHeaders(session);
    const withoutCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, cookie: headers["cookie"] ?? "" },
      body,
    });
    expect(withoutCsrf.status).toBe(403);
    expect(((await withoutCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...headers },
      body,
    });
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const accepted = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token(OWNER)) },
      body,
    });
    expect(accepted.status).toBe(200);
  });
});

describe("the DEK-wrap repair path (§12-6: delete → re-register the shortfall)", () => {
  it("deletes a poisoned wrap as admin and restores it through the append path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(removed.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      "SELECT recipient_user_id FROM dek_wraps WHERE environment_id = ? ORDER BY recipient_user_id",
      ENV,
    );
    expect(rows.map((row) => row["recipient_user_id"])).toEqual([MEMBER, OWNER].toSorted());
    const emptied = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    await expect(emptied.json()).resolves.toEqual({ deks: [] });

    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipient: identityOf(READER),
      signer: identityOf(MEMBER),
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(registered.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    await expect(
      unwrapAndDecrypt({
        recipient: identityOf(READER),
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("requires admin token scope and chain role admin (§12-3: same level as environment deletion)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const asMember = await requestJson("DELETE", `/environments/${ENV}/deks`, token(MEMBER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(asMember.status).toBe(403);
    expect(((await asMember.json()) as { reason: string }).reason).toBe("insufficient-role");
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await cliToken(9001, writeScope);
    const scoped = await requestJson("DELETE", `/environments/${ENV}/deks`, ownerWrite, {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(scoped.status).toBe(403);
    expect(((await scoped.json()) as { reason: string }).reason).toBe("insufficient-permission");
    const concealed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(STRANGER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(concealed.status).toBe(404);
    expect(((await concealed.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects missing tuples with 404 atomically and duplicate refs with 422", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const partial = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: "user-nobody-0404",
          recipientEncPubHex: "ab".repeat(32),
        },
      ],
    });
    expect(partial.status).toBe(404);
    await expect(partial.json()).resolves.toMatchObject({
      epoch: 1,
      recipientUserId: "user-nobody-0404",
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(3);
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(audits[0]?.["n"]).toBe(0);
    const duplicated = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(duplicated.status).toBe(422);
    expect(((await duplicated.json()) as { reason: string }).reason).toBe("duplicate-recipient");
  });

  it("treats re-registration after a full epoch deletion as an initial registration (§12-6)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({
        epoch: 1,
        recipientClass: "member" as const,
        recipientUserId,
        recipientEncPubHex: vectorKeyOf(recipientUserId).enc_pub_hex,
      })),
    });
    expect(removed.status).toBe(204);
    const partial = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek,
          recipient: identityOf(OWNER),
          signer: identityOf(MEMBER),
        }),
      ],
    });
    expect(partial.status).toBe(422);
    expect(((await partial.json()) as { reason: string }).reason).toBe("recipient-missing");
    const complete = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 1,
        dek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(complete.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    await expect(
      unwrapAndDecrypt({
        recipient: identityOf(READER),
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("rejects deletion requests for missing environments, empty lists and oversized lists", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const empty = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [],
    });
    expect(empty.status).toBe(400);
    const oversized = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
        epoch: 1,
        recipientClass: "member",
        recipientUserId: `u${index}`,
        recipientEncPubHex: "ab".repeat(32),
      })),
    });
    expect(oversized.status).toBe(422);
    await expect(oversized.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);
    const gone = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        },
      ],
    });
    expect(gone.status).toBe(404);
    const goneBody = (await gone.json()) as { environmentId?: string; epoch?: number };
    expect(goneBody.environmentId).toBe(ENV);
    expect(goneBody.epoch).toBeUndefined();
  });
});
