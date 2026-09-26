// Integration tests for the data-plane API (AUTH_SPEC §12) — DEK
// distribution, backfill for new members, and the repair path
// (AUTH_SPEC §12-6 / CRYPTO_SPEC §7).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.
//
// How the suite is split (for the split's motivation see the top of
// support/membership-scenario.ts):
// - This file: DEK distribution and the backfill / repair paths for new members
// - data-dek-signature.test.ts: the registration signature on DEK wraps
//   (§12-6 / CRYPTO_SPEC §5.1)
// - data-dek-server.test.ts: recipient class server (§12-6 / CRYPTO_SPEC
//   §9) and expectedWrapRecipientCount

import type { TokenScope } from "@maruhi/core";
import {
  decryptVariable,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  unwrapDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { MAX_DEK_WRAPS_PER_REQUEST } from "../src/policy.ts";
import { bearer, cliToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  digestOf,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  unwrapAndDecrypt,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
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
    // There are 3 recipients in total, but the response contains only the caller's
    expect(rows[0]?.["n"]).toBe(3);
  });

  it("backfills historical epoch DEKs for a newly added member, who can then decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // Add a new member (real keys generated at test time) to the chain via add_member
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

    // The inviter (owner) wraps the existing epoch's DEK for the new member and registers it (§7)
    const backfill = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: STRANGER,
      recipientEncPubHex: encPubHex,
      signerUserId: OWNER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [backfill],
    });
    expect(registered.status).toBe(204);

    // The new member can pull → decrypt with their own key
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
      context: { projectId, environmentId: ENV, epoch: 1, recipientUserId: STRANGER },
    });
    if (!unwrapped.ok) throw new Error("unwrap failed");
    const decrypted = await decryptVariable({
      dek: unwrapped.value,
      context: pulled.value.aad,
      nonce: hexBytes(pulled.value.nonceHex),
      ciphertext: hexBytes(pulled.value.ciphertextHex),
    });
    if (!decrypted.ok) throw new Error("decrypt failed");
    expect(new TextDecoder().decode(decrypted.value)).toBe("postgres://alpha");
  });

  it("rejects session-principal data writes uniformly (the §5 capability restriction)", async () => {
    const session = await loginSession(9001);
    const dek = makeDek();
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
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const statement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: ENV,
      name: "App",
      head: fixture.head,
    });
    // The manifest bundled into the creation composite (manifestVersion 1, empty variable set, epoch 1 — §12-4)
    const manifest = await signEnvManifestAs(OWNER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // The boundary checkpoint (H+2 — mandatory bundling per §12-4)
    const { entry: checkpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actorUserId: OWNER,
      operation: checkpointOperation({
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
    // Environment creation (§12-4) is on §5's explicit-deny surface (all
    // environment / variable mutations): uniformly 403 session-not-allowed
    // regardless of the CSRF header's presence (capability judgment comes
    // first)
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
    // The same body is accepted for a token principal (proving the rejection stems from the session principal)
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

    // The owner (admin scope × chain role owner ≥ admin) deletes the READER-directed wrap
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
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

    // Re-register the correct wrap via the shortfall-append path (§12-6) → READER can decrypt again
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
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
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("requires admin token scope and chain role admin (§12-3: same level as environment deletion)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // A member's default PAT has admin scope but chain role member → 403
    const asMember = await requestJson("DELETE", `/environments/${ENV}/deks`, token(MEMBER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(asMember.status).toBe(403);
    expect(((await asMember.json()) as { reason: string }).reason).toBe("insufficient-role");
    // Even the owner with a write token scope gets a 403 (insufficient-permission)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await cliToken(9001, writeScope);
    const scoped = await requestJson("DELETE", `/environments/${ENV}/deks`, ownerWrite, {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(scoped.status).toBe(403);
    expect(((await scoped.json()) as { reason: string }).reason).toBe("insufficient-permission");
    // The project itself is hidden from non-members (404 — §11-2)
    const concealed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(STRANGER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(concealed.status).toBe(404);
    expect(((await concealed.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects missing tuples with 404 atomically and duplicate refs with 422", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // The first ref exists, the second does not → 404 (DekWrapNotFound), and nothing is deleted
    const partial = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: "user-nobody-0404" },
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
    // A rejected deletion leaves no audit row (dek.deleted) at all (separation of verification and writing)
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(audits[0]?.["n"]).toBe(0);
    // Listing the same tuple twice is a 422 (duplicate-recipient)
    const duplicated = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: READER },
      ],
    });
    expect(duplicated.status).toBe(422);
    expect(((await duplicated.json()) as { reason: string }).reason).toBe("duplicate-recipient");
  });

  it("treats re-registration after a full epoch deletion as an initial registration (§12-6)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Delete all epoch-1 wraps → re-registration requires a complete match as an initial registration
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const partial = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek,
          recipientUserId: OWNER,
          signerUserId: MEMBER,
        }),
      ],
    });
    expect(partial.status).toBe(422);
    expect(((await partial.json()) as { reason: string }).reason).toBe("recipient-missing");
    // With the complete set it is accepted, and the recipients can decrypt again
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
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("rejects deletion requests for missing environments, empty lists and oversized lists", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // An empty list is a 400 (Schema — destructive call shapes leaving zero audit trace are not allowed — §12-6)
    const empty = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [],
    });
    expect(empty.status).toBe(400);
    // The count cap is the same MAX_DEK_WRAPS_PER_REQUEST as the registration side (judged before existence checks)
    const oversized = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
        epoch: 1,
        recipientUserId: `u${index}`,
      })),
    });
    expect(oversized.status).toBe(422);
    await expect(oversized.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
    // Deletion against a tombstoned environment (wraps are physically deleted) is a 404 EnvironmentNotFound
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);
    const gone = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(gone.status).toBe(404);
    // EnvironmentNotFound({environmentId}), not DekWrapNotFound({epoch, recipientUserId})
    const goneBody = (await gone.json()) as { environmentId?: string; epoch?: number };
    expect(goneBody.environmentId).toBe(ENV);
    expect(goneBody.epoch).toBeUndefined();
  });
});
