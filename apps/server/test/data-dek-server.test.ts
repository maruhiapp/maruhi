import type { ChainState, KeyFingerprintHex } from "@maruhi/crypto";
import {
  computeServerKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { testKeyFingerprintHex, testUserId } from "@maruhi/crypto/test-support";
import { describe, expect, it } from "vite-plus/test";

import { expectedWrapRecipientCount } from "../src/dek-wraps.ts";
import {
  commitmentOf,
  hexBytes,
  makeDek,
  signEntryAt,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
} from "./support/data-crypto.ts";
import { testEnvironmentId } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

const SERVER_ENC_PUB_HEX = "5a".repeat(32);

async function serverFingerprintHex(encPubHex = SERVER_ENC_PUB_HEX): Promise<KeyFingerprintHex> {
  const fp = await computeServerKeyFingerprint(hexBytes(encPubHex));
  if (!fp.ok) throw new Error("server fingerprint failed");
  return testKeyFingerprintHex(encodeHex(fp.value));
}

describe("recipient class server (AUTH_SPEC §12-6 / CRYPTO_SPEC §9)", () => {
  async function grantServer(scope: readonly string[]): Promise<KeyFingerprintHex> {
    const fpHex = await serverFingerprintHex();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: SERVER_ENC_PUB_HEX,
        serverKeyFingerprintHex: fpHex,
        scopeEnvironmentIds: scope.map(testEnvironmentId),
        leasePolicy: [],
      },
    });
    return fpHex;
  }

  async function serverWrap(input: {
    readonly epoch: number;
    readonly dek: Uint8Array;
    readonly fpHex: string;
    readonly encPubHex?: string;
    readonly signerUserId?: string;
    readonly environmentId?: string;
  }) {
    return wrapDekToServer({
      projectId,
      environmentId: input.environmentId ?? ENV,
      epoch: input.epoch,
      dek: input.dek,
      serverKeyFingerprintHex: input.fpHex,
      serverEncPubHex: input.encPubHex ?? SERVER_ENC_PUB_HEX,
      signerUserId: input.signerUserId ?? OWNER,
    });
  }

  it("backfills server wraps for all existing epochs right after the grant (the §12-6 post-grant backfill)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const fpHex = await grantServer([ENV]);
    const wraps = [
      await serverWrap({ epoch: 1, dek: dek1, fpHex }),
      await serverWrap({ epoch: 2, dek: dek2, fpHex }),
    ];
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: wraps,
    });
    expect(response.status).toBe(204);

    const rows = await queryProjectDo(
      projectId,
      "SELECT epoch, recipient_user_id FROM dek_wraps WHERE environment_id = ? AND recipient_class = 'server' ORDER BY epoch",
      ENV,
    );
    expect(rows.map((row) => [row["epoch"], row["recipient_user_id"]])).toEqual([
      [1, fpHex],
      [2, fpHex],
    ]);

    const events = await queryProjectDo(
      projectId,
      "SELECT epoch, target_user_id, target_key_fingerprint, actor_key_fingerprint FROM audit_events WHERE event = 'dek.registered' AND target_key_fingerprint IS NOT NULL ORDER BY epoch",
    );
    expect(events.length).toBe(2);
    expect(events[0]?.["target_user_id"]).toBeNull();
    expect(events[0]?.["target_key_fingerprint"]).toBe(fpHex);
    expect(events[0]?.["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(OWNER));
    const body = (await mine.json()) as { deks: readonly { epoch: number }[] };
    expect(body.deks.length).toBe(2);
  });

  it("rejects a duplicate server wrap with 409 (the no-overwrite rule is class-agnostic)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const first = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(first.status).toBe(204);
    const second = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(second.status).toBe(409);
    const body = (await second.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("DekWrapExists");
  });

  it("rejects a server wrap for an out-of-scope environment with 422 (scope-out-of-range)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const outDek = await createEnvironmentOk(fixture, "env-out-0002", "Out");
    const wrap = await serverWrap({
      environmentId: "env-out-0002",
      epoch: 1,
      dek: outDek,
      fpHex,
    });
    const response = await requestJson("POST", `/environments/env-out-0002/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("scope-out-of-range");
  });

  it("rejects a server wrap without a matching grant with 422 (recipient-not-granted)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await serverFingerprintHex();
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-not-granted");
  });

  it("refuses a server-class wrap whose recipient is not fingerprint-shaped at decode (400)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [{ ...wrap, recipientUserId: OWNER }],
    });
    expect(response.status).toBe(400);
  });

  it("rejects a server wrap whose enc pub differs from the grant with 422 (recipient-key-mismatch)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({
      epoch: 1,
      dek: dek1,
      fpHex,
      encPubHex: "6b".repeat(32),
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-key-mismatch");
  });

  it("requires the server key in the composite complete set once granted (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const dek2 = makeDek();
    const memberWraps = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const missing = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: memberWraps,
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(missing.status).toBe(422);
    const body = (await missing.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-missing");

    const full = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: [
        ...memberWraps,
        await serverWrap({ epoch: 2, dek: dek2, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(full.status).toBe(200);
  });

  it("keeps cross-class recipients with distinct keys as separate slots, and refuses a member holding the grant's key at the chain layer (422 duplicate-member-key)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);

    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const sockEncPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sockSigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: testUserId(fpHex),
        encPubHex: sockEncPubHex,
        sigPubHex: sockSigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    const dek2 = makeDek();
    const memberWraps = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const sockWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserId: fpHex,
      recipientEncPubHex: sockEncPubHex,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: [
        ...memberWraps,
        sockWrap,
        await serverWrap({ epoch: 2, dek: dek2, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(response.status).toBe(200);
    const slots = await queryProjectDo(
      projectId,
      "SELECT recipient_class, recipient_enc_pub_hex FROM dek_wraps WHERE environment_id = ? AND epoch = 2 AND recipient_user_id = ? ORDER BY recipient_class",
      ENV,
      fpHex,
    );
    expect(slots).toEqual([
      { recipient_class: "member", recipient_enc_pub_hex: sockEncPubHex },
      { recipient_class: "server", recipient_enc_pub_hex: SERVER_ENC_PUB_HEX },
    ]);

    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: testUserId(fpHex) },
    });
    const sameKeySigPair = await generateSigningKeyPair();
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: testUserId(fpHex),
          encPubHex: SERVER_ENC_PUB_HEX,
          sigPubHex: encodeHex(await exportSigningPublicKey(sameKeySigPair.publicKey)),
          role: "member",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
    });
    const refused = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
    });
    expect(refused.status).toBe(422);
    const body = (await refused.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-member-key");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("repairs a server wrap through delete → re-register (the §12-6 repair path)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    expect(
      (
        await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
          deks: [wrap],
        })
      ).status,
    ).toBe(204);

    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "server",
          recipientUserId: fpHex,
          recipientEncPubHex: SERVER_ENC_PUB_HEX,
        },
      ],
    });
    expect(removed.status).toBe(204);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT target_user_id, target_key_fingerprint FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted.length).toBe(1);
    expect(deleted[0]?.["target_user_id"]).toBeNull();
    expect(deleted[0]?.["target_key_fingerprint"]).toBe(fpHex);

    const reRegistered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(reRegistered.status).toBe(204);
  });

  it("rejects a server wrap for a revoked grant with 422 (a revoked grant is not-granted)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: fpHex },
    });
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-not-granted");
  });

  it("rejects a wrap deletion whose recipientClass does not match the stored row (closing manipulation of the audit columns)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const crossClass = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "server",
          recipientUserId: OWNER,
          recipientEncPubHex: vectorKeyOf(OWNER).enc_pub_hex,
        },
      ],
    });
    expect(crossClass.status).toBe(400);

    const fpHex = await grantServer([ENV]);
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [await serverWrap({ epoch: 1, dek: makeDek(), fpHex })],
    });
    expect(registered.status).toBe(204);
    const reverse = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: fpHex,
          recipientEncPubHex: SERVER_ENC_PUB_HEX,
        },
      ],
    });
    expect(reverse.status).toBe(404);

    const deleted = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted[0]?.["n"]).toBe(0);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = 1",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(ALL_MEMBERS.length + 1);
  });

  it("rejects class-only-differing refs in one deletion request (never stack 2 audit rows on 1 row)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        {
          epoch: 1,
          recipientClass: "member",
          recipientUserId: OWNER,
          recipientEncPubHex: vectorKeyOf(OWNER).enc_pub_hex,
        },
        {
          epoch: 1,
          recipientClass: "server",
          recipientUserId: OWNER,
          recipientEncPubHex: vectorKeyOf(OWNER).enc_pub_hex,
        },
      ],
    });
    expect(response.status).toBe(400);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted[0]?.["n"]).toBe(0);
  });
});

const memberOf = (userId: string, encByte: string, sigByte: string) =>
  [
    testUserId(userId),
    {
      userId: testUserId(userId),
      role: "member",
      scope: { kind: "all" },
      devices: new Map([
        [
          `${encByte}${sigByte}`.repeat(8),
          {
            keyFingerprintHex: testKeyFingerprintHex(`${encByte}${sigByte}`.repeat(8)),
            encPubHex: encByte.repeat(32),
            sigPubHex: sigByte.repeat(32),
            roleCap: "owner" as const,
            scope: { kind: "all" as const },
            addedSeq: 1,
          },
        ],
      ]),
    },
  ] as const;
const grantOf = (fingerprintHex: string, scope: readonly string[], serverEncPubHex: string) =>
  [
    testKeyFingerprintHex(fingerprintHex),
    {
      serverKeyFingerprintHex: testKeyFingerprintHex(fingerprintHex),
      serverEncPubHex,
      grantSeq: 1,
      scopeEnvironmentIds: scope.map(testEnvironmentId),
      leasePolicy: [],
    },
  ] as const;

describe("expectedWrapRecipientCount", () => {
  it("counts a member named by a grant's FP and that grant as two slots (the (id, key) device axis — K3)", () => {
    const collidingFp = "ab".repeat(16);
    const otherFp = "cd".repeat(16);
    const state: ChainState = {
      members: new Map([memberOf("user-1", "11", "21"), memberOf(collidingFp, "12", "22")]),
      serverGrants: new Map([
        grantOf(collidingFp, ["env-a"], "44".repeat(32)),
        grantOf(otherFp, ["env-a", "env-b"], "45".repeat(32)),
      ]),
      environments: new Map(),
      checkpoints: new Map(),
      approvalPolicy: null,
      pendingProposals: new Map(),
      namedServerKeys: new Map([
        ["44".repeat(32), testKeyFingerprintHex(collidingFp)],
        ["45".repeat(32), testKeyFingerprintHex(otherFp)],
      ]),
      headSeq: 1,
      headHashHex: "00".repeat(32),
    };
    expect(expectedWrapRecipientCount(state, testEnvironmentId("env-a"))).toBe(4);
    expect(expectedWrapRecipientCount(state, testEnvironmentId("env-b"))).toBe(3);
    expect(expectedWrapRecipientCount(state, testEnvironmentId("env-c"))).toBe(2);
  });
});
