// Integration tests for the data-plane API (AUTH_SPEC §12) — recipient
// class server (AUTH_SPEC §12-6 / CRYPTO_SPEC §9) and
// expectedWrapRecipientCount.
// See the top of data-dek.test.ts for how the suite is split.

import type { ChainState } from "@maruhi/crypto";
import {
  computeServerKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { expectedWrapRecipientCount } from "../src/dek-wraps.ts";
import {
  commitmentOf,
  hexBytes,
  makeDek,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
} from "./support/data-crypto.ts";
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

// The deployment's server enc public key (a dummy — an X25519 public key
// is formally valid as any 32 bytes; the server cannot verify a wrap's
// contents, so acceptance is judged on identification and signature only)
const SERVER_ENC_PUB_HEX = "5a".repeat(32);

async function serverFingerprintHex(encPubHex = SERVER_ENC_PUB_HEX): Promise<string> {
  const fp = await computeServerKeyFingerprint(hexBytes(encPubHex));
  if (!fp.ok) throw new Error("server fingerprint failed");
  return encodeHex(fp.value);
}

describe("recipient class server (AUTH_SPEC §12-6 / CRYPTO_SPEC §9)", () => {
  /** The owner appends a grant_server (the generic chain API — an admin op of AUTH_SPEC §6). */
  async function grantServer(scope: readonly string[]): Promise<string> {
    const fpHex = await serverFingerprintHex();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: SERVER_ENC_PUB_HEX,
        serverKeyFingerprintHex: fpHex,
        scopeEnvironmentIds: scope,
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
    // Establish epochs 1 / 2 before the grant (the complete set is
    // members only) → grant → the owner bulk-registers server-directed
    // wraps for every in-scope epoch via the append path
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

    // The stored rows are recipient_class = 'server' with the server-key FP in the identifier column
    const rows = await queryProjectDo(
      projectId,
      "SELECT epoch, recipient_user_id FROM dek_wraps WHERE environment_id = ? AND recipient_class = 'server' ORDER BY epoch",
      ENV,
    );
    expect(rows.map((row) => [row["epoch"], row["recipient_user_id"]])).toEqual([
      [1, fpHex],
      [2, fpHex],
    ]);

    // dek.registered is one row per recipient; a server row carries the
    // FP in target_key_fingerprint (never mix a key identifier into the
    // user_id column — AUDIT_SPEC §3.3 / §2)
    const events = await queryProjectDo(
      projectId,
      "SELECT epoch, target_user_id, target_key_fingerprint, actor_key_fingerprint FROM audit_events WHERE event = 'dek.registered' AND target_key_fingerprint IS NOT NULL ORDER BY epoch",
    );
    expect(events.length).toBe(2);
    expect(events[0]?.["target_user_id"]).toBeNull();
    expect(events[0]?.["target_key_fingerprint"]).toBe(fpHex);
    expect(events[0]?.["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    // No server row leaks into distribution (listMine) (distribution is to oneself only — §12-6)
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
    // An environment created after the grant is out of scope, so the composite's complete set is members only (§12-4)
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
    const fpHex = await serverFingerprintHex(); // no grant is appended
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-not-granted");
  });

  it("rejects a server wrap whose enc pub differs from the grant with 422 (recipient-key-mismatch)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    // The FP matches the grant but the enc public key differs (both FP + enc pub must match — §12-6)
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
    // A complete set missing the server-key direction is a 422 recipient-missing
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

    // A complete set including the server-key direction is accepted (signed by the rotation's executor — §7)
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

  it("keeps cross-class recipients with distinct keys as separate slots, and rejects the same (id, key) pair with 422 duplicate-recipient", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);

    // add_member's target user_id is intentionally a free-form string
    // with no existence check (AUTH_SPEC §11-1), so an admin can add a
    // member whose "user_id = the server-key FP of a valid grant" to the
    // chain. The stored row's primary key is the device axis
    // (environment, epoch, recipient_user_id, recipient_enc_pub_hex —
    // 2026-09-19 DK K3), so with different keys, both the fpHex-directed
    // wrap as a member and the fpHex-directed wrap as a server can be
    // written to separate slots (design notes §8 K3-4, second round)
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const sockEncPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sockSigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: fpHex,
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

    // The same id **and the same key** (the member's enc public key =
    // the server key) is still one slot: the expected count is
    // deduplicated at the stored-key granularity, and sending both-class
    // wraps falls over at the pre-acceptance check with 422
    // (duplicate-recipient) (letting it through the acceptance stage
    // would hit a primary-key violation in the write phase = defect
    // [500])
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: fpHex },
    });
    const sameKeySigPair = await generateSigningKeyPair();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: fpHex,
        encPubHex: SERVER_ENC_PUB_HEX,
        sigPubHex: encodeHex(await exportSigningPublicKey(sameKeySigPair.publicKey)),
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const dek3 = makeDek();
    const memberWraps3 = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 3,
      dek: dek3,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const sameKeyWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 3,
      dek: dek3,
      recipientUserId: fpHex,
      recipientEncPubHex: SERVER_ENC_PUB_HEX,
      signerUserId: MEMBER,
    });
    const collided = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks: [
        ...memberWraps3,
        sameKeyWrap,
        await serverWrap({ epoch: 3, dek: dek3, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 3, dek3),
      actorUserId: MEMBER,
    });
    expect(collided.status).toBe(422);
    const body = (await collided.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("duplicate-recipient");
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = 3",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(0);

    // Operational recovery: remove_member on the colliding member makes
    // the complete set satisfiable again, and the rotation goes through
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: fpHex },
    });
    const recovered = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks: [
        ...memberWraps3,
        await serverWrap({ epoch: 3, dek: dek3, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 3, dek3),
      actorUserId: MEMBER,
    });
    expect(recovered.status).toBe(200);
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
      wraps: [{ epoch: 1, recipientClass: "server", recipientUserId: fpHex }],
    });
    expect(removed.status).toBe(204);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT target_user_id, target_key_fingerprint FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted.length).toBe(1);
    expect(deleted[0]?.["target_user_id"]).toBeNull();
    expect(deleted[0]?.["target_key_fingerprint"]).toBe(fpHex);

    // Re-registration via the append path (not a first-time complete-match since the epoch still has member-directed wraps)
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
    // A deletion that points at a member wrap as class server: it
    // mismatches the stored row's class = 404. If passed through, the
    // member's ULID would land on the target_key_fingerprint column and
    // this deletion would vanish from the (target_user_id, seq) index
    // (AUDIT_SPEC §1-2)
    const crossClass = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientClass: "server", recipientUserId: OWNER }],
    });
    expect(crossClass.status).toBe(404);
    expect(((await crossClass.json()) as Record<string, unknown>)["_tag"]).toBe("DekWrapNotFound");

    // The reverse direction: deleting a server wrap by pointing at it as class member (the default when omitted) is also a 404
    const fpHex = await grantServer([ENV]);
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [await serverWrap({ epoch: 1, dek: makeDek(), fpHex })],
    });
    expect(registered.status).toBe(204);
    const reverse = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: fpHex }],
    });
    expect(reverse.status).toBe(404);

    // Neither attempt left a deletion or an audit row (the verification phase rejects the whole request)
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
    // Pointing at the same (epoch, recipient) as both member and server
    // classes: duplicate detection passes on the class-including key, but
    // the server side mismatches the stored row = 404, rejecting the
    // whole request
    const response = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: OWNER },
        { epoch: 1, recipientClass: "server", recipientUserId: OWNER },
      ],
    });
    expect(response.status).toBe(404);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted[0]?.["n"]).toBe(0);
  });
});

const memberOf = (userId: string) =>
  [
    userId,
    {
      userId,
      role: "member",
      scope: { kind: "all" },
      // One initial key = one device (the cap is structurally (owner, all) — CRYPTO_SPEC §6.2 DK)
      devices: new Map([
        [
          "33".repeat(16),
          {
            keyFingerprintHex: "33".repeat(16),
            encPubHex: "11".repeat(32),
            sigPubHex: "22".repeat(32),
            roleCap: "owner" as const,
            scope: { kind: "all" as const },
            addedSeq: 1,
          },
        ],
      ]),
    },
  ] as const;
const grantOf = (
  fingerprintHex: string,
  scope: readonly string[],
  serverEncPubHex: string = "44".repeat(32),
) =>
  [
    fingerprintHex,
    {
      serverKeyFingerprintHex: fingerprintHex,
      serverEncPubHex,
      grantSeq: 1,
      scopeEnvironmentIds: scope,
      leasePolicy: [],
    },
  ] as const;

describe("expectedWrapRecipientCount", () => {
  it("counts the union deduplicated at the (id, key) stored-key granularity (the device axis — K3)", () => {
    // add_member's target user_id is a free-form string with no existence
    // check (AUTH_SPEC §11-1), so a member with the same string as the
    // server-key FP can be created. The stored key is the device axis
    // (id, enc public key), so different keys are separate slots (counted
    // as 2); the same id and same key is one slot — the expected count
    // must be computed at this granularity or the complete-set check
    // fails permanently
    const collidingFp = "ab".repeat(16);
    const otherFp = "cd".repeat(16);
    const state: ChainState = {
      members: new Map([memberOf("user-1"), memberOf(collidingFp)]),
      serverGrants: new Map([
        grantOf(collidingFp, ["env-a"]),
        grantOf(otherFp, ["env-a", "env-b"]),
      ]),
      environments: new Map(),
      checkpoints: new Map(),
      approvalPolicy: null,
      pendingProposals: new Map(),
      headSeq: 1,
      headHashHex: "00".repeat(32),
    };
    // env-a: {user-1, collidingFp (member key), collidingFp (server key), otherFp} — 4 slots
    expect(expectedWrapRecipientCount(state, "env-a")).toBe(4);
    // env-b: the only in-scope grant is otherFp
    expect(expectedWrapRecipientCount(state, "env-b")).toBe(3);
    // Out-of-scope environments are members only
    expect(expectedWrapRecipientCount(state, "env-c")).toBe(2);

    // The same id and same key (the member's enc public key = the server key) is one slot
    const sameKey: ChainState = {
      ...state,
      serverGrants: new Map([grantOf(collidingFp, ["env-a"], "11".repeat(32))]),
    };
    expect(expectedWrapRecipientCount(sameKey, "env-a")).toBe(2);
  });
});
