// Integration tests for the data-plane API (AUTH_SPEC §12) — the
// registration signature on DEK wraps (AUTH_SPEC §12-6 / CRYPTO_SPEC
// §5.1). See the top of data-dek.test.ts for how the suite is split.

import {
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  commitmentOf,
  makeDek,
  signEntryAt,
  signWrapAs,
  unwrapAndDecrypt,
  vectorKeyOf,
  verifyDistributedWrapSignature,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
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
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("the registration signature on DEK wraps (§12-6 / CRYPTO_SPEC §5.1)", () => {
  it("rejects wraps signed by someone other than the caller (422 signature-invalid, the registration API path)", async () => {
    // The registration API is only for repair re-registration and
    // backfill (§12-6). Via the repair path, delete all epoch-1 wraps and
    // have MEMBER carry in a complete set signed by OWNER → rejected
    // because it violates the strict equality of caller = signer.
    // Nothing is inserted and no audit row remains
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const auditsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const signedByOwner = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: signedByOwner,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1",
      ENV,
    );
    expect(rows.length).toBe(0);
    const auditsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(auditsAfter[0]?.["n"]).toBe(auditsBefore[0]?.["n"]);
  });

  it("rejects a transplanted signature on environment creation (422 signature-invalid, the bundled path)", async () => {
    // Even a correct signature by the same signer (OWNER) fails
    // verification when transplanted from a different wrap (a different
    // recipient), because the signed_bytes differ
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const [first, second, third] = deks;
    if (first === undefined || second === undefined || third === undefined) {
      throw new Error("missing wraps");
    }
    const transplanted = [first, { ...second, signatureHex: first.signatureHex }, third];
    const response = await createEnvironmentWith(fixture, ENV, "App", transplanted);
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // The environment is not created (signature verification precedes the write phase)
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [], schemaPolicy: "disabled" });
  });

  it("rejects wraps without a signature (400 Schema, both paths)", async () => {
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const stripped = deks.map(({ signatureHex: _signatureHex, ...rest }) => rest);
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const created = await requestJson("POST", "/environments", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
      deks: stripped,
    });
    expect(created.status).toBe(400);
    // The registration API path is also a 400 under the same Schema (WrappedDekSchema)
    await createEnvironmentOk(fixture, ENV, "App");
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: stripped,
    });
    expect(registered.status).toBe(400);
  });

  it("rejects malformed signatures with 400 (Schema: uppercase hex / bad length / non-hex)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const [wrap] = await wrapsFor(ENV, [OWNER], 1, MEMBER);
    if (wrap === undefined) throw new Error("missing wrap");
    for (const signatureHex of [
      wrap.signatureHex.toUpperCase(),
      wrap.signatureHex.slice(2),
      `zz${wrap.signatureHex.slice(2)}`,
    ]) {
      const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
        deks: [{ ...wrap, signatureHex }],
      });
      expect(response.status).toBe(400);
    }
  });

  it("rejects third-party re-submission into a deleted slot (signer mismatch)", async () => {
    // The scenario named in CRYPTO_SPEC §5.1: the path where a third
    // party re-submits "a wrap signed by someone else" into a deleted
    // slot is closed by signer mismatch.
    // The strongest form — "a sock account (STRANGER) reusing MEMBER's
    // whole key set" (key match, user_id mismatch) — cannot even be
    // established at chain append because of §6.2's member-key
    // uniqueness (pinned by the chain-level test below and the authz
    // vector loop in membership.test.ts). Rejecting a signature whose
    // signer_user_id alone differs while the key matches is pinned in
    // the crypto layer by the negative vector `transplant-signer`
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
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

    // STRANGER (properly made a member with their own keys) re-submits a
    // MEMBER-signed wrap verbatim → a 422 for violating the strict
    // equality of caller = signer (§12-6)
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: encodeHex(await exportEncryptionPublicKey(encPair.publicKey)),
        sigPubHex: encodeHex(await exportSigningPublicKey(sigPair.publicKey)),
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    const removedAgain = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removedAgain.status).toBe(204);
    const replayed = await requestJson("POST", `/environments/${ENV}/deks`, token(STRANGER), {
      deks: [reWrap],
    });
    expect(replayed.status).toBe(422);
    expect(((await replayed.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?",
      ENV,
      READER,
    );
    expect(rows.length).toBe(0);
  });

  it("rejects the key-reuse sock puppet at the chain layer (422 duplicate-member-key)", async () => {
    // "STRANGER's add_member reusing MEMBER's whole key set" is rejected
    // at chain-append time by §6.2's member-key uniqueness (a consensus
    // rule) — removing the root cause of re-attribution (defense in
    // depth). Coverage against the vector-fixed chain is carried by
    // membership.test.ts's authz loop (authz-add-member-duplicate-key
    // plus 2 more); here we pin that it also holds on the data-plane
    // fixture chain
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: STRANGER,
          encPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
          sigPubHex: vectorKeyOf(MEMBER).sig_pub_hex,
          role: "member",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
    });
    const response = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-member-key");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("accepts the original signer re-registering the identical wrap and signature (the counterpart of §5.1's semantics)", async () => {
    // A signature is attribution, not a freshness proof: after deletion,
    // re-registration by the original signer with identical content +
    // identical signature is valid (the positive side of a design with
    // no timestamps or nonces)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    // For the positive case, pass the wrapped DEK's own commitment
    const created = await createEnvironmentWith(
      fixture,
      ENV,
      "App",
      deks,
      await commitmentOf(projectId, ENV, 1, dek),
    );
    expect(created.status).toBe(200);
    const readerWrap = deks.find((wrap) => wrap.recipientUserId === READER);
    if (readerWrap === undefined) throw new Error("missing reader wrap");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const restored = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [readerWrap],
    });
    expect(restored.status).toBe(204);
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    const body = (await mine.json()) as { deks: { signatureHex: string }[] };
    expect(body.deks[0]?.signatureHex).toBe(readerWrap.signatureHex);
  });

  it("rejects an empty registration list with 400 (§12-6: the same discipline as an empty deletion list)", async () => {
    // An empty deks: [] has no meaningful use case as a call shape, and a
    // silent no-op (204) would hide a client bug (mistaking sending an
    // empty array for a completed registration), so it is rejected by the
    // same minItems-1 Schema validation as the deletion side's empty
    // wraps 400
    await createEnvironmentOk(fixture, ENV, "App");
    const before = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [],
    });
    expect(response.status).toBe(400);
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });

  it("distributes the signature and signer identity, verifiable client-side (§12-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const path of [`/environments/${ENV}/deks`, `/environments/${ENV}/pull`] as const) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        deks: {
          suite: string;
          epoch: number;
          encHex: string;
          ciphertextHex: string;
          signatureHex: string;
          signerUserId: string;
          signerKeyFingerprintHex: string;
        }[];
      };
      const wrap = body.deks[0];
      if (wrap === undefined) throw new Error("missing distributed wrap");
      expect(wrap.signerUserId).toBe(OWNER);
      expect(wrap.signerKeyFingerprintHex).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      // Client-side verification (CRYPTO_SPEC §5.1): verify with one's own coordinates + the signer's chain key
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(true);
      // Verification fails on forged coordinates (client-side transplant detection)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: "env-forged-0001",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(false);
      // Verification fails even if the server declares a forged signer
      // (signer_user_id is part of the signed data — CRYPTO_SPEC §5.1;
      // the integration-level counterpart of the transplant-signer vector)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap: { ...wrap, signerUserId: MEMBER },
        }),
      ).resolves.toBe(false);
    }
  });

  it("accepts a caller-signed poison wrap: a signature is attribution, not content verification (§5.1 semantics)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    // Even a fake whose contents cannot be decrypted is accepted as long
    // as the calling principal's (MEMBER's) signature is correct (the
    // server cannot verify a wrap's contents — E2EE). Attribution,
    // however, is pinned to MEMBER via the signature + the dek.registered
    // FP without trusting the server
    const poison = await signWrapAs(MEMBER, projectId, ENV, {
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: READER,
      recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [poison],
    });
    expect(registered.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]?.["signer_user_id"]).toBe(MEMBER);
  });

  it("attributes repair-path re-registration via the signer fingerprint (delete → signed re-register → cross-check)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // The admin (owner) deletes the READER-directed wrap as the hypothetical poison wrap → MEMBER re-registers with a self-signature
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
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

    // The stored row's signer is MEMBER (user_id + FP)
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id, signer_key_fingerprint FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]).toEqual({
      signer_user_id: MEMBER,
      signer_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });

    // Attribution can be cross-checked via the signer FP of
    // dek.registered (AUDIT_SPEC §3.3): in order, the initial
    // registration (bundled with environment creation = OWNER-signed) →
    // the re-registration (MEMBER-signed)
    const audits = await queryProjectDo(
      projectId,
      `SELECT actor_user_id, actor_key_fingerprint FROM audit_events
       WHERE event = 'dek.registered' AND target_user_id = ? ORDER BY seq`,
      READER,
    );
    expect(audits).toEqual([
      {
        actor_user_id: OWNER,
        actor_key_fingerprint: vectorKeyOf(OWNER).key_fingerprint_hex,
      },
      {
        actor_user_id: MEMBER,
        actor_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
      },
    ]);

    // READER can verify the re-registered wrap's signature before decrypting it
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: {
        suite: string;
        epoch: number;
        encHex: string;
        ciphertextHex: string;
        signatureHex: string;
        signerUserId: string;
      }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(wrap.signerUserId).toBe(MEMBER);
    await expect(
      verifyDistributedWrapSignature({
        projectId,
        environmentId: ENV,
        recipientUserId: READER,
        recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        wrap,
      }),
    ).resolves.toBe(true);
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
});
