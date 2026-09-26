// Integration tests for the data-plane API (AUTH_SPEC §12) —
// acceptance verification of value signatures (AUTH_SPEC §12-5 =
// CRYPTO_SPEC §4.1 / §6.4).
// Verifies the HttpApi via SELF and DO SQLite on @cloudflare/vitest-plugin
// (real workerd environment).
// The shared fixture and helpers live in support/data-scenario.ts.

import type { ChainEntry } from "@maruhi/crypto";
import {
  buildValueSignedBytes,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importSigningKeyPair,
  verifyChainWithHistory,
  verifyDistributedValue,
} from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  hexBytes,
  signEntryAt,
  signValueAs,
  valueSignedBytesHashOf,
  vectorKeyOf,
} from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fakePayload,
  fixture,
  hashOf,
  registerDataScenario,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** Check side-effect-freeness on rejection: variables, versions, latest, and audits do not change. */
async function expectNoVersionSideEffects(expectedVersions: readonly number[]): Promise<void> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT version FROM variable_versions WHERE environment_id = ? AND variable_id = ? ORDER BY version",
    ENV,
    VAR,
  );
  expect(rows.map((row) => row["version"])).toEqual([...expectedVersions]);
  const pushedAudits = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.version_pushed'",
  );
  expect(pushedAudits[0]?.["n"]).toBe(expectedVersions.length);
}

describe("acceptance verification of value signatures (§12-5 = CRYPTO_SPEC §4.1 / §6.4)", () => {
  it("rejects a value signed by someone other than the caller (422 signature-invalid)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER carries in a value correctly signed by OWNER → the
    // verification key is the calling principal's (MEMBER's)
    // acceptance-time chain key, so it fails (refusing to carry
    // someone else's signature)
    const ownerSigned = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
      {
        writerUserId: OWNER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: ownerSigned },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    await expectNoVersionSideEffects([1]);
  });

  it("rejects creation with a tampered signature and writes nothing (no bypassing verification via the create path)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const value = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 1 },
      "postgres://alpha",
      { writerUserId: MEMBER, head: fixture.head },
    );
    const flipped = `${value.signatureHex.slice(0, -2)}${
      value.signatureHex.endsWith("00") ? "01" : "00"
    }`;
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: { ...value, signatureHex: flipped },
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // No variable row, statement row, version row, or audit remains
    for (const table of ["variables", "variable_meta_statements"]) {
      const rows = await queryProjectDo(
        projectId,
        `SELECT 1 FROM ${table} WHERE environment_id = ? AND variable_id = ?`,
        ENV,
        VAR,
      );
      expect(rows.length).toBe(0);
    }
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event IN ('var.created', 'var.version_pushed')",
    );
    expect(audits[0]?.["n"]).toBe(0);
  });

  it("rejects unknown declared heads (422 chain-head-unknown): hash mismatch and future seq", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // An existent seq × mismatched hash (valid signature) — existence of the exact pair is the acceptance condition
    const mismatched = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: "cd".repeat(32),
        chainHeadHashHex: "ee".repeat(32),
        chainHeadSeq: fixture.head.seq,
      },
      { seq: fixture.head.seq, hashHex: "ee".repeat(32) },
    );
    const hashMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: mismatched },
    );
    expect(hashMismatch.status).toBe(422);
    expect(((await hashMismatch.json()) as { reason: string }).reason).toBe("chain-head-unknown");

    // A seq beyond the local chain (nonexistent on the server) is also chain-head-unknown
    const future = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: "cd".repeat(32),
        chainHeadHashHex: "ee".repeat(32),
        chainHeadSeq: fixture.head.seq + 5,
      },
      { seq: fixture.head.seq + 5, hashHex: "ee".repeat(32) },
    );
    const futureResponse = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: future },
    );
    expect(futureResponse.status).toBe(422);
    expect(((await futureResponse.json()) as { reason: string }).reason).toBe("chain-head-unknown");
    await expectNoVersionSideEffects([1]);
  });

  it("rejects heads whose head-time state mismatches (422 chain-head-state-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const prevHash = await valueSignedBytesHashOf(v1, MEMBER);
    const chain = await requestJson("GET", "/chain", token(READER));
    const entries = ((await chain.json()) as { entries: { seq: number }[] }).entries;
    expect(entries.length).toBe(fixture.head.seq);

    // (a) Declaring a head from before the writer became a member (seq 1 = genesis)
    const beforeMembership = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: prevHash,
        chainHeadHashHex: await hashOf(1),
        chainHeadSeq: 1,
      },
      { seq: 1, hashHex: await hashOf(1) },
    );
    const notMember = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: beforeMembership },
    );
    expect(notMember.status).toBe(422);
    expect(((await notMember.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // (b) Declaring a head from before the environment's creation
    // (base-chain seq 3) — forbids an implementation that backfills an
    // epoch-undefined head with a default (the second half of §12-5
    // item 4)
    const beforeCreate = await signValueAs(
      MEMBER,
      {
        suite: "maruhi/v1",
        aad: aadFor(1, 2),
        nonceHex: "00".repeat(12),
        ciphertextHex: "ab".repeat(48),
        prevValueSigHashHex: prevHash,
        chainHeadHashHex: await hashOf(3),
        chainHeadSeq: 3,
      },
      { seq: 3, hashHex: await hashOf(3) },
    );
    const envNotCreated = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: beforeCreate },
    );
    expect(envNotCreated.status).toBe(422);
    expect(((await envNotCreated.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("rejects prev-chain mismatches (422 chain-head-state-mismatch): wrong prev and non-empty v1 prev", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // version 2's prev disagrees with the stored version 1's
    // signed_bytes hash (the signature is valid — pinning that it is
    // not crushed into an Ed25519 failure)
    const wrongPrev = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2), { prevValueSigHashHex: "cd".repeat(32) }) },
    );
    expect(wrongPrev.status).toBe(422);
    expect(((await wrongPrev.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // A non-empty prev on version 1 (build the validly-signed shape
    // via the low-level API — signValue refuses to sign a binding
    // violation)
    const context = {
      suite: "maruhi/v1",
      projectId,
      environmentId: ENV,
      epoch: 1,
      variableId: "var-phantom-prev",
      version: 1,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(48),
      prevValueSigHashHex: "cd".repeat(32),
      writerUserId: MEMBER,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    };
    const keys = vectorKeyOf(MEMBER);
    const pairResult = await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    });
    if (!pairResult.ok) throw new Error("key import failed");
    const rawSignature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        pairResult.value.privateKey,
        buildValueSignedBytes(context) as BufferSource,
      ),
    );
    const v1NonEmptyPrev = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        statement: await variableStatementFor(MEMBER, "var-phantom-prev", "PHANTOM"),
        value: {
          suite: "maruhi/v1",
          aad: aadFor(1, 1, { variableId: "var-phantom-prev" }),
          nonceHex: context.nonceHex,
          ciphertextHex: context.ciphertextHex,
          prevValueSigHashHex: context.prevValueSigHashHex,
          chainHeadHashHex: context.chainHeadHashHex,
          chainHeadSeq: context.chainHeadSeq,
          signatureHex: encodeHex(rawSignature),
        },
        manifest: unsignedManifest(),
      },
    );
    expect(v1NonEmptyPrev.status).toBe(422);
    expect(((await v1NonEmptyPrev.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("distributes the writer identity and signature block; client verifies via chain history (§12-7)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const headAtWrite = { ...fixture.head };
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: {
        variableId: string;
        value: WireEncryptedPayload & {
          writerUserId: string;
          writerKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    expect(pulled.value.writerUserId).toBe(MEMBER);
    expect(pulled.value.writerKeyFingerprintHex).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(pulled.value.chainHeadSeq).toBe(headAtWrite.seq);
    expect(pulled.value.chainHeadHashHex).toBe(headAtWrite.hashHex);
    expect(pulled.value.prevValueSigHashHex).toBe("");
    // The server-recomputed signed_bytes hash is not distributed (§12-2)
    expect("signedBytesHashHex" in pulled.value).toBe(false);

    // Client-side verification (§6.3): verification at the expected coordinates against the fetched chain's history index
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId,
        environmentId: ENV,
        epoch: pulled.value.aad.epoch,
        variableId: pulled.variableId,
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: pulled.value.writerUserId,
        chainHeadHashHex: pulled.value.chainHeadHashHex,
        chainHeadSeq: pulled.value.chainHeadSeq,
      },
      writerKeyFingerprintHex: pulled.value.writerKeyFingerprintHex,
      signatureHex: pulled.value.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("keeps distributing a removed writer's stored value, verifiable at its in-tenure head", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Remove the writer (MEMBER). The stored value's writer info is
    // distributed as of acceptance time (not re-derived from the
    // current member set — verifiability of a removed writer's past
    // values)
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: {
        variableId: string;
        value: WireEncryptedPayload & {
          writerUserId: string;
          writerKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    expect(pulled.value.writerUserId).toBe(MEMBER);

    // Even on the full chain after removal, verification passes because the declared head lies within the membership interval (§6.3-1/3)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId,
        environmentId: ENV,
        epoch: pulled.value.aad.epoch,
        variableId: pulled.variableId,
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: pulled.value.writerUserId,
        chainHeadHashHex: pulled.value.chainHeadHashHex,
        chainHeadSeq: pulled.value.chainHeadSeq,
      },
      writerKeyFingerprintHex: pulled.value.writerKeyFingerprintHex,
      signatureHex: pulled.value.signatureHex,
    });
    expect(result.ok).toBe(true);

    // A new push by the removed writer (declaring a post-removal
    // head) is rejected at the acceptance stage (the calling principal
    // is not a current member → the 404 existence hiding takes
    // precedence — §11-2)
    const rejected = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(rejected.status).toBe(404);
  });

  it("rejects a re-added member declaring a head from their old tenure (422 chain-head-state-mismatch)", async () => {
    // A principal that was removed and re-added with a different key
    // declaring a head from the old membership interval fails even
    // with a valid signature at "key bound at the declared head = key
    // at acceptance" (§12-5 item 3). The server-API-level counterpart
    // of the crypto vector key-from-other-tenure
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // Snapshot the old-tenure (current) head's hash, then remove MEMBER
    const oldTenureHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    // Re-add the same user_id (MEMBER) under a fresh key (reusing the
    // old key or another member's key is rejected by §6.2 member-key
    // uniqueness, so a newly generated key is used). MEMBER's
    // acceptance-time bound key becomes the new key, and a declaration
    // of an old-tenure head fails
    const newEncPair = await generateEncryptionKeyPair();
    const newSigPair = await generateSigningKeyPair();
    const rejoin = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: MEMBER,
          encPubHex: encodeHex(await exportEncryptionPublicKey(newEncPair.publicKey)),
          sigPubHex: encodeHex(await exportSigningPublicKey(newSigPair.publicKey)),
          role: "member",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      },
    });
    const rejoined = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: rejoin.entry,
    });
    expect(rejoined.status).toBe(200);
    fixture.head = { seq: rejoin.entry.seq, hashHex: rejoin.hash };
    // MEMBER's acceptance-time bound key is the new key. The server
    // verifies the signature with that key and uses MEMBER as the
    // signed writer_user_id. The attacker signs with the new key yet
    // declares a head from the old tenure (the signature is valid →
    // the key bound at the head = old key ≠ the new key at acceptance,
    // so it fails). Hand-build the context and sign with the new key.
    // prev must be the stored v1's real signed-bytes hash (with a
    // dummy, prev-hash-mismatch returns the same 422 reason and hides
    // the tenure check's mutation). The tenure check (state at the
    // head) precedes the prev check
    const context = {
      suite: "maruhi/v1" as const,
      projectId,
      environmentId: ENV,
      epoch: 1,
      variableId: VAR,
      version: 2,
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(48),
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      writerUserId: MEMBER,
      chainHeadHashHex: oldTenureHead.hashHex,
      chainHeadSeq: oldTenureHead.seq,
    };
    const signatureHex = encodeHex(
      new Uint8Array(
        await crypto.subtle.sign(
          "Ed25519",
          newSigPair.privateKey,
          buildValueSignedBytes(context) as BufferSource,
        ),
      ),
    );
    const value = {
      suite: "maruhi/v1" as const,
      aad: aadFor(1, 2),
      nonceHex: context.nonceHex,
      ciphertextHex: context.ciphertextHex,
      prevValueSigHashHex: context.prevValueSigHashHex,
      chainHeadHashHex: context.chainHeadHashHex,
      chainHeadSeq: context.chainHeadSeq,
      signatureHex,
    };
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoVersionSideEffects([1]);
  });

  it("stores the signature block and server-computed hash on the version row (the §12-5 stored row)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const headAtWrite = { ...fixture.head };
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const rows = await queryProjectDo(
      projectId,
      `SELECT prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
              signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint
       FROM variable_versions WHERE environment_id = ? AND variable_id = ? AND version = 1`,
      ENV,
      VAR,
    );
    expect(rows[0]).toEqual({
      prev_value_sig_hash_hex: "",
      chain_head_hash_hex: headAtWrite.hashHex,
      chain_head_seq: headAtWrite.seq,
      signature_hex: v1.signatureHex,
      signed_bytes_hash_hex: await valueSignedBytesHashOf(v1, MEMBER),
      writer_user_id: MEMBER,
      writer_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });
  });
});
