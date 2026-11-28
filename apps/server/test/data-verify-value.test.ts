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
import type { WireEncryptedPayload } from "@maruhi/test-kit";
import {
  encryptValue,
  hexBytes,
  signEntryAt,
  signValueAt,
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
  valueSignedBytesHashOf,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { identityOf, vectorKeyOf } from "./support/data-crypto.ts";
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
    const ownerSigned = await encryptValue({
      dek,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(VAR),
      version: 2,
      plaintext: "postgres://beta",
      writer: identityOf(OWNER),
      head: fixture.head,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
    });
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
    const value = await encryptValue({
      dek,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(VAR),
      version: 1,
      plaintext: "postgres://alpha",
      writer: identityOf(MEMBER),
      head: fixture.head,
    });
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
    const mismatched = await signValueAt(
      identityOf(MEMBER),
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

    const future = await signValueAt(
      identityOf(MEMBER),
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

    const beforeMembership = await signValueAt(
      identityOf(MEMBER),
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

    const beforeCreate = await signValueAt(
      identityOf(MEMBER),
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

    const context = {
      suite: "maruhi/v1",
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId("var-phantom-prev"),
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
    expect("signedBytesHashHex" in pulled.value).toBe(false);

    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: pulled.value.aad.epoch,
        variableId: testVariableId(pulled.variableId),
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: testUserId(pulled.value.writerUserId),
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

    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedValue({
      history: verified.value.history,
      context: {
        suite: "maruhi/v1",
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(ENV),
        epoch: pulled.value.aad.epoch,
        variableId: testVariableId(pulled.variableId),
        version: pulled.value.aad.version,
        nonceHex: pulled.value.nonceHex,
        ciphertextHex: pulled.value.ciphertextHex,
        prevValueSigHashHex: pulled.value.prevValueSigHashHex,
        writerUserId: testUserId(pulled.value.writerUserId),
        chainHeadHashHex: pulled.value.chainHeadHashHex,
        chainHeadSeq: pulled.value.chainHeadSeq,
      },
      writerKeyFingerprintHex: pulled.value.writerKeyFingerprintHex,
      signatureHex: pulled.value.signatureHex,
    });
    expect(result.ok).toBe(true);

    const rejected = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(rejected.status).toBe(404);
  });

  it("rejects a re-added member declaring a head from their old tenure (422 chain-head-state-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const oldTenureHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const newEncPair = await generateEncryptionKeyPair();
    const newSigPair = await generateSigningKeyPair();
    const rejoin = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actor: identityOf(OWNER),
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
    const context = {
      suite: "maruhi/v1" as const,
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(VAR),
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
