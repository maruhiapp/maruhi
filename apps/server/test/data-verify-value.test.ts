// データプレーン API(AUTH_SPEC §12)の統合テスト — 値署名の受理検証(AUTH_SPEC §12-5 = CRYPTO_SPEC §4.1 / §6.4)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

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
  VAR,
  variableStatementFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** 拒否時の無副作用の検査: 変数・バージョン・latest・監査のいずれも変わらない。 */
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

describe("値署名の受理検証(§12-5 = CRYPTO_SPEC §4.1 / §6.4)", () => {
  it("rejects a value signed by someone other than the caller (422 signature-invalid)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // OWNER が正しく署名した値を MEMBER が持ち込む → 検証鍵は呼び出し主体
    // (MEMBER)の受理時点チェーン鍵なので失敗する(他人の署名の持ち込み拒否)
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

  it("rejects creation with a tampered signature and writes nothing (作成経由の検証迂回は不可)", async () => {
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
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // 変数行・ステートメント行・バージョン行・監査のいずれも残らない
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
    // 実在 seq × 不一致 hash(有効署名)— exact pair の存在が受理条件
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

    // 自チェーンより先の seq(サーバーには存在しない)も chain-head-unknown
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

    // (a) writer が member になる前のヘッド(seq 1 = genesis)の宣言
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

    // (b) 環境作成前のヘッド(ベースチェーンの seq 3)の宣言 — エポックが未定義の
    // ヘッドを既定値で補う実装の禁止(§12-5 の 4 後段)
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
    // version 2 の prev が保存済み version 1 の signed_bytes ハッシュと不一致
    // (署名は有効 — Ed25519 failure に潰されないことの固定)
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

    // version 1 に非空 prev(署名は有効な形を低水準 API で作る — signValue は
    // 結合違反の署名を拒否するため)
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
    // サーバー再計算の signed_bytes ハッシュは配布されない(§12-2)
    expect("signedBytesHashHex" in pulled.value).toBe(false);

    // クライアント検証(§6.3): 取得チェーンの履歴索引に対する期待座標での検証
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
    // writer(MEMBER)を削除。保存済み値の writer 情報は受理時点のまま配布される
    // (現メンバー集合から再導出しない — 削除済み writer の過去値の検証可能性)
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

    // 削除後の全チェーンでも、宣言ヘッドが在籍区間内なので検証は通る(§6.3-1/3)
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

    // 削除済み writer による新規 push(削除後のヘッド宣言)は受理段階で拒否される
    // (呼び出し主体が現メンバーでない → 404 存在秘匿が先に立つ — §11-2)
    const rejected = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(rejected.status).toBe(404);
  });

  it("rejects a re-added member declaring a head from their old tenure (422 chain-head-state-mismatch)", async () => {
    // remove → 別鍵 re-add した主体が旧在籍区間のヘッドを宣言する形は、署名が
    // 有効でも「宣言ヘッド時点の束縛鍵 = 受理時点の鍵」で落ちる(§12-5 の 3)。
    // crypto ベクター key-from-other-tenure のサーバー API レベルの対
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 旧在籍区間(現ヘッド)の hash を控えてから MEMBER を削除
    const oldTenureHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    // 同一 user_id(MEMBER)を新鮮な鍵で re-add する(旧鍵・他メンバー鍵との
    // 重複は §6.2 のメンバー鍵一意性で弾かれるため、新規生成鍵を使う)。
    // 受理時点の MEMBER の束縛鍵は新鍵になり、旧在籍区間のヘッド宣言は落ちる
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
        },
      },
    });
    const rejoined = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry: rejoin.entry,
    });
    expect(rejoined.status).toBe(200);
    fixture.head = { seq: rejoin.entry.seq, hashHex: rejoin.hash };
    // 受理時点の MEMBER の束縛鍵は新鍵。サーバーはその鍵で署名検証し署名対象の
    // writer_user_id にも MEMBER を用いる。攻撃者は新鍵で署名した上で旧在籍区間の
    // ヘッドを宣言する(署名は有効 → ヘッド時点の束縛鍵 = 旧鍵 ≠ 受理時点の新鍵で
    // 落ちる)。context を手で組んで新鍵で署名する
    // prev は保存済み v1 の実 signed-bytes ハッシュにする(ダミーだと
    // prev-hash-mismatch が同じ 422 理由を返して tenure 検査の変異が隠れる —
    // レビューループ 2 [低])。tenure 検査(head 時点状態)が prev 検査より先
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

  it("stores the signature block and server-computed hash on the version row (§12-5 の保存行)", async () => {
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
