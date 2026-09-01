// データプレーン API(AUTH_SPEC §12)の統合テスト — メタステートメントの受理検証(AUTH_SPEC §12-5 のメタ規則 = CRYPTO_SPEC §4.2)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

import type { ChainEntry } from "@maruhi/crypto";
import { verifyChainWithHistory, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { MAX_VERSIONS_PER_VARIABLE } from "../src/policy.ts";
import { metaVersionsExceeded } from "../src/quotas.ts";
import { metaSignedBytesHashOf, signMetaStatementAs, vectorKeyOf } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  hashOf,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
  varStatements,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** 拒否時の無副作用: ステートメント行・変数名キャッシュ・監査が変わらない。 */
async function expectNoMetaSideEffects(expectedMetaVersions: readonly number[]): Promise<void> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version",
    ENV,
    VAR,
  );
  expect(rows.map((row) => row["meta_version"])).toEqual([...expectedMetaVersions]);
  // 受理されたメタ操作数との不変条件(rename 経路は名前の変更有無で
  // var.renamed / var.schema_reissued に分岐する — AUDIT_SPEC §3.3 2026-09-01。
  // 名前不変の受理ケースを将来足しても不変条件が黙って割れないよう両方数える)
  const renamedAudits = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM audit_events WHERE event IN ('var.renamed', 'var.schema_reissued', 'var.deleted')",
  );
  expect(renamedAudits[0]?.["n"]).toBe(Math.max(0, expectedMetaVersions.length - 1));
}

describe("メタステートメントの受理検証(§12-5 のメタ規則 = CRYPTO_SPEC §4.2)", () => {
  it("accepts the create → rename → delete statement chain and keeps distributing the tombstone", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 作成ステートメント(metaVersion 1)を rename が上書きする前に控える
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);

    // rename 後の pull は metaVersion 2 のステートメント + author を配布する
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: {
        statement: {
          name: string;
          status: string;
          metaVersion: number;
          prevMetaSigHashHex: string;
          authorUserId: string;
        };
      }[];
      deletedVariables: unknown[];
    };
    expect(body.variables[0]?.statement).toMatchObject({
      name: "DB_URL",
      status: "active",
      metaVersion: 2,
      authorUserId: MEMBER,
    });
    expect(body.deletedVariables).toEqual([]);

    // 削除: tombstone + 全バージョン削除。deleted ステートメント(name は直前
    // active 名を保持)は保存・配布し続ける(§12-5)
    const removed = await deleteVariableRequest(VAR, MEMBER);
    expect(removed.status).toBe(204);
    const afterDelete = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const deletedBody = (await afterDelete.json()) as {
      variables: unknown[];
      deletedVariables: {
        variableId: string;
        name: string;
        status: string;
        metaVersion: number;
        authorUserId: string;
        authorKeyFingerprintHex: string;
      }[];
    };
    expect(deletedBody.variables).toEqual([]);
    expect(deletedBody.deletedVariables).toEqual([
      expect.objectContaining({
        variableId: VAR,
        name: "DB_URL",
        status: "deleted",
        metaVersion: 3,
        authorUserId: MEMBER,
        authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
      }),
    ]);

    // ステートメント行(§12-5 の保存行): metaVersion ごとに author・宣言ヘッド・
    // prev・サーバー再計算ハッシュを保持する
    const rows = await queryProjectDo(
      projectId,
      `SELECT meta_version, name, status, prev_meta_sig_hash_hex, signed_bytes_hash_hex, author_user_id, author_key_fingerprint
       FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version`,
      ENV,
      VAR,
    );
    expect(rows.map((row) => [row["meta_version"], row["name"], row["status"]])).toEqual([
      [1, "DATABASE_URL", "active"],
      [2, "DB_URL", "active"],
      [3, "DB_URL", "deleted"],
    ]);
    expect(rows[0]?.["signed_bytes_hash_hex"]).toBe(
      await metaSignedBytesHashOf(projectId, created.statement, MEMBER),
    );
    expect(rows.every((row) => row["author_user_id"] === MEMBER)).toBe(true);
  });

  it("enforces the metaVersion CAS: only latest + 1, returning the number only (409 §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    // 申告 metaVersion 3(最新は 1)→ 409 currentMetaVersion 1。勝者の
    // signed_bytes ハッシュは載せない(§12-5 の 409 規律)
    const stale = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 3,
      prevMetaSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: stale, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(409);
    const staleBody = (await response.json()) as Record<string, unknown>;
    expect(staleBody).toMatchObject({ currentMetaVersion: 1 });
    expect(Object.keys(staleBody).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);
    await expectNoMetaSideEffects([1]);
  });

  it("rejects non-NFC names with 422 NameNotNfc on every statement path (§12-1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // NFD(結合文字)の名前 — サーバーは正規化せず検査のみ(byte-exact 署名との両立)
    const nfdName = "CAFE\u0301_URL";
    expect(nfdName.normalize("NFC")).not.toBe(nfdName);

    // 変数作成
    const created = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, nfdName),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(created.status).toBe(422);
    expect((await created.json()) as Record<string, unknown>).toMatchObject({
      _tag: "NameNotNfc",
    });
    await expectNoMetaSideEffects([]);

    // 変数 rename
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: await nextVariableStatement({
          variableId: VAR,
          name: nfdName,
          status: "active",
          authorUserId: MEMBER,
        }),
        manifest: unsignedManifest(),
      },
    );
    expect(renamed.status).toBe(422);
    await expectNoMetaSideEffects([1]);

    // 複合の環境作成(同梱ステートメント)— チェーンエントリも追記されない(原子性)
    const headBefore = fixture.head;
    const response = await createEnvironmentWith(
      fixture,
      "env-nfd-0002",
      nfdName,
      await wrapsFor("env-nfd-0002", ALL_MEMBERS),
    );
    expect(response.status).toBe(422);
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
  });

  it("requires the delete statement to keep the last active name (422 PayloadMismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const wrongName = await nextVariableStatement({
      variableId: VAR,
      name: "SOMETHING_ELSE",
      status: "deleted",
      authorUserId: MEMBER,
    });
    const response = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: wrongName, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("name");
    // 変数は削除されていない
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(((await pull.json()) as { variables: unknown[] }).variables.length).toBe(1);
    await expectNoMetaSideEffects([1]);
  });

  it("rejects a statement signed by someone other than the caller (422 signature-invalid)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // OWNER が署名した rename を MEMBER が持ち込む → 検証鍵は呼び出し主体
    // (MEMBER)の受理時点チェーン鍵なので失敗(他人の署名の持ち込み拒否)
    const ownerSigned = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: OWNER,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: ownerSigned, manifest: unsignedManifest() },
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    await expectNoMetaSideEffects([1]);
  });

  it("rejects statements whose declared head predates the author's membership or is unknown (§12-5 の 2〜3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const created = varStatements.get(VAR);
    if (created === undefined) throw new Error("missing recorded statement");
    const prevHash = await metaSignedBytesHashOf(projectId, created.statement, MEMBER);

    // (a) 宣言ヘッド = genesis(seq 1)。MEMBER の add_member は seq 2 なので
    // ヘッド時点で非在籍 → chain-head-state-mismatch。メタは環境の存在を検査
    // しない(§12-4 の非対称)ため、拒否理由は在籍のみに帰着する
    const beforeMembership = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: await hashOf(1),
      chainHeadSeq: 1,
    });
    const notMember = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: beforeMembership, manifest: unsignedManifest() },
    );
    expect(notMember.status).toBe(422);
    expect(((await notMember.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // (b) 実在 seq × 不一致 hash → chain-head-unknown
    const unknownHead = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: "ee".repeat(32),
      chainHeadSeq: fixture.head.seq,
    });
    const mismatch = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: unknownHead, manifest: unsignedManifest() },
    );
    expect(mismatch.status).toBe(422);
    expect(((await mismatch.json()) as { reason: string }).reason).toBe("chain-head-unknown");

    // (c) prev の不一致(署名は有効)→ chain-head-state-mismatch
    const wrongPrev = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      name: "DB_URL",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const prevMismatch = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: wrongPrev, manifest: unsignedManifest() },
    );
    expect(prevMismatch.status).toBe(422);
    expect(((await prevMismatch.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );
    await expectNoMetaSideEffects([1]);
  });

  it("distributes a removed author's statement, verifiable at its in-tenure head (§6.3 のクライアント検証)", async () => {
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
        statement: {
          suite: "maruhi/v1";
          name: string;
          status: "active" | "deleted";
          metaVersion: number;
          prevMetaSigHashHex: string;
          chainHeadHashHex: string;
          chainHeadSeq: number;
          signatureHex: string;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
      }[];
    };
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing pulled variable");
    // author 情報は受理時点のまま配布される(現メンバー集合から再導出しない)
    expect(pulled.statement.authorUserId).toBe(MEMBER);

    // クライアント検証(§6.3): 削除後の全チェーンでも、宣言ヘッドが在籍区間内
    // なので当時の鍵で検証できる
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const result = await verifyDistributedMetaStatement({
      history: verified.value.history,
      context: {
        suite: pulled.statement.suite,
        projectId,
        environmentId: ENV,
        target: { kind: "variable", variableId: pulled.variableId },
        name: pulled.statement.name,
        status: pulled.statement.status,
        metaVersion: pulled.statement.metaVersion,
        prevMetaSigHashHex: pulled.statement.prevMetaSigHashHex,
        authorUserId: pulled.statement.authorUserId,
        chainHeadHashHex: pulled.statement.chainHeadHashHex,
        chainHeadSeq: pulled.statement.chainHeadSeq,
      },
      authorKeyFingerprintHex: pulled.statement.authorKeyFingerprintHex,
      signatureHex: pulled.statement.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("lists deleted environments with their tombstone statement (§12-4 の配布継続)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const list = await requestJson("GET", "/environments", token(READER));
    const body = (await list.json()) as {
      environments: {
        environmentId: string;
        statement: { name: string; status: string; metaVersion: number; authorUserId: string };
      }[];
    };
    expect(body.environments.length).toBe(2);
    const deleted = body.environments.find((e) => e.environmentId === ENV);
    expect(deleted?.statement).toMatchObject({
      name: "App",
      status: "deleted",
      metaVersion: 2,
      authorUserId: OWNER,
    });
    // 削除済み環境への pull は従来どおり 404(tombstone)
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(404);
  });

  it("requires the composite statement to declare the pre-append head (§12-4)", async () => {
    // 先に 1 つ環境を作ってヘッドを進め、「古い実在ヘッド」を作る
    await createEnvironmentOk(fixture, ENV, "App");
    const staleHead = { seq: fixture.head.seq - 1, hashHex: await hashOf(fixture.head.seq - 1) };
    const deks = await wrapsFor("env-app-0002", ALL_MEMBERS);
    const headBefore = fixture.head;
    const staleStatement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: "env-app-0002",
      name: "Staging",
      head: staleHead,
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: "env-app-0002",
      name: "Staging",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      statement: staleStatement,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("statementChainHead");
    // 原子性: チェーンにも環境行にも痕跡を残さない
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
  });

  it("retries a composite creation after a head CAS conflict by re-signing both entry and statement (§12-4)", async () => {
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const stale = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId, // genesis ハッシュ = 古いヘッド
    });
    // CAS が先に落ちる(ステートメントの宣言ヘッドも古いが、409 で再試行を促す)
    expect(stale.status).toBe(409);
    const headBefore = { ...fixture.head };
    // 再試行はエントリ(prev 変更)とステートメント(宣言ヘッド変更)の両方を
    // 再署名する(fixture helper が両方作り直す — §12-4)
    const retried = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
    // 保存されたステートメントの宣言ヘッドは追記前の現ヘッド(= 再署名済み)
    const rows = await queryProjectDo(
      projectId,
      "SELECT chain_head_seq, chain_head_hash_hex FROM environment_meta_statements WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]).toEqual({
      chain_head_seq: headBefore.seq,
      chain_head_hash_hex: headBefore.hashHex,
    });
  });

  it("caps meta versions per variable (422 meta-versions — 仮裁定の §12-8 適用)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 実 rename 1,000 回は非現実的なので latest_meta_version を直接引き上げ、
    // 上限直前のステートメント行(prev 検査の predecessor)をシードする
    // (latest_meta_version の行は必ず存在する、という保存不変条件 —
    // findVariable の status JOIN の前提 — をシードでも保つ)
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      "UPDATE variable_meta_statements SET meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      {
        statement: await signMetaStatementAs(MEMBER, projectId, {
          suite: "maruhi/v1" as const,
          environmentId: ENV,
          variableId: VAR,
          name: "DB_URL",
          status: "active" as const,
          metaVersion: MAX_VERSIONS_PER_VARIABLE + 1,
          prevMetaSigHashHex: "cd".repeat(32),
          chainHeadHashHex: fixture.head.hashHex,
          chainHeadSeq: fixture.head.seq,
        }),
        manifest: unsignedManifest(),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "meta-versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  });

  it("accepts the delete statement even at the meta version cap (deleted は上限対象外)", async () => {
    // 上限で削除まで遮断すると、rename 連打で上限到達したリソースがどの role
    // でも恒久的に削除不能になる(レビュー②③ [major])。tombstone は連鎖の
    // 終端で追加行は高々 1 行なので上限の対象外とする
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE, "active")).toBe(true);
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE - 1, "active")).toBe(false);
    expect(metaVersionsExceeded(MAX_VERSIONS_PER_VARIABLE, "deleted")).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 実 rename 1,000 回は非現実的なので、latest と最新ステートメント行の
    // meta_version を直接引き上げて上限到達状態をシードする(prev は保存済みの
    // サーバー再計算ハッシュを流用)
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      "UPDATE variable_meta_statements SET meta_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    const anchorRows = await queryProjectDo(
      projectId,
      "SELECT signed_bytes_hash_hex FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    const prevHash = anchorRows[0]?.signed_bytes_hash_hex;
    if (typeof prevHash !== "string") {
      throw new Error("seeded meta statement row missing");
    }
    const deleteStatement = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: VAR,
      // deleted の name は直前 active 名を保持する(§4.2)
      name: "DATABASE_URL",
      status: "deleted" as const,
      metaVersion: MAX_VERSIONS_PER_VARIABLE + 1,
      prevMetaSigHashHex: prevHash,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // 上限到達でも同梱マニフェスト(tombstone 込みダイジェスト)は通常どおり
    // 要る(マニフェスト自体は行数上限の対象外 — §12-8: 保持は最新 1 通)
    const { manifest } = await manifestForStatement(deleteStatement, MEMBER);
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: deleteStatement, manifest },
    );
    expect(removed.status).toBe(204);
    // tombstone ステートメントは保存・配布され続ける(§12-5)
    const tombstones = await queryProjectDo(
      projectId,
      "SELECT status, meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? AND status = 'deleted'",
      ENV,
      VAR,
    );
    expect(tombstones).toEqual([
      { status: "deleted", meta_version: MAX_VERSIONS_PER_VARIABLE + 1 },
    ]);
  });
});
