// データプレーン API(AUTH_SPEC §12)の統合テスト — 変数の push→pull→クライアント復号とメタデータのみモード(AUTH_SPEC §12-5 / §12-7)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

import type { TokenScope } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { verifyChainWithHistory, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import {
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_VALUE_CIPHERTEXT_BYTES,
  MAX_VERSIONS_PER_VARIABLE,
} from "../src/policy.ts";
import { projectBytesExceeded } from "../src/quotas.ts";
import { deviceToken, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  encryptValue,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  vectorKeyOf,
} from "./support/data-crypto.ts";
import {
  createEnvironmentOk,
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
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("変数の push→pull→クライアント復号(§12-5 / §12-7)", () => {
  it("round-trips a value end to end: encrypt → create → pull → unwrap DEK → decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      environmentId: string;
      currentEpoch: number;
      statement: { name: string; status: string; authorUserId: string };
      variables: {
        variableId: string;
        statement: {
          variableId: string;
          name: string;
          status: string;
          metaVersion: number;
          authorUserId: string;
          authorKeyFingerprintHex: string;
        };
        value: WireEncryptedPayload;
      }[];
      deletedVariables: unknown[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(1);
    expect(body.variables.length).toBe(1);
    expect(body.deks.length).toBe(1);
    // pull は裸 name でなくステートメント + author 情報を運ぶ(§12-2 / §12-7)
    expect(body.statement).toMatchObject({ name: "App", status: "active", authorUserId: OWNER });
    expect(body.deletedVariables).toEqual([]);
    const [variable] = body.variables;
    const [wrappedDek] = body.deks;
    if (variable === undefined || wrappedDek === undefined) throw new Error("missing pull data");
    expect(variable.value.aad).toEqual(aadFor(1, 1));
    expect(variable.statement).toMatchObject({
      variableId: VAR,
      name: "DATABASE_URL",
      status: "active",
      metaVersion: 1,
      authorUserId: MEMBER,
      authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });

    // reader のクライアント側復号(E2EE のラウンドトリップ)
    const plaintext = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: wrappedDek,
      projectId,
      environmentId: ENV,
      payload: variable.value,
    });
    expect(plaintext).toBe("postgres://alpha");

    // 新バージョンを push すると pull は最新のみ返す(prev = v1 の signed_bytes
    // ハッシュへ連鎖 — §4.1)
    const v1 = variable.value;
    const v2 = await encryptValue(
      dek,
      { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
      "postgres://beta",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      },
    );
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(push.status).toBe(200);
    await expect(push.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 1 });

    const second = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const secondBody = (await second.json()) as typeof body;
    const latest = secondBody.variables[0];
    const latestDek = secondBody.deks[0];
    if (latest === undefined || latestDek === undefined) throw new Error("missing pull data");
    expect(latest.value.aad.version).toBe(2);
    const decrypted = await unwrapAndDecrypt({
      recipientUserId: READER,
      wrapped: latestDek,
      projectId,
      environmentId: ENV,
      payload: latest.value,
    });
    expect(decrypted).toBe("postgres://beta");
  });

  it("rejects declared AAD components that mismatch the storage coordinates (422 §12-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const cases: readonly [Partial<WireEncryptedPayload["aad"]>, string][] = [
      [{ environmentId: "env-app-0002" }, "environmentId"],
      [{ variableId: "var-other" }, "variableId"],
      [{ projectId: "ab".repeat(32) }, "projectId"],
    ];
    for (const [override, field] of cases) {
      const response = await requestJson(
        "POST",
        `/environments/${ENV}/variables/${VAR}/versions`,
        token(MEMBER),
        { value: await fakePayload(MEMBER, aadFor(1, 2, override)) },
      );
      expect(response.status).toBe(422);
      const body = (await response.json()) as { field: string };
      expect(body.field).toBe(field);
    }
  });

  it("enforces the version CAS: only latest + 1 is accepted (409 §12-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // 既知の version(1)を再申告 → 409 currentVersion 1
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 1)) },
    );
    expect(stale.status).toBe(409);
    // 409 は currentVersion(番号)のみを返す — 勝者の signed_bytes ハッシュは
    // 載せない(未検証値への連鎖署名の禁止 — §12-5)
    const staleBody = (await stale.json()) as Record<string, unknown>;
    expect(staleBody).toMatchObject({ currentVersion: 1 });
    expect(Object.keys(staleBody).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);

    // 飛び番(3)も拒否
    const skipped = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 3)) },
    );
    expect(skipped.status).toBe(409);
    await expect(skipped.json()).resolves.toMatchObject({ currentVersion: 1 });
  });

  it("creation requires version 1 (409 currentVersion 0)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 2)),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({ currentVersion: 0 });
  });

  it("serializes concurrent pushes: exactly one winner, no lost or interleaved writes", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const prevHash = await valueSignedBytesHashOf(v1, MEMBER);

    const contenders = await Promise.all(
      Array.from({ length: 8 }, (_v, index) =>
        encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: 2 },
          `postgres://contender-${index}`,
          { writerUserId: MEMBER, head: fixture.head, prevValueSigHashHex: prevHash },
        ),
      ),
    );
    const responses = await Promise.all(
      contenders.map((value) =>
        requestJson("POST", `/environments/${ENV}/variables/${VAR}/versions`, token(MEMBER), {
          value,
        }),
      ),
    );
    const statuses = responses.map((response) => response.status);
    expect(statuses.filter((status) => status === 200).length).toBe(1);
    expect(statuses.filter((status) => status === 409).length).toBe(7);
    for (const response of responses.filter((r) => r.status === 409)) {
      await expect(response.json()).resolves.toMatchObject({ currentVersion: 2 });
    }

    // 欠損・交錯なし: バージョン行は 1,2 のみ、latest は 2、勝者の暗号文が保存されている
    const rows = await queryProjectDo(
      projectId,
      "SELECT version, ciphertext_hex FROM variable_versions WHERE environment_id = ? AND variable_id = ? ORDER BY version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["version"])).toEqual([1, 2]);
    const winnerIndex = statuses.indexOf(200);
    expect(rows[1]?.["ciphertext_hex"]).toBe(contenders[winnerIndex]?.ciphertextHex);
    const variableRow = await queryProjectDo(
      projectId,
      "SELECT latest_version FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(variableRow[0]?.["latest_version"]).toBe(2);
  });

  it("accepts concurrent pushes to different variables", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const ids = ["var-a", "var-b", "var-c"];
    const firstVersions = new Map<string, WireEncryptedPayload>();
    for (const id of ids) {
      firstVersions.set(id, await createVariableOk(dek, id, `NAME_${id}`, `value-${id}`));
    }
    const values = await Promise.all(
      ids.map(async (id) => {
        const v1 = firstVersions.get(id);
        if (v1 === undefined) throw new Error("missing first version");
        return encryptValue(
          dek,
          { projectId, environmentId: ENV, epoch: 1, variableId: id, version: 2 },
          `next-${id}`,
          {
            writerUserId: MEMBER,
            head: fixture.head,
            prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
          },
        );
      }),
    );
    const responses = await Promise.all(
      ids.map((id, index) =>
        requestJson("POST", `/environments/${ENV}/variables/${id}/versions`, token(MEMBER), {
          value: values[index],
        }),
      ),
    );
    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
  });

  it("rejects pushes from readers with 403 insufficient-role (§6.2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(READER),
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("enforces min(token scope, chain role) (§9-2 / §12-3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // member の read スコープ: pull 可・push 不可(403 insufficient-permission)
    const readScope: readonly TokenScope[] = [{ project: projectId, permission: "read" }];
    const readToken = await deviceToken(9002, readScope);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, readToken);
    expect(pull.status).toBe(200);
    const push = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readToken,
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(push.status).toBe(403);
    expect(((await push.json()) as { reason: string }).reason).toBe("insufficient-permission");

    // reader の write スコープ: スコープが足りてもチェーン role が束縛(403 insufficient-role)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const readerWrite = await deviceToken(9003, writeScope);
    const readerPush = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      readerWrite,
      { value: await fakePayload(READER, aadFor(1, 2)) },
    );
    expect(readerPush.status).toBe(403);
    expect(((await readerPush.json()) as { reason: string }).reason).toBe("insufficient-role");

    // スコープ外プロジェクトは存在秘匿(404)
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scoped = await deviceToken(9002, otherScope);
    const concealed = await requestJson("GET", `/environments/${ENV}/pull`, scoped);
    expect(concealed.status).toBe(404);

    // 環境削除は admin スコープが必要(write では 403。スコープ検査は署名検証より
    // 前 — §12-3 — なので未署名ダミーのステートメントで足りる)
    const memberWrite = await deviceToken(9001, writeScope);
    const removal = await requestJson("DELETE", `/environments/${ENV}`, memberWrite, {
      statement: {
        suite: "maruhi/v1",
        environmentId: ENV,
        name: "App",
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "cd".repeat(32),
        chainHeadHashHex: fixture.head.hashHex,
        chainHeadSeq: fixture.head.seq,
        signatureHex: "00".repeat(64),
      },
    });
    expect(removal.status).toBe(403);
    expect(((await removal.json()) as { reason: string }).reason).toBe("insufficient-permission");
  });

  it("handles variable conflicts: duplicate id, retired id, duplicate name, rename", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    const duplicate = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "OTHER"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(duplicate.status).toBe(409);
    expect(((await duplicate.json()) as { reason: string }).reason).toBe("exists");

    const sameName = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, "var-other", "DATABASE_URL"),
      value: await fakePayload(MEMBER, { ...aadFor(1, 1), variableId: "var-other" }),
      manifest: unsignedManifest(),
    });
    expect(sameName.status).toBe(409);
    expect(((await sameName.json()) as { reason: string }).reason).toBe("duplicate-name");

    // 作成側の申告 AAD 不一致(§12-2): ステートメントの variableId と aad の不一致は 422
    const createMismatch = await requestJson(
      "POST",
      `/environments/${ENV}/variables`,
      token(MEMBER),
      {
        statement: await variableStatementFor(MEMBER, "var-other", "OTHER"),
        value: await fakePayload(MEMBER, aadFor(1, 1)),
        manifest: unsignedManifest(),
      },
    );
    expect(createMismatch.status).toBe(422);
    expect(((await createMismatch.json()) as { field: string }).field).toBe("variableId");

    // 改名も名前一意性の対象(§12-1)
    await createVariableOk(dek, "var-other", "OTHER", "other-value");
    const renameConflict = await renameVariableRequest("var-other", "DATABASE_URL", MEMBER);
    expect(renameConflict.status).toBe(409);
    expect(((await renameConflict.json()) as { reason: string }).reason).toBe("duplicate-name");

    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);

    const removed = await deleteVariableRequest(VAR, MEMBER);
    expect(removed.status).toBe(204);
    const versions = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variable_versions WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(versions.length).toBe(0);

    // 削除済み ID の再利用は拒否(§12-1)
    const retired = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "REBORN"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
    expect(retired.status).toBe(409);
    expect(((await retired.json()) as { reason: string }).reason).toBe("retired");

    // 削除済み変数への push は 404
    const pushDeleted = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(pushDeleted.status).toBe(404);
  });

  it("rejects an oversized ciphertext with 413 (§12-8)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "BIG"),
      value: await fakePayload(MEMBER, aadFor(1, 1), {
        ciphertextBytes: MAX_VALUE_CIPHERTEXT_BYTES + 1,
      }),
      manifest: unsignedManifest(),
    });
    expect(response.status).toBe(413);
    await expect(response.json()).resolves.toMatchObject({
      limitBytes: MAX_VALUE_CIPHERTEXT_BYTES,
    });
  });

  it("caps versions per variable (422 §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 1,000 回の実 push は非現実的なので latest_version を直接引き上げ、
    // 上限直前の version 行(prev 検査の predecessor)をシードする
    // (数量ポリシーは値署名の後 — 裁定 D — のため署名検証を通る形が要る)
    const seededHash = "aa".repeat(32);
    await queryProjectDo(
      projectId,
      "UPDATE variables SET latest_version = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_VERSIONS_PER_VARIABLE,
      ENV,
      VAR,
    );
    await queryProjectDo(
      projectId,
      `INSERT INTO variable_versions
         (environment_id, variable_id, version, suite, epoch, nonce_hex, ciphertext_hex, ciphertext_bytes,
          prev_value_sig_hash_hex, chain_head_hash_hex, chain_head_seq, signature_hex,
          signed_bytes_hash_hex, writer_user_id, writer_key_fingerprint, created_at)
       VALUES (?, ?, ?, 'maruhi/v1', 1, ?, ?, 48, ?, ?, 1, ?, ?, ?, ?, 0)`,
      ENV,
      VAR,
      MAX_VERSIONS_PER_VARIABLE,
      "00".repeat(12),
      "ab".repeat(48),
      "bb".repeat(32),
      projectId,
      "00".repeat(64),
      seededHash,
      MEMBER,
      vectorKeyOf(MEMBER).key_fingerprint_hex,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, MAX_VERSIONS_PER_VARIABLE + 1), {
          prevValueSigHashHex: seededHash,
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "versions",
      limit: MAX_VERSIONS_PER_VARIABLE,
    });
  });

  it("caps cumulative project ciphertext bytes (422 §12-8, unit + plumbing)", async () => {
    // 純関数の判定(1 GiB を実生成しない)
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES, 1)).toBe(true);
    expect(projectBytesExceeded(MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES - 10, 10)).toBe(false);

    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 保存済みバイト数だけを上限相当へ引き上げてプラミングを検証する
    await queryProjectDo(
      projectId,
      "UPDATE variable_versions SET ciphertext_bytes = ? WHERE environment_id = ? AND variable_id = ?",
      MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      ENV,
      VAR,
    );
    const response = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      {
        value: await fakePayload(MEMBER, aadFor(1, 2), {
          prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
        }),
      },
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      resource: "project-ciphertext-bytes",
      limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
    });
  });
});

describe("メタデータのみモード(§12-7 — 値・DEK を返さない)", () => {
  it("returns the statement-only material: environment + active + tombstones, no values, no deks", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek, "var-second", "REDIS_URL", "redis://alpha");
    const renamed = await renameVariableRequest(VAR, "DB_URL", MEMBER);
    expect(renamed.status).toBe(204);
    const removed = await deleteVariableRequest("var-second", MEMBER);
    expect(removed.status).toBe(204);

    const response = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(READER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      environmentId: string;
      currentEpoch: number;
      statement: { name: string; status: string; authorUserId: string };
      variables: {
        variableId: string;
        name: string;
        status: string;
        metaVersion: number;
        prevMetaSigHashHex: string;
        chainHeadHashHex: string;
        chainHeadSeq: number;
        signatureHex: string;
        authorUserId: string;
        authorKeyFingerprintHex: string;
        suite: "maruhi/v1";
      }[];
      deletedVariables: { variableId: string; name: string; status: string }[];
    };
    expect(body.environmentId).toBe(ENV);
    expect(body.currentEpoch).toBe(1);
    expect(body.statement).toMatchObject({ name: "App", status: "active", authorUserId: OWNER });
    // アクティブ変数は最新ステートメントのみ(rename 後 = metaVersion 2)。
    // 値(暗号文)の断片がどこにも同梱されない
    expect(body.variables).toEqual([
      expect.objectContaining({
        variableId: VAR,
        name: "DB_URL",
        status: "active",
        metaVersion: 2,
        authorUserId: MEMBER,
        authorKeyFingerprintHex: vectorKeyOf(MEMBER).key_fingerprint_hex,
      }),
    ]);
    expect(body.deletedVariables).toEqual([
      expect.objectContaining({ variableId: "var-second", name: "REDIS_URL", status: "deleted" }),
    ]);
    expect(body).not.toHaveProperty("deks");
    const raw = JSON.stringify(body);
    for (const forbidden of ["ciphertextHex", "nonceHex", "encHex", "prevValueSigHashHex"]) {
      expect(raw).not.toContain(forbidden);
    }

    // 配布されたステートメントは §6.3 のクライアント検証を通る(検証材料の
    // 同梱義務は値付き pull と同一 — §12-7)
    const chain = await requestJson("GET", "/chain", token(READER));
    const chainBody = (await chain.json()) as { entries: ChainEntry[] };
    const verified = await verifyChainWithHistory(chainBody.entries);
    if (!verified.ok) throw new Error("chain verification failed");
    const pulled = body.variables[0];
    if (pulled === undefined) throw new Error("missing statement");
    const result = await verifyDistributedMetaStatement({
      history: verified.value.history,
      context: {
        suite: pulled.suite,
        projectId,
        environmentId: ENV,
        target: { kind: "variable", variableId: pulled.variableId },
        name: pulled.name,
        status: pulled.status as "active" | "deleted",
        metaVersion: pulled.metaVersion,
        prevMetaSigHashHex: pulled.prevMetaSigHashHex,
        authorUserId: pulled.authorUserId,
        chainHeadHashHex: pulled.chainHeadHashHex,
        chainHeadSeq: pulled.chainHeadSeq,
      },
      authorKeyFingerprintHex: pulled.authorKeyFingerprintHex,
      signatureHex: pulled.signatureHex,
    });
    expect(result.ok).toBe(true);
  });

  it("authorizes like the bulk pull (read × reader) and conceals like it (§12-3 / §11-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // reader(チェーン role)+ read スコープで取得可(pull と同一行 — §12-3)
    const readScope: readonly TokenScope[] = [{ project: projectId, permission: "read" }];
    const readToken = await deviceToken(9003, readScope);
    const allowed = await requestJson("GET", `/environments/${ENV}/pull/metadata`, readToken);
    expect(allowed.status).toBe(200);

    // 非メンバーは 404(存在秘匿 — §11-2)
    const stranger = await requestJson(
      "GET",
      `/environments/${ENV}/pull/metadata`,
      token(STRANGER),
    );
    expect(stranger.status).toBe(404);

    // スコープ外プロジェクトも 404(存在秘匿はスコープ検査が先行)
    const otherScope: readonly TokenScope[] = [{ project: "ff".repeat(32), permission: "admin" }];
    const scoped = await deviceToken(9002, otherScope);
    const concealed = await requestJson("GET", `/environments/${ENV}/pull/metadata`, scoped);
    expect(concealed.status).toBe(404);

    // 削除済み環境は 404(pull と同じ)。READER のトークンは readToken の
    // 再発行で置換済みのため、以後は readToken を使う
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const gone = await requestJson("GET", `/environments/${ENV}/pull/metadata`, readToken);
    expect(gone.status).toBe(404);
  });
});

describe("セッション主体の一括 pull の CSRF ヘッダー(§12-7 — セキュリティレビュー L-1)", () => {
  it("requires the CSRF header for session pulls with values; bearer and metadata-only are exempt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);

    // ヘッダーなしのセッション pull(値付き)は 403。Lax クッキーはクロスサイトの
    // トップレベル遷移でも同送されるため、これを許すと第三者サイトが被害者の
    // セッションで偽の var.read を刻める(監査証跡の汚染)
    const withoutCsrf = await SELF.fetch(dataUrl(`/environments/${ENV}/pull`), {
      headers: { cookie: headers["cookie"] ?? "" },
    });
    expect(withoutCsrf.status).toBe(403);
    const body = (await withoutCsrf.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("csrf-header-required");

    // 拒否された pull は var.read を 1 行も記録しない(読んでいないものを
    // 読んだと記録しない — AUDIT_SPEC §3.3)
    const reads = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(reads[0]?.["n"]).toBe(0);

    // ヘッダーありのセッション pull は従来どおり 200 で、今度は var.read が
    // 記録される(positive control — 監査記録経路そのものが生きていることの裏取り)
    const withCsrf = await SELF.fetch(dataUrl(`/environments/${ENV}/pull`), { headers });
    expect(withCsrf.status).toBe(200);
    const readsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read'",
    );
    expect(readsAfter[0]?.["n"]).toBe(1);

    // Bearer はクロスサイトで付与できないため対象外(ヘッダーなしで 200)
    const bearerPull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(bearerPull.status).toBe(200);

    // メタデータのみモードは var.read を記録しないため対象外(セッション +
    // ヘッダーなしで 200 — §12-7)
    const metadata = await SELF.fetch(dataUrl(`/environments/${ENV}/pull/metadata`), {
      headers: { cookie: headers["cookie"] ?? "" },
    });
    expect(metadata.status).toBe(200);
  });
});
