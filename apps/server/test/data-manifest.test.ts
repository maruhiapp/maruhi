// データプレーン API(AUTH_SPEC §12)の統合テスト — 環境マニフェストの複合受理
// (AUTH_SPEC §12-5 = CRYPTO_SPEC §4.3。PR-M1)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
//
// session-27 §13-5 のマニフェスト項の実装テスト: メタ操作との複合受理 /
// manifestVersion CAS(409 は最新番号のみ)/ サーバーのダイジェスト再計算 /
// 保持は最新 1 通のみ / pull 両モードへの同梱(tombstone 込み)/ 環境削除
// カスケード / 移行経路(マニフェスト導入前の環境の rotate による v1 初期化)。

import { describe, expect, it } from "vitest";

import {
  commitmentOf,
  digestOf,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEnvManifestAs,
  signMetaStatementAs,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  envMetaOf,
  MEMBER,
  nextEnvironmentManifest,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fakePayload,
  fixture,
  manifestForStatement,
  nextVariableStatement,
  registerDataScenario,
  renameVariableRequest,
  token,
  unsignedManifest,
  VAR,
  variableStatementFor,
  varStatements,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

interface WireManifestBody {
  readonly manifest?: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly issuerUserId: string;
    readonly issuerKeyFingerprintHex: string;
  };
}

async function manifestRows(): Promise<readonly Record<string, unknown>[]> {
  return queryProjectDo(
    projectId,
    "SELECT environment_id, manifest_version, epoch, variables_digest_hex, issuer_user_id FROM environment_manifests ORDER BY environment_id",
  );
}

describe("環境マニフェストの複合受理(§12-5 = CRYPTO_SPEC §4.3)", () => {
  it("issues v1 on creation and re-issues on every meta op, keeping only the latest row (§12-5 / §12-8)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // 作成直後: manifestVersion 1・変数空集合・epoch 1
    expect(await manifestRows()).toEqual([
      {
        environment_id: ENV,
        manifest_version: 1,
        epoch: 1,
        variables_digest_hex: await digestOf([]),
        issuer_user_id: OWNER,
      },
    ]);

    // 変数作成 → v2(集合に新変数)。行は置き換わり蓄積しない(保持は最新 1 通)
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const afterCreate = await manifestRows();
    expect(afterCreate.length).toBe(1);
    expect(afterCreate[0]).toMatchObject({ manifest_version: 2, epoch: 1, issuer_user_id: MEMBER });

    // rename → v3、削除 → v4(tombstone 込みダイジェスト)、環境 rename → v5
    expect((await renameVariableRequest(VAR, "DB_URL", MEMBER)).status).toBe(204);
    expect((await deleteVariableRequest(VAR, MEMBER)).status).toBe(204);
    expect((await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER)).status).toBe(204);
    const rows = await manifestRows();
    expect(rows.length).toBe(1);
    expect(rows[0]).toMatchObject({ manifest_version: 5, epoch: 1 });
    // v4 以降のダイジェストは tombstone を含む集合(サーバー再計算と一致した申告)
    const recorded = fixture.manifests.get(ENV);
    if (recorded === undefined) throw new Error("missing recorded manifest");
    expect(recorded.entries).toEqual([
      expect.objectContaining({ variableId: VAR, status: "deleted", metaVersion: 3 }),
    ]);
    expect(rows[0]?.["variables_digest_hex"]).toBe(await digestOf(recorded.entries));
  });

  it("distributes the latest manifest with issuer info in both pull modes (§12-7)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await deleteVariableRequest(VAR, MEMBER);

    for (const path of [`/environments/${ENV}/pull`, `/environments/${ENV}/pull/metadata`]) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status).toBe(200);
      const body = (await response.json()) as WireManifestBody;
      expect(body.manifest).toMatchObject({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 3,
        // tombstone 込みの集合のダイジェスト(§12-7 — 両モード同水準)
        variablesDigestHex: fixture.manifests.get(ENV)?.manifest.variablesDigestHex,
        issuerUserId: MEMBER,
      });
      expect(body.manifest).toHaveProperty("issuerKeyFingerprintHex");
      expect(body.manifest).not.toHaveProperty("signedBytesHashHex");
    }
  });

  it("recomputes the digest server-side: omitting the new variable or the tombstone is 422 manifest-digest-mismatch (§12-5 (7))", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");

    // 変数作成のマニフェストが新変数のエントリを含まない(空集合のまま)
    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const emptyDigest = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const omitted = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: emptyDigest,
    });
    expect(omitted.status).toBe(422);
    await expect(omitted.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "manifest-digest-mismatch",
    });
    // 原子性: 変数行・ステートメント行・マニフェスト行のいずれも進まない
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM variables WHERE environment_id = ? AND variable_id = ?",
      ENV,
      VAR,
    );
    expect(rows.length).toBe(0);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1 });

    // 削除のマニフェストが tombstone を落とす(空集合へ戻す)
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const last = varStatements.get(VAR);
    if (last === undefined) throw new Error("missing recorded statement");
    const deleteStatement = await nextVariableStatement({
      variableId: VAR,
      name: last.statement.name,
      status: "deleted",
      authorUserId: MEMBER,
    });
    const tombstoneHidden = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const hid = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement: deleteStatement, manifest: tombstoneHidden },
    );
    expect(hid.status).toBe(422);
    await expect(hid.json()).resolves.toMatchObject({ reason: "manifest-digest-mismatch" });
  });

  it("rejects a manifest bound to a stale env-meta statement (422 manifest-digest-mismatch — §12-5 (7))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 環境 rename のマニフェストが旧 envMeta(metaVersion 1)を写している形は、
    // rename 適用後の再計算(metaVersion 2)と一致しない
    const staleEnvMeta = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 1,
      entries: [],
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    const recorded = fixture.envStatements.get(ENV);
    if (recorded === undefined) throw new Error("missing recorded env statement");
    const renameStatement = await signMetaStatementAs(MEMBER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      name: "App2",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(
        projectId,
        recorded.statement,
        recorded.authorUserId,
      ),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson("PATCH", `/environments/${ENV}`, token(MEMBER), {
      statement: renameStatement,
      manifest: staleEnvMeta,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({ reason: "manifest-digest-mismatch" });
  });

  it("rejects a manifest whose epoch is not current at the declared head (422 manifest-epoch-mismatch — §12-5 (4))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const staleEpoch = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      // 現エポックは 1 — 2 を焼き込んだマニフェストはエポック整合で落ちる
      epoch: 2,
      manifestVersion: 2,
      variablesDigestHex: await digestOf([
        {
          variableId: VAR,
          status: "active",
          metaVersion: 1,
          metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
        },
      ]),
      envMetaVersion: 1,
      envMetaSigHashHex: (await envMetaOf(fixture, ENV)).sigHashHex,
      prevManifestSigHashHex: await (async () => {
        const last = fixture.manifests.get(ENV);
        if (last === undefined) throw new Error("missing manifest");
        return manifestSignedBytesHashOf(projectId, last.manifest, last.issuerUserId);
      })(),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: staleEpoch,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "manifest-epoch-mismatch",
    });
  });

  it("enforces the manifestVersion CAS with the number only (409 §12-5 (6))", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 最新は 2。申告 4(prev はダミー)→ 409 currentManifestVersion 2。
    // 勝者のハッシュは載せない(§12-5 の 409 規律)
    const statement = await nextVariableStatement({
      variableId: VAR,
      name: "DB_URL",
      status: "active",
      authorUserId: MEMBER,
    });
    const stale = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 4,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: 1,
      envMetaSigHashHex: (await envMetaOf(fixture, ENV)).sigHashHex,
      prevManifestSigHashHex: "cd".repeat(32),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const response = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { statement, manifest: stale },
    );
    expect(response.status).toBe(409);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      _tag: "ManifestVersionConflict",
      currentManifestVersion: 2,
    });
    expect(Object.keys(body).filter((key) => key.toLowerCase().includes("hash"))).toEqual([]);
    // metaVersion CAS と同一トランザクション: ステートメント行も進まない
    const rows = await queryProjectDo(
      projectId,
      "SELECT meta_version FROM variable_meta_statements WHERE environment_id = ? AND variable_id = ? ORDER BY meta_version",
      ENV,
      VAR,
    );
    expect(rows.map((row) => row["meta_version"])).toEqual([1]);
  });

  it("rejects a manifest signed by someone other than the caller (422 signature-invalid — §12-5 (1))", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const statement = await variableStatementFor(MEMBER, VAR, "DATABASE_URL");
    const { manifest } = await manifestForStatement(statement, OWNER);
    // OWNER が署名したマニフェストを MEMBER が持ち込む → 検証鍵は呼び出し主体
    const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement,
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest,
    });
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "ManifestRejected",
      reason: "signature-invalid",
    });
  });

  it("requires the manifest on every meta-op path (400 schema) and checks its coordinates (422)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // マニフェスト欠落はワイヤ Schema の 400
    const missing = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
    });
    expect(missing.status).toBe(400);
    // 座標不一致(manifestEnvironmentId)は worker の自己整合検査の 422
    const wrongEnv = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
      statement: await variableStatementFor(MEMBER, VAR, "DATABASE_URL"),
      value: await fakePayload(MEMBER, aadFor(1, 1)),
      manifest: { ...unsignedManifest(), environmentId: "env-other-0002" },
    });
    expect(wrongEnv.status).toBe(422);
    expect(((await wrongEnv.json()) as { field: string }).field).toBe("manifestEnvironmentId");
  });

  it("re-issues the manifest with the new epoch on rotation and retries after a head-CAS conflict (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 親ヘッド CAS 失敗(409): マニフェストは受理されず記録も進まない
    const conflicted = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: "ee".repeat(32),
    });
    expect(conflicted.status).toBe(409);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 1, epoch: 1 });

    // 再試行(エントリとマニフェストの両方を現ヘッドで再署名 — フィクスチャが担う)
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    expect((await manifestRows())[0]).toMatchObject({ manifest_version: 2, epoch: 2 });

    // rotate 複合のマニフェスト epoch が new_epoch と食い違う形は複合内整合検査で 422
    const mismatched = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: "ab".repeat(32),
      manifest: await nextEnvironmentManifest(fixture, {
        environmentId: ENV,
        epoch: 2,
        entries: [],
        envMeta: await envMetaOf(fixture, ENV),
        issuerUserId: MEMBER,
        head: fixture.head,
      }),
    });
    expect(mismatched.status).toBe(422);
    expect(((await mismatched.json()) as { field: string }).field).toBe("manifestEpoch");
  });

  it("initializes manifestVersion 1 through a rotation for a pre-manifest environment (移行経路 — session-27 §14)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // マニフェスト導入前に作成された環境を、保存行の削除でシミュレートする
    await queryProjectDo(
      projectId,
      "DELETE FROM environment_manifests WHERE environment_id = ?",
      ENV,
    );
    // pull はマニフェストなしで応答する(過渡状態 — クライアント側が拒否を担う)
    const pulled = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect((await pulled.json()) as WireManifestBody).not.toHaveProperty("manifest");

    // rotate 複合が manifestVersion 1(prev 空)を確立する(CAS 初期値 = 0)
    const entries = fixture.manifests.get(ENV)?.entries ?? [];
    fixture.manifests.delete(ENV);
    const manifest = await nextEnvironmentManifest(fixture, {
      environmentId: ENV,
      epoch: 2,
      entries,
      envMeta: await envMetaOf(fixture, ENV),
      issuerUserId: MEMBER,
      head: fixture.head,
    });
    expect(manifest.manifestVersion).toBe(1);
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, makeDek()),
      manifest,
    });
    expect(response.status).toBe(200);
    expect((await manifestRows())[0]).toMatchObject({
      manifest_version: 1,
      epoch: 2,
      variables_digest_hex: await digestOf(entries),
    });
    const afterInit = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(((await afterInit.json()) as WireManifestBody).manifest).toMatchObject({
      manifestVersion: 1,
      epoch: 2,
    });
  });

  it("cascades the manifest row on environment deletion (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    expect((await manifestRows()).length).toBe(1);
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    expect((await manifestRows()).length).toBe(0);
  });
});
