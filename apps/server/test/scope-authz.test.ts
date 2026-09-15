// ES K3 — 環境対象 op の scope 認可(AUTH_SPEC §9-2 / §12-3 / §12-7 = CRYPTO_SPEC §6.2
// の検証状態が導出した scope の受理面。設計録 docs/notes/es-design.md §9 K3-A / K3-B /
// K3-C / K3-G)。@cloudflare/vitest-plugin(workerd 実環境)で SELF 経由の HttpApi を検証する。
//
// 固定する規則(§12-3 の表の各行を 1 つずつ):
//   1. 値付き pull・自分宛 DEK 取得 = 環境 ∈ scope(403 insufficient-scope)
//   2. メタのみ pull・環境一覧 = 不問(全環境。advisory の scope 欄は載せない — §12-7)
//   3. 変数の作成 / push / 改名 / 削除・環境の改名・DEK ラップ登録 = 環境 ∈ scope
//   4. 環境の作成 = scope = all
//   5. 環境の削除・DEK ラップの削除 = 環境 ∈ scope(admin)
//   - 判定順: role 403 → scope 403 → 存在 404(listed の主体には未存在環境も 403)
//   - rotate / checkpoint の 403 は合意規則 environment-out-of-scope(422)より先
//   - 認可時点の二重判定の scope 軸(3′)は chain-head-state-mismatch に畳む(K3-B)

import type { ChainOperation } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import {
  addMemberOperation,
  changeRoleOperation,
  checkpointOperation,
  commitmentOf,
  createVariableStatement,
  encryptValue,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valueSignedBytesHashOf,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekTo,
  type WireEncryptedPayload,
  type WireVariableMetaStatement,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  seedMemberToken,
  storedCheckpointValues,
  tokenOf,
} from "./support/data-fixture.ts";
import {
  aadFor,
  ENV,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

/** listed メンバー(ベクター鍵 — data-crypto.ts の vectorKeyOf)。 */
const DEV = "user-devmember-0010";
const DEVADMIN = "user-devadmin-0011";
const OTHER = "env-other-0002";
const GHOST = "env-ghost-9999";

async function expectForbidden(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(403);
  expect(((await response.json()) as { reason: string }).reason).toBe(reason);
}

const expectScopeForbidden = (response: Response): Promise<void> =>
  expectForbidden(response, "insufficient-scope");

/**
 * 2 環境(ENV / OTHER)を作り、DEV を member・listed{ENV} で追加する。listed の
 * scope は作成済み環境しか列挙できない(合意規則 unknown-environment)ため、環境
 * 作成が先。既存環境のラップ完全集合は追加前の R(E)(= ALL_MEMBERS)のまま。
 */
async function setupListed(): Promise<{ envDek: Uint8Array; otherDek: Uint8Array }> {
  const envDek = await createEnvironmentOk(fixture, ENV, "App");
  const otherDek = await createEnvironmentOk(fixture, OTHER, "Other");
  await seedMemberToken(fixture, DEV, 9010);
  await appendOperation(fixture, OWNER, addMemberOperation(DEV, "member", [ENV]));
  return { envDek, otherDek };
}

/** 任意の主体が任意環境に変数を作る(値 v1 + ステートメント + マニフェスト)。 */
async function createVariableAs(input: {
  readonly writer: string;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly variableId: string;
  readonly name: string;
}): Promise<{ value: WireEncryptedPayload; statement: WireVariableMetaStatement }> {
  const value = await encryptValue(
    input.dek,
    {
      projectId,
      environmentId: input.environmentId,
      epoch: 1,
      variableId: input.variableId,
      version: 1,
    },
    `${input.name}-plaintext`,
    { writerUserId: input.writer, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: input.writer,
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: input.writer,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, input.writer),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(input.writer),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
  return { value, statement };
}

/** 汎用 append を生で叩く(appendOperation は 200 を assert するため negative 用)。 */
async function appendRaw(actorUserId: string, operation: ChainOperation): Promise<Response> {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation,
  });
  return SELF.fetch(`${BASE}/projects/${projectId}/chain/entries`, {
    method: "POST",
    headers: { ...JSON_HEADERS, ...bearer(tokenOf(fixture.tokens, actorUserId)) },
    body: JSON.stringify({ parentHeadHashHex: fixture.head.hashHex, entry }),
  });
}

/** 当該環境の現状態(保存済みマニフェスト + 値列挙)を公証する standalone checkpoint。 */
async function checkpointFor(environmentId: string, epoch: number): Promise<ChainOperation> {
  const last = fixture.manifests.get(environmentId);
  if (last === undefined) {
    throw new Error(`no recorded manifest for ${environmentId}`);
  }
  return checkpointOperation({
    environmentId,
    epoch,
    manifestVersion: last.manifest.manifestVersion,
    manifestSigHashHex: await manifestSignedBytesHashOf(
      projectId,
      last.manifest,
      last.issuerUserId,
    ),
    valuesDigestHex: await valuesDigestOf(await storedCheckpointValues(environmentId)),
  });
}

/** 環境メタステートメント(未署名のダミー — 403 は署名検証より前に確定する)。 */
function unsignedEnvStatement(environmentId: string, name: string, status: "active" | "deleted") {
  return {
    suite: "maruhi/v1",
    environmentId,
    name,
    status,
    metaVersion: 2,
    prevMetaSigHashHex: "cd".repeat(32),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: "00".repeat(64),
  };
}

describe("scope 認可 — 読み取り系(§12-3 の 1〜2 行目 / §12-7)", () => {
  it("値付き pull と自分宛 DEK 取得は環境 ∈ scope: scope 内 200、scope 外 403 insufficient-scope(var.read も残さない)", async () => {
    await setupListed();
    expect((await requestJson("GET", `/environments/${ENV}/pull`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/pull`, token(DEV)));
    expect((await requestJson("GET", `/environments/${ENV}/deks`, token(DEV))).status).toBe(200);
    await expectScopeForbidden(await requestJson("GET", `/environments/${OTHER}/deks`, token(DEV)));
    // fail-closed: 拒否した pull は var.read を記録しない(§12-7 の記録条件 =
    // 暗号文を返したこと。scope 外は返していない)
    const reads = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'var.read' AND actor_user_id = ? AND environment_id = ?",
      DEV,
      OTHER,
    );
    expect(reads[0]?.["n"]).toBe(0);
  });

  it("メタのみ pull と環境一覧は scope 不問で、応答に advisory の scope 欄を載せない(§12-7)", async () => {
    await setupListed();
    const metadata = await requestJson("GET", `/environments/${OTHER}/pull/metadata`, token(DEV));
    expect(metadata.status).toBe(200);
    const list = await requestJson("GET", "/environments", token(DEV));
    expect(list.status).toBe(200);
    const body = (await list.json()) as { environments: Record<string, unknown>[] };
    expect(body.environments.map((environment) => environment["environmentId"]).toSorted()).toEqual(
      [ENV, OTHER].toSorted(),
    );
    for (const environment of body.environments) {
      // クライアントは検証済みチェーンから自分の scope を導出する — サーバー申告の
      // 「scope 内か」を検証規則の入力にしない(§12-7)
      expect(Object.keys(environment).toSorted()).toEqual(
        ["currentEpoch", "environmentId", "statement"].toSorted(),
      );
    }
  });
});

describe("scope 認可 — 書き込み系(§12-3 の 3〜5 行目)", () => {
  it("変数の作成 / push / 改名 / 削除・環境の改名・DEK ラップ登録は環境 ∈ scope(scope 外は 403、scope 内は受理)", async () => {
    const { envDek } = await setupListed();
    const otherAad = (version: number, variableId = VAR) =>
      aadFor(1, version, { environmentId: OTHER, variableId });
    // 作成(declared / active を問わず同じ経路)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables`, token(DEV), {
        statement: { ...unsignedVariableStatement("var-x", "X"), environmentId: OTHER },
        value: unsignedPayload(otherAad(1, "var-x")),
        manifest: unsignedManifest(OTHER),
      }),
    );
    // push(変数の存在に依らず scope が先)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/variables/${VAR}/versions`, token(DEV), {
        value: unsignedPayload(otherAad(2)),
      }),
    );
    // 改名 / スキーマ再発行
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "RENAMED"),
          environmentId: OTHER,
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    // 削除
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/variables/${VAR}`, token(DEV), {
        statement: {
          ...unsignedVariableStatement(VAR, "DATABASE_URL"),
          environmentId: OTHER,
          status: "deleted",
          metaVersion: 2,
          prevMetaSigHashHex: "cd".repeat(32),
        },
        manifest: unsignedManifest(OTHER),
      }),
    );
    // 環境の改名
    await expectScopeForbidden(
      await requestJson("PATCH", `/environments/${OTHER}`, token(DEV), {
        statement: unsignedEnvStatement(OTHER, "Renamed", "active"),
        manifest: unsignedManifest(OTHER),
      }),
    );
    // DEK ラップ登録(登録者 = 署名者 = 呼び出し主体の scope — §12-6 末尾 =
    // §12-3 と同一判定 → 403。受信者軸の 422 より先)
    await expectScopeForbidden(
      await requestJson("POST", `/environments/${OTHER}/deks`, token(DEV), {
        deks: [
          await wrapDekTo({
            projectId,
            environmentId: OTHER,
            epoch: 1,
            dek: makeDek(),
            recipientUserId: DEV,
            signerUserId: DEV,
          }),
        ],
      }),
    );
    // scope 内の書き込みは受理される(listed member の正例)
    await createVariableAs({
      writer: DEV,
      environmentId: ENV,
      dek: envDek,
      variableId: "var-dev",
      name: "DEV_ONLY",
    });
  });

  it("環境の削除と DEK ラップの削除は admin × 環境 ∈ scope(listed admin の scope 外は 403)", async () => {
    await setupListed();
    await seedMemberToken(fixture, DEVADMIN, 9011);
    await appendOperation(fixture, OWNER, addMemberOperation(DEVADMIN, "admin", [ENV]));
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}`, token(DEVADMIN), {
        statement: unsignedEnvStatement(OTHER, "Other", "deleted"),
      }),
    );
    await expectScopeForbidden(
      await requestJson("DELETE", `/environments/${OTHER}/deks`, token(DEVADMIN), {
        wraps: [{ epoch: 1, recipientUserId: OWNER }],
      }),
    );
    // scope 内の環境削除は受理される(admin の正例)
    expect((await deleteEnvironmentRequest(fixture, ENV, DEVADMIN)).status).toBe(204);
  });

  it("判定順: role 403 → scope 403 → 存在 404(listed の主体には未存在環境も 403、all の主体は 404)", async () => {
    await setupListed();
    // role が先: member の DEV が admin 操作(環境削除)を scope 外に対して行う
    await expectForbidden(
      await requestJson("DELETE", `/environments/${OTHER}`, token(DEV), {
        statement: unsignedEnvStatement(OTHER, "Other", "deleted"),
      }),
      "insufficient-role",
    );
    // scope が存在より先: 未作成の環境 id は listed の scope に含まれえない
    await expectScopeForbidden(await requestJson("GET", `/environments/${GHOST}/pull`, token(DEV)));
    const ghostRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: GHOST,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(ghostRotate);
    // all の主体は従来どおり存在 404(K3 単独デプロイでの不変性)
    expect((await requestJson("GET", `/environments/${GHOST}/pull`, token(MEMBER))).status).toBe(
      404,
    );
  });
});

describe("scope 認可 — チェーン op を伴う経路(§9-2 / §12-3 の 4 行目。403 が合意規則 422 より先 — K3-G)", () => {
  it("環境の作成は scope = all(listed の member / admin は 403)、rotate は環境 ∈ scope", async () => {
    await setupListed();
    const creation = await createEnvironmentComposite(fixture, {
      environmentId: "env-new-0003",
      name: "New",
      deks: await wrapDekForAll({
        projectId,
        environmentId: "env-new-0003",
        epoch: 1,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: DEV,
      }),
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(creation);
    const otherRotate = await rotateEnvironmentComposite(fixture, {
      environmentId: OTHER,
      newEpoch: 2,
      deks: [],
      dekCommitmentHex: "ab".repeat(32),
      actorUserId: DEV,
    });
    await expectScopeForbidden(otherRotate);
    // scope 内の rotate は受理される。完全集合は R(ENV) = 全 all メンバー + DEV
    const dek = makeDek();
    const rotated = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek,
        recipientUserIds: [...ALL_MEMBERS, DEV],
        signerUserId: DEV,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek),
      actorUserId: DEV,
    });
    expect(rotated.status).toBe(200);
  });

  it("standalone checkpoint は全タプルの環境 ∈ scope(scope 外タプルは 403、scope 内のみなら受理)", async () => {
    await setupListed();
    await expectScopeForbidden(await appendRaw(DEV, await checkpointFor(OTHER, 1)));
    await appendOperation(fixture, DEV, await checkpointFor(ENV, 1));
  });
});

describe("認可時点の二重判定の scope 軸(§12-3 / CRYPTO_SPEC §6.3 の 3′ — K3-B)", () => {
  it("受理時点は scope 内・宣言ヘッド時点は scope 外の値 / メタ / マニフェストは 422 chain-head-state-mismatch(役割軸と同じ畳み込み)", async () => {
    const { otherDek } = await setupListed();
    const created = await createVariableAs({
      writer: OWNER,
      environmentId: OTHER,
      dek: otherDek,
      variableId: "var-o",
      name: "OTHER_SECRET",
    });
    // 拡大前のヘッド(DEV の scope は {ENV})
    const oldHead = { ...fixture.head };
    await appendOperation(fixture, OWNER, changeRoleOperation(DEV, "member", [ENV, OTHER]));

    // 値: 受理時点(現ヘッド)では OTHER ∈ scope なので 403 は通り、宣言ヘッド
    // 時点(拡大前)で scope 外 → 3′ の拒否
    const stale = await encryptValue(
      otherDek,
      { projectId, environmentId: OTHER, epoch: 1, variableId: "var-o", version: 2 },
      "stale-head",
      {
        writerUserId: DEV,
        head: oldHead,
        prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
      },
    );
    const staleValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: stale },
    );
    expect(staleValue.status).toBe(422);
    expect(((await staleValue.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // メタ: 改名ステートメントの宣言ヘッドが拡大前
    const staleStatement = await signMetaStatementAs(DEV, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: OTHER,
      variableId: "var-o",
      name: "OTHER_SECRET_RENAMED",
      status: "active" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, created.statement, OWNER),
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const { manifest: freshManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, staleStatement, DEV),
      },
    });
    const staleMeta = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: staleStatement, manifest: freshManifest },
    );
    expect(staleMeta.status).toBe(422);
    expect(((await staleMeta.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // マニフェスト: ステートメントは現ヘッド、マニフェストだけ拡大前のヘッド
    const freshStatement = await signMetaStatementAs(DEV, projectId, {
      ...staleStatement,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const { manifest: baseManifest } = await manifestForVariableOp(fixture, {
      environmentId: OTHER,
      issuerUserId: DEV,
      entry: {
        variableId: "var-o",
        status: "active",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, freshStatement, DEV),
      },
    });
    const { signatureHex: _signatureHex, ...unsignedManifestBody } = baseManifest;
    const staleManifest = await signEnvManifestAs(DEV, projectId, {
      ...unsignedManifestBody,
      chainHeadHashHex: oldHead.hashHex,
      chainHeadSeq: oldHead.seq,
    });
    const staleManifestResponse = await requestJson(
      "PATCH",
      `/environments/${OTHER}/variables/var-o`,
      token(DEV),
      { statement: freshStatement, manifest: staleManifest },
    );
    expect(staleManifestResponse.status).toBe(422);
    expect(((await staleManifestResponse.json()) as { reason: string }).reason).toBe(
      "chain-head-state-mismatch",
    );

    // 現ヘッドを宣言した同じ書き込みは受理される(受理時点・宣言ヘッド時点とも
    // scope 内 — 3′ だけが落としていたことの確認)
    const fresh = await encryptValue(
      otherDek,
      { projectId, environmentId: OTHER, epoch: 1, variableId: "var-o", version: 2 },
      "fresh-head",
      {
        writerUserId: DEV,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(created.value, OWNER),
      },
    );
    const freshValue = await requestJson(
      "POST",
      `/environments/${OTHER}/variables/var-o/versions`,
      token(DEV),
      { value: fresh },
    );
    expect(freshValue.status).toBe(200);
  });
});
