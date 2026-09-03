// データプレーン API(AUTH_SPEC §12)の統合テスト — エポックとローテーション
// (§12-4 複合 / §12-5 / §12-6 / CRYPTO_SPEC §7)・境界 checkpoint の複合内整合
// (§12-4 / CRYPTO_SPEC §4.3 (2))。
// @cloudflare/vitest-plugin(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 環境管理・複合作成の DEK ラップ検証は data-environment.test.ts(分割の動機は
// support/membership-scenario.ts 冒頭を参照)。

import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  commitmentOf,
  createEnvironmentOperation,
  encryptValue,
  makeDek,
  signEntryAt,
  unwrapAndDecrypt,
  valueSignedBytesHashOf,
  valuesDigestOf,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentComposite,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
} from "./support/data-fixture.ts";
import {
  aadFor,
  createVariableOk,
  ENV,
  fakePayload,
  fixture,
  registerDataScenario,
  token,
  VAR,
  wrapsFor,
} from "./support/data-scenario.ts";

registerDataScenario();
describe("エポックとローテーション(§12-4 複合 / §12-5 / §12-6 / CRYPTO_SPEC §7)", () => {
  it("accepts pushes only under the current chain epoch and completes the composite rotation flow", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const varV1 = await createVariableOk(dek1, VAR, "DATABASE_URL", "postgres://alpha");
    await createVariableOk(dek1, "var-static", "STATIC_KEY", "static-secret");

    // ローテーション前の未来エポック push も拒否
    const early = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(2, 2)) },
    );
    expect(early.status).toBe(409);
    await expect(early.json()).resolves.toMatchObject({ currentEpoch: 1 });

    // ローテーションは複合リクエスト(§12-4): 部分集合の同梱は 422 recipient-missing
    // で、チェーンエントリも追記されない(原子性)
    const dek2 = makeDek();
    const headBefore = fixture.head;
    const partial = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: [OWNER],
      signerUserId: MEMBER,
    });
    const rejected = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: partial,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(rejected.status).toBe(422);
    expect(((await rejected.json()) as { reason: string }).reason).toBe("recipient-missing");
    const chainAfterRejection = await requestJson("GET", "/chain", token(READER));
    expect(((await chainAfterRejection.json()) as { headSeq: number }).headSeq).toBe(
      headBefore.seq,
    );

    // 完全集合の複合ローテーション → エポック 2 へ(チェーン追記 + ラップ登録が原子)
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // 受理される正例はラップした DEK 自身のコミットメント(session-31 M1-T1)
    const rotation = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: complete,
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
    });
    expect(rotation.status).toBe(200);
    // 複合は rotate(H+1)+ 境界 checkpoint(H+2)の 2 エントリを追記する(§12-4)
    await expect(rotation.clone().json()).resolves.toMatchObject({
      environmentId: ENV,
      currentEpoch: 2,
      headSeq: headBefore.seq + 2,
    });

    // 旧エポックの push は 409(現エポックを返す — クライアントは再暗号化して再試行)
    const stale = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: await fakePayload(MEMBER, aadFor(1, 2)) },
    );
    expect(stale.status).toBe(409);
    await expect(stale.json()).resolves.toMatchObject({ currentEpoch: 2 });

    // 既存 (エポック, 受信者) の上書きは禁止(409 DekWrapExists)
    const overwrite = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: makeDek(),
        recipientUserIds: [READER],
        signerUserId: MEMBER,
      }),
    });
    expect(overwrite.status).toBe(409);
    const overwriteBody = (await overwrite.json()) as { epoch: number; recipientUserId: string };
    expect(overwriteBody).toMatchObject({ epoch: 2, recipientUserId: READER });

    // 未来エポック(3)宛の登録は 422 epoch-out-of-range
    const future = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 3,
        dek: makeDek(),
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(future.status).toBe(422);
    expect(((await future.json()) as { reason: string }).reason).toBe("epoch-out-of-range");

    // 新エポックで再暗号化した値を push(var-static は当時のエポックのまま保持 — §7)。
    // 宣言ヘッド = rotate エントリを含む現ヘッド、prev は v1 へ連鎖、エポックは
    // 単調(1 → 2)— ローテーション実行フローの §4.1 の形
    const v2 = await encryptValue(
      dek2,
      { projectId, environmentId: ENV, epoch: 2, variableId: VAR, version: 2 },
      "postgres://rotated",
      {
        writerUserId: MEMBER,
        head: fixture.head,
        prevValueSigHashHex: await valueSignedBytesHashOf(varV1, MEMBER),
      },
    );
    const pushed = await requestJson(
      "POST",
      `/environments/${ENV}/variables/${VAR}/versions`,
      token(MEMBER),
      { value: v2 },
    );
    expect(pushed.status).toBe(200);
    await expect(pushed.json()).resolves.toEqual({ variableId: VAR, version: 2, epoch: 2 });

    // pull: 現エポック 2、最新バージョンのエポックは変数ごとに異なる。全エポックの
    // 自分宛ラップが同梱され、両方のエポックの値をクライアント側で復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      currentEpoch: number;
      variables: { variableId: string; value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    expect(body.currentEpoch).toBe(2);
    expect(body.deks.map((wrap) => wrap.epoch)).toEqual([1, 2]);
    const rotated = body.variables.find((v) => v.variableId === VAR);
    const kept = body.variables.find((v) => v.variableId === "var-static");
    if (rotated === undefined || kept === undefined) throw new Error("missing pulled variables");
    expect(rotated.value.aad.epoch).toBe(2);
    expect(kept.value.aad.epoch).toBe(1);
    const dekByEpoch = new Map(body.deks.map((wrap) => [wrap.epoch, wrap]));
    const wrap1 = dekByEpoch.get(1);
    const wrap2 = dekByEpoch.get(2);
    if (wrap1 === undefined || wrap2 === undefined) throw new Error("missing dek wraps");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap2,
        projectId,
        environmentId: ENV,
        payload: rotated.value,
      }),
    ).resolves.toBe("postgres://rotated");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap1,
        projectId,
        environmentId: ENV,
        payload: kept.value,
      }),
    ).resolves.toBe("static-secret");
  });

  it("rejects a rotation to a deleted environment with 404 (§12-4: §7 の「全環境」は削除済みを含まない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removed.status).toBe(204);
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { environmentId: string }).environmentId).toBe(ENV);
  });

  it("rejects a rotation to an environment that was never created with 404", async () => {
    // 環境の存在はチェーン導出 + データ行(複合で原子的に作られる)。未作成の
    // 環境への rotate はデータ行の不在 = 404(unknown-environment の合意規則は
    // crypto 層のベクターが固定する — サーバーではデータ行検査が先に立つ)
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-ghost-9999",
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: "env-ghost-9999",
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(404);
  });

  it("rejects an out-of-sequence rotation with 422 chain-entry-invalid (epoch-out-of-sequence)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 3,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // 現エポック 1 からの rotate は 2 のみ(CRYPTO_SPEC §6.3 — verifyChain が権威)
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 3,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-sequence");
  });

  it("rejects a rotation whose URL and entry name different environments (422 PayloadMismatch)", async () => {
    // 複合内整合検査(§12-4): 別環境のエントリ × 別環境の URL の組を受理しない
    await createEnvironmentOk(fixture, ENV, "App");
    await createEnvironmentOk(fixture, "env-app-0002", "Staging");
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      urlEnvironmentId: "env-app-0002",
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { field: string }).field).toBe("environmentId");
  });

  it("rejects composite wraps whose epoch differs from the entry's new epoch (422 epoch-out-of-range)", async () => {
    // §12-4 の複合内整合検査: 同梱ラップの epoch = エントリの new_epoch。
    // エポック 1 宛(登録済みエポック)のラップを rotate 複合に紛れ込ませても拒否
    await createEnvironmentOk(fixture, ENV, "App");
    const headBefore = fixture.head;
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("epoch-out-of-range");
    // 原子性: エントリも追記されない(エポックは 1 のまま)
    const chain = await requestJson("GET", "/chain", token(READER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore.seq);
    const list = await requestJson("GET", "/environments", token(READER));
    const listBody = (await list.json()) as { environments: { currentEpoch: number }[] };
    expect(listBody.environments[0]?.currentEpoch).toBe(1);
  });

  it("retries a composite rotation after a head CAS conflict (§12-4 の再署名リトライ)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const stale = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
      parentHeadHashHex: projectId, // genesis ハッシュ = 古いヘッド
    });
    expect(stale.status).toBe(409);
    const staleBody = (await stale.json()) as { currentHeadHashHex: string };
    expect(staleBody.currentHeadHashHex).toBe(fixture.head.hashHex);
    // 正しい親ヘッドで作り直したエントリ(再署名)は受理される
    const retried = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks,
      dekCommitmentHex: "ab".repeat(32),
    });
    expect(retried.status).toBe(200);
  });
});

/**
 * 独自タプルの境界 checkpoint を OWNER 署名で作る(同梱物一致の negative 用)。
 * 一致検査はチェーン受理検証より先に働くため、prev はダミーで良い(到達しない)。
 */
const shapeCheckpoint = async (tuple: {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly auditHeadHashHex?: string;
}) => {
  const { entry } = await signEntryAt({
    seq: fixture.head.seq + 2,
    prevHashHex: "ab".repeat(32),
    actorUserId: OWNER,
    operation: checkpointOperation({
      ...tuple,
      manifestSigHashHex: "cd".repeat(32),
      valuesDigestHex: await valuesDigestOf([]),
    }),
  });
  return entry;
};

const createWithCheckpoint = async (checkpoint: Awaited<ReturnType<typeof shapeCheckpoint>>) =>
  createEnvironmentComposite(fixture, {
    environmentId: ENV,
    name: "App",
    deks: await wrapsFor(ENV, [...ALL_MEMBERS]),
    dekCommitmentHex: await commitmentOf(projectId, ENV, 1, makeDek()),
    checkpoint,
  });

const expectPayloadMismatch = async (response: Response, field: string) => {
  expect(response.status).toBe(422);
  expect(((await response.json()) as { field: string }).field).toBe(field);
};

describe("境界 checkpoint の複合内整合(§12-4 / CRYPTO_SPEC §4.3 (2) — 2026-08-27)", () => {
  it("rejects a tuple naming another environment (payload-mismatch checkpointEnvironment)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: "env-other-0009", epoch: 1, manifestVersion: 1 }),
    );
    await expectPayloadMismatch(response, "checkpointEnvironment");
  });

  it("rejects a tuple whose epoch differs from the established epoch (checkpointEpoch)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: ENV, epoch: 2, manifestVersion: 1 }),
    );
    await expectPayloadMismatch(response, "checkpointEpoch");
  });

  it("rejects a tuple whose manifestVersion differs from the bundled manifest (checkpointManifestVersion)", async () => {
    const response = await createWithCheckpoint(
      await shapeCheckpoint({ environmentId: ENV, epoch: 1, manifestVersion: 2 }),
    );
    await expectPayloadMismatch(response, "checkpointManifestVersion");
  });

  it("rejects a fabricated audit head on a boundary checkpoint (audit-head-unknown)", async () => {
    // 非空 audit_head_hash は §16-2 の規則(実効権限 admin + §6.4 の存在・位置
    // 検査)で受理する(2026-08-28 PR-M2 — F3b の暫定 fail-closed を置換)。
    // 保存済みの累積ハッシュ列に存在しない申告 = 偽公証は受理段で落ちる
    const response = await createWithCheckpoint(
      await shapeCheckpoint({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        auditHeadHashHex: "ef".repeat(32),
      }),
    );
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("audit-head-unknown");
  });

  it("rejects a checkpoint whose actor differs from the caller (403 actor-mismatch — §12-4)", async () => {
    // エントリ・ステートメント・マニフェストは呼び出し主体(OWNER)のまま、
    // checkpoint だけ MEMBER 署名 → チェーンエントリ両方の actor 厳密一致に反する
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: "ab".repeat(32),
      actorUserId: MEMBER,
      operation: checkpointOperation({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: "cd".repeat(32),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const response = await createWithCheckpoint(checkpoint);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("actor-mismatch");
  });

  it("rejects a binding whose manifest hash differs from the bundled manifest (422 checkpoint-binding-mismatch)", async () => {
    // 座標(env / epoch / manifestVersion)は同梱物と一致させ、タプルの
    // manifest_sig_hash だけを別値にする: 形状検査とチェーン受理は通り、
    // §4.3 (2) の完全一致束縛(acceptEnvManifest — 適用後履歴のタプル)が落とす。
    // H+1 エントリはフィクスチャと同じ材料の決定的署名で再構成し、prev を接続する
    const commitment = await commitmentOf(projectId, ENV, 1, makeDek());
    const { hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: createEnvironmentOperation(ENV, commitment),
    });
    const { entry: checkpoint } = await signEntryAt({
      seq: fixture.head.seq + 2,
      prevHashHex: hash,
      actorUserId: OWNER,
      operation: checkpointOperation({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: "ef".repeat(32),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const response = await createEnvironmentComposite(fixture, {
      environmentId: ENV,
      name: "App",
      deks: await wrapsFor(ENV, [...ALL_MEMBERS]),
      dekCommitmentHex: commitment,
      checkpoint,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe(
      "checkpoint-binding-mismatch",
    );
    // 原子性: 拒否された複合はチェーンに何も残さない
    const chain = await requestJson("GET", "/chain", token(OWNER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(fixture.head.seq);
  });

  it("rejects a rotate checkpoint whose values digest mismatches the stored enumeration (422 values-digest-mismatch)", async () => {
    // 宣言ヘッド確定後の並行 push と同型の不一致(§12-4): クライアントは再 pull の
    // 上で有界再試行する。タプルの digest は保存列挙に存在しない変数から構成する
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: await wrapsFor(ENV, [...ALL_MEMBERS], 2, MEMBER),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, makeDek()),
      checkpointValues: [
        { variableId: "var-phantom-0001", version: 1, valueSigHashHex: "ab".repeat(32) },
      ],
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("values-digest-mismatch");
  });
});
