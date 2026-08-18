// 要ローテーション検出(AUDIT_SPEC §4.1)+ フラグビュー / 取り下げ(§6 / §7)+
// B1a 追補(AUTH_SPEC §12-6 — 409 の保存済み受信者 enc 公開鍵と再追加時掃除)の
// 統合テスト。vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と
// DO SQLite を検証する。
//
// このスイートが固定するもの(変異検証の対応):
// - 候補集合 = 在籍区間 × 存在期間の重なり(区間外の変数の除外・削除済み変数の
//   包含・再追加の区間和)
// - 根拠ランク: 在籍区間内の var.read = read / それ以外 = readable
// - rotation.recommended の記録細則(§3.3): 1 対 1 行・actor = system・
//   chain_seq 列は使わない・payload の basis / triggerChainSeq・ミラーと同一
//   受理の直後 seq
// - 解消導出(§4.1-5): マーカーなし push と dismissed は解消、再暗号化マーカー
//   付き push は解消しない、解消は seq 順(取り下げ後の再検出は生き返る)
// - 可視性(§6): フラグビューはクラス 1(reader 可)、非メンバー 404。
//   取り下げは admin 以上(member = 403)・有効フラグなし 404・all-or-nothing・
//   重複対の畳み込み・空列挙 400
// - revoke_server 変種: 候補 = grant スコープ内のみ、(a) = 区間内の
//   server.lease_issued(発行時点のアクティブ変数)、拡大再 grant は
//   「環境ごとの開示窓」(拡大 seq 起点 — 最初のスコープ固定でも区間開始への
//   繰り上げでもない)
// - B1a: 409 が占有ラップの保存済み enc 公開鍵を運ぶ / add_member 受理時の
//   旧鍵宛ラップ掃除(dek.deleted actor = system + 原因 payload。同一鍵の
//   再追加は掃除しない・他メンバーのラップは触らない)

import { encodeHex, exportEncryptionPublicKey, generateEncryptionKeyPair } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { JSON_HEADERS } from "./support/auth.ts";
import {
  createVariableStatement,
  encryptValue,
  makeDek,
  metaSignedBytesHashOf,
  signMetaStatementAs,
  valueSignedBytesHashOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
  type WireEncryptedPayload,
  type WireVariableMetaStatement,
} from "./support/data-crypto.ts";
import { commitmentOf } from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentComposite,
  createEnvironmentOk,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentOk,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  deleteVariableRequest,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { deploymentKey, LEASE_AUDIENCE, LEASE_SUBJECT, makeOidcToken } from "./support/lease.ts";
import { OIDC_ISSUER } from "./support/oidc-issuer.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
}

async function readFlags(asUserId: string = READER): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(asUserId));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

/** remove_member をチェーンへ追記し、その chain seq を返す。 */
async function removeMember(targetUserId: string): Promise<number> {
  await appendOperation(fixture, OWNER, {
    op: "remove_member",
    payload: { targetUserId },
  });
  return fixture.head.seq;
}

/** ベクター固定鍵での再追加(同一鍵の再参加)。 */
async function readdWithSameKeys(targetUserId: string, role: "member" | "reader"): Promise<void> {
  const keys = vectorKeyOf(targetUserId);
  await appendOperation(fixture, OWNER, {
    op: "add_member",
    payload: {
      targetUserId,
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
    },
  });
}

/** 対象メンバーとしての一括 pull(var.read の記録経路 — §12-7)。 */
async function pullAs(userId: string): Promise<void> {
  const response = await requestJson("GET", `/environments/${ENV}/pull`, token(userId));
  expect(response.status).toBe(200);
}

/** OWNER が任意環境に変数を作る(createVariableOk は writer = MEMBER 固定のため)。 */
async function createVariableAsOwner(input: {
  readonly dek: Uint8Array;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
}): Promise<WireVariableMetaStatement> {
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
    { writerUserId: OWNER, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: OWNER,
    projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: input.environmentId,
    issuerUserId: OWNER,
    entry: {
      variableId: input.variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
    },
  });
  const response = await requestJson(
    "POST",
    `/environments/${input.environmentId}/variables`,
    token(OWNER),
    { statement, value, manifest },
  );
  expect(response.status).toBe(200);
  fixture.manifests.set(input.environmentId, state);
  return statement;
}

/** OWNER による VAR の v(N) push(値署名の prev 連鎖込み)。 */
async function pushNextVersion(input: {
  readonly dek: Uint8Array;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly reencryption?: boolean;
}): Promise<WireEncryptedPayload> {
  const value = await encryptValue(
    input.dek,
    { projectId, environmentId: ENV, epoch: 1, variableId: VAR, version: input.version },
    `value-v${input.version}`,
    { writerUserId: OWNER, head: fixture.head, prevValueSigHashHex: input.prevValueSigHashHex },
  );
  const response = await requestJson(
    "POST",
    `/environments/${ENV}/variables/${VAR}/versions`,
    token(OWNER),
    { value, ...(input.reencryption === true ? { reencryption: true } : {}) },
  );
  expect(response.status).toBe(200);
  return value;
}

describe("要ローテーション検出: remove_member(AUDIT_SPEC §4.1)", () => {
  it("在籍区間内に読んだ変数は read、読んでいない候補は readable として 1 対 1 行を記録する", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER が暗号文を取得(var.read の記録)してから、読んでいない 2 本目を作る
    await pullAs(MEMBER);
    await createVariableOk(dek, "var-api-key", "API_KEY", "sk-alpha");
    const removalSeq = await removeMember(MEMBER);

    const flags = await readFlags();
    expect(flags).toHaveLength(2);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
    });
    expect(byVariable.get("var-api-key")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
      targetUserId: MEMBER,
      triggerChainSeq: removalSeq,
    });

    // 記録細則(§3.3): actor = system、chain_seq 列は使わない(payload に運ぶ)
    const events = await readAuditEvents(projectId);
    const recommended = events.filter((event) => event["event"] === "rotation.recommended");
    expect(recommended).toHaveLength(2);
    for (const event of recommended) {
      expect(event["actor_type"]).toBe("system");
      expect(event["actor_user_id"]).toBeNull();
      expect(event["chain_seq"]).toBeNull();
      expect(event["target_user_id"]).toBe(MEMBER);
      const payload = JSON.parse(String(event["payload"])) as Record<string, unknown>;
      expect(payload["triggerChainSeq"]).toBe(removalSeq);
      expect(["read", "readable"]).toContain(payload["basis"]);
    }
    // 検出行はミラー(chain.member_removed)の直後 seq(同一受理の追記 — §4.1-4)
    const mirror = events.find((event) => event["event"] === "chain.member_removed");
    expect(mirror).toBeDefined();
    expect(Math.min(...recommended.map((event) => Number(event["seq"])))).toBe(
      Number(mirror?.["seq"]) + 1,
    );
  });

  it("削除済み変数も候補に含め、dismissed だけが解消し、取り下げ後の再検出は生き返る(§4.1-2 / -5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await pullAs(MEMBER);
    // 変数を消しても過去の閲覧可能性は消えない(上流 credential は失効しない)
    expect((await deleteVariableRequest(VAR, OWNER)).status).toBe(204);
    await removeMember(MEMBER);
    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags[0]).toMatchObject({ variableId: VAR, basis: "read" });

    // 削除済み変数は push できない — 唯一の解消経路が取り下げ(admin)
    const dismissed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(dismissed.status).toBe(204);
    expect(await readFlags()).toHaveLength(0);
    const events = await readAuditEvents(projectId);
    const dismissedRows = events.filter((event) => event["event"] === "rotation.dismissed");
    expect(dismissedRows).toHaveLength(1);
    expect(dismissedRows[0]).toMatchObject({
      actor_type: "user",
      actor_user_id: OWNER,
      environment_id: ENV,
      variable_id: VAR,
    });

    // 解消は seq 順(§4.1-5): 取り下げ後の再追加 → 再削除の検出は生き返る
    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);
  });

  it("再追加の区間和: 全区間の候補を含み、どの区間とも重ならない変数は含まない(§4.1-1 / -2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);

    // 不在の間だけ存在した変数(OWNER が作成し、再追加前に削除)
    const gapVar = "var-gap-secret";
    const gapStatement = await createVariableAsOwner({
      dek,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
    });
    const gapDeleteStatement = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: ENV,
      variableId: gapVar,
      name: "GAP_SECRET",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, gapStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const gapDelete = await manifestForVariableOp(fixture, {
      environmentId: ENV,
      issuerUserId: OWNER,
      entry: {
        variableId: gapVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, gapDeleteStatement, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${ENV}/variables/${gapVar}`, token(OWNER), {
          statement: gapDeleteStatement,
          manifest: gapDelete.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(ENV, gapDelete.state);

    // 再追加(同一鍵)→ 再削除
    await readdWithSameKeys(MEMBER, "member");
    await removeMember(MEMBER);

    const flags = await readFlags();
    // VAR は両方の削除で検出される(1 対に有効フラグ 2 行 — 区間の和)。
    // gap 変数はどの在籍区間とも重ならないため 1 行も検出されない
    expect(flags.filter((flag) => flag.variableId === VAR)).toHaveLength(2);
    expect(flags.filter((flag) => flag.variableId === gapVar)).toHaveLength(0);
  });

  it("解消導出: マーカーなし push は解消し、再暗号化マーカー付き push は解消しない(§4.1-5)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const v1 = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    expect(await readFlags()).toHaveLength(1);

    // 再暗号化マーカー付き(義務ローテーションの再 push 相当)は解消しない
    const v2 = await pushNextVersion({
      dek,
      version: 2,
      prevValueSigHashHex: await valueSignedBytesHashOf(v1, MEMBER),
      reencryption: true,
    });
    expect(await readFlags()).toHaveLength(1);
    // マーカーは監査 payload に写る(AUDIT_SPEC §3.3)
    const events = await readAuditEvents(projectId);
    const markedPush = events.find(
      (event) => event["event"] === "var.version_pushed" && Number(event["version"]) === 2,
    );
    expect(JSON.parse(String(markedPush?.["payload"])) as Record<string, unknown>).toMatchObject({
      reencryption: true,
    });

    // マーカーなし push(= 上流をローテーションして新しい値を入れた)は解消する
    await pushNextVersion({
      dek,
      version: 3,
      prevValueSigHashHex: await valueSignedBytesHashOf(v2, OWNER),
    });
    expect(await readFlags()).toHaveLength(0);
  });

  it("可視性: フラグビューはクラス 1(reader 可)・非メンバーには 404(§6 / §11-2)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    await removeMember(MEMBER);
    // reader も見える(検出の目的は全員への促し — admin 限定では機能しない)
    expect(await readFlags(READER)).toHaveLength(1);
    const stranger = await requestJson("GET", "/rotation/flags", token(STRANGER));
    expect(stranger.status).toBe(404);
  });
});

describe("取り下げ操作(AUDIT_SPEC §3.3 / §7)", () => {
  it("admin 未満は 403、有効フラグの無い対は 404 で all-or-nothing、重複対は 1 行に畳む", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER を残したまま READER を削除(取り下げ権限の検査に member が要る)
    await removeMember(READER);
    expect(await readFlags(OWNER)).toHaveLength(1);

    // チェーン role member は取り下げられない(admin 以上 — ラップ削除と同水準)
    const asMember = await requestJson("POST", "/rotation/dismissals", token(MEMBER), {
      targets: [{ environmentId: ENV, variableId: VAR }],
    });
    expect(asMember.status).toBe(403);

    // 有効フラグの無い対を含むリクエストは全体を 404 で拒否(黙って成功させない)
    const mixed = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: "var-not-flagged" },
      ],
    });
    expect(mixed.status).toBe(404);
    await expect(mixed.json()).resolves.toMatchObject({
      _tag: "RotationFlagNotFound",
      variableId: "var-not-flagged",
    });
    // all-or-nothing: 有効だった対も取り下げられず、監査にも 1 行も積まれない
    expect(await readFlags(OWNER)).toHaveLength(1);
    const before = await readAuditEvents(projectId);
    expect(before.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(0);

    // 同一対の重複列挙は 1 行に畳む(対単位の冪等)
    const deduped = await requestJson("POST", "/rotation/dismissals", token(OWNER), {
      targets: [
        { environmentId: ENV, variableId: VAR },
        { environmentId: ENV, variableId: VAR },
      ],
    });
    expect(deduped.status).toBe(204);
    const after = await readAuditEvents(projectId);
    expect(after.filter((event) => event["event"] === "rotation.dismissed")).toHaveLength(1);
    expect(await readFlags(OWNER)).toHaveLength(0);

    // 空列挙は Schema 検証の 400(呼び出し形として意味がない)
    const empty = await requestJson("POST", "/rotation/dismissals", token(OWNER), { targets: [] });
    expect(empty.status).toBe(400);
  });
});

describe("要ローテーション検出: revoke_server 変種(AUDIT_SPEC §4.1)", () => {
  it("候補は grant スコープ内のみ、リース発行時点のアクティブ変数が read になる", async () => {
    // ENV(スコープ内)と env-out(スコープ外)を用意する
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    const outEnv = "env-out-of-scope";
    const outDek = makeDek();
    const outDeks = await wrapDekForAll({
      projectId,
      environmentId: outEnv,
      epoch: 1,
      dek: outDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: outEnv,
          name: "Out",
          deks: outDeks,
          dekCommitmentHex: await commitmentOf(projectId, outEnv, 1, outDek),
        })
      ).status,
    ).toBe(200);
    const outVar = "var-out-of-scope";
    await createVariableAsOwner({
      dek: outDek,
      environmentId: outEnv,
      variableId: outVar,
      name: "OUT_SECRET",
    });

    // grant(スコープ = ENV のみ)+ サーバー宛バックフィル + リース発行
    const key = await deploymentKey();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV],
        leasePolicy: [
          {
            issuerUrl: OIDC_ISSUER,
            audience: LEASE_AUDIENCE,
            claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
          },
        ],
      },
    });
    const serverWrap = await wrapDekToServer({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      serverKeyFingerprintHex: key.fingerprintHex,
      serverEncPubHex: key.encPubHex,
      signerUserId: OWNER,
    });
    expect(
      (await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), { deks: [serverWrap] }))
        .status,
    ).toBe(204);
    const workload = await generateEncryptionKeyPair();
    const ephemeralPubHex = encodeHex(await exportEncryptionPublicKey(workload.publicKey));
    const lease = await SELF.fetch(
      `https://maruhi.test/projects/${projectId}/environments/${ENV}/lease`,
      {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ oidcToken: await makeOidcToken(), ephemeralPubHex }),
      },
    );
    expect(lease.status).toBe(200);

    // リース発行より後に作られた変数(発行時点で存在しない → readable)
    await createVariableOk(dek, "var-after-lease", "AFTER_LEASE", "later-secret");

    // 失効 → 検出(変種): スコープ内のみ・(a) はリース発行時点のアクティブ変数
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });
    const revokeSeq = fixture.head.seq;

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    expect(byVariable.get(VAR)).toMatchObject({
      environmentId: ENV,
      basis: "read",
      targetServerKeyFingerprintHex: key.fingerprintHex,
      triggerChainSeq: revokeSeq,
    });
    expect(byVariable.get("var-after-lease")).toMatchObject({
      environmentId: ENV,
      basis: "readable",
    });
    // スコープ外の環境の変数は候補にならない(§4.1 変種の手順 2)
    expect(byVariable.has(outVar)).toBe(false);
    // member 変種の列(target_user_id)は使わない
    expect(flags.every((flag) => flag.targetUserId === undefined)).toBe(true);
  });

  it("拡大再 grant で加わった環境は「拡大 seq からの開示窓」で検出される(§4.1 変種)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // 拡大で後から加わる環境と、拡大**前**に削除される変数を用意する
    const widenEnv = "env-widened";
    const widenDek = makeDek();
    const widenDeks = await wrapDekForAll({
      projectId,
      environmentId: widenEnv,
      epoch: 1,
      dek: widenDek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    expect(
      (
        await createEnvironmentComposite(fixture, {
          environmentId: widenEnv,
          name: "Widened",
          deks: widenDeks,
          dekCommitmentHex: await commitmentOf(projectId, widenEnv, 1, widenDek),
        })
      ).status,
    ).toBe(200);
    const preVar = "var-deleted-before-widen";
    const preStatement = await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
    });

    const key = await deploymentKey();
    const leasePolicy = [
      {
        issuerUrl: OIDC_ISSUER,
        audience: LEASE_AUDIENCE,
        claimConstraints: [{ claimName: "sub", claimValue: LEASE_SUBJECT }],
      },
    ];
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV],
        leasePolicy,
      },
    });
    // 最初の grant の後・拡大の前に preVar を削除(存在期間が窓の手前で閉じる)
    const preDelete = await signMetaStatementAs(OWNER, projectId, {
      suite: "maruhi/v1" as const,
      environmentId: widenEnv,
      variableId: preVar,
      name: "PRE_WIDEN",
      status: "deleted" as const,
      metaVersion: 2,
      prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, preStatement, OWNER),
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    const preDeleteManifest = await manifestForVariableOp(fixture, {
      environmentId: widenEnv,
      issuerUserId: OWNER,
      entry: {
        variableId: preVar,
        status: "deleted",
        metaVersion: 2,
        metaSigHashHex: await metaSignedBytesHashOf(projectId, preDelete, OWNER),
      },
    });
    expect(
      (
        await requestJson("DELETE", `/environments/${widenEnv}/variables/${preVar}`, token(OWNER), {
          statement: preDelete,
          manifest: preDeleteManifest.manifest,
        })
      ).status,
    ).toBe(204);
    fixture.manifests.set(widenEnv, preDeleteManifest.state);
    // 拡大再 grant(チェーン合意規則は同一鍵 FP への拡大のみ受理 — CRYPTO_SPEC §6.2)
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: key.encPubHex,
        serverKeyFingerprintHex: key.fingerprintHex,
        scopeEnvironmentIds: [ENV, widenEnv],
        leasePolicy,
      },
    });
    // 窓の内側で生きている変数(拡大後に作成)
    const widenVar = "var-in-window";
    await createVariableAsOwner({
      dek: widenDek,
      environmentId: widenEnv,
      variableId: widenVar,
      name: "IN_WINDOW",
    });
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: key.fingerprintHex },
    });

    const flags = await readFlags(OWNER);
    const byVariable = new Map(flags.map((flag) => [flag.variableId, flag]));
    // 拡大で加わった環境の変数は検出される(最初のスコープへの固定は fail open)
    expect(byVariable.get(widenVar)).toMatchObject({
      environmentId: widenEnv,
      basis: "readable",
      targetServerKeyFingerprintHex: key.fingerprintHex,
    });
    // 最初のスコープの環境は従来どおり検出される
    expect(byVariable.get(VAR)).toMatchObject({ environmentId: ENV, basis: "readable" });
    // 拡大前に削除された変数は窓と重ならない(窓を区間開始まで繰り上げない —
    // 繰り上げると grant #1 と拡大の間に存在した preVar へ誤検出が出る)
    expect(byVariable.has(preVar)).toBe(false);
  });
});

describe("B1a 追補(AUTH_SPEC §12-6 — 2026-08-15)", () => {
  it("上書き禁止 409 は占有ラップの保存済み受信者 enc 公開鍵を運ぶ", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 既存スロット (ENV, 1, MEMBER) への追記は 409 + 保存済み enc 公開鍵
    const duplicate = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek: makeDek(),
      recipientUserId: MEMBER,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [duplicate],
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      _tag: "DekWrapExists",
      epoch: 1,
      recipientUserId: MEMBER,
      storedRecipientEncPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
    });
  });

  it("鍵を変えた再追加の受理時に旧鍵宛ラップを掃除し、dek.deleted(system + 原因)を記録する", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await rotateEnvironmentOk(fixture, OWNER, ENV, 2);
    await removeMember(MEMBER);
    const wrapsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsBefore[0]?.["n"])).toBe(2);

    // 別鍵での再追加(受諾鍵が変わった再参加)— 旧鍵宛の 2 ラップは受理時に消える
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: MEMBER,
        encPubHex: "11".repeat(32),
        sigPubHex: "22".repeat(32),
        role: "member",
      },
    });
    const readdSeq = fixture.head.seq;
    const wrapsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsAfter[0]?.["n"])).toBe(0);
    // 他メンバーの正当なラップは触らない(上書き禁止の不変条件は不変)
    const others = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id != ?",
      MEMBER,
    );
    expect(Number(others[0]?.["n"])).toBe(2 * (ALL_MEMBERS.length - 1));

    const events = await readAuditEvents(projectId);
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted).toHaveLength(2);
    for (const event of deleted) {
      expect(event["actor_type"]).toBe("system");
      expect(event["target_user_id"]).toBe(MEMBER);
      expect(JSON.parse(String(event["payload"])) as Record<string, unknown>).toEqual({
        cause: "member-readded",
        triggerChainSeq: readdSeq,
      });
    }
  });

  it("同一鍵での再追加は掃除しない(既存ラップがそのまま有効に復帰する)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    await removeMember(READER);
    await readdWithSameKeys(READER, "reader");
    const wraps = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      READER,
    );
    expect(Number(wraps[0]?.["n"])).toBe(1);
    const events = await readAuditEvents(projectId);
    expect(events.filter((event) => event["event"] === "dek.deleted")).toHaveLength(0);
  });
});
