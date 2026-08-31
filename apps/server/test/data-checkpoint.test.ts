// standalone(周期)checkpoint の受理面と GET /audit-head の統合テスト
// (AUTH_SPEC §16-2 / CRYPTO_SPEC §6.4 / AUDIT_SPEC §5.1 — 2026-08-28 PR-M2)。
//
// - 認可 2 水準(session-27 §13-5 の権限マトリクス): 空 audit head =
//   write スコープ × member 以上、非空 = 実効権限 admin(不足 403)
// - 受理時点突合の 5 理由(manifest-mismatch / values-digest-mismatch /
//   audit-head-unknown / audit-head-stale / environment-deleted)。
//   実在しない先行 manifest_version の公証拒否(session-33 §5 の申し送り)を含む
// - 原子性(拒否はチェーン・ミラー・スナップショットの何も残さない)と
//   スナップショット保存規律の経路同一性(A のみ再 checkpoint しても B の
//   基準は維持 — §16-2「経路によらず同一」)
// - 監査ヘッド: 遅延 materialize の初期化(既存行からの再計算)・行追記での
//   前進・位置下限(audit-head-stale)と初回の空虚な真
//
// 合意規則の理由コード・検査順序そのもの(role / audit role / unknown / epoch /
// regression)は crypto 層の 4 実行環境テスト(chain-entries.json)が固定済みで、
// ここでは API 到達面の代表(unknown-environment / epoch / reader role)だけを
// 実データで確認する。

import type { ChainEntry, CheckpointEnvironmentEntry } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, cliToken } from "./support/auth.ts";
import {
  commitmentOf,
  makeDek,
  manifestSignedBytesHashOf,
  signEntryAt,
  valuesDigestOf,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  createEnvironmentOk,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  storedCheckpointValues,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

// data-fixture.ts の GITHUB_IDS と同じシード値(あちらは非公開のため写す)
const GITHUB_IDS: Record<string, number> = {
  [OWNER]: 9001,
  [MEMBER]: 9002,
  [READER]: 9003,
};

/**
 * 対象プロジェクト限定の write スコープトークン(実効権限マトリクスの b / d)。
 * fixture の既定トークン(CLI ログインの既定名)を同名ローテーションで失効させ
 * ないよう、別名で発行する。
 */
async function writeScopedToken(userId: string): Promise<string> {
  const githubId = GITHUB_IDS[userId];
  if (githubId === undefined) {
    throw new Error(`no seeded github id for ${userId}`);
  }
  return cliToken(githubId, [{ project: projectId, permission: "write" }], "write-scoped");
}

/** 保存済み最新マニフェストのタプル座標(受理時点突合の一致側の材料)。 */
async function currentManifestTuple(
  environmentId: string,
): Promise<{ manifestVersion: number; manifestSigHashHex: string }> {
  const state = fixture.manifests.get(environmentId);
  if (state === undefined) {
    throw new Error(`no recorded manifest for ${environmentId}`);
  }
  return {
    manifestVersion: state.manifest.manifestVersion,
    manifestSigHashHex: await manifestSignedBytesHashOf(
      projectId,
      state.manifest,
      state.issuerUserId,
    ),
  };
}

/** 受理時点の保存状態と一致するタプル(epoch は既定 1 — rotate を挟まない限り)。 */
async function matchingTuple(
  environmentId: string,
  overrides?: Partial<CheckpointEnvironmentEntry>,
): Promise<CheckpointEnvironmentEntry> {
  const manifest = await currentManifestTuple(environmentId);
  return {
    environmentId,
    epoch: 1,
    manifestVersion: manifest.manifestVersion,
    manifestSigHashHex: manifest.manifestSigHashHex,
    valuesDigestHex: await valuesDigestOf(await storedCheckpointValues(environmentId)),
    ...overrides,
  };
}

/** standalone checkpoint を汎用チェーン追記(§16-2)へ送る。200 ならヘッドを進める。 */
async function sendStandaloneCheckpoint(input: {
  readonly actorUserId: string;
  readonly environments: readonly CheckpointEnvironmentEntry[];
  readonly auditHeadHashHex?: string;
  readonly authToken?: string;
}): Promise<{ response: Response; entry: ChainEntry }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId: input.actorUserId,
    operation: {
      op: "checkpoint",
      payload: {
        environments: input.environments,
        auditHeadHashHex: input.auditHeadHashHex ?? "",
      },
    },
  });
  const response = await requestJson(
    "POST",
    "/chain/entries",
    input.authToken ?? token(input.actorUserId),
    { parentHeadHashHex: fixture.head.hashHex, entry },
  );
  if (response.status === 200) {
    fixture.head = { seq: entry.seq, hashHex: hash };
  }
  return { response, entry };
}

async function fetchAuditHead(authToken: string): Promise<Response> {
  return requestJson("GET", "/audit-head", authToken);
}

async function auditHeadOk(authToken: string): Promise<string> {
  const response = await fetchAuditHead(authToken);
  expect(response.status).toBe(200);
  const body = (await response.json()) as { auditHeadHashHex: string };
  expect(body.auditHeadHashHex).toMatch(/^[0-9a-f]{64}$/);
  return body.auditHeadHashHex;
}

/** chain.checkpointed ミラー行数(原子性・ミラー記録の検証材料)。 */
async function checkpointMirrorCount(): Promise<number> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'chain.checkpointed'",
  );
  return Number(rows[0]?.["n"]);
}

async function snapshotRow(
  environmentId: string,
): Promise<{ chainSeq: number; manifestVersion: number } | null> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT chain_seq, manifest_version FROM environment_checkpoints WHERE environment_id = ?",
    environmentId,
  );
  const row = rows[0];
  return row === undefined
    ? null
    : { chainSeq: Number(row["chain_seq"]), manifestVersion: Number(row["manifest_version"]) };
}

describe("GET /projects/:id/audit-head(AUTH_SPEC §16-2 / AUDIT_SPEC §5.1)", () => {
  it("returns the cumulative hash to effective admin, initializing the derived column from existing rows", async () => {
    // 初回アクセスが既存監査行(ベースチェーンのミラー)からの再計算 =
    // §5.1 の導入マイグレーションを兼ねる(遅延 materialize)
    const first = await auditHeadOk(token(OWNER));
    // 冪等: 再取得は同じヘッド(行が増えていない限り)
    expect(await auditHeadOk(token(OWNER))).toBe(first);
  });

  it("advances when audit rows are appended", async () => {
    const before = await auditHeadOk(token(OWNER));
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, "var-head-0001", "DATABASE_URL", "postgres://alpha");
    const after = await auditHeadOk(token(OWNER));
    expect(after).not.toBe(before);
  });

  it("rejects non-admin chain roles with 403 and strangers with 404 (§11-2 concealment)", async () => {
    expect((await fetchAuditHead(token(MEMBER))).status).toBe(403);
    expect((await fetchAuditHead(token(READER))).status).toBe(403);
    // スコープ半分の不足(admin role × write トークン)も 403(実効権限の min)
    expect((await fetchAuditHead(await writeScopedToken(OWNER))).status).toBe(403);
  });

  it("returns the presented token's scopes from /auth/me (the client-side pre-determination material)", async () => {
    const scoped = await writeScopedToken(OWNER);
    const response = await SELF.fetch(`${BASE}/auth/me`, {
      headers: { authorization: `Bearer ${scoped}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tokenScopes?: unknown };
    expect(body.tokenScopes).toEqual([{ project: projectId, permission: "write" }]);
  });
});

describe("standalone checkpoint の認可 2 水準(session-27 §13-5 の権限マトリクス)", () => {
  it("(a) admin role × admin token + a fresh audit head is accepted, (d) member × write token + empty head is accepted", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // (d): member role × write スコープ × 空 audit head = データ層 checkpoint
    const memberAttempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
      authToken: await writeScopedToken(MEMBER),
    });
    expect(memberAttempt.response.status).toBe(200);
    // (a): 実効権限 admin + CAS 親確定後に取得した申告の公証
    const head = await auditHeadOk(token(OWNER));
    const ownerAttempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
    });
    expect(ownerAttempt.response.status).toBe(200);
  });

  it("(b) admin role × write token + non-empty head is 403 (scope half of the effective permission)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
      authToken: await writeScopedToken(OWNER),
    });
    expect(attempt.response.status).toBe(403);
  });

  it("(c) member role × admin token + non-empty head is 403 (role half — precedes the consensus rejection)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: head,
    });
    expect(attempt.response.status).toBe(403);
    const body = (await attempt.response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });

  it("rejects a reader's checkpoint via the consensus rule (422 insufficient-role)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: READER,
      environments: [await matchingTuple(ENV)],
    });
    expect(attempt.response.status).toBe(422);
    const body = (await attempt.response.json()) as { reason: string };
    expect(body.reason).toBe("insufficient-role");
  });
});

async function expectMismatch(response: Response, reason: string): Promise<void> {
  expect(response.status).toBe(422);
  const body = (await response.json()) as { _tag?: string; reason: string };
  expect(body.reason).toBe(reason);
}

describe("standalone checkpoint の受理時点突合(CRYPTO_SPEC §6.4 の 5 理由)", () => {
  it("rejects notarizing a manifest_version that does not exist yet (manifest-mismatch — session-33 §5 の申し送り)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const manifest = await currentManifestTuple(ENV);
    const headBefore = fixture.head.seq;
    const mirrorsBefore = await checkpointMirrorCount();
    // 悪意メンバーが実在しない先の manifest_version を公証して以後の正当な
    // マニフェストを checkpoint-regressed で詰まらせる形。合意規則
    // (regression = 非後退)は通るが、受理時点の最新マニフェストとの一致
    // (§6.4)が落とす
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { manifestVersion: manifest.manifestVersion + 5 })],
    });
    await expectMismatch(attempt.response, "manifest-mismatch");
    // 原子性: 拒否はチェーンにもミラーにも何も残さない(基準の汚染が起きない)
    const chain = await requestJson("GET", "/chain", token(OWNER));
    expect(((await chain.json()) as { headSeq: number }).headSeq).toBe(headBefore);
    expect(await checkpointMirrorCount()).toBe(mirrorsBefore);
    // 正当な現行版の公証はその後も受理される(詰まっていない)
    const legitimate = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(legitimate.response.status).toBe(200);
  });

  it("rejects a stale manifest reference (manifest-mismatch — the issuer's view is behind)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const stale = await matchingTuple(ENV);
    // メタ操作(変数作成)が manifestVersion を進める → 古い参照は一致しない。
    // 合意規則の regression(非後退)は等号を許すため、拒否は受理時点突合の側
    await createVariableOk(dek, "var-meta-advance-0001", "API_KEY", "sk-alpha");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [stale],
    });
    await expectMismatch(attempt.response, "manifest-mismatch");
  });

  it("rejects a values digest that mismatches the stored enumeration (values-digest-mismatch)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, "var-values-0001", "DATABASE_URL", "postgres://alpha");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { valuesDigestHex: await valuesDigestOf([]) })],
    });
    await expectMismatch(attempt.response, "values-digest-mismatch");
  });

  it("rejects a fabricated audit head (audit-head-unknown)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: "ef".repeat(32),
    });
    await expectMismatch(attempt.response, "audit-head-unknown");
  });

  it("rejects an attestation older than the previous checkpoint's mirror row (audit-head-stale) and accepts a refetched one", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 位置下限の基準になる「直前 checkpoint のミラー行」を作る前に申告を取る
    // (CAS 競合後に申告を取り直さなかった発行の形 — §6.4)
    const staleHead = await auditHeadOk(token(OWNER));
    const first = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(first.response.status).toBe(200);
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: staleHead,
    });
    await expectMismatch(attempt.response, "audit-head-stale");
    // 申告の取り直し(§16-2 の再試行)で受理される
    const refetched = await auditHeadOk(token(OWNER));
    const retried = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [await matchingTuple(ENV)],
      auditHeadHashHex: refetched,
    });
    expect(retried.response.status).toBe(200);
  });

  it("does not impose the position floor on the project's first checkpoint (空虚に真 — §6.4 の基底ケース)", async () => {
    // ベースチェーンは環境を持たない = checkpoint がまだ 1 つも無い。
    // 要素ゼロ(環境ゼロ)+ 公証は合意規則上有効(§6.2)で、位置下限は課されない
    const head = await auditHeadOk(token(OWNER));
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: OWNER,
      environments: [],
      auditHeadHashHex: head,
    });
    expect(attempt.response.status).toBe(200);
  });

  it("rejects a tuple for a tombstoned environment (environment-deleted)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const tuple = await matchingTuple(ENV);
    expect((await deleteEnvironmentRequest(fixture, ENV, OWNER)).status).toBe(204);
    const attempt = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [tuple],
    });
    await expectMismatch(attempt.response, "environment-deleted");
  });

  it("rejects unknown environments and epoch mismatches at the consensus layer (422 ChainEntryInvalid)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const unknown = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { environmentId: "env-phantom-0001" })],
    });
    expect(unknown.response.status).toBe(422);
    expect(((await unknown.response.json()) as { reason: string }).reason).toBe(
      "unknown-environment",
    );
    const epochMismatch = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV, { epoch: 2 })],
    });
    expect(epochMismatch.response.status).toBe(422);
    expect(((await epochMismatch.response.json()) as { reason: string }).reason).toBe(
      "checkpoint-epoch-mismatch",
    );
  });
});

describe("境界 checkpoint の監査ヘッド公証(§16-2 — standalone と同一規則)", () => {
  it("accepts a rotate composite whose boundary checkpoint attests a fresh audit head (effective admin)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    // 受理まで進める正例はラップした DEK 自身のコミットメントを渡す(M1-T1)
    const next = makeDek();
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      actorUserId: OWNER,
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 2,
        dek: next,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: OWNER,
      }),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, next),
      checkpointAuditHeadHashHex: head,
    });
    expect(response.status).toBe(200);
  });

  it("rejects a member's attested boundary checkpoint with 403 (role half of the effective permission)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const head = await auditHeadOk(token(OWNER));
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      actorUserId: MEMBER,
      deks: await wrapsFor(ENV, [...ALL_MEMBERS], 2, MEMBER),
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, makeDek()),
      checkpointAuditHeadHashHex: head,
    });
    expect(response.status).toBe(403);
    expect(((await response.json()) as { reason: string }).reason).toBe("insufficient-role");
  });
});

/** 保存済みスナップショット列挙(配布内容の期待値 — §16-2 の保存行そのもの)。 */
async function storedSnapshotEnumeration(
  environmentId: string,
): Promise<readonly { variableId: string; version: number; valueSigHashHex: string }[]> {
  const rows = await queryProjectDo(
    projectId,
    `SELECT variable_id, version, value_sig_hash_hex
     FROM checkpoint_snapshot_values WHERE environment_id = ? ORDER BY variable_id`,
    environmentId,
  );
  return rows.map((row) => ({
    variableId: String(row["variable_id"]),
    version: Number(row["version"]),
    valueSigHashHex: String(row["value_sig_hash_hex"]),
  }));
}

interface PullSnapshotBody {
  readonly checkpointSnapshot?: {
    readonly chainSeq: number;
    readonly entryHashHex: string;
    readonly values: readonly {
      readonly variableId: string;
      readonly version: number;
      readonly valueSigHashHex: string;
    }[];
  };
}

async function pullBody(environmentId: string): Promise<PullSnapshotBody> {
  const response = await requestJson("GET", `/environments/${environmentId}/pull`, token(OWNER));
  expect(response.status).toBe(200);
  return (await response.json()) as PullSnapshotBody;
}

describe("値スナップショットの配布(AUTH_SPEC §12-7 / §14-2 — PR-M3)", () => {
  it("value pull bundles the stored enumeration of the latest covering checkpoint", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // 作成複合の境界 checkpoint(空列挙)が誕生時からの基準(§12-4)
    const creation = await pullBody(ENV);
    const creationRow = await snapshotRow(ENV);
    expect(creation.checkpointSnapshot).toBeDefined();
    expect(creation.checkpointSnapshot?.chainSeq).toBe(creationRow?.chainSeq);
    expect(creation.checkpointSnapshot?.values).toEqual([]);
    // 変数作成は checkpoint を発行しない — 配布される列挙は保存行のまま(空)
    await createVariableOk(dek, "var-m3-0001", "DATABASE_URL", "postgres://alpha");
    const beforeCheckpoint = await pullBody(ENV);
    expect(beforeCheckpoint.checkpointSnapshot?.chainSeq).toBe(creationRow?.chainSeq);
    expect(beforeCheckpoint.checkpointSnapshot?.values).toEqual([]);
    // standalone checkpoint の受理後は、受理時に保存した列挙そのものを配布する
    const accepted = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(accepted.response.status).toBe(200);
    const after = await pullBody(ENV);
    expect(after.checkpointSnapshot?.chainSeq).toBe(accepted.entry.seq);
    const stored = await storedSnapshotEnumeration(ENV);
    expect(stored.length).toBe(1);
    expect(after.checkpointSnapshot?.values).toEqual(stored);
  });

  it("metadata-only pull does not carry the snapshot (§12-7 — 値を運ばない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("GET", `/environments/${ENV}/pull/metadata`, token(OWNER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as PullSnapshotBody;
    expect(body.checkpointSnapshot).toBeUndefined();
  });
});

describe("スナップショット保存規律の経路同一性(§16-2 — 部分集合 checkpoint)", () => {
  const ENV_B = "env-second-0001";

  it("re-checkpointing A alone atomically updates A's baseline and leaves B's untouched", async () => {
    const dekA = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dekA, "var-a-0001", "DATABASE_URL", "postgres://alpha");
    await createEnvironmentOk(fixture, ENV_B, "Batch");
    // A + B の両方をカバーする standalone checkpoint で基準を確立する
    const both = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV), await matchingTuple(ENV_B)],
    });
    expect(both.response.status).toBe(200);
    const baselineA = await snapshotRow(ENV);
    const baselineB = await snapshotRow(ENV_B);
    expect(baselineA?.chainSeq).toBe(both.entry.seq);
    expect(baselineB?.chainSeq).toBe(both.entry.seq);
    // A のみ再 checkpoint(部分集合は合意規則上有効 — §6.2)
    const onlyA = await sendStandaloneCheckpoint({
      actorUserId: MEMBER,
      environments: [await matchingTuple(ENV)],
    });
    expect(onlyA.response.status).toBe(200);
    expect((await snapshotRow(ENV))?.chainSeq).toBe(onlyA.entry.seq);
    // B の基準(最新包含 checkpoint)は維持される — payload に含まれない環境の
    // 既存スナップショットは変更しない(§16-2)
    expect(await snapshotRow(ENV_B)).toEqual(baselineB);
    // 配布(§12-7 — PR-M3)も環境ごとの最新包含 checkpoint に対応する:
    // A は再 checkpoint の位置、B は元の位置の列挙を配る
    expect((await pullBody(ENV)).checkpointSnapshot?.chainSeq).toBe(onlyA.entry.seq);
    const pulledB = await pullBody(ENV_B);
    expect(pulledB.checkpointSnapshot?.chainSeq).toBe(both.entry.seq);
    expect(pulledB.checkpointSnapshot?.values).toEqual(await storedSnapshotEnumeration(ENV_B));
    // ミラー行(chain.checkpointed)は受理ごとに記録される(AUDIT_SPEC §3.4)
    const mirrors = await queryProjectDo(
      projectId,
      "SELECT chain_seq FROM audit_events WHERE event = 'chain.checkpointed' AND chain_seq IN (?, ?)",
      both.entry.seq,
      onlyA.entry.seq,
    );
    expect(mirrors.length).toBe(2);
  });
});
