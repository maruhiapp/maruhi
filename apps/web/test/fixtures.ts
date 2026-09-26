// ダッシュボード e2e / スクリーンショットの共用フィクスチャ(DP3 裁定 F)。W3b(S8 招待管理・
// S9 トークン管理)の裁定 CE / CO / CQ もここのフィクスチャが固定する。
//
// api-schema 由来の型(src/dashboard/types.ts)に適合するリテラルで、乖離は tsc が
// 検出する。実 Schema でのデコード検査は e2e.test.ts(裁定 BV)。ここはテスト
// プロセス専用のモジュールで、配信バンドルには入らない(screenshots.ts と
// e2e.test.ts だけが import する)。
import type {
  AuditEvent,
  ChainSnapshot,
  DeviceList,
  EnvironmentList,
  EnvironmentMetadataPull,
  InvitationList,
  Me,
  ProjectList,
  RotationFlagList,
  TokenList,
} from "../src/dashboard/types.ts";

export const PROJECT_1 = "ab".repeat(32);
export const PROJECT_2 = "cd".repeat(32);
const HEX64 = "12".repeat(32);
const SIG = "34".repeat(64);
const FP = "56".repeat(16);
const ROW_ID_1 = "78".repeat(16);
const ROW_ID_2 = "9a".repeat(16);
const ROW_ID_3 = "bc".repeat(16);
const ROW_ID_4 = "de".repeat(16);
// 端末鍵(DK K5): D2 = 電話(cap member / production)、R = 予備鍵(owner / all)。公開鍵は
// 最初の鍵(HEX64)と重複させない(chain-view の duplicate-member-key の fold)
export const FP_D2 = "d2".repeat(16);
const KEYS_D2 = { encPubHex: "a2".repeat(32), sigPubHex: "b2".repeat(32) };
const KEYS_R = { encPubHex: "ae".repeat(32), sigPubHex: "be".repeat(32) };

export const meFixture: Me = { userId: "user_e2e", orgs: [] };

export const PROJECT_GHOST_CURSOR = "ef".repeat(32);

export const projectsPage1: ProjectList = {
  projects: [{ projectId: PROJECT_1, role: "admin" }],
  nextAfter: PROJECT_1,
};
// 空ページ + nextAfter(AUTH_SPEC §11-5 — ghost 除外・確認失敗の省略で
// 候補ページが空になる形)。UI はこれを終端と誤断せずカーソルを進める
export const projectsPageEmpty: ProjectList = {
  projects: [],
  nextAfter: PROJECT_GHOST_CURSOR,
};
export const projectsPage2: ProjectList = {
  projects: [{ projectId: PROJECT_2, role: "reader" }],
};

// 端末鍵の 2 op を含む(DK K5): seq 3 = D1 が D2 を足す、seq 4 = D2 が署名して R を足す
// (D2 の FP はここで束縛される)、seq 5 = D1 が D2 を失効。畳み込み後の user_e2e の
// 端末 = D1(FP 束縛済み)+ R(FP 未束縛・owner/all)= 2 台
export const chainFixture: ChainSnapshot = {
  projectId: PROJECT_1,
  headSeq: 5,
  headHashHex: HEX64,
  entries: [
    {
      suite: "maruhi/v1",
      seq: 1,
      prevHashHex: "00".repeat(32),
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_000_000,
      signatureHex: SIG,
      op: "genesis",
      payload: { encPubHex: HEX64, sigPubHex: HEX64 },
    },
    {
      suite: "maruhi/v1",
      seq: 2,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_100_000,
      signatureHex: SIG,
      op: "add_member",
      payload: {
        targetUserId: "user_colleague",
        encPubHex: HEX64,
        sigPubHex: HEX64,
        role: "reader",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    },
    {
      suite: "maruhi/v1",
      seq: 3,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_200_000,
      signatureHex: SIG,
      op: "add_device",
      payload: {
        ...KEYS_D2,
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["production"],
      },
    },
    {
      suite: "maruhi/v1",
      seq: 4,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP_D2 },
      timestampMs: 1_756_000_300_000,
      signatureHex: SIG,
      op: "add_device",
      payload: { ...KEYS_R, roleCap: "owner", scopeKind: "all", scopeEnvironmentIds: [] },
    },
    {
      suite: "maruhi/v1",
      seq: 5,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_400_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: "user_e2e", deviceFingerprintsHex: [FP_D2] },
    },
  ],
  attestations: [],
};

// 読めない端末 op を 1 行含むチェーン(K5-17 の注記の描画用): 現メンバーでない対象の失効
export const chainWithUnreadableEntry: ChainSnapshot = {
  ...chainFixture,
  headSeq: 6,
  entries: [
    ...chainFixture.entries,
    {
      suite: "maruhi/v1",
      seq: 6,
      prevHashHex: HEX64,
      actor: { userId: "user_e2e", keyFingerprintHex: FP },
      timestampMs: 1_756_000_500_000,
      signatureHex: SIG,
      op: "revoke_device",
      payload: { targetUserId: "user_ghost", deviceFingerprintsHex: [FP_D2] },
    },
  ],
};

const environmentStatement = {
  suite: "maruhi/v1",
  environmentId: "production",
  name: "production",
  chainHeadHashHex: HEX64,
  chainHeadSeq: 1,
  signatureHex: SIG,
  status: "active",
  metaVersion: 1,
  prevMetaSigHashHex: "",
  authorUserId: "user_e2e",
  authorKeyFingerprintHex: FP,
} as const;

export const environmentsFixture: EnvironmentList = {
  environments: [{ environmentId: "production", currentEpoch: 1, statement: environmentStatement }],
  schemaPolicy: "disabled",
};

export const metadataPullFixture: EnvironmentMetadataPull = {
  environmentId: "production",
  currentEpoch: 1,
  statement: environmentStatement,
  variables: [
    {
      ...environmentStatement,
      variableId: "var-database-url",
      name: "DATABASE_URL",
    },
  ],
  deletedVariables: [],
  schemaPolicy: "disabled",
};

// admin 可視の project DO 応答(seq あり — AUDIT_SPEC §7)。端末 2 事件(AUDIT_SPEC §3.4 —
// DK)は汎用描画のまま(K5-6): payload は記録どおりの JSON で出る
export const projectAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_4,
      seq: 5,
      serverTs: 1_756_000_400_000,
      event: "chain.device_revoked",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 5,
      payload: { deviceKeyFingerprints: [FP_D2] },
    },
    {
      id: ROW_ID_3,
      seq: 3,
      serverTs: 1_756_000_200_000,
      event: "chain.device_added",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 3,
      payload: {
        deviceKeyFingerprint: FP_D2,
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["production"],
      },
    },
    {
      id: ROW_ID_1,
      seq: 2,
      serverTs: 1_756_000_100_000,
      event: "chain.member_added",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_colleague",
      chainSeq: 2,
    },
    {
      id: ROW_ID_2,
      seq: 1,
      serverTs: 1_756_000_000_000,
      event: "chain.genesis",
      actor: { type: "user", userId: "user_e2e", keyFingerprintHex: FP },
      targetUserId: "user_e2e",
      chainSeq: 1,
    },
  ],
};

// 本人軸(D1 経路 — seq は誰にも返らない)
export const selfAuditEvents: { events: AuditEvent[] } = {
  events: [
    {
      id: ROW_ID_1,
      serverTs: 1_756_000_200_000,
      event: "auth.login_succeeded",
      actor: { type: "user", userId: "user_e2e" },
    },
  ],
};

export const rotationFlagsFixture: RotationFlagList = {
  flags: [
    {
      environmentId: "production",
      variableId: "var-database-url",
      basis: "read",
      targetUserId: "user_colleague",
      recommendedAtMs: 1_756_000_300_000,
      triggerChainSeq: 3,
      trigger: "remove_member",
    },
    // 端末失効の変種(AUDIT_SPEC §4.1 — DK): trigger = revoke_device、対象は人(FP は運ばない)
    {
      environmentId: "production",
      variableId: "var-api-key",
      basis: "readable",
      targetUserId: "user_e2e",
      recommendedAtMs: 1_756_000_400_000,
      triggerChainSeq: 5,
      trigger: "revoke_device",
    },
  ],
};

// ---------------------------------------------------------------------------
// S8(招待管理)・S9(トークン管理)のフィクスチャ。期限は「未来 = 2100 年 /
// 過去 = 2023 年」の固定値(実行時刻に対して安定 — 裁定 CQ の Expired 表示は
// クライアント時計との比較なので、境界近傍の値を使わない)
// ---------------------------------------------------------------------------

const FUTURE_MS = 4_102_444_800_000; // 2100-01-01
const PAST_MS = 1_700_000_000_000; // 2023-11-14

const acceptanceFixture = {
  inviteeUserId: "user_colleague",
  inviteeEncPubHex: HEX64,
  inviteeSigPubHex: HEX64,
  signatureHex: SIG,
  linkSignatureHex: SIG,
  acceptedAtMs: 1_756_000_100_000,
} as const;

// 発行文(AUTH_SPEC §15-1 — IV): リンク公開鍵・発行時点のヘッド・発行署名(公開値)
const issuanceFixture = {
  linkPubHex: HEX64,
  headHashHex: HEX64,
  headSeq: 3,
  issueSignatureHex: SIG,
} as const;

const pendingInvite = {
  id: "inv-pending",
  projectId: PROJECT_1,
  role: "member",
  scopeKind: "all",
  scopeEnvironmentIds: [],
  status: "pending",
  inviterUserId: "user_e2e",
  issuance: issuanceFixture,
  createdAtMs: 1_756_000_000_000,
  expiresAtMs: FUTURE_MS,
  acceptance: null,
} as const;

export const invitationsFixture: InvitationList = {
  invitations: [
    pendingInvite,
    {
      id: "inv-accepted",
      projectId: PROJECT_1,
      role: "reader",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      status: "accepted",
      inviterUserId: "user_e2e",
      issuance: issuanceFixture,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: FUTURE_MS,
      acceptance: acceptanceFixture,
    },
    {
      id: "inv-completed",
      projectId: PROJECT_1,
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      status: "completed",
      inviterUserId: "user_e2e",
      issuance: issuanceFixture,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: PAST_MS,
      acceptance: acceptanceFixture,
    },
  ],
};

// 失効後のサーバー申告(pending 行が revoked へ) — UI は再取得で写す(裁定 CO)
export const invitationsAfterRevoke: InvitationList = {
  invitations: [
    { ...pendingInvite, status: "revoked" },
    ...invitationsFixture.invitations.slice(1),
  ],
};

export const tokensFixture: TokenList = {
  tokens: [
    {
      id: "tok-active",
      name: "ci",
      tokenPrefix: "maruhi_pat_abcdefgh",
      scopes: [{ project: "*", permission: "admin" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: 1_756_000_100_000,
      expiresAtMs: FUTURE_MS,
    },
    {
      id: "tok-expired",
      name: "old-laptop",
      tokenPrefix: "maruhi_pat_ijklmnop",
      scopes: [{ project: PROJECT_1, permission: "read" }],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: null,
      expiresAtMs: PAST_MS,
    },
    // 移行(AUTH_SPEC §6 裁定 CE)前の旧無期限行 — 検証側は期限切れ扱い
    // (fail-closed)。表示は Expired + no expiry recorded(裁定 CQ)
    {
      id: "tok-legacy",
      name: "legacy",
      tokenPrefix: "maruhi_pat_qrstuvwx",
      scopes: [],
      createdAtMs: 1_756_000_000_000,
      lastUsedAtMs: null,
      expiresAtMs: null,
    },
  ],
};

// 指定失効は行の削除(サーバー実装 — 一覧から消える)
export const tokensAfterRevoke: TokenList = { tokens: tokensFixture.tokens.slice(1) };

// ---------------------------------------------------------------------------
// S11(端末登録簿 — AUTH_SPEC §13-11。advisory)。tokenId は tokens の一覧と id で突合する
// (K5-8): 1 行目は "ci"(tok-active)に紐づき、2 行目は一覧に無いトークン、3 行目は紐づけなし
// ---------------------------------------------------------------------------

export const devicesFixture: DeviceList = {
  devices: [
    {
      keyFingerprintHex: FP,
      encPubHex: HEX64,
      sigPubHex: HEX64,
      label: "macbook",
      tokenId: "tok-active",
      createdAtMs: 1_756_000_000_000,
    },
    {
      keyFingerprintHex: FP_D2,
      ...KEYS_D2,
      label: "phone",
      tokenId: "tok-gone",
      createdAtMs: 1_756_000_200_000,
    },
    {
      keyFingerprintHex: "0e".repeat(16),
      ...KEYS_R,
      label: "codespace",
      createdAtMs: 1_756_000_300_000,
    },
  ],
};
