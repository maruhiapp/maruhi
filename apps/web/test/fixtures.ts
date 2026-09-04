// ダッシュボード e2e / スクリーンショットの共用フィクスチャ(DP3 裁定 F)。
//
// api-schema 由来の型(src/dashboard/types.ts)に適合するリテラルで、乖離は tsc が
// 検出する。実 Schema でのデコード検査は e2e.test.ts(裁定 BV)。ここはテスト
// プロセス専用のモジュールで、配信バンドルには入らない(screenshots.ts と
// e2e.test.ts だけが import する)。
import type {
  AuditEvent,
  ChainSnapshot,
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

export const chainFixture: ChainSnapshot = {
  projectId: PROJECT_1,
  headSeq: 2,
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
      },
    },
  ],
  attestations: [],
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
};

// admin 可視の project DO 応答(seq あり — AUDIT_SPEC §7)
export const projectAuditEvents: { events: AuditEvent[] } = {
  events: [
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
    },
  ],
};

// ---------------------------------------------------------------------------
// W3b(S8 招待管理・S9 トークン管理)のフィクスチャ。期限は「未来 = 2100 年 /
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
  acceptedAtMs: 1_756_000_100_000,
} as const;

const pendingInvite = {
  id: "inv-pending",
  projectId: PROJECT_1,
  role: "member",
  status: "pending",
  inviterUserId: "user_e2e",
  tokenHashHex: HEX64,
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
      status: "accepted",
      inviterUserId: "user_e2e",
      tokenHashHex: HEX64,
      createdAtMs: 1_756_000_000_000,
      expiresAtMs: FUTURE_MS,
      acceptance: acceptanceFixture,
    },
    {
      id: "inv-completed",
      projectId: PROJECT_1,
      role: "member",
      status: "completed",
      inviterUserId: "user_e2e",
      tokenHashHex: HEX64,
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
