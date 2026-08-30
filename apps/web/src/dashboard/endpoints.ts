// ダッシュボードが消費する API 面の単一目録(裁定 BW — docs/notes/session-43.md §11)。
//
// 画面が fetch するパスはすべて本モジュールのビルダー経由とし、目録
// (DASHBOARD_ENDPOINTS)が各ビルダーを api-schema の (group, endpoint) 識別子に
// 束縛する。ユニットテスト(test/unit/endpoints.test.ts)が目録を登録済み
// HttpApi と突合し、次の 2 不変条件を fail-loud にする:
//
//   1. **パス整合**: ビルダーの生成パス = api-schema のパステンプレート
//      (リネーム・タイポは実行時 404 でなくテストで割れる)
//   2. **セッション許可**: 全消費面が SESSION_ALLOWED_ENDPOINTS(AUTH_SPEC §5)の
//      列挙内(新画面が列挙外 API を呼ぶ形は実行時 403 でなくテストで割れる)
//
// これはサーバー側の serving-topology スイープ(run_worker_first 被覆)の
// クライアント側対応物で、api-schema を中心に両方向の消費が機械検査になる。
// 本モジュール自体は純粋な文字列ビルダーのみ(バンドルへ実行コードの追加なし)。

/** 目録のサンプルパラメータ(テストのテンプレート置換と共有する)。 */
export const SAMPLE_PROJECT_ID = "ab".repeat(32);
export const SAMPLE_ENVIRONMENT_ID = "production";
export const SAMPLE_INVITE_ID = "inv-sample";
export const SAMPLE_TOKEN_ID = "tok-sample";

/**
 * カーソルクエリ名(裁定 CB — session-43 §13)。ビルダーと目録が同じ定数を
 * 読むため、呼び出し側は名前に触れない(取り違えは構文上あり得ない — 裁定 CA
 * と同じ共有定数の形。PR #107 pullfrog 指摘の反映)。`after` = プロジェクト
 * 一覧(AUTH_SPEC §11-5)、`before` = 監査ページング(AUDIT_SPEC §7)。
 */
const PROJECTS_CURSOR = "after";
const AUDIT_CURSOR = "before";

/** カーソルクエリの組み立て(唯一のクエリ付与点 — ビルダー内部でのみ使う)。 */
function withCursor(path: string, name: "after" | "before", value: string | undefined): string {
  return value === undefined ? path : `${path}?${name}=${encodeURIComponent(value)}`;
}

/** 画面が使うパスビルダー(ページング面はカーソル値を受け、名前は付けない)。 */
export const apiPaths = {
  /** Web OAuth の開始(ナビゲーション導線 — 未認証面。AUTH_SPEC §3)。 */
  githubStart: () => "/auth/github/start",
  me: () => "/auth/me",
  logout: () => "/auth/logout",
  projects: (after?: string) => withCursor("/projects", PROJECTS_CURSOR, after),
  chain: (projectId: string) => `/projects/${projectId}/chain`,
  environments: (projectId: string) => `/projects/${projectId}/environments`,
  pullMetadata: (projectId: string, environmentId: string) =>
    `/projects/${projectId}/environments/${environmentId}/pull/metadata`,
  auditEvents: (projectId: string, before?: string) =>
    withCursor(`/projects/${projectId}/audit/events`, AUDIT_CURSOR, before),
  auditInvites: (projectId: string, before?: string) =>
    withCursor(`/projects/${projectId}/audit/invites`, AUDIT_CURSOR, before),
  auditSelf: (before?: string) => withCursor("/auth/audit/events", AUDIT_CURSOR, before),
  rotationFlags: (projectId: string) => `/projects/${projectId}/rotation/flags`,
  invites: (projectId: string) => `/projects/${projectId}/invites`,
  // inviteId / tokenId はサーバー発行の不透明 id(projectId のような形式検査を
  // UI 側に持たない)ため encodeURIComponent を通す — 敵対的サーバーの id が
  // パスを踏み外しても可視の 404/405 に留める(裁定 CN の付随具体化 —
  // docs/notes/session-45.md §5)
  inviteRevoke: (projectId: string, inviteId: string) =>
    `/projects/${projectId}/invites/${encodeURIComponent(inviteId)}`,
  tokens: () => "/auth/tokens",
  tokenRevoke: (tokenId: string) => `/auth/tokens/${encodeURIComponent(tokenId)}`,
} as const;

/** One dashboard-consumed endpoint bound to its api-schema identity. */
export interface DashboardEndpoint {
  readonly group: string;
  readonly endpoint: string;
  /**
   * 認証面の分類: `session` はセッション許可列挙(AUTH_SPEC §5)内で
   * なければならない fetch 消費面、`unauthenticated` は未認証面
   * (ナビゲーション導線 — UNAUTHENTICATED_ENDPOINTS 内)であること。
   */
  readonly access: "session" | "unauthenticated";
  /** サンプルパラメータで具体化したパス(テストがテンプレートと突合する)。 */
  readonly sample: string;
  /**
   * この面に withCursor で付けるカーソルクエリ名(裁定 CB — session-43 §13)。
   * スイープが api-schema のクエリ Schema にこの名前の宣言があることを検査する
   * (パラメータ名のリネームはページング無反応でなくテストで割れる)。
   */
  readonly cursor?: "after" | "before";
}

/** ダッシュボードの全消費面(スイープの検査対象)。 */
export const DASHBOARD_ENDPOINTS: ReadonlyArray<DashboardEndpoint> = [
  {
    group: "auth",
    endpoint: "githubStart",
    access: "unauthenticated",
    sample: apiPaths.githubStart(),
  },
  { group: "auth", endpoint: "me", access: "session", sample: apiPaths.me() },
  { group: "auth", endpoint: "logout", access: "session", sample: apiPaths.logout() },
  {
    group: "membership",
    endpoint: "list",
    access: "session",
    sample: apiPaths.projects(),
    cursor: PROJECTS_CURSOR,
  },
  {
    group: "membership",
    endpoint: "get",
    access: "session",
    sample: apiPaths.chain(SAMPLE_PROJECT_ID),
  },
  {
    group: "environments",
    endpoint: "list",
    access: "session",
    sample: apiPaths.environments(SAMPLE_PROJECT_ID),
  },
  {
    group: "variables",
    endpoint: "pullMetadata",
    access: "session",
    sample: apiPaths.pullMetadata(SAMPLE_PROJECT_ID, SAMPLE_ENVIRONMENT_ID),
  },
  {
    group: "audit",
    endpoint: "events",
    access: "session",
    sample: apiPaths.auditEvents(SAMPLE_PROJECT_ID),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "audit",
    endpoint: "invites",
    access: "session",
    sample: apiPaths.auditInvites(SAMPLE_PROJECT_ID),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "audit",
    endpoint: "self",
    access: "session",
    sample: apiPaths.auditSelf(),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "rotation",
    endpoint: "flags",
    access: "session",
    sample: apiPaths.rotationFlags(SAMPLE_PROJECT_ID),
  },
  // W3b(S8 招待管理・S9 トークン管理 — 失効系画面): 一覧 + 指定失効の 4 面
  {
    group: "invites",
    endpoint: "list",
    access: "session",
    sample: apiPaths.invites(SAMPLE_PROJECT_ID),
  },
  {
    group: "invites",
    endpoint: "revoke",
    access: "session",
    sample: apiPaths.inviteRevoke(SAMPLE_PROJECT_ID, SAMPLE_INVITE_ID),
  },
  { group: "auth", endpoint: "listTokens", access: "session", sample: apiPaths.tokens() },
  {
    group: "auth",
    endpoint: "revokeTokenById",
    access: "session",
    sample: apiPaths.tokenRevoke(SAMPLE_TOKEN_ID),
  },
];
