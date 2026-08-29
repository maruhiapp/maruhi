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

/** 画面が使うパスビルダー(パス部のみ — クエリは呼び出し側が付ける)。 */
export const apiPaths = {
  me: () => "/auth/me",
  logout: () => "/auth/logout",
  projects: () => "/projects",
  chain: (projectId: string) => `/projects/${projectId}/chain`,
  environments: (projectId: string) => `/projects/${projectId}/environments`,
  pullMetadata: (projectId: string, environmentId: string) =>
    `/projects/${projectId}/environments/${environmentId}/pull/metadata`,
  auditEvents: (projectId: string) => `/projects/${projectId}/audit/events`,
  auditInvites: (projectId: string) => `/projects/${projectId}/audit/invites`,
  auditSelf: () => "/auth/audit/events",
  rotationFlags: (projectId: string) => `/projects/${projectId}/rotation/flags`,
} as const;

/** One dashboard-consumed endpoint bound to its api-schema identity. */
export interface DashboardEndpoint {
  readonly group: string;
  readonly endpoint: string;
  /** サンプルパラメータで具体化したパス(テストがテンプレートと突合する)。 */
  readonly sample: string;
}

/** ダッシュボードの全消費面(スイープの検査対象)。 */
export const DASHBOARD_ENDPOINTS: ReadonlyArray<DashboardEndpoint> = [
  { group: "auth", endpoint: "me", sample: apiPaths.me() },
  { group: "auth", endpoint: "logout", sample: apiPaths.logout() },
  { group: "membership", endpoint: "list", sample: apiPaths.projects() },
  { group: "membership", endpoint: "get", sample: apiPaths.chain(SAMPLE_PROJECT_ID) },
  { group: "environments", endpoint: "list", sample: apiPaths.environments(SAMPLE_PROJECT_ID) },
  {
    group: "variables",
    endpoint: "pullMetadata",
    sample: apiPaths.pullMetadata(SAMPLE_PROJECT_ID, SAMPLE_ENVIRONMENT_ID),
  },
  { group: "audit", endpoint: "events", sample: apiPaths.auditEvents(SAMPLE_PROJECT_ID) },
  { group: "audit", endpoint: "invites", sample: apiPaths.auditInvites(SAMPLE_PROJECT_ID) },
  { group: "audit", endpoint: "self", sample: apiPaths.auditSelf() },
  { group: "rotation", endpoint: "flags", sample: apiPaths.rotationFlags(SAMPLE_PROJECT_ID) },
];
