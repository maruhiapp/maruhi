// ダッシュボードのルート定義(共有モジュール — 裁定 BO: docs/notes/session-43.md)。
//
// パス空間は /dashboard 前置に固定し、API のパス空間(/auth・/projects 前置 —
// server の run_worker_first 列挙)と素で分離する。component は App.tsx が
// bindRoute で結合し、クライアント側は本モジュールを import して useRouteParams の
// 型を得る(funstack-router の部分ルート定義)。
import { route } from "@funstack/router/server";

/** S1 landing (static, unauthenticated). */
export const homeRoute = route({ id: "home", path: "/" });

/** About page (static). */
export const aboutRoute = route({ id: "about", path: "/about" });

/** S3 login / S4 project list (auth-state adaptive). */
export const dashboardRoute = route({ id: "dashboard", path: "/dashboard" });

/** S6 self axis: the signed-in user's account events. */
export const accountAuditRoute = route({ id: "dashboard-account", path: "/dashboard/account" });

/** S5 overview / S6 project audit / S7 rotation flags for one project. */
export const projectRoute = route({
  id: "dashboard-project",
  path: "/dashboard/projects/:projectId",
});

/**
 * 全 SPA ルート(裁定 BZ — docs/notes/session-43.md §12)。ユニットテストが
 * この列挙を wrangler.jsonc の run_worker_first と突合し、「SPA のルート空間は
 * Worker に飲まれない」(裁定 BO の分離)を実ルート定義から導出して検査する。
 * ルートを追加したらここに載せる — App.tsx が本モジュール以外のルートを
 * 持たないことは同テストの目視外だが、bindRoute の結合は本モジュールの
 * export を経由することで単一目録が保たれる。
 */
export const SPA_ROUTES = [homeRoute, aboutRoute, dashboardRoute, accountAuditRoute, projectRoute];
