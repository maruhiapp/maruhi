// App エントリポイント(サーバーコンポーネント)。ルート定義はサーバーモジュールに置き、
// ページ本体(サーバーコンポーネント)を RSC ペイロードとしてビルド時に固める。
// ダッシュボード(W2 — S3〜S7)はクライアントコンポーネントで、共有ルート定義
// (dashboard/routes.ts)を bindRoute で結合する(裁定 BO — docs/notes/session-43.md)。
import { Router } from "@funstack/router";
import { bindRoute } from "@funstack/router/server";

import { Providers } from "./components/Providers.tsx";
import { AccountAuditScreen } from "./dashboard/AccountAuditScreen.tsx";
import { DashboardScreen } from "./dashboard/DashboardScreen.tsx";
import { DashboardLayout } from "./dashboard/DashboardShell.tsx";
import { ProjectScreen } from "./dashboard/ProjectScreen.tsx";
import {
  aboutRoute,
  accountAuditRoute,
  dashboardRoute,
  dashboardShellRoute,
  homeRoute,
  projectRoute,
  tokensRoute,
} from "./dashboard/routes.ts";
import { TokensScreen } from "./dashboard/TokensScreen.tsx";
import { AboutPage } from "./pages/AboutPage.tsx";
import { HomePage } from "./pages/HomePage.tsx";

// ルート定義(パス)は routes.ts が単一目録(裁定 BZ — SPA 空間と
// run_worker_first の非交差をユニットテストが検査する)。ここは結合のみ
const routes = [
  bindRoute(homeRoute, { component: <HomePage /> }),
  bindRoute(aboutRoute, { component: <AboutPage /> }),
  // 認証が要る画面は pathless の親(DashboardLayout: セッション + AppShell + SideNav +
  // Outlet)の子に置く — 遷移でシェルが再マウントされない(routes.ts の dashboardShellRoute)
  bindRoute(dashboardShellRoute, {
    component: <DashboardLayout />,
    children: [
      bindRoute(dashboardRoute, { component: <DashboardScreen /> }),
      bindRoute(accountAuditRoute, { component: <AccountAuditScreen /> }),
      bindRoute(tokensRoute, { component: <TokensScreen /> }),
      bindRoute(projectRoute, { component: <ProjectScreen /> }),
    ],
  }),
];

export default function App() {
  return (
    <Providers>
      {/* fallback="static": Navigation API 非対応ブラウザでは MPA(フルページロード)に劣化 */}
      <Router routes={routes} fallback="static" />
    </Providers>
  );
}
