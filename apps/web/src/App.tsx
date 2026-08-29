// App エントリポイント(サーバーコンポーネント)。ルート定義はサーバーモジュールに置き、
// ページ本体(サーバーコンポーネント)を RSC ペイロードとしてビルド時に固める。
// ダッシュボード(W2 — S3〜S7)はクライアントコンポーネントで、共有ルート定義
// (dashboard/routes.ts)を bindRoute で結合する(裁定 BO — docs/notes/session-43.md)。
import { Router } from "@funstack/router";
import { bindRoute, route } from "@funstack/router/server";

import { Providers } from "./components/Providers.tsx";
import { AccountAuditScreen } from "./dashboard/AccountAuditScreen.tsx";
import { DashboardScreen } from "./dashboard/DashboardScreen.tsx";
import { ProjectScreen } from "./dashboard/ProjectScreen.tsx";
import { accountAuditRoute, dashboardRoute, projectRoute } from "./dashboard/routes.ts";
import { AboutPage } from "./pages/AboutPage.tsx";
import { HomePage } from "./pages/HomePage.tsx";

const routes = [
  route({
    path: "/",
    component: <HomePage />,
  }),
  route({
    path: "/about",
    component: <AboutPage />,
  }),
  bindRoute(dashboardRoute, { component: <DashboardScreen /> }),
  bindRoute(accountAuditRoute, { component: <AccountAuditScreen /> }),
  bindRoute(projectRoute, { component: <ProjectScreen /> }),
];

export default function App() {
  return (
    <Providers>
      {/* fallback="static": Navigation API 非対応ブラウザでは MPA(フルページロード)に劣化 */}
      <Router routes={routes} fallback="static" />
    </Providers>
  );
}
