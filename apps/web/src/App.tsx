// App エントリポイント(サーバーコンポーネント)。ルート定義はサーバーモジュールに置き、
// ページ本体(サーバーコンポーネント)を RSC ペイロードとしてビルド時に固める。
import { Router } from "@funstack/router";
import { route } from "@funstack/router/server";

import { Providers } from "./components/Providers.tsx";
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
];

export default function App() {
  return (
    <Providers>
      {/* fallback="static": Navigation API 非対応ブラウザでは MPA(フルページロード)に劣化 */}
      <Router routes={routes} fallback="static" />
    </Providers>
  );
}
