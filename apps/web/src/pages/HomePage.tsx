// サーバーコンポーネント(ビルド時に RSC ペイロードへ固められる)。
//
// `my.maruhi.app/` は製品オリジン(TCB)のトップ。LP と docs は apex `maruhi.app`(apps/site —
// Blume)に移ったため、ここは最小の案内(ロゴ + ダッシュボードへの導線 + 製品サイトへのリンク)だけ
// を置く(DP2 裁定 F — docs/notes/web-design-pass.md §4)。e2e の機構検証フック(built-at /
// counter / to-about)は /about(AboutPage — 「このデプロイについて」)へ移した。
import { ResumeToDashboard } from "../dashboard/ResumeToDashboard.tsx";
import { spaPaths } from "../dashboard/routes.ts";

export function HomePage() {
  return (
    <main>
      {/* サインイン往復のマーカーがあるときだけ /dashboard へ戻す(裁定 BU)。
          マーカーなしのランディングは API を呼ばない */}
      <ResumeToDashboard />
      {/* ブランドマークは自前 SVG(DP1)。絵文字 ㊙ はテキスト文脈(CLI / README)に限る */}
      <h1 data-testid="home-heading">
        <img src="/logo.svg" alt="" width="40" height="40" /> maruhi
      </h1>
      <p>
        <a href={spaPaths.dashboard()} data-testid="to-dashboard">
          Open the dashboard
        </a>{" "}
        — a read-only view of your projects (sign-in required).
      </p>
      <p>
        Docs, installation, and the product overview live at{" "}
        <a href="https://maruhi.app">maruhi.app</a>. Everything else happens in the CLI.
      </p>
      <p>
        <a href={spaPaths.about()} data-testid="to-about">
          About this deployment
        </a>
      </p>
    </main>
  );
}
