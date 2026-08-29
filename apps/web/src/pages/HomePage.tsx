// サーバーコンポーネント(ビルド時に RSC ペイロードへ固められる)。
// ビルド時刻を埋め込むことで「ビルド時レンダリングされた静的シェル」であることを検証可能にする。
import { CounterCard } from "../components/CounterCard.tsx";
import { ResumeToDashboard } from "../dashboard/ResumeToDashboard.tsx";

const builtAt = new Date().toISOString();

// S1 ランディング(web-dashboard-design.md §3 S1 — 静的・未認証・API 不要)。
// 本格的なポリッシュは W2 以降。e2e の機構検証フック(built-at / counter / to-about)は
// 維持する(スパイク A の CSP・hydration・StyleX 検証の回帰テスト対象)
export function HomePage() {
  return (
    <main>
      {/* サインイン往復のマーカーがあるときだけ /dashboard へ戻す(裁定 BU)。
          マーカーなしのランディングは API を呼ばない */}
      <ResumeToDashboard />
      <h1>㊙ maruhi</h1>
      <p>A general-purpose, diskless secrets manager that runs on Cloudflare.</p>
      <p>
        Self-hostable, serverless, and end-to-end encrypted by default. Everything happens in the
        CLI: <a href="https://github.com/maruhiapp/maruhi#install-cli">install maruhi</a> to get
        started.
      </p>
      <p>
        <a href="/dashboard" data-testid="to-dashboard">
          open the dashboard
        </a>{" "}
        — a read-only view of your projects (sign-in required).
      </p>
      <p>
        <a href="/about" data-testid="to-about">
          go to about
        </a>
      </p>
      <CounterCard />
      <p data-testid="built-at">server-rendered at build time: {builtAt}</p>
    </main>
  );
}
