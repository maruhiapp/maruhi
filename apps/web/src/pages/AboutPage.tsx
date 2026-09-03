// サーバーコンポーネント。「このデプロイについて」— ビルド時刻とクライアント側の動作確認。
//
// e2e の機構検証フック(スパイク A 起源)の置き場(DP2 裁定 F — docs/notes/web-design-pass.md §4):
//   - built-at: ビルド時 RSC(サーバーコンポーネントが埋めた値が静的シェルに出る)
//   - counter-button: "use client" 島の hydrate と、厳格 CSP 下での StyleX(xstyle)適用
//   - about-heading / to-home: SPA 遷移(Navigation API)と MPA 劣化の検証対象
// セルフホスト運用者にも「何がデプロイされているか」「クライアントバンドルが CSP 下で動くか」を
// 示す診断ページとして意味を持たせる。
import { CounterCard } from "../components/CounterCard.tsx";
import { spaPaths } from "../dashboard/routes.ts";

const builtAt = new Date().toISOString();

export function AboutPage() {
  return (
    <main>
      <h1 data-testid="about-heading">about maruhi</h1>
      <p>
        This is a maruhi server with its read-only dashboard. Values and keys never reach this
        origin in plaintext; everything else happens in the CLI. Source and license:{" "}
        <a href="https://github.com/maruhiapp/maruhi">github.com/maruhiapp/maruhi</a>.
      </p>
      <h2>Diagnostics</h2>
      <p data-testid="built-at">server-rendered at build time: {builtAt}</p>
      <p>Client script check (the button should count when clicked):</p>
      <CounterCard />
      <p>
        <a href={spaPaths.home()} data-testid="to-home">
          back to home
        </a>
      </p>
    </main>
  );
}
