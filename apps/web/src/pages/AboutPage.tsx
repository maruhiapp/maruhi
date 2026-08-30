// サーバーコンポーネント。SPA ナビゲーション(Navigation API)/ MPA 劣化の検証対象ページ。
import { spaPaths } from "../dashboard/routes.ts";

export function AboutPage() {
  return (
    <main>
      <h1 data-testid="about-heading">about maruhi</h1>
      <p>
        <a href={spaPaths.home()} data-testid="to-home">
          back to home
        </a>
      </p>
    </main>
  );
}
