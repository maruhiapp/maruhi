// サーバーコンポーネント。SPA ナビゲーション(Navigation API)/ MPA 劣化の検証対象ページ。
export function AboutPage() {
  return (
    <main>
      <h1 data-testid="about-heading">about maruhi</h1>
      <p>
        <a href="/" data-testid="to-home">
          back to home
        </a>
      </p>
    </main>
  );
}
