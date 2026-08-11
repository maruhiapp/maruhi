// サーバーコンポーネント(ビルド時に RSC ペイロードへ固められる)。
// ビルド時刻を埋め込むことで「ビルド時レンダリングされた静的シェル」であることを検証可能にする。
import { CounterCard } from "../components/CounterCard.tsx";

const builtAt = new Date().toISOString();

export function HomePage() {
  return (
    <main>
      <h1>maruhi</h1>
      <p data-testid="built-at">server-rendered at build time: {builtAt}</p>
      <p>
        <a href="/about" data-testid="to-about">
          go to about
        </a>
      </p>
      <CounterCard />
    </main>
  );
}
