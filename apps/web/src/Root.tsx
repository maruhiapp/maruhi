// 静的シェル(ビルド時 RSC)。ここはサーバーコンポーネントであり、
// クライアントコンポーネントを import してはならない(hydrate されない)。
import type React from "react";

import "./styles/global.css";

// OG 画像は絶対 URL が必須(スクレイパーは相対 URL を解決しないものがある)。静的シェルは
// ビルド時に確定するため、配信オリジンをビルド時環境変数で受け、既定は hosted origin
// (docs/notes/hosted-ops.md)。セルフホストは `MARUHI_WEB_ORIGIN` で自分の deploy URL を
// 指定できる(docs/SELF_HOSTING.md)。裁定 D — docs/notes/web-design-pass.md §3
const publicOrigin = (process.env["MARUHI_WEB_ORIGIN"] ?? "https://my.maruhi.app").replace(
  /\/+$/,
  "",
);
const description =
  "Diskless, end-to-end encrypted secrets manager on Cloudflare. Self-hostable with a single wrangler deploy.";

export default function Root({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>maruhi</title>
        <meta name="description" content={description} />
        {/* ブランドアセットはすべて自己配信(apps/web/public — TCB 規則)。絵文字 ㊙ は使わない */}
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32" />
        <link rel="icon" href="/favicon-192.png" type="image/png" sizes="192x192" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180" />
        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="maruhi" />
        <meta property="og:title" content="maruhi" />
        <meta property="og:description" content={description} />
        <meta property="og:image" content={`${publicOrigin}/og.png`} />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta
          property="og:image:alt"
          content="The maruhi mark (a vermilion 秘 in a circle) next to the word maruhi"
        />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="maruhi" />
        <meta name="twitter:description" content={description} />
        <meta name="twitter:image" content={`${publicOrigin}/og.png`} />
      </head>
      <body>
        {/* フレームワーク(funstack-static)のマウントポイント制約で raw div が必要 — コンポーネント化しないこと。children は親要素の唯一の子でなければならない */}
        <div id="app">{children}</div>
      </body>
    </html>
  );
}
