// 静的シェル(ビルド時 RSC)。ここはサーバーコンポーネントであり、
// クライアントコンポーネントを import してはならない(hydrate されない)。
import type React from "react";

import "./styles/global.css";

export default function Root({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>maruhi</title>
      </head>
      <body>
        {/* フレームワーク(funstack-static)のマウントポイント制約で raw div が必要 — コンポーネント化しないこと。children は親要素の唯一の子でなければならない */}
        <div id="app">{children}</div>
      </body>
    </html>
  );
}
