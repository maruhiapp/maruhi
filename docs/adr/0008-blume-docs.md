# ADR-0008: docs は Blume、ランディングは FunStack(改訂 1: ランディングも Blume — apex `maruhi.app` に LP + docs)

**Decision**: ドキュメントサイトは Blume(Astro ベース、MCP / llms.txt / 検索 / OpenAPI 内蔵)。
**Rationale**: docs の資産はコンテンツ(Markdown)でありフレームワークではないため移行コストが低く、「後から変えやすい決定」。ゼロコンフィグで AI-ready な現時点最速を採る。Fumadocs は未採用のメタフレームワークを持ち込むため不採用。自作は非差別化労働のため不採用。

## 改訂 1(2026-09-03): ランディングも Blume — apex `maruhi.app` = LP(`/`)+ docs(`/docs`)

Status: 2026-09-03 所有者裁定(docs/notes/web-design-pass.md §1-4 / §4)。DP2 の PR のマージをもって Accepted。表題の「ランディングは FunStack」は本改訂で差し替える(再議論ではなく裁定への同期)。

**Decision**: ランディングページ(LP)は FunStack(`apps/web`)ではなく **Blume のカスタムページ**(Astro の `pages/index.astro`)として、docs と同じ静的サイト `apps/site` に置く。配信は apex `maruhi.app`(Workers Static Assets のみの独立 Worker `maruhi-site`)。製品オリジン `my.maruhi.app`(ダッシュボード = TCB)とは別デプロイ。`apps/docs` スタブは `apps/site` に吸収する。

**Rationale**:
1. **TCB 分離**: LP はマーケティング面であり、ダッシュボードのオリジンに同居させると LP の変更がすべて TCB のリリースになる。別オリジン・別 Worker にすることで、CSP の厳格さと変更頻度をそれぞれに合わせられる(LP も「言わざる」は守る — 外部スクリプト・外部フォント・トラッカーはゼロ)。
2. **1 サイト 1 デプロイ**: LP と docs を同じ Blume プロジェクトに置くと、テーマ(朱 accent・warm neutral・Archivo / Martian Mono)・検索・OG・`llms.txt` を共有でき、ドメインも 1 つ(SEO の集約)。Blume は `basePath: "/docs"` で docs を `/docs/*` に載せ、ルートはカスタムページに委ねる構成を公式にサポートする(DP2 で実機確認)。
3. **FunStack 側の単純化**: `apps/web` は製品(ダッシュボード + 儀式ページ)だけを持ち、`my.maruhi.app/` は最小の案内ページになる。ADR-0007(フロントは FunStack)はダッシュボードについて不変。

**Consequences**: `apps/site` の依存は `blume` 本体(+ 開発用の wrangler / playwright / vitest)。Blume は Astro / Tailwind / React / mermaid 等を内包するため node_modules は大きいが、静的出力の配信物には Blume の chrome が要る JS しか載らない。Tailwind / StyleX / Astryx の React 部品は LP に持ち込まない(web-design-pass.md §4 の 3 層)。LP を Blume の外で作る必要が出た場合は本 ADR の再改訂として提示する。
