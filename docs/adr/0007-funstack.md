# ADR-0007: フロントエンドは FunStack(funstack-static + funstack-router)

**Context**: 候補は Vite SPA + TanStack Router、Next.js 等のメタフレームワーク、FunStack。
**Decision**: funstack-static(ビルド時 RSC、静的デプロイ)+ funstack-router(Navigation API)。HeroUI v3 / Pro + Tailwind v4。
**Rationale**: E2EE アプリはリクエスト時 SSR の利益がゼロ(サーバーは暗号文しか持たない)。ビルド時 RSC はこの制約と完全に整合し、静的シェルのバンドル削減と SEO ページの同居を実現、成果物は Workers Static Assets にそのまま載る。「No server runs = No RCE」は secrets 製品の攻撃面削減思想と一致。
**Consequences**: 本番実績の少なさはリスク。緩和: RSC 境界を静的シェルに限定し、Vite SPA への退避を安価に保つ。シークレットを扱うコードは必ず client 側。
