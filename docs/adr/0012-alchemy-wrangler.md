# ADR-0012: IaC は Alchemy v2 Effect スタイル + セルフホストは wrangler 両対応

**Context**: 自分が運用するデプロイ(クラウド版・開発環境)と、ユーザーがセルフホストする配布物では要件が異なる。
**Decision**: 運用側は Alchemy v2 の Effect スタイル(インフラとランタイムの型付き結線)。セルフホスト配布物は素の wrangler 設定 / Deploy to Cloudflare ボタンで立つ経路を必ず維持し、ユーザーに Alchemy 依存を強要しない。
**Rationale**: 「ワンクリックで自分のアカウントに立つ」が製品価値の核であり、配布物の依存は最小でなければならない。デプロイ定義の二重管理は参入障壁を下げる対価として許容する。
**Consequences**: 退避経路: Alchemy の async スタイル、または wrangler への完全退避。CI でセルフホスト経路(wrangler のみ)のデプロイ検証を行う。
