# ADR-0001: 実行基盤に Cloudflare を採用

**Context**: セルフホスト可能かつサーバーレスの secrets 管理。候補は Cloudflare / Deno Deploy / Prisma Compute。
**Decision**: Cloudflare(Workers + Durable Objects + D1 + Static Assets)。
**Rationale**: (1) 基盤の存続性・成熟度が突出(Deno Deploy は Classic 廃止の移行実績、Prisma Compute はベータ + canary ランタイム)。(2) DO の「テナント = 一貫性ドメイン」がプロジェクト単位の DEK・監査ログ設計と例外的に適合。(3) ターゲット層の CF アカウント保有率が高く「自分のアカウントに一発で立つ」体験が成立する。
**Consequences**: 動的シークレット等の長時間処理は将来 Cloudflare Containers 等へ逃がす。
