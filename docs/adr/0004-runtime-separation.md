# ADR-0004: ランタイムと実行環境の分離

**Decision**: 開発ツールチェーン・CLI = Bun 1.4 系。サーバー実行 = workerd(Workers)。サーバーコードは Web 標準 + Workers API のみで Bun API 禁止。テストは Vitest に統一(サーバー / DO は @cloudflare/vitest-pool-workers、他は通常環境)。`bun:test` 不使用。
**Rationale**: Bun はサーバー上で動かない(動かす必要がない)。暗号コアはブラウザ / Bun / workerd の 3 環境で動く WebCrypto 縛りとし、移植性を CI で担保。
