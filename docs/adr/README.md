# maruhi Architecture Decision Records

Status: すべて Accepted(0001〜0013 は 2026-08-01 までに承認。0014 は 2026-08-07 提案、PR #37 のマージをもって承認。0015 は 2026-08-14 提案、リリース基盤 PR のマージをもって承認)。
これらの決定を覆す実装をエージェントが行うことは禁止。変更提案は ADR の改訂案として人間に提示すること。

## 索引

- [ADR-0001: 実行基盤に Cloudflare を採用](./0001-cloudflare.md)
- [ADR-0002: 暗号アーキテクチャは選択的開示 E2EE](./0002-selective-disclosure-e2ee.md)
- [ADR-0003: ライセンスは FSL-1.1-MIT(サーバー)+ MIT(CLI/SDK/crypto)【仮決定・公開前に最終確認】](./0003-license-fsl-mit.md)
- [ADR-0004: ランタイムと実行環境の分離](./0004-runtime-separation.md)
- [ADR-0005: HTTP 層は @effect/platform HttpApi(Hono 不使用)](./0005-effect-httpapi.md)
- [ADR-0006: DB 層は Drizzle v1(Effect サービス境界内に隔離)](./0006-drizzle.md)
- [ADR-0007: フロントエンドは FunStack(funstack-static + funstack-router)](./0007-funstack.md)
- [ADR-0008: docs は Blume、ランディングは FunStack](./0008-blume-docs.md)
- [ADR-0009: 認証は GitHub OAuth 直接実装、WorkOS は不採用(再判断ポイント付き)](./0009-github-oauth-direct.md)
- [ADR-0010: 品質ツールチェーン](./0010-quality-toolchain.md)
- [ADR-0011: 未安定依存のリスク管理原則](./0011-unstable-deps.md)
- [ADR-0012: IaC は Alchemy v2 Effect スタイル + セルフホストは wrangler 両対応](./0012-alchemy-wrangler.md)
- [ADR-0013: web の UI ライブラリは Astryx(HeroUI v3 / Pro + Tailwind v4 を置換)](./0013-astryx.md)
- [ADR-0014: 製品進化方針 — ゼロ知識チーム秘密基盤を本線とし、エージェント隔離を次の楔にする](./0014-product-evolution-policy.md)
- [ADR-0015: CLI 配布 = コンパイル済みバイナリ一次 + npm は Bun 前提のバンドル JS](./0015-cli-distribution.md)
