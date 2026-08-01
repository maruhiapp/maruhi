# ADR-0010: 品質ツールチェーン

**Decision**: oxlint + oxfmt(Prettier 不使用)、ImportLint(@public カプセル化)、fallow(コードベース健全性、baseline 運用)、React Doctor(web、diff モード)。CI 順: format → lint → tsc → ImportLint → fallow → React Doctor → テスト(Vitest)。
**Rationale**: oxc ファミリーで統一(速度・Tailwind クラスソート内蔵)。ImportLint は暗号コアの API 境界強制というセキュリティ設計を機械化する。全ツールがエージェントスキルを配布しており、エージェント併用開発のガードレールとして機能する。
