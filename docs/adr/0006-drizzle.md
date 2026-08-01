# ADR-0006: DB 層は Drizzle v1(Effect サービス境界内に隔離)

**Context**: 当初は @effect/sql-d1 で Effect 一貫の予定。Drizzle v1 が Effect v4 ネイティブ対応を発表。
**Decision**: Drizzle v1 + drizzle-kit。リポジトリ層を Effect サービスとして 1 枚に閉じ、Drizzle の型を外に出さない(ImportLint で強制)。D1 は drizzle-kit migrations、DO SQLite は DO 内自己マイグレーション(drizzle-orm/durable-sqlite)。
**Rationale**: スキーマ差分からのマイグレーション自動生成と DO 対応は自作代替不能な生産性。Effect 一貫の目的(型付きエラー・Layer・テスト容易性)はサービス境界で保たれる。
**Consequences**: D1 / DO SQLite 向け Effect ネイティブドライバの有無を開発開始時に確認(なければ tryPromise の薄いアダプタ)。
