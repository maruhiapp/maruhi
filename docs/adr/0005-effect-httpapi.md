# ADR-0005: HTTP 層は @effect/platform HttpApi(Hono 不使用)

**Context**: Workers のデファクトは Hono。Effect v4 全面採用と Alchemy v2 Effect スタイルを決定済み。
**Decision**: HttpApi によるスキーマファースト API。Hono は採用しない。
**Rationale**: (1) Alchemy v2 Effect スタイルは @effect/platform の HTTP 抽象を既に使用しており、Hono を重ねると抽象が二重になる。(2) スキーマ定義から型付きクライアント(CLI 用)と OpenAPI が自動導出される。(3) `EncryptedPayload` 型を API 境界で強制でき、平文が API を通らない不変条件をコンパイル時に守れる。
**Consequences**: 退避経路: HttpApi が実運用に耐えない場合は Hono + ハンドラ内 Effect へ差し替え(ドメインコア・API Schema は無傷)。
