# ADR-0011: 未安定依存のリスク管理原則

**Decision**: 影響半径が小さい場所ほど新しい技術を許容し(docs = Blume、fmt = oxfmt)、退避可能な場所は退避経路つきで採用し(FunStack → SPA、Alchemy → wrangler、HttpApi → Hono)、暗号コアは退屈な標準(WebCrypto、HPKE)のみとする。全依存はバージョン厳密ピン留め、更新は独立 PR で意図的に行う。
