# ADR-0008: docs は Blume、ランディングは FunStack

**Decision**: ドキュメントサイトは Blume(Astro ベース、MCP / llms.txt / 検索 / OpenAPI 内蔵)。
**Rationale**: docs の資産はコンテンツ(Markdown)でありフレームワークではないため移行コストが低く、「後から変えやすい決定」。ゼロコンフィグで AI-ready な現時点最速を採る。Fumadocs は未採用のメタフレームワークを持ち込むため不採用。自作は非差別化労働のため不採用。
