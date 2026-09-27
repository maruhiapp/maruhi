# ADR-0006: The DB layer is Drizzle v1 (isolated inside the Effect service boundary)

**Context**: The original plan was @effect/sql-d1 for Effect consistency. Then Drizzle v1 announced native Effect v4 support.
**Decision**: Drizzle v1 + drizzle-kit. The repository layer is closed behind a single Effect service; Drizzle types never escape it (enforced by ImportLint). D1 uses drizzle-kit migrations; DO SQLite self-migrates inside the DO (drizzle-orm/durable-sqlite).
**Rationale**: Automatic migration generation from schema diffs plus DO support is productivity we cannot replace in-house. The goals of Effect consistency (typed errors, Layers, testability) are preserved at the service boundary.
**Consequences**: At development start, check whether Effect-native drivers exist for D1 / DO SQLite (if not, a thin tryPromise adapter).
