# ADR-0005: The HTTP layer is @effect/platform HttpApi (no Hono)

**Context**: Hono is the de facto standard on Workers. Full adoption of Effect v4 and the Alchemy v2 Effect style were already decided.
**Decision**: A schema-first API via HttpApi. Hono is not adopted.
**Rationale**: (1) The Alchemy v2 Effect style already uses @effect/platform's HTTP abstraction; layering Hono on top would duplicate the abstraction. (2) The schema definition auto-derives a typed client (for the CLI) and OpenAPI. (3) The `EncryptedPayload` type can be enforced at the API boundary, so the invariant that plaintext never crosses the API is upheld at compile time.
**Consequences**: Fallback path: if HttpApi cannot hold up in production, replace it with Hono + in-handler Effect (the domain core and API schema remain intact).
