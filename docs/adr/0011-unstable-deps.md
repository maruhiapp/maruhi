# ADR-0011: Risk-management principles for unstable dependencies

**Decision**: Permit newer technology where the blast radius is small (docs = Blume, fmt = oxfmt); where a fallback exists, adopt it with a declared fallback path (FunStack → SPA, Alchemy → wrangler, HttpApi → Hono); and keep the crypto core on boring standards only (WebCrypto, HPKE). All dependencies are pinned to exact versions, and updates are done deliberately in separate PRs.
