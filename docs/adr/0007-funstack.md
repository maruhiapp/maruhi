# ADR-0007: The frontend is FunStack (funstack-static + funstack-router)

**Context**: Candidates were Vite SPA + TanStack Router, meta-frameworks such as Next.js, and FunStack.
**Decision**: funstack-static (build-time RSC, static deploy) + funstack-router (Navigation API). HeroUI v3 / Pro + Tailwind v4.
**Rationale**: An E2EE app gains zero benefit from request-time SSR (the server only holds ciphertext). Build-time RSC aligns perfectly with that constraint: a smaller bundle for the static shell coexists with SEO pages, and the artifact sits as-is on Workers Static Assets. "No server runs = No RCE" matches the attack-surface-reduction philosophy of a secrets product.
**Consequences**: Limited production track record is a risk. Mitigation: restrict the RSC boundary to the static shell and keep a Vite SPA fallback cheap. Code that touches secrets always lives client-side.

**Note (2026-08-01)**: The UI-library portion (HeroUI v3 / Pro + Tailwind v4) was revised to Astryx in [ADR-0013](./0013-astryx.md). The adoption of FunStack (funstack-static + funstack-router) is kept as-is.
