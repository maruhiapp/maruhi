# ADR-0012: IaC is Alchemy v2 Effect style + self-hosting also supported via wrangler

**Context**: The deploys we operate ourselves (cloud edition, development environments) and the distributed artifact users self-host have different requirements.
**Decision**: Operations side uses Alchemy v2's Effect style (typed wiring of infrastructure and runtime). The self-hosted distribution always keeps a path that stands up with plain wrangler config / a Deploy to Cloudflare button, and never forces an Alchemy dependency on users.
**Rationale**: "One click to stand up in your own account" is the core of the product's value, so the distribution's dependencies must be minimal. Double-maintaining deploy definitions is accepted as the price of lowering the barrier to entry.
**Consequences**: Fallback path: Alchemy's async style, or a full retreat to wrangler. CI verifies the self-hosted path (wrangler only) deploy.
