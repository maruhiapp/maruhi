# ADR-0001: Adopt Cloudflare as the execution platform

**Context**: Self-hostable and serverless secrets management. Candidates were Cloudflare / Deno Deploy / Prisma Compute.
**Decision**: Cloudflare (Workers + Durable Objects + D1 + Static Assets).
**Rationale**: (1) The platform's longevity and maturity stand out (Deno Deploy has the migration track record of retiring Classic; Prisma Compute is beta + canary runtime). (2) DO's "tenant = consistency domain" is an exceptionally good fit for the per-project DEK and audit-log design. (3) A large share of the target audience already has a CF account, so the "stands up in your own account in one shot" experience works.
**Consequences**: Long-running work such as dynamic secrets will be offloaded to Cloudflare Containers or similar in the future.
