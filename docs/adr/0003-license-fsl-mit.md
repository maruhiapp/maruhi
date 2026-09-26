# ADR-0003: Licenses are FSL-1.1-MIT (server) + MIT (CLI/SDK/crypto)

**Status**: Accepted (final; carried out with owner approval on 2026-08-12)
**Context**: We want to forbid third parties from offering a competing cloud service. AGPL cannot prohibit the offering itself.
**Decision**: Server = FSL-1.1-MIT (prohibits competing use only; auto-converts to MIT after 2 years). CLI / SDK / crypto = MIT.
**Rationale**: The only option that permits self-hosting and personal use while still banning a competing SaaS. The 2-year MIT conversion also tells a trust story: "even if the author disappears, the asset remains".
**Consequences**: Does not call itself OSI "open source" (described as source-available / Fair Source). DCO + the license clause in CONTRIBUTING.md are required at publication. Closed development until then.
**Implementation record**: 2026-08-12, the LICENSE set was introduced on main (root / `apps/server` / `apps/web` = FSL-1.1-MIT full text, `apps/cli` / `packages/{crypto,core,api-schema}` = MIT, CONTRIBUTING.md [DCO 1.1], README license section, and the license field of each package.json). The repository default is FSL-1.1-MIT; MIT overrides it via per-directory LICENSE files.
