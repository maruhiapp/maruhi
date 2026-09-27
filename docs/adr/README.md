# maruhi Architecture Decision Records

Status: 0001–0015 are Accepted (0001–0013 approved by 2026-08-01; 0014 proposed 2026-08-07, approved on merge of PR #37; 0015 proposed 2026-08-14, approved on merge of the release-infrastructure PR). 0016 / 0017 proposed 2026-08-16, each approved on merge of its migration PR / the PR adding the ADR. 0018 proposed 2026-08-18 (owner agreement in a design session — session-29), approved on merge of PR #82. 0018 revision 1 (UI contract settled ahead, ceremony TTY-pinning, shell selection deferred — session-30) approved on merge of the PR containing the revision. 0014 revision 1 (pulling the hosted cloud version forward — H0, session-47) and the re-judgment record of 0009 (continuing the direct GitHub implementation — same session) are approved on merge of the PR containing them. 0008 revision 1 (landing page also on Blume — LP + docs on apex `maruhi.app`, synced to the 2026-09-03 owner ruling in web-design-pass.md §1-4) is approved on merge of the DP2 PR. 0019 proposed 2026-09-26, approved on merge of the PR adding this ADR.

Agents are forbidden from implementing anything that overturns these decisions. Propose changes to a human as an ADR revision.

## Index

- [ADR-0001: Cloudflare as the execution platform](./0001-cloudflare.md)
- [ADR-0002: Crypto architecture is selective-disclosure E2EE](./0002-selective-disclosure-e2ee.md)
- [ADR-0003: License is FSL-1.1-MIT (server) + MIT (CLI/SDK/crypto) [provisional — final confirmation before publication]](./0003-license-fsl-mit.md)
- [ADR-0004: Separation of runtime and execution environment](./0004-runtime-separation.md)
- [ADR-0005: HTTP layer is @effect/platform HttpApi (no Hono)](./0005-effect-httpapi.md)
- [ADR-0006: DB layer is Drizzle v1 (confined inside the Effect service boundary)](./0006-drizzle.md)
- [ADR-0007: Frontend is FunStack (funstack-static + funstack-router)](./0007-funstack.md)
- [ADR-0008: docs on Blume, landing on FunStack (revision 1: landing also on Blume — LP + docs on apex)](./0008-blume-docs.md)
- [ADR-0009: Auth is a direct GitHub OAuth implementation; WorkOS rejected (with re-judgment points)](./0009-github-oauth-direct.md)
- [ADR-0010: Quality toolchain](./0010-quality-toolchain.md)
- [ADR-0011: Unstable-dependency risk-management principle](./0011-unstable-deps.md)
- [ADR-0012: IaC is Alchemy v2 Effect-style + self-hosted stays wrangler-compatible](./0012-alchemy-wrangler.md)
- [ADR-0013: Web UI library is Astryx (replaces HeroUI v3 / Pro + Tailwind v4)](./0013-astryx.md)
- [ADR-0014: Product evolution policy — a zero-knowledge team-secret foundation as the mainline, agent isolation as the next wedge](./0014-product-evolution-policy.md)
- [ADR-0015: CLI distribution = compiled binaries first; npm is a Bun-assuming bundled JS](./0015-cli-distribution.md)
- [ADR-0016: CLI argument layer is effect/unstable/cli (gunshi retired) + the value-display boundary is TTY-first](./0016-effect-cli.md)
- [ADR-0017: User-facing text is English only (no i18n mechanism)](./0017-english-only-user-facing.md)
- [ADR-0018: Web trust boundary — hosted Web does not ship a decryptor (values and keys stay on each person's machine; screens roll out in stages)](./0018-web-trust-boundary.md)
- [ADR-0019: All repository text is English (supersedes ADR-0017 decision 3)](./0019-english-only-repository-text.md)
