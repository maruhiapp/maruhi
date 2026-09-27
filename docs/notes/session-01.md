# Session 01 handoff memo (setting up the development foundation)

Date: 2026-07-31. Scope is the development foundation only. No product logic or crypto code implemented yet.

## What this session did

1. Consistency check across the 5 documents (CLAUDE.md / ROADMAP.md / CRYPTO_SPEC.md / AUTH_SPEC.md / ADR.md) (results below)
2. Split `docs/ADR.md` into `docs/adr/NNNN-slug.md` × 12 + index `README.md` (verified the bodies match the originals; only heading levels `##`→`#` were adjusted)
3. Bun workspaces monorepo skeleton: `packages/{crypto,core,api-schema}` + `apps/{server,cli,web,docs}`
4. Wired the 7-step quality gate into `bun run check` and GitHub Actions (`.github/workflows/ci.yml`)
5. Vitest 4 + `@cloudflare/vitest-pool-workers` (the server runs in a real workerd environment). 5 dummy test files, 6 tests passing
6. Installed 18 agent skills under `.agents/skills/` (source of truth) + `.claude/skills/` (symlinks)

## Document inconsistencies and gaps (unfixed — awaiting human judgment)

1. The ADR preamble's "Status: all Accepted" contradicts ADR-0003's "[provisional]". 0003 should carry its own Status
2. The docs row of the CLAUDE.md tech-stack table still reads "separate repository or apps/docs", left undecided. Under the monorepo layout it is settled as apps/docs
3. The count of "to be decided before implementation starts" items: ROADMAP says 2 (environment model, authorization model), but AUTH_SPEC §9-1 "the relationship between projects and organizations" is also marked to-be-decided, so effectively 3
4. ADR-0010's CI ordering lacks the seventh step (tests). Inconsistent with CLAUDE.md's quality gate
5. The CRYPTO_SPEC §8 recovery wrap's AES-256-GCM has no AAD specified (inconsistent with design principle 3, "every ciphertext is bound via AAD / info"). → The 2026-07-31 revision draft has been reflected in §8 (AAD = "maruhi/v1/recovery-wrap" || user_id). Awaiting approval
6. The CRYPTO_SPEC §8 HKDF has no salt specified. → The 2026-07-31 revision draft has been reflected in §8 (salt = empty; the RFC 5869 §3.1 uniform-random-IKM clause). Awaiting approval
7. The preamble of the split-out `docs/adr/README.md` still contains the line "each ADR will be split in the future" (kept per the no-text-changes instruction; can be removed in the next document revision)
8. Typo level: missing spaces such as ADR-0005 "平文がAPI", ADR-0009 "でありGitHub" — english-exempt: quotes literal text owned by docs/adr/

## Actual environment / versions (deltas from the documents)

- **Bun 1.4 is unreleased** (latest as of 2026-07-31 is 1.3.14). Pinned 1.3.14 via `.bun-version` + `engines`. Consistent with ROADMAP's "waiting for Bun 1.4 release". Update it in an independent PR once 1.4 ships
- Major versions (all strictly pinned): typescript 7.0.2 / vitest 4.1.10 / @cloudflare/vitest-pool-workers 0.20.1 / oxlint 1.76.0 / oxfmt 0.61.0 / @import-lint/cli 0.1.6 / fallow 3.10.0 / react-doctor 0.9.2 / @cloudflare/workers-types 5.20260731.1
- vitest-pool-workers changed its API in v0.13. The old `defineWorkersConfig` has been removed; the current form is the `cloudflareTest()` Vite plugin (see `apps/server/vitest.config.ts`). Config examples in old articles do not work

## Operating the quality gate

- `bun run check` = oxfmt --check → oxlint → tsc → ImportLint → fallow audit → React Doctor → vitest run. CI uses the same order
- **fallow**: baselines are committed under `fallow-baselines/`. Only update them via `bun run fallow:baseline` when intentionally re-accepting existing issues
- **ImportLint**: `*.package` directory naming is the boundary (`defaultImportability: "package"`). To activate the Drizzle isolation (ADR-0006) or crypto-internal API boundaries during implementation, name the target directory `foo.package`
- **React Doctor**: apps/web has no React yet, so it passes with "rules gated off". Once React lands in spike A it becomes a real check automatically. Because telemetry (Sentry) exists, **always pass `--no-telemetry`** (already set in scripts)
- **oxfmt**: Markdown is excluded from formatting (decided 2026-07-31: documents are not reformatted)
- No vitest projects are defined for web / docs. Add them to the root `vitest.config.ts` projects when spike A / Blume land

## Agent skills

- Source of truth: `.agents/skills/` (read by Cursor etc.). `.claude/skills/` is a symlink
- fallow / react-doctor / improve-react are **symlinks into node_modules** (version-linked). They show as broken links until `bun install` runs — that is normal
- The 8 drizzle skills are **copies** from drizzle-kit@rc (1.0.0-beta line). Once drizzle-kit is added as a dependency in Phase 1, resync them with `drizzle-kit skills`
- Sources: heroui-react / import-lint / funstack-{router,static}-knowledge / blume / blume-update-docs were installed via `npx skills add` (GitHub distribution)

## The Astryx adoption decision (2026-08-01, ADR-0013) and the styling operating rules

- By owner decision the web UI uses Astryx (Tailwind v4 rejected). See ADR-0013. The heroui-react skill has been removed
- Astryx has 4 styling paths: defineTheme (tokens, variants) / xstyle (stylex.create + typed tokens) / className (external CSS interop) / style (inline). swizzle means importing source code (**requires the StyleX compiler — without it the trap is silently rendering unstyled**)
- **Operating rules decided at B2 (2026-08-01)**: defineTheme is the baseline; only local adjustments use xstyle (bound to typed tokens). className / inline style / stylex.props in app code are mechanically banned via oxlint (oxlint-plugin-eslint's no-restricted-syntax, apps/web scope), lifted only inside `ui.package/`. Recurrence of the same override is promoted to a theme variant or into ui.package (no backflow). Codified in CLAUDE.md; firing and exemption verified against a dummy violation file
- **swizzle is fully banned — settled (2026-08-01, owner decision)**: importing Astryx internals into the repository is prohibited regardless of means (substantive criterion; manual copying counts the same). Upstream bugs are handled by rejecting upgrade PRs under strict pinning, so no hotfix exception is needed. UI that cannot be expressed is solved by UX redesign / composition / building on the public API / upstream issues and PRs
- **Correction (important)**: the StyleX compiler is required not for swizzle but **the moment `stylex.create` is written (the moment xstyle use begins)** (confirmed in the official docs). "No warning, unstyled render" applies to authored StyleX generally. In spike A, always verify the combination of FunStack (Vite) + the StyleX compiler
- Implementation left for spike A: `astryx init --features agents` (generates AGENTS.md), adding `astryx doctor` to the quality gate, considering `@stylexjs/eslint-plugin` on top (validating xstyle values)
- Enforcement means (verified): oxlint native no-restricted-imports (paths/patterns + overrides), no-restricted-syntax via oxlint-plugin-eslint (jsPlugins), astryx doctor (CI-friendly exit code), ImportLint's *.package boundary
- Astryx distributes SKILL.md files; there is no MCP npm package (verified). Agent support is the CLI (--json / capability manifest / --lang dense) plus AGENTS.md / CLAUDE.md generated by astryx init --features agents. Adoption happens in spike A
- Version discipline: stable only (no canary), strict pinning, updates via the astryx upgrade codemod + an independent PR

## Handoff to the next session (ROADMAP spike A)

Spike A (updated by ADR-0013): funstack-static + funstack-router + **Astryx** → Workers Static Assets. Verify the `"use client"` boundary, degraded behavior in browsers without Navigation API, static delivery of Astryx's prebuilt CSS, and conformance with the strict CSP. Generate agent documents with `astryx init --features agents` and add `astryx doctor` to the quality gate.

- Workspace is `apps/web` (skeleton only, no React dependency). A disposable spike may live in a separate directory
- Skills `funstack-static-knowledge` / `funstack-router-knowledge` are installed (heroui-react removed per ADR-0013)
- ~~Register the HeroUI Pro license in the cloud environment (Cloud Agents > Secrets)~~ → **no longer needed (ADR-0013)**. This repository does not use HeroUI. If Pro is used, it belongs to a future private marketing-site repository
- **HeroUI Pro license constraints (2026-07-31 research; recorded for history)**: Pro is a proprietary license (`@heroui-pro/react`, token required) that forbids sharing/publishing/redistributing components and source, and forbids exposing the token in public environments. Hence Pro cannot ship in an OSS distribution. → This constraint started the UI-library re-selection and **was resolved by ADR-0013 (adopt Astryx)**
- **Research on HeroUI replacement candidates (2026-08-01, updated with measurements)**: candidates are Astryx (Meta, MIT, StyleX-based, published 2026-06, 8 years internal / 13,000 apps) and React Aria Components (Adobe, v1.20, already a monopackage, with official agent skill + MCP + llms.txt). Measured: both pull in 16 packages / ~72 MB, equivalent. However Astryx's prebuilt-CSS approach removes the Tailwind toolchain entirely. Fragility favors RAC (8 years of public compatibility, codemod culture — though its next major is in-flight on nightly); Astryx is 0.x semver with unproven external-community support. **The owner has stated they accept Astryx's newness risk and are willing to drop Tailwind**. Recommendation: repurpose spike A to "Astryx × FunStack" validation, set the fallback path = RAC (+ Tailwind v4), and revise ADR-0007 (awaiting the human's final decision). On adoption, remove heroui-react from .agents/skills, switch in Astryx's CLI/MCP (`astryx init` generates AGENTS.md / CLAUDE.md), and drop oxfmt's sortTailwindcss setting
- **Substantiation of the CRYPTO_SPEC §8 revision draft (2026-07-31)**: Shelve / Keyway do server-side encryption and have no recovery-wrap concept at all — not applicable. E2EE's Infisical decrypts a copy of the private key directly with a recovery kit (random key), and stores a salt only on the low-entropy password path (Argon2id). → The decision stands: "salt = empty" matches Infisical's recovery path, and "AAD binding" is an added hardening none of the three products do
- Adding dependencies uses `bun add -E` (enforced by exact=true in bunfig.toml). Write the reason in the commit message (CLAUDE.md)
- The web is the Trusted Computing Base: verify CSP (`script-src 'self'`) and the no-third-party-scripts rule from the static-shell stage
- funstack-static is based on `@vitejs/plugin-rsc`. Include the "RSC is static shell only (ADR-0007)" constraint among the spike's verification items
