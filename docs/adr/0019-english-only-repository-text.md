# ADR-0019: All repository text is English (supersedes ADR-0017 decision 3)

Status: 2026-09-26 owner ruling. Accepted on merge of the PR that adds this ADR.

**Context**: ADR-0017 made all user-facing text English (CLI output, web UI, docs site, README, release notes) while leaving internal text — code comments, ADRs, specs, `docs/notes/`, commit messages, PR descriptions — in Japanese (decision 3). That boundary was "does a user read it from the distributed artifact".

Two things changed since:

1. maruhi is published as OSS (ROADMAP Phase 2) and is being expanded overseas. The repository itself is now part of the distributed artifact: issues, review comments, and contributions arrive from engineers who cannot read Japanese, and source text in Japanese is a trust and contribution barrier.
2. AI agents (Devin, Claude Code, Cursor) are primary readers and writers of this codebase. English source is better understood by them and costs fewer tokens than Japanese.

The ADR-0017 rationale — one language, chosen so that error text can be pasted into issues, searched, and read in CI logs — now applies to internals for the same reasons.

**Decision**:

1. **All text committed to this repository is English.** Scope: code comments, JSDoc/doc-comments, internal documentation (`docs/**` including the specs, ADRs, and `docs/notes/`), test names and test-internal messages, workflow/config comments, agent-facing instruction files (`CLAUDE.md`, `AGENTS.md`, `.agents/skills/`, `.claude/`), and commit messages / PR titles / PR descriptions. This supersedes ADR-0017 decision 3; ADR-0017 decisions 1, 2, 4, and 5 stand unchanged (user-facing text is English; no i18n mechanism is introduced).
2. **Exceptions are enumerated, not discretionary.** A file may contain non-English text only when:
   - it is intentional non-English test/fixture data (e.g. values exercising non-ASCII handling) — the line carries an inline `english-exempt: <reason>` marker,
   - it is a third-party license or externally-defined text that must stay verbatim (e.g. `apps/web/public/fonts/OFL-NotoSansCJK.txt`),
   - its path is listed in `scripts/english-exemptions.txt` (with the reason recorded there).
3. **Enforcement is mechanical.** `bun run check:english` (`scripts/check-english.mjs`) scans the files a PR touches for CJK text and fails the check pipeline first. Lines marked `english-exempt` and paths in the exemptions file are skipped. Until the migration completes the gate covers changed files only (the ratchet); the final migration PR switches it to `--all`.
4. **Migration is incremental, per area** — the same pattern as ADR-0017 decision 4. Each PR translates a disjoint file set and must keep `bun run check` green. Mixed-language state is tolerated during the migration. Translation preserves cross-reference codes verbatim (`DK`, `ES`, `KL3`, `IV`, `K15`, `DP2`, `BU`, `§` section refs, `session-NN`, `ADR-NNNN`) and follows `docs/GLOSSARY.md` for domain terms.
5. **Commit messages, PR titles, and PR descriptions are English from now on.** Release notes are generated from PR titles (`release.yml` `--generate-notes`), so this retires the manual release-notes rewrite recorded in ADR-0017 addendum ruling 3. Git history is not rewritten.

**Rationale**: (1) On a public repo, comments and docs *are* user-facing — the ADR-0017 boundary moved, not its logic. (2) A single language everywhere removes the mixed state that ADR-0017 explicitly called out as having neither side's benefits. (3) Enumerated exceptions keep "intentional" distinguishable from "not yet migrated" — a regression the ratchet gate can then catch mechanically. (4) Agents read specs and comments constantly; English is both better parsed and cheaper in tokens.

**Consequences**: The migration is large (~700 files contain Japanese at adoption time) but almost entirely comments and documents — identifiers and user-facing strings were already English, so behavior does not change. Meta-tests that mechanically scan source text (`apps/cli/test/message-style.test.ts`, `redacted.test.ts`) interact with translation and may need their own Japanese text translated in the same PR. The specs (`CRYPTO_SPEC` / `AUTH_SPEC` / `AUDIT_SPEC`) are normative documents — their translation PRs get the same human review bar as spec changes. `docs/notes/` session logs are translated last and least carefully: they are historical records, and the ADR accepts their translation being lossier than the specs'.
