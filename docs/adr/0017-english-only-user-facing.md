# ADR-0017: All user-visible text is English only (no i18n mechanism)

Status: 2026-08-16 owner ruling. Accepted upon merge of the PR that adds this ADR.

**Context**: The CLI's text is currently **written in Japanese**, but actual output is a mix of Japanese and English, because only the parser's default help rendering remains English. During the migration, two notations sit side by side:

```
$ maruhi pull --help          $ maruhi push --help
DESCRIPTION                   stdin から読んだ値を暗号化して push する…  english-exempt: recorded CLI output
  同期検査(§6.3)+ …          USAGE:                                    english-exempt: recorded CLI output
USAGE                           maruhi push <OPTIONS> <name>
  maruhi pull [flags]         ARGUMENTS:
FLAGS                           name  変数名(表示名。環境変数名になる)     english-exempt: recorded CLI output
  --server string  サーバー…   OPTIONS:                                   english-exempt: recorded CLI output
GLOBAL FLAGS                    -h, --help  Display this help message
  --help, -h  Show help …
```

English survives in three places: (a) headings (`DESCRIPTION` / `USAGE` / `FLAGS` — effect/unstable/cli; `USAGE:` / `ARGUMENTS:` / `OPTIONS:` — gunshi), (b) built-in flag descriptions (`Show help information` / `Display this help message`), and (c) a fallback that emits gunshi's English verbatim for codes missing from `args.ts`'s mapping (customParse, conflict).

No i18n mechanism exists anywhere. gunshi has `@gunshi/plugin-i18n`, but it is neither a dependency nor imported, and `effect/unstable/cli` has no locale mechanism at all (the only substitution point is `CliOutput.Formatter` — ADR-0016 decision 3).

**Decision**:

1. **All user-visible text is English**. Scope: CLI output (diagnostics, help, warnings, confirmation prompts), server-API error text that clients display, the web dashboard's UI text, the docs site, README and release notes
2. **No i18n mechanism**. One language; no message table, locale detection, or translation files. `CliOutput.Formatter` is used only "to compose English wording in maruhi's vocabulary"
3. **Internal documents may stay in Japanese**. Code comments, ADRs, `docs/notes/`, `CRYPTO_SPEC` / `AUTH_SPEC` / `AUDIT_SPEC`, commit messages, and PR descriptions are out of scope (keeping the CLAUDE.md coding convention "code comments and internal documentation may be Japanese; JSDoc on the public API is English"). **The boundary is "does a user read it from the distributed artifact"**, not "is it written in the source"
4. **Migration is not done in bulk**. Text is rewritten **per command**, in **the same PR** as the ADR-0016 argument-layer migration (because that command's tests are being rewritten anyway). Wording on commands still on gunshi may stay Japanese until their turn — the mixed period is tolerated.

   **Exception: the 3 commands whose argument layer moved ahead** (`pull` / `run` / `env create`). Migrated before this ADR, they will never again trigger an "argument-layer migration PR". Reading decision 4's binding verbatim would let **these three slip through quietly**, so they are filed as an **independent item** on ROADMAP Phase 2 (already filed in the same PR as this ADR)
5. **Help headings are also unified to English**. ADR-0016 decision 3's `formatHelpDoc` delegates to the default formatter, which can stay English (not inventing our own headings = riding upstream's notation)

**Rationale**: (1) maruhi is a developer CLI distributed via GitHub Releases / npm / brew and will be published as OSS in ROADMAP Phase 2. **Error messages get pasted into issues, searched, and preserved in CI logs**. If that vocabulary is Japanese, the reports and answers that arrive after publication would be split across languages. (2) The current state — "Japanese + English scaffolding" — **enjoys neither side's benefits**; committing to one language removes the inconsistency with the scaffolding itself. (3) Having no i18n mechanism is consistent with maruhi's discipline (invent no in-house mechanisms, add no dependencies). (4) With a single language, if multilingual support is ever needed later, the substitution point is confined to `CliOutput.Formatter`.

**Consequences**: The amount of rewriting is not small — in `apps/cli/src` alone, 53 files contain Japanese and roughly 434 string literals contain Japanese (estimate as of 2026-08-16). In addition, **tests pin behavior on Japanese substrings**, so mechanical replacement would break on the dangerous side (some places branch on exact wording — e.g. `SAFE_EXPECTATIONS` in `cli-formatter.ts`, the mapping in `args.ts`). Decision 4's per-command migration exists for this reason.

Once gunshi is abolished (ADR-0016 decision 1), the only dependency with i18n capability is gone. As decision 2 states, that is the intended outcome; if it is ever needed, an in-house message table goes behind the Formatter (no new dependencies).

The web app (`<html lang="ja">` in `apps/web/src/Root.tsx`) and the docs site are separate work from the CLI. Filed as items on ROADMAP Phase 2.

---

**Addendum (2026-08-17 — English-izing distribution documents and the installer)**: the rest of decision 1 (everything but the CLI) was carried out. The boundary was drawn by decision 3's "does a user read it from the distributed artifact".

**What users read (English-ized this time)**:

- `README.md` / `CONTRIBUTING.md` — the repository's cover page and the DCO document. Contributors read them from the distribution
- `docs/SELF_HOSTING.md` — the verified runbook for self-hosting users (ADR-0014's advanced path. Verified against a real deploy in session 19)
- User-visible messages in `packaging/install.sh` (`warn` / `die` / `printf` / `--help`). In-script comments are internal and stay Japanese
- `lang="en"` in `apps/web/src/Root.tsx` (the web app's visible strings contain no Japanese — Japanese exists only in comments = kept under decision 3)
- GitHub Release published body text is English (decision 1). The mechanism is ruling 3 below

**Internal (stay Japanese)**:

- `docs/CRYPTO_SPEC.md` / `AUTH_SPEC.md` / `AUDIT_SPEC.md`
- `docs/RELEASING.md` itself (operating procedure for the owner)
- `docs/notes/` / `docs/adr/` (except this addendum)
- `CLAUDE.md` / `AGENTS.md`
- Code comments in general. **Including the header comment of `packaging/install.sh`** (ruling 2)
- Comments in `packaging/homebrew/maruhi.example.rb` (`desc` is already English)
- Label strings in `packaging/install-test.sh` (CI-internal. Only the spots that pin install.sh wording by grep were updated collaterally)
- The workspace `apps/cli/package.json` has no `description` field (none added). The manifest shipped to npm is assembled by `apps/cli/scripts/build-npm.ts`; its `description` and bundled `README.md` are **already English** (out of scope this time; kept in English)

The docs site (Blume) was not yet started at the time (`apps/docs` was only a placeholder), and the ROADMAP noted it would be written in English when built. **On 2026-09-03 in DP2 it was built as `apps/site` (LP + docs), and all LP / docs text was written in English** (ADR-0008 Revision 1).

**Rulings**:

1. `SELF_HOSTING.md` / `CONTRIBUTING.md` / install.sh's user-visible messages are on decision 3's "users read from the distribution" side. `CRYPTO_SPEC` / `AUTH_SPEC` / `AUDIT_SPEC` / `RELEASING.md` itself / `docs/notes` / ADR bodies / `CLAUDE.md` are internal
2. **`install.sh` comments stay Japanese**. The README first guides users to `less` the script before running it, but the source of truth for the trust model users read is the English trust-model section of the README. Descriptions of what runs when the script is opened (comments) are for maintainers; only the text emitted at runtime (`usage` / `die` / `warn`) is user-visible. Header lines 5-16 are not English-ized just because they are comments (decision 3 is "does a user read it from the distributed artifact", not "is it written in the source")
3. **GitHub Release published body text is English** (decision 1). The current `release.yml` runs `gh release create --generate-notes`, which builds the body from merged PR titles (no `--draft` = published the moment the tag is pushed). Decision 3 leaves commit messages and PR descriptions in Japanese, and this addendum adopts neither English PR titles, `--notes-file`, nor `--draft`. The owner rewrites the Release body into English right after publication (pinned in RELEASING.md). Mechanism-side changes are a separate decision
4. With `SELF_HOSTING.md`'s headings translated to English, heading references in living internal documents (`AUTH_SPEC` / `SECURITY_REVIEW_2026-08-14.md`) follow the English heading names. Session notes (`docs/notes/`) are dated logs and are not touched
