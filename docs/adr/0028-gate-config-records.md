# ADR-0028: Quality-gate configuration decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 116 comments on quality-gate configuration were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `.fallowrc.json`

- L3: fallow >=3.34 required for the newest keys; an older binary names the upgrade instead of failing on an unknown key
- L7: failOnParseError: an unparseable file drops out of every detector, so a parse failure fails the run instead of warning
- L57: apps/web entries are string references inside vite.config.ts, so fallow entry points are declared manually
- L6 (2026-11-28 tree): ignoreDependencies keeps pagefind only. fallow 3.42 reports an ignore entry that hides no finding (`ignore-dependencies-entry-redundant`, `ignore-patterns-entry-redundant`); with node_modules installed, as in every gate run, it resolves the lint-config and CLI-only tools itself (@effect/tsgo, @import-lint/cli, oxlint-plugin-eslint, @stylexjs/unplugin, @stylexjs/eslint-plugin). The same report retired the `apps/site/public/**` ignore pattern: the directory holds only static assets fallow never analyzes
- L87 (2026-11-28 tree): Every public member of a class that extends DurableObject counts as used: the worker, the cron sweep and the restore worker call the methods through the stub, which the module graph cannot see, so fallow can never tell a used RPC method from an unused one. One scoped `usedClassMembers` rule states that in place of a suppression comment on each of the 42 methods of `apps/server/src/do/chain-do.ts`. The trade: a new public member of that class (a field or a static too) no longer needs its own acknowledged suppression. The rule matches the heritage name only; an unused member of any other class is still reported (probe-verified)
- L135: Boundary zones mirror the CLAUDE.md layer structure: packages below apps, packages never import an app, apps never import each other
- L276: Owner ruling 2026-10-06: a still-consumed @deprecated export is a backward-compat leftover and fails the gate; revisit at first release
- L374: Owner decision 2026-10-24: gate 'all' — every error-level finding in a changed file fails; base-snapshot attribution is skipped

### `.github/jactionlint.yaml`

- L1: jactionlint config of record: default profile, pinned binary run on every change via scripts/install-jactionlint.sh
- L7: No self-hosted declaration: all workflows run on GitHub-hosted ubuntu-26.04; declaring one would misclassify the pool
- L13: Declaring repo variables makes vars.X references strict, so a typo fails lint instead of silently expanding to empty
- L21: Declaring the workflow secrets makes secrets.X references strict

### `.github/workflows/ci.yml`

- L1: ci.yml was split from one job into parallel jobs on separate runners (2026-11-15) because step groups shared one runner's CPUs
- L39: release.yml reuses ci.yml via workflow_call so the release side never drifts onto a stale copy of the gate
- L54: Explicit minimal permissions instead of the loose defaults; test execution needs only checkout
- L59: 'Say nothing' applied to CI: telemetry for cf / wrangler / alchemy disabled in one place
- L66: PLAYWRIGHT_DOWNLOAD_HOST is an unresolvable host so any Playwright download fails; only the verified headless shell is used
- L78: Explicit 15-min cap because ci.yml also gates releases via workflow_call; the 360-min default could block a release for 6 hours
- L85: fetch-depth 0: the fallow audit compares against the base branch and fallow health reads the full history
- L88: persist-credentials false: later steps only read local history; no token left in a job running dependency and test code
- L93: Workflow lint runs first on the checkout alone so a broken workflow fails fast, before the Bun install
- L108: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L121: Static-gate members share no written state (they read checkout and node_modules only), except the .fallow/ cache steps 5 and 5a share
- L175: Lint carries the Effect diagnostics (formerly the separate step 3b) and warnings fail: the pass bar is zero diagnostics
- L195: fallow runs once and renders annotations/summary from the same JSON because those formats work on fork PRs without a write token
- L210: The whole-project fallow run exists because the diff-only audit never judges whether a baseline entry has gone stale
- L225: The duplication baseline is shrink-only; fallow's own --fail-on-baseline-growth does not replace this check
- L240: React Doctor runs on the whole web tree with warnings blocking and no baseline, because the tree is clean
- L245: astryx doctor sits with the static gates because its checks are source-level and read-only, not build dependents
- L254: Explicit 15-min cap because this job also gates releases via workflow_call
- L259: fail-fast false: all shards always report, so a cancelled sibling cannot hide its share of the suite
- L267: Full history in every job: the six jobs share one checkout prefix and the history readers set the floor for all of them
- L272: persist-credentials false: no token left in a job running dependency and test code
- L277: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L283: Server suite sharded across four jobs; hash ranges are not duration-balanced, so each added shard cuts the slow last range again
- L297: Explicit 15-min cap because this job also gates releases via workflow_call
- L302: fail-fast false: both shards always report, so a cancelled sibling cannot hide its half of the suite
- L310: Full history in every job: the six jobs share one checkout prefix and the history readers set the floor for all of them
- L315: persist-credentials false: no token left in a job running dependency and test code
- L320: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L326: The CLI suite is sharded across two jobs like the server suite
- L333: Explicit 15-min cap because this job also gates releases via workflow_call
- L340: Full history in every job: the six jobs share one checkout prefix and the history readers set the floor for all of them
- L345: persist-credentials false: no token left in a job running dependency and test code
- L350: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L356: zsh is installed because ubuntu-26.04 lacks it and the docs recipe checks run on every shell the page promises, zsh included
- L365: This group holds the plain-node suites; the workerd server suite and the CLI suite are their own sharded jobs
- L377: Explicit 15-min cap because this job also gates releases via workflow_call
- L384: fetch-depth 0: step 7d diffs the vectors against the merge-base with the PR's base branch
- L387: persist-credentials false: no token left in a job running dependency and test code
- L392: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L395: Crypto-vector tools are installed once in the prefix step so 7b/7c/7d share it instead of racing concurrent installs
- L404: pyca comes from the Ubuntu archive this step already trusts: no new package source and no hash list to maintain
- L412: The independent-implementation cross-check runs in CI (consideration 7); manual-only runs could not detect joint impl/vector degradation
- L423: The vector regeneration check runs on every event, not only PRs: it is as cheap as 7b and also gates releases
- L431: 7d is a review aid only: it approves nothing and fails closed when the tool breaks, so a PR is never reviewed without its summary
- L447: Explicit 20-min cap because this job also gates releases via workflow_call
- L454: fetch-depth 0: Nimbus's lastUpdated reads the full history for the site build and the e2e page-date checks
- L457: persist-credentials false: no token left in a job running dependency and test code
- L462: The browser is the pinned, SHA-256-verified headless shell installed by script, not `playwright install`; it runs as a background step
- L500: Bun comes from the SHA-256-pinned official zip with no Actions cache (reasoning in the install-bun action)
- L506: Builds run in parallel because the dependents below read apps/web/dist and apps/site/dist
- L509: Web e2e is not in the root vitest projects because it assumes build artifacts (dist/public + _headers)
- L514: The site deploys via Alchemy (ADR-0012 rev. 1), so the dependents group no longer dry-runs its cf config
- L523: The wait step publishes the background install's PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH and fails the job here if the install failed
- L528: 8b/8c stay one step: every cf deploy build writes apps/server/.cloudflare/output, so the two dry-runs cannot run concurrently
- L556: Site content validation never hits external URLs: 'say nothing' applies to CI too
- L563: No Alchemy plan step in CI: the workflow holds no secrets by supply-chain policy, so the declaration is covered statically instead
- L572: e2e is a separate group after the dry-runs: 8b/8c's cf deploy builds and step 9's cf dev both work in apps/server and must never overlap
- L585: Site e2e contract: every request same-origin, zero CSP violations, self-hosted fonts, /docs reachable, trailing-slash/404 behavior
- L592: Crypto's workerd/browser runs are their own step because they need out-of-build dependencies the root vitest projects do not pick up

### `.github/workflows/english-pr.yml`

- L1: ADR-0019 decision 5 is kept out of ci.yml so editing a PR description re-runs only this lightweight check, not the full gate
- L24: fetch-depth 0: the BASE_SHA..HEAD_SHA commit range needs the full history
- L27: Event fields pass through env, never interpolated into the script, so a PR title or description cannot inject shell

### `.github/workflows/pullfrog.yml`

- L20: 75-min bound: a hung agent run would otherwise hold provider keys and tokens for the 6-hour default; the action self-stops at 1 hour
- L29: External actions are pinned by commit SHA on this privileged path because it passes many provider API keys via env
- L37: persist-credentials false: GITHUB_TOKEN is not left in .git/config on the agent-running job

### `.importlintrc.jsonc`

- L1: The *.package convention: a directory is an encapsulation boundary by name; only @public exports or index.ts re-exports cross it
- L45: indexLoophole is the *.package escape valve: a bare re-export from a boundary's index.ts promotes the export to the parent package
- L58: defaultImportability is 'package', so every *.package boundary is an encapsulation boundary by default with no JSDoc tag required
- L74: packageDirectory is the **/*.package naming convention: a directory is a boundary by name, so this never needs updating as the project grows

### `apps/cli/test/workflows-supply-chain.test.ts`

- L864: The reviewer-approval gate on the publish jobs is deferred until the first public release (docs/RELEASING.md); until then a stable version is refused twice (here on bump, in version-check on tag) — enabling the gate replaces this block

### `apps/cli/tsconfig.json`

- L4: tsconfig: the DOM lib is needed for the WebCrypto types to import @maruhi/crypto sources as types; Bun-specific APIs come from @types/bun (ADR-0004: the CLI may use Bun).
- L8: resolveJsonModule is on because package.json is the single source of truth for the version, imported by cli.ts.

### `apps/site/astro.config.ts`

- L53: Frontmatter must validate against the content schema and broken internal links are reader-facing 404s; bun run validate runs these in CI.

### `apps/site/vitest.config.ts`

- L3: The apex e2e presumes a built dist + _headers, so it is excluded from the root vitest projects and runs as its own CI step.

### `apps/site/vitest.unit.config.ts`

- L3: Site unit tests run without a build and detect theme-artifact drift (ruling B), so they are on the root vitest projects (quality gate 7).

### `apps/web/test/unit/styling-lint.test.ts`

- L1: Styling bans (ADR-0013) silently stopped applying to web files from 2026-08-01 because oxlint matched inherited globs relative to apps/web; the test copies the root config into a temp tree and probes the bans through the effect-tsgo wrapper.

### `apps/web/vite.config.ts`

- L115: The StyleX compiler is always on with no switch to remove it: a build without it loses all styles at runtime silently, and the e2e is the effective defense.

### `apps/web/vitest.config.ts`

- L3: The web e2e config is intentionally not added to the root vitest projects: it assumes a prebuilt dist, so CI runs it as its own step after the build.

### `apps/web/vitest.unit.config.ts`

- L3: Web unit tests run with no build, so they are listed in the root vitest projects (quality-gate 7); styling-lint.test.ts also runs the root lint on probe files in a temporary tree.

### `bunfig.toml`

- L1: All dependencies are strictly pinned (CLAUDE.md / ADR-0011), hence exact = true

### `package.json`

- L17 (2026-11-28 tree): `fallow:baseline` saves the health baseline with `--complexity`: without it fallow also saves its refactoring-target keys, which follow git churn (14 on main 930a1f1) and never gate, so a re-save on a clean tree rewrote the file; complexity findings are saved and gated the same with or without the flag (probe-verified). The dead-code save has no such switch and records warn-level findings too: the six that .fallowrc.json overrides hold at warn and two root devDependencies that production code imports (warn by fallow's default). While they are in the baseline the whole-project run no longer prints them, and an entry that stops matching fails that run (CI 5a), which is the only check that a warn override is still needed

### `packages/core/test/comment-ratchet.test.ts`

- L388 (2026-11-28 tree): The codegen-banner exemption reads "generated by" on a comment's first line only. Matched anywhere in a comment that starts within the first ten lines, it exempted an 18-line prose comment of .fallowrc.json the moment an edit above moved its start to line 10, and the failure asked for a regeneration that would have dropped the comment from the ratchet. No comment in the tree relied on the wider match

### `packages/core/test/effect-tsgo-rules.test.ts`

- L1: Watchdog: vite.config.ts pins every effecttsgo rule because enabling the plugin switches rules on by category — a future rule outside the presets would switch on with no config diff; this test derives the registry from the installed package and fails naming the rule
- L54: The rule registry is derived from the installed @effect/tsgo's oxlint-schema.json — every rule the plugin implements is a key there

### `packages/core/tsconfig.json`

- L4: tsconfig lib includes DOM because @maruhi/crypto's source is imported as types and needs the same WebCrypto types as crypto's

### `packages/crypto/vitest.browser.config.ts`

- L1: This package deliberately declares its own vitest devDependency — the only one in the repo: browser mode dedupes every vitest resolution to the project copy so client and test modules share one module instance; the pin must move with whatever vitest version a new vite-plus bundles, and @vitest/browser-playwright stays direct because it is vite-plus's optional peer the consumer must supply

### `scripts/check-dupes-baseline.mjs`

- L1: Shrink-only gate (CI 5b) for the fallow duplication baseline: entries may be lost but never gained versus the merge-base baseline
- L43: A baseline absent at that revision returns null, which downstream means every current entry is growth

### `scripts/check-english-pr.mjs`

- L12: The CJK class is written with escapes so this file holds no CJK itself; U+3299 (the maruhi mark) stays intentionally out of range

### `scripts/check-english.mjs`

- L25: The CJK character class is documented by range; U+3299 (the maruhi mark glyph) is intentionally out of range
- L87: Hunk-parsing contract: +++ / --- are file headers only before a hunk's first marker; inside a hunk an added line can itself start with +++
- L121: Regression guard: --all scanning zero lines means file collection silently broke, not a clean repo

### `scripts/install-jactionlint.sh`

- L2: jactionlint is the only workflow linter parsing this repo's parallel/background/wait syntax; size, archive and binary SHA-256 all pinned
- L28: die() annotates with ::error:: under GitHub Actions because the message is a workflow command
- L43: An empty destination is refused because the destination is wiped before the unpack

### `vite.config.ts`

- L4: Lint config lives in vite.config.ts because vite-plus reads only the workspace root's lint block; the Effect diagnostics gate lives here too
- L50: Formatter config (formerly .oxfmtrc.json): import sorting is part of the format, and prose / generated files stay unformatted
- L66: effecttsgo is supplied at runtime by the effect-tsgo wrapper (hence the cast); a bare `vp lint` fails to parse this config loudly, by design
- L76: The ten typescript/* ports are wanted at error but inert under tsrs (probe-proven); pinned off, to flip back on a --tsrs-lint bump. Re-probed 2026-11-26 on the 7.1.0-beta.tsrs4 pin (@effect/tsgo 0.73.7): textbook repros (floating promise, await of a non-thenable, async forEach callback, delete on an array index, string setTimeout, for-in over an array, unsafe enum comparison, unsafe unary minus, mixed-type plus, meaningless void) still fire nothing while the type-aware effecttsgo rules fire on the same file, so the ports stay off
- L18: effecttsgo/flat-map-map-to-zip-with (new in @effect/tsgo 0.73.0) is pinned off explicitly: it is a style rule, and style rules stay off in this config
- L19: effecttsgo/promise-all-in-effect and effecttsgo/promise-race-in-effect (new since @effect/tsgo 0.71.0) are adopted at error: a diagnostics census over every workspace project on 2026-11-26 found zero hits, and the rules guard against unbounded, uninterrupted promise fan-out inside Effect code
- L22: A dynamic `import()` in shipped CLI / server / site / package source names a relative path literal (added 2026-11-28). The `importNames` bans of no-restricted-imports (FetchHttpClient, the identity mints) cannot see which names a dynamic import takes — probe-proven: `(await import("effect/http")).FetchHttpClient` passed the gate — while its whole-module bans do fire on a dynamic import. `require()`, any import or re-export of `node:module` (the home of `createRequire`) and `import.meta.require` are banned outright in the same files: no-restricted-imports reads none of them, and Bun runs `require` in an ES module. No shipped source imported a package dynamically or called `require`, so the shapes themselves are banned. The selectors are repeated in the CLI and api-schema overrides because a later no-restricted-syntax override replaces an earlier one; the pagefind search provider in apps/site loads a URL computed at runtime and is exempt; `packages/core/test/module-load-lint.test.ts` lints a probe in every file group. A relative path that climbs into another package's source or into node_modules is outside this rule, as it is outside the static one
- L149: consistent-function-scoping off for tests: promoted to correctness by oxlint 1.85; moving helpers out of tests is a large migration
- L156: Outbound HTTP goes through packages/core/src/egress.ts only: Effect's clients add trace headers, which 'say nothing' rules out
- L218: packages/core/src/egress.ts is the one place allowed to wrap Effect's fetch client (no-restricted-imports off there)
- L223: Identity mint imports are restricted to trust boundaries; the is* guards are not restricted because a non-narrowing format check cannot mint
- L313: Effect fence: packages/crypto is a trusted leaf, Effect-free by contract (values/types/subpaths); the web leaf uses a tripwire instead
- L341: User-facing text says 'device key'/'reserve key' since the device-key separation (DK K7-5/K7-13); 'master key' only in persisted names
- L366: HttpApi success values must be named envelopes (DK K9-4/K9-5/K9-7), not inline Schema.Struct; payload/params/error Structs are excluded
- L388: Astryx styling discipline (ADR-0013) applies to apps/web sources, with the stylex plugin validating xstyle values via jsPlugins
- L417: Styling restrictions are lifted only in apps/web/src/ui.package, where new visual patterns live, and in no other ui.package directory

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
