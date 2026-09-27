# deepsec setup

[Vercel Labs' deepsec](https://github.com/vercel-labs/deepsec) is installed as an optional security review for maintainers. It is not part of the quality gate (`bun run check` / the 7 CI steps) (ADR-0010 is unchanged).

The official setup runs `npx deepsec init`, which goes straight from scaffolding to AI review. Here, only the workspace was committed via `--scaffold-only`. Reasons:

- `process` / `setup` send source to the model and are billed per file
- model credentials are not kept in the repository
- deepsec itself is treated as "a coding agent with a full shell" (the official trust model)

## Location

The isolated workspace is `.deepsec/` (outside the parent bun workspace; the empty `packages` in `pnpm-workspace.yaml` cuts it off from the ancestor monorepo). It is not a product dependency.

| Committed | Not committed |
|---|---|
| `deepsec.config.ts` / `generated-matchers.ts` / `package.json` / lockfile | `node_modules/` |
| `data/maruhi/INFO.md` (prompt context) | `data/*/files/` `runs/` `reports/` `setup/` `project.json` |
| `data/maruhi/SETUP.md` | `.env.local` (credentials) |

The version is strictly pinned in `.deepsec/package.json`. Updates are separate PRs.

## Review results

Revalidated, unfixed findings are tracked in
[`DEEPSEC_FINDINGS_2026-08-25.md`](./DEEPSEC_FINDINGS_2026-08-25.md).
Past documents were closed through revalidation: the initial full review
([`2026-08-22`](./DEEPSEC_FINDINGS_2026-08-22.md)) by the 08-24 run, and
its fixes ([`2026-08-24`](./DEEPSEC_FINDINGS_2026-08-24.md)) by the 08-25
run (in the latter, 7 of 8 points came back `fixed`, only R4 remains).
The generated reports under `.deepsec/data/` are gitignored, so use this
document when handing off to Cloud environments or another chat.

## Invoking as a skill

Installed per the official procedure with `npx skills add vercel-labs/deepsec`. The source of truth is `.agents/skills/deepsec/SKILL.md`; `.claude/skills/deepsec` is a symlink. `skills-lock.json` pins the source and hash. Updates go through `npx skills update deepsec`.

An agent reads the official runbook via `/deepsec` or "scan with deepsec". It first asks for the scope (uncommitted / diff against `origin/main` / the whole repository), then runs `process`. `process` is paid, so decide the spend cap before invoking it.

Step 2 of the official SKILL.md restarts `npx -y deepsec init --through coverage` when `.deepsec/node_modules/deepsec` is missing. Here `INFO.md` was written by hand under scaffold-only and the CLI is pinned in `.deepsec/package.json`, so that path is forbidden. `.agents/skills/deepsec/SKILL.md` carries an overlay:

- `deepsec.config.ts` present = onboarded
- missing `node_modules` is fixed with `cd .deepsec && pnpm install --frozen-lockfile`
- `init` only when there is no config

`npx skills update deepsec` removes this overlay (the `skills-lock.json` hash stays upstream's). Restore the same overlay after updating.

The version-matched documentation is `.deepsec/node_modules/deepsec/SKILL.md` and `dist/docs/` (bundled with the package; named `deepsec-docs`).

## Daily operations

```sh
cd .deepsec
pnpm install
pnpm deepsec scan --project-id maruhi          # regex only. Free
# after preparing credentials:
pnpm deepsec process --project-id maruhi       # AI investigation. Paid
pnpm deepsec revalidate --project-id maruhi    # reduces false positives
pnpm deepsec export --format md-dir --out ./findings
```

Credentials are one of the following (values go in the environment or `.deepsec/.env.local`; only the names stay in config):

- the machine's `claude` / `codex` login — `pnpm deepsec setup --model-auth local`
- a local API key — `--model-auth direct --ai-provider anthropic|openai --ai-api-key-env <ENV>`
- Vercel AI Gateway — per the official docs. Only Sandbox parallel execution needs a Gateway-side token

Credentials are not needed up to `scan`. The first AI review runs only after a human sets the caps (`--max-cost-usd` / `--max-duration`).

## Custom matchers

Per the official docs, add them only from confirmed true positives. Do not grow matchers by guesswork. Procedure: `.deepsec/node_modules/deepsec/dist/docs/writing-matchers.md`.

## CI

Not part of the default PR CI. If it is added, use the official PR mode (`process --diff`) and a split two-job setup (the analysis job gets no write permissions), only after a human approves the spend and the secrets. Do not pass secrets to fork PRs.

## Relationship to the product's "say nothing"

This is a review tool a maintainer runs explicitly, not telemetry added to the product. `process` sends source to the chosen model. Do not run it without that consent.
