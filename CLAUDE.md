# CLAUDE.md — maruhi

maruhi (㊙) is a general-purpose diskless secrets manager running on Cloudflare.
It is self-hostable (a single `wrangler deploy` into the user's own CF account)
and serverless. E2EE (zero-knowledge) is the default. The brand spelling is
always lowercase `maruhi`.

## Absolute rules (violations forbidden)

### Cryptography & security
- Crypto primitives are WebCrypto plus the selected HPKE library only. **Never
  invent custom protocols or primitives**
- The crypto spec is `docs/CRYPTO_SPEC.md`, the single source of truth. Do not
  implement crypto operations that are not in the spec. Spec changes update the
  spec first, get human approval, then get implemented
- Changes to `packages/crypto` always go through human review. Write test
  vectors first and confirm the implementation passes them
- Plaintext secrets never cross the server API. API-boundary types are the
  `EncryptedPayload` family only (enforced via Schema)
- Actors in the membership log and audit log are **internal user_id and key
  fingerprints only**. Provider identity such as GitHub IDs is never written
  into append-only structures
- No real secrets in the repo, tests, or `.dev.vars`. Always use dummy values
- No telemetry or any external reporting is implemented (the "say nothing"
  principle). Communication with a peer the user explicitly named, for the
  user's own purpose (the sync destination `maruhi sync`; the identity-backing
  lookup `identityBacking = github-signing-keys` — a public-API check that sends
  only the named login, disabled with `none`), is not telemetry
  (2026-09-13 IV ruling)

### CLI diskless invariants
- Never write plaintext secrets to disk. `maruhi run -- <cmd>` passes values by
  memory injection into the child process's environment variables only
- Do not build features that generate or emit `.env`-style files (export is
  future SOPS compatibility only, and explicit)
- The CLI may persist only: the maruhi API token (OS keychain), the master
  secret key (OS keychain), and non-secret configuration
- Value-displaying commands (e.g. cat/export of a value) refuse and print a
  message under AI-agent environments. The implementation is a fail-closed
  two-layer gate (ADR-0016 decision 7 — `ensureValueDisplayAllowed` in
  `apps/cli/src/agent-gate.ts`): the primary boundary is "are stdin and stdout
  both terminals" (`Stdio` service), the secondary layer is known-agent
  detection (std-env — `detectAgentProfile` in `live.ts`). Inputs come through
  Effect services; `process.*` is never read directly. Non-ceremony `isAgent`
  gates (invite / recovery etc.) stay deny-list-based (decision 7's scope)
- Never emit plaintext values or key material into logs, error messages, or
  crash reports

### The web dashboard is the Trusted Computing Base
Under E2EE, decryption happens on the client, so an XSS in the web frontend
leaks every secret. Therefore:
- A strict CSP is mandatory (`script-src 'self'` baseline; no inline scripts or
  eval). The single exception: the bootstrap script produced by our own build,
  individually allowed by a SHA-256 hash computed at build time (owner approval
  2026-08-01; see `apps/web/scripts/write-headers.ts`). `'unsafe-inline'` is
  forbidden in all cases
- No third-party scripts, CDNs, or analytics are ever loaded. All assets are
  self-hosted (Workers Static Assets)
- `dangerouslySetInnerHTML` and equivalent raw-HTML injection are forbidden
  (checked by React Doctor / review)
- Keep dependency additions minimal and the frontend supply chain small

### Web UI (Astryx) styling discipline (ADR-0013)
- Visual changes start at `apps/web/theme/` defineTheme (tokens / variants).
  Brand definitions live only there
- Per-component adjustments use the Astryx `xstyle` prop only, written with
  `stylex.create` + typed tokens (`@astryxdesign/core/theme/tokens.stylex`).
  No raw hex values or magic numbers
- `className` and inline `style` are forbidden (oxlint errors). No external CSS
- Raw-DOM `stylex.props` and new visual patterns live only under
  `apps/web/src/ui.package/`
- Consider customization strictly in this order: ① defineTheme (including new
  variants) → ② xstyle → ③ composition wrapper in ui.package → ④ new hand-built
  component in ui.package (using only Astryx's public API: hooks / tokens etc.)
  → ⑤ issue / PR to upstream (facebook/astryx). UX redesign is an option at
  every stage
- **`astryx swizzle` is forbidden**. Not just the command — bringing Astryx
  internal source into this repository by any means is forbidden (reading the
  internals for learning is fine, copying is not). Upstream bugs are handled by
  strict pinning and "reverting the upgrade PR"; never hot-fix via swizzle
- Hand-written StyleX (`stylex.create`, including for xstyle) requires the
  StyleX compiler at build time and silently renders unstyled without it.
  Consuming prebuilt CSS and defineTheme does not need the compiler
- When the same xstyle override appears 2–3 times, propose promoting it to a
  defineTheme variant or into ui.package to a human (no backflow)
- Do not guess an Astryx component's API — check with
  `astryx component <name> --json`. Versions are stable-only (no canary),
  strictly pinned, and updated via the `astryx upgrade` codemod in a dedicated PR

### Architecture
- Authentication follows `docs/AUTH_SPEC.md`. No automatic account linking by
  email. Sessions are DB-backed (no stateless-JWT-only sessions)
- Drizzle types (table types, select result types) never leave the repository
  service. Public APIs use domain types and Effect types only
- RSC (server components) are static shells only. Secret-handling logic and
  decryption always live in client components / client code
- No Bun-specific APIs (`bun:*`) in server code. The Worker side uses Web
  standards + Workers APIs only
- Past design decisions live in `docs/adr/`. Do not implement anything that
  relitigates an ADR decision (propose changes as an ADR revision to a human)

## Tech stack

| Layer | Technology |
|---|---|
| Runtime (dev/CLI) | Bun 1.4.2 (strictly pinned via `.bun-version`. Reached the 1.4 line per ADR-0004) |
| Server runtime | Cloudflare Workers (workerd) + Durable Objects + D1 |
| Server HTTP layer | Effect v4 `@effect/platform` HttpApi (no Hono) |
| App foundation | Effect v4 line (pinned. Current `4.0.0-rc.117`) |
| DB | Drizzle v1 (`drizzle-kit` migrations, confined inside the Effect service boundary). D1 + DO SQLite |
| Frontend | React + FunStack (funstack-static + funstack-router) + Astryx (StyleX-based. ADR-0013) |
| CLI | `effect/unstable/cli` + Effect. gunshi is retired (ADR-0016). HttpApi-derived typed client |
| IaC | Current deploys are plain wrangler. Alchemy v2 is decided (ADR-0012) but not yet adopted. The self-hosted artifact stays wrangler |
| LP / docs | Blume (ADR-0008 revision 1 — the LP is also Blume). `apps/site` = apex `maruhi.app` (LP `/` + docs `/docs`). Separate deploy from the product origin `my.maruhi.app` |
| Lint/Format | oxlint + oxfmt + ImportLint + fallow + React Doctor |

## Monorepo layout

```
packages/
  crypto/        # E2EE core. WebCrypto + HPKE. Runs in every environment (browser/Bun/workerd). Human review required
  core/          # Domain types, Effect Schema, shared logic
  api-schema/    # HttpApi definitions (shared source for server impl and client derivation)
apps/
  server/        # Workers + DO + D1. Effect HttpApi
  cli/           # `effect/unstable/cli` + Effect. `maruhi` / `mh` binaries
  web/           # FunStack dashboard (product origin my.maruhi.app)
  site/          # Blume. LP (/) + docs (/docs) on apex maruhi.app. Independent wrangler config
```

## Quality gate (always pass before committing)

1. `check:english` → 2. `oxfmt` → 3. `oxlint` → 4. `tsc --noEmit` →
   5. ImportLint → 6. fallow (baseline) → 7. React Doctor (web only, diff mode)
   → 8. **tests** (Vitest: crypto/core/CLI in the normal environment,
   server/DO via `@cloudflare/vitest-plugin` [formerly vitest-pool-workers])

- Respect ImportLint's `@public` directory encapsulation. If a direct import of
  an internal module feels necessary, that is a public-API design gap — consult
  a human
- Tests: server/DO via `@cloudflare/vitest-plugin` (formerly
  `@cloudflare/vitest-pool-workers`, a real workerd environment);
  crypto/core/CLI via Vitest. Do not use `bun:test`
- `packages/crypto` requires test-vector (`test-vectors/`) validation
- deepsec (`.deepsec/`) is an optional maintainer-facing review and is not part
  of the steps above. Procedure: `docs/DEEPSEC.md`. Agent invocation is
  `/deepsec` (`.agents/skills/deepsec`)

## Coding conventions

- Express errors as Effect typed errors; never swallow them. Code that silently
  eats a `catch` is forbidden
- Keep new dependencies minimal. When adding one, record the reason in the
  commit message
- **All repository text is English** (ADR-0019): user-facing strings (ADR-0017),
  comments, internal docs, test names, and commit messages / PR titles. There is
  no i18n mechanism. Exceptions are enumerated in ADR-0019 decision 2 and
  `scripts/english-exemptions.txt`; intentional non-English data carries an
  inline `english-exempt` marker. `bun run check:english` enforces this on
  newly added lines
- Domain-term renderings follow `docs/GLOSSARY.md`; cross-reference codes
  (ruling codes, `§` refs, `session-NN`) are never translated
- Pin unstable dependencies (Bun / Effect v4 / Alchemy v2 / FunStack) exactly.
  Update them deliberately in their own PR

## Reference documents

- `docs/CRYPTO_SPEC.md` — crypto spec (the single source of truth)
- `docs/AUTH_SPEC.md` — authentication & identity spec
- `docs/adr/` — design decision records
- `docs/GLOSSARY.md` — fixed English renderings of domain terms (ADR-0019)
- `docs/DEEPSEC.md` — deepsec (optional vulnerability review, outside the
  quality gate)
- License: server/web = FSL-1.1-MIT, CLI/SDK/crypto = MIT (final — ADR-0003.
  The LICENSE set and CONTRIBUTING.md [DCO] are in place)
