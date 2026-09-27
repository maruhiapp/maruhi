# Session 03 memo (real deployment verification + root integration + AUDIT_SPEC + test vectors)

Date: 2026-08-01. Prerequisite: all of session 02's PRs (#2–#5) are merged to main. Cloudflare credentials (an account API token) are registered in Cloud Agents > Secrets.

## 1. Real deployment verification (demonstrating ADR-0012)

All commands were run with `DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false` ("say nothing").

### Credential check

- `wrangler whoami`: **authentication succeeded with the account API token** (account: maruhi). Every wrangler operation (deploy / delete / direct API calls) works with this token
- Token-type measurement: `/accounts/:id/tokens/verify` → active, `/user/tokens/verify` → `Invalid API Token`. In other words it is an **account-owned token**, and no `/user/*` endpoint can be called at all

### spike-b: wrangler path — ✅ works

- `wrangler deploy` succeeded (Total Upload 1272 KiB / gzip 264 KiB; Worker Startup Time 25 ms)
- Verified the counter API on the real URL: GET initial value 0 → increment (+3, +2) → GET 5 (**DO SQLite persistence works in the real edge environment**). A different-named counter is 0 (DO isolation). An invalid payload is a 400 (Schema validation)
- `wrangler delete --force` succeeded. Verified via API that the workers list is empty (no residue)

Pitfalls:

1. **wrangler auto-registered a workers.dev subdomain**: deploying with no subdomain registered on the account registers one derived from the worker name, `spike-b`, with a warning (there is no delete API — it can only be changed). Changing it to `maruhi` via API was not possible under this session's permission constraints, so **the `spike-b` subdomain remains on the account**. Recommend the owner change it in the dashboard (Workers & Pages → workers.dev in the right pane) to `maruhi` or similar (changing it invalidates the old URL immediately; there are currently 0 workers so now is the time)
2. **Issuing the TLS certificate for a new subdomain takes about 10 minutes**. Until then, connections to `*.spike-b.workers.dev` fail with SSL handshake failure (not an HTTP response — verifying right after a deploy needs a retry loop)

### spike-b: Alchemy v2 path — ⛔ blocked by the account API token (request to the owner)

- Env-var authentication under `CI=1` itself works (credentials are read; no `AuthError: No credentials configured`)
- `alchemy plan` requires a state store: `Cloudflare State store not found. Run 'alchemy bootstrap cloudflare' ... or pass --yes`
- `alchemy deploy --yes` (with state-store bootstrap) failed while deploying the `alchemy-state-store` worker with **`Unauthorized: Authentication error` (Cloudflare error 10000)**
- Root-cause substantiation (checked the alchemy 2.0.0-beta.67 source): the state-store bootstrap uses an **edge-preview session + `/user/tokens` endpoints** (`src/Cloudflare/StateStore/State.ts`; `src/Cli/commands/cloudflare.ts` comments `/user/tokens/verify` as the "source of truth"). These assume a **user API token** and return 401 for an account-owned token. Consistent with wrangler working everywhere on the same token
- **→ Stopped here as instructed. Request to the owner: replace `CLOUDFLARE_API_TOKEN` with a user API token (created in the dash under My Profile → API Tokens, with Workers edit permission).** Re-verify `alchemy deploy` / `alchemy destroy` in a separate session after the swap
- The failure happened before deploy, so **no resource residue** (workers list verified empty). Only the local `spikes/spike-b/.alchemy/log/out` was updated (git-restored)

**Re-verification (2026-08-02, after swapping to a user API token) — ✅ works. Both ADR-0012 paths demonstrated**:

- `/user/tokens/verify` → active; `wrangler whoami` shows "User API Token"
- `CI=1 bun x alchemy deploy --yes`: state-store bootstrap (the `alchemy-state-store` worker + `AlchemyStateStoreToken` / `AlchemyStateStoreEncryptionKey` registered in Secrets Store) → the SpikeB stack deployed in one go. **The worker name under alchemy's naming rule was `spike-b-spikeb-dev-unknown-<hash>`** (derived from stack + resource + stage; different from the wrangler path's `spike-b`. When putting it into operation in Phase 1, explicit settings for stage / naming are needed)
- Verified the counter API on the real URL (`*.maruhi.workers.dev`): GET 0 → increment (+3) → 3; invalid payload 400. TLS responded immediately since enough time had passed since the subdomain change (spike-b → maruhi)
- Cleanup: `alchemy destroy --yes` deleted SpikeB → `wrangler delete --name alchemy-state-store` → deleted the 2 alchemy secrets in Secrets Store via API → verified workers / KV / secrets all empty. **Only Cloudflare's default Secrets Store container (`default_secrets_store`, empty) remains** (created by the alchemy bootstrap; the account-default store, harmless)
- Learning: alchemy's state store is designed as "bootstrap a permanent worker + secret each time it is used". Deleting it every time, as in verification, is not the intended usage; when adopting it operationally in Phase 1, decide whether to accept the state store (worker + secret) as a permanent resource or switch `alchemy.run.ts`'s `state:` to a different store

### apps/web: Workers Static Assets + _headers (CSP) — ✅ works

- `bun run build` (vite build + write-headers.ts) → `wrangler deploy` succeeded. 11 asset files uploaded (`_headers` is not served as an asset; it is consumed as configuration — as expected)
- **Confirmed the CSP header is applied in production**: the real URL's response carries `content-security-policy: default-src 'none'; script-src 'self' 'sha256-…'; …` (the build-time-computed hash allowlist for the inline bootstrap — the approved exception in CLAUDE.md). `referrer-policy: no-referrer` / `x-content-type-options: nosniff` are also applied
- Verified delivery of index.html / CSS / the RSC payload (`funstack__/fun__rsc-payload/*.txt`). **For the first tens of seconds after deploy, assets can 404** (propagation delay; resolves on retry)
- **SPA fallback behaves differently in production than under wrangler dev**: `not_found_handling: "single-page-application"` returns index.html only for requests carrying `Sec-Fetch-Mode: navigate` in production (a bare curl GET `/about` gets a 404 text/plain). Browser navigations always send navigate, so no real harm — but health checks and curl verification must set the header
- Real-browser measurement (hydration + zero CSP violations via Playwright) is impossible in this cloud environment because the proxy does not pass Chromium's outbound CONNECT (curl works; Chromium gets ERR_CONNECTION_RESET even for example.com). Covered by local e2e against the same build (wrangler dev + Playwright, 4 tests including zero CSP violations)
- Deleted with `wrangler delete` after verification. Workers list verified empty

### Environment-related learnings

- Playwright in the cloud environment uses the preinstalled Chromium at `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` (`bunx playwright install` is unnecessary and forbidden). The apps/web e2e (localhost-facing) works because localhost is in the proxy exclusion list

## 2. Root integration PR

- Added 3 independent steps to ci.yml: 8. web build (vite + write-headers), 9. web e2e (`bunx playwright install --with-deps chromium` → wrangler dev + Playwright), 10. `doctor:astryx`. **The web e2e is NOT in the root vitest.config.ts projects** (it requires build artifacts — as spike-a recommended)
- Removed the fixed e2e port (8791): switched to letting the OS assign a free port via `node:net`'s `listen(0)` (no collisions under parallel runs). Added an `e2e` script to apps/web for running from CI
- Added `DO_NOT_TRACK=1` / `WRANGLER_SEND_METRICS=false` to CI-wide env (applying "say nothing" to maintainer CI too — a spike-b learning)
- ROADMAP check-offs: the 3 to-be-decided items, the 3 verification spikes, the npm placeholder + org

## 3. Drafting docs/AUDIT_SPEC.md (0.1-draft, awaiting human review)

- Designed the schema by working backward from the event list (authentication / org / data = variables × environments / chain mirror / server access via grant_server), the actor model (internal user_id + key FP + API token id only), and the query requirements (Q1–Q5) of CRYPTO_SPEC §7's rotation-needed detection
- Storage: project-family events = append-only inside the project DO (same DO, same transaction as the chain; queries complete inside the DO). Org / user-family events = **proposal: a dedicated D1 table (option A)** after comparing 3 options (authentication events can be written in the same transaction as sessions / tokens, and they do not participate in detection queries, so there is no benefit to co-locating them in the DO)
- Points needing a decision (undecided #1–#5): details of the read-permission model, chain checkpoints for audit heads, preservation after project deletion, aggregation of var.read, SIEM export

## 4. Crypto test vectors (packages/crypto/test-vectors/; committed ahead of implementation)

- Copied the official RFC 9180 vectors (extracted in spike-c) into `hpke/`. The maruhi-specific parts are `encoding.json` / `variable-encryption.json` / `chain-entries.json` / `recovery-wrap.json` / `dek-wrap.json` (fixed keys and fixed nonces + tamper-type negatives)
- Expected values computed by two independent reference tools: Python 3.11 + pyca/cryptography (`tools/generate_reference.py`) and hpke-js's ekm derandomize (`tools/generate-dek-wrap.mjs`). Additionally cross-checked all vectors with a third implementation line (Bun WebCrypto + panva hpke's non-extract KeyPair Open) (`tools/verify_reference.mjs` — all PASS)
- **Defined the substance of chain canonicalization here** (CRYPTO_SPEC §6.1: "implementations pin it down with test vectors"): nested LP encoding (payload fields in a fixed per-op order), binary values as lowercase hex strings, entry_hash = SHA-256(the signed entry bytes). Key FP is a plain concatenation (fixed-length 32B×2). **Human review required** (see "points to check in particular" in test-vectors/README.md)
- Excluded `packages/crypto/test-vectors/tools/**` from fallow's analysis (same disposable-tool treatment as spikes/)
- No packages/crypto implementation code written (post-spec-approval, human review mandatory)

## Record of decisions / sorting (2026-08-01)

- **The hosted version does not use Workers for Platforms** (sorted with the owner): it is served as a normal multi-tenant Workers app + project-DO isolation. WfP is a mechanism for running tenant code; maruhi's tenant isolation is at the data level (the project DO's namespace separation) and suffices. The AUDIT_SPEC §5 storage design (shared D1 table + project DO) also rests on this premise
- **Upstream reports around funstack-static are set aside for now** (owner decision; no real harm). Record of findings: ① tracing the emitter of the preload `as="stylesheet"` (correctly `style`) showed the source is **react-server-dom code vendored into @vitejs/plugin-rsc 0.5.32**, not funstack-static itself. The preload is merely disabled with a console warning; the CSS body loads via a normal `<link rel="stylesheet">` — no real harm. ② The inline bootstrap is a funstack-static design choice (`bootstrapScriptContent`), and operation is settled on the approved hash-allowlist scheme. If reported, ① belongs to plugin-rsc / React (after cross-checking against the facebook/react original), and ② belongs as a proposal to funstack-static to switch to `bootstrapScripts` (external URL)
- **The workers.dev subdomain change to `maruhi` is complete** (done by the owner in the dashboard; the old `spike-b` is disabled. Future deploy URLs are `<worker>.maruhi.workers.dev`)
- **The owner swapped `CLOUDFLARE_API_TOKEN` for a user API token** (My Profile → API Tokens, "Edit Cloudflare Workers" template + D1 Edit, scoped to the maruhi account). Re-verification of the Alchemy path happens in a new session after the swap (secrets are injected at container start and do not reach existing sessions)
