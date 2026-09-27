# Session 02 handoff memo (Phase 0 verification spikes C / B / A + decisions)

Date: 2026-08-01. Scope is the three Phase 0 verification spikes in ROADMAP and the decisions taken with the owner on their results.

## What this session did

1. Step 0: the document fixes flagged in session 01 (explicit Status on ADR-0003, raising ROADMAP's to-be-decided count to 3, deleting the adr README preamble, ADR-0005/0009 typos) → bundled into the spike C PR
2. Spike C (PR #2): HPKE verification → `docs/notes/spike-c.md`
3. Spike B (PR #3): server foundation wiring → `docs/notes/spike-b.md`
4. Spike A (PR #4): front-end foundation → `docs/notes/spike-a.md`
5. Decisions through Q&A with the owner (below) and their reflection into CRYPTO_SPEC (this PR)

## Decisions (2026-08-01, confirmed by the owner)

1. **HPKE library = `hpke` (panva) adopted**. Fallback path = hpke-js (dajiaji). Reflected in CRYPTO_SPEC §2 / §13 (this PR). Open takes a KeyPair as the standard form
2. **Safari (browsers without Navigation API) is not supported**. The main target is Chrome on PC. `<Router fallback="static">` (MPA degradation) stays in the code as insurance, but the degraded mode's UX is neither verified nor improved
3. **Effect v4 is expected to reach stable within the month**, so beta-specific problems will not be chased. Once stable ships, update the pin in an independent PR (per ADR-0011)
4. Cloudflare credentials are registered later. **The real deployment verification (wrangler / Alchemy v2) happens in a separate session after credential registration**
5. **The CSP inline-bootstrap exception approved** (owner). Only "SHA-256 hash allowlisting of the boot script our own build generates" is allowed; `'unsafe-inline'` is always forbidden. Codified in CLAUDE.md (this PR). An upstream proposal for an external-file option in funstack-static is made separately

## Decisions (agent discretion — the owner delegated "pick the long-term best among the options")

6. **Policy for disposing Effect Layers inside a DO**: the ManagedRuntime is built once at DO instance creation and **dispose is never called**. Instead, Layers scoped to the DO instance lifetime are limited to "ones whose correctness does not depend on a finalizer running", and real resources needing cleanup (connections, locks, etc.) are acquired and released per request / per RPC call via **`Effect.scoped`**
   - Rationale: workerd Durable Objects have no destruction hook (no onDestroy equivalent); hibernation / eviction can happen at any time. A design premised on "dispose gets called eventually" cannot work in principle, so guaranteeing correctness without the call is structurally safer long-term
   - Rejected alternatives: (a) build and tear down a ManagedRuntime per request — loses the DO's in-memory state advantage and pays a latency tax every time. (b) periodic dispose via alarm — no execution guarantee, only more complexity
7. **Merge order of the 3 PRs (measured)**: merge in the order **C (#2) → B (#3) → A (#4)**. C → B has no conflict. Merging A produces one conflict in `.fallowrc.json`, and **taking A's side (`git checkout --theirs .fallowrc.json`) yields the correct merged result** (A's branch already carries the same `spikes/**` exclusion line as B/C). `bun run check` verified green locally on the integrated state
8. **The root integration (adding web e2e to CI, adding `doctor:astryx` to the quality gate, handling of the web vitest project) happens as an independent PR at the start of the next session, after the 3 PRs + this PR merge**. No Cloudflare credentials needed (wrangler dev is local-only), so there is no need to wait for the deployment-verification session

## Decisions (agent-delegated items — additions)

9. **The CRYPTO_SPEC §8 revision draft (the part reflected 2026-07-31) is approved** (the owner delegated the call). Basis: recovery_secret is a uniform-random 256-bit value, meeting RFC 5869 §3.1's salt-omission condition; use separation is carried by info; the AAD is context-bound to user_id in the §2.1 encoding. Consistent with session 01's substantiation (same shape as Infisical's recovery path + AAD as added hardening)
10. **The document inconsistencies flagged in session 01 are resolved** (delegated by the owner): the docs row of the CLAUDE.md tech-stack table is settled as `apps/docs` / ADR-0010's CI ordering gains the seventh step (tests) (this PR)

## Decisions (additional rulings)

11. **Environment model = option C adopted** (owner ruling 2026-08-01): DEK granularity = **project × environment × epoch**. An environment identifier is added to the AAD / HPKE info, and epochs are independent per (project, environment). v1 builds no per-environment permission UI (all members, all environments); only the data structures become environment-aware. The revision of the CRYPTO_SPEC body (§3 / §4 / §5 / §13 #6) happens once, together with the rulings on the authorization model and the org relationship
12. **Crypto test-vector policy approved** (owner): the HPKE layer reuses the official RFC 9180 vectors (extracted in spike-c); the maruhi-specific parts (§2.1 encoding, variable-encryption AAD, chain canonicalization + signatures, recovery wrap) get hand-written JSON with fixed keys and fixed nonces plus tamper-type negatives. Committed after the environment model is reflected and before implementation starts
13. **Splitting the npm securing work** (owner): only the creation of the org `maruhi` is done by the owner in the Web UI (no API is provided). Publishing the placeholder package `maruhi` is done by the agent. The npm token (Granular Access Token) is to be registered as `NPM_TOKEN` in Cloud Agents > Secrets → carried out in a new session after registration

14. **Authorization model = option B adopted** (owner ruling 2026-08-01): complete separation of org roles and project roles. The on-chain role has 4 tiers — owner / admin / member / reader; grant_server / revoke_server are owner-only. Reflected in CRYPTO_SPEC §6.2 / §13 #7 and AUTH_SPEC §2 / §9-2 (this PR)
15. **Relationship between projects and organizations = option A adopted** (owner ruling 2026-08-01): automatic personal-org creation, projects.org_id is NOT NULL, and the UI hides the org in solo use. Reflected in AUTH_SPEC §9-1 (this PR)
16. **The "self-host = single-user only + hosted = WorkOS for organization features" proposal is withdrawn** (owner, as a result of the 2026-08-01 discussion). Record of the evaluation: (1) what WorkOS provides is authentication (SSO) and directory sync; the core of maruhi's organization features (who receives a DEK = chain + client-side crypto operations, role authorization) cannot be outsourced due to E2EE's nature, so the design volume does not shrink. (2) The product would fork into single-user and multi-tenant, doubling all future features (collides with ADR-0009's single-codebase strategy). (3) Removing team use from self-hosting thins the OSS distribution's value (what the FSL wants to forbid is competing SaaS; corporate self-hosted team use is an adoption path to welcome). (4) "Being able to insert WorkOS later with no downtime" is already guaranteed at minimal cost by the insertion-point design of AUTH_SPEC §7. Note the audit log is independent of the WorkOS decision by the absolute rule that actor = internal user_id + key fingerprint only
17. **The audit log schema (`docs/AUDIT_SPEC.md`) is drafted next session** (owner confirmed): writing it on top of this PR's spec revisions (environment model, authorization model) after review and merge avoids rework
18. **The npm name securing is complete** (2026-08-01): the org `maruhi` (the @maruhi scope) was created by the owner; the placeholder `maruhi@0.0.1` was published by the agent (maintainer: the owner's account). The token used was a short-lived disposable; the owner revokes it right after publishing (no permanent registration in Cloud Agents Secrets. The real publish in Phase 2 switches to provenance-backed CI publish)

## Remaining tasks for the next session onward

- [x] ~~Merge the 3 spike PRs + this PR (procedure 7 above)~~ (#2–#5 merged)
- [x] ~~After merging: run the environment-setup agent~~ (set in the environment configuration. Playwright uses the preinstalled Chromium)
- [x] ~~Root integration PR (item 8 above) + checking off the ROADMAP spike items~~ (done 2026-08-01. Made web build + e2e / doctor:astryx independent CI steps, removed the fixed e2e port, disabled CI telemetry)
- [x] ~~Draft the audit log schema (`docs/AUDIT_SPEC.md`) → define crypto test vectors (committed before implementation)~~ (done 2026-08-01. AUDIT_SPEC is 0.1-draft awaiting review; test vectors committed under packages/crypto/test-vectors/. See docs/notes/session-03.md)
- [x] ~~npm placeholder publish~~ (complete 2026-08-01. `maruhi@0.0.1`)
- [x] ~~ROADMAP check-offs (in the root integration PR after #2 merges. Targets: 3 to-be-decided items, 3 verification spikes, npm placeholder + org — all complete)~~ (done 2026-08-01)
- [ ] Delete the disposable code under `spikes/` (owner-approved policy: delete once Phase 1 has finished referencing it for crypto's 3-environment CI and the server-implementation skeleton. Restore the `spikes/**` line in `.fallowrc.json` at that time)
- [x] ~~Upstream proposal to funstack-static: an option to externalize the boot script (+ report the wrong value on `<link rel="preload" as="stylesheet">`)~~ (owner decision 2026-08-01: **set aside for now**, since there is no real harm. Investigation record in docs/notes/session-03.md)
- [x] ~~After Cloudflare credential registration: real deployment verification (one-shot wrangler deploy / Alchemy v2 / confirming Static Assets honors _headers)~~ (done. The wrangler path + _headers reflection verified 2026-08-01; the Alchemy path after swapping to a user API token verified 2026-08-02. Both ADR-0012 paths demonstrated. See docs/notes/session-03.md)
- [ ] After the Effect v4 stable release: an independent PR to update the pin
