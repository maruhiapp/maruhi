# Design of the hosted cloud edition (H0 — within the frame of ADR-0014 revision 1)

Date: 2026-08-30 (session 47 — rulings CY through DE are in docs/notes/session-47.md). Positioning:
**design document** (same format as W0's docs/notes/web-dashboard-design.md). The norms
(ordering, experience requirements, guardrails) are ADR-0014 revision 1, and the auth-provider
re-examination is governed by ADR-0009's re-examination record; this document fixes the design
references, gap analysis, and implementation split (H1 onward). The merge of this PR
(ADR, ROADMAP, and notes only — no code or spec-body changes) constitutes owner approval.

Premises (do not move — 2026-08-30 owner ruling): (1) the docs site (Wave 3 G) is deferred,
(2) the hosted cloud edition is the top priority and is to be brought to "complete as a service",
(3) the value-free schema is fully implemented, and MCP delivery is deferred (the spec landed in
S0 — docs/notes/session-46.md).

Current state (as of 2026-08-30): the server is structurally multi-tenant (automatic personal-org
creation = AUTH_SPEC §9-1, per-project DOs, E2EE), and no signup restriction exists
(completing GitHub OAuth = get-or-create creates the account — same §3–§4). The W series
(minimizing operator capability — ADR-0018) is implemented. The gaps lie in productization
(signup control, quota, operations, legal).

## 1. Who we promise what (personas)

| # | persona | provenance | what they need from hosted | can self-hosting substitute? |
|---|---|---|---|---|
| HP1 | Individual developers / small teams who do not want to self-host | landing page, word of mouth | "The first 5 minutes" (signup → add secret → `maruhi run`). Must not require a Cloudflare account, OAuth App creation, or wrangler | Possible but an advanced route (ADR-0014 ruling 5) — effectively not viable for this persona |
| HP2 | Developers who habitually use agents | value-free schema, agent-gate differentiation (ADR-0014 decision 2) | Operation that never hands values to agents must hold by default. `maruhi schema` must be immediately tryable | Same as HP1 |
| HP3 | Self-host evaluators | the step before SELF_HOSTING.md | An evaluation environment. Touch it first, then stand it up on their own CF account | Possible (hosted is the shortcut) |
| HP4 | Teams (including GitHub Actions sync) | via invite links (P2 — web-dashboard-design.md) | The invite → mutual confirmation → share sequence. CI leases (AUTH_SPEC §14) | Possible, but requires an operator "sharing one deploy across the whole team" |
| HP5 | Stakeholders who only need audit viewing | identical to W0's P5 | Keyless Web read access (implemented — W2) | No (assumes the CLI is not installed) |

**What we promise** (all are externalizations of properties the implementation and spec already carry):

1. **Zero knowledge**: the operator cannot read variable values (E2EE — the exact scope of the
   guarantee is CRYPTO_SPEC §14. We do not say "absolutely the safest" — ADR-0014 guardrails)
2. **Verifiability**: the source of the clients that perform decryption (CLI / crypto — MIT) is
   public, so the "cannot read" claim can be verified in code (the basis for the ordering in §4)
3. **Minimizing operator capability**: the Web the operator ships holds no decryptor (ADR-0018).
   Token and invitation issuance are terminal-only (same, revision 2)
4. **Zero telemetry**: no outbound transmissions from the client at all (CLAUDE.md "unspoken".
   The line against hosted operational observation is drawn in §6)
5. **Exit path**: because every member's CLI can always decrypt values, migration to self-host
   completes client-side (values are not held hostage)

**Boundaries of the promises** (stated without concealment — continuing ADR-0014 decision 5's
"separate it honestly"):

- **Migration is "re-creation"**: because project ID = genesis hash (bound to the chain),
  hosted → self-host migration is re-creating the project + re-pushing values (+ re-inviting
  members). Chain and audit history cannot be migrated. SOPS-compatible export remains future
  work (ROADMAP). **(2026-08-30 owner decision — this line will be updated in the future)**:
  **productize export / import for hosted → self-host**. Since project ID = genesis hash, the
  chain is self-verifiable, and values are ciphertext, it is **structurally portable**; what is
  missing is only the transport (once implemented, history itself can be carried rather than
  "re-created"). See the §10 handoff for the remaining non-portable parts and design issues
- **Metadata is operator-visible**: project, environment, and variable names, schema fields
  (type, required, description), members' internal user_ids, key FPs, and access patterns sit
  in plaintext on the server (as designed in CRYPTO_SPEC §4). The threat-model document (§7)
  states this line in plain terms
- **No availability SLA** (during beta). Substitute a status page and honest incident reports (§6)
- **Consequence of zero knowledge**: if keys and recovery codes are lost, the operator cannot
  restore values (CRYPTO_SPEC §8. This is not a defect but the price of promise 1 — made
  explicit during onboarding)

## 2. Beta shape and signup control (ruling CY)

### 2-1. Stages

| stage | signup | billing | target | opening conditions |
|---|---|---|---|---|
| **private preview** | manual (a handful of people whose account creation the operator attends) | free | owner + personal-trust acquaintances | anytime (an extension of dogfooding — a verification deploy has existed since 2026-08-10) |
| **invite-only beta** | signup invitation code (2-2) | free | unspecified external developers (HP1–HP4) | the §4 gate (S1–S3 landed × H1–H5 complete × **DP1–DP5 complete [design pass — added by owner ruling on 2026-09-03. ROADMAP.md]** × made public) |
| **open beta** | free (rate-limited) | free + quota (§3) | everyone | measured quota in the invite-only beta + confirmation of GitHub quota headroom (§3-4) + ~~ruling on the CLI login scaling path (§8 gap 9)~~ (ruled 2026-08-31 — session-48 ruling DF. Implementation = H1b completes before H5, so the remaining conditions are measured quota and confirming headroom in self-counted 2,000 token requests/hour) |
| **GA** | free | billing introduced (design is an independent task — out of this document's scope) | everyone | beta-graduation judgment (separate). The docs site (G) is due by here |

The distinction between private preview and invite-only beta is the point of this design:
**before going public (source verifiability), the only acceptable users are those who use maruhi
on personal trust**. Externally promising zero knowledge and holding the secrets of unspecified
outside tenants comes after going public (§4 — ruling DA).

### 2-2. Signup-control design policy (implementation is H1 — enumeration only in this PR)

- **Introduce a deployment setting `signupPolicy` (`open` | `invite` | `closed`)**. The decision
  point is a single gate immediately **before new user creation** in get-or-create
  (AUTH_SPEC §3-3 / §4) — it does not affect existing users' login, token verification, or
  acceptance at all (only new creation is blocked). `closed` rejects all new creation (for
  maintenance or beta closure). **The self-host default is `open`** (identical to current
  behavior — control is unnecessary in single/few-person deploys). Hosted starts at `invite`.
  It is the same "server acceptance policy" class as schemaPolicy (AUTH_SPEC §12-11) and does
  not go on the chain or into signatures
- **Signup invitation codes**: 256-bit random bearer tokens, single-use, expiring (following
  §15 invitations' token_hash / single-use CAS / expiry forms). A code is not bound to any
  project, org, or role (**it carries only permission to create an account**). Issuance is an
  operator operation in beta operations (no issuance UI is built — the operator's wrangler /
  script path suffices — a draft value; finalized in H1)
- **No allowlist of provider identifiers**: an allowlist by GitHub login (mutable) or GitHub ID
  would pull provider information into authorization decisions (running counter to ADR-0009's
  independence), and an email allowlist violates "do not build user lookup/matching by email as
  a code path" (AUTH_SPEC §2 rule, §10 prohibitions). Invitation codes depend on neither
  identifier
- **Form of denial**: new creation that `signupPolicy` does not permit is rejected **after** the
  OAuth / device exchange completes (= after GitHub-side authentication succeeded) with a typed
  error, returning wording that directs to the waitlist (because the decision input — whether
  the user is new — does not exist before get-or-create, the decision point is structurally
  here). No users / linked_identities rows are created on denial (fail-closed). The decision
  uses the configuration at acceptance time (same rule as AUTH_SPEC §12-11 — no transition race
  window is created)
- **Distribution of the setting**: `GET /auth/config` carries `signupPolicy` as advisory
  (public information — the same content as the landing's "beta is invite-only" wording, with no
  incremental reconnaissance value. The original "do not carry it" decision was revised in the
  PR #113 Bugbot review — session-47 §10. It is not an input to authorization or verification
  rules)
- **Cutting off shared-quota consumption on the denial path (2026-08-30 PR #113 Bugbot review
  follow-up — session-47 §10)**: the decision point for signup denial is at exchange time
  (above), but the GitHub device flow's code entry (shared 50/hour — §3-4) is consumed
  **before** that on github.com — denied login attempts burn quota too. In particular, under
  ruling DA's ordering, going public (H5) precedes invite-only beta (H6), so **a window in which
  the hosted existence is public knowledge while signup alone is invite-gated always arises by
  design** (the pullfrog review's reinforcement point). H1 design requirements: (i) the CLI
  checks `/auth/config`'s `signupPolicy` **before starting** the device flow, and if `invite`,
  confirms "re-login of an existing account, or present an invitation code" before starting
  (a fail-closed mis-operation guard — not authorization. The source of truth for acceptance
  stays on the server). (ii) For uninvited new applicants, do not start the device flow and
  instead show waitlist / invitation guidance. (iii) **When an invitation code is presented, the
  CLI checks the code's format, existence, and unconsumed status on an unauthenticated
  pre-verification endpoint before starting the flow** (cuts off the path where a typo'd,
  revoked, or already-consumed code wastefully burns one code entry. Because codes are 256-bit
  random and single-use, the verification surface is not an existence oracle — the same level as
  §15 invitation tokens. Impose a per-IP rate limit). (iv) Add "counting of signup denials" to
  H3's tripwires (§5-2 — denials reach the server at exchange time, so they are observable).
  **Residuals (explicit acceptance ruling — session-47 §10)**: (a) attempts that lie on the
  pre-check or hit the API directly without the CLI still reach code entry — because the
  consumption point is on github.com and no enforcement point exists on the maruhi server, this
  is **structurally unblockable**. (b) Hostile quota exhaustion is possible without going
  through maruhi in the first place (client_id is public information, and device-flow start and
  code entry can be performed directly against github.com). (a) is a subset of (b), and the
  acceptance rationale is identical — unpreventable by server design, and the mitigations are
  that guidance on the legitimate path (CLI) stops good-faith attempts, plus monitoring (iv) and
  the staged gates. The permanent fix is gap 9 (web-flow handoff), which removes the dependency
  on device flow itself.
  **(2026-08-31 addendum — gap 9 ruled: session-48 ruling DF)** With the full revision of
  AUTH_SPEC §4 (device flow abolished — server-mediated handoff), this item is re-based as
  follows: the pre-checks of (i)(ii) are kept as the same-shaped guard "before handoff start
  (`POST /auth/cli/start`)", (iii)'s invitation-code pre-verification can be integrated into
  attached verification on the start payload (whether an independent endpoint is needed is the
  H1 implementation PR's call), and (iv) is unchanged.
  **(2026-08-31 second addendum — supplemental ruling DH: session-48)** Because CLI login no
  longer creates an account (the only signup entry is the Web in AUTH_SPEC §3), (iii) moves
  again: **acceptance and pre-verification of signup invitation codes live only on the Web
  signup side (§3 and its form)**. No code rides on the CLI's start, and the CLI-side guard
  shrinks to the (i)(ii) guidance (if invite-gated, direct to "sign up on the Web, then
  `maruhi login`"). The wrong-account code-burning branch (the former §4-3's referral to H1)
  disappears with this — Web signup can be redone through normal page navigation, and the CLI
  flow consumes nothing until approval. Because the shared 50/hour quota itself disappears, what
  the denial path burns changes to consumption against the 2,000 token requests/hour, and
  moreover every consumption point becomes server-mediated — per-IP blocking and self-counting
  become possible, and the "structurally unblockable" of residuals (a)(b) shrinks significantly
  (the hosted OAuth App can disable Device Flow itself, so direct consumption on the former
  50/hour surface vanishes. The remaining hostile surface is only token requests via the
  callback, which require obtaining a valid GitHub code and sit under per-IP limits)
- **Composition with project invitations (AUTH_SPEC §15)**: during invite-only beta, a person
  without a maruhi account may receive a project invitation (acceptance is token-led = login
  must come first). H1 includes "a signup invitation code can be attached to login / device
  exchange" in its requirements (the §15 invitation-link format is unchanged — the signup code
  is passed over a separate channel. Details in H1)
  ~~**(2026-08-31 addendum — following the §4 revision: the attachment point is the
  `POST /auth/cli/start` payload. "Device exchange" disappears)**~~ **(2026-08-31 second
  addendum — supplemental ruling DH: the attachment point is Web signup (§3) only. Because CLI
  login creates no account, no code ever rides the CLI path — see the second addendum of §2-2)**
- **The waitlist is not productized** (a temporary beta-period operation — contact collection is
  done via external means such as a form; no email-collection surface is built into the server)

## 3. Bounding tenant resources (ruling CZ)

### 3-1. Platform nominal values (primary sources — verified on official Cloudflare / GitHub docs on 2026-08-30)

| resource | nominal value (Workers Paid) | source / note |
|---|---|---|
| D1: max size of one database | **10 GB (cannot be raised)** | developers.cloudflare.com/d1/platform/limits (2026-04-21 edition). Free is 500 MB |
| D1: databases per account / total storage | 50,000 / 1 TB (both raisable on request) | same |
| D1: throughput | one DB is single-threaded (serial). The bound is the inverse of query time (~1,000 qps at 1 ms). Overload queues → overloaded error | same, FAQ |
| D1: Time Travel (PITR) | 30 days | same |
| DO (SQLite): max storage per object | **10 GB** | developers.cloudflare.com/durable-objects/platform/limits (2026-06-01 edition) |
| DO (SQLite): object count / account total | unlimited / unlimited | same |
| DO: throughput | soft cap of ~1,000 req/s per object (single-threaded) | same, FAQ |
| GitHub: OAuth App client-credential requests (incl. the check-token API) | **5,000/hour/App** (15,000 if owned by a GHE Cloud org) | docs.github.com — Rate limits for the REST API |
| GitHub: OAuth access-token requests (web code exchange + device-flow polling) | **2,000/hour/App** (secondary limit) | same |
| GitHub: device-flow user-code entries | **50/hour/App** | docs.github.com — Authorizing OAuth apps, "Rate limits for the device flow" |
| GitHub: token issuance | 10/hour/user; the same (user, app, scope) tops out at 10 | same |

### 3-2. Resource topology and growth terms

Tenant separation is already in good shape — **the project's substance (chain, ciphertexts, DEK
wraps, DO-side audit) is enclosed in the per-project DO, and the 10 GB ceiling is separated on
the Cloudflare side**. The per-object limits inside the DO (AUTH_SPEC §12-8: cumulative
ciphertext 1 GiB, 100 environments, 1,000 variables/environment, etc.) are already bounded
inside it. What hosted must newly consider is two cross-cutting resources:

1. **Shared D1 (single, 10 GB ceiling, single-threaded)**: users / linked_identities / sessions
   / api_tokens (≤ 100 per user) / invitations (≤ 100 pending per project) / recovery_wraps
   (1 row per user, ≤ 16 KiB) / the project_members projection /
   **user_audit_events, org_audit_events (append-only — the only unbounded growth term)**.
   Auth-related events are low-frequency (logins, token issuance) and failure-kind events carry
   fixed-window caps (AUDIT_SPEC §3.1), so growth is slow but proportional to tenant count
2. **The shared quota of the GitHub OAuth App** (3-4)

### 3-3. per-tenant quota (policy. Numbers are draft values — implementation is H2; spec revisions go in each implementation PR)

| target | policy | stage |
|---|---|---|
| projects / org | new acceptance-policy cap of **100 active (draft value)** (revision of AUTH_SPEC §11-3 / §12-8 — gap 2). DO materialization = operator storage, so an unlimited creation surface is not left alone. Since the org-creation API is unimplemented, v1's effective unit is the personal org ≈ per user | H2 (**implemented 2026-09-02 — PR #134**) |
| resources inside a project | already bounded by the existing §12-8 (kept as-is — unchanged) | — |
| total DO storage | **implement §12-8's announced Phase 2 guard (`databaseSize` threshold) in H2**. The only defensive line covering the audit log's indefinite retention (AUDIT_SPEC §5.3). Two-stage thresholds: "warning (ops alert) 8 GB / rejection 9 GB" (draft values — 10 GB's SQLITE_FULL is a readable-but-unwritable floor; do not let it be reached) | H2 (**implemented 2026-09-02 — PR #134**. The announcement text has already been rewritten into §12-8's normative provision) |
| audit rows (DO side) | no cap (append-only discipline — AUDIT_SPEC §1-4). The dominant term var.read has its density reduced by aggregation (same §3.3 / undecided 4), and the DO guard absorbs the total. **2026-09-02 owner decision: pull aggregation forward from "after dogfooding measurement" and design/implement it without waiting for measurement** (per value-carrying bulk pull: one row per environment + enumeration of returned variables in the payload — AUDIT_SPEC 1.5-draft §3.3 / AUTH_SPEC 0.20-draft §12-7. As the paired countermeasure, partial indexing of audit_events' target / key-FP indexes was done in a preceding small PR) | ~~after measurement~~ → **implemented 2026-09-02 — PR #136** (partial indexing in PR #135) |
| audit rows (D1 side) | no row cap (auth-kind is low-frequency + failure-kind is already capped). **Reserve a D1-total monitoring threshold (draft 5 GB) + separation into a dedicated audit D1** (schema-identical, and references are append/read-only so separation is mechanical. The 50,000 DB/account headroom is ample) | H3 (monitoring) / separation when needed |
| sessions / tokens / invitations / recovery | bounded by existing caps (kept as-is) | — |

All quotas are **server acceptance policies** (not consensus rules — same character as §12-8),
and raising them on self-host is free. Overruns are typed errors (429 / 413 / 422); nothing
silently degrades.

### 3-4. GitHub OAuth App shared quota (known concern — an operational revisit of AUTH_SPEC §4 L-3)

In hosted, all tenants share a single OAuth App. Consumption paths vs limits:

| maruhi path | GitHub quota | consumption |
|---|---|---|
| `POST /auth/device/exchange` (server → check-token) | 5,000/hour | 1 exchange = 1 |
| web OAuth callback (server → code exchange + /user + /user/emails) | 2,000/hour (token requests) + ~~5,000/hour~~ (2026-08-31 correction: the /user family counts against the individual user's 5,000/hour — shared App-quota consumption is only the 1 token request. See the addendum below) | 1 login = 1 token request + 2–3 API calls |
| CLI device-flow polling (**user's device** → GitHub) | 2,000/hour (token requests, summed per App) | 1 login ≈ elapsed seconds to approval / 5 |
| device-flow code entry (**user's browser** → github.com) | **50/hour (per App)** | 1 CLI login = 1 |

**The hardest constraint is the device flow's 50 code entries/hour**: CLI logins are a shared
ceiling of 50/hour across all of hosted, and since the consumption point is the user's browser →
github.com, **there is no control or observation point on the maruhi server side** (exhaustion
surfaces as a GitHub error on the user's side).

Bounding policy (integral with ruling CY):

1. **The primary mitigation is the staged gate itself**: keep the invite-only beta's acceptance
   scale within "login frequency × headcount does not reach 50/hour". With the default token TTL
   of 90 days (AUTH_SPEC §6), steady-state re-logins are low-frequency, and the peak concentrates
   right after signup — the invitation-code issuance pace is itself the peak control
2. **Tripwire monitoring** (H3): a threshold alert on the check-token response's rate-limit
   header (x-ratelimit-remaining) + device-exchange failure rate + **the signup-denial count**
   (denials also reach the server up to the exchange, so they are observable — §2-2. Rising
   denials double as a proxy indicator of "quota burned by good-faith wasted attempts"). Direct
   observation of the 50 code entries/hour is impossible, so substitute estimation from
   signup/exchange rates and the denial count (§5-2). **The CLI-side pre-check (§2-2) cuts off
   the denial path's quota consumption itself** — monitoring watches what escapes it (old CLIs,
   direct API use)
3. **Escalation paths are enumerated only** (decision input for the open-beta opening condition
   — gap 9): (a) a web-flow handoff for CLI login (the CLI opens §3's web OAuth in a browser and
   returns to the CLI with a one-time code — moves from the device flow's 50/hour quota to the
   2,000/hour one. Requires an AUTH_SPEC §4 revision), (b) migration to a GitHub App (different
   rate characteristics — a large undertaking), (c) GHE Cloud org ownership (5,000 → 15,000.
   Code entry's 50/hour does not change, so this is not a solution on its own). **Sharding
   across multiple OAuth Apps is not taken** (callback-URL / client_id consistency breaks, and
   the quota is not worth the GitHub ToS risk)

**(2026-08-31 addendum — gap 9 ruled: session-48 ruling DF)** The **direction** of escalation
(a) was adopted (though delivery is **polling**, not (a)'s "return to the CLI with a one-time
code" — code-paste delivery is session-48 §2's rejected option), and AUTH_SPEC §4 was fully
revised (device flow abolished — server-mediated handoff, polling delivery, provider-independent
CLI. Implementation is H1b — §9 addendum). Two corrections to this section from re-confirming
the primary sources (session-48 §1): (1) the "+ 5,000/hour" in this table's web-login row is
wrong — `/user` / `/user/emails` are called with **the user's token** and count against the
individual user's 5,000/hour (shared App-quota consumption is only the 1 token request). (2) It
is now certain that (b) GitHub App migration does not solve this problem — the 2,000/hour
token-request secondary limit is shared across "GitHub Apps and OAuth apps", and code entry's
50/hour also does not change by App type, so the bottleneck does not move; effectively dropped.
(c) is unchanged. After implementation, the two device-flow rows of this table lose their
consumers, and the bottleneck moves to the 2,000/hour token request (summed with web login) —
because every consumption point becomes server-mediated, **self-counting and throttling become
possible** (added to H3's tripwires: "self-counting of token requests" and "login-flow row
creation cap reached" (AUTH_SPEC §4-1 (4) (iii) — the fallback mechanism disappeared under
supplemental ruling DH, and with unrecorded start the only alert target is the creation-point
cap. An event that does not occur in normal operation; occurrence = anomaly detection) — since
the secondary limit has no remaining-observation API, self-counting is the only means of
observation). Additionally, the hosted OAuth App can disable "Enable Device Flow", so hostile
consumption on the 50/hour surface (§2-2 residual (b)) disappears along with the surface. BYO
App is deferred by ruling DG (merges into ADR-0009's next re-examination point).

## 4. Ordering — dogfooding, the S series, going public, beta, GA (rulings DA / DB)

```
   dogfooding (incl. private preview)────────────────────── runs in parallel, ongoing ──────→
   S1 ─ S2 ─ S3 (signing, acceptance, verification surfaces)──┐
   H1 ─ H2 (signup control, quota)──────────────────────────┼─→ H5 publication ceremony → go public → invite-only beta
   H3 (ops foundation) · H4 (legal)─────────────────────────┘        (SECURITY.md + threat-model doc)
   S4 · S5 (import / export / lint)── not a gate (allowed during beta)──────────→
                                       invite-only beta → open beta → GA (billing, docs site)
```

1. **Redefine dogfooding from a "completion condition" to a "parallel ongoing activity"**
   (ADR-0014 revision 1). A verification deploy has existed since 2026-08-10 (session-19), and
   Phase 1's feature surface is already complete — rather than a "wait several weeks first"
   gate, start it alongside the H series and continue until invite-only beta. The private
   preview (§2-1) is its extension
2. **Going public (making the repository public) is a precondition (gate) of invite-only
   beta**. Rationale: a zero-knowledge product's "the operator cannot read" becomes an external
   claim only once **the source of the clients that perform decryption is verifiable**. The
   cryptographic design treats the server as the party under verification (the distrusted one)
   (CRYPTO_SPEC §6.3 / §14 — server honesty is not assumed), so publishing the server code is
   not a necessary condition for trust — the crux of verifiability is on the client side
   (CLI / crypto). Because making the monorepo public is all-at-once, in practice "repository
   public = client verifiability established". Holding unspecified external tenants' secrets
   while still private would mean collecting secrets under an unverifiable promise, running
   counter to minimizing operator capability (ADR-0018)
3. **The completion conditions for going public (Phase 2) are unchanged**: shipped together with
   SECURITY.md + the threat-model document (§7 — promoted to a beta precondition by ruling DD).
   The pre-publication checklist (license done, maruhi.dev, trademark, Deploy to Cloudflare
   button verification, CLI distribution and notarization) is folded into H5.
   **The docs site (G) is removed from the publication requirements** (owner ruling — at
   publication, README + SELF_HOSTING suffice; the docs site is due by GA)
4. **The S-series gate is only S1–S3** (ruling DB — resolves the session-46 §9 handoff):
   - **S1 (test vectors + crypto), S2 (wire, acceptance, schemaPolicy), and S3 (CLI
     verification side + schema / set + fail-fast) must land before invite-only beta opens**.
     Re-checking the rationale: layout v2 is designed to coexist with v1 (no migration needed),
     but if a design defect in v2 itself is found, fixing it (moving to v3, changing acceptance
     rules) is a signature/wire-surface change, which is cheapest before external tenants exist.
     Before beta, run v2 in production under dogfooding to secure time to trip over defects.
     Additionally, the value-free schema is the core of HP2 (agent usage) differentiation and
     is the very thing to observe in beta — opening beta without it loses learning value
   - **S4 (import) and S5 (export / lint) are not gates**: they are unsigned, unaccepted
     artifacts and incidental UX (same line as ruling CX's demarcation); shipping them after
     external tenants exist creates no migration. They run in parallel during beta
   - The rest of Phase 3 (MCP delivery, brokering, agent leases, no-reveal) stays later
     (no reordering needed — ADR-0014 decision 2's priority order is unchanged)
5. **The S and H series can run in parallel**: S1–S3 are crypto / api-schema / server
   acceptance / CLI, and H1–H3 are server configuration and ops; the only shared shape is
   "adding server acceptance policies", while the implementations are independent. On
   contention, the S series wins (the longer pole of the beta gate)

## 5. Operations (ruling DC)

### 5-1. The line against zero telemetry (normative)

- **The telemetry ban (CLAUDE.md "unspoken") prohibits client → external transmission**; the
  operator observing its own servers' behavior (Workers metrics, logs) is not telemetry. This
  line is stated externally in the threat-model document (§7)
- However, operational observation also carries discipline: **application logs are static
  messages only** (no request-derived identifiers or user input — AUTH_SPEC §11-5's existing
  discipline promoted to a hosted-wide norm). The existing absolute rule that plaintext values,
  key material, and tokens never land in logs stays unchanged
- **Project ID = genesis hash is effectively a capability (AUTH_SPEC §11-2)**: because it
  appears in URL paths, enabling platform-side request logs (Workers Logs / Logpush) makes the
  log store an accumulation of capabilities. The default is **aggregated metrics only**;
  per-request logs require sampling + short retention + operator-internal access control
  (finalized in H3)

### 5-2. Monitoring and alerts (H3 — enumeration of tripwires)

| target | signal | threshold (draft value) |
|---|---|---|
| D1 total | database size | 5 GB warning (§3-3) |
| DO total guard | number of projects reaching the warning threshold | notify from 1 (§3-3) |
| GitHub quota | check-token x-ratelimit-remaining / exchange failure rate / signup-denial count (§2-2) | remaining < 20% / failure rate 5% / denial baseline deviation |
| auth-surface floods | 429 (AuthRateLimited / LeaseRateLimited) rate, login_failed suppression markers (AUDIT_SPEC §3.1) | baseline deviation |
| availability | external monitoring (`GET /auth/config` returning 200 — an existing unauthenticated, stateless surface. No dedicated health endpoint is built) | page on consecutive failures |
| error rate | Workers 5xx rate, DO overloaded errors | baseline deviation |

### 5-3. Backups

- **D1**: Time Travel (30-day PITR — nominal value §3-1) + periodic `wrangler d1 export`
  (scheduled execution; artifacts stored encrypted). The export contains D1's own contents
  (users, session hashes, token hashes, audit — no raw secret values existed to begin with)
- **DO (project substance)**: the platform has no user-facing PITR/export mechanism. v1 relies
  on Cloudflare durability (replicated persistent storage), and **app-level periodic backup
  (DO → R2; contents stay ciphertext + chain + audit = a form the operator cannot read) is an
  H3 design item** (gap 5 — backup is an operator-only path; no tenant-facing API is built).
  Loss scenarios are handled as the platform-failure class under incident response (5-4)
- One restore drill (verifying the rebuild procedure from export) is performed before invite-only
  beta opens (H3's completion condition)

### 5-4. Incidents and the status page

- **SECURITY.md** (part of the H5 publication ceremony): the vulnerability-report contact
  (security@ — prepared in H4), disclosure policy, scope
- **Status page**: an origin independent of maruhi's serving surface (external hosting or a
  separate static page). The rule of no third-party scripts in maruhi's web (CLAUDE.md) stays
  unchanged while keeping an announcement surface that stays alive during an outage
- **Minimal incident response** (honest to the scale of solo operation): detect (5-2 alerts) →
  update the status page → recover → public postmortem afterward (for significant ones).
  Incidents suspected of secret leakage include notification to affected users and an honest
  disclosure of "what the operator could see" (the zero-knowledge design means the range over
  which "values cannot have leaked" can be stated is broad — the threat-model document §7 fixes
  the basis of this claim in advance)

### 5-5. Consistency with AUDIT_SPEC

- **Do not mix audit logs (a product feature, tenant-visible) with operational logs
  (operator-only)**: do not let operational logs substitute for audit (audit is the formal
  record disclosed to tenants under AUDIT_SPEC's visibility classes). Do not write operational
  concerns (quota reached, error rates) into audit events (outside §1's purpose)
- The operator view (direct D1 reads — the note in AUDIT_SPEC §3.1) stays as-is. No
  operator-facing admin API or admin UI is built in v1 hosted (avoid the attack-surface
  increment; start at a scale where the wrangler / D1 console path suffices). Mechanisms for
  abuse response (account suspension etc.) are gap 7 (enumeration only)

## 6. Positioning of the threat-model document (ruling DD — drafting plan only; the body comes next session)

- **Promoted from "one item on the pre-publication checklist" to "a precondition of hosted
  (invite-only beta)"**. Because going public precedes beta in §4's ordering, its position in
  effect stays "a bundled artifact of going public" but becomes stronger — the promotion's point
  is to close the path of deferring the threat-model document under pressure to hurry beta
- Location: `docs/THREAT_MODEL.md` (a first-class document of the public repository. Since the
  docs site is deferred, it stands alone as Markdown). Because it is a document users read, it
  is **in English** (ADR-0017)
- Draft table of contents (drafting is next session — based normatively on CRYPTO_SPEC §14,
  restated plainly without duplication):
  1. What maruhi protects and from whom (a plain rendering of §14.1's G1–G9)
  2. What the operator can see (hosted-specific — the external version of §1's "boundaries of
     the promises": metadata, access patterns, and plaintext meta names are visible / values are
     not)
  3. What we cannot protect against (an honest enumeration of §14.3's non-guarantees —
     revocation of already-read values, complete compromise of a legitimate device,
     availability, semantic correctness of plaintext)
  4. How to verify our claims (public source, `maruhi project verify` / `audit verify`,
     test vectors — verifiability made procedural)
  5. Operational boundaries (zero telemetry, the operational-log demarcation — the external
     version of §5-1)
- Separate from SECURITY.md (intake channel): the threat model = statements of design,
  SECURITY = reporting procedure

## 7. Legal and commercial checklist (human tasks — enumeration only; not executed)

| # | task | rough deadline |
|---|---|---|
| L1 | ~~Decide the hosted serving domain (apex / app subdomain)~~ **Ruled 2026-09-03**: product origin (API + dashboard) = `my.maruhi.app` [bound via custom domain, workers.dev disabled], apex `maruhi.app` = LP + **docs (`/docs` path — SEO consolidated into one deploy. 2026-09-03 revision: the original "`maruhi.dev` = docs" is retracted)**, `maruhi.dev` stays acquired and 301s to `maruhi.app` (the dashboard's origin is the TCB, so it is separated from the LP — hosted-ops.md §7 O3 / docs/notes/web-design-pass.md §1-4). Remaining tasks = ~~placing a static site on apex (integrated with DP2)~~ (**implemented in DP2 on 2026-09-03 — `apps/site` [Blume] + `apps/site/wrangler.jsonc` [`maruhi-site`]**. First deploy = hosted-ops.md §7 O10) and the `maruhi.dev` redirect (same, O11). Both domains are acquired; zones live in the operator's CF account | before DP2 (the H6 gate) |
| L2 | Trademark filing (classes 9 and 42 — existing checklist item) | filing started before going public |
| L3 | Terms of Service, Privacy Policy (incl. sorting out GDPR / national-law applicability), Acceptable Use Policy (AUP). Keep the zero-knowledge boundary (§1) and threat model (§6) consistent with the legal texts. **The serving surface is static pages on web (the web surface in §9 — belongs to H4)** | before invite-only beta |
| L4 | Subprocessor list (Cloudflare — relies on the DPA) and disclosure | same time as L3 |
| L5 | Prepare security@ / a contact email address (the SECURITY.md channel) | before H5 |
| L6 | Prepare the Cloudflare Workers Paid operator account (D1 10 GB and DO unlimited storage assume Paid — §3-1) | before H3 |
| L7 | Create the dedicated hosted GitHub OAuth App (production callback URL) and the client_secret management procedure | before H3 |
| L8 | Arrange the status page (choose an external service or a static page) | before invite-only beta |
| L9 | Choose a billing foundation (Stripe etc.) — an independent task before GA (out of this design's scope) | before GA |
| L10 | Apple Developer Program (macOS notarization — existing ROADMAP item "2–3 weeks before going public") | before H5 |

## 8. Gap analysis (missing APIs, spec revisions — **enumeration only. Not implemented in this PR**)

| # | target | content | stage |
|---|---|---|---|
| 1 | AUTH_SPEC §3 / §4 | The `signupPolicy` (open / invite / closed) decision gate + acceptance and consumption of signup invitation codes (§2-2). Includes the composition path with project invitations (§15) (attachment to login), advisory distribution via `/auth/config`, and unauthenticated pre-verification of invitation codes (~~fail-fast before device-flow start~~ ~~after the 2026-08-31 §4 revision, "before handoff start"~~ after the 2026-08-31 supplemental ruling DH, **the Web signup side (§3) only** — no code rides the CLI path. The form of the form's pre-verification is the H1 implementation PR's call — §2-2 second addendum. With a per-IP rate limit) | H1 |
| 2 | AUTH_SPEC §11-3 / §12-8 | Acceptance cap on projects / org (draft value: 100 active) | H2 (**resolved 2026-09-02 — PR #134**) |
| 3 | AUTH_SPEC §12-8 | Implementation of the Phase-2-announced total DO storage guard (`databaseSize` threshold — two stages, warning / rejection) | H2 (**resolved 2026-09-02 — PR #134**) |
| 4 | AUDIT_SPEC §5.3 / undecided 3 | The D1-side audit total policy (monitoring + reserved separation into a dedicated D1 — §3-3). Audit preservation after project deletion (undecided 3) is revisited after the hosted legal requirements (L3) are fixed | H3 (**monitoring implemented 2026-09-02 — the H3 PR** [D1 total is judged at 5 GB via `wrangler d1 info` in the ops-backup workflow. The separation procedure is reserved in docs/notes/hosted-ops.md §3 row 1]) / separation when needed |
| 5 | operations (outside spec) | Design of app-level periodic backup of DOs (DO → R2, staying ciphertext) (§5-3). No tenant-facing API is built | H3 (**implemented 2026-09-02 — the H3 PR** [design = docs/notes/hosted-ops.md §2-D / §2-E: the DO itself multipart-streams NDJSON gzip to R2 under permit; full snapshot + skip rules; restore accepts only empty DOs; a temporarily deployed restore worker with no HTTP]) |
| 6 | AUTH_SPEC (new) | Account deletion (withdrawal): no deletion path exists for users / linked_identities / sessions / api_tokens / recovery_wraps. Internal user_ids (ULIDs) remain on the chain and in audit — after L3 / the threat model codify that these are anonymous identifiers and not personal data, design a deletion API | before invite-only beta (interlocked with L3) |
| 7 | AUTH_SPEC / AUDIT_SPEC (new) | Abuse response: operator-side suspension paths for accounts/projects and audit events. Availability is unguaranteed (G8), but a policy, record, and appeal form for operator actions are needed | before open beta |
| 8 | notifications | users.email is stored but there is zero notification machinery. Design the path for beta-operations contact (L3-covered incident notices). Unrelated to telemetry (server → registered email), but adding a sending foundation is a supply-chain increment — keep it minimal | before invite-only beta |
| 9 | AUTH_SPEC §4 | A scaling path for CLI login (breaking the device flow's 50/hour — §3-4's (a) web-flow handoff is the lead candidate). ~~Ruled after invite-only-beta measurement~~ **(ruled 2026-08-31 — session-48 ruling DF: (a) adopted ahead of measurement; spec landed = AUTH_SPEC 0.17-draft §4. Implementation = H1b, a precondition of H5)** | ~~before open beta~~ → before H5 (§9 addendum) |
| 10 | ADR-0012 | Alchemy v2 for the operator-side deploy (existing ROADMAP item — naturally around H3's time. The self-host distribution stays wrangler) | around H3 |

## 9. Implementation split (H1 onward) and independent-stoppability (the format of session-27 §14 / value-free-schema-design §3)

| stage | content | why it is safe to stop here |
|---|---|---|
| **H1** (**implemented 2026-09-01 — PR #133** [spec = AUTH_SPEC 0.18-draft §3, AUDIT_SPEC 1.4-draft §3.1. Implementation rulings: config lives in D1 `deployment_settings` [unknown values treated as closed, fail-closed]; code pre-verification is folded into the start-time check on `GET /auth/github/start?signup_code=` rather than an independent endpoint [per-IP limited — the reduced shape after ruling DH]; consumption is a CAS in the same D1 transaction as account creation; denials are recorded as the new event `auth.signup_denied` [same fixed-window discipline as login_failed]]) | Signup control — **server**: `signupPolicy` decision gate + signup invitation codes + ~~code pre-verification endpoint~~ (the implementation PR's ruling: folded into the start handler — zero unauthenticated-surface increment) + advisory distribution on `/auth/config` (the AUTH_SPEC §3 / §4 revisions land on the implementation-PR side). **CLI**: login's ~~device-flow~~ pre-handoff fail-fast (following the 2026-08-31 §4 revision + supplemental ruling DH — the target is before `POST /auth/cli/start`. §2-2 (i)(ii) — signupPolicy check and the "sign up on the Web first" guidance to the uninvited. ~~Code attachment and the pre-verification call~~ under ruling DH, code acceptance/verification lives only on the Web signup side) **is included in the same stage** (it validates the server implementation as the first consumer of the login-flow contract that the same §4 revision defines — the W2a pattern. The ruling not to split it to a later stage of H5 is session-47 §10-8). Includes the composition path with §15 invitations | Default `open` = identical to current behavior. Zero impact on self-host and existing users. **Fail-closed holds even in a server-only intermediate state** (the source of truth for denial is the server — an unimplemented CLI guard only loses shared-quota savings; safety does not degrade). The public-knowledge × invite-gated window (§2-2) only begins at H5 (CLI publication), and the gate order (§4) in which H1 completes before H5 automatically satisfies "the published CLI ships with the guard" |
| **H1b** (added 2026-08-31 — session-48 ruling DF + supplemental ruling DH. **Implemented 2026-08-31 — PR #117** [the old endpoints were deleted immediately with no grace window — because this is pre-publication. Includes review follow-ups such as `frame-ancestors 'none'` on the approval page CSP and URL verification of the CLI opener]) | Replacement of the CLI login path (implementing gap 9 — the AUTH_SPEC §4 revision of 2026-08-31): server = `POST /auth/cli/start` (**unrecorded** — signed flow credentials, automatic generation of the flow-signing key) / `GET /auth/cli/verify` / `POST /auth/cli/poll` + a scriptless approval page + **a signup-guidance page** (existing accounts only — ruling DH) + deletion of the old `/auth/device/exchange`, check-token, and format pre-checks; CLI = replacement of login (device-flow.ts deleted, client_id resolution abolished, provider-independent). Includes applying the character-set constraint on the existing `tokenName` wire Schema (AUTH_SPEC §6 2026-08-31 addendum — non-retroactive) and following up `docs/SELF_HOSTING.md` (removing the Enable Device Flow step, updating the WAF table, troubleshooting) | Independent of and parallel with H1 (the §4 revision already landed in this PR — the H1 portion is only the signupPolicy supplement). **Added as a precondition of H5 (going public)**: deleting device flow after publication would be a breaking change for external users, so pre-publication is cheapest. The published CLI ships with only the handoff. ~~Server-first deploy + a coexistence grace window for old CLIs is possible (the implementation PR's call)~~ (implementation PR #117's call: no grace window, immediate deletion — pre-publication means no external old CLI exists) |
| **H2** (**implemented 2026-09-02 — PR #134** [spec = AUTH_SPEC 0.19-draft §11-3 / §12-8. Implementation rulings: the project-count cap is a best-effort D1 count check + a report-only query to the DO [`admitFresh: false`] so the §11-3 repair path is not blocked; 429 `ProjectLimit`; slight overruns from concurrent inits are accepted. The DO guard reads `databaseSize` on every admission and returns 422 `DataLimitExceeded` [resource `project-storage-bytes`] — rejection covers only content-growth surfaces; reads [incl. pulls carrying var.read], deletion, revocation, rotation, leases, attestations, and checkpoints are still accepted under rejection [the sole exception = reads that require materializing the audit-head derived column]. The 8 GB warning emits one static-message ops log per DO instance = H3's alert hook. Observation points sit on the read surfaces that write audit rows [value-bearing pulls, leases] in addition to the growth surfaces — so warn-band entry is observed even in pull-dominated projects (PR review follow-up). Under rejection, the non-constant writes are two items: var.read [proportional to time] and rotation.recommended at revocation [proportional to variable history — detection is not truncated and is named in the accounting] — AUTH_SPEC §12-8 "headroom accounting"]) | Tenant quota — projects/org cap + total DO storage guard (implementing the §12-8 announcement) | The caps sit well above realistic use. No impact on existing projects (no tenant has reached them) |
| **H3** (**implemented 2026-09-02 — PR #137 / restore drill (O7) performed 2026-09-03 — H3 complete** [design = docs/notes/hosted-ops.md. Implementation rulings: counting sources are D1 fixed-window counters [`ops_counters` — decorating exchangeCode + the flow-cap-reached point] and windowed aggregation of existing audit rows for signup denials / suppression markers; threshold evaluation is the worker's hourly cron; notification is an operator webhook [unset Secret = disabled, static signal names + aggregate values only, fires on transition]; only D1 total is judged in the export workflow; H2 warning rows are counted by the backup sweep's census [same meter and pure function]; DO → R2 backup is the DO itself multipart-streaming NDJSON gzip under permit [full snapshot + skip rules on audit / chain seq; keys are the image of the DO id]; restore is an internal RPC accepting only empty DOs + a temporarily deployed restore worker with no HTTP [cron + R2 job files; drills use a separate-class drill namespace]; hosted-specific bindings live in the wrangler named environment `hosted` [the top level = self-host defaults unchanged; drift blocked by CI 8c]; D1 export is GitHub Actions cron + age encryption + the same R2 bucket. **Restore drill (the record in hosted-ops.md §5-3)**: on operator account `maruhi`, hosted origin `https://my.maruhi.app` [custom domain. Owner ruling: product = `my.maruhi.app`, apex = LP + docs (`/docs`). The original "docs = `maruhi.dev`" was retracted by the L1 revision (2026-09-03) and `maruhi.dev` 301s], a dogfooding project was created; confirmed 2 generations of DO → R2 backup + 2 skips → restored into the drill namespace and all 17 tables' row counts, the chain head, and audit seq matched the trailer; the audit head matched three ways between tenant-side recomputation and production `GET /audit-head` → decrypted the D1 export and imported into a fresh DB; all 21 tables' row counts matched. Defects found by the drill: the Effect HTTP logger was leaving `http.url` [a capability] in Workers Logs → `disableLogger: true`. Runbook corrections: `lifecycle add`'s rule name, the Actions token permissions [D1: Edit + R2 Edit], reordering D1 import statement order [`scripts/reorder-d1-dump.ts`]. Draft values [`OPS_BACKUP_MAX_BYTES` 2 GB etc.] kept as-is for lack of evidence. O5 external monitoring = Better Stack Uptime [30 s interval, 180 s confirmation, expects 200]. O8 [extra encryption of backups] ruled unnecessary-permanent by the owner on 2026-09-03. Remaining human task: O9 Alchemy]) | Ops foundation — monitoring/alerts (5-2), backups (5-3), the restore drill, the operations GitHub OAuth App (L7), (optional) Alchemy v2 | Operator-side only. No change to the product's wire or acceptance surfaces |
| **H4** | Legal and commercial — §7's human tasks (agents assist drafting at most) + design of account deletion (gap 6) and the notification path (gap 8) + **the serving surface for legal documents (static web pages — see "web-surface ownership" below)** | Mostly documents and external procedures. Product change is only the independent PRs for gaps 6 / 8 plus static pages |
| **H5** | Publication ceremony — SECURITY.md + threat-model document (§6) + the rest of the pre-publication checklist (Deploy-button verification, CLI distribution, notarization) → **go public** | Going public is irreversible, but is itself the goal being reached. Can still stop before opening invite-only beta afterward |
| **H6** | Open invite-only beta — start operating invitation-code issuance, verify the "first 5 minutes" experience is met (ADR-0014 revision 1's experience requirement) + **the onboarding / beta-guidance static web surfaces (below)** | Can stay stopped at H5 until the gates (§4) are met. Even after opening, `signupPolicy` can be flipped back to closed (stops only new signups — reversible) |

- Dependencies: H1 and H2 are independent and parallelizable. H3 and H4 are likewise. H5 waits
  for H1–H4 + S1–S3 to complete. **The DP series (design pass — ROADMAP.md DP1–DP5, added
  2026-09-03) gates H6** and is also the visual container for H4's legal pages and H6's static
  web surfaces, so DP1 / DP2 go first. DP2 is integrated with §7 L1 (the serving domain —
  ruled 2026-09-03: product = `my.maruhi.app`, apex `maruhi.app` = LP + docs [`/docs`],
  `maruhi.dev` 301s. **Implemented in DP2**: `apps/site` [Blume] + the independent wrangler
  config `maruhi-site`. First deploy, the 301, and Web Analytics are hosted-ops.md §7 O10–O12)
  (the §4 gate. 2026-08-31 addendum: **H1b is also added to H5's preconditions** — session-48
  ruling DF). H6 comes after H5
- **Web-surface ownership (2026-08-30 PR #113 pullfrog review follow-up — session-47 §10)**:
  what hosted adds to web is **unauthenticated static pages only** — legal documents
  (ToS / privacy / AUP serving — H4), invite-only-beta guidance / the waitlist path and the
  landing wording on signup denial (H6), and the "first 5 minutes" onboarding (guidance on CLI
  install steps — H6). All are **extensions of web-dashboard-design.md's S1 (landing) family**
  and create no new trust surface: they add no auth, mutation, or script dependency and stay
  inside ADR-0018 revision 2's boundary (read + revoke only) and CLAUDE.md's CSP / self-serving
  discipline (the option of pushing legal documents to an independent origin was rejected — it
  only adds supply chain and serving surface; the only thing needing outage-time independence is
  the status page [§5-4]. Record explicitly that this asymmetry is the sole justification for an
  independent origin)
- Parallel with the S series: every H stage is implementation-independent of S1–S5 (§4-5). Only
  S1–S3 enter the beta gate
- Stoppability of each stage: H1 alone = standalone value as a signup-control feature for
  self-host. H2 alone = stronger resource defense. H3 alone = operational maturity. Any
  intermediate state after any stage stands on its own

## 10. Out of scope and handoffs

- **Design of export / import (hosted → self-host migration) — a separate session (2026-08-30
  owner decision. Out of scope for this H0)**: doing it is already decided. Design questions =
  (i) the transport form (a bulk export of chain + values + manifest, and the bulk-acceptance
  rules on the destination server — it touches the acceptance surface, so the same "design →
  approve → implement" order as W0 / S0 is needed), (ii) `grant_server`'s wraps addressed to the
  server key become invalid at the destination, so CI must re-grant (making the non-portable
  part explicit), (iii) the portability of audit history and the boundary of verifiability at
  the destination. The motivation is the structural backing for §1's "no availability SLA"
  (making ADR-0003's FSL = "you can escape to self-host" hold as a mechanism, not a promise)
- Billing design (an independent task before GA — L9), pricing, plan structure
- The threat-model document's body (next session — §6 is a drafting plan only)
- Implementation of gaps 1–10 and the spec-body revisions (delegated to each implementation PR)
- Enterprise SSO (WorkOS) — deferred in ADR-0009's re-examination. The next re-examination
  point is "observing real SSO demand on paid plans" (ADR-0009's re-examination record)
- The docs site (Wave 3 G) is due by GA (owner ruling)
- `maruhi ui` (stage 2), the value-bearing UI (stage 3), and Phase 3 follow-ons (brokering
  onward) each stay on their existing plans (this design creates no preconditions for them)
