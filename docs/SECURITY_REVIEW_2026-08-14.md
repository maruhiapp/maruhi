# maruhi security review (2026-08-14)

- Target revisions: main body = `9e30a56c4efa0c46435e15e4d53a7ff20d3567c8`,
  supplement = `de8f3af03291a33fa3c5634652040399ded37278` (diff = PR #63's 67
  files / +8,596 lines), supplement 2 = `6b839cc` (diff = PR #65's 46 files /
  +4,415 lines)
- **Timing note**: while the main body was under review, PR #63 (Phase 2 Wave 2
  A1 — grant_server 0.5 implementation) was merged into main. The main body's
  statements (especially finding M-1 and the "verified clean" list) apply to the
  **tree at `9e30a56`**; the PR #63 diff is covered by the **supplement
  (2026-08-15)** at the end. Places whose status changed in the supplement are
  annotated inline
- Method: static review of all layers (no code execution). Judgment criteria:
  the spec documents (`docs/CRYPTO_SPEC.md` v0.5-draft / `docs/AUTH_SPEC.md`
  v0.9-draft / `docs/AUDIT_SPEC.md`) and CLAUDE.md's absolute rules; checked for
  divergence from them and for common vulnerability classes (authn / authz /
  injection / CSRF / secret leakage / DoS / supply chain)
- Scope: `packages/crypto` / `packages/core` / `packages/api-schema` /
  `apps/server` / `apps/cli` / `apps/web` / `packaging` / `.github/workflows` /
  `.claude`
- This review only records findings. Fixes are done separately (see "recommended
  handling" in this file)

## Overall assessment

**No critical (immediately exploitable) vulnerability was found.** Spec–
implementation agreement is extremely high: the crypto boundary (E2EE),
authorization (chain-derived role), existence hiding (uniform 404), DO
serialization (TOCTOU protection), the CLI's diskless invariant, the web CSP,
and CI's least-privilege + SHA pinning are all implemented carefully per spec.
SQL is parameterized on every path, and the server and crypto packages emit no
logs at all.

The findings center on two points:

1. ~~The "dangerous window" of divergence between the approved spec (0.5-draft)
   and the implementation (M-1)~~ — **resolved by the merge of PR #63**
   (implementation verified in supplement §A-0. Main-body M-1 is kept as a
   record of the history)
2. **Gaps in the consistency of defensive discipline**: places where the
   project's own discipline — enforced elsewhere — did not reach, e.g. the
   unpinned privileged CI workflow (M-2) and the missing CSRF header
   requirement on an audit-writing GET (L-1)

---

## Findings list

| ID | Severity | Area | Status | Summary |
|---|---|---|---|---|
| M-1 | ~~Medium~~ | server / crypto | **Resolved (PR #63)** | The approved 0.5-draft consensus rules were unimplemented while `grant_server` could still be accepted in the old format (resolution verified in supplement §A-0) |
| M-2 | Medium | CI | **Fixed (2026-08-15)** | `pullfrog.yml` held many AI provider API keys under mutable tag references (an exception to the SHA-pinning discipline) |
| L-1 | Low | server | **Fixed (2026-08-15)** | The session-authenticated `GET …/pull` (which records `var.read` audit) had no CSRF header requirement, letting a cross-site request force audit records |
| L-2 | Low | server | **Fixed (2026-08-30 W3a)** | API tokens had no expiry (`expires_at` always NULL) |
| L-3 | Low | server | **Mitigated (2026-08-15)** | `/auth/device/exchange` (unauthenticated) had no rate limit; a third party could burn the GitHub check-token API quota (login availability) |
| L-4 | Low | server | Still applies on current main | `auth.login_failed`'s recording cap is a global fixed window, so a flood can suppress recording of targeted failures (design documented) |
| L-5 | Low | web / server | **Fixed (2026-08-15)** | HSTS unset (on custom domains), no security headers on API responses |
| A-1 | Low | server / crypto | **Corrected (2026-08-15)** | An identifier collision across recipient classes (a member's user_id = the server key FP) makes first-time registration of the wrap complete-set a defect (500), blocking rotation/creation of that environment |
| I-1 | Info | packaging | — | `checksums.txt` is unsigned (TLS only) — a ratification; already documented and on the ROADMAP |
| I-2 | Info | server | — | Full-chain re-verification per chain append (up to 10,000 × Ed25519): whether it fits within the DO CPU limit is unmeasured |
| I-3 | Info | .claude | — | The remote-dev-environment SessionStart hook installs Bun via `curl \| bash` (dev environment only) |
| A-2 | Info | api-schema / docs | **Resolved (PR #65)** | The `serverEncPubHex` returned by `/auth/config` was not in AUTH_SPEC §4's response definition (spec-first discipline missed) → PR #65's `50452f6` added it to §4 |
| A-3 | Info | cli | **Fixed (2026-08-15)** | `server grant --expect-fingerprint` assumes an out-of-band copy; passing the value fetched from `/auth/config` makes the check self-referential (should be stated in the ops docs) |
| A-4 | Info | server | New (supplement 2), handoff noted | A single valid OIDC token can materialize a DO (empty tables) for an arbitrary project ID (no audit row is left, but storage is consumed) — the DO-creation aspect should be added to the in-code handoff |
| A-5 | Info | crypto / cli | New (supplement 2) | Handoffs to A3 (workload implementation): use `computeLeaseClaimsDigest` for the claims digest (using the builder directly bypasses the empty-field guard); DEK-length verification belongs to the §5.2 commitment-check layer; replay non-guarantee (§9.1) was awaiting a ruling |
| A-6 | Low | server | **Mitigated (supplement 3)** | `/auth/github/callback` has the same unauthenticated outbound amplification as L-3 (self-bound state lets one request induce a code exchange each time), and the query had no input cap — cap added + put under the operational rate limit |

---

## Finding details

### M-1. Approved 0.5-draft consensus rules unimplemented while `grant_server` accepted the old format (~~Medium~~ → resolved)

> **Status (added 2026-08-15)**: PR #63 (`de8f3af`) implemented 0.5-draft, so
> this finding is **resolved**. Old 3-field `grant_server` entries are no longer
> accepted by the consensus rules (`invalid-payload`), and the window closed
> with the precondition "no old-format entry exists in any accepted chain"
> preserved. Verification details in supplement §A-0. The below is kept as a
> record of the `9e30a56` state.

**Location** (at `9e30a56`):
- `packages/crypto/src/internal.package/chain-canonical.ts` (grant_server's
  canonical payload is 3 fields — no `lease_policy_lp_hex`)
- `packages/crypto/src/internal.package/chain-verify.ts` (`shapeGrantServer` /
  `applyGrantServer` had no `duplicate-server-key` check)
- `apps/server/src/authz.ts` + `apps/server/src/chain-do.ts` (generic append
  accepted `grant_server` / `revoke_server`)
- `apps/server/src/dek-wraps.ts` / `apps/server/src/composite-programs.ts`
  (wrap complete-set determination covered only the current member set — not
  wraps addressed to the server key)

**Content**: CRYPTO_SPEC 0.5-draft (§6.2's grant_server payload lease-policy
extension and server-key uniqueness, §9.1 workload leases) and AUTH_SPEC
0.9-draft (§12-4/§12-6's server-key-addressed wraps, §14 lease API, §15 invite
API) were designated "owner-approved upon merge of this revision PR", and the
specs were already written in 0.5 form. Meanwhile the implementation at
`9e30a56` remained in 0.4 form, and the live API could still accept a 0.4-format
`grant_server` entry. Because the 0.5 format change carries no backward-
compatibility clause — justified by "no accepted chain containing a
grant_server entry exists before publication" — starting operations before the
0.5 implementation would break that precondition and could cause (a) wholesale
invalidation of chains containing old entries, (b) retrofitting a grandfathering
clause, (c) entry of entries not checked for `duplicate-server-key`. There was
no direct confidentiality harm in the implementation of that time because no
registration path for server-key-addressed wraps existed (the danger was
erosion of the precondition).

**Recommended handling at the time** (no longer needed): reject `grant_server` /
`revoke_server` as an acceptance policy at both layers until 0.5 is
implemented. → **Moot because the 0.5 implementation itself was merged during
this review.**

### M-2. `pullfrog.yml` missing pinning + many secrets (Medium)

> **Status (added 2026-08-15)**: **Fixed** — both actions are pinned by commit
> SHA (`actions/checkout` = `d23441a4` (v6.1.0), `pullfrog/pullfrog` =
> `0657d542` (v0.1.57). Tags → commits were resolved via `git ls-remote` and
> both confirmed to be lightweight tags = the commit SHA itself). Deleting
> unused provider-key lines was deferred (unset secrets pass through empty with
> no harm; whether to remove them is an ops decision). **2 residual points**
> (supplement 3): (1) as the file's leading "DO NOT EDIT" says, a pullfrog
> template regeneration could silently return the pins to `@v0`. A CI step
> checking `uses:` SHA form is not yet in place (future improvement candidate).
> (2) The checkout pin keeps the vendor template's major (v6), so there are now
> two lines of checkout versions across workflows — the others use v4.4.0
> (intentional — don't change the template's assumed major).

**Location**: `.github/workflows/pullfrog.yml:24-42` (at `6b839cc`)

**Content**: `actions/checkout@v6` and `pullfrog/pullfrog@v0` remain **mutable
tag references** while env passes `ANTHROPIC_API_KEY` /
`CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` and many other provider API keys.
`release.yml` itself codifies the discipline "external actions are pinned by
commit SHA (because it is a privileged path; eliminates upstream compromise via
mutable tags)" (`ci.yml` / `installer.yml` comply too), and only this workflow —
the one holding the most secrets — is the exception. Replacing an upstream tag
(account compromise, repository transfer) enables secret exfiltration. Being
`workflow_dispatch`-only (starting it requires write permission) and
`contents: read` are mitigating factors.

**Recommended handling**: pin both actions by commit SHA (the leading "DO NOT
EDIT" is the vendor template's notice; check the pullfrog-side docs on whether
pinning counts as an editable part). Also consider deleting unused provider-key
lines (unset secrets become empty, but if the lines are gone they can't be
passed even if set later).

### L-1. Session-authenticated `GET …/pull` has no CSRF header requirement (Low)

> **Status (added 2026-08-15)**: **Fixed** — per the recommendation,
> session-principal pulls with values now require `x-maruhi-csrf: 1` (the check
> predicate is consolidated into `statefulGetCsrfViolated` in `auth.package`,
> shared with the recovery-blob GET. Bearer and metadata-only mode are out of
> scope). A provision was added to AUTH_SPEC §12-7, and §11-4's CSRF text was
> revised to include an explicit list of "stateful GETs" ("state" = writes to
> audit rows or counters; it also now states that infrastructure aspects like DO
> materialization belong to A-4's probe-rate design decision). Tests pin both
> the 403 + non-recording of `var.read`, and the recording of `var.read` on
> success (positive control).

**Location** (at `6b839cc`):
- `packages/api-schema/src/data-api.ts` (`GET
  /projects/:projectId/environments/:environmentId/pull`)
- `apps/server/src/programs-environment.ts` (pull records `var.read` audit per
  variable)
- `apps/server/src/auth.package/middleware.ts` (the CSRF check exempts
  GET/HEAD/OPTIONS)
- Precedent: `apps/server/src/handlers-auth.ts` (`GET /auth/recovery` is a
  "GET that has state", so it requires `x-maruhi-csrf` from session principals)

**Content**: bulk pull is a GET but carries a state change: recording a
`var.read` audit row. Session cookies are `SameSite=Lax`, so they are sent even
on cross-site **top-level navigations** (links, `window.open`), letting a
third-party site fire a pull under the victim's session. The response
(ciphertext, wraps) cannot be read by the attacker (no CORS), so **there is no
data leak**, but there is impact:

- Audit-trail contamination: a third party can carve a false `var.read` — "user
  X read variable Y" — into the victim's account (poisoning forensics, e.g.
  making a departed employee appear to have exfiltrated afterward). It also
  enters the "definitely fetched" rank of rotation-needed detection (AUDIT_SPEC
  §4.1) (it errs toward over-rotation, which is not the dangerous direction)
- Asymmetric with the project's own discipline of requiring a CSRF header on
  the recovery-blob GET for the same reason ("a GET that has state — fetch
  counting")

Mitigating factors: project_id = genesis hash is effectively a capability
(AUTH_SPEC §11-2), so the attacker must know the target project ID. Also, at
this time no Web dashboard (a client that calls pull with a session) exists.

**Recommended handling**: like `recoveryGet`, **require `x-maruhi-csrf: 1` on
session-principal pulls (with values)** (Bearer is out of scope). Metadata-only
mode records no audit, so it may stay out of scope. If a future Web dashboard
on a separate origin introduces CORS, keep `Access-Control-Allow-Origin` to a
fixed origin + header allowlist so the precondition "custom headers cannot be
sent cross-site" does not break.

### L-2. API tokens have no expiry (Low)

> **Status (added 2026-08-28)**: **Spec revision drafted** — per the handoff
> (recommended handling order 5: "together with token-management UI design and
> spec revision"), the default TTL (drafted at 90 days, refreshed on re-login)
> was drafted into AUTH_SPEC §6 alongside W0's token-boundary ruling (Web
> dashboard screen design — ADR-0018 revision 2). Implementation is Wave 3 W3a
> (docs/notes/web-dashboard-design.md §7), so it is not "fixed".
>
> **Status (added 2026-08-30)**: **Fixed (W3a)** — the default TTL of 90 days is
> pinned into `expires_at` at issuance, and expired means 401 at verification
> (same handling as revoked). Existing no-expiry rows are re-anchored by the
> migration (`token_ttl_reanchor`) to "application time + 90 days", and the
> verification side treats NULL as expired too (fail-closed — no-expiry does not
> resurrect even when the migration is unapplied). For unattended PATs in
> lease-incapable execution environments, an explicit TTL at issuance
> (`expiresInDays` 1..365 — capped) was provided instead of returning to the
> no-expiry default. The ruling comparison and rejected options are in
> docs/notes/session-44.md (rulings CE / CF).

**Location**: `apps/server/src/db.package/repos.ts` (`expiresAt: null` fixed),
`apps/server/src/auth.package/token.ts` (**same on current main**)

**Content**: tokens issued through the device flow have no expiry. Revocation
means exist (self-revocation, rotation by reissuing under the same name), but a
leaked token persists unless the leak is noticed. Not a spec violation since
AUTH_SPEC §6 has `expires_at` in the data model but does not mandate a TTL.
Mitigating factors: the CLI token is stored in the keychain, and its effective
scope permission is bound by min(scope, chain role).

**Recommended handling**: consider a default TTL (e.g. 90 days) + refresh on
re-login (accompanied by an addition to AUTH_SPEC §6). At minimum, design a
revocation policy for long-unused tokens based on `last_used_at` together with
the Phase 2 token-management UI.

### L-3. `/auth/device/exchange` has no rate limit (unauthenticated outbound amplification) (Low)

> **Status (added 2026-08-15)**: **Mitigated** — both recommended items were
> done. (1) A pre-check of the token format (`gh[a-z]_` prefix + Base62/`_`
> body) is enforced in the wire Schema (`api-schema/src/auth-api.ts`); malformed
> input is a 400 without querying GitHub. Added to AUTH_SPEC §4. (2)
> `SELF_HOSTING.md` now documents a recommended Cloudflare per-IP rate-limit
> rule for the unauthenticated outbound-inducing surfaces (device/exchange,
> callback, lease). **Why not "fixed"** (supplement 3): the format check blocks
> only indiscriminate, malformed floods — a targeted flood of format-valid
> tokens has no server-side countermeasure, and per-IP limiting is an optional
> ops-side setting (the decision to defer an in-server per-IP window is recorded
> in this finding's recommended handling). Note the format is a shared Schema,
> so it is simultaneously enforced on the sending side of derived clients (the
> CLI) — the intended symmetry.

**Location**: `apps/server/src/handlers-auth.ts`,
`apps/server/src/auth.package/github.ts` (at `6b839cc`)

**Content**: an unauthenticated POST where each request makes the server call
GitHub's check-token API outbound (Basic auth = client_id:client_secret). That
API's quota is rate-limited per OAuth App, so a third party pouring in garbage
tokens exhausts the deployment's quota and an availability attack succeeds —
**legitimate users' logins (device exchange) fail**. The body's token field is
capped at 512 chars (api-schema) preventing bloat, but there is no request-rate
limit. The `auth.login_failed` recording cap (L-4) only protects D1 writes; the
outbound call happens every time.

**Recommended handling**: (1) pre-check the GitHub token format (`gh[a-z]_`
prefix; mismatches get an immediate 400 without querying GitHub) to block most
of an indiscriminate flood. (2) Document a recommended Cloudflare rate-limit
rule (per-IP limit on `/auth/device/exchange`) in the self-hosting doc
(`docs/SELF_HOSTING.md`). Weigh an in-server per-IP fixed window (D1 or DO)
against write amplification.

### L-4. `auth.login_failed` recording cap is a global fixed window (Low / design documented)

**Location**: `apps/server/src/db.package/audit.ts:69-113` (**same on current
main**)

**Content**: the recording cap (100 entries/hour) is a deployment-wide global
window, so an attacker saturating the window with 100 harmless failures keeps
subsequent (targeted) failures from being recorded. It is an intentional
best-effort documented in an implementation comment — "the flood itself is
observable as the window reaching its cap" — and the cap being a signal in
itself is reasonable.

**Recommended handling**: keeping it is acceptable. If improving, split the
window per reason kind (`authMethod` × `reason`), or on reaching the cap leave
one aggregate event line saying "N further entries were not recorded"
(visualizing suppression).

### L-5. Missing HSTS / security headers (Low)

> **Status (added 2026-08-15)**: **Fixed** — `Strict-Transport-Security:
> max-age=31536000` was added to both the web `_headers` and every API worker
> response (the API side can also get a custom domain via routes and is an
> origin holding a session cookie + OAuth flow — resolving the web-only
> asymmetry noted in supplement 3). Every API worker response also gets
> `X-Content-Type-Options: nosniff` + `Cache-Control: no-store` (`index.ts`'s
> `withSecurityHeaders`; applies to lease responses too — unauthenticated
> responses containing the chain + ciphertext — and to the pre-router 413 path).
> Tests pin that a 302 + multiple Set-Cookie are preserved across the wrapper.
> **One deviation from the recommendation**: HSTS was added without
> `includeSubDomains` — if self-hosted and mounted on an apex, it would pin
> unrelated subdomains browser-side for a year, which is excessive as a
> distributed default (zones that need it can add it operationally).

**Location**: `apps/web/scripts/write-headers.ts:41-45`,
`apps/server/src/index.ts` (API responses) (at `6b839cc`)

**Content**: the web `_headers` lacks `Strict-Transport-Security`.
`workers.dev` is HSTS-preloaded so there is no harm on the default URL, but if a
**custom domain is assigned via routes** a downgrade of the first connection is
theoretically possible. API worker responses carry no `X-Content-Type-Options:
nosniff` etc. at all (JSON API only, never returns HTML, so harm is small).

**Recommended handling**: add `Strict-Transport-Security: max-age=31536000;
includeSubDomains` to `_headers`. On the API side, consider common response
headers (`nosniff` + `Cache-Control: no-store` to suppress caching of
token/ciphertext responses).

### I-1. `checksums.txt` unsigned (Info / ratification)

`packaging/install.sh:12-13` explicitly states "no signature verification is
written (don't appear to verify something that doesn't exist)", and it honestly
documents that integrity rests solely on TLS to github.com. This ratifies the
ROADMAP's planned signature adoption (minisign / Sigstore etc.). The script
itself is exemplary (wrapped in `main()`, doesn't write to the install
destination before checksum verification, no sudo, no rc-file edits).

### I-2. Full-chain re-verification cost per chain append (Info)

`apps/server/src/chain-accept.ts` re-verifies the whole chain via
`verifyChainEffect([...entries, entry])` on every accepted append (up to 10,000
entries × Ed25519 verification). AUTH_SPEC §12-8 accepts this cost level, but
there is no measurement near the workerd CPU-time cap. Repeated appends at
member permission consume O(n) CPU per append (serialized, so per-DO latency).
Consider benchmarking near the cap (or optimizing toward incremental
verification with a cached derived state) in Phase 2.

### I-3. `curl | bash` in the SessionStart hook (Info / dev environment only)

`.claude/hooks/session-start.sh:17-19` runs `curl -fsSL https://bun.sh/install |
bash` in remote dev environments. The version is pinned but the installer
itself is unverified. Info because it is dev-environment-only, not a user-facing
artifact. If it matters, replace with a checksummed fetch from official GitHub
Releases.

---

## Verified-clean items (against the tree at `9e30a56`)

> **Scope note**: this list applies to the tree at target revision **`9e30a56`**
> and does not extend to later commits (especially PR #63 = `de8f3af`). Surfaces
> added or changed by PR #63 (recipient class server, grant_server 0.5 format,
> `server grant` / `server revoke` CLI, deployment key, `/auth/config`
> extension) are covered by the **supplement (below)**. ★ = items whose
> behavior changed in PR #63 (the supplement's text is the current truth).

Items checked and found clean are recorded so fix chats can skip re-checking.

### Authentication (AUTH_SPEC §3–§6)
- OAuth state: 128-bit random + `__Host-` cookie (HttpOnly/Secure/Lax/10 min) +
  constant-time comparison (`handlers-auth.ts`). Login CSRF blocked by cookie
  binding
- `redirect_uri` is derived from the actual request URL's origin, not the Host
  header (`handlers-auth.ts`). No open redirect
- device flow audience verification (check-token API) implemented — reuse of
  tokens meant for other Apps (confused deputy) is blocked
  (`auth.package/github.ts`)
- GitHub access token is non-persisted, non-logged (verified on all paths)
- Sessions: 256-bit random → only the SHA-256 hash stored in DB, sliding 30
  days, DB-backed revocation, cron cleanup of expired rows. Tokens:
  `maruhi_pat_` + Base62 (256-bit), hash comparison + constant-time compare,
  atomic same-name rotation (atomic batch + UNIQUE), issuance cap 100
- CSRF: custom header `x-maruhi-csrf` + SameSite=Lax + **no CORS** (custom
  headers can't be sent cross-site because preflight fails) + Authorization
  header wins with no fallback to cookie
- Unconfigured server fails closed (503 SetupIncomplete), placeholder detection
  ★ (the `/auth/config` response gained the server-key public surface in PR #63
  — supplement §A-0 / A-2)
- Recovery-blob API (§13): `*`×admin scope condition, CSRF header on the GET,
  fixed window 5/hr, 404 not counted, suite check — all per spec
- No code path for auto-linking or email search by email. `getOrCreateUser`
  resolves by (provider, provider_user_id) only

### Authorization / existence hiding (AUTH_SPEC §9-2 / §11 / §12-3)
- Effective permission = min(token scope, chain role): both halves implemented
  (`authz.ts` + the DO-side `requireRole`). The out-of-scope 404 /
  insufficient-level 403 / non-member 404 distinctions follow the spec's
  judgment order exactly
- org roles play no part at all in project access (the chain is the only source
  of truth)
- DO Semaphore(1) serializes all operations including reads — blocks the TOCTOU
  between membership judgment and data distribution (distribution to a
  just-removed member). Cache invalidation on defect (prevents phantom state)
  also implemented

### Chain (CRYPTO_SPEC §6)
- Verification stage order (framing → payload structure → actor resolution →
  signature → authorization + state transition); all reason codes pinned by
  test vectors. Design never throws on untrusted input (runtime checks on
  `unknown`)
- Consensus rules: epoch +1 strict, `create_environment` must come first,
  environment ID unique across all history, member-key uniqueness (enc/sig
  separately), admin/owner operations owner-only, last-owner protection, 1024-
  byte field cap, re-grant may only widen scope — all verified implemented ★
  (grant_server became 0.5 format in PR #63 — supplement §A-0)
- Canonicalization (LP encoding) shares the single §2.1 implementation across
  all uses. Length prefixing gives no concatenation ambiguity
- Project ID = genesis hash bound to DO routing (worker computes + DO
  re-verifies)
- Acceptance policy (1 MiB / 10,000 / 32 MiB) + a front stage of raw HTTP body
  8 MiB (measured enforcement not relying on Content-Length)
- Chain-mirror audit commits atomically in the same sync task as the chain
  insert. Audit seq gap prevention (cache discard on failure)

### Data plane (AUTH_SPEC §12 / CRYPTO_SPEC §4–§5)
- Server-side verification of value signatures / meta statements (§12-5's
  1–5): caller = signer, declared head exists, role + key binding at head time
  (rejects across tenure), epoch coherence (rejects heads before environment
  creation, forbids default fallback), prev chaining (stored-anchor check after
  CAS passes), rejects re-activating a deleted variable — consolidated in the
  crypto layer's `verifyDistributedValue` / `verifyDistributedMetaStatement`;
  the server just calls them
- Signed coordinates are reconstructed from server-side values (genesis hash,
  URL, storage destination), never assembled from wire-declared values (§12-5's
  invariant). The AAD coordinate-match check (422) is only a self-consistency
  check, per the authz-first exception provision
- CAS: version (+1 strict), current epoch only, metaVersion CAS, 409 does not
  carry the winner's hash (prevents evidence-chain contamination)
- DEK wrap acceptance (§12-6): recipient = both user_id and enc public key
  match, ★ exact match on first registration (at `9e30a56`, count = current
  member count. **PR #63 changed it to "current members + server keys with
  valid grants in the disclosure scope"** — supplement §A-0), append-only and
  no overwrite (409), repair path is admin, registration signature (§5.1)
  verified on all paths, distribution only to the addressee (recipient binding
  checked in SQL), epoch equality check for composite-bundled wraps
- Composite acceptance (§12-4): chain entry + statements + wrap complete-set
  commit atomically in a single sync task, declared head = pre-append head
  strict match, URL / payload coordinate cross-check
- Quantity policy (§12-8): all limits implemented. Judgments use stored state
- Audit (AUDIT_SPEC): actor is only internal user_id + key FP. Verified there
  is no path by which provider ID / login / email enter D1/DO audit or the
  chain (org name = derived from providerLogin lives only in the organizations
  table; not copied into audit payloads)

### crypto package
- AES-256-GCM: nonce always generated internally (can't be passed by the
  caller), AAD via the shared LP encoder, decryption failure carries no detail
- HPKE: single construction point via panva `hpke`, one-shot Base mode
  Seal/Open, info context binding, Open only takes a KeyPair (compatible with
  non-extractable keys)
- Keys: private keys default extractable=false, FP computed per spec (user =
  SHA-256(enc‖sig)[:16], server = SHA-256(enc)[:16])
- Recovery: HKDF (empty salt = RFC 5869 §3.1-conformant, premise stated) + AAD
  binding to user_id
- hex accepts lowercase only (eliminates multiple canonical forms), fail-fast
  on huge input (length check → decodeHex)
- The discipline of never putting secrets or input fragments in error values is
  observed throughout
- Test vectors (positive cases + negative cases: tamper, transplant,
  substitution, branching, etc.) exist for every signature system, with 3-
  environment CI: browser / Bun / workerd

### CLI
- Diskless invariant: no path writes plaintext values or key material to disk.
  Persistence is only the keychain (token, master key) and non-secret config /
  floor. No fallback to plaintext files (typed error when keychain is
  unavailable)
- `maruhi run`: memory injection into the child process env only. **A denylist
  of execution-control environment variables (PATH / LD_* / DYLD_* / GIT_* /
  NODE_OPTIONS etc.) + POSIX identifier restriction (blocks shellshock-style
  function injection) + Windows case-collision check + NUL / invalid UTF-8
  rejection** — layered defense against malicious members and renaming attacks
- Agent detection (gunshi/agent) rejects value-display commands, and the
  rejection message does not suggest bypass recipes like `run -- printenv`
- Terminal-injection defenses: control characters in server-distributed
  metadata are visibly replaced; value display also neutralizes control
  characters other than \t\n
- Server URL is https-forced (http allowed only for loopback), `MARUHI_TOKEN`
  is origin-bound via `MARUHI_TOKEN_ORIGIN` (prevents sending the token to a
  different origin), error messages never embed raw URL values (which could
  contain credentials)
- Client verification (§6.3) order: value signature → wrap-registration
  signature → DEK commitment check → decrypt. Decryption AAD is built from
  verified coordinates, not declared values. Bounded resync on future head,
  local floor (hash/serial only, no plaintext), non-echo input (raw mode)
- device flow: token lives only in a local variable, polling-interval floor is
  fixed (prevents busy-spin)

### Web / packaging / CI
- CSP: `default-src 'none'` baseline + only the single bootstrap script allowed
  by SHA-256 hash (no `'unsafe-inline'`); build fails if there is more than one
  inline script. `frame-ancestors 'none'` / `base-uri 'none'` /
  `Referrer-Policy: no-referrer`. No `dangerouslySetInnerHTML` / eval /
  external resource loading exists
- install.sh: `main()` wrapper (mid-download truncation protection), mandatory
  checksum verification (don't install what can't be verified), no partial
  files left, no sudo, no rc-file edits, version↔binary consistency check
- CI: minimal explicit `permissions`, `persist-credentials: false`, SHA pins on
  external actions (except pullfrog.yml — M-2), main-lineage check on tags
  (blocks publishing commits that skipped review), `bun audit` always runs,
  telemetry wholesale-disabled (left unsaid)
- `.dev.vars.example` has dummy values only. No real secrets in the repo or
  tests (test-vectors use fixed dummy keys by design)

---

## Supplement (2026-08-15): additional review of PR #63 (`9e30a56...de8f3af`)

While the main body was under review, PR #63 (Phase 2 Wave 2 A1) was merged to
main, so its diff (67 files / +8,596 lines) was reviewed additionally. The
target is the whole surface of the grant_server 0.5 implementation: crypto
(lease-policy canonicalization, `duplicate-server-key`, FP word display),
server (deployment key, `/auth/config` public surface, recipient class server),
CLI (`maruhi server grant` / `server revoke`), wire (api-schema), test-vector
regeneration.

### A-0. Verification of M-1's resolution (conclusion: resolved)

The following were confirmed in primary sources (main's source):

- **Canonicalization**: `chain-canonical.ts`'s `grant_server` payload is 4
  fields — `[serverEncPubHex, serverKeyFingerprintHex, scopeLpHex,
  leasePolicyLpHex]`. lease_policy is the spec's 3-level nested LP (constraint =
  LP(name, value) → element = LP(issuer, audience, LP(constraints)) → policy =
  LP(elements)); empty policy = empty byte string
- **Old format blocked**: `shapeGrantServer` rejects a missing `leasePolicy`
  (the old 3-field format) with `invalid-payload`. At consensus-rule level the
  old format is unacceptable = the "dangerous window" is closed
- **Size caps**: 8 elements / 8 constraints / 1024 bytes per string (§6.2's
  consensus rules) enforced in the shape check
- **`duplicate-server-key`**: implemented in `applyGrantServer`; the check
  order (role → FP self-consistency → re-grant rules → key duplication) is
  pinned by test vectors. The reverse direction (reusing a valid grant's server
  key as an add_member) stays explicitly out of scope in the spec (per §6.2's
  note)
- **Re-grant's two-layer judgment**: disclosure scope may only widen
  (`grant-scope-narrowed`), lease_policy is freely revised — per §6.3
- **Wrap complete-set**: `expectedWrapRecipientCount` = current member count +
  valid grants in the disclosure scope, defined once and shared by both the
  standalone-registration and composite paths (matches §12-4 / §12-6's
  2026-08-12 revision)
- **Recipient class server**: identification = both the server-key FP and the
  enc public key strictly match a valid grant's payload; out of scope is
  `scope-out-of-range` (422). The recipient position of HPKE info / the §5.1
  signed object carries the server-key FP (CRYPTO_SPEC §9). The distribution
  query has `recipient_class = 'member'` as an explicit condition so
  server-addressed wraps cannot leak into the member distribution path
- **Audit identity rule**: server recipients put the FP in the
  `target_key_fingerprint` column and are not mixed into the user_id column.
  The `chain.server_granted` mirror **deliberately does not copy** lease_policy
  (which contains external identifiers) (AUDIT_SPEC §1-2)
- **Class cross-check on the delete path**: how `dek.deleted`'s audit columns
  are written is decided only after verifying the stored row's
  `recipient_class` matches the request's declaration (audit-column semantics
  are not delegated to wire input)
- **Deployment key**: derived from `SERVER_ENC_KEY_IKM` (a 32-byte hex Workers
  Secret) via RFC 9180 `DeriveKeyPair` (standard API; verified against RFC 9180
  official vectors). A1 does not build a decryption path, only the public
  surface. Unset is designed not to fail open as "pure E2EE is normal" (the
  grant CLI side gives an explicit error)
- **CLI `server grant`**: owner check, scope existence, early checks of
  `duplicate-server-key` / re-grant rules → recompute the FP from the enc
  public key of `/auth/config` for self-consistency → **confirmation
  ceremony** (BIP39 12-word display + retyping the last word; non-interactive
  is `--expect-fingerprint`. **In AI-agent environments the ceremony is not
  delegated and is refused**) → CAS retry (resync with extension check —
  blocks re-signing a shortened/branched chain) → after acceptance, resync and
  verify the grant's presence (doesn't take the server's word as truth) →
  backfill (idempotent re-run converging on 409 = already registered)
- **CLI `server revoke`**: revoke_server append + **forced rotation of all
  environments** (§7's obligation). Interruption recovery is chain-derived
  (comparing the last revoke seq with the epoch-start seq) with no progress
  file. A deleted environment is skipped **only if a verified signed deletion
  statement exists** (not silently skipped on the server's 404 claim alone —
  per §7). Per-environment failures are not swallowed; they're aggregated
- **Removal of the old interim guard**: the "reject composite operations while
  a grant is valid" guard (`ensureNoServerGrant`) present at `9e30a56` was
  legitimately removed now that the complete-set includes server-key wraps

### A-1. Cross-recipient-class identifier collision makes first-time registration of the wrap complete-set a defect (Low, new)

> **Status (added 2026-08-15)**: **Corrected (defect eliminated)** — per the
> recommendation, the registration path's duplicate-detection key was changed
> to the stored row's uniqueness unit (epoch × recipient, ignoring class), and
> it now rejects pre-acceptance with a 422 (`duplicate-recipient`)
> (`dek-wraps.ts`. Mutation-verified that removing the fix makes the test fail
> with a 500). The delete path is unchanged (class-inclusive key + class
> cross-check against the stored row). **Why "corrected" and not "fixed"**
> (supplement 3): as long as the collision exists the complete-set is
> inherently unsatisfiable (member and server are different keys, so one row
> cannot serve both), and **the blockage of a new epoch itself is not solved by
> turning it into a 422**. Backfills addressed to the colliding member on an
> existing epoch are likewise pinned at 409 by the same root. The correction's
> meaning is the conversion "opaque defect → diagnosable typed rejection";
> recovery is via the operational means under "impact and mitigations"
> (remove_member or revoke_server of the colliding member) — **tests pin that
> rotation passes after remove_member**. The root cause (acceptance-policy
> format check on add_member's target user_id) is left untouched because it
> needs a spec-side decision. Note: now that A2 (PR #65)'s lease path is live,
> this finding's impact grew to include "blocking the §7 revocation rotation
> and lease availability" (the reason handling priority was raised).

**Location**: `apps/server/src/dek-wraps.ts` (`checkWrapSets`'s
first-registration branch, `wrapRefKey`), `apps/server/src/do-schema.ts`
(dek_wraps's primary key remains `(environment_id, epoch, recipient_user_id)` —
`recipient_class` is outside the key)

**Content**: a stored row's uniqueness is `(environment, epoch,
recipient_user_id)` — it does not include class — premised on member user_ids
and server server-key FPs "practically never overlapping in format" (ULID 26
chars vs hex 32 chars) (a comment in do-schema states this too). However,
**add_member's target user_id is intentionally a free string with no existence
check** (AUTH_SPEC §11-1), so an admin can add a member whose "user_id = the
server-key FP of a valid grant (32-char lowercase hex)". Then:

- The wrap complete-set (environment creation, rotation, first registration)
  requires wraps addressed to **both** this member and the server (exact-match
  requirement)
- The in-request duplicate check (`wrapRefKey`) uses a class-inclusive key, so
  both pass
- The first-registration branch (`existing === 0`) checks only the count, not
  per-wrap storage collisions
- In the write phase the second row's INSERT hits a primary-key violation →
  defect (500) → task rollback

Result: **as long as the collision exists, wrap registration for a new epoch
of that environment (= the composite of rotation/environment creation) always
fails with a 500**. The §7 revocation rotation is also blocked on that
environment. The append path into an existing epoch has a class-ignoring 409
check, so it does not defect (as intended).

**Impact and mitigations**: availability only (no confidentiality/integrity
impact; rollback leaves no inconsistency). Realization requires admin
permission (add_member) plus a grant already issued by the owner; an admin has
other means of disruption anyway. Recovery is possible via remove_member of the
colliding member (the chain append itself needs no rotation) or revoke_server.

**Recommended handling**: add a class-crossing identifier-duplicate check to
`checkWrapRecipients`, rejecting pre-acceptance with a typed error (a
`duplicate-recipient`-equivalent 422, not a 500). Additionally, a more
fundamental option is checking the format of add_member's target user_id
(internal ULID form) as an **acceptance policy** (§11-1 only asks that it not
be a consensus rule; it does not forbid an acceptance-policy format check) —
but the latter touches operational assumptions of the chain format, so it
needs a spec-side decision.

### A-2. `/auth/config`'s `serverEncPubHex` is not written in AUTH_SPEC §4 (Info, new)

> **Status (added 2026-08-15)**: **Resolved (PR #65)** — commit `50452f6` wrote
> `serverEncPubHex` into AUTH_SPEC §4, aligning spec and implementation
> (verified in supplement 2).

The implementation (`packages/api-schema/src/auth-api.ts` /
`apps/server/src/handlers-auth.ts`) returns `serverEncPubHex` in addition to
`serverKeyFingerprintHex`. It is needed as the distribution channel for "the
enc public key the server distributes" (CRYPTO_SPEC §9) and is public
information (the CLI recomputes and self-verifies consistency with the FP), so
**the implementation is sound**, but AUTH_SPEC §4's response definition lists
only `serverKeyFingerprintHex`. Per the "the spec is the only source of truth"
discipline, adding one line to AUTH_SPEC §4 is recommended.

### A-3. Caution on `--expect-fingerprint`'s self-referential check (Info, new)

> **Status (added 2026-08-15)**: **Fixed** — added a caution to
> `SELF_HOSTING.md`'s "Record the fingerprint (the comparison baseline)"
> section noting that passing the `/auth/config` re-fetch value at grant time
> makes the check self-referential.

The `server grant` confirmation ceremony is refused in AI-agent environments,
and non-interactive use is designed around passing **the FP copied
out-of-band** to `--expect-fingerprint`. "Copy the FP right after deployment
and use it as the comparison baseline (non-interactive passes it to
`--expect-fingerprint`)" is **already documented** in `docs/SELF_HOSTING.md`'s
"Record the fingerprint (the comparison baseline)" section and in the CLI help
("server-key FP copied out-of-band"). Only one gap remains: stating that
**mechanically fetching the value from `/auth/config` at grant time makes the
check self-referential and voids the ceremony** (the post-deploy fetch is the
intended trust-on-first-use anchor procedure, a different meaning from a
re-fetch at grant time). Recommend adding one caution line to that section of
`SELF_HOSTING.md`.

### Items checked and found clean in the supplement

- lease_policy CLI file input: the size caps (8/8/1024) are checked at the
  input stage too, claim names normalized ascending, `claimValue` allows the
  empty string (matches real OIDC claims) — doubles the consensus-rule shape
  check (crypto layer)
- `server grant`'s ceremony is not skipped even when the append is skipped
  (a backfill-only re-run)
- Backfill's 409 absorption is the only means of convergence given the
  constraint "there is no API listing server-addressed wraps (distribution is
  to the addressee only)", and it is compatible with the acceptance rule that
  forbids overwrite
- grant/revoke CAS retries go through resync with extension check
  (`resyncExtended`), refusing to re-sign a shortened or branched chain
- The FP word display (BIP39 12 words) is display encoding only (SHA-256 +
  fixed dictionary), no new primitive. English list fixed, no truncation (per
  §3)
- The DO schema migration (adding the `recipient_class` column via ALTER TABLE
  + DEFAULT 'member') correctly treats existing rows as member
- Test vectors: all grant_server vectors regenerated + added
  `duplicate-server-key` / check order / old-format rejection
  (`grant-server-lease-policy-dropped`) / positive and negative cases for
  recipient class server (keeping the spec §11 discipline of "vectors before
  implementation")

---

## Supplement 2 (2026-08-15): additional review of PR #65 (`3cfc205...6b839cc`)

PR #65 (Phase 2 Wave 2 A2 — OIDC verification + lease endpoint + lease wraps.
46 files / +4,415 lines), merged after PR #64 (which added this document), was
reviewed with the same methodology as the main body (spec cross-check +
primary-source verification). Judgment criteria: CRYPTO_SPEC §9.1 / AUTH_SPEC
§14 / AUDIT_SPEC §3.5 (§14's `crit` rejection, JWKS grace window, rate-limit
position, and the two 503 reasons were drafted by PR #65 itself and are
owner-approved by its merge). **On the added surfaces — the new
unauthenticated face (lease), the hand-rolled JWT verification, and unwrapping
by the server key — no spec divergence, authz regression, injection, or
external-identifier leakage into audit was found.** New findings: 2 Info (A-4 /
A-5) and 1 awaiting a ruling (below).

### Verification of A-2's resolution (conclusion: resolved)

Commit `50452f6` wrote `serverEncPubHex` into AUTH_SPEC §4, matching the
implementation (`packages/api-schema/src/auth-api.ts` /
`apps/server/src/handlers-auth.ts`).

### Items checked and found clean

**OIDC verification (`apps/server/src/oidc.package/` — AUTH_SPEC §14-1)**
- Structural blocking of alg confusion: the verification algorithm is always
  derived from the JWK's kty / crv, and the header `alg` is used only as a
  match check against the derived expectation (`jwk.ts`). Only RS256 / ES256
  are permitted; symmetric-key algs and `none` have no corresponding kty and
  are unreachable
- A `crit` header is rejected merely by being present (§14-1 (2b); closes ahead
  of time the same class of hole as the 2025–2026 Authlib / PyJWT / fast-jwt
  CVEs). Not checking `typ` is intentional, with the rationale stated in a
  comment (maruhi itself never issues a JWT, so there is no counterpart for
  cross-JWT confusion)
- Issuer allowlist check happens **before any external fetch** (`verifier.ts` —
  blocking induced arbitrary-URL fetches from the unauthenticated surface =
  amplification). Discovery checks self-claims (`issuer` match + `jwks_uri`
  same-origin https — blocks SSRF and key-provenance substitution),
  `redirect: "manual"`, 5-second timeout, measured 256 KiB cutoff
- JWKS cache (`jwks.ts`): a structure separating "the last good value" from
  "the fetch in flight" so a failure can never touch the good value.
  Forced refresh on unknown kid (60-second cooldown), an independent cooldown
  on the failure side (60 seconds), 6-hour grace window with
  stale-while-revalidate — all of §14-1's requirements implemented. Tokens
  without kid are accepted only when the usable key is unique (eliminates
  brute-force verification)
- base64url is strict-decoded (charset + length mod-4 checks; blocks a lenient
  decode passing a different byte string). The signed object is the received
  segment string itself (no re-serialization)
- Time checks: `exp` / `iat` required, ±60 s skew, `nbf` handled. `aud`
  normalizes both string/array forms, and **multiple audiences get 401
  `ambiguous-audience`** (they would break claims_digest uniqueness —
  `handlers-lease.ts`)

**Lease authorization / response (`programs-lease.ts` / `handlers-lease.ts` —
AUTH_SPEC §14-3)**
- Judgment order per spec: server key unset → uniform 503 before the chain is
  read (existence doesn't leak on a keyless deploy) → uninitialized → 404 (no
  audit row left — blocks unauthenticated-path audit-bloat DoS) → grant /
  lease_policy (existence quantized) / scope mismatch → uniform 404 →
  environment exists → rate limit (after authorization — blocks existence
  leakage via 429) → server-addressed wrap exists (503). Tests pin both that
  the five 404 branches are identical down to the body, and that the audit
  reason column records each branch separately (`lease.test.ts`)
- The rate-limit window is consumed only on successful issuance (the 503 path
  and unauthorized requests are pinned non-consuming by tests). The window is
  300 issuances/hour per project; the noisy-neighbor radius is stated in
  `policy.ts`
- Claim constraints are string exact-match only, no type coercion
  (`lease-policy.ts`; `claims["__proto__"]` etc. are objects and do not match a
  string). An empty lease_policy is always unauthorized
- Unwrap + re-wrap are unified inside the `ServerKey` closure
  (`server-key.ts`). No API returns the plaintext DEK; it is zeroed after use
  (limits noted in a comment). Failures carry only fixed-vocabulary reason
  codes (no key-material or ciphertext fragments)
- `LeasedDek` is a distinct type from `RecipientDek` (cannot confuse response-
  scoped material lacking a registration signature with a distributable wrap).
  The response wire form is shared with §12-7 bulk pull (the `toWireVariable`
  move is a pure share — function bytes identical)

**Audit (AUDIT_SPEC §3.5)**
- `server.dek_unwrapped` / `server.lease_issued` use actor = server + key FP;
  `server.lease_denied` uses actor = system. Payloads carry only reason code +
  claims_digest + grant_chain_seq — **external identifiers (repository name,
  ref, raw issuer URL) appear in none of the three** (the only consumer of
  `facts.claims` is the authorization check). denied is recorded only after
  signature verification passes, in a fixed window of 100 rows/hour, and
  recording + window consumption share one sync block
- `var.read` is not recorded on lease responses (§14-4)

**Wire / schema (`packages/api-schema`)**
- `oidcToken` ≤16 KiB + compact-JWS charset; `ephemeralPubHex` strict 32-byte
  hex. The error contract limits 404 to a single `ProjectNotFoundError` kind
  (deliberately does not declare `EnvironmentNotFoundError`, eliminating 404
  branching at the type level). The lease group is the only group that does not
  declare `.middleware(AuthMiddleware)`, so unauthenticated separation holds at
  the api-schema contract level (a wiring mistake in index.ts is structurally
  impossible)
- Point-invalid X25519 public keys are still rejected by
  `importEncryptionPublicKey` failing after Schema passes (layered)

**crypto lease wrap (`packages/crypto/src/internal.package/lease-wrap.ts` —
CRYPTO_SPEC §9.1)**
- info / claims_digest construction matches the spec exactly (an independent
  implementation recomputed LP + SHA-256 and matched the vectors on every
  field). The domain `maruhi/v1/lease-wrap` diverges from §5's
  `maruhi/v1/dek-wrap` at the first LP byte, making cross-transplant
  structurally impossible
- No new crypto primitive or custom construction: HPKE goes through the
  existing single construction point (`hpke.ts`), LP through the §2.1 shared
  encoder, hashing is WebCrypto SHA-256 only. Open takes a KeyPair (compatible
  with non-extractable keys)
- Input checks: `claimsDigestHex` is 64-char lowercase hex only (both wrap and
  unwrap sides), issuer / sub / aud reject empty strings, dek fixed at 32
  bytes. Error values carry only static-literal field names (no secret or input
  fragments); HPKE exceptions fold to information-free errors via an unbound
  catch (no oracle)
- Vectors: 2 positive (basic / prior-epoch) + 5 negative (4 coordinate kinds +
  domain substitution) exist, and `basic`'s coordinates and DEK are identical
  to dek-wrap.json's `server-basic` (the unwrap → re-wrap handoff is traceable
  on the vectors). The `chain-entries.json` diff is only the addition of
  `grant_seq` to derived state (zero byte change to entries, signatures, or
  the hash chain; added to every non-empty server_grants; a consistency-check
  code was added too)

**Secondary server-side changes**
- Added SQL (3 queries in `data-store.ts`) is all `?`-bound. The only string
  concatenation is a column name reachable only from source literals
- The `lease_windows` table is `kind TEXT PRIMARY KEY` (max 2 rows); the
  migration conforms to the existing discipline (append at end +
  transactionSync + old-code rejection). Test-reset declarations complete
- `chain-do.ts`'s new RPC `issueLease` goes through the same permit
  serialization + defect-time cache discard. No changes to existing RPC
  judgments
- Test infrastructure: builds a server-addressed wrap with a key actually
  derived from `SERVER_ENC_KEY_IKM` and checks "it really unwraps". The OIDC
  issuer is an outboundService fake and never hits the real network. Verified
  that every test the PR claims exists is real — e.g. "the DEK the workload
  opens = the original epoch DEK", "no repeated re-fetch while the issuer is
  down", "falls before reading the chain when the server key is unset
  (ChainStore stubbed to throw)"

### A-4. A single valid OIDC token can materialize a DO for an arbitrary project ID (Info, new)

**Location**: `apps/server/src/chain-do.ts` (the constructor's
`ensureProjectDoTables`), `apps/server/src/programs-lease.ts` (the handoff
comment on the probe-rate cap)

**Content**: lease is the data plane's only unauthenticated endpoint (the
auth-flow unauthenticated surfaces are separate — A-6), and a holder of one
valid token from a permitted issuer who throws an arbitrary 64-hex project ID
gets an uninitialized 404 that leaves no audit row, but **a DO holding empty
tables is still created** (a storage cost). Project IDs are genesis hashes and
unguessable, and passing OIDC verification is a precondition — mitigating
factors — and the code already has a nearby handoff saying "a cap on the
request rate itself is unimplemented", but the "a DO gets materialized" aspect
is not stated. Note the same DO materialization exists on **authenticated**
GETs (environment list, metadata-only pull, etc. — a session principal with an
arbitrary project ID has no scope check), which a third party can fire via a
Lax-cookie top-level navigation (supplement 3). In both cases the impact is
storage consumption only, and the countermeasure belongs to the same design
decision as the probe-rate cap (that AUTH_SPEC §11-4's definition of "stateful
GET" excludes this is now stated spec-side).

**Recommended handling**: add one line to `programs-lease.ts`'s handoff comment
(folding DO-creation cost into the probe-rate design decision). The
countermeasure itself belongs to the same decision as the probe-rate cap, so
it stays a handoff. → **The comment addition is done (2026-08-15)**. What
remains is the design decision on the probe-rate cap itself (same as the
existing handoff).

### A-5. Handoffs to A3 (workload implementation) (Info, new)

Three cautions for implementing the CI client (unwrap side) in A3. None is a
defect of the current implementation; they are discipline for using the public
API:

1. **Use `computeLeaseClaimsDigest` for the claims digest**: the exported
   `buildLeaseClaimsBytes` has no empty-string guard on issuer / sub / aud (LP
   means no collision, but `computeLeaseClaimsDigest` is the only
   verified-guarded entry point)
2. **`unwrapLeaseDek` does not check the length of the extracted DEK** (same
   treatment as §5's `unwrapDek`). The layer that catches a malicious server
   Sealing something other than 32 bytes is §5.2's commitment check — do not
   skip client verification (§6.3 / §9.1's recipient obligations)
3. **State the replay non-guarantee explicitly**: `lease-wrap.ts`'s header
   comment only covers the guarantee "reuse on a different job fails
   decryption". Adding a one-line reference to §9.1's non-guarantee — "replay
   of a token within its validity" (awaiting ruling, below) — prevents an A3
   implementer reading the module alone from misreading → **done
   (2026-08-15)**. Note the ruling on replay itself was settled by adopting
   first-come binding (status note below) — the crypto layer's non-defense
   (the fact this reference points at) is unchanged after the ruling (binding
   is carried by server state)

### Awaiting ruling (owner decision): replay of an OIDC token within its validity

> **Status (added 2026-08-15)**: **Ruled — first-come binding adopted** (an
> owner ruling after 3 rounds of design exploration; comparison, rejected
> options, and precedent in docs/notes/session-24.md). The server records
> "token hash → ephemeral public key" at issuance and rejects a re-request with
> the same token + different key as 401 `token-replayed` (AUTH_SPEC §14-1 /
> §14-3, CRYPTO_SPEC §9.1 shrink the non-guarantee to "first-come before first
> use" and "cross-project first-come"). Because the wire form, lease_policy
> check semantics, claims_digest, and chain format are unchanged, the earlier
> assessment below — "every mitigation affects the wire form / policy-check
> semantics" — did not apply to the adopted option (it applied to the rejected
> proof-of-possession family — same note). The below is kept as the pre-ruling
> record.

An open item PR #65 explicitly handed off (not an implementation bug — behavior
is per spec). `claims_digest` binds only issuer / subject / audience and
includes neither the ephemeral public key nor a nonce, so **anyone who obtains
a copy of a still-valid token can receive a DEK legitimately re-wrapped to
their own ephemeral key** (exposure window = `exp - iat`; GitHub Actions OIDC
tokens default to ~10 minutes). §9.1's guarantee is "cannot be transplanted to
a different workload identity", not bearer-replay prevention within the same
identity (already written as a non-guarantee in CRYPTO_SPEC §9.1). Every
mitigation affects the wire form / policy-check semantics (mixing an
ephemeral-key hash into `aud`, or a server-issued nonce two-round-trip), so
**a ruling is needed before A3 (CI client) implementation**.

---

## Supplement 3 (2026-08-15): self-review of the follow-up fixes

The fix diffs for M-2 / A-1 / L-1 / L-3 / L-5 / A-3 / A-4 themselves went
through two independent review rounds (round 1 = a single-pass full review;
round 2 = adversarial review + discipline-consistency review in parallel).
Results are reflected in each status note above (L-3's downgrade to
"mitigated", A-1's qualification to "corrected", M-2's 2 residual points,
A-4's widened scope). One new finding:

### A-6. `/auth/github/callback`'s unauthenticated outbound amplification and missing input cap (Low, new)

**Location**: `packages/api-schema/src/auth-api.ts` (`githubCallback`'s query),
`apps/server/src/handlers-auth.ts` (callback handler)

**Content**: L-3 covered only device/exchange, but the web OAuth callback has
the same "unauthenticated → GitHub outbound" shape. state is self-bound
(double-submit): the attacker can put it on both the cookie and the query, so
after getting one state at `/auth/github/start`, each subsequent callback
request can induce a code exchange (a normal flow costs up to 3 calls
including the post-success `/user` and `/user/emails`). Moreover the `code` /
`state` query had **no size cap at all** (device/exchange has 512 chars +
format check). OAuth's code format is not spec-defined, so a device/exchange-
style format check cannot block it.

**Handling (done)**: added a 512-char cap to `code` / `state` (length only —
a format check is impossible. The amplification itself can still be induced
with an in-cap code, so this blocks oversized input; the primary
countermeasure is the operational rate limit). Added callback to
`SELF_HOSTING.md`'s per-IP rate-limit recommendation table, and corrected the
mistaken "there are 2 unauthenticated endpoints" (`/auth/config` and
`/auth/github/start` are also unauthenticated) to the accurate enumeration
"3 unauthenticated surfaces where a third party can induce expensive work".
Added a mention of callback to AUTH_SPEC §4's format pre-check paragraph.
**The remainder is identical to L-3** (per-IP limiting of in-cap floods of
format-valid input is ops-side), so the severity and status follow L-3.

### Main attack hypotheses verified "does not hold" in round 2 (record)

- L-1: header-name case bypass (effect's Headers lowercases every key) · a
  4th value of principal.kind (3 values on the type; anonymous 401s earlier) ·
  header attachment via CORS (no CORS → preflight impossible)
- L-3: ReDoS in the pattern (single char-class + anchors = linear) · false
  rejection of real tokens (`gh[a-z]_` covers gho/ghp/ghu/ghs/ghr.
  `github_pat_` reaches the check-token path and 404s anyway, so no lost
  functionality)
- A-1: acceptance-boundary skew vs the delete path (deletion always 404s one
  side via the stored-row class cross-check) · key collision via epoch's
  numeric representation (`PositiveInt` Schema + decimal notation is
  injective)
- L-5: re-wrapping 204/null bodies and streaming responses (`new
  Response(body, …)` is legal for both) · cache destruction of static assets
  (the API worker has no assets binding)
- Reduced test strength from test renaming (`gho_test<n>` etc.) — confirmed
  every "invalid token" case still goes through the check-token path in
  format-valid form

---

## Known residual non-guarantees at the spec level (reference)

The following are not implementation flaws but v1 non-guarantees stated in
CRYPTO_SPEC §14.3, and this review does not re-raise them: availability (G8),
plaintext correctness (G9), rollback distribution to floor-less first-sync
clients, the mechanical non-detection of split view, collusion injection into
in-membership-interval coordinates (especially forward injection of meta
statements), and the impossibility of unreading an already-read value.
Mitigations (out-of-band anchors, head gossip, environment manifests) are
already planned in the spec as Phase 2 responsibilities.

## Recommended handling order (revised 2026-08-15)

1. ~~M-1~~ — **resolved by PR #63**
2. ~~M-2 / A-1 / L-1 / L-3 / L-5 / A-3 / A-6~~ — **handled in the 2026-08-15
   follow-up** (see each finding's status note — L-3 / A-6 remain "mitigated"
   and A-1 "corrected". A-1's priority was raised and handled because A2's
   lease went live)
3. ~~A-2~~ — **resolved by PR #65** (verified in supplement 2)
4. ~~OIDC replay ruling (supplement 2)~~ — **ruled and implemented
   (2026-08-15)**: first-come binding adopted (see supplement 2's status note
   and docs/notes/session-24.md)
5. **L-2 / L-4** — together with Phase 2's token-management UI / audit UI
   design + spec revision
6. **A-5** — referenced as discipline at A3 implementation time (A-4's comment
   addition is done; the probe-rate-cap design decision is the same as the
   existing handoff)
