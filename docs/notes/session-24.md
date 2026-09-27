# Session 24 notes (ruling on in-lifetime replay of OIDC tokens)

Date: 2026-08-15. Prerequisites: main with PR #66 in (`39a3371`).
Branch: `claude/maruhi-oidc-replay-ruling-jiwfhb`.
Scope: the owner ruling on **in-lifetime replay of OIDC tokens**, which PR #65
(Wave 2 A2) explicitly handed off and `docs/SECURITY_REVIEW_2026-08-14.md`
supplement 2 marked "awaiting ruling" (item 4 of that review's "recommended
response order". The precondition for A3 = CI client implementation).
On numbering: session-22.md is the last file on disk, but since PR #65 calls
itself "session 23" in its body, this note is 24.

## 1. Problem definition

The `claims_digest` on the lease path (CRYPTO_SPEC §9.1 / AUTH_SPEC §14) binds
only issuer / subject / audience — neither the workload's ephemeral public key
nor a nonce. So **anyone who obtains a copy of an in-lifetime OIDC token**
(network capture, a malicious workflow step, log leakage) can request a lease
with **their own ephemeral key** and receive a legitimately re-wrapped DEK.
Exposure window = `exp - iat`. §9.1's guarantee is "cannot be redirected to a
different workload identity", not prevention of bearer replay under the same
identity (already documented as a non-guarantee at A2 merge). The replay's loot
being "all environment ciphertexts + the chain + a DEK lease" is the decisive
asymmetry versus AWS-style federation, where the loot stays an ephemeral
credential (→ the precedent split in §2).

## 2. External facts (ruling inputs. Verified against real APIs / primary sources)

### Issuer capability differences

| issuer | Issuance timing | Runtime control of aud | jti | exp − iat |
|---|---|---|---|---|
| GitHub Actions | Per-request during the job (`ACTIONS_ID_TOKEN_REQUEST_URL` + `&audience=`) | ✓ arbitrary string (**charset/length constraints undocumented**) | ✓ | Measured ~5 min (300 s reported; no documented guarantee) |
| GitLab CI | **Pre-issued at job start** (`id_tokens:` in `.gitlab-ci.yml`) | ✗ fixed at config time (CI variable expansion allowed. **Job-generated values are not**) | ✓ | Job timeout (can be hours) |
| CircleCI | Pre-injected via env var by default (aud = org ID, fixed) | △ runtime issuance possible via `circleci run oidc get --claims` | unverified | unverified |
| Kubernetes | projected volume is pre-issued / TokenRequest API is runtime | △ (only with TokenRequest permission) | ✓ (GA in 1.32) | 1h default |

Implication: **"have something embedded into the token" mitigations are
structurally impossible on GitLab** (pre-issued + config-time-fixed aud). Only
mitigations completed by server-side state alone preserve issuer generality
(session-22 §2 R1).

### Precedents (how mint-type endpoints handle replay)

- **PyPI trusted publishing (the closest isomorph)**: implements **single-use
  jti** on its mint-token endpoint (recorded in Redis with exp+5 s). Then the
  2026 second audit found and fixed the inconsistency "JWT verification leeway
  30 s > replay-cache residual 5 s" (replays pass during exp+5 to exp+30's 25
  s). **Lesson: keep the duplicate record alive at least as long as the
  signature-verification acceptance window** (reflected in the adopted spec)
- **AWS AssumeRoleWithWebIdentity / Vault JWT auth / Infisical / Doppler**: no
  single-use (bearer accepted for its lifetime). But these are
  authorization-gate types where "what the exchange yields is an ephemeral
  credential whose exercise is separately recorded". **Only PyPI — the closest
  secret/capability direct-distribution type — chose the (c) family**
- **Sigstore Fulcio**: challenge = "ephemeral-key signature over the OIDC
  token's sub" = **a proof of ephemeral-key possession, not a token↔key
  binding** (a stolen token + your own key passes). Its replay residue is left
  to post-hoc detection via the transparency log (CT) — the (d) trap, knowingly
  accepted by a production system
- **Ecosystem direction**: W. Woodruff (designer of PyPI trusted publishing)
  publicly proposed on 2026-08-10 that "GitHub's **runtime arbitrary audience
  is itself a defect** and `id-token: [aud]` should be constrained to a static
  allowlist". A design depending on dynamic audience ((b) below) collides
  head-on with this hardening direction
- **IETF WIMSE (standardizing)**: WIT (key-bound token) + WPT (per-request
  proof of possession) = the standardized version of (b). **It presumes
  issuer-side support**, which CI issuers lack. A topic for an additional
  ruling when issuers do support it (§7)

## 3. Refutation of (d) server-issued nonce (checking the prior estimate — conclusion: does not work, as estimated)

- The naive form (sign a nonce with the ephemeral key and return it) proves
  **only possession of the ephemeral key**. The ephemeral key is the attacker's
  free choice, and there's no cryptographic binding between token and key. A
  stolen token + your key + your key's nonce signature passes (same shape as
  Fulcio's challenge — §2)
- The only way to make a nonce meaningful is "have the nonce placed **inside**
  the signed token" = proof of the ability to make the issuer issue anew. The
  only field the workload can control at issuance on real APIs is **aud** (§2).
  So (d) is not an independent option — it converges to a (b) variant
- What that variant adds over (b) is only the freshness of "issuance after
  nonce fetch"; the only attack it closes is "post-hoc use of tokens stockpiled
  during a temporary workload compromise (max ~5 min on GitHub)". The cost is a
  **new unauthenticated nonce endpoint** (the only option that would force a
  row addition to the existence-concealment design + SELF_HOSTING's per-IP
  table) + nonce state + an extra round trip. Rejected

## 4. Option comparison (summary. Aggregated from exploration rounds 1–3)

Judgment axes: what it prevents (first-use wins / visibility / exposure
window) / lease_policy matching semantics / the identification premise of
claims_digest and AUDIT §3.5 / issuer generality / spec delta / size of A2
follow-up implementation and vector regeneration / A3 procedure / SELF_HOSTING's
per-IP table.

### (a) Status quo (documented as a non-guarantee only)

No added defense. Exposure window = the full exp−iat (adding GitLab makes it
hour-scale). Replays only appear as duplicate `lease_issued` under the same
claims_digest, indistinguishable from matrix parallelism / retries =
**invisible**. Precedents exist (AWS/Vault) but they're authorization-gate
types (§2), and the isomorphic PyPI chose (c). Zero impact everywhere is the
sole merit.

### (b) Binding an ephemeral public-key hash into the requested aud (proof of possession)

**Blocks all token theft including first-use races** (the token is bound to the
legitimate job's key at issuance time). Residue is workload compromise only
(shared across all options, principled and unavoidable — issuance capability =
the workload identity itself). However:

- **Structurally impossible on GitLab** (§2) → becomes a per-issuer
  requirement, breaking the spirit of R1's "adding an issuer changes nothing"
- The dynamic-audience mechanism it depends on is itself headed toward static
  constraints (§2's Woodruff proposal)
- GitHub's audience constraints (charset, length) are undocumented = a measured
  risk for A3
- lease_policy matching becomes "strip the suffix and exact-match the base"
  (chain format and policy notation unchanged). Using the **base** as
  claims_digest's audience input keeps §3.5's identification premise unchanged
  (the variant putting the full aud in was rejected — it changes the digest
  per job and breaks audit identification)
- **Can be added later with backward compatibility** (policies carry only the
  base, so it can land in two stages: additionally accepting suffixed aud →
  making it per-issuer mandatory) = no need to decide now

### (c) single-use jti → adopted form (c′) first-binding of a token hash

The naive (c) with two fixes:

1. The duplicate key is **SHA-256(JWS signing input = `header.payload`)**, not
   jti (jti presence/semantics vary by issuer — §2 table. A signing-input hash
   asks nothing of the issuer). **Initially drafted as "SHA-256(raw token
   bytes)", but review found the raw token's signature segment is malleable,
   so it was changed to the signing input (§9)**
2. Not strict single-use but **first-binding**: at issuance record
   "token hash → ephemeral public key"; a repeat request under the same token
   is **idempotently allowed if the same key** (legitimate retry after losing
   the response — doesn't break pre-issuing issuers that can't re-issue a
   token), and **401 `token-replayed` under a different key**

Prevents: **all post-use replay** (logs, post-hoc leakage — almost the whole
realistic theft surface. The exposure window shrinks to "until first use" —
since A3 issues just before requesting, effectively seconds). Doesn't prevent:
theft + first-use win before first legitimate use (effectively TLS-breaking
MITM class; the legitimate job fails with `token-replayed`, which is detected),
cross-project first-binding (§7). Visibility: the attacker's later attempt =
401 + `lease_denied` (and since claims_digest is identical to the legitimate
one, **it identifies which workload's token was stolen**). Impact: lease_policy
matching, claims_digest, AUDIT §3.5, the chain, crypto, vectors, A3 procedure,
the SELF_HOSTING table = **all unchanged**. Implementation is server-only and
small (1 DO table + 1 decision stage + GC).

### (e) Combine (b)+(c′)

The strongest form — closes even the first-use race — but pays (b)'s
per-issuer branching, dynamic-audience future risk, and A3 measurement risk
now. As long as (b) can be added later, there's little necessity to pay it in
v1.

## 5. Other considered & rejected options (re-consideration record)

- **iat freshness cap (accept only within N seconds of issuance)**: shrinks but
  doesn't close the window, and is incompatible with GitLab's pre-issuance +
  long-running jobs. Under (c′) the gain mostly vanishes
- **Detection only (Fulcio CT style: surface same-digest anomalies in the audit
  UI)**: inferior because (c′) already includes both blocking and detection
- **Single-use keyed by claims_digest**: would wrongly reject matrix-parallel
  jobs (same iss/sub/aud). The duplicate key must be **per-token**
- **Embedding the PoP public key in the repository anchor** (riding on §6.3
  (b)): the corresponding private key could only live in GitHub secrets,
  abandoning R1's "nothing stored on the GitHub side". Also contradicts the
  design premise that anchors are non-sensitive
- **Querying GitHub Actions run state** (verify via GitHub API that the token's
  run_id job is running): needs a credential for private repositories (violates
  R1), the unauthenticated API is rate-limited into uselessness, issuer-
  specific. Rejected
- **ZK-JWT (zkLogin style: never send the token, prove possession in ZK, bind
  the proof to the ephemeral key)**: the theoretical silver bullet, but it's
  introducing a new crypto primitive — ZK circuits — and collides head-on with
  CLAUDE.md's absolute rule (WebCrypto + the selected HPKE only). **Recorded as
  the kind of solution the rule rightly forbids**
- **DPoP / RFC 7800 cnf / WIMSE WIT+WPT**: all presume the issuer can bind keys
  into the token. CI issuers don't support it (additional ruling in §7 when
  they do)
- **mTLS / client certificates**: CI runners can't hold long-term credentials
  (the diskless / nothing-stored principle)

## 6. Ruling and key points of the adopted spec

**Ruling (2026-08-15, owner)**: **adopt (c′) first-binding**. Exploration ran
3 rounds (each at the owner's direction to re-check "is there a better option"
— round 2 surfaced the PyPI precedent, Fulcio's (d) isomorphism, and the
Woodruff proposal; round 3 covered WIMSE, GitLab direction, and competing
secrets managers). No strictly-better option emerged, and (c′)'s grounds
strengthened across rounds).

Adopted spec (reflected in AUTH_SPEC §14-1 / §14-3 and CRYPTO_SPEC §9.1):

- At issuance, record "SHA-256(JWS signing input = `header.payload`) →
  ephemeral public key" on the project DO. Same key + same token = idempotent
  allow / same key + different key = 401 `token-replayed` (**the reason for
  hashing the signing input rather than the raw token is §9** — the raw token
  is malleable)
- The check runs right after authorization (lease_policy, scope) and before
  environment-existence checks (don't let the binding state be observable with
  less-than-authorized standing. Uniform 401 regardless of the environment's
  actual existence = a holder of a policy-matching copy learns nothing about
  the environment's existence). Reads consume no rate window
- The record lives in the same atomic block as issuance, audit, and
  rate-window consumption (DO permit serialization)
- **Retention consistency (required)**: binding rows live ≥ exp + clock skew
  (the PyPI audit lesson — §2). GC runs after that lifetime
- 401 semantics: `token-replayed` is a 401 as "a failure attributable to the
  presented credentials" (reachable only after authorization passes =
  compatible with existence concealment. Folding it into 404 would make the
  legitimate job's failure undiagnosable, defeating the visibility purpose)
- Audit: `server.lease_denied` reason `token-replayed` (a rejection after
  signature verification passes ✓. Counted in the fixed window of 100
  rows/hour)

## 7. Residue and conditions for future additional rulings

- **First-use win before first legitimate use** (CRYPTO_SPEC §9.1
  non-guarantee (1)): closing it needs proof of possession ((b) / WIMSE).
  Conditions for an additional ruling = either (i) the target issuer provides
  key binding into the token (cnf / WIMSE WIT), or (ii) the move toward static
  constraints on dynamic audience stalls and (b)'s future risk resolves
- **Cross-project first-binding** (same (2)): only possible when multiple
  projects' lease_policies allow the same workload identity. Globalizing the
  binding needs cross-DO state and isn't worth v1's complexity (avoidable by
  configuration: vary audience per project)
- Compromising the workload itself (stealing issuance capability) is shared by
  all options and can't be prevented in principle — §14.2's guarantee (no
  forged-value injection) and the out-of-band anchor (§6.3 (b)) are unaffected

## 8. Handoff to implementation

- No required change to the A3 client. SHOULD/MUST:
  - (SHOULD) issue the token immediately before the lease request (minimizes
    the first-use window)
  - (SHOULD) GitHub (runtime-issuance type) may auto-retry `token-replayed`
    once with a fresh token
  - (**MUST** — review-reflected §9): a job leasing multiple environments on
    one token must present **the same ephemeral key** on every request (the
    binding is per-token and pins the key across environments — rotating the
    key makes the second request onward `token-replayed`). For pre-issuing
    issuers (GitLab / k8s), reusing the token with a fixed key is the only
    option
- Server implementation follows the lease_windows DO-table append pattern
  (`lease_bindings`). Row count is bounded by the issuance rate window
  (300/h); GC runs after exp + skew. **The binding key column is
  `binding_key_hex`** (not `token_hash_hex` — prevents the §9 mix-up)
- No vector regeneration (the crypto layer is unchanged — claims_digest's
  definition and the lease wrap's info construction are untouched)
- The lease-wrap.ts header reference (security review A-5's item 3) was done
  this session — since the crypto layer's non-prevention of replay is
  unchanged by the ruling (the binding is carried by server state), the
  reference wording was written ruling-independent

## 9. Review reflections (2026-08-15 pullfrog — PR #67)

Against the initial implementation (commit abbd392), the pullfrog review
produced 1 CAUTION and 2 secondary findings. One was a real bug that disabled
the defense; it was fixed.

- **🚨 Binding-key malleability (real bug — fixed)**: the first implementation
  used **SHA-256 of the raw token string** as the binding key. The raw token
  includes the third segment (the signature), which lies **outside** the
  signature's protection and is malleable via unused bits in the trailing
  base64url group (which WHATWG forgiving-base64 decode discards) and ES256's
  `s`-malleability — **you can change the raw token string without changing
  the decoded bytes, the signature verification, or claims_digest at all**
  (the RS256 trailing character has 15 equivalent values. Measured: it passes
  OidcTokenSchema's regex, decodeBase64Url, and atob alike). Keying on the raw
  token means swapping the last character of a stolen token makes the binding
  check miss and a lease gets issued to the attacker's ephemeral key = this
  ruling's entire defense voided. **Fix**: the binding key is now **SHA-256 of
  the JWS signing input (`header.payload`)** (computed by the verifier after
  signature verification passes, exposed as
  VerifiedOidcToken.signingInputHashHex). The signing input is the byte string
  the issuer actually signed and is invariant under validity-preserving
  mutation. ES256 s-malleability lands on the same key too since the signing
  input is unchanged. Wire shape, claims_digest, and vectors are unchanged
  (only the hash **input** changed: raw token → signed bytes). The column was
  also renamed `token_hash_hex` → `binding_key_hex` to prevent mix-ups about
  "what is hashed" at the naming level. Added a regression test (a token whose
  signature tail is mutated to an equivalent value passes signature
  verification yet yields `token-replayed`)
- **⚠️ Undocumented client obligation (docs added)**: the binding is per-token
  and doesn't key environment_id, so a job leasing N environments on one token
  must use the same ephemeral key on every request. Rotating the key per
  request makes the second one `token-replayed`. This is intentional (locking
  the token to its first key simultaneously closes the path of pulling an
  unbound other environment with a stolen token) but undocumented — now stated
  as an obligation in AUTH_SPEC §14-1 / CRYPTO_SPEC §9.1 / this note's §8.
  Added positive tests (same token + same key across multiple environments OK /
  key rotation on another environment → 401)
- **ℹ️ Missed follow-through on the check-order description (docs fixed)**:
  the `programs-lease.ts` module header and
  `packages/api-schema/src/lease-api.ts`'s check-order enumeration still had
  the old 4 stages (§14-3 and the test header were already updated). Added the
  first-binding stage to both

Note the core of this ruling (adopting first-binding, shrinking the
non-guarantee, the check position, the retention derivation) was judged sound
in review and is unchanged. The fix is a single implementation-level point
("what to use as the binding key") + 2 documentation points — not the ruling
itself.

Re-review (feab660) approved. Handling the additional 2 ℹ️:
- **In-place edit of migration step 4**: the column-name fix (token_hash_hex →
  binding_key_hex) was done by editing step 4's DDL directly. It's an exception
  to the append-only rule (do-schema.ts), but step 4 was created inside this
  PR, is unmerged and undeployed, and no external DO has applied it — so it's
  acceptable (adding a rename step would leave permanent noise for a table
  nobody holds — the review also judged in-place "the right call").
  **Pre-merge check item**: if a DO applied abbd392 (the intermediate commit)
  and recorded version 4, the fixed DDL is skipped by `IF NOT EXISTS` and
  runtime hits `no such column: binding_key_hex`. This branch was deployed
  nowhere (CI creates a fresh DO every run), so no such persistent DO exists.
  Only if the intermediate commit was run under local `wrangler dev` would that
  persistent storage need discarding (handle by deletion, not migration)
- When §9 was inserted, §8's trailing item (the lease-wrap.ts reference) had
  flowed to the end of §9 — moved back inside §8 (this commit)
