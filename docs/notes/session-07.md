# Session 07 notes (variable-value API + audit log — AUTH_SPEC §12 / AUDIT_SPEC implementation)

Date: 2026-08-02. Prerequisites: PR #16 / #17 merged (D1 + auth foundation + chain API authorization).
Scope: the data-plane API for environments, variables, and DEK wraps (spec ruling → AUTH_SPEC §12 →
implementation) plus the project-DO side of the audit log (AUDIT_SPEC §3.3 / §3.4 / §5.1).

## 0. How AUDIT_SPEC approval was handled (first thing to confirm)

Because this execution environment couldn't get real-time responses to AskUserQuestion, the
"proceed provisionally on the recommended option that avoids irreversibility" decision protocol was applied:

- **What proceeded provisionally**: AUDIT_SPEC was already merged as the owner's own draft (PR #10) with
  only its Status left as draft, so Status was updated to approved conditionally on "owner approval =
  review approval of this PR", and the project DO side (§3.3 data family + §3.4 chain mirror
  + §5.1 schema) was implemented together with the variable API
- **Confirmation condition**: review approval of this session's PR. If not approved, the AUDIT_SPEC
  Status change and the audit-log implementation commits get reverted (the append API is not exposed
  and the D1-side schema is untouched, so the revert stays local)

## 1. What was done (commit order = layer order)

1. **spec**: AUTH_SPEC v0.3 — added §12 (connection to the variable-value / environment / DEK APIs).
   CRYPTO_SPEC **unchanged** (all rules specified as API acceptance policy; consensus rules and
   crypto spec untouched — a structure that avoids the pre-approval requirement for crypto-spec changes). Added the
   mirror backfill ruling to AUDIT_SPEC
2. **core/api-schema**: EnvironmentId / VariableId (§12-1), authMethod added to session principals,
   wire representations of EncryptedPayload / WrappedDek / RecipientDek (§12-2), the 3 groups
   environments / variables / deks + typed errors
3. **server (DO)**: do-schema.ts (DDL consolidation + PROJECT_DO_TABLES), chain-store.ts
   (shared extraction of derived caches), data-store / data-plane / data-programs,
   audit-store (§5.1 + §3.4 mirror). Chain-append acceptance and mirror appends are written under the
   same Semaphore(1) serialization
4. **server (HTTP)**: handlers-{environments,variables,deks} + data-http
   (callProjectData common path, DataRejection → typed-error mapping)
5. **tests**: 34 added (294 green). Verified through round-trips with real crypto (test-time signing
   chains, real HPKE wraps, real AES-GCM)
6. **docs**: this memo

## 2. Rulings (multi-option comparison → proceeded on the recommendation; confirmation = PR review approval)

### Ruling 1: who assigns environment_id / variable_id

| Option | Content | Evaluation |
|---|---|---|
| A: server-assigned (ULID) | the create API returns the ID | the value entering AAD / HPKE info can't be fixed before encryption, producing a 2-round-trip "get ID → wrap → register" flow and an intermediate state of "environment exists but no DEK" |
| **B: client-assigned (adopted)** | format is acceptance policy `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` | the create request can carry the complete epoch-1 wrap set, making it **atomic**. Under E2EE only the client can fix the encryption context |
| C: name = ID | no extra field | renaming breaks the encryption context (violates CRYPTO_SPEC §3's stable-identifier requirement) |
| D: server-assigned + pre-reservation API | the two stages made explicit in the API | pays extra round-trips and server state (a reservation table) for a result equivalent to B |

### Ruling 2: consistency between rotate_epoch and environment metadata (unknown environment_id)

| Option | Content | Evaluation |
|---|---|---|
| A: reject rotate_epoch on unknown IDs | check chain acceptance against metadata | chain acceptance rules would depend on mutable server-local state, giving clients an acceptance condition they can't verify. Also races with environment deletion. Contradicts existing test vectors (rotate without registering env metadata) |
| **B: no cross-check (adopted)** | rotate is accepted on §6.4 rules alone. A rotate without matching metadata has no data-layer effect | keeps the chain self-contained. A junk rotate just burns the ID as "used" (the ID space is effectively infinite, member privileges are required, chain capacity policy bounds it) |
| C: auto-create the environment on rotate acceptance | metadata follows the chain | creates nameless environments, incompatible with bundling the complete wrap set (ruling 1) |
| D: make environment creation a chain op | single source of truth | plaintext metadata (CRYPTO_SPEC §4) need not be signed; doesn't justify consensus-rule bloat and chain-capacity consumption |

Alongside: **environment creation rejects chain-observed IDs (present in environmentEpochs)**.
This keeps the epoch at creation always 1, structurally eliminating the composite case of
"creation at epoch >1".

### Ruling 3: deletion semantics and ID reuse

| Option | Content | Evaluation |
|---|---|---|
| A: delete rows, IDs reusable | minimal implementation | since epoch / version enter the AAD, reuse could leave ciphertexts at the same AAD coordinates existing twice across generations (client caches and audit existence intervals get ambiguous) |
| **B: tombstone + no reuse (adopted)** | environment/variable rows stay with deleted_at; ciphertext and wraps are deleted immediately | structurally preserves AAD-coordinate uniqueness. Consistent with audit existence intervals (var.created–var.deleted). Tombstone growth is bounded by the row-count policy (§12-8) |
| C: logical delete only (data also kept) | restorable | "deleted but ciphertext remains" contradicts secrets-management expectations. No restore requirement exists in v1 |

### Ruling 4: which epoch and version a push may reference (CAS)

| Option | Content | Evaluation |
|---|---|---|
| **A: accept only current-epoch × latest+1 (adopted)** | mismatches return 409 with the current value | since version is part of the AAD and the server can't assign it, CAS is the only consistency mechanism. On rotation races, 409 currentEpoch lets the client fetch the new DEK → re-encrypt → retry |
| B: also accept pushes on old epochs | grace period | a removed member could write new values with a retained old DEK (a rollback-attack variant). §7's "past versions are **kept** at the epoch of their time" is about stored data, not a relaxation of new acceptance |
| C: server assigns version | simpler client | the assigned value would diverge from the declared AAD, storing undecryptable values (structurally impossible under E2EE) |
| D: head gossip instead of optimistic CAS | isomorphic to the chain | variables aren't a chain (no signatures). Introducing a head concept only adds complexity |

### Ruling 5: identifying DEK-wrap recipients and acceptance verification

| Option | Content | Evaluation |
|---|---|---|
| A: user_id only | same as HPKE info (§5) | can't detect wraps to **keys different from** the one on the chain (effectively ghost members) |
| B: enc public key only | match by key | can't cross-check against info's recipient_user_id, and distorts the index of the fetch API (addressed to self) |
| **C: strict match of both (adopted)** | user_id + enc public key must match the chain-derived member | the strongest implementation of §6.3's server side. The redundant field is only 32 bytes |

Set verification: **the first registration for (environment, epoch) must match the current member set exactly** (a miss =
recipient-missing rejection); afterwards **only appends for the deficit** (the backfill
path after add_member); **overwriting existing tuples is forbidden** (wrap contents are
unverifiable by the server, so allowing overwrites is an availability attack: "crush a valid wrap with
an undecryptable blob").
Epochs range 1–current epoch (future-addressed wraps are rejected).

### Ruling 6: EncryptedPayload wire representation

`{ suite, aad: {projectId, environmentId, epoch, variableId, version}, nonceHex,
ciphertextHex }` (lowercase hex). base64 is 25% smaller, but consistency with the chain (§6.1)
representation wins (at the 64 KiB value-size cap the difference isn't harmful). The declared AAD's
coordinate components are checked by the worker against the URL (422); state-dependent components
(epoch / version) are checked by the DO (409). **The server cannot cryptographically verify the AAD**,
so this is equality + structure checking; enforcement of context binding falls to decryption failure
(pinned by crypto test vectors).

### Ruling 7: required privileges per op (extension of the AUTH_SPEC §6 table = §12-3)

pull / list / fetch own DEK = read × reader; variable create / push / rename / delete,
environment create / rename, DEK registration = write × member; environment delete = admin × admin.
Only environment deletion requires admin because it's the sole data operation that irreversibly
erases ciphertexts of every variable and version under it (variable deletion is member — the same
level as a principal who can crush values via push).

### Ruling 8: acceptance policy (§12-8. DoS considerations were the most frequent point in the last review)

Value ciphertext 64 KiB / environments 100 (1,000 rows) / variables 1,000 (5,000 rows) / versions
1,000 / project cumulative ciphertext 1 GiB (resource protection of DO SQLite's 10 GB; freed on
deletion) / DEK wraps 10,000 per request (taken above the member-count cap the chain capacity binds,
so the exact-match requirement on first registration can't make a project unregistrable) / display
names 256 chars (Schema-enforced). None of these are consensus rules; self-hosters may raise them.

### Ruling 9: chain-mirror backfill (AUDIT_SPEC §3.4 addition)

Not needed. No DO holding chains accepted before the audit implementation exists (unreleased).
If it ever becomes necessary, design it as a rebuild procedure grounded in §1-5 (the mirror is
reconstructible).

### Ruling 10: re-evaluating Drizzle (drizzle-orm/durable-sqlite) for DO tables

**Still passed over** (session 05's judgment stands). Reasons: (1) all queries are simple key
lookups, so an ORM's gain is thin; (2) DO migrations are effectively "apply DDL in the constructor",
so a folder-format migration machinery would be surplus; (3) the Store service boundary
(same shape as ChainStore) is already established and isolation is achieved. The D1 side (db.package)
keeps Drizzle. Re-evaluation triggers: when aggregation/joins grow, or when DO schema needs
backward-compatible migrations.

### Other design decisions (mechanical, reversible)

- **Audit seq assignment**: single-statement synchronous SQL `INSERT ... SELECT COALESCE(MAX(seq),0)+1`.
  It doesn't span an await boundary, so gap-free numbering holds even outside the write lock (pull's var.read)
- **Reads also serialized under the permit** (loop 3 = changed from the original lock-free reads
  per Bugbot. See §3.5). var.read records against "the rows actually returned", so
  rows and events always match
- **authMethod added to session principals** (core's AuthenticatedPrincipal).
  To record AUDIT_SPEC §2's actor.auth_method in the payload JSON per §5.1's policy.
  Data operations carry no signature, so actor_key_fingerprint is NULL (only the chain mirror
  holds an FP)
- **Environment deletion records var.deleted for remaining variables first** (closes existence
  interval Q2. So §4.1's candidate-set computation doesn't need special handling of env.deleted)
- **AAD-coordinate self-consistency check (422) precedes membership determination (404)**: the response
  depends only on request content and carries no project-existence information, so it's compatible
  with §11-2 (stated in §12-3)

## 3. Sticking points & environment findings

- **HttpApi typed errors include `_tag` on the wire**. Assert error bodies with
  `toMatchObject` or per-field, not `toEqual`
- **`Schema.TaggedErrorClass`'s instanceof works as-is**: the DataRejection →
  typed-error mapping implemented the "drop out-of-contract (endpoint error declarations)
  rejections to defect" filter as an instanceof list (also consistent with oxlint's ban on
  direct `_tag` access). "T explicit, error-class list inferred" is reconciled with the curried
  `callProjectData<T>()({...})` form (TS can't partially apply type arguments)
- **SQLite's `ROWS` is a reserved word**. `COUNT(*) AS rows` doesn't work (renamed to total_rows)
- **`decodeHex` (crypto) returns null for the untrusted-data boundary**. Wrap it in a throwing
  wrapper (hexBytes) for pre-formatted hex in tests
- **Consolidating DO DDL into constructor application means test beforeEach doesn't have to carry
  CREATE IF NOT EXISTS around** (runInDurableObject guarantees instantiation = DDL application).
  The reset target takes src's PROJECT_DO_TABLES as its single definition, and the test side
  DELETEs by name
- **fallow again detected cyclomatic > 12 and new clones**. Resolved by extracting the audit
  INSERT's `?? null` list into a bindings-builder function and the handlers' common shape into
  callProjectData. `unused-export` also covers test-only exports (don't export what won't be used)
- vitest-pool-workers test files can use top-level await (run fixture chain signing once at
  module scope)

## 3.5 Review→fix loops (inside PR #18. 3 parallel review perspectives → fixes)

### Loop 1 adopted/fixed findings (by severity)

1. **Environment creation's complete-set requirement bypassed with empty `deks` (High. Security and
   correctness reviews detected it independently)**: the per-epoch set check (checkWrapSets) only
   looks at epochs present in the request, so `deks: []` slipped through and could create
   "an environment no one can hold a DEK for" (confirmed under real workerd behavior). Added an
   explicit check at creation that "wrap count for epoch 1 = current member count" (since recipient /
   duplicates / range are already checked, count equality = exact match). Pinned the empty-set 422
   as a negative test
2. **Crash atomicity of write sequences (Medium)**: Effect fibers yield on a macrotask every 2048 ops,
   so write sequences spanning multiple Effect.syncs (e.g. the up-to-10,000 wrap-insert loop) get split
   at task boundaries and a crash could leave a partial commit (worst case: orphan wraps with no
   environment row → recreating the same ID fails permanently with 500).
   All stores got **synchronous write functions** (DataStore.write / AuditStore.appendSync /
   ChainStore.insertSync), and each operation's write phase (data + audit) was consolidated into
   **a single Effect.sync = the same event-loop task** (DO SQLite writes commit atomically per task).
   Chain insert and mirror append were also made the same task
3. **Missing tests for the 4 chain-mirror kinds (High)**: added tests verifying row contents of
   member_removed / role_changed / server_granted / server_revoked (target_user_id /
   target_key_fingerprint / payload — the columns §4.1's Q1/Q6 depend on)
4. **The 5 quantity caps of §12-8 untested (Medium)**: pinned environments / environment-rows /
   variables / variable-rows / dek-wraps-per-request 422s (incl. resource / limit) with a
   WITH RECURSIVE row seed
5. **Contract vs implementation mismatch on check order (Medium)**: documented in AUTH_SPEC §12-3 as
   an exception that the AAD-coordinate check (422) runs before the scope check (404) (a
   self-consistency check carries no existence information), and pinned "non-member + AAD mismatch =
   422 / self-consistent = 404" in tests
6. **`env.renamed` was the only §3.3 event unverified (Medium)** → added to the lifecycle test
7. **WrappedDek's recipientUserId cap (256) is narrower than the chain consensus rule (1024 bytes)
   (Low)**: wraps addressed to legitimate on-chain members could become unregistrable, colliding with
   the first-registration exact-match requirement — aligned to 1024. Noted in §12-8 that at the
   theoretical extreme the body cap binds first
8. **Others (Low)**: added tests for variable rename duplicate-name / create-side AAD mismatch /
   ID & EncryptedPayload Schema negative cases (400). Noted in §12-8 that over-long display names
   become a Schema 400. Strengthened the audit §1-2 check to substring-based

### Loop 2 (re-verification of the fixes)

All 3 perspectives confirmed **zero findings** (the security perspective verified the equivalence of
the empty-deks fix — count equality against an already-checked set = bijection — and the absence of
remaining bypass paths; the correctness perspective verified the full migration to the synchronous
write phase — no Effect-version writes remain, no awaits inside sync blocks, and synchronous execution
of up to 10,001 statements has 3 orders of magnitude of headroom against DO CPU limits; the contract
perspective verified coverage of the 9 items and test quality). CI (check) also green. Bugbot didn't
run because the PR was a draft (will address any findings after marking ready).

### Loop 3 (Bugbot after marking the PR ready. 1 High → fixed)

- **A just-removed member could fetch values via reads outside the permit (High. Adopted & fixed)**:
  read operations (pull / list / DEK fetch / chain snapshot) ran without the permit, so there was a
  TOCTOU where a remove_member acceptance could interpose between "membership check (chain-derived) →
  data read" (could even distribute versions of values accepted **after** removal — a §11-2 violation.
  Under E2EE, decryptable leakage is limited to old-epoch values since a member removed can't receive
  new-epoch DEKs registered after removal, but new values written before §7's rotation obligation
  fall in this). **All DO operations (reads included) were serialized on the same permit**,
  linearizing authorization and data reads against chain writes. The DO is inherently
  single-threaded and the permit only closes await-boundary (crypto.subtle in chain derivation)
  interleavings, so the real impact on read performance is minor.
  This also resolved loop 1's v1-tolerated item (pull/removal interleaving) at the same time

### Findings not adopted and escalated to owner ruling → **ruled (2026-08-02. Implemented next session)**

All 3 were ruled on by the owner in real time after comparing multiple options. **Not implemented in
this PR** (handled in a separate PR. Done before CLI / Web work starts = while wire-format changes
are free):

1. **dek_wraps resource protection → adopted option B + F advance notice**: add a **row-count cap**
   on project accumulation to §12-8 (value proposed at implementation time; 3 orders of magnitude
   above realistic use, e.g. 1M rows). The DO total-storage guard (`databaseSize` threshold turned
   into a typed error — the only line of defense also covering audit_events' indefinite retention) is
   announced in the spec as a Phase 2 operational guard
2. **Poisoned-wrap attribution & repair → adopted option E as the axis with D alongside, keeping B
   (owner ruling: do the long-term front-runner E now, while unreleased)**:
   - **E**: require wrap registration to carry a client signature with the chain signing key
     (Ed25519). Attribution holds under server distrust (B's audit rows are server-managed data and
     forgeable). This is a **crypto-layer change** involving a CRYPTO_SPEC revision, so strictly
     follow the order: spec revision → test vectors first → human review of packages/crypto.
     Main ruling points: signing unit (**per-wrap**, so recipients can verify individually on
     distribution, is likely) / canonicalization of the signed payload (§2.1 LP + domain separation.
     binding suite, project, env, epoch, recipient, enc, ct) / replay handling / verification rules
     keyed on "the key at registration time"
   - **D**: an admin-only repair path of "delete wrap → re-register the deficit" (E is attribution,
     not prevention or repair. There is currently zero means of repairing a poisoned slot, and epoch
     rotation can't save that epoch's history). Deletion becomes an audit event
   - **B**: keep the `dek.registered` audit event (uniformity with the §3.3 system.
     Copy E's signer FP into it so they can be cross-checked)
3. **suite storage → adopted option D**: add a suite column to **both** variable_versions **and
   dek_wraps**, and **add suite to WrappedDek's wire form too** (closes the current gap against
   CRYPTO_SPEC §2 design principle 4 "every persistent data structure carries a suite identifier").
   The API schema stays pinned at Literal "maruhi/v1". Judgment on binding suite to epoch (the shape
   of a v2 migration) is deferred until v2 design

**PR split**: PR A (doesn't touch the crypto layer: 1-B + 3-D + 2's B/D) → PR B (crypto layer:
2-E. Natural after PR A since 3-D's suite enters the signed payload).
- ~~A pull (outside the permit) interleaving with deletion could answer "variable exists but deks is
  empty"~~ → **resolved in loop 3 (Bugbot) by serializing reads under the permit** (§3.5)

## 4. Known constraints / v1 tolerances

- **The audit-log read API is unimplemented** (intentionally out of scope). AUDIT_SPEC §6's
  view-permission model details are undecided (open item #1), so it's designed together with the
  Phase 2 audit-log UI. The current verification means is direct DO SQLite inspection only
- **AUDIT_SPEC §3.1–§3.2 (auth & org family = the D1 side) are unimplemented** (per the task's
  line-drawing. The event structure is isomorphic to §5.1, so a supplement can be an independent PR)
- **Computing what needs rotation (§4.1) and rotation.recommended / dismissed are Phase 2**.
  This round's schema and events record in a form that satisfies §4.2's query requirements
  (the Q1–Q6 indexes)
- Server-key-addressed DEK wraps for grant_server'd projects are a §12-6 revision item
  (unimplemented per CRYPTO_SPEC §9's MVP line-drawing)
- No thinning/compression of variable versions (capped at 1,000 versions. If high-frequency CI pushes
  become a measured problem, handle it via a §12-8 revision)
- `var.read` aggregation (AUDIT_SPEC open item #4) stays at the naive 1-variable-1-row (awaiting
  dogfooding measurement, per spec)

## 5. Handoff to the next session

- **After PR merge**: update the ROADMAP Phase 1 note (independent PR): "server: project DO, D1,
  HttpApi, audit log (append-only)" → done through variable-value / environment / DEK APIs and the
  audit log (project DO side)
- **Implement the 3 ruled items of §3.5** (2 PRs, A → B; details and ruling rationale in §3.5):
  do it before CLI / Web work starts (wire-format changes = last chance to add suite / signatures
  to WrappedDek for free)
- **AUDIT_SPEC's Status update (approved) is conditioned on this PR's review approval** (§0)
- When implementing the CLI (`maruhi run`): a bulk pull via `GET /projects/:id/environments/:envId/pull`
  in one shot gets the latest values + all-epoch DEKs addressed to self. Implement a retry loop of
  "re-sync → re-encrypt → retry" for EpochConflict / VersionConflict (409).
  Don't forget the transport-413 handling branch (a bare response outside the schema) (re-posted
  from session 06's handoff)
- When implementing client sync: §6.3's client-side checks (DEK wrap-target consistency, head
  gossip) are untouched. The server's recipient verification (§12-6) is only an auxiliary line;
  client verification is the main line (the defense under server distrust)
- Uncollected optional items (continuing): rate-limit design for recovery-blob retrieval
  (CRYPTO_SPEC §8). Since the endpoint itself is unimplemented, start the design at implementation
  time from "auth required + per-user fixed window (e.g. 10/hr; DO or rate-limiter binding)"
- When implementing the Web dashboard: data-write operations pass as-is with session +
  `x-maruhi-csrf: 1` (tested). The pull response's EncryptedPayload is self-describing with aad
  included, but **the client must not trust the declared AAD — build the decryption context from its
  own coordinates** (under server tampering, falling to decryption failure is the correct behavior)
