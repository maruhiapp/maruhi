# Session 05 memo (server-side storage of the membership log — apps/server foundation + CRYPTO_SPEC §6.4)

Date: 2026-08-02. Prerequisite: PRs #12 and #13 (packages/crypto = the E2EE core) merged.
Scope: spec addition (§6.4 size limits) + packages/core + packages/api-schema + apps/server
(project DO, chain-append API) + vitest-pool-workers tests.

## 1. What was done (commit order = layer order)

1. **spec**: §6.4 gained size limits (server acceptance policy) and project ID = genesis
   entry hash (resolving §6.1's deferred item)
2. **deps**: added effect 4.0.0-beta.102 to core / api-schema / server, fully pinned
3. **core**: mapping `CryptoResult` (kind-discriminated union) → `Data.TaggedError`
   (`fromCryptoResult` / `cryptoEffect`; the consequence of session 04's ruling (b)) + `ProjectId`
4. **api-schema**: HttpApi definitions for chain init / get / append. The ChainEntry wire
   Schema (an op-discriminated union, pinned to match crypto's `ChainEntry` at the type level) + typed errors
   (404 / 409 CAS / 409 duplicate genesis / 413 / 422 verification failure / 422 cumulative limit)
5. **server**: `ProjectChainDO` (DO SQLite append-only storage, verifyChain re-execution,
   CAS, acceptance policy, Semaphore(1) serialization) + the HttpApi worker + the authentication service boundary
6. **tests**: replayed 9 vector positives + 14 authorization negatives through the API, CAS contention,
   duplicate genesis, size / cumulative limits, the authentication boundary. All 30 (server) / root 197 PASS

## 2. Rulings (important: no real-time response from the owner was available)

Four rulings were requested via AskUserQuestion during the session, but no response came, so
**everything proceeded as "recommended option provisional progress + owner approve/reject at PR review"**. All four
avoided irreversible options (making something a consensus rule = a crypto change). Merging counts as approval.

### Ruling 1: total entry-size limit (§6.1's deferred item)

Options compared: (a) a 1 MiB acceptance policy [adopted] / (b) per-op limits (64 KiB + a grant_server
exception) / (c) a consensus rule (built into verifyChain) / (d) leave it unspecified.

Adoption rationale: §6.1's field limits (a consensus rule) **mathematically bound** the normalized size of a
spec-conformant entry to at most ~516 KiB (grant_server's maximal form = 1024 B environment IDs × 256), so
a 1 MiB acceptance policy cannot reject a spec-conformant entry = implementation divergence cannot
structurally split the chain. (c) triggers a packages/crypto change (human review + vectors first)
and only duplicates the field-limit checks — no cryptographic gain. (d) fails to answer the spec's
"to be defined additionally when §6.4 is implemented".

### Ruling 2: cumulative chain limit (a new issue separate from the deferred item)

Options compared: (a) introduce an acceptance policy (10,000 entries / 32 MiB cumulative) [adopted] /
(b) do not introduce one / (c) a consensus rule / (d) entry count only.

Adoption rationale: appends re-verify the whole chain per §6.4 (O(n) signature verification), and
member-privilege `rotate_epoch` spam opens a DoS that bloats the chain (server CPU + every client's
sync/verification cost). An acceptance policy lets future increases not affect past chains' validity.
"A long chain = invalid" is unnatural as validity semantics, so it is not made a consensus rule.

### Ruling 3: project ID and DO name resolution

Options compared: (a) genesis entry hash = project_id, DO via idFromName [adopted] /
(b) server-assigned (newUniqueId) / (c) client-generated ULID / (d) a D1 projects table.

Adoption rationale: (a) cryptographically binds the chain to the ID — a client can mechanically detect
the server substituting a different chain under the same ID just by recomputing the genesis hash
(§6.1 has no entry↔project binding, so this property can only come from the ID design).
Resubmitting an identical genesis structurally reaches the same DO and is rejected as a duplicate. No D1 needed,
so it also does not preempt org integration (AUTH_SPEC §9, deferred to the authentication session). (d) steps into out-of-scope D1.

### Ruling 4: preventing the auth stub from leaking into production

Options compared: (a) module-graph separation [adopted] / (b) env-var switching / (c) build-time define +
DCE / (d) a separate package (@maruhi/server-testing).

Adoption rationale: (a) places the stub at `apps/server/test/support/auth-stub.ts`; since wrangler's
bundle starts from `src/index.ts`, there is structurally no path for the stub to enter the production
build (unlike (b), which could be enabled by a config mistake, and (c), which is costly to verify — the guarantee is mechanical via the bundler's
module graph). The production side carries only an "explicit unauthenticated placeholder" (`unauthenticatedRequestAuth`),
which is not a stub but an honest expression of the current state.

**Known limitation (for the stub's lifetime)**: client identity claims are not trusted. The append API is
currently protected only by chain-signature verification (§6.4); the request principal is not authenticated. In the authentication session,
the SessionService / TokenService implementations get wired into `RequestAuth`.

### Other design decisions (mechanical, reversible — proceeded with the recommended option)

- **Drizzle deferred (the DO chain table)**: ADR-0006's intent is "keep the repository layer inside
  the service boundary". For a single append-only table (one SELECT + one INSERT) a migration
  generator adds nothing, and there is no reason to pull in the drizzle-orm dependency (the 1.0.0-rc line) now. Plain SQL is
  confined inside the `ChainStore` service boundary (no Drizzle types — not even SQL — escape).
  Drizzle is introduced when the D1 user / org schema lands (the authentication session); whether to
  align the DO side then is re-evaluated at that point
- **Serialization of DO mutating operations uses an Effect Semaphore(1)**: the DO input gate opens during
  non-storage awaits (crypto.subtle inside verifyChain), so leaving it to the gate would interleave appends —
  another append could slip between "verified → insert". Serialized with a Semaphore, with the seq PRIMARY KEY as
  the last line of defense
- **The 4 MiB raw HTTP body limit is an implementation detail**: the spec (§6.4) defines only the
  normalized-bytes basis (1 MiB). The raw-body limit defends against pre-JSON-parse
  memory DoS, anticipating JSON escape inflation (worst case ~6×), and returns a bare 413 outside the schema
- **Did not duplicate the §6.1 free-string limits into api-schema Schemas**: an over-limit value must always
  be reported as verifyChain's `invalid-payload` (a reason code pinned by vectors); do not build
  a second rejection path as a Schema 400. Only fixed-length hex is checked in Schema (cheap, precise)

## 3. Pitfalls and environment learnings

- **The cloudflareTest plugin (0.20.1) has no per-test storage isolation** (nothing equivalent to the old
  defineWorkersConfig's isolatedStorage exists in the source). DO SQLite carries
  over between tests in a file, so reset it explicitly in beforeEach. Moreover, the DO's
  ManagedRuntime layer is lazily built until the first method call, so the reset side must
  CREATE TABLE IF NOT EXISTS before DELETE
- **Combining workers-types with the DOM lib**: the server tsconfig uses
  `types: ["@cloudflare/workers-types", "@cloudflare/vitest-pool-workers/types"]` +
  `lib: ["ES2023", "DOM"]`. Without the DOM lib, @maruhi/crypto's source (which assumes the DOM
  SubtleCrypto overloads) fails typecheck (workers-types flattens
  exportKey's return into a union). Using them together produced no duplicate-identifier errors
- **workers-types RPC stub types distribute over union returns**: a DO method returning
  `Promise<A|B>` becomes `Promise<A>&... | Promise<B>&...` through the stub and the awaited type breaks.
  Interposed a helper (rpcCall) on the worker side that narrows back to `as Promise<T>`
- **HttpApi handler error types must match the endpoint declaration exactly**: if a handler's
  error union is even one type wider than declared, `.handle()`'s type breaks and a misleading error
  surfaces far away (toWebHandler's Context type becoming unknown, etc.). Shared mapping
  functions must narrow the return union with overloads
- **oxlint's no-underscore-dangle is active** (via the eslint-js plugin). Direct `_tag`
  access and `_`-prefixed identifiers cannot be written even in tests. Use instanceof to discriminate
- **fallow's CRAP gate trips even at cyclomatic 6** (a function with estimated 0 coverage has
  CRAP = c²+c > 30). Even a flat switch mapping must be split/shared down to ≤ 4. DO RPC
  methods look statically unreferenced, so they were suppressed with reasoned `fallow-ignore-next-line unused-class-member`
- Effect v4 beta.102: `Effect.catchAll` does not exist (catchTag / catchTags / catchCause).
  Semaphore is `Semaphore.makeUnsafe(permits)` + `withPermit` directly under `effect`

## 4. Handoff to the next session

- **After the PR merges**: update the note on ROADMAP's membership-log item (server storage and append API
  done; remaining is client sync. Do not fully check it off) ← to be handled on the post-PR-creation
  event of this session
- **Rulings 1–4 need owner approval in PR review** (see §2). On rejection,
  change the spec (the two items added to CRYPTO_SPEC §6.4 on 2026-08-02) and the implementation (apps/server/src/policy.ts,
  chain-do.ts, auth.ts) as a pair
- **Phase 0's remaining item "audit log schema design" is untouched** (an optional item this session,
  deferred for time). Draft it as a proposal document in a later session
- Unimplemented (intentionally out of scope): §6.3 client sync (DEK-wrap-destination match check, head
  gossip), the real authentication implementation (AUTH_SPEC; the wiring point into RequestAuth is prepared), audit logging,
  D1, org integration (projects.org_id), real deployment verification (a continuing item from spike-b)
- A consequence of project ID = genesis hash: when implementing client sync, include
  the check "hash(entries[0]) == projectId" in `GET chain` verification (noted in §6.4)
- Authorization (e.g. rejecting a reader's pull — §6.2's "the server authorizes data operations by chain-derived role")
  will use ChainState derivation (inside the DO) when the variable-value API is implemented. This session's chain-get API
  is fully public because there is no authentication yet (included among the known limitations)
