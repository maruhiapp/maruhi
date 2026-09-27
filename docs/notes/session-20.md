# Session 20 memo (the pull metadata-only mode — the last of session-11's ruled follow-up PRs)

Date: 2026-08-10. Prerequisite: started from main with PR #39 (session 19) merged.
Scope: the remaining 3 of session-11 §5's three ruled follow-up PRs
(the pull metadata-only mode. 1 = the public config endpoint done in session 19;
2 = the test-support fixture sharing done in session 17-1).
**With this, all 3 ruled follow-up PRs are complete.**

## 1. Spec (spec first — merge constitutes owner approval)

- **AUTH_SPEC §12-7**: codified an independent endpoint in the same per-environment unit as bulk pull that
  **does not return values (ciphertexts) or DEKs**. Response = the environment's latest statement + the current epoch +
  every active variable's latest `VariableMetaStatement` + deleted variables' deleted
  statements. Bundling of verification material and the obligation of client verification (§6.3) are identical to
  bulk pull, and authorization is the same level (the same §12-3 row = read × reader)
- **var.read's semantics (AUTH_SPEC §12-7 / AUDIT_SPEC §3.3)**: the recording condition is
  **the distribution of ciphertext**. Metadata-only mode records nothing —
  "do not record as read what was not read". The reason is the input purity of the
  "definitely fetched" rank in rotation-needed detection (AUDIT_SPEC §4): letting
  resolve operations that read no value into var.read overstates "fetched". The converse discipline
  (always record what was read) is carried by bulk pull's "one row per returned variable"

## 2. Design decisions

- **Wire form = an independent endpoint** `GET …/pull/metadata` (not a mode switch via a query
  parameter): the success Schema is a different shape (no value / DEK fields exist), so the
  type is simpler and more self-describing than a union response
- **Push to existing variables still uses the valued pull**: when ruling 3 was drafted
  (session-11) values were unsigned, but the authenticity series since (PR #30) introduced the
  prev chain (§4.1 = chain-signed into the signed-bytes hash of the verified latest value), so
  **prev cannot be computed without the ciphertext**. Therefore:
  - New creation: metadata resolution only → create (**var.read zero** — per the semantics)
  - Existing update: metadata resolution → valued pull (this var.read is correct as a record
    of an actual read) → push
- **Eliminating the double DEK fetch (the latter half of ruling 3)**: the create path = listMine
  exactly once. The existing path verifies and opens the DEK bundled with the valued pull and
  **does not call listMine**. Either way the fetch happens exactly once. Conflict-retry
  re-resolution prefers the in-hand DEK of the known epoch and calls listMine only when the epoch has
  advanced (the pre-existing refreshEpochState, unchanged)
- **Connection to the floor (§6.3)**: metadata-only pull gets **meta-level floor checks**
  (checkEnvironmentMetadataPull = environment / variable-meta regression / differing signed bytes for the same
  metaVersion / a verified variable gone missing / an unannounced undeletion / tombstone
  substitution). Value-level checks and rule (c) cannot be checked from a shape carrying no values
  (do not pretend to have checked). **No floor commit either** — variable floor records need the value
  digests and are not fabricated from metadata alone. The consequence: a push of only creates establishes
  no floor (establishment lags one cycle until the next valued pull / run. The floor is a SHOULD, with no
  false positives). Attack-surface implication: an attack that hides an existing variable from the resolve
  response to induce a duplicate create is detected as a missing variable (variable-omitted) once the
  floor is established
- **The `maruhi pull` command stays valued**: the default display (byte lengths) and floor
  establishment need the values. The only CLI consumer of metadata-only mode is push's resolve path

## 3. Implementation

- api-schema: `EnvironmentMetadataPullSchema` + the `pullMetadata` endpoint
- server: the `activeVariableStatements` query (the active counterpart of the deleted side),
  `pullEnvironmentMetadataProgram` (reader authorization, no audit record), a DO RPC,
  the handler. The shared prelude with valued pull was extracted into `requirePullContext`
- cli: `pullVerifiedEnvironmentMetadata` (values.ts — the verification skeleton shared with the
  valued side as `verifyAllCommon`), `checkEnvironmentMetadataPull`
  (floor-check.ts — shared as `checkFloorCommon`), and switching push's resolveTarget /
  initialState

## 4. Tests and quality

- server +2: response shape (no value fragment appears anywhere in the JSON / the distributed statements
  pass §6.3 client verification) / authorization and existence hiding (read scope 200, non-member
  404, out-of-scope 404, deleted environment 404). The audit lifecycle test wove in
  "the expected event sequence is unchanged when pull/metadata intervenes"
- cli: following the new flow (resolve = metadata, existing = one valued fetch) + 2 wire-level
  regression guards (**create must not call valued pull** / **existing push must not call
  listMine**) + rejection of deleted statements leaking into the active list + that floor-missing
  detection also fires under push's metadata resolution (floor-detection)
- fallow: the 5 new clone groups were not escaped into the baseline; resolved by factoring
  (verifyAllCommon / checkFloorCommon / requirePullContext). checkEnvironmentPull's complexity
  overflow also came under threshold in the same refactor
- `bun run check` green (924 tests)

## 5. Pitfalls and environment learnings

- **Reissuing a test's deviceToken replaces the same user's existing token**:
  using the fixture's token on subsequent requests yields 401 (measured in data.test's authorization
  test). After reissue, keep using the new token
- **vitest-pool-workers' default testTimeout of 5s flakes under load**:
  an existing test doing 13 round trips exceeded 5s once the added suite changed
  scheduling (290ms in isolation). Set testTimeout to 15s explicitly in server's vitest.config
  (boundedness for hang detection is preserved)

## 6. Out of scope (handoffs — continued from session-19)

- Human tasks when dogfooding starts: create the GitHub OAuth App +
  register client_id/secret on the verification deploy (SELF_HOSTING.md steps 5–7)
- Audit events (the D1 side of auth.*) come together with the D1 audit foundation (session-18 §3)
- The chain-append commands and the crypto test/checks organization candidate (session-17 §4)
- Deploy to Cloudflare button verification is Phase 2 (at publication)
- When the future Web dashboard shows a name listing, it should use the metadata-only mode
  (a listing that does not pollute var.read already exists on the wire)
