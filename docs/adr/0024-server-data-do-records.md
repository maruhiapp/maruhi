# ADR-0024: Server data-plane and Durable Object decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 1037 comments on the server data plane and Durable Objects were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/server/src/audit-store-query.ts`

- L1: The audit log's generic read surface (AUDIT_SPEC §7 — C1), served by AuditStore's queryEventsSync (audit-store.ts).
- L20: The **non-chain** event names of class 1 (chain role reader or above = every member) (§6).
- L64: Sealed value proposals (AUDIT_SPEC §3.3 — PF7b):
- L71: Class 1 because the setting itself is advisory-distributed to every member in pull responses (AUDIT_SPEC §3.3 — AUTH_SPEC §12-11)
- L76: Whether an event is class 1 (§6): the whole `chain.` namespace + {@link CLASS1_EVENTS}.
- L86: The visibility specification (§6). admin = every row (the caller has already confirmed "chain role admin-or-above × token scope admin"),…
- L96: The generic-read query (only the §7 filter vocabulary; null = no filter).
- L98: The paging cursor = the row_id of the last row of the previous page (§7 — opaque).
- L107: A prefix match on the event namespace (§7).
- L118: The read shape of a stored row (all §5.1 columns; NULL is null).
- L126: The wire row identifier (§5.1 row_id — 16 bytes random hex).
- L135: The WHERE condition of the visibility class (§6) (shared by this query and cursor resolution).
- L142: §6 / §7: a class-2 row behaves as if it did not exist for a sub-admin.
- L162: Cursor resolved under the viewer's visibility predicate: an invisible row's id behaves like an unknown id, no existence oracle (§7)
- L220: Aggregate var.read rows narrowed by the value's per-environment existence interval (unioned) so a deleted variable never scans all pulls
- L312: Aggregate rotation.recommended matched by payload scan with no interval narrowing: low-frequency and class 1, unlike var.read (§3.3)
- L335: The +variable_id unary-plus idiom disqualifies ae_var so the planner drives ae_event; the plan is pinned by test
- L349: Pages merge without dedup: the sources are disjoint and each page is already its source's top limit
- L379: An unknown or invisible cursor is an empty page, the same shape as the end of paging (§7)
- L387: Prefix match uses substr, never LIKE, so % and _ in the input cannot act as wildcards
- L409: Column match and aggregate queries run separately and merge: a fused OR would degrade the column match's index-ordered paging
- L420: Aggregate var.read is bound to the value-existence interval and the viewer's own rows (class 2); null = the variable never held a value

### `apps/server/src/audit-store-rotation-read.ts`

- L1: The audit log's read surface for rotation-needed detection (AUDIT_SPEC §4.1 / §4.2's Q1-Q6), served by AuditStore's readRotationSync…
- L15: The scope read out of a mirror payload (AUDIT_SPEC §3.4's scopeKind / scopeEnvironmentIds — the input of §4.1 step 2's per-environment…
- L24: Q1: the membership-interval events of the target user_id (chain.genesis / member_added / role_changed / member_removed — role_changed…
- L39: The device axis of Q1 (2026-09-19 DK — the `revoke_device` variant of AUDIT_SPEC §4.1):
- L54: Q6: the grant-interval events of a server key FP (chain.server_granted / revoked).
- L58: From a chain.server_granted payload. A revoked row is the empty array.
- L67: Q2: a variable's existence-interval events (var.created / var.deleted).
- L75: Q3: the target user_id's var.read (expansion of the aggregate form's payload — §3.3).
- L82: The seq range of Q3 (both ends are **open** — `afterSeq < seq < beforeSeq`).
- L94: Q6: a server key FP's disclosure exercises (server.lease_issued / value_decrypted [reserved]).
- L99: server.lease_issued is per-environment distribution, so null (§3.5).
- L103: One epoch transition of an environment, from the chain mirror (§4.1-5 — VH).
- L110: Q5: the input rows of flag derivation (rotation.recommended / dismissed / var.version_pushed).
- L117: The version column (var.version_pushed only — the lineage fold's key; NULL otherwise).
- L119: The epoch column: a var.version_pushed's epoch, or a rotation.recommended's exposure bound (the environment's epoch at detection — VH).
- L129: The synchronous read surface used by detection and flag derivation (indexes in §4.2 / do-schema.ts).
- L137: Every environment's epoch transitions from the chain mirror (`chain.environment_created` = epoch 1, `chain.epoch_rotated` = the new…
- L145: The same rows narrowed to the given (variable × environment) pairs (the history's flagsIfCurrent, a dismissal's live check — ae_var).
- L160: Read the payload's scopeEnvironmentIds. A broken row — not an array, or containing non-string elements — is null (a silently narrowed…
- L172: Read the scope of a mirror payload. A broken row with kind listed but a non-array id list falls to null (= the window derivation treats…
- L187: Read one Q1 row with (role, scope) attached (the payloads of member_added / role_changed in AUDIT_SPEC §3.4).
- L215: Q1: the (target_user_id, seq) index (ae_target).
- L229: The device axis of Q1 (the same ae_target index — device_added / device_revoked of AUDIT_SPEC §3.4 carry target_user_id = the subject).
- L266: Q6: the (target_key_fingerprint, seq) index (ae_target_fp)
- L285: Q2: the (event, seq) index (ae_event)
- L299: Q3: the (actor_user_id, seq) index (ae_actor).
- L336: The (a) input of Q6: the (actor_key_fingerprint, seq) index (ae_actor_fp)
- L353: Q5: the (event, seq) index (ae_event)
- L368: Q5: the aggregate rotation.recommended rows (ae_event — one row per environment, §3.3's aggregate form), each expanded to its per-pair…
- L390: Recommended rows are narrowed in SQL to the requested pairs before JS expansion instead of parsing every recommended row
- L431: RECOMMENDED_COLUMNS reads the aggregate row's fields; variable_id is NULL because the enumeration lives in the payload (§3.3)
- L437: Aggregate rows expand to per-pair rows byte-for-byte in the pre-aggregation shape so the fold is untouched; a broken payload yields nothing
- L493: Resolution rows fetched in one statement: json_each expands the pairs, DISTINCT dedups, CROSS JOIN fixes the join order

### `apps/server/src/audit-store-rows.ts`

- L1: The audit store's stored-row decoders, shared by the head derivation (audit-store.ts) and both read surfaces (audit-store-query.ts and…
- L8: The fixed 17 columns of an audit row, in the column order of AUDIT_SPEC §5.1:
- L35: payload is the stored TEXT bytes verbatim (no JSON normalization — §5.1)
- L42: A NULL-or-brand column read (the mint is the stored-row decode boundary).
- L65: Defensive parse of the payload column (JSON) (a broken row is treated as null — detection is never made a defect).

### `apps/server/src/audit-store.ts`

- L1: The audit log's append store (AUDIT_SPEC §5.1) and the AuditStore service over it.
- L39: The input of one audit-event row (columns per AUDIT_SPEC §5.1; unspecified = NULL).
- L46: The result of ensureHeadCurrent: "current" = the column has reached MAX(seq) (the head may be read); "more-remains" = hit the bounded…
- L55: A synchronous append. Called inside the same synchronous block (= the same event-loop task) as the data write, the inconsistency "the…
- L62: A bulk synchronous append of multiple events (a multi-row INSERT).
- L71: Discard the sequence cache. On a task failure the storage rolls back per task while only the in-memory sequencing stays advanced, making…
- L80: The reads for rotation-needed detection and flag derivation (§4.1; adds no append entry point).
- L82: The generic read (§7 — C1): seq-descending (newest first) + filters + visibility class.
- L89: Extend the audit-head cumulative hash column (AUDIT_SPEC §5.1 — audit_head_hashes) toward MAX(seq).
- L113: Whether the cumulative hash column is behind MAX(seq) (= whether the next ensureHeadCurrent involves materialization writes).
- L123: The current cumulative hash (empty string when there are no audit rows).
- L129: The position inside the cumulative hash column (= the audit seq; the membership check — CRYPTO_SPEC §6.4).
- L136: The audit seq of the mirror row of the previous checkpoint (chain.checkpointed — with or without notarization; the basis of the…
- L154: The placeholders of one row (seq + row_id + the 15 values of eventBindings = 17 columns).
- L157: The per-statement row count of a multi-row INSERT.
- L168: chain_seq is reserved for chain.* mirrors (AUDIT_SPEC §5.1).
- L185: The checks every row passes ahead of sequencing and SQL execution:
- L196: The stored payload: the event's payload plus a session actor's auth method (§2 / §5.1).
- L205: The insert bindings (same order as INSERT_EVENT's SELECT columns).
- L226: The options of makeAuditStore (so a test can pin a smaller bounded-extension limit).
- L228: ensureHeadCurrent's per-call chunk limit (defaults to the production value).
- L232: The AuditStore implementation (exposed separately from the Layer so tests can build it directly).
- L264: row_id = the wire row identifier (16 bytes random — AUDIT_SPEC §5.1 / §7)
- L273: Check every event ahead of the SQL so a violation in a later chunk never leaves only the earlier chunks written
- L337: Lazy extension of the audit-head cumulative hash (AUDIT_SPEC §5.1 — the implementation-shape ruling is docs/notes/session-35.md).
- L343: The rows read and written per chunk (2 columns × 50 rows = 100 bindings, inside the SQLite limit).
- L346: ensureHeadCurrent's per-call chunk limit (session 38's ruling AF).
- L360: Extend audit_head_hashes toward audit_events's MAX(seq) (up to maxChunks chunks per call — see the bounded contract in the service…
- L397: The chunk limit was reached. Settle whether rows remain with a light existence check (so a call that finished exactly at the limit does…
- L406: Hash the next chunk (up to HEAD_CHUNK_ROWS rows) and commit it in a single INSERT.
- L417: A structural invalidity on input derived from a stored row is an implementation bug (the error value carries no secrets):
- L426: The failure reason is a structural debugging label only, carrying no row content — the CryptoError kind-only discipline
- L438: One chunk loop body serves the lazy extension and the staged/restore derivation; memory stays at one chunk (ruling J rev)
- L513: Derivation requires exactly contiguous rows; a gap or refused row returns null so a replica or snapshot never installs it (ruling J r10)
- L541: A log failing the canonical form is refused (null): staging/restore treat it as untrusted input, not as a defect
- L555: The canonical row shape is stated once as SQL so every replica/snapshot row, including rows under an uploaded head column, is checked

### `apps/server/src/data.package/data-events.ts`

- L1: Module scope: audit events a data operation writes, per AUDIT_SPEC §3.3
- L15: Data events exclude chain-mirror, server-access and system-actor rows (§3.4/§3.5)
- L29: User-actor payload contract: dek.deleted carries no user payload; its cause-naming payload is the system actor's cleanup
- L54: Audit event construction per AUDIT_SPEC §3.3: auth_method rides the actor; signer FP recorded only for signed operations
- L81: DEK wrap target routing: server recipients have no user_id, so their FP goes to target_key_fingerprint, never the user-id column

### `apps/server/src/data.package/data-guards.ts`

- L1: Module scope: chain-derived role/scope guards per CRYPTO_SPEC §6.2 / AUTH_SPEC §12-3
- L27: roleAtLeast rank table is shared with invites API; do not proliferate it
- L36: Signing device resolved from the signature itself; effective permission = min(role,cap) ∩ scope (§6.2, K3)
- L52: Effective permission is the input of second-stage authorization (§6.2)
- L56: deviceOf returns undefined when FP absent; caller picks the reason code
- L76: Devices tried in ascending FP order for determinism, though result is order-independent
- L83: Only signature-invalid rejections retry with the next device; all others are final
- L103: withSigningDevice tries devices in FP order, fail-closed when all answer signature-invalid (K3-1 a-3)
- L122: Invariant: a current member holds at least one active device (§6.2 last-device-protected)
- L127: Only signature-invalid folds into try-next-device; other rejections are final
- L143: Invariant: candidates non-empty, so lastRejection is always set
- L149: Second-stage device check reuses first-stage reason codes; a device never exceeds its person (K3-1)
- L188: requireRole is stage 1 only; device stage runs after signature verification via ensureDevicePermission
- L204: Non-member gets nothing back, not even the head (§11-2); worker maps to 404
- L213: Scope check placed after role floor, before environment existence: chain-derived checks precede stored-state reads (K3-C)
- L235: requireRoleInScope is the two-stage order for ops that load the whole chain themselves
- L253: requireMemberState also returns history index and member as inputs to signature verification (§4.1/§6.4)
- L264: Member is the person; the signing device is resolved later from the signature, unsigned ops judged on person alone (K3-1)
- L274: InitializedChain type guarantees the genesis hash exists
- L280: Uninitialized vs headSeq>0-with-missing-head: the latter is storage corruption, a defect
- L299: Front stage order: initialization → derivation → membership/role floor (§12-3); derivation reuses chain API cache
- L315: Check order role → scope → existence (§9 K3-C); existence is the caller's step after this
- L340: Epoch is chain-derived with no default-to-1 fallback; active row without chain environment is a defect

### `apps/server/src/data.package/data-http.ts`

- L1: Module scope: DO rejection mapping, AAD consistency (§12-2), preliminary size check (§12-8 before semantics)
- L82: toValueInput carries verified coordinates plus state-dependent part and signature block (§4.1)
- L101: Preliminary ciphertext size check (§12-8); hex is 2 chars per byte
- L127: AAD coordinate check covers project/env/variable only; epoch/version are state-dependent, checked by the DO (§12-2)
- L140: Worker rejects coordinate mismatch early as a request-only self-consistency check, though the DO would fail verification anyway
- L162: Manifest variant of the statement coordinate check (§12-5)
- L177: toManifestInput: creation composite's narrower wire form is assignable to the general one (§12-5)
- L197: Fields copied by explicit name, not rest-spread, so wire-declared coordinates never reach stored input; satisfies pins completeness (§12-5)
- L239: maxAgeDays rides only when the wire carries it; its absence on layout 3 is verify-meta's 422 after the range check
- L247: Stored writer/statement returned as stored, not re-derived, so past data from removed writers stays verifiable (§12-2/§12-7)
- L270: Stored value → wire form; AAD rebuilt from stored coordinates (§12-2)
- L343: satisfies enforces mapping exhaustiveness while keeping a precise return type per kind; §11-2 folds uninitialized/non-member to 404
- L352: insufficient-scope maps to ForbiddenError, same layer/type as insufficient role (§9-2/§12-3)
- L361: Chain-acceptance kinds are shared by the composite request (§12-4) and the generic chain API
- L363: device-limit is the device-count acceptance policy (§12-8, DK K3)
- L365: proposal-limit is the four-eyes propose acceptance policy (§12-8, K5)
- L370: audit-head-not-ready is a retryable 503 with empty body so no count leaks (§5.1/§16-2)
- L409: activation-required: a normal push to a declared variable requires the activation composite (§12-5)
- L426: storedRecipientEncPubHex on the 409 comes from the occupying wrap's stored key (§12-6)
- L459: dataRejectionError is the single home of the per-kind mapping; chain handlers pass through it, no dual maintenance
- L474: ContractDataError excludes worker preliminary-check errors, which never arise from a DataRejection
- L486: Contract filter list is built once per endpoint because an endpoint is fixed at build time
- L503: Returnable errors derive from the endpoint contract itself, so declaration and mapping cannot drift; out-of-contract rejection becomes a defect
- L526: callProjectData is the shared §12-3 check-order path: principal → token scope → DO RPC → outcome mapping
- L560: requireProjectChainAdmin: token scope admin → memberRoleFor → chain role admin, shared by invite API and audit read

### `apps/server/src/data.package/data-plane.ts`

- L1: Module scope: RPC-boundary types are plain structured-clone-safe objects; projectIdOf mints the id from the genesis hash (§6.4)
- L16: The genesis hash IS the project id (§6.4); shared by every program/DO method naming the project
- L25: DataActor carries no key FP; the DEK wrap exception takes the signer FP in the DO from the chain member (§5.1)
- L36: Suite is the literal 'maruhi/v1' at the RPC boundary and in stored rows, pinned by the wire Schema (§2 principle 4)
- L43: DEK wrap recipient classes: member (current chain member) vs server (valid grant_server key) (§12-6)
- L49: recipientUserId position holds a user id or a server key FP by class, mirroring the HPKE info / §5.1 substitution (§9)
- L60: No signer ID rides the wire: the registration signature's signer must match the calling principal exactly (§12-6)
- L75: Wrap deletion unit is per device: slots are on the device axis (§12-6, DK)
- L85: RPC statement derives from the wire form so it cannot drift; converter copies fields by name so declared coordinates never reach the DO (§12-5)
- L102: declared status is layout-v3 only; the DO storage/verification type accepts all three values (§4.2)
- L110: varType is a closed set; empty string means unspecified (§4.2)
- L113: v3 schema fields are a present-together set; a v3 statement without maxAgeDays is refused 422 and every stored row carries it
- L130: Stored statement input: author is the calling principal by contract, so no author ID/FP is carried; DO takes it at acceptance (§12-5)
- L158: Environment statement re-types the author FP to the branded type; past statements stay verifiable after author deletion (§12-2)
- L177: No new field is added to a v1 distribution; v3 fields exist as a complete set only on v3 rows (§12-2)
- L191: Manifest input: issuer is the calling principal by contract; DO reconstructs the signed target from storage coordinates (§12-5)
- L202: epoch is the current epoch at issuance, §4.3's freshness anchor
- L208: prevManifestSigHashHex is the previous manifest's signed_bytes hash; empty string for version 1
- L212: Manifest signature is Ed25519 (§4.3)
- L216: Distributed manifest returns the stored signature block and issuer as-is for verifiability after issuer deletion (§12-2)
- L229: Value input: writer is the calling principal by contract; DO verifies state-dependent epoch/version and signature (§12-5/§4.1)
- L245: prevValueSigHashHex is the previous version's hash; empty string for version 1
- L247: chainHeadHashHex is the head the writer last verified at signing (§4.1 authorization-time binding)
- L250: Value write signature is Ed25519 (§4.1)
- L257: Environment statement is always active; a deleted environment is not listed, its deletion is a chain entry
- L267: Bulk pull returns stored writer as-is, not re-derived, so past values stay verifiable; server-recomputed hash is not distributed (§12-7)
- L290: Distributed wrap carries signature and signer info so the client can verify at distribution time (§5.1)
- L299: Wraps are per device key; a recipient opens only its own device row so an open failure is not mistaken for a poisoned wrap (§12-6)
- L314: Checkpoint snapshot entry is the distributed form (§12-7)
- L321: Snapshot supply is the atomically stored rows, never reconstructed; chainSeq/entryHash are advisory locators only (§12-7/§16-2)
- L335: Checkpoint snapshot key is legitimately absent without a baseline; the manifest is never omittable (§12-4)
- L354: Field is the environment's latest meta statement, the bundled verification material of §12-7
- L360: Deleted variables' statements keep being stored and distributed (§12-5)
- L362: declaredVariables omitted when none exist (optionalKey shape); input for manifest digest recomputation (§12-7)
- L370: schemaPolicy advisory bundle is always present (§12-7/§12-11)
- L372: Manifest is required: a missing row is an invariant violation (defect), never an omission (§12-7)
- L381: Snapshot enumeration always bundled when a basis row exists; client rule 2 rejects basis-present + enumeration-absent (§6.3)
- L391: Metadata-only pull carries no values or DEKs and records no var.read (§12-7, AUDIT §3.3)
- L402: Declared variables' statements also appear in the metadata pull; status carries the discrimination (§12-7)
- L410: Manifest is required in metadata-only mode too; meta verification completeness matches the with-values pull (§12-7)
- L416: schemaPolicy advisory bundle is always present (§12-7/§12-11)
- L420: Environment list RPC value includes the schemaPolicy advisory bundle (§12-4/§12-7)
- L426: SchemaPolicy acceptance reads the policy at acceptance time inside the DO's serialization (§12-11)

### `apps/server/src/data.package/data-rejection.ts`

- L1: Module scope: the DataRejection union is the single rejection vocabulary crossing the RPC boundary as DataOutcome (§12)
- L13: An environment's only 409 is a display-name collision; ID uniqueness is the chain consensus rule (§6.2/§12-4)
- L30: Value-signature 422 vocabulary is exactly the spec's 3 reasons (provisional ruling C) with defined semantics (§12-5)
- L44: Meta 422 adds layout-regression and unsupported-layout; unsupported-layout is not squashed into an invalid signature (ruling CR)
- L68: Attestation 422 shares the 3-vocabulary, no new code; chain-head-unknown also covers a seq ahead of the head (§16-1)
- L76: Manifest 422 shares the 3-vocabulary plus digest-recompute and epoch reasons; kept in sync with api-schema (§12-5)
- L91: Checkpoint mismatch vocabulary kept in sync with api-schema's CheckpointMismatchReasonSchema (§6.4/§16-2)
- L102: Proposal-limit reasons kept in sync with api-schema's ProposalLimitReasonSchema (§12-8, K5)
- L121: project-storage-bytes is the DO storage total guard; limit is the rejection threshold in bytes (§12-8)
- L129: insufficient-scope sits right after the role 403 and before the existence 404 (§9-2/§12-3, ES K3)
- L140: Chain-acceptance family is shared by the composite request and the generic chain API; worker maps to the chain error types
- L148: device-limit is an acceptance policy, not a consensus rule: valid devices capped at 16 at add_device acceptance (§12-8/§6.4)
- L153: proposal-limit counts pending only (expired excluded) and bounds expires_at_ms (§12-8/§6.4, K5)
- L163: Checkpoint cross-check is common to the boundary-bundled and standalone paths, with different acceptance-time bases (§6.4/§16-2)
- L172: audit-head-not-ready is returned instead of judging on a stale row when the bounded extension is unfinished (§5.1)
- L196: payload-mismatch is the composite-internal check: URL coordinate vs bundled entry payload (§12-4)
- L209: schema-policy-rejected: a creation without varType under locked policy (§12-11)
- L212: activation-required: a normal push to a declared variable requires the activation composite (§12-5)
- L214: description-rejected bounds: ≤1024 code points, no control characters (§12-8)
- L218: manifest-version-conflict returns only the latest number, not the winner's hash — same discipline as the metaVersion CAS (§12-5)
- L228: storedRecipientEncPubHex is not secret (historical keys are chain-distributed) and inputs the client's re-add decision (§12-6)
- L246: Sealed-proposal resolution folds unknown/resolved/expired into not-found; a non-newer acceptance version is version-missing (§14-5)
- L253: export-changed (409, project moved mid-export) and export-rate-limited (429 window) (§11-6, PF3)
- L258: Mirror rejections: read-only write, mark state 409, refused replication page 422 with api-schema vocabulary (§11-7, PF2)
- L273: Attestation seq regression returns the stored seq instead of silently succeeding; identical seq is an idempotent 204
- L308: DataRejectedError is the only typed error a data-plane program carries as a failure
- L316: DataOutcome crosses the RPC boundary as structured clone

### `apps/server/src/data.package/data-store-attestation-queries.ts`

- L1: Module scope: head-attestation reads and per-member fixed window, assembled into DataStoreShape (§16-1)
- L13: Attestation window semantics (judgment/consumption separation, expired = count from 0) match the lease window; key is per-member
- L79: attestationWindowRow shares the lease window's 'live window' definition

### `apps/server/src/data.package/data-store-environment-queries.ts`

- L1: Module scope: environment-side read queries, assembled into DataStoreShape by dataStoreLayer
- L61: Only live environments are listed: a deleted environment's statements are deleted with its data; clients derive deletion from the chain (§12-7)
- L109: Distribution never selects signed_bytes_hash_hex (§12-2); a verifier recomputes it, same discipline as statement distribution

### `apps/server/src/data.package/data-store-proposal-queries.ts`

- L1: Module scope: sealed-proposal reads and pending scans, assembled into DataStoreShape (§14-5)
- L12: Stored facts are a JSON array of strings written by insertProposal; anything else is storage corruption
- L21: Proposals read as head/variables/wraps with wraps in variable order; pending readers return only unexpired rows (§14-5)

### `apps/server/src/data.package/data-store-rows.ts`

- L1: Module scope: stored-row decoders shared by every query file; the service itself is data-store.ts
- L21: Every row→domain mapping goes through the checked decode layer: a bare String()/Number() passthrough would hide column typos as 'undefined'/NaN
- L33: columnValue detects a SELECT/decoder column-name mismatch as an implementation bug
- L70: SUM(CASE...) returns NULL on zero rows and is read as 0; COUNT is always a number
- L75: storedSuite: a value outside the known set is storage corruption → defect, never swallowed by a cast (§12-2)
- L87: Environment statement status is only 'active'; deletion is the chain op delete_environment, any other value is a defect (§4.2)
- L95: Write path is pinned by the Schema Literal; an unknown status is storage corruption
- L101: Variable statement status has 3 values; declared is v3 only
- L109: Stored var_type maps to the closed set; an unknown value is a defect (§4.2)
- L123: Stored required column is the signed-target 'true'/'false' representation, decoded to boolean
- L139: A v1 row decodes schema columns as all-absent; a NULL schema column on a v3 row is a write-path invariant violation (defect)
- L156: Storage contract: max_age_days is stored as the signed string, empty string means none
- L169: Meta-statement decode is shared; prefix serves latestVersions SQL aliases and the caller picks env vs variable status decode
- L197: statementOf returns the distributed form with author included; environmentId comes from the column, not the row body
- L205: v3 carried fields (§12-2): absent on v1 rows (no new field added to v1 distribution), expanded on v3 rows
- L241: variableAnchorOf exposes layoutVersion as the stored actual value
- L255: Environment meta is always layout 1
- L269: Only anchor lookups read signed_bytes_hash_hex; distribution never selects it (§12-2)
- L275: Variable statements additionally select v3 carried-field columns that do not exist on the environment side's SELECT

### `apps/server/src/data.package/data-store-settings-queries.ts`

- L1: Module scope: project-settings reads (currently only schemaPolicy), assembled into DataStoreShape (§12-11)
- L10: No settings row = default enabled; an unknown stored value is a defect, never silently re-read as the default (§12-11)

### `apps/server/src/data.package/data-store-variable-queries.ts`

- L1: Module scope: variable-side read queries, assembled into DataStoreShape by dataStoreLayer
- L84: Metadata-only mode (§12-7): latest statements only; values and DEKs are never selected because never distributed
- L106: Declared variables' statements ride the value-bearing pull (§12-7); the JOIN naturally excludes latest_version 0 rows
- L138: variables_digest recompute input (§12-5): canonical byte order is established inside crypto, not canonicalized here
- L159: declared rides along as an entry's status value; canonical form and encoder unchanged (CRYPTO_SPEC §4.3)
- L167: Checkpoint values_digest input (§6.4): canonical order established inside crypto's computeEnvValuesDigest, not here
- L193: The distributed checkpoint snapshot is the stored rows themselves (§12-7)

### `apps/server/src/data.package/data-store-version-queries.ts`

- L1: Module scope: version-side read queries (bulk pulls, history/range/anchor, ciphertext meter), assembled into DataStoreShape
- L22: signed_bytes_hash_hex is never selected, hence never distributed (§12-7/§12-2)
- L45: Distribution returns stored signature/writer as-is, never re-derived; signed_bytes_hash_hex is not selected on values or statements (§12-2)
- L84: Statement part reads the ms_* aliased columns as-is; environment ID is the WHERE argument, variable ID is the row's value
- L160: The §12-8 meter counts pending proposals' sealed values too, so ciphertext cannot be parked outside the cap in proposals
- L173: Per-environment meter uses the same join as latestVersions, so it counts exactly what a pull or lease carries (§12-8)

### `apps/server/src/data.package/data-store-wrap-queries.ts`

- L1: Module scope: wrap- and lease-side queries, assembled into DataStoreShape by dataStoreLayer
- L72: Distribution is recipient-only; the class condition is stated explicitly to pin the boundary though id shapes cannot intersect (§12-6)
- L97: Server wraps are narrowed by FP so a re-granted environment cannot grab a row addressed to the old server key (§12-6)
- L113: An expired window, a first request and a clock rewind all mean count from 0 = always allowed
- L153: GC runs first so an expired leftover of the same key cannot block a new binding via a primary-key conflict
- L167: leaseWindowRow is the single place where judgment and consumption share the 'live window' definition
- L190: selectWrapRows is the common wrap SELECT, ordered by ascending epoch
- L217: Unknown suite in a stored wrap row is a defect, never silently distributed or re-wrapped as v1 (§13-5 discipline)

### `apps/server/src/data.package/data-store-write-ops.ts`

- L1: Module scope: synchronous write functions — every write of one operation, audit included, in one synchronous block
- L12: A v1 statement stores layout_version 1 and NULL schema fields; required uses the signed-target 'true'/'false' form (§4.2)
- L24: max_age_days stores the signed string ('' = none); NULL is never written for v3 and decodes as a defect
- L42: insertStatementRow shares the column order between variable and environment; only the table name is swapped
- L89: latest_meta_version is inserted as 0 and settled to 1 by insertEnvironmentMetaStatement in the same synchronous block
- L124: Subordinate statements deleted immediately on environment deletion (§12-4): the chain entry is the deletion's only record
- L134: Manifest cascade-deleted (§12-4): a never-distributed server artifact has no residual value as detection material
- L140: Checkpoint tuple and value snapshot cascade-deleted by the same §12-4 argument
- L146: Sealed proposals deleted with the environment (§12-4): left to expire they would hold the §12-8 meter and pending limit
- L212: Only the latest manifest is kept per environment (§12-5), replaced via upsert; rows are not accumulated
- L255: Stored values_digest_hex equals the stored enumeration's hash (both tables written atomically), so a match safely skips rewrite
- L301: Checkpoint snapshot enumeration is a wholesale replacement per environment (§6.4 upsert semantics)
- L384: deleteStaleMemberWraps is atomic under the permit; recipient index dw_recipient bounds the scan to the target user's wrap rows
- L471: Minted order is the push order (companions first, CRYPTO_SPEC §5.3); position is stored because variable ids are random

### `apps/server/src/data.package/data-store.ts`

- L1: Module scope: deletion is a tombstone feeding no-ID-reuse (§12-1) while ciphertexts/wraps delete immediately; Drizzle forgone (see do-schema.ts)
- L43: latestMetaVersion is a derived cache for the metaVersion CAS
- L53: latestStatus source of truth is the statement row, read via JOIN; variable and statement rows are written in one synchronous block (§12-5)
- L65: WrapSignerInfo is stored into dek_wraps's signer_* columns
- L71: ValueWriterInfo is the chain-derived member at acceptance time, stored into writer_* columns (§4.1/§12-5)
- L81: StoredVersionMeta is metadata only, no ciphertext (§12-7, VH)
- L87: pushedAtMs is the row's created_at, the acceptance time
- L91: VersionAnchor (server-recomputed hash + epoch) is the input of the next version's prev check (§12-5)
- L101: EnvironmentCiphertextBytes: an environment's current ciphertext bytes and one variable's share (§12-8)
- L107: MetaAuthorInfo is the chain-derived member at acceptance time, stored into author_* columns (§4.2)
- L117: MetaAnchor inputs the next prev check and the post-deletion re-statement rejection; layoutVersion is the stored actual value (§12-5)
- L129: Anchor name inputs the name-preservation checks of deletion and activation (§12-5)
- L136: VariableDigestEntryRow is held structurally because data-store does not depend on crypto (§4.3)
- L148: CheckpointValueEntryRow is held structurally because data-store does not depend on crypto (§6.2)
- L159: CheckpointSnapshotInput is the coordinate part of the snapshot-saving input (§6.4/§16-2)
- L174: EnvManifestAnchor inputs the manifestVersion CAS, the prev check and the predecessor epoch-monotonicity check (§12-5)
- L186: ResourceCounts include tombstones; input of the §12-8 quantity-policy judgment
- L192: StoredWrapRecipient's enc key is the only source of the 409's storedRecipientEncPubHex; class is cross-checked on delete (§12-6)
- L204: All writes of one operation run in one synchronous block so a crash cannot partially write; verification reads happen ahead on the Effect side
- L213: insertEnvironment: name/latest_meta_version are settled by insertEnvironmentMetaStatement right after
- L215: insertEnvironmentMetaStatement also updates the environment-row cache, called in the same block on create/rename/delete
- L228: retireEnvironment tombstones plus immediately deletes all environment data; the chain entry is the deletion's record (§12-4)
- L247: insertVariableMetaStatement mirrors the environment shape: statement row plus variable-row cache update
- L256: retireVariable tombstones and deletes every version's ciphertext; the deleted statement stays
- L262: Only the latest manifest is kept per environment — no verification path needs past rows (§12-5)
- L276: Snapshot replacement is skipped when the enumeration is identical; re-checkpointing one environment never loses another's basis (§6.4)
- L293: insertVersion advances latest_version and is called under the write lock
- L303: insertWrap's signer is the chain-derived member at registration acceptance (§5.1)
- L314: deleteWrap is the §12-6 repair path; the caller has already done the existence check
- L321: deleteStaleMemberWraps never targets wraps to current chain keys; the overwrite-prohibition invariant is unchanged (§12-6)
- L334: Head attestation is per device, latest one row; monotonic seq advancement is the caller's job (§16-1, DK)
- L342: remove_member deletes all the target's attestation rows and the window row, converging storage to current members only (§6.4)
- L350: revoke_device deletes only that device's attestation row; the per-member window row is left alone (§16-1, DK)
- L359: setSchemaPolicy runs in the same synchronous block as its audit row, so the change and the row are atomic (§12-11)
- L365: insertProposal stores the proposal with variables and wraps in one synchronous block with the audit row (§14-5)
- L367: deleteProposal removes a proposal and its rows on resolution; the audit row carries the outcome
- L369: deleteExpiredProposals returns what it removed so an audit row can close each proposal (AUDIT §3.3, P-2)
- L370: The sweep spares `except`, a proposal being resolved by a member who evidently did not abandon it
- L377: RemovedProposal inputs the audit row closing its history (proposal_expired / proposal_cancelled)
- L385: expiresAtMs is the stored expiry, exact whatever the sweep's time
- L389: StaleWrapRef inputs the dek.deleted audit row for a cleanup-deleted wrap
- L395: StoredHeadAttestation excludes accepted_at: stored but never distributed, so absent from the type from the start (§16-1)
- L420: listEnvironmentStatements includes deleted environments, for the environment-list response
- L424: environmentStatement: a missing row is an invariant violation, returned as null
- L428: environmentMetaAnchor is the input of the prev check (§12-5 meta rules)
- L433: environmentManifest: null cannot happen on a created environment, which bundles manifest_version 1
- L442: environmentManifestAnchor inputs the manifestVersion CAS (6) and prev check (5); epoch feeds epoch-monotonicity (§12-5)
- L464: variableMetaAnchor is the input of the prev check (§12-5 meta rules)
- L470: deletedVariableStatements keep being distributed on pull (§12-5)
- L474: activeVariableStatements serves the metadata-only mode (§12-7), declared included
- L481: declaredVariableStatements is bundled material of a value-bearing pull / lease; no value or version exists (§12-7)
- L489: variableDigestEntries recompute CRYPTO_SPEC §4.3's variables_digest; metaSigHashHex is the server-recomputed hash (§12-5)
- L498: checkpointValueEntries exclude tombstones (active variables only, §6.2); the manifest side captures the tombstones
- L508: checkpointSnapshot returns the atomically saved tuple as-is, never reconstructed (§16-2); no basis = null
- L525: versionHistory is metadata only, ascending; no ciphertext is selected (§12-7, VH)
- L533: versionRange distributes the same columns as the bulk pull's value part (§12-7, VH)
- L544: versionAnchor is the input of the prev check (§12-5's 5)
- L550: totalCiphertextBytes is the amount currently stored (§12-8)
- L552: environmentCiphertextBytes counts latest versions of active variables; a variable with none contributes 0 (§12-8)
- L566: countWrapRows is the amount currently stored (§12-8)
- L568: The stored class is cross-checked on delete; the client-declared class is never used verbatim to pick the audit column (§12-6)
- L576: listWrapSlots inputs the uniqueness judgment when a delete reference omits the device key (§8 K3-3)
- L598: listServerWraps is kept separate from distribution: server unwrap material never goes out on a response (§14/§9.1)
- L612: Lease window judgment and consumption are separated: a window may be consumed only when an issuance was actually made (§14-3)
- L624: recordLeaseWindowUse is serialized under the DO permit, so nothing interposes between judgment and consumption
- L630: isMirrorSync is asked after a program's own authorization (existence concealment first); write entry points are guarded in chain-do.ts (§11-7)
- L638: leaseBinding correctness is detached from GC timing: expired rows are ignored by the expires_at condition (§14-1)
- L649: recordLeaseBinding does not overwrite an idempotent retry row; it also GCs expired rows (§14-1)
- L662: schemaPolicy is read per program under the DO permit — the policy at acceptance time (§12-11)
- L668: headAttestationSeq inputs the monotonic-advance check; null when none was submitted (§16-1)
- L673: listHeadAttestations narrowing to current members is the caller's job; distribution keeps a defensive layer in case remove missed a row (§6.4)
- L681: Attestation window judgment only, does not consume — same separation discipline as checkLeaseWindow
- L691: Consume is serialized under the permit so nothing interposes between judgment and consumption
- L694: Pending = stored and unexpired; resolution deletes rows, and expiry is judged by expires_at without depending on the sweep
- L702: findProposal returns expired-but-unswept rows because a resolution can reach them (§14-5)
- L706: variableHasPendingProposal backs the pre-flight's variable-pending refusal (§14-5 O-4)
- L716: Fixed-window kinds map to §14-3 issuance and AUDIT_SPEC §3.5 denial records
- L717: proposed is the sealed-proposal mint window with its own counter beside issuance (§14-5)
- L720: On excess the window decision returns remaining seconds, same shape as the §13-3 precedent
- L726: A proposal wrap is sealed to one recipient device (a stored row — §14-5)
- L740: StoredProposal is one stored sealed proposal with its variables and wraps (CRYPTO_SPEC §5.3)
- L753: ProposalWriteInput is what the mint program hands the store: wire proposal plus the lease's attribution

### `apps/server/src/data.package/index.ts`

- L1: data.package public surface: only the data plane's shared vocabulary is re-exported; store query modules stay internal

### `apps/server/src/data.package/verify-manifest.ts`

- L1: Manifest acceptance is full server-side verification (meta is plaintext, no E2EE constraint) incl. digest recomputation (§12-5)
- L50: Manifest reason mapping: 3 vocabularies shared with values/meta plus 2 manifest-specific; exhaustiveness enforced by Record
- L64: Issuer out of scope at declared head maps to chain-head-state-mismatch (§6.3 rule 3-prime, same class as role insufficiency)
- L69: A forward manifestVersion with a stale epoch (epoch regression) is rejected as manifest-epoch-mismatch (§12-5)
- L77: Checkpoint binding check uniquely owns the composite's bundled-payload tuple/manifest hash match (§6.4 split unified here)
- L87: Digest entries are built from the post-acceptance meta state, tombstones included, with server-recomputed hashes (§4.3)
- L119: Missing stored env meta statement is an invariant violation = defect (env row and statement are created atomically)
- L143: Non-composite meta ops share manifest acceptance (§12-5) plus a write-phase closure; digestOverride carries the applied statement
- L179: writeSync runs inside the write phase's single Effect.sync — the latest-only manifest upsert (§12-8)
- L196: history is the acceptance-time chain for meta ops but the post-bundled-entry index for composites (§12-5 (4) basis)
- L211: Crypto composite verification covers §12-5 (1)-(4),(7); predecessor is undefined only at environment creation
- L231: Manifest coordinates are reconstructed from server-side values, never assembled from wire-declared values (§12-5)
- L242: issuer = the caller (§12-5 (1)); bound-key match at head time is checked via the FP by verifyDistributedEnvManifest
- L263: Other crypto error kinds are unreachable with a validated wire shape and chain-derived keys = defect; errors carry no secrets
- L291: A created environment always has a stored manifest (§12-4 atomic write), so a missing row is a defect, never accepted as v1
- L309: Manifest CAS (§12-5 (6)): only declared == latest + 1
- L322: Creation form is the sole point where the CAS initial value 0 exists; a stored row for a just-created env is a defect

### `apps/server/src/data.package/verify-meta.ts`

- L1: Module scope: server-side meta statement verification (§12-5 meta rules = CRYPTO_SPEC §4.2 / §6.4)
- L25: Meta reason mapping follows provisional ruling C; only layout-regression gets an independent code (spec names it explicitly)
- L40: Author out of scope at declared head maps to chain-head-state-mismatch (§6.3 rule 3-prime)
- L45: Layout v3 transition declared-after-active folds into state-mismatch; the spec gives no dedicated error name
- L48: Layout monotonicity gets its own reason because the spec states the error name explicitly (§12-5)
- L52: The required boolean to true/false mapping lives in this one place; max_age_days is the §4.2 LP representation
- L73: A v3 statement without maxAgeDays is refused as payload-mismatch before the signature, keeping the honest wording (§12-5)
- L85: Meta acceptance checks signature against the chain-derived caller key and author = caller (§12-5 items 1-3 + prev chain)
- L135: The layout carrier field (§12-2, omitted = 1) selects which layout's signed_bytes to recompute (ruling CR)
- L141: author = the calling principal (§12-5 item 1); bound-key match checked via FP by verifyDistributedMetaStatement
- L159: Unsupported layout is a fail-closed second line of defense: a 422, never a defect indistinguishable from a 500 (ruling CR)
- L168: Other crypto error kinds are unreachable with a validated wire shape and chain-derived keys = defect; no secrets in errors
- L195: Server only checks NFC and never normalizes: byte-exact signatures require the client to normalize before signing (§12-1)
- L203: A statement's effective layout: wire convention omitted = 1 (§12-2)
- L209: Layout support-range check runs before every other acceptance check; earlier schema errors would be misleading (ruling CR)
- L228: Description policy (§12-8): NFC not required (not an identifier, never matched) — an intentional difference from names
- L247: The description limit counts Unicode code points, not UTF-16 code units (§12-8)
- L254: Each route fixes the lifecycle operation, and it selects the predecessor-match rule
- L265: Delete statements must match the previous statement byte-exactly; crypto intentionally does not check this (§12-5)
- L276: A deleted statement's name preserves the previous active name (§4.2)
- L284: Layout already matched at this point: only the both-v1 case (no schema fields) reaches here
- L299: Predecessor checks run only after the metaVersion CAS: a stale-view statement is a 409, never a 422 (§12-5 check order)
- L334: Meta CAS (§12-5): only declared == latest + 1; the 409 returns the latest number only
- L359: Meta acceptance pipeline order is pinned: bound, CAS, predecessor fetch, predecessor match, description policy, signature
- L384: The support-range check runs first (see ensureSupportedLayout — ruling CR)
- L404: Description policy does not apply to deletes: byte-exact preservation governs, and limits must never block deletion (§12-8)
- L420: The anchor's stored layout_version feeds the monotonicity check; MetaPredecessor.layoutVersion is mandatory fail-closed

### `apps/server/src/data.package/verify-value.ts`

- L1: Module scope: server-side value signature verification and the (epoch, version) CAS (§12-5 = CRYPTO_SPEC §4.1 / §6.4)
- L27: Value CAS (§12-5): only the current epoch x latest + 1
- L54: chain-head-future folds into chain-head-unknown on the server (no client resync branch exists server-side; ruling C)
- L71: Writer out of scope at declared head is the head-state mismatch class; a caller-scope 403 is K3 (§6.3 rule 3-prime)
- L82: Value signature check order is after the CAS and before the quantity policy (session-14 ruling D)
- L124: Post-CAS the predecessor always exists; absence is a storage/implementation bug = defect; version 1 has no predecessor
- L155: writer = the caller (§12-5 item 1); bound-key match checked via FP by verifyDistributedValue
- L174: Other crypto error kinds are unreachable with a validated wire shape and chain-derived keys = defect; no secrets in errors

### `apps/server/src/db.package/import.ts`

- L1: Import provisioning must make D1 look as if every member had logged in here, with users rows carrying the chain's user id (PF3)
- L47: genesisHash is the hash the DO was restored under
- L72: project is created on first import, kept on a re-run (which provisions only the missing members)
- L77: ImportClassification is the read-only verdict used as a job's pre-check and as provisioning's first step
- L84: project absent = first import; exporter = the projects row sits under the exporter's personal org (a re-run)
- L88: personalOrgSlug reproduces the slug first login assigns in identities.ts createUserBatch
- L93: IN chunk sized inside D1's bound-parameter cap with headroom, same width as identities.ts identitiesOf
- L104: classify is read-only: existing, to-create, or conflict per identity against the deployment
- L152: A person who logged in here before with a different id cannot be bound to the chain's id now: identity-conflict
- L160: The chain's id held by someone else on this deployment refuses as user-id-taken
- L182: existingPersonalOrg finds the exporter's personal org by the slug first login assigned
- L199: A repeated id inside the file is a malformed companion, not a conflict with this deployment
- L207: classifyImportedProject runs before the DO is touched (ruling H revision) and doubles as a drill rehearsal report
- L217: A project row under any chain owner's personal org counts as a re-run (ruling I revision)
- L232: A chain owner's own project row is a re-run (provision missing members only); anyone else's row refuses as project-exists
- L245: provisionImportedProject writes in one batch; a second run provisions only what is missing (ruling I revision)
- L263: This plain-async entry point provides the composed crypto-services layer itself rather than threading it through the signature
- L298: Import writes the same audit rows first login writes, marked as an import; provider id and login are never recorded (§3.1/§3.2)

### `apps/server/src/dek-wraps.ts`

- L58: Duplicate-detection key mirrors the stored row's primary key (class-agnostic) so a duplicate fails as 422, never a PK violation (A-1)
- L84: Expected wrap count is |R(E)| from @maruhi/crypto's single definition (CRYPTO_SPEC §6.2), shared by registration and composite checks
- L117: Recipient identification per class (§12-6): member = live device key + effective scope; server = grant match + disclosure scope; ghost countermeasure
- L160: The recipient key must be one of the member's live device keys (R(E) device expansion); a revoked or unregistered key does not match (§12-6)
- L185: Self-backfill checks id + key: id alone would mistake a wrap addressed to someone else's key for one's own (§12-3)
- L221: Duplicate detection is class-agnostic at storage granularity: cross-class duplicates cannot coexist as stored rows either
- L271: The signer must be the calling principal (§12-6); reattribution via a key-duplicated member is caught here as an independent layer (§5.1)
- L281: Every crypto failure, including InvalidInput, folds into signature-rejected on a Schema-validated wire
- L287: importSignerKey failure is a storage / verifier bug = defect, not a rejection
- L291: Import relies on WebCrypto raw Ed25519 import checking length only; if the runtime adds point validation, bad-key members self-harm only
- L304: The verification key is the caller's chain-derived sig key at acceptance time; the device resolves on the first wrap, the rest use that key (§12-6)
- L340: Initial registration requires an exact count match against R(E); appending to an existing epoch rejects duplicates of existing wraps (§12-6)
- L366: Existence check at storage-key granularity: an identical (ID, key) in another class would still collide on insert, so it fails as 409 here
- L377: The occupying wrap's stored key is returned; under the device-axis PK its role shrinks to the idempotency decision, wire unchanged (K3-3)
- L394: Every wrap-insertion path passes through this one check, so the limit and signature requirement are wired once; signature verification runs last
- L425: dek.registered writes one row per recipient (§3.3); server recipients use target_key_fingerprint, never the user_id column (§3.4)

### `apps/server/src/do/chain-accept.ts`

- L1: Shared implementation of chain-entry acceptance (CRYPTO_SPEC §6.4).
- L57: Acceptance policy (§6.4): caps on the whole chain's entry count and cumulative byte count.
- L90: CAS (§6.4): if the parent head does not match the current head, reject with the current head's information (the worker maps this to a 409).
- L113: Acceptance check (size → capacity → §6.4's full-chain re-verification = prev_hash continuity, signatures, consensus rules).
- L135: Acceptance check for the composite's 2 entries (AUTH_SPEC §12-4:
- L206: The proposal a completed approve applied (the inner op and the proposal entry's seq).
- L218: The proposal index of the post-acceptance chain (including the accepted entry) — the input to AUDIT_SPEC §3.4's approve / withdraw rows…
- L228: entryHashAt is a method on the index object (this-bound), so it is wrapped in an argument
- L236: The empty index for paths that carry only non-proposable ops (the composite's create / rotate + boundary checkpoint).
- L239: Inserts the accepted entry + §3.4 audit mirror + per-op acceptance side effects (synchronous).
- L284: The application row has already been written as the mirror's second row (chainMirrorEvents).
- L293: Inserts the composite's 2 entries (H+1 / H+2 — already through verifyAcceptableEntryPair) + mirror + side effects (synchronous, in seq…
- L321: Per-op acceptance side effects (after the mirror append, inside the same task).

### `apps/server/src/do/chain-commit.ts`

- L1: Shared write phase that records §3.4 mirror events alongside acceptance of a chain append (generic append = programs-chain.ts /…
- L25: Atomic commit of an accepted entry. `chain` is the stored chain before acceptance (the sequence with the accepted entry appended is the…
- L34: The device FP carried by `add_device` (CRYPTO_SPEC §3 — first 16 bytes of SHA-256 over enc ‖ sig).
- L41: The payload already passed verifyChain (lowercase hex, 64 chars), so decode / computation succeed.
- L62: Acceptance side effects (chain-accept.ts):
- L68: add_device's mirror row (AUDIT_SPEC §3.4) needs the carried device's FP.

### `apps/server/src/do/chain-do.ts`

- L1: The project DO: colocates the append-only membership-chain storage (CRYPTO_SPEC §6.4), the data plane (environments, variables,…
- L300: Serialization of all operations (writes + reads) — see the header comment
- L302: Cache of the chain-derived state + the parsed chain (see chain-store.ts)
- L304: Issued leases' heads awaiting their chain read (lease-chain-grants.ts)
- L306: Whether this DO's tables exist. A fresh DO holds no storage until a genesis is accepted (Sc-7 / A-4, owner approval 2026-10-11 —…
- L325: Read-only detection (creates nothing). A materialized DO applies any pending migration steps and re-asserts its triggers (the catch-up…
- L338: The measurement point of the DO storage total guard (AUTH_SPEC §12-8 — storage-guard.ts).
- L342: Lease unsealing + re-wrapping happen inside the DO (the head of programs-lease.ts:
- L350: Effect logs from DO programs go to console.warn / console.error with the message text only (server-logger.ts)
- L357: Invalidation of instance memory on task failure.
- L387: Whether this DO's tables exist, re-checking storage when the cached flag is `false` and latching it `true` on the way (read-only —…
- L405: Run a data-plane program folded into an outcome under the permit.
- L412: An unmaterialized DO holds no tables (Sc-7 / A-4):
- L425: A mirror accepts no write (AUTH_SPEC §11-7 ruling B):
- L442: {@link #runData} for the write entry points:
- L467: Rejections (DataRejected) fold into the same rejected shape as toDataOutcome.
- L478: The genesis committed and the tables were materialized (initProgram):
- L556: Composite acceptance (§12-4): the chain append (CAS + verifyChain) and the data registration are made atomic in the same permit and the…
- L605: Composite acceptance (§12-4 — 2026-10-07):
- L626: The version-1 value of an active creation.
- L648: The activation composite (§12-5): declared → active as the atomic acceptance of value version 1 + the statement + the manifest
- L676: The version history (§12-7 — VH): metadata only, no var.read
- L689: The version value range (§12-7 — VH): records var.read
- L820: The workload mint (programs-proposal.ts).
- L853: The mint's pre-flight (AUTH_SPEC §14-5 O-4 — programs-proposal.ts):
- L961: Lease authorization, unsealing, re-wrap, and audit (programs-lease.ts).
- L1002: The chain half of a lease (programs-lease.ts — §14-2), so the chain and the values each get their own RPC result.
- L1015: A token miss is checked before the defect guard:
- L1026: Ops RPC (hosted-ops.md §2-D / §2-E; not callable over HTTP)
- L1028: The DO → R2 evacuation (hosted-ops.md §2-D):
- L1038: A never-materialized DO has nothing to evacuate (Sc-7 / A-4).
- L1059: Restore from an evacuation (under the permit).
- L1080: restoreProgram may have materialized the tables (Sc-7 / A-4) before the outcome resolved — a committed restore whose post-commit head…

### `apps/server/src/do/chain-store.ts`

- L1: Shared parts of the project DO's chain storage (ChainStore) and derived state (ChainState).
- L24: 0 = uninitialized
- L27: Hash of the genesis entry = the project ID (CRYPTO_SPEC §6.4).
- L34: Synchronous insert. Called in the same synchronous block as the audit mirror's append (audit-store.ts) so the chain insert and the…
- L45: Differential load (only rows after the cached head).
- L58: Decodes one stored `entry_json` row through the shared wire schema (the same transport shape the API boundary enforces — the…
- L96: The empty chain (the base of a differential load when the cache is invalid = a full load).
- L105: Concatenate the cached prefix with the newly loaded rows (append-only, so a diff concat = a full load).
- L117: A never-materialized DO has no tables (AUTH_SPEC §14-3 / §11-3 — the tables are created only at genesis acceptance; Sc-7 / A-4).
- L125: An invalid cache (e.g. right after a DO restart) makes the differential load off the empty base = a full load
- L147: Incremental reflection of an accepted append into the cache.
- L166: The pair of a verified chain's derived state and history index (CRYPTO_SPEC §6.3 / §4.1).
- L178: Lifts verifyChainWithHistory into Effect; failures other than ChainInvalid (contractually impossible) become defects.
- L186: verifyChain contractually returns only ChainInvalid; anything else is an implementation bug
- L209: The length of the canonical byte string.
- L221: Cache of the chain-derived state + history index (DO instance memory).
- L240: Cache updates carry a monotonic guard on headSeq (the chain is append-only, so a headSeq comparison suffices).
- L253: Derives the verified view (state + history index) from a stored chain.

### `apps/server/src/do/do-mirror.ts`

- L1: Mirror state and replication inside the project DO (AUTH_SPEC §11-7 — PF2, docs/notes/pf2-design.md rulings A / D / G).
- L95: Snapshot tables a replication never replaces:
- L113: Where the mirror's own audit rows wait during the swap (dropped afterwards; never exported — not in `tables`).
- L116: Where the staged replica's trailer waits between the trailer page and the commit.
- L124: expectedSequence: 0 means no replication in progress
- L128: lastSyncedAtMs null = never replicated since the mark; the position is then the mark's bootstrap
- L132: lastAuditSeq: the replica's audit seq at the last replication; rows past it are the mirror's own
- L159: remarkMirror: staging dropped, chain position kept, audit position resets to 0 — a seq floor compares one source's log only (ruling C rev)
- L188: markMirror: audit position starts at 0; the first replica is accepted at any seq; uncarried rows are re-appended, never replaced (C r5)
- L225: discardMirrorStaging applies to every refusal but the sequence one
- L246: Inside transactionSync the refusal is still thrown (the throw rolls the page back); the boundary catch is the only instanceof site
- L325: Column names are embedded as identifiers: only the live table's own list passes (the restore's rule)
- L329: The staging table takes the live table's column affinities: a typeless column made prefix checks scan the staged log per live row (ruling J r8)
- L421: A non-integer staged max seq means a replica that is not what the server writes = malformed
- L438: Staged log must be exactly seq 1..N and head column 1..M with M ≤ N: a gapped log once poisoned every later page, read and export (ruling J r9)
- L475: The staged chain must extend the live chain: every live entry at the same seq with the same hash, the head not behind (ruling D)
- L497: The source's first-come bindings merge into the mirror's own, never replacing one (ruling D rev): a bound token cannot rebind on the mirror
- L522: Past the replicated position the served heads are the mirror's own derivation; rows up to it were verified identical, so their heads are kept
- L542: A deployment-local table keeps its rows; the merged table takes the source's live bindings and drops the expired of either side (ruling D r3)
- L546: Only live bindings are merged and the mirror's own expired ones dropped: a mirror that never issues a lease has no other collection here
- L572: Trailer checks run inside the page's transaction; then the trailer is parked and the position advanced, so a retry is out of sequence
- L587: Every staged row's numbers are checked against the canonical form: rows under an uploaded head column are never derived over (round 11)
- L600: The replica's log must extend the last replicated one row for row; the carried hash column is an uploaded value and proves nothing (ruling J r7)
- L620: A staged head differing from the mirror's own derivation at or below the position is audit-not-extension (ruling J rev r8)
- L674: Append-only projection rows must be present identically in the staged replica; the only removals are deletion cascades via the exempt predicate
- L725: Projection counters, manifests and checkpoints may only advance; a mirror takes no data-plane writes, so a replica behind them is malformed
- L764: An environment row is never removed (deletion tombstones it); a variable row only by its environment's cascade
- L810: Manifest regression: version and epoch may only advance; at the live version an equal signed-bytes hash is the whole manifest
- L841: At an equal values digest the staged checkpoint enumeration must equal the live one exactly in both directions; both are written atomically
- L882: The enumeration check is exact in both directions: the one-directional form let an extra staged row poison the next checkpoint's cross-check
- L948: Unparseable staged entries are skipped and mark the anchors incomplete: content verification refuses such chains before any commit
- L975: add_member entries anchor the stale-wrap sweep: chain-accept runs deleteStaleMemberWraps at every add_member acceptance
- L1003: ANCHORS_IGNORED_OPS is the closed chain-op union minus the ops the anchors read; an op outside both sets cannot verify
- L1091: Only direct membership entries are credited: a proposal's completion is verifyChain's quorum judgment, so proposal-caused removals stay unexcused
- L1273: Staged projections are bound to the staged chain (checkpoints, manifests, tombstones, wraps, attestations); digests are a stated residual
- L1358: Anchored checks defer on unconsumable entries rather than pre-empting the content verification's own malformed / chain-invalid refusal
- L1444: Manifest version equals the staged statement-set size: creation writes statement 1 with manifest 1; each meta statement or rotation adds exactly one
- L1490: A chain-live environment always carries its manifest: the creation and rotation composites write it atomically with the chain entry
- L1544: Live wraps are preserved row for row, excused only by delete_environment or a direct add_member stale sweep; repair deletions are not excused
- L1641: Attestations upsert per device, advancing monotonically; a missing live row is excused only by a direct remove_member / revoke_device
- L1733: State no chain entry carries folds from the staged audit log: policy rows chain predecessor to successor; every mint gets exactly one closing row
- L1816: project_settings and sealed rotation proposals have no chain anchor; the prefix-bound staged audit log is the strongest remaining anchor
- L1906: With no staged audit log there is no mint to bind to: a staged proposal is admitted only as the live row itself (exact preservation)
- L1938: No staged variable or wrap row may hang off a proposal the replica does not carry: the store inserts and deletes the three tables together
- L1959: A staged row absent from the live table is admitted only under a mint-bound proposal, and only when a staged log exists to bind it
- L1987: Derivation start head: the mirror's own column at the replicated position, or (first replica) the staged column's tail as an uploaded claim
- L2011: Heads are derived before the swap (ruling J rev r10): a refused row or a gap is malformed with the live log untouched
- L2032: A replica without the head column is derived from seq 1 into a created staged column: an absent column once installed empty, unchecked (r11)
- L2105: The commit is its own transaction after chain verification; a live-schema constraint refusal rolls it back and is malformed
- L2123: Rows the replica carries by wire row id are excluded from re-append: re-appending them would collide on the row id (§7 C1, ruling J r4)
- L2132: A carried row must be the mirror's own row byte for byte (seq may differ): the replica cannot rewrite witnessed evidence under the same row id
- L2192: Inside transactionSync the refusal is a throw (it rolls the swap back); any other throw is SQLite refusing the replica's rows = also malformed
- L2201: toMirrorRefusal is the only place an instanceof may remain; the restore reader's other codes cannot arise here
- L2233: stageMirrorPage fails with MirrorPageRefusedError; any other throw is a defect, the transaction rolled back either way

### `apps/server/src/do/do-schema.ts`

- L1: Table definitions and migration mechanism for the project DO (SQLite).
- L21: The current schema (version 9: the base step — the migration history was squashed into it on 2026-10-06, owner-approved, the same move…
- L32: name / latest_meta_version are derived caches of the latest statement (*_meta_statements) — used for the name-uniqueness query and the…
- L53: Metadata statements (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5):
- L107: The suite column: every persistent data structure carries a suite identifier (CRYPTO_SPEC §2 design principle 4 / AUTH_SPEC §12-2 — lets…
- L137: DEK wraps (AUTH_SPEC §12-6). A slot = (environment, epoch, recipient, recipient's device enc public key) — one slot per device of the…
- L162: Recipient index: the §12-6 cleanup at re-add acceptance (deleteStaleMemberWraps in data-store-write-ops.ts) queries by…
- L167: The AUDIT_SPEC §5.1 schema. row_id is the wire row identifier (16-byte random hex — §7 ruling C1:
- L193: The target / key-FP indexes are partial indexes (audit-log growth-density measure 1):
- L201: Fixed-window counters for workload leases (AUTH_SPEC §14-3 / AUDIT_SPEC §3.5).
- L211: First-come bindings for workload leases (the AUTH_SPEC §14-1 ruling — docs/notes/session-24.md).
- L228: Environment manifests (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5).
- L251: Checkpoint value snapshots (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2).
- L274: Computed columns of the audit head's cumulative hash (AUDIT_SPEC §5.1).
- L287: Head attestations (CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1).
- L310: Project settings (one row). No row = schemaPolicy 'enabled' (the default — AUTH_SPEC §12-11).
- L317: Sealed value proposals (2026-10-02 — PF7b, CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5):
- L351: The mirror mark and the replication position of a project that is a read replica of a source deployment (2026-10-02 — PF2 mirrors,…
- L376: The deployment-local mutation counter a paged export binds its cursor to (2026-10-02 — PF3 ruling C revision, AUTH_SPEC §11-6).
- L388: A single ordered migration step for the project DO's SQLite schema.
- L399: The project DO's migration plan: one `base` step that builds the schema as of `baseVersion` directly (applying it records…
- L415: The tables the base declares (PROJECT_DO_TABLES is derived from it).
- L439: The migration plan: the squashed `base` step below builds the version-9 schema directly, so a fresh DO reaches 9 in one step and a DO…
- L461: The mutation triggers on every declared table that isMutationTracked:
- L481: The audit write trigger (ruling C revision, round 6 / ruling J revision, round 6):
- L504: The base step's audit trigger (also re-asserted at every open — {@link ensureAuditWriteTrigger}).
- L513: The trigger's deny list is baked into its SQL at apply time, so the trigger is re-created whenever its stored text no longer names the list
- L526: SQLite stores trigger text verbatim from the name on, so the whole text is compared; any drift re-creates it (ruling C rev r8)
- L539: Read-appended audit rows do not restart an export (the export bounds the log by seq); every other audit row moves the mutation counter (§3.3)
- L553: Mutation-untracked tables: the audit log (its own trigger), its hash column, ruling C drift tables, local state tables, the migration meta row
- L587: schema_meta is intentionally excluded from PROJECT_DO_TABLES: the applied-version row must survive test resets
- L599: Deployment-local tables are never exported, restored or replicated; a mirror keeps them across a sync (§11-7)
- L611: The materialization probe is read-only and creates nothing, so probing an arbitrary project ID leaves no storage behind (§14-3 / §11-3)
- L636: A corrupt schema version fails explicitly for human investigation: treating it as 0 or lower would re-run non-idempotent steps
- L645: Migrations refuse a stored version newer than this deployment: after a rollback deploy the old code cannot know the newer schema's shape
- L665: Rollback deploys really happen self-hosted: forward-only is an intentional consistency-over-availability choice; the throw fires in the constructor
- L678: A version below the base is corrupt and fails closed, like the corrupt read path
- L708: ensureProjectDoTables runs at genesis, on restore, and in the constructor catch-up; a never-initialized DO is never passed here (Sc-7 / A-4)

### `apps/server/src/do/do-snapshot-export.ts`

- L223: Chunk emission stops after the row crossing maxBytes: a row is up to 64 KiB of hex and a whole chunk past the bound would be tens of MiB
- L238: The audit log is exported up to the mark: rows past it are reads and leases served during the export and belong to the next export
- L271: A page ends after the line crossing maxBytes or at maxRows (never more than one line past); the trailer rides the last page while the bound has room
- L282: A cursor past the table order (another server's, or a forged one) is treated like a changed project: the client starts over
- L310: The trailer describes the exported state (the cursor's marks and bound), never the live one

### `apps/server/src/do/do-snapshot-restore.ts`

- L31: CHAIN_STAGING_TABLE is not listed in tables, so it never appears in evacuations; leftovers are dropped at the next restore
- L37: Restore refusal reasons are static codes, safe to put in result files and logs
- L51: Inside transactionSync and the stream loop the refusal is thrown (rolls back, stops the read); the boundary catch is the only instanceof
- L69: storesAuditHeads is asked before each chunk: false = hash and check but store no further head (the storage guard's line, §11-7 / §12-8)
- L111: A non-JSON or unknown-shape line is a corrupted evacuation; the reason folds into a static code and the body is not carried
- L120: toRestoreRefusal is the only place an instanceof may remain; any other throw is a defect
- L183: acceptColumns requires an exact match including order: column names are embedded as SQL identifiers, so only values passing here are used
- L195: The table argument is already checked against the known-tables set, so it is safe to embed as an identifier
- L240: The restore holds no chain verifier: unparseable entries are skipped because import-check / DO-load verification fails such chains before serving
- L265: Epochs are exactly 1..current per live environment: create is 1, rotate is always +1
- L419: #table is the logical table under accept, distinct from the insert target: chain_entries is routed to staging
- L456: verify() checks row counts, trailer watermarks, chain heads and binding rules against the staged chain before promotion, in that order.
- L472: The trailer's audit head is carried only when the source's column was current; then the derivation over the restored log must land on it
- L482: Watermarks are compared against what actually landed, not the reader's tally, so a trailer written for other rows cannot promote
- L505: The head seq must name exactly one entry: a duplicate makes the head hash ambiguous
- L525: Declared heads bind projections to the chain's contents, not its signatures: digest recomputation needs machinery a restore deliberately lacks
- L570: Presence checks complement declared-head checks: a snapshot omitting a live environment's manifest restored silently before this check
- L598: Every chain-created environment has its restored row (tombstoned exactly when deleted) and every live one its manifest row
- L639: Restored checkpoint rows are exactly the staged chain's latest tuple per environment in both directions; acceptance writes row and entry atomically
- L675: No restored wrap may name an environment the staged chain does not hold live, or an epoch it has not opened (§12-6 writer discipline)
- L703: A checkpoint enumeration exists only under a checkpoint row (written and cascade-deleted together); its contents stay unbound — no stronger binding exists
- L730: Project settings have no chain or trailer anchor: the only binding is the writer's closed value domain, since the reader dies on any other value
- L749: Sealed rotation proposals bind only by coordinates to the staged chain; their contents remain the resolving client's verification, as at mint
- L799: Audit heads are derived before chain promotion (ruling J rev r10); stored only below the storage guard's threshold, past it returned from memory
- L820: Every row's numbers are checked against the canonical form, including the rows under the snapshot's own column (round 11)
- L840: The restored log must be exactly seq 1..N with head column 1..M, M ≤ N: a gapped log threw the append-only defect on every later read (ruling J r9)
- L873: A second table line is refused: it would restart the row tally while the earlier segment's rows stay committed, restoring them unaccounted
- L884: Evacuation column names are embedded as SQL identifiers: unless they exactly match the live table's, including order, refuse as corrupt
- L891: chain_entries goes through staging: a mid-chain process death would otherwise leave a valid-but-truncated chain and block restore forever
- L943: Restore contract: batches commit atomically, any mid-way failure wipes back to empty, chain rows promote only after verification passes

### `apps/server/src/do/do-snapshot-write.ts`

- L70: An empty final part is not sent: R2 rejects an empty part when the compressed total is an exact multiple of partBytes
- L96: R2 multipart requires the same size for every part except the last, so exactly partBytes are carved out each time
- L145: The snapshot object key contains no project ID: it is an image of the DO id plus the taken-at time
- L151: writeSnapshot reads one page at a time via a rowid keyset (no cursor held across awaits); every failure is a defect and aborts the upload

### `apps/server/src/do/do-snapshot.ts`

- L178: chain_entries comes last in the evacuation order: the basis of restore's 'chain comes last' rule
- L197: A snapshot holding an undecodable scalar is corrupt and fails loudly, as the old throwing atob did

### `apps/server/src/handlers/handlers-deks.ts`

- L1: Handlers for the DEK-wrap store / distribute / repair API (AUTH_SPEC §12-6).
- L37: Wrap deletion (the §12-6 repair path) is the same level as environment deletion:

### `apps/server/src/handlers/handlers-environments.ts`

- L1: Handlers for the environment-management API (AUTH_SPEC §12-4).
- L28: §12-4: the chain entry's actor and the wrap's signer must strictly equal the caller.
- L41: The composite's token-scope level (AUTH_SPEC §12-3 / §16-2):
- L58: §12-4: the actor of the chain entries (both create and the boundary checkpoint) must strictly equal the caller (2-entry composition)
- L63: The worker side of the composite consistency check (§12-4):
- L76: When the boundary checkpoint notarizes the audit head (non-empty audit_head_hash), require the scope half of effective permission admin…
- L103: Same as create: bundling a non-empty audit_head_hash requires admin scope (§16-2)
- L118: List including the schemaPolicy advisory bundling (§12-7 / §12-11)
- L150: The deletion composite (§12-4 — 2026-10-07):

### `apps/server/src/handlers/handlers-membership.ts`

- L288: A stale ghost projection row is excluded and deleted to converge onto chain truth; a D1 fault on the delete is swallowed (§11-5)
- L317: Uninitialized and non-member are not distinguished — existence concealment (§11-2)
- L321: A successful get lazy-inserts into the projection (self-repair); a D1 fault is not propagated into the success response (§11-5 (4))
- L336: Head attestations are the current members' latest; the stored acceptance time never appears here (§16-1)
- L344: Attestation scope is read: a read-token sync client can join the gossip; attester is structurally the calling principal (§16-1)
- L362: create/rotate/delete_environment go only through composites: a generic-append bypass would create unbundled intermediate states (§12-4)
- L380: Four-eyes and device-key ops are accepted via generic append since K5/K3; their side effects run inside the DO's acceptance task
- L407: The accepted effect is the appended op or a completed approve's inner op (identical to accepting it directly, §6.4)
- L414: On add_member acceptance the matching invite is cross-checked into completed — a derived state; no separate audit event (§15-2/§15-4)
- L442: Projection insert failure's only consequence is a listing omission, which the next chain fetch self-repairs (§11-5 (2))
- L453: Listing correctness does not depend on the projection delete succeeding — read-time DO confirmation excludes stale rows (§11-5 (3))

### `apps/server/src/handlers/handlers-rotation.ts`

- L1: Handlers for the needs-rotation flag API (AUDIT_SPEC §4.1 / §6 / §7).
- L31: The audit seq is not carried by the derived result itself (AUDIT_SPEC §7 — 2026-08-16 C1 ruling.
- L37: Unlike the audit read filters, these decodes stay.
- L62: Sealed value proposals (AUTH_SPEC §14-5):
- L73: A member's resolution (write scope × chain role member × environment ∈ scope — the DO verifies the named versions on acceptance)

### `apps/server/src/handlers/handlers-schema-policy.ts`

- L1: Handlers for the schemaPolicy configuration API (AUTH_SPEC §12-11).

### `apps/server/src/handlers/handlers-variables.ts`

- L1: Handlers for the variable API (AUTH_SPEC §12-5 / §12-7).
- L52: A GET that carries state — the var.read audit record (§12-7 / AUDIT_SPEC §3.3) of the with-values pull and the version value range —…
- L68: Rename and remove (§12-5) take the same request — a signed statement and the manifest that reflects it, without a value — and check it…
- L121: Union of the 2 create forms (§12-5): active = value bundled / declared = no value (the wire Schema fixes the coupling of status and…
- L137: The variableId destination is fixed by the statement (match-checked against the value's AAD)
- L171: The value-lineage declaration (AUTH_SPEC §12-5 — VH)
- L177: Version history (§12-7 — VH): metadata only, reader, scope-agnostic; no var.read (same row as pullMetadata)
- L196: A GET that records var.read (§12-7 — VH)
- L222: The activation composite (§12-5): preliminary checks identical to create (the value-bundled form), and the variableId is fixed by the URL
- L247: The metadata-only mode (pullMetadata) records no audit and is out of scope
- L264: Statements of declared variables (§12-7 — no value; present only when they exist)
- L269: The schemaPolicy advisory bundling (§12-7 / §12-11)
- L271: The latest manifest (§12-7 — required since 0.28-draft; the client uniformly refuses its absence — CRYPTO_SPEC §6.3)
- L274: The value snapshot at checkpoint time (§12-7 — always bundled when a stored row of the baseline checkpoint exists; the material of…
- L283: Metadata-only mode (§12-7): authorization identical to pull (read × reader).

### `apps/server/src/handlers/json-stream.ts`

- L38: jsonStream emits JSON.stringify output as a pull-driven byte stream of ~64 KiB chunks (§14-2 lease)

### `apps/server/src/programs/composite-programs.ts`

- L1: Module scope: composite acceptance programs — creation/rotate bundle chain entry + statement + manifest + wraps atomically (§12-4)
- L88: The composite front stage omits the environment-in-scope check: it depends on the chain the entry is appended onto (§12-3)
- L106: history is the pre-append chain's index: a statement declaring the bundled entry itself as head is not accepted (§12-4)
- L112: Second stage re-judges the role floor under the named device's effective permission; an invalid FP gets actor-key-mismatch (K3-1)
- L130: For creation only a scope=all principal passes (a not-yet-existent id cannot be in listed) — one predicate satisfies the table (§12-3)
- L152: Composite wrap checks: epoch equality with the established epoch, exact recipient-set match by count, signatures, row bound (§12-4)
- L169: The epoch equality check is stricter than the range check: it also rejects a stray wrap addressed to a past epoch (§12-4)
- L187: Bundled wraps must be signed by the bundled entry's device — one request, one device; another device's wrap fails closed (§12-4)
- L193: Exact match is demanded explicitly by count: checkWrapSets skips absent epochs, so the empty set must not slip through (§12-6)
- L208: Boundary checkpoint shape: exactly one tuple, coordinate/epoch/version match; the hash match is owned by manifest verification (§12-4)
- L240: A non-empty audit_head_hash is accepted under §16-2; the role half and content check are the caller-side ensureCheckpointAuditHead
- L248: Audit-head notarization mirrors the standalone path (§16-2); an empty string means no notarization and does nothing
- L269: Boundary checkpoint front-pipeline order: shape match, audit-head check, then the shared 2-entry acceptance check (§12-4, §6.4)
- L293: The audit-head check repeats here: effective-permission admin + §6.4 existence/position (same rule as the standalone path, §16-2)
- L306: A composite does not change values, so stored values at acceptance equal post-application values — the §6.4 cross-check basis
- L313: CompositeWriteContext bundles the write phase's shared dependencies and parameters for the synchronous functions
- L322: readRotationSync is unused by composites but keeps the acceptance path's type surface as one
- L333: insertCompositeWrapsSync writes bundled wraps plus one dek.registered audit row per recipient (§3.3)
- L402: The storage guard runs on creation (a growth surface) but not on mandatory rotation — a security remediation with bounded volume (§12-8)
- L411: Bundled statement/manifest declared heads must match the pre-append head exactly; a retry re-signs all three artifacts (§12-4)
- L429: The manifest epoch check is an early composite-internal rejection; full epoch consistency is judged over post-application history
- L438: Creation judges the 2 entries (H+1, H+2) with one whole-chain re-verification via acceptBoundaryCheckpointPair (§12-4)
- L456: ID uniqueness is verifyChain's job; the data plane keeps only display-name uniqueness and the quantity policy
- L468: A meta statement is accepted even if the environment did not exist at the declared head — the intended asymmetry vs value signatures
- L482: Epoch consistency for creation is judged by the checkpoint binding; a tuple/manifest hash disagreement doubles as the §12-4 check
- L498: Creation's checkpoint values_digest is the enumeration of the empty variable set (§6.4)
- L501: The current epoch after a create_environment applies is always 1 (§12-4)
- L517: The write phase is a single synchronous block — do not split entry, mirror, rows, manifest, wraps and audit (§12-4)
- L545: env.created records the statement author's key FP (§3.3)
- L555: Creation's snapshot save is atomic: the empty enumeration plus the tuple coordinates (§6.4/§16-2)
- L596: The URL coordinate must match the entry's environment_id: independent checks alone could accept a mismatched entry/wraps pair (§12-4)
- L603: Existence and scope are judged after the parent-head CAS: a rotate signed over a pre-deletion view is a 409 (§12-5 check order)
- L610: Check order is scope (403) then existence (404); a rotate to a deleted environment is a 404 (§12-3 order, K3-C)
- L619: On a retry after a head CAS failure, both the entry and the manifest are re-signed (§12-4)
- L631: Rotate judges its 2 entries (H+1, H+2) through acceptBoundaryCheckpointPair (§12-4)
- L647: Rotate's manifest is a reissue reflecting only epoch advancement; the meta set is the stored latest shape as-is (§12-5 (4))
- L662: Under rotate, un-re-encrypted values are a legitimate §12-7 state: the enumeration is the old epoch's current values (§6.4)
- L673: The epoch after a rotate applies is new_epoch; epoch ordering is already verified by verifyChain
- L707: Rotate's snapshot save is atomic: the cross-checked current-values enumeration plus the tuple coordinates (§6.4/§16-2)
- L729: Deletion composite accepts the chain entry and the data deletion atomically in one synchronous block; chain-dependent checks follow the CAS (§12-4)
- L759: Two different heads in one deletion request are malformed whichever one is current (2026-10-08)
- L769: An FP that is not a valid device of the caller is answered early as verifyChain's actor-key-mismatch
- L781: After the CAS the head is the one the entry was signed over, so the scope judgment cannot be stale
- L786: A chain-live environment's data row is live too (only this composite tombstones it); anything else is storage corruption
- L798: Deletion write phase is one synchronous block: entry, mirror, tombstone, data deletion, closing audit rows (§12-4, §3.3)
- L817: An already-expired proposal closes as the sweep would have (actor system); a pending one is cancelled by the deletion (§12-4)

### `apps/server/src/programs/programs-audit.ts`

- L1: Module scope: DO audit reads — visibility classes are enforced at authorization; admin = chain role admin x token scope admin (§6/§7)
- L34: AuditEventsQueryInput crosses the RPC boundary; its filter vocabulary is per §7
- L36: beforeRowId is the opaque §7 cursor: the previous page's last row id
- L40: eventPrefix is a prefix match on the event namespace (§7)
- L42: chainSeqPresent returns only rows whose chain_seq is not NULL (§7)
- L48: scopeAdmin is worker-judged on the same trust boundary as actor (auditActorOf); the DO composites it with chain role (§6)
- L67: id is the wire row identifier (row_id — §5.1/§7)
- L69: seq appears only on admin-visible DO responses: the gapless ordinal would leak the class-2 row count (§7)
- L82: orgId is the org axis — D1 rows only, always absent on project DO rows
- L87: actorTypeOf maps the stored column to §2's 3 actor kinds; the column is already fixed at write time
- L96: seq rides only on admin-visible responses: gap detection is meaningful only to an admin who sees every row (§7)
- L124: A JSON.parse value is always JSON vocabulary at runtime; unknown to Json is a type-only narrowing
- L131: The DO bounds the page limit too, though the Schema enforces the 200 cap — defense in depth
- L137: audit-head authorization is effective-permission admin; opening it to member level would leak via polling (§16-2)
- L158: This GET deliberately writes: lazy materialization extends the accumulated-hash column before reading, under the permit (§5.1)

### `apps/server/src/programs/programs-chain.ts`

- L1: Module scope: chain API programs — genesis, generic append policies, chain get, caller's chain-derived role (§6.4, §11-2)
- L53: FreshInitNotAdmitted is reached only after the existing-chain check: AlreadyInitialized (the repair path) stands first (§11-3)
- L68: appliedProposal lets the worker run the same D1 post-processing as a direct append; it is not carried on the HTTP wire (K5)
- L79: Snapshot attestations narrow to current members' valid devices — an independent defensive layer beyond row deletion (§16-1)
- L98: already-initialized returns genesis actor + head as the worker repair's decision input (§11-3 idempotent repair)
- L110: fresh-not-admitted writes nothing; an initialized DO never reaches this branch (repair path / 409 instead) (§11-3)
- L123: admitFresh is the worker's §11-3 limit decision; the DO still decides already-initialized inside its own serialization first
- L146: ensureChainMember rejects anything that is not a chain-derived member, reader included (§6.2/§11-2)
- L166: Missing genesis/head on an initialized chain is storage corruption = defect, never an empty-string success response
- L177: The §11-3 limit check sits after already-initialized so an at-limit org's repair re-init passes regardless of the limit
- L186: On an empty chain the capacity check is vacuously satisfied; a non-genesis at seq 1 becomes bad-genesis under verifyChain
- L195: Project ID = genesis entry hash; a broken DO/entry binding refuses acceptance (defense against a worker-side bug) (§6.4)
- L201: DO tables materialize only after every refusal branch, so a refused or probing init leaves no storage (Sc-7/A-4)
- L211: A non-member gets nothing back — not even the CAS's current head or the policy decision (worker maps not-member to 404)
- L235: state here is the reference for the four-eyes acceptance policy and the growth guard in appendProgram
- L241: The growth guard stops at the entry where intent first appears: propose/approve of a growth op count as growing (K5-D, §12-8)
- L267: appendProgram is also run by storage-guard.test.ts, which pins growth-op rejection and non-blocking of removals
- L283: The composite-only guard sits on the DO side too (the acceptance authority), not only in the worker handler (§12-4)
- L298: A standalone checkpoint branches into a dedicated path: content cross-check at acceptance time + atomic snapshot save (§16-2)
- L306: The storage guard covers only access-set growth, aligned at the entry because the follow-up wrap backfill is what is rejected (§12-8)
- L318: Four-eyes propose policy inputs are the derived state and the server clock, which only the DO has — never placed on the worker (K5-B)
- L332: The device cap counts valid devices on the pre-acceptance derived state; revoked ones do not count (§12-8, DK K3)
- L345: The 4 acceptance steps are shared with the composite path; a completed approve commits the inner op's mirror and side effects (K5-H)
- L360: snapshotProgram is pinned by storage-guard.test.ts: reads pass even under storage rejection
- L366: Attestation bundling narrows to current members' valid devices as an independent defensive layer (§16-1, §6.6 (1))
- L386: memberRoleProgram's floor is reader; the admin/owner level judgment is done worker-side per endpoint (§15-2)

### `apps/server/src/programs/programs-dek.ts`

- L1: Module scope: DEK-wrap registration, distribution and repair programs; acceptance body lives in dek-wraps.ts (§12-6)
- L46: The registrant must also have the target environment in scope — a 403 that comes before the recipient-axis 422 (§12-6)
- L66: Registration is a growth surface (guard after existence, before set checks); deletion never calls it — it must not plug release (§12-8)
- L82: An empty deks array is unreachable: the wire Schema enforces at least one entry (400)
- L86: Stage 2 re-checks role/scope against the signing device's effective permission (K3-1)
- L102: A deletion reference's device key may be omitted (design record §8 K3-3)
- L108: The §12-6 repair path deletes poisoned wraps per tuple (overwrite prohibition intact); a nonexistent tuple is a 404
- L136: The audit column is chosen from the stored row's recipient class, never the client-declared class; a mismatch is a 404 (§12-6)
- L160: The deletion write phase is a single task: deletion + one dek.deleted row per recipient, atomically (§3.3)
- L169: A server recipient's FP rides target_key_fingerprint (no user_id); using ref's class is sound because the check phase matched it
- L191: Own-DEK fetch requires environment in scope; the 403 makes do-not-distribute structural (fail-closed) (§12-3)

### `apps/server/src/programs/programs-environment.ts`

- L1: Module scope: environment management and bulk pull; creation/rotation/deletion go through composites (§12-4/§12-7)
- L46: Rename acceptance resolves the signing device from the statement, then judges that device's effective permission (§12-4, K3-1)
- L94: Rename is a growth surface (statement + manifest); deletion does not call the guard — it must not plug the release path (§12-8)
- L109: Rename check order mirrors ruling D: caps, CAS, statement signature, manifest acceptance, atomic write (§12-4)
- L121: A rename's bundled manifest copies in the new envMetaSigHashHex; the envMeta expectation is this very statement (§12-4/§12-5)
- L162: Every listed environment carries create_environment on the chain, so currentEpochOf is derivable for every row
- L170: schemaPolicy rides the environment list as an advisory bundle — not an input to the verification rules (§12-7/§12-11)
- L177: Pull front half: with-values requires environment in scope; metadata-only is scope-agnostic (plaintext meta visible to members) (§12-7)
- L204: A missing manifest row can only come from a corrupted DO or crafted snapshot — never from the API's own write paths (§12-7)
- L223: With-values pull is a read that writes var.read rows — the dominant growth term; observation only, never refuses (§12-8)
- L232: Deleted variables' statements keep being distributed as denial-of-deletion detection material; no value accompanies them (§12-5)
- L237: Declared variables distribute statements only — required material for the manifest's digest recomputation (§12-7)
- L242: The checkpoint snapshot is always bundled when present; client rule 2 rejects basis-present + enumeration-absent (§12-7, §6.3)
- L247: Bulk-pull audit is one aggregate row per environment enumerating the returned variables, so enumeration and response always agree (§3.3)
- L280: Without declared variables the key itself is omitted (the optionalKey wire shape)
- L291: Metadata-only mode records no audit: var.read's condition is ciphertext distribution; what was not read is not recorded (§12-7)
- L308: Declared variables' statements ride the metadata pull too; status does the discrimination (§12-7)

### `apps/server/src/programs/programs-export.ts`

- L1: Module scope: project export — page 1 is owner-only, consumes the export window and appends project.exported itself (PF3, §11-6)
- L48: mirrorOf is read with the marks (ruling J revision); absent on a writable project
- L71: Mark and page marks are read in one synchronous call, so 'marked at last page, unchanged since first' holds by construction
- L94: A foreign cursor is treated like a changed project; continuation is served only to the owner whose export the cursor names (ruling D)
- L126: An initialized project always has a head (requireMemberState passed)
- L135: First page order: window, then the audit row before the marks (the exported log carries its own export — ruling F), then hash extension
- L170: Hash extension runs only below the storage rejection threshold, measured before each bounded call; at most one call overshoots (§11-6)
- L179: Each extension call makes progress (the bounded contract of audit-store.ts), so the loop terminates
- L188: The cursor binds the export row's payload: a column not decoding to exactly this head fails like a stale cursor (ruling D revision)
- L200: exportRowBinds checks the cursor's row exists, is the requester's, and names the cursor's head within the exported bound
- L219: The export companion's members are bound to the chain head they were read at (ruling H revision)
- L226: exportMembersProgram is owner-only: the identities companion of an export, with the chain head

### `apps/server/src/programs/programs-history.ts`

- L1: Module scope: version history — metadata only, no ciphertext/DEK, hence no var.read; flags derive from the lineage fold (§12-7, VH)
- L50: Byte-budget trimming always keeps the first version: a single value is at most 64 KiB (§12-8), so progress is guaranteed (§12-7)
- L129: A declared variable has latestVersion 0, so every fromVersion is past the latest (the Schema already refuses < 1)
- L135: History values read observes the storage level like the with-values pull — a read that writes var.read rows (§12-8)
- L142: History audit is one aggregate row enumerating every returned version; the range check guarantees at least one row (§3.3)

### `apps/server/src/programs/programs-lease.ts`

- L1: Module scope: workload leases — unwrap/re-wrap inside the DO so the code reading response material also appends the audit (§14)
- L62: LeaseTokenFacts carries only the parts of a verified OIDC token that authorization and binding need
- L67: claims must be structured-clone-safe (crosses RPC) and appear in neither audit nor response — no external identifiers (§14-4)
- L74: claimsDigestHex is computed by the worker via crypto (§9.1)
- L76: The binding key hashes the JWS signing input, not the raw token: the raw signature segment is malleable (§14-1 ruling)
- L87: Binding lifetime is token exp + retention margin, guaranteeing at least the validation clock skew (policy.ts derivation)
- L95: LeaseValue is the pull shape minus deks plus lease wraps; the chain is read separately via leaseChainProgram (§14-2)
- L103: schemaPolicy's advisory bundling targets only the environment list and pull responses — it is not carried on the lease response
- L120: A replayed token is a 401, not folded into 404: diagnosability is half of the first-come binding's observability (§14-1)
- L132: chainToken is a single-use token for the chain read (ProjectChainDO.leaseChain — §14-2)
- L137: lease_denied records only post-verification rejections, globally bounded; actor is system — not an exercise of the server key (§3.5)
- L167: denyWithAudit folds rejection + audit recording into one, leaving no path that forgets to record
- L177: Same token + same key passes the binding check (legitimate-retry idempotency); only a different key is replayed (§14-1 ruling)
- L198: AuthorizedWorkload is what the shared front stage hands the lease and proposal programs
- L207: authorizeWorkload is shared by lease and mint: steps 0-2, every mismatch a uniform 404 with a lease_denied row (§14-2/§14-5)
- L228: A keyless deployment fails before reading the project: running chain loading first would leak project existence via 404/503 (§11-2)
- L241: An uninitialized project is 404 with no storage left behind; tables are created only at genesis acceptance (Sc-7/A-4)
- L255: Derivation of a stored chain cannot fail; a verification failure there is a defect (chain-store.ts)
- L259: Grant identification has no nondeterminism: the server can only unwrap wraps addressed to its own FP (§14-1)
- L274: The binding check precedes environment existence: a bound-token copy holder gets a uniform 401 with no existence information (§14-3)
- L280: Environment existence: a deleted tombstone is 404 (§14-2 step 2)
- L310: The rate-limit check is after authorization (concealment) but consumption only at issuance — a 503ing project must not burn its window
- L326: Missing server wraps = 503, the last line of defense against a missed backfill (A1 ruling, §14-3)
- L341: Declared variables' statements ride the lease response under §12-7 rules — material for the workload's digest recomputation (§9.1)
- L345: A missing manifest is an invariant violation = defect, never an omission: creation writes it atomically (§12-4, §14-2)
- L354: The checkpoint snapshot rides the lease response as in §12-7; null (no baseline) is not included (§14-2)
- L358: The full epoch set is required with no gaps: one missing epoch would put an undecryptable value on the response (§14-2)
- L375: Unwrap/re-wrap happens inside the ServerKey closure: no plaintext DEK escapes it
- L388: Unwrap and re-wrap failures fold into the same 503 as missing wraps; the finer reason lives in the operator audit row (§12-6)
- L404: Lease observation is placed after authorization, compatible with existence concealment (§11-2, §12-8)
- L410: No var.read is recorded for leases: that is a human read's evidence; workload disclosure is carried by the server.* family (§14-4)
- L416: Window consumption and the binding record share issuance's synchronous block — neither intermediate state exists (§14-1)
- L438: The audit payload cross-checks via grant_chain_seq + claims_digest; no external identifiers are written (§14-4)
- L465: The chain is append-only, so the judged prefix is stable; a different hash at the head seq is a broken invariant (§14-2)

### `apps/server/src/programs/programs-mirror.ts`

- L1: Module scope: mirror programs — mark turns the project read-only at once; status fields are admin/owner-gated (PF2, §11-7)
- L58: MirrorSyncPosition is the last replication as status reports it: the commit's position, without ownAuditRows
- L61: Audit seq, attestation mark and last replication are admin/owner-only (ruling G revision); every member sees mark/source/head (§7)
- L93: sourceMutationSeq is the source's mutation counter as the export's head reported it (recorded by the trailer page)
- L102: An initialized project always has a head (the role check passed)
- L120: Sync time and source counter are written together by the commit, so both are set exactly when a replication was recorded
- L162: A mark naming another source re-points the mirror; the project stays frozen throughout (ruling C revision)
- L169: unmark is the promotion (ruling C): the mark goes and the project accepts writes again
- L183: Staging refusals surface as the data-plane rejection the worker maps to 422 MirrorSyncRejected
- L190: decodeEntry classifies unparsable JSON as malformed and a schema-refused shape as an invalid chain
- L211: Staged-chain verification reuses the same verifier the DO runs on load (§11-7 chain-invalid)
- L225: A crypto rejection here is a platform defect — the same outcome the bare Promise's rejection propagated before the bridge
- L255: The mirror's audit-head column must reach the replicated position before the trailer comparison (ruling J revision)
- L260: Each ensureHeadCurrent call makes progress (bounded contract), so the loop terminates
- L276: Trailer checks run outside the page transaction (permit held), so a refusal discards the staging explicitly before mapping
- L286: Staged audit heads are derived before anything live is touched (ruling J revision, round 10)
- L298: After the swap the derived memory is discarded and the audit-head column extended — the same convergence as a restore
- L307: Each ensureHeadCurrent call makes progress (bounded contract), so the loop terminates

### `apps/server/src/programs/programs-proposal.ts`

- L1: Module scope: sealed value proposals — mint reuses the lease's authorizeWorkload; every mismatch is a uniform 404 (PF7b, §14-5)
- L45: RotationConnector derives from core's ROTATION_CONNECTORS — the single definition
- L48: ProposalWrapInput is a proposed value sealed to one recipient device, crossing the RPC boundary
- L62: RotationProposalInput is already Schema-validated by the worker (§14-5)
- L67: expiresInDays is 1-30 (worker Schema); the server sets the instant
- L72: ProposalRejection is the lease vocabulary plus the §14-5 acceptance checks
- L87: MemberProposalValue distributes a pending proposal to one member with their own wraps only
- L98: W(E) = R(E) minus readers, reader-capped devices and server keys; keyed like the wrap store (§5.3)
- L116: An unknown stored connector is storage corruption = defect, never re-read as a default
- L125: One variable's wraps must be exactly W(E) — nobody missing, nobody extra, no duplicates (§14-5 (5))
- L141: Duplicate variable naming is judged over the whole list before any per-variable check (§14-5 (3))
- L146: variableRefusal bundles one variable's §14-5 (4)-(6) checks: active, base current, recipients exact, no pending proposal
- L164: One proposal per variable at a time, at mint as at pre-flight: two pre-flighted jobs must not both store (ruling O revision)
- L172: proposalRefusal runs the §14-5 acceptance checks in their order (2)-(7); null = acceptable
- L197: Sealed values count toward the project's ciphertext cap — the meter includes pending proposals (§12-8)
- L203: proposalCiphertextBytes counts hex at two characters per byte
- L226: Mint steps 0-2 are the lease's authorizeWorkload (uniform 404 / 401 binding / existence)
- L236: A mirror mints nothing (§11-7), judged after authorization in the proposal vocabulary — the job mints against the source
- L247: The mint window is judged after authorization (existence concealment) and consumed only when a proposal is stored (§14-5 (1))
- L261: Expired rows are swept before the id and pending-count checks: an expired proposal neither blocks its id nor counts
- L268: Expiry is a duration on the wire but the instant is the server's, so a fast client clock cannot make a proposal unacceptable (ruling O)
- L274: Window consumption, binding, rows and audit happen in one synchronous block at the mint
- L297: rotation.proposed's actor is system (the workload has no maruhi identity); attribution is claims digest + grant seq (§3.3)
- L319: Every proposed row gets exactly one closing row (ruling P-2), so minted-but-never-accepted is enumerable from the log alone (§3.3)
- L326: The sweep payload carries the expiry instant: in a quiet project the sweep can run long after expiry (ruling P revision)
- L355: The mint storage guard is judged before the window and semantic checks: a proposal minted at the threshold could never be accepted (§12-8)
- L375: PreflightVariableInput is what the job intends to propose, checked before the issuer is touched (§14-5 O-4)
- L381: The pre-flight recipient set is checked against W(E) before the issuer is touched (ruling O revision)
- L392: Pre-flight runs every §14-5 check not needing a sealed value; nothing is stored and no window is consumed (ruling O-4)
- L420: Pre-flight reads the mint window without consuming it, so a rate-limited job learns it before the issuer is touched (ruling O)
- L440: A non-race recipient disagreement is answered at pre-flight, before the issuer is touched; the mint repeats the check
- L464: preflightVariable runs the mint's per-variable checks in the same order as the mint
- L483: ownView narrows a stored proposal to the caller's own wraps only
- L498: The proposal list's role floor is member: a reader is never a recipient, so their view would be empty by construction (§14-5)
- L504: The proposal list also sweeps (a read that appends, the var.read precedent); a mirror writes nothing — its source sweeps (ruling P)
- L518: Acceptance requires every proposed variable named with a stored version newer than its base (§14-5)
- L551: A resolution reaches a proposal expired or not; unknown/resolved/swept fold into one indistinguishable 404 by design (ruling P)
- L562: Resolution scope is judged on the stored environment and folded into the same 404, so pending cannot be told from absent (§12-3)

### `apps/server/src/programs/programs-rotation.ts`

- L1: Module scope: needs-rotation flags — the flag view is class 1 (all members); dismissal is a dedicated operation (§4.1/§6/§7)
- L51: Dismissal does not consult scope: it is a governance operation absent from §12-3's table; the flag view has no environment axis (K3-C)
- L70: Dismissal is idempotent per pair (duplicates fold); a pair with no active flag rejects the whole request all-or-nothing
- L91: The dismissal write phase is a single task: one rotation.dismissed row per pair, actor = the dismisser (§3.3)

### `apps/server/src/programs/programs-schema-policy.ts`

- L1: Module scope: schemaPolicy program — get is reader-level, set is admin-level and writes project.schema_policy_changed (§12-11)
- L32: The settings set is inside the storage guard's refused set: each change adds an unbounded audit row; get passes as a read (§12-8)
- L42: An idempotent equal-value PUT stays a 204 and records no audit: a non-transition is not a 'changed' event (§3.3)
- L50: The settings upsert and its audit row are written in the same synchronous block (atomicity)

### `apps/server/src/programs/programs-variable.ts`

- L1: Module scope: variable programs — check order is requireEnvironmentAccess, existence, CAS, signature, quantity, atomic write (§12-5)
- L68: writeVersionWithAudit is synchronous (used inside write phases); the audit records only the chain-derived writer (§4.1)
- L117: Schema-locked creation is a one-time creation check, not a continuing invariant — a later reissue may change layout (§12-11)
- L139: Creation schema gates run under the policy at acceptance time; the layout support-range check is the caller's, earlier (§12-11)
- L154: Creation pre-check order: ID availability (no tombstone reuse), quantity policy, NFC, name uniqueness (§12-1/§12-8)
- L180: Bundled version-1 value pipeline: value CAS, value signature, capacity
- L202: requireVariableWriteContext bundles the shared three-stage prefix so push/activation/rename/delete do not repeat it (§12-3)
- L222: The support-range check runs before every statement-dependent check so a v3 client gets the honest update-required (ruling CR)
- L243: Meta-op core: acceptance pipeline under the signing device, then manifest composite with the statement as the digest entry (§12-5)
- L254: operation selects the predecessor-match checks, which run after the metaVersion CAS (§12-5)
- L296: Declared creation is the sole exception to 'a variable without a value does not exist'; layout v3 only (§12-5)
- L310: value is undefined exactly for a declared creation (no value)
- L323: The support-range check precedes even the pre-checks: a v3 client must not get duplicate-name for a colliding name (ruling CR)
- L329: The storage guard sits before the semantic checks: resource protection outranks semantics (§12-8)
- L335: The schema policy is read at acceptance time under the permit: locked requires v3 + non-empty varType on creation (§12-11)
- L339: The creation CAS is kept as a defensive line though the wire Schema already fixes metaVersion 1 and empty prev (§12-5)
- L344: Creation path verifies value and meta signatures like the normal path — bypass via creation is impossible; order CAS, meta, value (§12-5)
- L378: The manifest digest is recomputed from the post-creation meta state; its CAS is judged in the same transaction as the meta CAS (§12-5)
- L404: Creation's write phase is atomic: never leave an active variable occupying only an ID with latest_version 0 (§12-5)
- L420: A declared creation's var.created records only the statement author's FP (there is no value signature) (§3.3)
- L433: Creation is by definition not a re-encryption and carries no marker declaration surface (§12-5)
- L451: A declared creation stays at stored version 0 (§12-5)
- L472: A normal push to a declared variable is refused: the first value comes only via the activation composite (§12-5)
- L478: Re-encryption/rollback pushes are also under the storage guard: under rejection no new value can be written (§12-8 (d))
- L484: The lineage claim is unverifiable (E2EE) and affects nothing else; post-CAS, < version is exactly an existing earlier version (§12-5)
- L491: Push check order (ruling D): CAS, signature, quantity, atomic write; on non-acceptance nothing changes
- L544: Activation is a composite of existing rules (value + active statement + manifest), not a general push-plus-reissue (§12-5)
- L573: Activation's storage guard sits after existence and support range, before CAS and signature (§12-8)
- L576: Declared is the only legitimate latestVersion-0 state, so the CAS forces value version 1 (§12-5)
- L579: Activation does not double as a rename: the declared name is kept, so declaration-time NFC/uniqueness checks stay valid (§12-5)
- L611: Activation involves a manifest reissue: the 'a value push does not touch the manifest' invariant covers only normal pushes (§4.3)
- L634: Activation's write phase is one task; var.version_pushed (version 1) starts the value's existence interval (§3.3)
- L648: Activation is the first value and is by definition not a re-encryption
- L671: variableMetaProgram is the shared frame: resolve the meta-op context from the common tuple, then run the op's own pipeline
- L722: Rename's storage guard keeps the delete path's prefix shape; delete itself does not call the guard (§12-8)
- L737: Rename/reissue never changes status: declared-to-active is only the activation composite; active-to-declared is forbidden (§12-5)
- L757: Only a name-changing reissue is var.renamed; a name-preserving one is var.schema_reissued — branched on a byte comparison (§3.3)
- L797: The digest is recomputed over the set including the tombstone: a mismatch from hiding a tombstone is caught here (§4.3 (3))
- L817: Delete's write phase: tombstone + delete all versions + the deleted statement row (kept stored and distributed) + manifest (§12-5)

### `apps/server/src/quotas.ts`

- L1: Existence guards and quantity policies (AUTH_SPEC §12-8).
- L31: AUTH_SPEC §11-3: the cap on active projects per org.
- L46: An extant (non-tombstone) environment. Absent → environment-not-found.
- L58: An extant (non-tombstone) variable. Absent → variable-not-found.
- L71: The quantity policy on environment count (§12-8; called from composite creation — composite-programs.ts).
- L91: The quantity policy on variable count and variable-row count (tombstones included) (§12-8).
- L113: The cap on metaVersion row count (interim ruling — applies the same value as §12-8's "versions / variable" to statement rows.
- L133: §12-8 (Sc-3): the cap on an environment's current ciphertext.
- L150: Called on every path that sets an active variable's latest version (push, create with a value, activation).
- L170: §12-8: the cap on accumulated ciphertext bytes.
- L189: §12-8: the cap on accumulated DEK-wrap rows per project.
- L199: Called on every wrap-insertion path (DEK registration, environment creation) (§12-8).
- L214: The acceptance policy for four-eyes proposals (AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — not consensus rules; design record es-design.md §11…
- L226: Whether a proposal is within its lifetime on the server clock (= counted in the pending-cap computation).
- L231: §6.4: whether `expires_at_ms` exceeds the server clock at acceptance + 30 days (pure function — exposed for unit tests).
- L236: §12-8: whether adding one to the in-lifetime pending proposals exceeds the cap (pure function — exposed for unit tests).
- L255: The acceptance policy of `propose` (upper bound → pending cap).

### `apps/server/src/rotation-detect.ts`

- L1: Detection of rotation-needed flags (AUDIT_SPEC §4.1 = the implementation of CRYPTO_SPEC §7) and derivation of flag dismissal (§4.1 step 5).
- L68: Basis rank (§4.1 step 3): read = definitely obtained / readable = could have been obtained.
- L71: The op that triggered detection (§3.3 `rotation.recommended`'s payload.trigger — 2026-09-14 ES):
- L78: One `rotation.recommended` row (§3.3) — what every detection variant returns.
- L81: A currently-effective rotation-needed flag (the §4.1 step 5 derivation result; crosses the RPC boundary).
- L86: Only on the remove_member / change_role variants.
- L88: Only on the revoke_server variant.
- L90: No audit seq is carried (the 2026-08-16 ruling C1):
- L96: The chain seq of the deletion / demotion-or-shrink / revocation entry that triggered detection (from the payload).
- L100: The version whose push restored a value from before this flag after the flag had been resolved (§4.1-5 / §7 — 2026-09-27 VH).
- L108: A half-open interval on the audit seq (end = +Infinity means unclosed).
- L114: A variable's existence interval (Q2 of §4.1 step 2 — var.created to var.deleted).
- L140: Scope transitions are open / update / close only, identical across recipient classes; the window derivation looks only at these three kinds
- L159: The derivation treats open-while-open as update and update-outside-interval as open: for corrupt input, err toward not missing (§9 K3-F)
- L201: A membership row whose scope cannot be read fails safe and opens the window as all (the not-missing side, §9 K3-F)
- L222: Grant scope accumulates monotonically as a union inside an interval: a shrinking re-grant must never close a disclosure window (§6.3)
- L240: An interval containing an unreadable grant scope is treated as all environments (fail-safe, K3-F)
- L307: The exposure bound is the epoch at the end of the subject's last window; no epoch row means unbounded (+Infinity), resolving only by dismissal (§4.1-5)
- L331: The exposure bound is a per-environment invariant across a detection's candidates, so pairs fold into rows per environment with the bound on epoch
- L346: Recommended rows are chunked at a max variables per row: an unbounded row's export line would exceed the mirror page slack forever (Sc-5)
- L386: Every candidate of an environment shares the same windows, so the exposure bound is taken structurally from the first flag rather than asserted
- L426: Member-variant candidates overlap subject windows including deleted variables: an upstream credential does not expire because the variable is deleted
- L465: The window envelope is passed to Q3 as a range scan over ae_actor; the result is identical to not narrowing
- L507: remove_member detection uses all windows in the membership interval, including shrink-closed ones, per the letter of §4.1 step 2
- L538: change_role: shrink candidates equal removal; demotion uses all windows open before the trigger, clipped at the trigger seq; promotion yields none
- L570: An unreadable role is judged as a demotion (the not-missing side, §9 K3-F): unknown old role = was a writer; unknown new role = no longer one
- L576: If the trigger's scope cannot be read, windows never close, so every window open before the trigger becomes a candidate, as with demotion
- L610: A revoked FP absent from device_added is a first key: its interval runs from the membership start with scope all, structurally (owner, all) (§6.2)
- L651: revoke_device candidates = device live interval ∩ access windows ∩ device scope; a vote-only device (empty scope) writes no row
- L701: revoke_server candidates use per-environment disclosure windows: an environment entered via an enlarging re-grant counts from the enlargement seq
- L780: This server is the only writer of recommended rows, so a missing or invalid trigger is corruption = defect
- L803: The origin epoch follows the sameValueAs lineage; a named version with no row falls to 0, the oldest possible origin = the safe side (§4.1-5)
- L824: A recommended row without an epoch bound (corruption) never resolves by a push — the safe side
- L845: A push moving a flag from resolved to effective is a re-exposure: a restore of a value the subject could read
- L880: A new flag starts effective unless the live value was already first encrypted above its bound (an old shrink, since rotated and re-pushed)
- L892: A dismissal covers only the flags effective at that point — what the admin saw; a resolved flag stays resolved but can re-open on a restore (§4.1-5)
- L906: A flag is effective while not dismissed and the live value's origin predates it; multiple effective recommendeds on one pair are all returned (§4.1 step 5)
- L932: flagsIfCurrent: a version with no push row falls to origin 0, the same safe side as originEpochOf, so every non-dismissed flag counts (§12-7)

### `apps/server/src/storage-guard.ts`

- L1: The DO storage-total guard (AUTH_SPEC §12-8; hosted-design.md §3-3 / §8 gap 3).
- L78: The decision for a measured size (admit < warn < reject).
- L86: The draft values in policy.ts (§12-8 — decimal GB).
- L92: §12-8: the pure function measured size → decision.
- L110: The ops-log bands (once each per DO instance).
- L114: The DO SQLite's measured size in bytes. The instantaneous value of SqlStorage.databaseSize (no I/O).
- L116: Records a once-only ops-log firing. true on the first call (the caller emits the log), false when already emitted.
- L126: The measurement fetch point (the tests' injection point).
- L136: The meter's substance (the construction shared by the SqlStorage version and the tests' fixed-size version).
- L154: Measure → decide → ops log (observation only — does not refuse).
- L176: Static message only (no variable values like project ID or size — the size is the monitoring system's domain; this is the one line…
- L191: The guard the acceptance programs of content-growth surfaces call (§12-8).
- L212: The guard for paths that read the audit-head derived column (AUDIT_SPEC §5.1 — lazy materialization) (`GET /audit-head`, checkpoint…

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
