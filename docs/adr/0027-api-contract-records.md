# ADR-0027: API contract decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 528 comments on the API schema and contracts were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/api.ts`

- L1: Typed client is derived automatically from the api-schema (ADR-0005); the bearer token rides only on the request header, never in logs or errors
- L15: Separate header timeout (30s) and wider body timeout: a server that accepts and never answers would otherwise hold a read forever and mirror fallback never fires
- L24: Body timeout also serves as the header bound for clients uploading large bodies (mirror sync pages)
- L27: A request past its timeout is classified as a transport failure (unreachable), never as an answer
- L52: Bearer token rides via upstream bearerToken (accepts Redacted as-is); a hand-written Authorization header would send the redacted form verbatim, so it is not used
- L81: A stalled response body is classified as the same transport failure as missing headers

### `apps/cli/src/commands/login-logout.ts`

- L40: The --token-name bound reads the same constant as @maruhi/api-schema's declaration — transcribing the number on the CLI side would keep refusing under a stale bound when the declaration is relaxed; the given value never appears in the error.
- L54: The --token-ttl-days bound and default read the same constants as @maruhi/api-schema's declaration (AUTH_SPEC §6), so a misspelling drops before browser approval completes; an omitted value stays undefined for the server-side default.

### `apps/cli/src/key.package/command.ts`

- L52: The passkey label's api-schema acceptance shape is checked early, on the declaration side.

### `apps/server/scripts/d1-api.ts`

- L17: Poll envelope layout: success/status/at_bookmark at top level, the export signed URL under result, import upload instructions at top level

### `apps/server/test/data-http-converters.test.ts`

- L1: The converter copies only stored-input fields so wire-declared coordinates never reach the DO; the DO reconstructs the signed target from storage coordinates (section 12-5)

### `apps/web/src/dashboard/endpoints.ts`

- L1: endpoints.ts is the single catalog of consumed API surfaces (ruling BW); a unit test makes path agreement with api-schema and session allowance (§5) fail loud instead of as runtime 404/403.
- L30: Cursor query names are shared constants (ruling CB) read by both builders and catalog, so callers never touch the name and a mix-up is impossible syntactically.
- L89: The catalog's cursor field is swept against api-schema's query Schema so a parameter rename fails in a test rather than as silent unresponsive paging.

### `packages/api-schema/src/audit-api.ts`

- L1: Audit read API contract: visibility classes enforced at authorization; class-2 rows behave as nonexistent; no append API exposed (§7)
- L36: Max page size 200 per AUDIT_SPEC §7; excess is a Schema 400
- L45: Row-id format exported so the CLI pre-request check shares the Schema format instead of duplicating it
- L62: Single wire shape for all audit stores; no second format gate on read side — head hash detects tampering, stored values must round-trip
- L78: Row id doubles as paging cursor and carries no ordinal distance (§7 non-leakage of counts)
- L84: seq present only for admin-visibility DO responses (gap = deletion trace); always absent on D1 paths to avoid leaking autoincrement ordinals
- L105: Payload is supplementary JSON as recorded — a server assertion under the header's verification discipline
- L109: Audit read success response never returns count fields (§7 non-leakage)
- L114: Audit-head response carries only the cumulative hash; seq and row count excluded; zero rows returns empty string
- L128: Page limit defined on NumberFromString to satisfy QueryConstraint (encode to string)
- L136: Filter acceptance limits: user_id bound from CRYPTO_SPEC §6.1 free-string limit (1024 bytes); other filters sized to spec vocabularies
- L144: Cursor paging: invisible or unknown cursor id behaves as an empty page — no existence oracle (§7)
- L162: Event-prefix match lets verify pull every chain.* row incl. forged names; server uses substr, not LIKE (no wildcard semantics)
- L170: chain_seq presence filter catches forged provenance claims outside the chain.* namespace; only literal 'true' accepted
- L178: Below admin, actor filter may name only self; static data-independent rule so existence information does not leak
- L192: invite.* reads use the project chain-role admin × token scope admin axis despite D1 storage (§7 exception provision)
- L203: Self-read of user-scoped events restricted to session or * × admin tokens, same level as AUTH_SPEC §13-2
- L214: Audit-head fetch requires effective-permission admin; member-level access would make hash-change polling a timing side channel
- L225: AuditHeadNotReady (503) is retryable and returned only after the auth decision; DataLimitExceeded (422) conditions for lazy materialization

### `packages/api-schema/src/auth-api.ts`

- L1: All auth endpoints incl. OAuth redirects live in api-schema (session-06 ruling 4); GitHub tokens never appear in any response type (§10)
- L39: 302 Redirect success declaration; githubStart/githubCallback are browser-navigation only, not for the HttpApi-derived client
- L47: Token-name length limit shared with the CLI argument layer so over-long names fail before any network call, not after browser approval
- L58: Token names forbid control and bidi-control chars at acceptance time (approval-text impersonation mitigation); not retroactive
- L69: Forbidden-char check shared with the CLI argument layer so authoring mistakes are rejected before any network call
- L77: Token name wire acceptance shape (§6): ≤128 chars, no control or bidi characters; shared by cliStart payload and CLI check
- L89: Token TTL fixed at issuance, intentionally asymmetric with §5 session sliding renewal; self-host adjustable acceptance policy
- L97: Explicit TTL capped at 365 days — the cap itself prevents reintroducing non-expiring tokens (L-2); shared with CLI layer
- L116: Signup policy is a per-deployment acceptance policy; never appears on chain or in signatures
- L125: Signup code binds only a size limit; real verification is the server hash comparison — format must not leak existence
- L134: Public config: client_id is public info; serverEncPubHex is the §9 key distribution channel; signupPolicy is advisory only
- L158: Token summary structurally excludes raw value and token_hash — no schema columns exist to return them by mistake
- L187: Me response includes the user's orgs because project creation needs an org id (§11-3)
- L191: tokenScopes only for token principals; lets the client compute effective permission min(scope, chain role) in advance (§9-2)
- L201: tokenExpiresAtMs discloses only the presented credential's own expiry; lets unattended PAT use arrange reissuance before a 401
- L213: providerLogin is a self-information-only snapshot used as invite-link il comparison material (§15-3)
- L223: Recovery blob is opaque ciphertext to the server; the recovery code itself never appears on the wire (§13)
- L227: Recovery ciphertext acceptance bound: AES-256-GCM ct||tag, 16 bytes to 16 KiB including the tag (§13-4 policy)
- L249: Recovery status returns registration state only — never the blob (§13-2)
- L255: Token issuance happens only through the CLI login handoff; no additional issuance UI/API is built (W0 ruling)
- L265: Auth config endpoint is unauthenticated; an unconfigured server answers 503 and directs to the setup guide
- L275: signup_code is pre-verified at githubStart with per-IP rate limit; invalid ends on a script-free guidance page, valid rides a __Host- cookie to callback
- L290: OAuth code capped at 512 chars (format undefined by spec, length only); exchange count bounded by per-IP Workers Rate Limiting
- L323: Token listing returns own metadata only, never raw value/hash; scope-limited tokens excluded to deny reconnaissance material (ruling CH)
- L336: Targeted revocation: own tokens only, uniform 404 for others/nonexistent; decision order 401 → 403 → 404 (ruling CG)
- L349: Recovery registration/reissuance is a replace upsert — the old wrap disappears at acceptance (§13-1)
- L352: strict acceptance applies only to this payload's decode/encode; the shared RecoveryWrapSchema itself is not wrapped, avoiding propagation

### `packages/api-schema/src/auth-cli-api.ts`

- L1: CLI login wire is provider-agnostic; flowToken never rides the browser channel; uniform refusal, no typed flow errors; not in session allowlist
- L39: CLI clamps pollIntervalSeconds at the 5s lower bound so a hostile/misconfigured server cannot cause a busy spin
- L48: flowId is a public correlator, 128-bit random hex per the §4-1 (1) unguessability requirement
- L51: flowToken is opaque to the CLI (server implementation detail); unauthenticated write surface binds only the size limit
- L59: cliStart is recordless (ruling DH); verificationUrl is vsig-covered and knowing it grants no polling credential
- L74: Poll pending includes the no-row case, which is the normal case of a recordless start
- L79: Approved poll result is single-issuance; the raw token appears on the wire only this once (§6/§10)
- L98: Poll pending/denied are typed states carrying no new information (§4-2); expired is typed, credential mismatch is uniform refusal
- L111: cliVerify params are all optionalKey; handler checks missing/tampered and refuses with a uniform HTML error page — JSON 400 never shown to browser
- L130: cliApprove credential is a single-use short-lived approval ticket, not a session; mismatches get a uniform error page
- L150: All CLI login surfaces are unauthenticated: recordless start, stateless vsig verify, ticket-based approve, CAS-gated single-issuance poll
- L165: CLI start issuance params follow §6 semantics; size limits bound on the wire because the surface is unauthenticated

### `packages/api-schema/src/auth-middleware.ts`

- L1: Auth middleware contract lives in api-schema; implementation (session/token resolution, CSRF header check) is a server-side Layer
- L15: CSRF header name is a shared constant so server and client cannot drift; a rename cannot silently degrade to generic 403s
- L24: AuthMiddleware contract: session cookie or Bearer PAT resolves to RequestAuth, 401 anonymous; cookie writes require the CSRF header (403 otherwise)
- L34: Middleware requires the Digest service because resolving a presented credential hashes it (§5/§6)

### `packages/api-schema/src/chain.ts`

- L1: Chain Schema checks transport shape only; §6.1 free-string consensus limits deliberately not duplicated — verifyChain's invalid-payload is the single refusal path
- L26: userId deliberately unbounded in the Schema; verifyChain checks the §6.1 free-string limit
- L28: Decoding mints the KeyFingerprintHex brand — the identity half the chain carries next to the user id
- L45: Scope consensus rules (all ⇒ empty list, ≤256, no duplicates) are checked by verifyChain as invalid-payload, not duplicated into the Schema
- L100: create_environment only via the composite endpoint (generic append rejects it); environmentId format checked here as the only wire acceptance point
- L127: delete_environment only via the composite deletion endpoint (entry + data deletion atomically); generic append rejects it
- L145: rotate_epoch entry submitted only through the composite rotation endpoint; exported for that endpoint's payload schema
- L151: rotate_epoch environmentId pinned to the create_environment acceptance format so the URL-coordinate match check has no asymmetry
- L166: Lease claim constraint size limits are consensus rules checked by verifyChain, not duplicated into the Schema
- L188: Lease policy carried as an array in as-signed order — order is part of the signed payload, so not an object
- L211: Checkpoint tuple numeric ranges, duplicates and audit_head form are consensus rules checked by verifyChain; only fixed-length hex checked here
- L227: Boundary checkpoints only via composite create/rotate endpoints; standalone checkpoints via generic append with acceptance-time content matching (§16-2)
- L236: Checkpoint environments carried as an array in as-signed order — order is part of the signed payload
- L241: Empty auditHeadHashHex means no audit-head notarization; the 'empty or 64 hex' check is consolidated into the verifyChain consensus rule
- L255: Four-eyes policy may name only this closed target set of operations (§6.2)
- L265: required_approvals '0 or at least 2' and closed-set checks are verifyChain consensus rules; only the literals are held as a type so wire matches crypto
- L283: add_device scope pair reuses the member-scope fields with the same encoding/structure rules, checked by verifyChain
- L295: revoke_device 1..256 entries and no-duplicates are consensus rules (invalid-payload), not Schema checks
- L306: propose inner op is any non-approval operation as {op, payload}; propose/approve/withdraw are not members — nesting a proposal is structurally invalid
- L322: delete_environment is structurally an inner op but never a four-eyes policy target (approval-not-required); verifyChain decides
- L336: Device-key ops can be inner ops but never four-eyes policy targets (approval-not-required); verifyChain decides
- L348: Non-negative safe integer for expiresAtMs is a consensus rule (verifyChain invalid-payload), not a Schema check
- L402: Static type check that a decoded wire value can be passed unchanged to @maruhi/crypto's ChainEntry — divergence fails compilation

### `packages/api-schema/src/data-api.ts`

- L1: Data plane: uniform 404 for non-members (§11-2); display-name 256 cap enforced by the Schema because values have no dedicated verification layer
- L92: Environment name travels as the latest verified-able metadata statement, not a bare snapshot; deletion is derived by clients from the verified chain
- L113: Composite create/rotate result: accepted chain head plus current epoch — the entry was appended atomically with the data (§12-4)
- L125: Variable version result: creation is version 1 (§12-5)
- L132: Version history is metadata only — no ciphertext or DEK, so no var.read is recorded; a declared variable has an empty list
- L143: Version values page contract (≤100 versions, ~1 MiB, at least one); an old version is trusted only as an ancestor of a bulk-pull-verified latest
- L161: Query-string version defined on NumberFromString to satisfy QueryConstraint (encode to string)
- L168: Pulled variable is self-describing via AAD in distributed form; name → variableId resolution goes through verified statements (§12-7)
- L181: Bulk pull bundles deleted variables' statements (ciphertexts deleted) as detection material for denial of deletion and unauthorized revival
- L197: Declared variables' statements are mandatory pull material for manifest digest recomputation; declared is the only legitimate valueless state
- L207: schemaPolicy bundle is advisory and unsigned — client use is UX only, never an input to verification rules
- L213: Pull manifest is required — a created environment always has one; absence is refused unconditionally (§6.3)
- L222: checkpointSnapshot enumeration bundled when a baseline exists; a valued response lacking it is refused so omission cannot skip rule 2 non-regression
- L235: Metadata-only pull carries the full §6.3 verification material without values/DEKs; the server records no var.read for it
- L249: Declared variables' statements land in the same pull column as active ones in metadata mode; the status field discriminates
- L255: Manifest is required in metadata-only mode too — metadata verification completeness is at the same level as the with-values pull
- L265: Environment create/rotate are composite chain+data operations accepted atomically; rename is a metaVersion-CAS statement; remove deletes data in the same DO transaction
- L292: Create payload uses strict acceptance — the wrapper passes onExcessProperty: 'error' into the nest (§12-10 (1))
- L301: Boundary checkpoint accepted atomically as a second entry (create = H+1, checkpoint = H+2) covering this environment's single tuple
- L318: PayloadMismatchError here means environment_id / declared head mismatch between the entry payload and the statement / manifest (§12-4)
- L323: ManifestVersionConflict not declared: creation's duplicate-environment consensus rule guarantees novelty, so a v1 manifest cannot CAS-conflict
- L331: DekWrapExistsError declared even though currently unreachable, so a future rule change cannot drop a 409 outside the contract (500)
- L338: Boundary checkpoint content matching is against the post-application baseline of the composite (§6.4)
- L342: AuditHeadNotReady (503) is a contract for other clients too; the CLI's boundary checkpoints do not notarize (empty — ruling M-b)
- L360: Rotation manifest has the new epoch baked in and reflects the epoch advance even when the meta set is unchanged (§4.3)
- L364: Rotate boundary checkpoint (H+2) values_digest covers current values at acceptance; not-yet-reencrypted old-epoch values are a legitimate state
- L377: Rotating a deleted (tombstone) environment is 404 — §7's 'all environments' does not include deleted ones
- L388: Bundled manifest verified with epoch = new_epoch after applying the entry; a 409 retry re-signs both the entry and the manifest
- L394: DekWrapExistsError declared for rotate for the same reason as create, though epoch monotonicity makes existing wraps impossible today
- L398: CheckpointStateMismatch 422 also fires when a concurrent push knocked the values_digest off; the client re-pulls and retries with a bound
- L404: AuditHeadNotReady (503) is a contract for other clients too; the CLI's boundary checkpoints do not notarize (empty — ruling M-b)
- L424: Rename bundles the manifest (manifestVersion +1, copies new envMetaSigHashHex); metaVersion and manifestVersion CAS decided in the same transaction
- L453: Composite deletion carries the delete_environment entry under strict acceptance; DELETE + body follows the deks.remove precedent
- L463: Deletion judgment order role → match → CAS → scope → verifyChain; no environment 404 (existence judged after CAS) and no DataLimitExceeded (deletion is the freed path)
- L484: A variable push is a CAS on epoch and next version; conflicts return the current values for a client retry
- L493: Creation is a Union of active and declared forms; declared is the sole exception to 'a variable without a value does not exist'; neither form can create deleted
- L512: Creation bundles a manifest reflecting the post-creation meta state — composite acceptance of every meta-changing operation (§12-5)
- L532: MetaVersionConflict declared as the CAS contract though effectively unreachable under the wire Schema (metaVersion pinned to 1)
- L543: Bundled-manifest verification and manifestVersion CAS: concurrent meta operations serialize on the per-environment manifestVersion
- L550: SchemaPolicyRejectedError: creating without varType under a locked schema policy is schema-required (§12-11)
- L567: sameValueAs is the writer's lineage self-declaration (version-1 = re-encryption, older = rollback); accepted only when < version; read only by rotation-needed detection
- L600: Version history authorization = metadata-only mode (reader, scope-agnostic); no var.read since no ciphertext is distributed
- L619: Version values authorization = with-values pull; records one var.read enumerating every returned version; out-of-range fromVersion is 422
- L641: Activation composite is declared → active only, not a generic value+meta composite — this restriction makes the §12-11 policy exemption precondition hold
- L673: A declared variable's latest is always 0, so the activation CAS forces value version 1
- L695: The v3 form doubles as rename and schema reissuance under the same acceptance rule; status must keep the current state (no transition in this form)
- L734: Deletion requires a signed tombstone statement plus manifest; v3 deletion accepted regardless of policy as a continuation statement (§12-11 reversibility)
- L752: DataLimitExceeded not declared for variable deletion: deleted is outside the metaVersion cap (§12-8), same as environments.remove
- L777: Metadata-only pull authorization is the same row as pull (read × reader); no var.read is recorded (AUDIT_SPEC §3.3)
- L791: DEK list returns the wraps addressed to the caller only — distribution is caller-only (§12-6)
- L797: DEK registration covers full-set and backfill paths; distribution is caller-only; deletion is the admin-only repair path and overwriting stays forbidden
- L810: Empty deks registration is 400 — the same 'don't silently succeed' discipline as the delete side's empty wraps
- L839: DEK deletion targets are enumerated in the body because recipientUserId (free string ≤1024 bytes) cannot be a path segment; empty enumeration is 400
- L864: Schema policy PUT requires admin scope × chain admin; session principals refused (outside §5 allowlist); payload carries no signed structure, outside the strict class
- L892: DataLimitExceeded: a DO at/above the storage refusal threshold rejects schema-policy changes too (every change adds an audit row); GET passes as a read

### `packages/api-schema/src/data.ts`

- L1: API boundary invariant: values are represented only as EncryptedPayload in data.ts; the Schema checks transport shape only, AAD binding enforced by decryption failure
- L36: Suite identifier pinned as a Literal in v1; the shape of a v2 migration is deferred until the v2 design (§12-2)
- L45: Wrapped DEK wire length is 48 bytes = 32-byte DEK + 16-byte GCM tag (CRYPTO_SPEC §5)
- L47: prev_value_sig_hash binding to version (1 ⇔ empty) is checked by signature verification, not the Schema — the Schema covers wire shape only
- L62: BoundedUserId limit aligned to the §6.1 consensus free-string limit; a narrower limit could make a legitimate chain member unrepresentable
- L71: The user_id limit counts UTF-8 bytes via a custom filter because isMaxLength counts UTF-16 code units
- L88: EncryptedPayload is the only shape a secret value takes across the API boundary (§10); for push/create the writer identity is not on the wire
- L114: Distributed payload adds writer identity at acceptance; the server-computed signed-bytes hash is NOT distributed — verifiers recompute it themselves
- L131: Version-history rows are metadata only and server-declared: clients must not base a write on them; rollback verifies its target through the value range
- L160: Meta statement signature binds name ↔ ID and state authenticity; names are NFC-normalized by the client before signing — the server only checks, never normalizes
- L171: NFC conformance of statement names is checked by the server's 422 (NameNotNfc), not by the Schema
- L174: Layout v3 adds the declared state for variable statements; environment statements stay always active — environment deletion is the chain op, not a statement
- L180: metaVersion 1 is creation-only, so the rename/delete request forms are pinned to metaVersion >= 2
- L205: Lifecycle forms pinned per operation so 'deleted at creation' or 'active at deletion' is refused by the Schema (400), not a server check
- L224: The environment distribution side carries creation and rename forms — the self-describing form of a stored statement, always active
- L232: Layout v3 scope: v1 statements keep the traditional field set (strict acceptance enforces absence); environment meta statements stay v1
- L240: varType is a closed set; no validation DSL, enum, or default is introduced (ruling CT); membership decided by Schema validation (400)
- L247: layoutVersion has no pinned upper bound in the Schema; the supported-range check is an acceptance-time typed 422, not conflated with a Schema 400 / tampering
- L263: maxAgeDays absence on a v3 statement is refused by an acceptance check (422 payload-mismatch, before signature verification), not a Schema 400
- L279: v3 schema fields are all required fail-closed; description limits are a §12-8 acceptance check (422), deliberately a different category from the display-name 400
- L307: Declaration statement is the sole exception to 'a variable without a value does not exist', layout-v3 only; creating a deleted variable is structurally refused
- L329: v3 rename keeps the current status; a status mismatch with the preceding statement is 422 — transitions cannot happen in this form (§4.2)
- L357: Deletion statement's name is the immediately preceding active name (§4.2)
- L363: Deleting a v3 variable is always v3 (layout monotonicity); schema fields and layout must keep the preceding statement's values unchanged
- L387: Name-returning responses carry distributed statements instead of bare name snapshots — clients must not trust a name that did not pass statement verification
- L398: Variable-side distribution carries 3 states; declared is layout v3 only (§4.2)
- L402: v3 carriage presence binding: on a v1 distribution all 5 schema fields are absent; on v3 all 5 are present (maxAgeDays null = no declaration)
- L431: Manifest signs the full picture of the environment's meta state with the current epoch baked in — the meta layer's freshness anchor (§4.3)
- L446: Manifest epoch is the current epoch at issuance at the declared head — the meta layer's freshness anchor (§4.3)
- L457: Creation manifest pins manifestVersion 1, empty variable set, empty prev — a manifest-uninitialized state cannot structurally exist on a new environment
- L469: manifestVersion 1 exists only inside the environment-creation composite; declared to any other operation it can only meet the CAS as latest 0, which never occurs
- L484: EnvironmentManifest issuance form: the contract is issuer = calling principal (§12-5 (1))
- L487: Distributed manifest absence is unconditional refusal (§6.3) — no warning-downgrade branch; required on the wire since a created environment always has one
- L510: Required manifest uses annotateKey so an omitted manifest is refused as manifest suppression (§6.3), not reported as a bare missing-key shape error
- L526: Checkpoint value-snapshot enumeration is bundled into value-bearing responses only; metadata-only pull is out of scope (it carries no values)
- L549: Snapshot chain position is an advisory locator only (ruling S); the verification baseline is always the client's own chain-derived latest covering checkpoint
- L571: Schema policy is a write acceptance policy; not placed on the chain nor an input to verification rules — distribution is advisory
- L584: Wrap recipient is typed by class: the class decides the brand at decode — a non-fingerprint server recipient is malformed, a 32-hex member id stays a UserId
- L610: Wrap registration requires both user id and enc key to match the chain-derived member exactly; recipientUserId limit aligned to §6.1 so legitimate members stay registrable
- L647: Distributed wrap carries the registration signature and signer identity so the client can verify attribution against the chain history (§5.1)
- L656: recipientEncPubHex is the device axis: an open failure on another device's row is not a poisoned wrap
- L673: Wrap reference is the unit of the admin-only §12-6 repair deletion (delete poisoned wrap, re-register via append); server rows carry the FP in recipientUserId
- L697: LeasedDek is deliberately not a RecipientDek: lease wraps are server-generated and never persisted, so no §5.1 signature or signer identity — types kept apart against misuse

### `packages/api-schema/src/devices-api.ts`

- L1: Device registry is advisory only — never an input to verification or authorization; approval is not an API (FP recompute + add_device); no audit events by design
- L39: Device registry row cap is an acceptance policy (§13-11), not a consensus rule
- L46: Device label reuses the §6 token-name acceptance discipline (no control/bidi chars, ≤128); empty is not allowed — a row carries a human-chosen name
- L60: Device tokenId is advisory only (§6); never an input to authorization
- L80: Approving client recomputes the FP from the response's public key and ignores anything not matching the human-carried FP — a server key swap is caught (§13-11)
- L97: Request-creation result not shared with the guardian handoff's result schema because the expiry's meaning differs (DK K9-4)
- L112: Device endpoint HTTP statuses follow the §13-11 table: reads and request creation/listing 200; writes, deletions and cancellation 204
- L119: Registry reading is open to every authenticated principal, session principals too (the §5 allowlist)
- L125: Registry register: fp must equal the value recomputed from the body's public key (400); rows capped at 32 per user (429 — updates do not count)
- L131: Registry registration uses strict acceptance — registering a public key is the key-declaration class; unknown fields are not silently dropped
- L139: Registry deletion removes an advisory only, independent of chain revocation; 404 when absent
- L148: Add-request creation success is the HttpApi default 200 (same as §13-7); conflict with an existing request of the same FP or registry row is 409
- L159: Add-request listing is caller-only (for the approving device); expired rows are not included
- L167: Unknown and expired add requests are a uniform 404
- L176: Add-request cancellation is caller-only; the client removes the request after approval; 404 when absent

### `packages/api-schema/src/errors.package/attestation.ts`

- L1: Attestation errors carry only identifiers and counters — no fragments of plaintext values or key material
- L9: Attestation reject reasons fold crypto's detailed reasons like value signatures; chain-head-unknown includes seq ahead of head (no client re-sync branch on the server)
- L38: Attestation regression 409 returns the stored seq — a regression must surface, not be silently swallowed; resubmitting the same seq is idempotent (204)
- L52: Attestation rate limit is a per-member fixed window (drafted value: 60 per hour — §16-1)

### `packages/api-schema/src/errors.package/auth.ts`

- L1: Auth errors carry only identifiers and counters — no plaintext values, key material, or external token values
- L16: 403 reason codes: session-not-allowed is a uniform response computable from the request alone (existence concealment); insufficient-scope is chain-derived, not folded into 404
- L43: mirror-read-only: the project is a read-only mirror of another deployment — every write is refused after authentication; reads and leases are served
- L59: AuthFlow 400 carries a reason code only — the presented external ID / token values are not carried
- L71: Setup-incomplete reasons: OAuth unconfigured, or the rate-limit binding absent — the §4-1 (1) binding pattern fails closed on a missing binding
- L86: SetupIncomplete 503 directs the user to the setup procedure; /auth/config success semantically means the OAuth App is registered
- L98: Auth rate limit applies even on the default deployment because unauthenticated surfaces consume the OAuth App's shared quota / CPU / D1 writes; retryAfterSeconds is a hint
- L114: CliFlowExpired is a typed termination instruction to a legitimate flowToken holder; it discloses nothing about flow state
- L128: CliFlowRejected is a uniform refusal: MAC mismatch, flowId mismatch, re-poll after consumed, and CAS loser all get the same response (no flow-state oracle)
- L149: TokenNotFound is uniform for another user's or a nonexistent token id, and does not copy the target id into the error
- L170: Recovery fetch rate limit (§13-3); retryAfterSeconds is the remaining seconds of the fixed window

### `packages/api-schema/src/errors.package/chain.ts`

- L1: Chain errors carry only identifiers and counters — no fragments of plaintext values or key material
- L10: Chain invalid reason list kept in sync with crypto's ChainInvalidReason via satisfies; substance lives here so api-schema does not depend on crypto at runtime
- L58: Reverse static check: if a reason code is added on the crypto side, this fails to compile
- L83: ProjectLimit returned only for a fresh genesis — the §11-3 repair path is never blocked by the tenant quota; carries the limit only
- L95: ChainHeadConflict returns the current head so the client can fetch, re-verify, and retry
- L116: Chain entry canonical byte length cap is the §6.4 acceptance policy (1 MiB)
- L123: Chain capacity acceptance policy: 10,000 entries / 12 MiB cumulative canonical bytes (§6.4)
- L133: Composite-only ops rejected on the generic append so entry-plus-data atomicity cannot be bypassed; checkpoint is explicitly not a target of this error
- L152: Device limit is an acceptance policy, not a consensus rule; counted on chain-derived state before the entry — revoked devices do not count
- L165: Proposal limit reasons: pending-proposals (limit = max live count; completing/withdrawing frees a slot) and proposal-lifetime (limit = max lifetime in ms)
- L180: ProposalLimit is an acceptance policy, not a consensus rule — an entry valid under §6.2 may still be refused here

### `packages/api-schema/src/errors.package/data.ts`

- L1: Data-plane errors: EnvironmentNotFound/VariableNotFound returned only to chain-derived members — project existence concealment (§11-2) takes precedence
- L25: Resource conflict reasons: exists = id in use, retired = tombstoned id may not be reused, duplicate-name = display name taken in the uniqueness scope
- L37: Environment conflict keeps only duplicate-name as a data-plane check — id uniqueness was absorbed into the chain consensus rule duplicate-environment
- L59: Push CAS failure: the server cannot renumber because the version is part of the AAD — the client re-encrypts under the next version and retries
- L70: Epoch conflict: after a rotation the client fetches the new DEK, re-encrypts and retries under currentEpoch
- L91: Value-signature reject reasons with a fixed check order (signature → unknown head → state mismatch); only the spec's three reasons — a fourth would be a wire change
- L113: ValueSignatureRejected carries a reason code only — never signature bytes, hashes or ciphertext fragments
- L123: Meta-statement reasons add layout-regression (layout monotonicity) and unsupported-layout — an honest 'server update required' failure, not collapsed into invalid signature (ruling CR)
- L151: MetaStatementRejected carries a reason code only — never signature bytes or hashes
- L161: schema-required is a one-time check at creation in a locked project — a later schema reissuance can still downgrade
- L179: A plain value push to a declared variable is refused — the first value must arrive through the activation composite
- L190: Description reasons: single-line pinned (ANSI/newline spoofing rejected at acceptance); NFC not required — a deliberate difference from name
- L210: Manifest reject reasons: digest mismatch recomputed from post-acceptance meta state; checkpoint binding/equivocation/regression reasons from §4.3
- L242: ManifestRejected carries a reason code only — never signature bytes, hashes or digests
- L252: Checkpoint mismatch reasons: manifest/values-digest matching against acceptance-time state, audit-head unknown/stale position floor; deleted-env tuples fail chain verification instead
- L303: AuditHeadNotReady body is empty — carrying progress would disclose ordinal information about the audit row count (§7 non-leakage); shared by every audit-head path
- L320: ManifestVersionConflict carries the latest manifestVersion number only, never the winner's hash; a retry re-signs both the statement and the manifest
- L333: MetaVersionConflict carries the latest metaVersion number only — the client refetches and verifies the winner and computes prev itself (§12-5 409 discipline)
- L346: NameNotNfc: normalization is the signing client's responsibility — the server only checks and never normalizes (byte-exact signatures)
- L358: Value ciphertext cap is the §12-8 acceptance policy (64 KiB)
- L372: meta-versions resource applies the same 1,000 value as 'versions / variable' to rename/delete statement rows — blocks DO-storage bloat from rename spam
- L377: environment-ciphertext-bytes = the latest version of every active variable (what one pull or lease carries); refused only when a write grows the sum past the limit
- L386: DO storage guard: at the measured-size refusal threshold (drafted 9 GB) content-growing surfaces are refused; reads, deletions, revocations and rotations keep being accepted
- L396: project-storage-bytes limit is a threshold on measured storage, not a count the request adds to — freeing space is the way back under it

### `packages/api-schema/src/errors.package/deks.ts`

- L1: DEK errors carry only identifiers and counters — no fragments of wraps or key material
- L11: DEK wrap reject reasons map by recipient class: server class uses recipient-not-granted / scope-out-of-range; member scope-out-of-range is the same reason (recipient set R(E))
- L33: DekWrapRejected enumerates the §12-6 violation conditions: non-member recipient, inexact initial coverage, duplicate recipient, epoch out of range, bad registration signature
- L46: Wrap overwriting is forbidden — replacing a valid wrap with an undecryptable blob would be an undetectable availability attack; storedRecipientEncPubHex comparison is exact
- L70: DekWrapNotFound: repair deletion targets must exist — silently succeeding would let an admin believe a poisoned wrap was removed when it was not

### `packages/api-schema/src/errors.package/devices.ts`

- L1: Device errors do not copy the requester's public keys/FPs into the error — the same non-reflection discipline as TokenNotFound; the registry is advisory
- L12: DeviceNotFound is uniform for absent and expired; the registry is per-user, so no other user's rows are ever reachable
- L23: The registry never stores a fingerprint the server did not derive itself — :fp must equal the recomputed fingerprint from the body's public keys
- L34: Device registry conflict reasons: request-exists (unexpired request pending) vs device-registered (approve or delete it first)
- L51: Device registry 429 reasons are an acceptance policy, not a consensus rule: 32 rows per user; 5 add requests per hour fixed window

### `packages/api-schema/src/errors.package/export.ts`

- L5: ExportChanged: the project changed between pages of one export — the export is not resumable, the client starts over from the first page (ruling C)
- L17: Export rate limit is judged after authorization, like the lease windows

### `packages/api-schema/src/errors.package/invites.ts`

- L1: Invite errors: InviteNotFound carries no project coordinates at all — holding the token is the capability; unknown tokens must not let project existence be inferred
- L12: InviteNotFound carries no fields, for existence concealment
- L22: InviteGone reasons are observable only by the capability holder; they let a legitimate acceptor detect a first-come acceptance as a noisy race; order is state → expiry
- L44: Invite signature failure folds signature-by-another, transplantation, and key substitution into one error — signed_bytes are reconstructed from the stored row and calling principal
- L61: Invite ids are client-assigned and link_pub is UNIQUE; on conflict the client reassigns / regenerates and retries
- L79: Invite issuance window is a fixed window, 30 per hour; retryAfterSeconds is the remaining seconds of the window

### `packages/api-schema/src/errors.package/key-wraps.ts`

- L1: Key-wrap ledger lookups fold not-the-ward-or-guardian, unknown, and revoked into the same uniform 404 (existence concealment)
- L19: HandoffNotFound is the §13-7 uniform 404: unknown, expired, or not visible to the caller (neither ward nor one of the ward's guardians)
- L40: Key-wrap policy reasons enumerate the §13-7/§13-8 caps and structural conditions (share counts, guardian conditions, source-mismatch, approvals cap, duplicate-id)

### `packages/api-schema/src/errors.package/lease.ts`

- L1: Lease errors must not carry the OIDC token's value, claims, or external identifiers; existence concealment folds policy/scope/grant/unknown-project into 404s outside this file
- L16: Lease unauthorized reasons are attributable to the presented token alone; token-replayed is checked after authorization (first-use binding) and keeps existence hiding intact
- L64: LeaseUnauthorized covers only credential-attributable failures — everything about this project's grant, policy and scope is 404 (§14-1 existence concealment)
- L79: Lease unavailable reasons keep verification fail-closed while reporting retryable/setup conditions distinctly (JWKS outage is not a bad credential; missing server key points to setup)
- L106: LeaseUnavailable 503 is distinct from 404 on purpose — reaching it already means the caller matched an on-chain lease policy, so it leaks nothing new
- L117: Lease rate-limit scopes differ in remedy: the project window drains on its own; a shared-egress fleet hitting the per-IP limit needs the operator to raise the binding limit
- L130: The lease project window is judged after authorization — judged earlier, a 429 would leak that the project exists (§11-2); the source-address window leaks nothing and is judged first

### `packages/api-schema/src/errors.package/mirror.ts`

- L6: Mirror sync reject reasons: every reason but sequence-mismatch discards the staging in progress; a mirror that syncs cannot be a source (its rows are renumbered at every commit)

### `packages/api-schema/src/errors.package/rotation.ts`

- L7: RotationFlagNotFound: dismissals must target live flags — a cancellation event without a live target would silently record nothing meaningful
- L19: Sealed value proposal reject reasons are judged after authorization, so a reason leaks nothing an authorized caller would not learn from a successful call
- L46: storage-limit reason: the proposal's sealed values would cross the §12-8 ciphertext cap, or the project is at the storage-total rejection threshold (also the pre-flight's answer)
- L50: variable-pending is the pre-flight (O-4): a pending proposal already targets the variable, so the job stops before the issuer is touched
- L53: mirror-read-only rides the proposal-reject vocabulary rather than Forbidden because the workload's credential is not a member's; the job mints against the source deployment
- L66: RotationProposalNotFound folds unknown, already resolved, and expired into one 404 so a resolution cannot probe which

### `packages/api-schema/src/export-api.ts`

- L1: Export delivers the DO content exactly as stored — nothing is decrypted, re-encrypted, or signed; authorization is chain owner × token admin (the strongest read a project has)
- L35: Export cursor is opaque — the server's encoding; the client never interprets it
- L42: ExportHead carries the watermarks of the state the export is taken from; the cursor binds them and the trailer repeats them
- L47: mutationSeq is the project DO's mutation counter at export; a mirror records it with the replica as the sync's no-change check
- L49: mirrorOf is read in the same call as the marks (switch-over): a last page carrying it with marks unchanged says no write landed on this server after the export
- L72: Export identity is keyed by the chain's user id — the login lookup key (§2)
- L82: Export identities companion: unlinked members cannot be pre-bound at the destination — they stay chain members nobody can log in as until the ruling G-2 follow-up
- L92: The companion's chainHeadSeq binds it to the export file whose trailer names this head (ruling H revision)

### `packages/api-schema/src/hex.ts`

- L1: Hex naming convention: same meaning + width merges into one name; same width, different meaning keeps domain names; aliases centralized here to stop proliferation
- L42: KeyFingerprintHex here is format only — fields landing where the brand is required decode with core's KeyFingerprintHexSchema instead
- L78: PositiveInt is kept in hex.ts as the shared definition for the chain-head field family (the hash + seq pair)

### `packages/api-schema/src/index.ts`

- L1: api-schema boundary invariant: API-boundary types are the EncryptedPayload family only — no type representing a plaintext secret belongs here

### `packages/api-schema/src/invites-api.ts`

- L1: Invites: the server does not verify the issuance signature (its verifiers are inviter and acceptor) and never returns an invitation secret; holding the link key is the accept capability
- L55: Owner is never granted via the invite path (§15-1)
- L58: Invite scope environment cap is 256 — the same as grant_server's scope (§6.1/§6.2)
- L61: Invite scope gets format checks only — no existence check; verifyChain checks it as a consensus rule when the add_member is accepted
- L94: Invite status: expired is derived from expiresAtMs, not a stored status (§15-1)
- L97: Invite id is a client-assigned ULID covered by the issuance signature
- L102: The server only stores and distributes the issuance statement — it does not verify; the inviter client re-verifies under its own sig key before add_member
- L128: Invitation list rows carry the issuance statement and acceptance block as the inviter client's re-verification material (reconstructing signed_bytes) and FP word display
- L165: Invite issue response is expiry only — there is no token-equivalent secret (§15-1)
- L170: Accept response is a minimal form on purpose: it must not create a surface where server-declared display information is trusted
- L182: Only an owner may issue an admin-role invite (same level as the §6.2 add_member permission table); accept is a single-use CAS; keys get a format check only
- L202: Invite creation/acceptance payloads use strict acceptance — §15-2's key-declaration class (§12-10 (1))

### `packages/api-schema/src/key-wraps-api.ts`

- L1: Key-wrap ledger: every wrap/segment is opaque ciphertext to the server, KEK material appears in no type; the handoff's E.pub never touches the wire (§8.4)
- L34: Guardian mode semantics: any = 1-of-n / all = n-of-n threshold (§8.3)
- L37: Key-wrap ledger caps are an acceptance policy (§13-8), not a consensus rule
- L41: Guardian device cap derivation: 5 logical segments × 16 active devices per guardian (§12-8); the same share_index appears once per guardian device
- L49: Approval cap is set to the structural ceiling itself and made a derived value so the policy declaration and the effective bound agree (PR #168 review)
- L76: Share ciphertext is an HPKE single-shot Seal over a 32-byte plaintext = 32 + 16 tag = 48 bytes
- L84: Passkey label uses the same acceptance discipline as token names (no control/bidi characters, ≤64 chars)
- L89: Passkey label pattern shares TOKEN_NAME_FORBIDDEN_CLASS so §13-9's 'same discipline as token names' cannot drift
- L103: wrapId is client-assigned because the wrap's AAD binds wrap_id — a server-assigned id would not be known before encryption; a collision is 422 duplicate-id
- L130: The same logical segment share_index is sealed to each of the guardian's active device keys, so it appears once per device
- L147: groupId is client-assigned (ULID) — the AAD / segment info binds group_id, same as passkey wraps
- L162: Guardian group distribution form carries no segments
- L181: Status carries prfSaltHex because the restoring client needs the public PRF salt before the PRF ceremony (§13-7 revision)
- L209: wardLogin is a display snapshot of provider_login, not an identifier (§2)
- L225: deviceShares holds all of the caller's device rows (FP ascending); the client picks the row matching its on-hand device-key FP (DK K3)
- L242: The old device-path handoff source 'device' was removed (DK K4) — the Schema refuses it on the wire (400)
- L263: Approver FP is self-declared; the ward client matches it against the chain-derived FP; the value lands in the auth.key_handoff_approved audit row
- L293: Handoff create result not shared with the device-add request's result schema because the expiry means something different (DK K9-4)
- L306: Key-wrap ledger endpoints are token-only (* × admin) except status, which any authenticated principal (session included) may read
- L319: Passkey wrap registration uses strict acceptance — a wrap is a registration of key material (§12-10 (1))
- L375: Handoff creation payload is outside strict scope: it carries only request_id (derived from E.pub) — no signed structure, ciphertext, or key material
- L393: Handoff approval uses strict acceptance — a re-sealed segment / KEK_h is ciphertext of key material (§12-10 (1))

### `packages/api-schema/src/lease-api.ts`

- L1: The lease group alone declares no AuthMiddleware: the credential is the OIDC token bundled in the request; sessions and API tokens are not used (§14-1)
- L42: oidcToken capped at 16 KiB and charset-narrowed in the Schema because it has no dedicated verification layer (same discipline as display names)
- L57: Lease request: the ephemeral private key never leaves the workload and dies with the job, so the response is worthless to anyone else (§9.1)
- L68: Lease response bundles the whole chain (the chain API 404s non-members) and leases instead of stored deks; the workload must run the §9.1 verification duties before using anything
- L91: The whole chain is bundled in the lease response; the workload pre-pins the genesis and must not trust a server-declared head
- L100: Declared variables in lease responses follow the §12-7 distribution rule — statements only, as material for manifest-digest recomputation
- L109: Lease manifest is required — a missing one is refused, same as pull (§6.3)
- L117: Lease checkpointSnapshot: a response lacking the enumeration is refused while a baseline checkpoint exists on the bundled chain; absent with no baseline is a warning (§6.3 SHOULD)
- L128: Lease decision order (§14-3): OIDC 401 → policy/scope uniform 404 → first-come binding → existence 404 → rate limit 429 → server wraps 503; the server never decrypts a value
- L145: Sealed-proposal mint reuses the lease credential (one token, one key); the server never touches the server key on this path — the first-come binding refuses token copies before anything is stored
- L159: Mint pre-flight runs every check needing no sealed value so a CI job learns of refusal before the issuer is touched; nothing is stored, but the first-come binding is taken
- L173: Pre-flight recipients are checked against W(E) before the issuer is touched; the bound is the §12-8 DEK-wrap row cap, set above the chain capacity for the same reason as the mint's wraps
- L186: Pre-flight 'passed' means the proposal would be accepted as far as its content is not involved
- L200: The mint folds unknown project into the same uniform 404 as the lease (§14-1 existence concealment)
- L234: Lease payload strict acceptance: the shared LeaseRequestSchema itself is not wrapped; strict covers only this payload's decode/encode, not success/error encodings
- L242: All lease-path absence causes fold into one 404 kind; EnvironmentNotFound is deliberately not declared — two 404s would give the implementation a choice of which to return

### `packages/api-schema/src/membership-api.ts`

- L1: Membership API-boundary invariant (§10): no type here represents a plaintext secret, DEK, or master private key — chain entries are signed public data
- L62: Head attestation submission: the attester is the calling principal — the wire has no attester field (§12-5's signer rule)
- L74: Distributed attestation omits the server's acceptance time — it confines the action information an attestation carries to the reached point of chain sync (§16-1)
- L92: Omitted attestation distribution is §6.3's normative non-guarantee (G8), so an empty attestation set is not refused
- L107: Project list role is the chain-derived role at read time, not the D1 projection value (the projection holds no role); it is a server-declared display value
- L120: Project list is a deliberate minimal form: org membership, creation time, and head info are absent so cross-org members learn nothing about other orgs (ruling BK)
- L133: Membership endpoints: composite-only ops are refused on the generic append (CompositeRequired); standalone checkpoint authorization splits on empty (member) vs non-empty (admin) audit_head_hash
- L164: Genesis append payload uses strict acceptance — the chain-append surface carrying a genesis (§12-10 (1))
- L172: Project cap judged after the org permission check (403) — principals outside the org are not told whether the cap is reached
- L181: Project list has no target designator, so a 404-family error structurally cannot exist; token principals get only the intersection with their scopes
- L205: Malformed CAS parent head values are dropped by the schema boundary's 400 — a deliberate acceptance change
- L218: Non-empty audit_head_hash acceptance is fail-closed: audit-head-unknown/stale are never judged on a stale derived column; bounded extension unfinished is a retryable 503
- L225: ProposalLimit is propose's acceptance policy (32 pending, expires_at_ms capped at 30 days), not a consensus rule
- L228: DeviceLimit is add_device's acceptance policy (16 active devices / member / project), not a consensus rule
- L232: Storage guard: on a DO at/above the threshold, access-widening add_member / grant_server are refused; remove/revoke/change_role/checkpoint are still accepted (explicit enumeration)
- L243: Attestation submission authorization is read × reader or higher (only one's own signed attestation can be written); regression is 409 returning the stored seq, same-seq resubmission is idempotent 204
- L252: Attestation payload uses strict acceptance — a mutation carrying a signed structure (§12-10 (1))
- L268: CLI login group is entirely unauthenticated — the credential is the flow credential (UNAUTHENTICATED_ENDPOINTS)
- L275: schemaPolicy group: session principals are refused on both GET and PUT — outside §5's allowlist
- L280: Key-wrap ledger group: only status is session-allowed
- L282: Device registry group is advisory; only reads are session-allowed
- L286: Export group is owner × admin scope, never session-allowed
- L288: Mirror group is never session-allowed
- L290: The lease group is the only unauthenticated group — the credential is the OIDC token itself (§14-1)
- L292: ProblemDetails converts framework-level failures only, without includeDetails; declared endpoint errors are NOT converted — their bodies are the AUTH_SPEC contract (pinned by test)
- L301: Span redaction names are declared at the API definition because the framework's UrlParams defaults cover only AWS/GCS signature parameters — code/state/signup_code/vsig are the gap
- L317: Load-time sweep asserts security-critical payloads refuse unknown fields at import; success/error encodings are deliberately not made strict (TaggedError stack metadata would 500)
- L325: Load-time sweep checks the session-capability declaration agrees with the registered endpoint set; unlisted = refused (fail-closed) is guaranteed by server-side matrix tests

### `packages/api-schema/src/mirror-api.ts`

- L1: Mirror design: the mark lives in the DO (ruling A), marked projects refuse writes (B), the replica arrives as export pages (D), unmarking promotes to primary (C)
- L35: Mirror page line bound = the export's 2,000-row bound plus one table line per snapshot table and the header/trailer
- L50: MirrorSyncRecord: attestationMark is the sync's no-change check (ruling H revision); ownAuditRows counts the mirror's own audit rows re-appended after the replica's (ruling G revision)
- L63: Mirror mutationSeq is the source's mutation counter the replica was exported at — the sync's no-change check (ruling H revision, round 3)
- L68: Mirror status visibility: the audit seq and attestation mark are shown to admins and owners only (AUDIT_SPEC §7); every member sees the chain head
- L79: Mirror mutationSeq is admin/owner-only: every write moves it, so it covers what no audit row records
- L85: Mirror status: mark, source, and chain head are readable by every member (the fallback read checks them before trusting a mirror); audit seq and attestation mark are admin/owner only
- L168: Mirror page staging in progress is growth under the §12-8 storage guard (DataLimitExceeded applies)

### `packages/api-schema/src/rotation-api.ts`

- L1: Rotation flags are a standalone derived view with class-1 visibility — detection exists to prompt rotation and would not work admin-only; dismiss is a dedicated operation endpoint (no raw-event append)
- L47: Flag basis semantics: read = the removed subject verifiably fetched the ciphertext during an interval; readable = it could have (§4.1 step 3)
- L54: Flag trigger vocabulary: remove_member, change_role (demotion below member or scope narrowing), revoke_server (§3.3 payload.trigger)
- L68: Flag view expands the stored per-environment aggregate back to per-pair flags; no audit seq is carried — gapless ordinals would leak the count of class-2 rows (§7)
- L94: reopenedByVersion: a flag resolved then effective again because a push restored a pre-flag value; a later re-encryption of the restored value keeps it
- L118: Proposal id is 16 random bytes as lowercase hex, chosen by the minting workload (§5.3)
- L124: Proposal facts are shown to members verbatim after display neutralization; bounded and free of control characters at acceptance (§14-5)
- L135: Sealed value bounds: the §4 value cap (64 KiB) bounds the whole ciphertext; the plaintext is at least one byte (17 to 65,536 bytes as hex)
- L146: Sealed wrap has no registration signature and no signer — the minting workload holds no on-chain key; attribution is the lease's claims digest recorded beside the proposal
- L165: Proposal wraps are capped at the §12-8 DEK-wrap row cap — the same bound as the preflight recipient set, since the mint's wraps carry that set
- L185: Proposal lifetime: the server sets the expiry instant from expiresInDays — a client clock plays no part (ruling O revision)
- L205: A pending proposal as a member sees it carries only the caller's own wraps; claimsDigestHex + grantChainSeq identify the minting workload (same cross-check as server.lease_issued)
- L235: Resolution semantics: accepted names the versions the member pushed — the resolution creates no version; rejected carries nothing
- L262: An empty dismissal enumeration is a Schema-validation 400 — the same 'never silently succeed' discipline as deks.remove
- L272: Dismissal aimed at a pair with no effective flag refuses the whole request (all-or-nothing)
- L278: Proposal listing: read × member or above; out-of-scope environments are filtered out and only the caller's own wraps travel; session principals refused
- L289: Proposal resolution: write × member or above × environment in scope; accepted is checked against the stored versions the member pushed just before

### `packages/api-schema/src/session-capability.ts`

- L1: Session allowlist is fail-closed by design; this module's list is the only source of truth because an AST annotation can silently lapse under check composition — effectiveness is matrix-test guaranteed
- L29: Session allowlist contents follow §5; audit.auditHead is deliberately unlisted (no consumer on the Web — session-39 §10-4)
- L53: keyWraps status is session-allowed because it carries no wraps or segments; register/get/delete/approve are device-only = unlisted
- L57: devices list is session-allowed: it carries only display names, key FPs, and public keys — no secrets; writes are device-only = unlisted
- L75: Every endpoint must either carry AuthMiddleware or be listed unauthenticated; the sweep refuses dual membership and non-membership at load time (fail-closed)
- L92: CLI login surfaces are unauthenticated (flow credentials, not a session) — never add them to SESSION_ALLOWED_ENDPOINTS
- L101: The sealed-proposal mint and pre-flight are unauthenticated-surface entries because they use the same OIDC credential as the lease (§14-5)
- L117: The sweep takes a structural slice of HttpApi because the concrete HttpApi type is invariant in its group union (same reason as strict.ts)
- L130: Session-capability sweep asserts allowlist entries are real AuthMiddleware endpoints and every no-middleware endpoint is consciously listed; no refused-surface enumeration — the predicate carries the default refusal

### `packages/api-schema/src/strict.ts`

- L1: Since Effect rc.113 parseOptions annotations are not read by the parser, strict acceptance is a wrapper, not an annotation; HttpApi.ParseOptions and API-wide strict are rejected (strict error encoding would 500)
- L42: The sweep's probe key uses the same name as the fixed acceptance-path test (__maruhiStrictProbe)
- L48: The sweep takes a structural slice because the concrete HttpApi type is invariant in its group union, so HttpApi.Top is not usable as a parameter type
- L68: strictPayload contract: do not put HttpApi.ParseOptions on the endpoint (strict-encoding a TaggedError fails into HTTP 500); shared component schemas stay unwrapped
- L85: Unknown on both sides of the wrapper so encode sees the extra keys (Schema.toType would drop them first and strict encode would succeed); the type stays the inner schema's
- L109: The security-critical payload endpoint enumeration is the §12-10 (1) classes projected onto implemented endpoints
- L135: variables.activate is in the strict list — the activation composite belongs to §12-10 (1)'s 'value push / meta operations' class
- L141: Key-wrap ledger endpoints are strict: wraps / segments / re-sealed values are ciphertext of key material
- L145: Device registry endpoints are strict: registering public keys is the key-declaration class (never silently drop unknown fields)
- L149: Lease propose/preflight are strict: the mint carries ciphertexts of credentials and the resolution names pushed versions
- L156: Mirror pages are strict: a replication page carries the source's chain, ciphertexts and wraps (§11-7)
- L160: Every payload-bearing endpoint must appear in exactly one of the strict / exempt lists — the sweep fails closed so adding an endpoint forces a conscious strict decision
- L172: CLI login endpoints are strict-exempt: the pre-auth handoff surface carries no signed structure, ciphertext, or key material; approve's handler uniformly refuses mismatched values
- L180: deks.remove is strict-exempt: it carries only coordinate references to the wrap to delete (the §12-6 repair path)
- L182: rotation.dismiss is strict-exempt: it carries only an enumeration of (environment, variable) identifiers (AUDIT_SPEC §7)
- L184: schemaPolicy.set is strict-exempt: it carries no signed structure; the 2-value Literal closes Schema validation
- L187: keyWraps.handoffCreate is strict-exempt: it carries only request_id (the SHA-256 of the ephemeral public key) — no signed structure, ciphertext, or key material
- L191: mirror.mark is strict-exempt: the mark names a source origin only (§11-7)
- L195: The strictness assertion assembles the decoder the way HttpApiBuilder does (a union, no options); an AST parseOptions annotation does not satisfy this check
- L213: Schema.Top's DecodingServices is unknown; security-critical payloads require no services, so the builder's Union is treated as a closed decoder
- L238: The strict sweep machine-enforces endpoint classification instead of leaving it a process obligation; query/headers blind spot is named, and such endpoints must not receive HttpApi.ParseOptions
- L270: Exempt entries get the same existence check as strict ones: a lingering exemption for a removed surface would let a later security-critical surface masquerade as deliberately exempt

### `packages/api-schema/src/sweep.ts`

- L1: Sweep helpers share only the HttpApi traversal shape; the per-endpoint check stays with the caller (the concrete HttpApi type is invariant, so a structural type is used)

### `packages/core/src/audit-payloads.ts`

- L1: Audit payloads are per-event Schemas enforced at each store's single serialization point; the identity rule gate — an append-only row never carries a provider identity (§1-2)
- L46: AuditText is a guard against the direct mistake, not a sound exclusion — a union with plain string widens; the per-event key set and runtime check are what close a payload
- L67: rotation.recommended enumeration discipline: non-empty and strictly ascending by variableId (which also makes it duplicate-free), as an identity guard composing as Schema.refine
- L99: Chain mirror payload: an inner operation applied by a completed approve is written at the approve's seq with viaProposalSeq added (PF1)
- L121: ROTATION_CONNECTORS is the single definition — the api-schema wire literal and the server's stored-row check derive from it
- L134: Lease denial reseal-* reasons are built by the server as reseal-${failure} from ResealFailure and must type-check against this set, so neither side can drift
- L160: everyOf makes the runtime list complete against its type: a missing member makes the argument never, an extra fails the element constraint — the list cannot drift
- L203: dek.deleted: the admin repair path has no payload; the cleanup on re-add (actor system) names its cause
- L207: rotation.recommended aggregate form: epoch and target stay columns (per-environment invariants) and are not repeated per element; the enumeration is non-empty and ascending+unique for row_digest fixity
- L318: Login payload copies differ by flow: a Web login copies the session id hash; a CLI login the flow id
- L323: auth.login_failed is unauthenticated: the kind name and the reason only — never the presented external id
- L326: Only the Web OAuth signup can be denied — the CLI handoff never creates an account (AUTH_SPEC §4)
- L333: replacedTokenId is added by the SQL of a same-name rotation — the row that actually vanished
- L341: auth.identity_linked records the provider's kind name only — provider_user_id and the login are never recorded (§3.1)
- L374: D1 rows have no actor key column, so the approving device's fingerprint rides the key_handoff_approved payload
- L382: A signup consuming an invite names the invite row (an internal ULID); a restore marks the import in user_created's payload
- L386: A personal org's name derives from the login, so it is never copied into org.created
- L394: invite.accepted records the accepting key's fingerprint only — not the backing source's login, the link key, or a signature (§3.2)
- L420: PayloadField is conditional: the payload field is required when the event always writes one, optional when it may write none, absent when it never writes one
- L444: assertPayload violations are producer bugs and throw (a defect — the append and its write roll back together), naming the event, never a value

### `packages/core/src/audit.ts`

- L1: The chain-mirror mapping lives in core because the server's mirror append and the CLI's mirror verification share one implementation — two copies would drift into false tamper detections or misses
- L31: AuditActor carries the internal user id plus token id or auth method name only — never provider identifiers (GitHub id, login, email)
- L42: auditActorOf is the only principal-to-actor mapping — both the DO data plane and the D1 audit log go through it
- L53: auditPayloadWith is shared by the DO and D1 serialization so the auth-method merge cannot drift between the two stores
- L70: Four-eyes mirror rows cannot be mapped from the entry alone — they take a ProposalIndex derived from the verified chain as input
- L91: actorAuthMethod is not a column: the store merges it into the stored payload (§5.1)
- L105: AuditEventRecord is shared between the server-side append input and the client-side mirror verifier, so the mirror mapping produces the exact shape the server persists
- L128: MIRROR_EVENT_NAME is a whole-domain map over ChainOp (the type enforces exhaustiveness) so an added op cannot update only one consumer and drift the verifier
- L157: CHAIN_MIRROR_EVENTS is derived from the exhaustive per-op map so the mirror verifier cannot silently miss a future ChainOp
- L164: Mirror verification reads the whole chain. namespace by prefix — a row claiming an unmapped chain.* event is forgery evidence and must not hide by using an unmapped name
- L186: ProposalIndex derivation is shared by the server (mirror writer) and the CLI (audit verify) so neither can drift
- L195: indexProposals reads completion off the chain's consensus rules rather than re-evaluating: a proposal absent from the final pending set and not withdrawn was completed by the last approve naming it
- L216: entryHashAt undefined on a verified chain is a caller-side inconsistency: the proposal is not indexed and a referencing approve/withdraw surfaces as a contract violation
- L248: The added device FP is computed by the caller (SHA-256 is asynchronous) so the mapping stays synchronous; missing for an add_device is a contract violation (throw), never a silent row without the fingerprint
- L258: approve/withdraw's referenced proposal data comes from the proposal index; missing = a contract violation (throw)
- L293: mirrorTails input is op + payload (+ actor), so it applies both to signed entries and to a proposal's inner op; genesis's target is the creator = actor
- L308: add_member's scope is copied into the mirror payload — material to reconstruct §4.1's per-environment access windows (2026-09-14 ES)
- L334: create_environment's dek_commitment is copied into the mirror payload for matching audit rows against chain-published commitments
- L360: grant_server's lease_policy is deliberately NOT copied into audit rows: claim_value can contain external identifiers such as repository names (§1-2 / §14-4); the scope is copied
- L373: checkpoint copies the notarized digests into the payload; audit seq and row counts are not copied even into the payload (the chain payload itself contains no seq)
- L392: Four-eyes mirror rows do not copy the inner payload — the chain is the source of truth; proposalChainSeq and completed come from the proposal index
- L419: Device mirror mapping: add_device's target = actor (one can only add one's own device); revoke_device's payload = the revoked FP list (§4.1's detection trigger)
- L460: A missing referenced proposal on a verified chain is a bug in how the index was built — a contract violation of the mapping's input
- L471: chainMirrorEvents row order is mirror row first, applied row second — the server writes them in this order in one transaction and rotation detection reads the applied row as the latest membership event
- L539: The applied row's discipline exists so §4.1's membership intervals (Q1) and grant intervals (Q6) keep the same input structure as direct appends
- L554: The aggregated var.read form's construction and interpretation share one implementation — the enumeration's shape determines the input bytes of row_digest (§5.1)
- L577: auditReadPayload fixes sort and key order here rather than leaving them to the caller, because the stored JSON bytes feed the audit row digest (§5.1)
- L598: RotationRecommendedVariable.variableId is kept as a raw string: silently dropping a flag is the unsafe direction (a needed rotation prompt would vanish)
- L611: Reading rotation.recommended rows: an unknown basis falls to 'readable' (the safe over-report side); a present string id is kept verbatim with no format filter
- L637: Reading var.read rows: malformed entries are skipped rather than failing the caller — corruption to surface, not a reason to abort rotation detection

### `packages/core/src/auth.ts`

- L1: Core auth boundary lives in core because api-schema's middleware contract and the server implementation both reference it; §10 prohibition — no type here carries a raw session/token value in persisted or logged form
- L20: Authentication vocabulary has single definitions in core — the api-schema error schemas, the server, and the audit payloads all derive from these
- L26: AUTH_METHODS kind names are the only provider-related value an audit row may carry (AUDIT_SPEC §1-2)
- L53: OrgId is branded because organizations.id and memberships.org_id are ULID columns adjacent to same-shaped user-id columns; brands are minted only at trust boundaries (vite.config.ts pins the mint sites)
- L68: decodeOrgId mints an OrgId only at a trust boundary: generation, a hand-written parser of a wire/stored record, or a branded column read
- L79: OrgRole authorizes org management only — it is not involved in project access (§9-1)
- L95: Token scope: effective permission is always min(scope, chain role) — a token never exceeds its owner's chain role; the project field's restricted form blocks scopes-JSON bloat via arbitrary strings
- L117: scopePermissionFor returns null when no entry covers the project — the caller must then conceal the project's existence (§11-2)
- L142: parseTokenScopes returns null on decode failure — the same failure value as before, so the caller's handling is unchanged
- L155: Principal semantics: session principals carry the user's full power bounded by chain roles; token principals additionally carry scopes for min(scope, chain role) enforcement (§9-2)
- L169: A token principal's expiresAtMs is always non-null because only a principal that passed verification is constructed (expired = anonymous); /auth/me discloses it as an attribute of the presented credential
- L190: IssuedSession: the raw cookie value is returned exactly once
- L198: issueSession stores only the hash in the DB; the raw value is returned only at issuance
- L213: IssuedToken: the raw token is returned exactly once; expiresAtMs is fixed at issuance — deliberately asymmetric with the §5 sliding renewal of sessions
- L232: issueToken stores only the hash; reissuing under the same name revokes the existing one (rotation); expires_at is fixed at issuance from ttlMs resolved by the caller
- L260: RequestAuthShape is provided only by the middleware of auth-required endpoints (AuthMiddleware in api-schema)

### `packages/core/src/identity.ts`

- L1: UserId and ProviderUserId are branded with distinct invariants (the login is never an identifier); the display login stays a plain string; brands are minted only at trust boundaries, enforced by vite.config.ts
- L41: The UserId brand assertion accepts every string: the brand records provenance, not a format (§11-1 keeps the chain independent of the user id's format); bounds belong to the field
- L58: decodeUserId mints a UserId only at a trust boundary: generation, a hand-written parser of a wire/stored record, or a field whose recipient class makes it a user id
- L86: isKeyFingerprintHex is non-narrowing on purpose — 32 lowercase hex has the same shape as a proposal id and an audit row id, so a value-is guard would be an unpinned mint
- L107: decodeKeyFingerprintHex's shipped users are the server's stored-row decoders; a new caller is a new mint site for vite.config.ts
- L117: userKeyFingerprintHex computes and mints in one step — the only inputs are the two public keys, so the provenance holds by construction
- L140: computedFingerprintHex: the compute functions always yield 16 bytes; anything else is a defect

### `packages/core/src/ids.ts`

- L25: ULID uses: server principal identifiers; client wrap_id / group_id — the AAD binds the id, so the client assigns it before encrypting

### `packages/core/src/project.ts`

- L1: Project id brands are minted only at trust boundaries; the is* guards are non-narrowing because every format collides with another domain's — a value-is guard would let any file mint one brand from another domain's same-shaped string
- L45: isProjectId is non-narrowing on purpose (see the header): minting is the schema's and decodeProjectId's job
- L55: The schemas' expected annotations are exported for the CLI's diagnostic formatter — the annotation carries no input, so echoing it next to a refused flag is safe by construction
- L73: decodeProjectId mints only at a trust boundary: project creation (the genesis hash), a hand-written parser, or a branded column read
- L81: environment_id / variable_id are client-assigned because the values entering AAD / HPKE info must be fixed before encryption / wrapping; the form is an acceptance policy, not a consensus rule
- L92: isEnvironmentId is non-narrowing on purpose (see the header): minting is the schema's and decodeEnvironmentId's job
- L111: environmentIdSchemaWithMessage exists for config leaves that must not echo the typed value — the failure message is caller-supplied
- L118: decodeEnvironmentId mints only at a trust boundary: a validated command argument or a branded column read
- L126: isVariableId is non-narrowing on purpose (see the header): minting is the schema's and decodeVariableId's job
- L143: decodeVariableId mints only at a trust boundary: generation, a hand-written parser of a wire/stored record, or a branded column read

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
