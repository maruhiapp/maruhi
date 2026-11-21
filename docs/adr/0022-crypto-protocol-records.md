# ADR-0022: Cryptographic protocol decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 1931 comments on the cryptographic protocol implementation were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/anchor.ts`

- L1: Repository anchor (CRYPTO_SPEC 6.3 (b)) lets floorless CI clients detect rollback distribution by requiring the view to contain the anchor head and epochs at or above it
- L38: RepositoryAnchor is the CRYPTO_SPEC 6.3 out-of-band anchor (b) file shape
- L41: projectId is the genesis hash (CRYPTO_SPEC 6.4)
- L53: Anchor environments are sorted by ID ascending for deterministic output so committed diffs stay stable
- L144: Anchor mismatch is a contradiction between signature-verified data and a committed anchor = rollback/fork evidence, so refuse (strong side of SHOULD)
- L175: A missing anchored environment means the segment containing create_environment was rolled back — the same rollback evidence as an epoch regression, with different wording

### `apps/cli/src/approval-rules.ts`

- L1: Four-eyes CLI foretelling shares crypto's single definitions (no CLI copies) and re-tallies votes under current policy/members instead of echoing the record (CRYPTO_SPEC 6.2)
- L58: Section: vote re-tally is the CLI-side copy of CRYPTO_SPEC 6.2 principle 2; the target check itself is crypto's isApprovalTarget
- L68: Foretelling and tallying read the same owner predicate so the layers cannot disagree on a capped device (PR #186 finding); K4 narrows to the signing device
- L114: voters are recounted under current policy/members, never the raw record (which keeps revoked votes)
- L146: needed subtracts 1 because the next approve's actor is themself one vote (floor 0)
- L179: My vote is judged by the signing device's effective role (DK K4), while eligibleApprovers stays person-level because others' devices are unknowable
- L261: On zero pending matches, resolveProposalRef distinguishes completed/withdrawn from unknown so an old id can be told from a typo
- L269: Proposals can be referenced as '#<seq>': the seq is immutable and chain-fixed, and '#' separates it structurally from hex prefixes
- L325: Key-FP re-registration detection distinguishes a past membership of the same user_id from a different user_id; proposer and approver sides share one predicate
- L388: Omitted expiry defaults to 7 days (ruling P6); 0 and over-30-day values are refused by construction here (the K5-S pre-flight checks are folded in)

### `apps/cli/src/approval.package/approval-approve.ts`

- L1: Approve learns its result from the re-synced verified chain, not the server response; the completing approver fulfils the §7 post-stages per inner op kind.
- L55: Fulfilment records what the completing approver's client did after the inner op was applied (approval item 22).
- L104: A proposal targeting the approver themself is refused when applying it would leave the approver unable to fulfil the §7 obligations (K6-N).
- L121: Demotion/scope narrowing is judged by the same single predicate as a direct append's self-obligation check, keeping both paths consistent.
- L137: The approve pre-check is re-run after a resync so the decision rests on the current verified chain.
- L158: Fulfils the applied inner op regardless of its kind (approval item 22).
- L279: A vote's eligibility is the signing device's effective role, so the device FP is what is recorded.
- L303: If another owner completed or withdrew the proposal first, re-signing would only be rejected as unknown-proposal, so stop with a typed outcome (K6-B).
- L326: The result is learned from the post-acceptance resync because the server response does not carry whether the approve applied (K5-S).
- L350: When another owner's approve completed the proposal after mine, my vote counted but that owner is the fulfiller.

### `apps/cli/src/approval.package/approval.ts`

- L1: Propose is idempotent (existing pending proposal returned), no sweep/backfill runs at proposal time (P7), and approve lives in a separate file to avoid circular imports.
- L60: Pending-same lookup returns the first (smallest seq) matching proposal, which is what makes propose idempotent (K6-A).
- L71: Fail-closed when a policy enable/disable changed the append shape (direct vs proposal) between check and append (K6-A).
- L91: proposeOperation resyncs after acceptance and confirms the proposal is pending on the verified chain rather than trusting the server's claim.
- L164: After a CAS-conflict resync the caller's pre-append check re-runs and an already-applied concurrent change stops the proposal (K6-A).
- L194: The withdraw pre-check (proposer or an owner, §6.2) is re-run after a resync.
- L209: Withdraw consensus is judged by effective permission (person intersect device cap, §6.2 effectivePermissionOf), not the bare role.
- L239: A concurrently completed/withdrawn proposal stops withdraw with a typed outcome instead of sending an unknown-proposal append.
- L271: PolicyRequest's targeted ops are kept sorted and deduplicated so policy comparisons are canonical.
- L300: The policy pre-append check covers owner status, reachability foretell and no-op detection, and re-runs after a resync.
- L371: While a policy is enabled, set_approval_policy itself is an always-target (§6.2 "policy").
- L373: Do not propose when the same policy was already applied after the resync — that would be a redundant proposal.
- L425: Distinguishes completed / withdrawn / pending; used by approve's conflict handling (K6-B).

### `apps/cli/src/approval.package/command.ts`

- L117: An already-satisfied pending proposal can only be completed by a not-yet-voted owner after the required_approvals reduction (K5-L/K6).
- L133: List shows the verified chain's pending proposals and re-tallies vote counts rather than trusting stored counts (K5-M).
- L177: The approver-side key-FP re-registration warning uses the same predicate and wording as the proposer-side warning (K6-I).
- L183: On a keyless MARUHI_TOKEN run no device is determined, so show states only that and stays a key-free command; a vote's eligibility is the signing device's effective role.
- L230: The "can you approve" line includes K5-L's guidance.
- L278: Fulfilment reporting covers approval item 22 and the exit code, dispatched per inner op kind.

### `apps/cli/src/attestation.ts`

- L1: Head gossip reconciliation: hash mismatch at or below own head is fork evidence (interrupt, warn, save evidence); ahead-of-head resolves via one bounded resync; unverifiable attestations are excluded to prevent warning-induction DoS
- L56: Only the two head-binding verification outcomes become reconciliation material; all other verification failures are skipped (CRYPTO_SPEC 6.6)
- L65: Attester must be a current member in the local view, else the attestation is not reconciliation material (CRYPTO_SPEC 6.6 (1))
- L91: Verification failures land on skip, not warn, eliminating warning-induction DoS via forged attestations (CRYPTO_SPEC 6.6)
- L102: Signature and key selection are already verified at this point, so a hash mismatch makes the attestation itself evidence, not a skip
- L179: Failure to save fork evidence does not swallow the detection: the warning carries the evidence and interruption is unchanged
- L189: A contradiction between signed data is evidence that a re-run does not resolve (round 12)
- L196: Reconciliation runs one bounded resync for future attestations, then re-reconciles the advanced view's set plus unresolved ones; unresolved means fork evidence
- L222: Bounded resync runs once; its extension check drops a substitution to a different chain at that point
- L225: Union dedupe key is every wire field: a partial key would let a malicious server collide away a genuine carried-over attestation and reopen the omission bypass (ruling AA)
- L265: Head attestation is a SHOULD: submission failures never fail the command but are reduced to a one-line warning; a 409 regression is warned separately as floor damage / concurrent CLI
- L289: Re-attestation is suppressed only for the identical head, not by seq alone: at the same seq a different hash is equivocation and must still be submitted so the server's 409 surfaces
- L319: Reading _tag directly is banned by oxlint, so discrimination goes through catchTag; the diagnostic names only internalErrorKind (a type name, no response fragment)
- L352: An attestation submission failure is non-fatal (SHOULD) but never ignored — it is reduced to a one-line warning

### `apps/cli/src/audit.package/audit-d1.ts`

- L46: A D1 row has no chain provenance: a slipped-in chain_seq is never displayed as a bare coordinate; it warns and exits non-zero (S1).

### `apps/cli/src/audit.package/audit-list.ts`

- L100: A wire env id outside §12-1's form is skipped from name resolution, degrading to identifier display (SHOULD-level), never a defect.

### `apps/cli/src/audit.package/audit-mirror.ts`

- L1: TCB discipline: every response field is a server claim; chain.* rows are labelled by reconciliation against the verified chain using the server's own mapping to block verifier-drift false alarms.
- L28: WireAuditEvent is derived from api-schema's AuditEventSchema rather than duplicated, and every field is treated as a server claim.
- L59: Expected-row matching picks the expected row with the same event name (a completed approve yields two rows); a name matching none reports the mismatch on event.
- L74: chainMirrorEvents always returns at least one row per op, so an empty result is an internal error, not a server mismatch.
- L80: serverTs is excluded from mirror comparison because the client has nothing to verify the server's acceptance time against; signed-entry-derived payload fields are in scope.

### `apps/cli/src/audit.package/audit-page.ts`

- L1: Display names are resolved only from verified meta-statements (including tombstones); a payload name snapshot is shown separately as a record, never promoted to the display name.

### `apps/cli/src/audit.package/audit-reconcile.ts`

- L1: Reconcile recomputes the cumulative hash column and checks membership, non-regression and position floor per notarizing checkpoint; violations split into row-tampering vs acceptance-policy evidence.
- L66: Reconcile pre-judges effective admin because below admin the gap check would misread a visibility hole as a deletion.

### `apps/cli/src/audit.package/audit-verify.ts`

- L1: audit verify rebuilds the expected mirror column from the verified chain with the server's mapping and detects missing, forged and altered rows (bijection verification, §6).
- L39: Mirror event names come from core's shared CHAIN_MIRROR_EVENTS mapping, not a hand-written list, which could miss a future op and falsely convict an honest server of forgery.
- L86: A re-appearing row id is refused as a contradictory server response; ids are opaque, so paging progress is checked as set non-duplication.

### `apps/cli/src/backfill.ts`

- L1: Backfill core is shared between server-directed and member-directed flows; only per-epoch 409 resolution differs, so that is the injection point (CRYPTO_SPEC 7)
- L24: 409 outcome carries the occupying wrap's stored recipient enc public key (AUTH_SPEC 12-6), which the repair path needs
- L43: Backfill aggregate contract: one environment's failure does not stop the rest (CRYPTO_SPEC 7)
- L51: Per-environment failures are collected and the backfill run continues (shared by member add, role widening, device addition)
- L80: On bulk 409 the backfill drops to per-epoch because a batch is accepted atomically, so a re-run after partial registration always 409s the bulk
- L101: member add's re-add repair performs delete then re-register at the per-epoch 409 slot (CRYPTO_SPEC 12-6 repair path)
- L111: epochs option exists for device gap filling (DK K11-1), which passes only the missing epochs it could open
- L131: A missing epoch wrap is a poisoned wrap or loss, never silently skipped, and the message must not say re-run since a plain re-run hits the same gap (CRYPTO_SPEC 7)
- L166: On a bulk 409 the backfill drops to per-epoch registration to converge
- L202: A 409 DekWrapExists is returned as the value 'existing slot', as input to re-run convergence and repair decisions rather than as a failure

### `apps/cli/src/chain-append.ts`

- L1: Chain append is one shared sign-at-head + CAS retry loop; device ops are the exception because they resolve the actor device first for cap and role checks
- L56: The signing device is the person's valid device matching the signing key at hand (K4-16)
- L108: appendWithRetry re-runs resync (extension-checked) and the op's pre-checks after a head conflict — including after the last attempt, so a definite error beats the exhausted wording
- L147: A state for which settled holds appends nothing: a concurrent run already made the change or closed the target

### `apps/cli/src/chain-applied.ts`

- L1: Applied-operations column: an inner op takes effect at its quorum approve's seq, giving direct and proposal-mediated applies one shape so none is overlooked (K6-C)
- L20: The server's mirror mapping and the CLI share core's indexProposals derivation (K5-F)
- L38: Attribution rule: an applied inner op is attributed to its proposer (CRYPTO_SPEC 6.2)
- L44: propose, incomplete approve and withdraw change no state so they are excluded from the applied column

### `apps/cli/src/chain-sync.ts`

- L1: Every sync re-verifies the whole chain and binds genesis hash to projectId; v1 deliberately has no local cache or incremental verification, with session-10 cautions if added
- L46: Distributed attestations are carried as unverified raw data and feed no judgment until attestation.ts verifies them (CRYPTO_SPEC 6.6)
- L61: VerifiedProject bundles the verified chain with the 5.1 signer-key history index and 4.1 chain-history index
- L72: keyHistory is append-only and dedupe must not erase tenure (session-14 ruling A); value-signature lookups use the history side instead
- L81: entries is a read-only view for historical facts absent from derived state, e.g. the last revoke_server seq used by interruption recovery
- L88: Consumers scan the applied column rather than the entry list so a proposal-mediated application is never missed
- L98: Attestations on the view are unverified; their omission is CRYPTO_SPEC 6.3's normative non-guarantee, not refused; lease views are always empty
- L111: A post-verifyChain derivation inconsistency is a typed failure here: a silent omission from the key index would resurface disguised as 'signer does not exist' at §5.1 verification
- L142: Key history is built from genesis/add_member/add_device (incl. proposal-mediated adds); revocation does not erase history, and the FP is recomputed from the payload key
- L184: Both distribution paths (chain API sync and the lease-bundled chain) pass through the single verifyChainSnapshot: splitting verification would silently regress genesis pinning on one side
- L208: A distributed chain failing verification is evidence (a contradiction in signed data) and is never folded into a cleanup warning — re-running does not resolve it
- L247: The server-declared head is not trusted: it is checked for equality against the locally derived head
- L305: Extension check (§6.3-2b): the new head must be at or above the old and contain the old head's seq/hash; a consistent replacement chain, missing old head, or same-seq hash mismatch fails

### `apps/cli/src/checkpoint-integrity.ts`

- L1: Checkpoint rule 2: baseline is chain-derived, the wire locator is advisory only, omission of the enumeration with a baseline present is refused, and mismatches are rollback/forward-injection evidence
- L63: signedBytesHashHex is self-computed (CRYPTO_SPEC 4.1), not a server-claimed value
- L67: rejected verdicts carry an evidence flag distinguishing signed-data contradictions from the benign race where the baseline advanced after the response's fetch
- L89: An enumeration for an environment with no baseline is fabrication even when its position is a real entry, since a covering checkpoint would have derived a baseline
- L114: Locator classification: only a baseline that landed after the response's fetch view is retriable (benign race under bounded resync); a pre-existing baseline mismatch is stale-distribution evidence
- L139: A 'future' locator may be a checkpoint that landed just before the response (local staleness): pull resolves it via bounded resync, the lease caller refuses it as self-contradiction
- L169: A served variable below the baseline epoch may be a legitimate post-checkpoint creation — the epoch baseline acts as the version-0 equivalent
- L201: The checkpoint baseline is always derived from the verifier's own verified chain, never server claims; the wire's checkpoint seq/hash is only an advisory locator
- L219: fetchedAtHeadSeq records the verified view at fetch time so a benign race (history advancing under bounded-resync re-verification) can be told from evidence
- L231: An environment without a baseline is outside checkpoint verification (§6.3): the guarantee covers only floor/manifest epoch consistency
- L237: A baseline accepted after the response's fetch view leaves a benign explanation, so the outcome is retriable — a re-pull brings the new baseline's enumeration
- L246: Baseline present plus no enumeration is a MUST-refuse; the remedy is server-side (atomic storage with checkpoint acceptance), a client cannot re-issue its way out

### `apps/cli/src/checkpoint.package/checkpoint.ts`

- L1: Checkpoint issuance builds tuples only from the verified view (never signs server-declared values), decides notarization authority up front, and bounds 422 retries with a one-time subset fallback (§6.3).
- L76: After the 422 retry cap (3) is spent, issuance is attempted exactly once with the stable subset (§6.3 fallback).
- L80: AuditHeadNotReady budget of 10 with the server's 10k-row cap per response guarantees 100k rows of extension per run; progress is saved so a re-run continues (ruling AG).
- L91: Backoff between AuditHeadNotReady retries is exponential only to avoid pounding the endpoint; each retry is productive because the server extension advances per call.
- L102: The baseline age for issuance trigger (iii) is 7 days, the drafted value of CRYPTO_SPEC §6.3.
- L126: Coverage "all" means every environment in the verified view except chain-deleted ones (§6.3); an explicit list serves trigger (i), the environment whose rotate just completed.
- L139: Comparison is ascending UTF-8 byte order, the payload generation order SHOULD of CRYPTO_SPEC §6.2.
- L209: Out-of-scope environments cannot be value-pulled or notarized (§6.2/§6.3), so they are excluded from "all" and returned via outOfScope for a SHOULD warning rather than silenced; an explicit out-of-scope target is a typed error.
- L263: The last pull's verified view becomes the signing basis (CAS parent) and each tuple's epoch copies that view's chain-derived value; changes between pull and signing are caught at acceptance (409/422) and absorbed by bounded retries.
- L335: Re-notarizing a tuple equal to its baseline would feed every consistency check the same inputs (§6.3), so only changes are covered.
- L424: One attempt is sign, append, then post-acceptance reconciliation (§12-10 (3)).
- L454: Post-acceptance reconciliation confirms the own entry on the verified chain: a 2xx is only a transport-layer fact and success is reported only after this confirmation (§12-10 (3)).
- L461: A transport failure is reported as "may or may not have landed"; a checkpoint advances no local state and re-running is safe either way, so no landing probe is needed (session-35 ruling).
- L500: Success is reported only after a chain sync confirms the own entry landed at that seq; a 2xx alone is a transport fact (§12-10 (3)).
- L528: Zero coverage targets is a failure, and the out-of-scope exclusion is a SHOULD warning because the reason for missing the all-environments SHOULD must not be silenced (K4-M).
- L556: issueCheckpoint is the shared implementation for the project checkpoint command and post-rotate periodic issuance, including §6.3 retries and subset fallback.
- L570: A tuple-less entry by a non-notarizing issuer only restarts trigger (iii)'s clock, so it requires a view of every active environment and a stale baseline (§6.3).
- L581: On a subset rebuild, the environments the last full build found unchanged are carried into the summary.
- L585: The 503 budget is cumulative across the outer retry loop (a per-call times could not bound it), and each retry refetches view and attestation after the CAS parent settles (§6.3/§16-2).
- L611: The subset-fallback baseline is the previous build; inside a subset issuance there is no further fallback.
- L631: AuditHeadNotReady re-fails before classification so the unit's Effect.retry handles it instead of it being absorbed as an outcome.
- L639: Failures re-fail at this layer: Effect.retry handles the 503, while toCliError is the CLI's final error shape elsewhere.
- L663: absorbSendFailure's return contract: null retries as-is, an array falls back to the subset issuance.
- L686: Send failures are absorbed per kind with independent budgets; the 503 no longer reaches here because the retried unit's Effect.retry absorbs it (AUDIT_SPEC §5.1, ruling AG).
- L778: The subset fallback is the environments whose tuples were unchanged across the last two builds; no stable environment (or already on a subset) is a definitive failure (§6.3).
- L815: Trigger (iii) baselines differ by effective authority (admin: latest notarized checkpoint), and 'never issued' counts elapsed days from genesis's time (DP5 ruling C).
- L840: With no baseline, staleness counts from genesis's time (DP5 ruling C); an entry-less view falls to the proposing side (fail-open, a single Note line).
- L873: /auth/me is fetched only when a checkpoint proposal is about to be made, so the proposal's frequency adds no scope-fetch round trips.
- L892: Checkpoint issuance proposals require member or above (§6.2); a reader gets no proposal.
- L898: A non-notarizing issuer missing an environment in scope is prompted only after its own write, since after a pull the prompt could repeat with nothing to notarize (§6.3).
- L927: The anchor-refresh proposal is unconditional on rotate but bundled into the same single line as trigger (iii) on push, so users are not trained to ignore it (session-35 ruling, DP5 C).

### `apps/cli/src/ci.package/ci-lease.ts`

- L1: CI lease acquisition deliberately depends only on the OIDC token (no maruhi token, keychain, session or config), with verification material bundled in the lease response and no floor/pins (§14).
- L67: The OIDC token is unwrapped only at the lease request's wire boundary; the plaintext rides only in the request body and never appears in logs or errors.
- L92: Losing the first-come race twice with fresh tokens is treated as a sign of token leakage: retries cap at 1 and the message prompts investigation.
- L100: Only token-replayed failures are classified as retryable in a lease issuance attempt.
- L119: leaseEnvironments uses one in-memory ephemeral key and one OIDC token for every environment and runs all §9.1 verification duties against the pre-pinned genesis.
- L136: The sealed-proposal mint must present the same token and ephemeral key pair it leased with; a second key under the same token would be refused as replayed (§14-1).
- L158: An unexpired credential is re-presented for a re-lease (idempotent under §14-1) so re-leasing needs no issuance endpoint, which may have stopped answering (ruling O).
- L208: GitHub is a runtime-minting issuer, so one automatic retry with a fresh token is allowed (session-24 §8 MAY — cap of 1 total, even across multiple environments).
- L220: The retry presents the same ephemeral key: the fresh token is unbound and binds to this key.
- L232: §9.1 verification obligations (1)–(6): no value is decrypted until all of them pass.
- L242: The §9 server disclosure shown on the workload side comes from the bundled chain this lease just verified.
- L256: A fresh credential's ephemeral X25519 key pair is generated in memory (non-extractable, disappears with the job, §9.1) and the token is minted right before the lease request to minimize the first-come binding's exposure window; one call = one token = one key.

### `apps/cli/src/ci.package/ci-rotate.ts`

- L1: ci rotate seals new values to accepting members' devices instead of pushing signed versions, and refuses rules whose rotation invalidates the current credential at once (dual-credential discipline).
- L74: Proposal facts are capped at 16 facts of at most 256 characters each (AUTH_SPEC §14-5).
- L158: The credential is unwrapped because the connector consumes it in memory to authenticate the rotation at the issuer (the same as var rotate).
- L163: A missing admin input from the leased environments stops the rotation before anything is sent.
- L319: The pre-flight refusal happens before the issuer is touched, so nothing exists to recover.
- L394: ci rotate leases, runs the connector, seals new values to W(E) and stores the proposal under the lease's credential; values are never displayed.
- L415: The failure is unreachable (fixed-size hex); the check keeps the proposal id form pinned to the crypto package's definition.
- L440: Recipients are W(E) (§5.3): devices whose effective permission is member or above with E in scope; the server checks the sealed set against the same definition and refuses a different one as recipients-mismatch.
- L452: The pre-flight (O-4) asks first, under the lease's credential, the mint checks the issuer cannot undo once a credential exists; a refusal here strands nothing.
- L464: The recipient set is checked against W(E) locally too (ruling O revision, round 4): a disagreement that is not a race is answered before the issuer is touched.
- L491: The one purely-race post-issuer refusal (O-7): members/devices changed between lease and mint, so lease again, recompute W(E), seal again and mint once more under a new proposal id; a second mismatch stops.
- L499: Recovery re-leases under the lease's key with the newest token held for it (the mint's if unexpired — a runner whose issuance endpoint stopped answering can still recover, O-13/O-15); a fresh pair otherwise.
- L560: The mint's token is minted after the connector for the lease's key (K-5; mintTokenFor).
- L571: The mint's server refusals come back as they are — the caller decides which one is a race; everything else is the mint refusal with the recovery step.
- L600: The token is unwrapped at the mint request's wire boundary: the lease's ephemeral key under a token of the same workload (AUTH_SPEC §14-5).
- L609: The lifetime travels as days and the server sets the instant, so a CI clock ahead of the server can never make the proposal unacceptable after the issuer was touched (O-9).
- L625: The mint's token is minted now for the lease's key (K-5: the key binding, not the token, is the credential's continuity under §14-1); the lease's token is the fallback unless it expired meanwhile (K-6).
- L638: The fetch's bound follows the lease token's life (O-18): a hung endpoint must not eat the fallback to a token that still lives.

### `apps/cli/src/ci.package/ci-run.ts`

- L1: ci run injects decrypted values into the child environment in memory only (diskless invariant); as injection rather than display it sits outside the agent-gate (ADR-0016 decision 7).
- L49: Required-variable presence is judged against the verification material bundled in the lease response (§14-2); a missing required declaration stops the child from starting.
- L54: Variable type mismatches are advisory only: warn and continue execution (§14.3-7).

### `apps/cli/src/ci.package/command.ts`

- L232: The audience's default is the server's normalized origin (AUTH_SPEC §14-1's recommended value).

### `apps/cli/src/commands/flags.ts`

- L153: The proposal expiry flag is never read on an operation the four-eyes policy does not target (a direct append).

### `apps/cli/src/commands/pull-run.ts`

- L210: Issuance trigger (iii) (§6.3): a successful pull detects baseline checkpoint staleness and only proposes a refresh — never auto-issues.

### `apps/cli/src/commands/shared.ts`

- L124: The identity backing defaults to github-signing-keys when unset (CRYPTO_SPEC §6.5).
- L130: §7: a duty environment outside the performer's scope cannot be rotated — a note, not a failure; the always-on warning keeps displaying it until a member whose scope covers it rotates it.
- L145: Issuance trigger (iii) (§6.3) emits the staleness proposal as a 1-line Note; a failed proposal judgment never overturns the command's success (a SHOULD attachment), and on push the anchor-update proposal is bundled into the same line (DP5 ruling C).
- L250: Four-eyes (K6-K): --expires is never read on an operation the policy doesn't target, but a malformed format drops as usage (2) before any communication.
- L266: The proposal's remaining vote count wording follows ruling P8.
- L275: Proposed reporting (K6-A) is shaped never to be mistaken for "appended": it states nothing was applied and who does what next.
- L302: The sweep report and exit-code derivation are shared in one place because the report shape and §7's "never silently skip a failed rotate" discipline, held twice, would only get fixed once.
- L337: §7: never silently skip a rotate refusal of an environment believed active — that would make selective rotation blocking by a malicious server invisible.
- L346: The anchor-update proposal is emitted as one line across the whole sweep.

### `apps/cli/src/connector.package/connector-shared.ts`

- L123: Value shape (D-7/D-8) is shown locally and at acceptance computed on-device — never sent to the server

### `apps/cli/src/context.ts`

- L323: The floor head is deliberately not advanced in loadCheckedFloor: recording before gossip reconciliation would make a rejected view's head the floor's permanent record (floor pollution)
- L358: Partial floor-log corruption continues via fold self-healing but is never silent: a dropped latest observation thins detection material until the next verified observation
- L370: A same-coordinate conflict from the fold is hard evidence of equivocation (§6.3): the floor is refused for use or advancement
- L379: On a head regression the resync must be an extension of the initial view; otherwise the initial view itself was a fork (shortening + fork composite) and is rejected as evidence
- L396: A pending (empty-slot) intent is never finalized: the chain may simply not have the landed entry yet, and collapsing it would leave nobody to promote the manifest later
- L407: Intent acceptance is judged by the entry at the declared-head+1 slot, not by DEK commitment alone: a CAS retry re-signs the same commitment, so commitment matching cannot tell attempts apart
- L565: Anchor rejection wording includes where the pin file lives, keeping a path to investigation and recovery against a permanent halt
- L581: The inviter's key is a device that was valid at the pinned head, drawn over the device's validity interval (2026-09-19 DK)
- L599: Invite-anchor reconciliation (§6.3(a)/§6.5) runs on every sync while an anchor exists: the check is only 2 references and an always-on check is strictly stronger
- L653: The floor head advances only after all checks (floor/anchor/gossip) pass; advancing earlier would let a rejected fork reject every future honest chain (floor pollution)
- L682: Sync/floor semantics are unified in one prologue for keyed and keyless commands: split into two tracks they would silently diverge; keyless prologues reconcile but never submit attestations
- L712: The prologue's full sync+verify every run is the reconciliation point for unresolved composite intents (3-F), including recovering the floor's manifest advance
- L727: After reconciliation the floor is re-read and the conflict check re-applied: a concurrent contradictory append during reconciliation must not be proceeded past (same fail-closed as loadCheckedFloor)
- L751: Verified-head attestation is submitted only for views that passed every reconciliation; failure is a non-fatal warning
- L863: Floor environment lookup is own-property only: a legitimate environment ID like 'constructor' must not resolve to an inherited Object property
- L882: Every value command passes through openEnvironment's effective-scope pre-check (§6.3 'do not wait for the server's 403'); metadata-only commands visibly take a different function (K4-C)
- L899: A chain-deleted environment is refused before the scope check: its ID left every listed scope at deletion, so the scope check would misreport it (§6.2)
- L902: The scope check is this device's effective scope (person ∩ device, K4-17); an unregistered/revoked key at hand is guided to the registration path before any value fetch
- L924: commitVerifiedHead exists because value-less commands never pass commitPull/commitPush: without it their verified head would never reach the floor and an in-between rollback would go undetected
- L954: openMetadataEnvironment deliberately does not check scope: a metadata-only pull is allowed outside scope (AUTH_SPEC §12-7, ruling G-2)
- L986: env diff opens the project once with a floor handle per environment: two separately synced verified views could disagree and make the comparison's history unsayable

### `apps/cli/src/dek-wrap.ts`

- L1: Wrap generation builds the complete set matching R(E) from the verified ChainState (single definition in crypto); on CAS retry the set is rebuilt only when the recipient set changed, avoiding unneeded random re-wraps
- L57: A recipient identifier (user_id or server key FP) goes verbatim into HPKE info and the 5.1 signature target's recipient position (CRYPTO_SPEC 9)
- L83: Wrap build results keep the real reason code: multiple causes must not be crushed into one generic message
- L103: The same recipient identifier value goes into both HPKE info and the 5.1 signature target's recipient position (CRYPTO_SPEC 9)
- L125: The DEK is unwrapped only as input to the HPKE wrap at the crypto boundary; the product is the wrapped ciphertext
- L188: Wrap set covers one wrap per R(E) recipient in wrapRecipientsOf's fixed order so a request is reproducible, each signed by the caller (5.1)
- L206: Chain-derived identifiers are free-form strings and are always neutralized before being emitted to the terminal
- L229: Wrap recipient-set sameness judges whether the wrap set may be reused on a CAS retry (§12-4)
- L239: wrapRecipientsOf lists recipients in one fixed order, so equal sets yield equal lists and list comparison is sound
- L257: ROLE_RANK must not be written in negative form ('=== reader'): with satisfies Record<Role, number>, adding a lower role becomes a type error instead of a silent pass
- L275: requireWritingMember drops ineligible requests before DEK generation, HPKE wrap, and any pull — it does not wait for the server's 403 (§6.2/§6.3)
- L297: The target kind ('existing' vs 'new') is a required input so every caller of the composite guard decides it explicitly

### `apps/cli/src/deks.ts`

- L1: DEK verification coordinates are assembled independently of declared values, and an unwrapped DEK is never used until matched against the chain-derived commitment (5.2 poisoned-wrap defense)
- L57: A wrap's registration signature is verified and it is unwrapped only with the 5.2 commitment check before the DEK leaves
- L125: A DEK is never used until its §5.2 commitment check succeeds; the check coordinates are assembled from the client's own verified values
- L150: Chain-deleted environments derive from the verified chain alone (§6.2): no server listing is consulted, so deletion cannot be withheld
- L175: requireChainEnvironment enforces chain-derived existence: distributing a not-yet-created environment contradicts the chain, and a deleted one is never read, written, or rotated
- L200: Every distributed wrap is verified (§5.1) and unwrapped, aborting on any failure; phantom-epoch defense caps a wrap's epoch at the chain-derived current epoch (§12-6/§12-7)
- L218: Distribution of an environment absent from the verified chain is refused wholesale as a phantom environment (§6.2)
- L224: Only rows addressed to my devices are opened (AUTH_SPEC §12-6 device axis, DK K4-16); rows for other devices of the same person are not poisoned wraps
- L231: The suite check is currently unreachable via the Schema Literal pin but is pinned explicitly on the CLI side as defense against a future union
- L267: An unwrapped DEK is Redacted-wrapped only after the §5.2 commitment check passes — an unchecked DEK never leaves verifyAndUnwrapOne
- L285: missingEpochsOf is the single absence judgment shared by pull's warning and device add's reachability check, so an ahead-of-time report and a later warning cannot disagree
- L299: environmentKeysFor enforces 'epoch and DEK set from the same verified view' by construction, with cached→prefetched→fetch precedence and the receiver-side scope rule placed at the only acquisition point
- L341: The unwrapping device is my valid device matching the key at hand (DK K4-16); a DEK for an environment outside the effective scope is not used even when addressed to me

### `apps/cli/src/device-gaps.ts`

- L1: Gap-fill design (K11): bundled pull rows are the signal only, content comes from the verified chain and my-addressed DEKs; outside the ceremony gate, and failures fold into the result without changing pull's success
- L105: fillOwnDeviceGaps wraps only epochs this device itself could open and never fails: every problem is returned as a fact for the report (DK K11)

### `apps/cli/src/device-key.ts`

- L1: Device-key resolution never silently picks 'the first device': the key at hand must match a currently valid device, else typed failure routes (revoked → re-add, unregistered → registration paths)
- L37: ROLE_RANK's satisfies exposes any change to Role to the type checker (§6.2)
- L84: ownDeviceOrFail resolves through the verified chain's key history, so a revoked key (no longer in member.devices) is still recognised; never 'the first device' (K4-16/K13-5)
- L164: Key-uniqueness pre-flight (§6.2 duplicate-member-key): current device holder first, else the grant that named the enc key, else null; the chain verifier stays the final arbiter
- L198: Monotonicity (principle D2) compares cap to cap — never against the person's effective permission — and is derived from crypto's public API without copying its internal implementation

### `apps/cli/src/device-ops.ts`

- L1: Device-ops pre-flight checks copy the §6.2 consensus rules instead of waiting for the server's 422; backfill targets the new device's effective scope (person ∩ device) per §7
- L87: appendWithCas runs signEntry's pre-flight checks on each view, so the resync after a head conflict needs no recheck of its own
- L347: deviceEnvironmentsOf is the single function deciding both the backfill target set and device add's key-reachability set, keeping 'should have delivered' and 'checked' identical (K12-1)
- L416: Revocation sweep (K4-8): obligations inside the signing device's effective scope (role member+) are rotated; the rest are carried over as outOfScope to another device or the next sync

### `apps/cli/src/device-standing.ts`

- L1: Standing design (K13-1): one place answers a key's standing; the pure keyStandingIn works on an already-verified chain, keyStandingsOf syncs per project, and neither produces wording (K12-10)
- L48: An active standing wins over an earlier revocation: the key can only be active again as a new registration, which the chain would show
- L100: keyStandingsOf never fails: a list failure and each sync failure are carried as facts, with tamper signals riding on `evidence`
- L180: For a ledger key, reserve-ness is decided by the mark in the ledger's contents (CRYPTO_SPEC §8); the chain says only whether it is revoked anywhere (DK K16)
- L198: Unchecked (unsynced) projects do not stop the operation (K16-6), but the reporting side names them in a Note — a revocation there would be invisible
- L223: The ledger verdict syncs every server-listed project; key recover instead applies reserveVerdictOf directly on the chain it already opened, avoiding a double sync

### `apps/cli/src/device-sync.ts`

- L1: First-sync device reconciliation design (K4-3/K4-4/K4-9/K4-14): observation, revocation observation, gated registration, reserve-key warning; the device registry is neither read nor written here (pinned by test)
- L60: syncOwnDevices is idempotent and never fails the command: every problem becomes a Note/Warning (registration is an adjunct of a SHOULD)
- L93: Registration signs, so it runs only in a human session passing the device-approve ceremony gate: the local record is an unsigned file, and a planted row would otherwise add a signer without the gate (K4-37)
- L113: Registration's ceremony gate emits a Note and returns false instead of stopping the command body — registration is an adjunct of a SHOULD (K4-37)

### `apps/cli/src/device.ts`

- L66: A registry/request row's claimed FP is never trusted: the FP is recomputed from the public key (§13-11)

### `apps/cli/src/env.package/boundary-checkpoint.ts`

- L1: Boundary checkpoint (AUTH_SPEC 12-4 / CRYPTO_SPEC 6.3): H+2 checkpoint covers only the one tuple of the composite's environment
- L31: signBoundaryCheckpoint covers active variables only — the 6.2 values_digest definition
- L38: compositeEntry is the anchor for the checkpoint's seq/prev
- L41: Epoch established by the composite: creation = 1, rotate = new_epoch
- L43: manifestVersion/manifestSigHashHex are the binding target (4.3 (2))
- L47: verified view resolves the signing device; DK K13-5 covers the missing-key message
- L50: Signing device must be the same device as the composite entry

### `apps/cli/src/env.package/command.ts`

- L121: env create body is the 12-4 composite request
- L146: Member count shown is the wrap set actually registered; under a CAS retry rebuild it may differ from the run-start view
- L153: env rotate command body (AUTH_SPEC 7 / 12-4)
- L215: Anchor-update proposal (CRYPTO_SPEC 6.3 (b)) is emitted before cleanup: the epoch advance and anchor staleness stand even if cleanup fails
- L253: env rename body: the environment's own meta statement + manifest (12-4)
- L281: env rm body: the delete_environment chain entry (12-4 / CRYPTO_SPEC 6.2)

### `apps/cli/src/env.package/composite-retry.ts`

- L1: Shared CAS retry for the two composites (AUTH_SPEC 12-4): retryable failures, extension-checked resync, wrap-set reuse
- L26: AuditHeadNotReady (503) is retryable like a head conflict: the server's extension is saved even on failure, so resend covers only the remainder (M-b: checkpoint not notarized)
- L43: Recovery resync is extension-checked (6.3-2b) against a shortened/forked chain; wrap set rebuilt only when the recipient set changed (HPKE Seal is random)
- L73: Exhaustion wording names both causes because AuditHeadNotReady circulates under the same classification (prevents mis-guidance)

### `apps/cli/src/env.package/env-create.ts`

- L1: Env creation composite (AUTH_SPEC 12-4 / CRYPTO_SPEC 5.2, 6.2, 4.2): entry + meta statement + epoch-1 wrap set accepted atomically; name NFC-normalized before signing
- L58: Role is checked up front, shared with rotate: otherwise the reader would do DEK generation, wraps and signing, then only get the server's generic 403
- L71: Creation requires scope=all (6.2, rulings E/K4): a listed scope cannot contain an environment that does not exist yet; server returns 403 insufficient-scope
- L78: environment_id uniqueness across chain history is detected client-side early instead of waiting for the server's 422
- L99: Signing-device resolution and signing live in one shared place (chain-append.ts — DK K13-12).
- L130: env create via the 12-4 composite; success only after 12-10 (3) effect confirmation, then the v1 floor is established
- L159: The name is NFC-normalized by the client before signing (4.2 / 12-1)
- L161: The DEK is wrapped right after generation; from then on it flows only as a Redacted
- L171: Unwrap justified: input to the commitment computation at the crypto boundary; the product is a hash
- L191: A CAS retry re-signs both entry and statement (12-4); the wrap set is rebuilt only when the member set changed
- L196: A definite error the resynced view shows surfaces even after the final attempt
- L214: The floor is established and success reported only after the 12-10 (3) effect confirmation passes
- L216: Current epoch after creation is structurally 1 (12-4); member count is the wrap set actually registered
- L247: The declared head is the current head before appending (= the bundled entry's prev, 12-4); shared meta-statement implementation
- L258: Bundled manifest: version 1, empty variable set, epoch 1; a CAS retry re-signs entry, statement and manifest
- L280: Boundary checkpoint (12-4): one tuple of this environment; a CAS retry re-signs it with the other bundled items
- L296: Journal-before-send (3-F): the intent is appended before sending, fail-closed if persisting fails
- L330: A server refusal (CAS 409 included) means the effect did not occur (settled) — the intent is closed
- L347: Post-acceptance confirmation (12-10 (3)) gates floor establishment and success reporting
- L370: A 2xx whose verified chain lacks the entry or carries a different DEK means the response contradicts the chain — unconfirmable
- L379: The v1 floor is the empty variable set at epoch 1; journal-before-release: persisting the floor precedes reporting success
- L403: A resolution-append failure may be swallowed: an intent left open is the safe direction

### `apps/cli/src/env.package/env-diff.ts`

- L79: DiffTarget.floor serves 6.3's meta-level checks and is not committed
- L85: Required contract derives only from the verified statement's schema field; server declarations are not used (14.2-8)

### `apps/cli/src/env.package/env-list.ts`

- L53: environmentStatusOf is the one place status is derived: from the verified chain (deletion = delete_environment, 6.2)
- L71: Disclosed server-key fingerprints are fingerprint-ascending; empty means none (CRYPTO_SPEC 9)

### `apps/cli/src/env.package/env-meta.ts`

- L1: env-meta: rename signs the next meta statement under 12-5 rules with metaVersion CAS retry; deletion is a 6.2 chain entry
- L36: Display-name cap is the wire Schema's limit (12-8), in UTF-16 code units
- L39: Name rule shared by create/rename: client NFC-normalizes before signing (4.2/12-1; server only checks); the given name is never echoed in a refusal
- L76: currentEpoch is chain-derived — the next manifest's epoch (4.3)
- L78: variableNames includes tombstones — the names env rm records before deletion takes them (AUDIT_SPEC 7)
- L93: Pre-signing permission check on the verified chain (rename = member, 12-3/4.2; deletion = admin, 6.2) instead of waiting for the server 403
- L145: Next meta statement: metaVersion + 1, prev = verified current hash, declared head = last verified head; wire derived from the signed context
- L166: An environment statement is always active — deletion is the chain op delete_environment (4.2 / 6.2)
- L194: Retryable CAS conflicts of a meta operation (12-5): MetaVersionConflict and ManifestVersionConflict — refetch, re-verify, re-sign

### `apps/cli/src/env.package/env-rename.ts`

- L1: Rename changes only the display name: the environment ID is the crypto context (3) and never changes, so no value is re-encrypted
- L138: Rename: signed statement + next manifest, CAS-retried with both re-signed over a re-verified view (12-5), confirmed before success (12-10 (3))
- L147: Normalization is the client's job before signing (4.2 / 12-1)
- L163: A concurrent meta operation re-resolves (refetch, verify, re-sign both — 12-5); a same-name rename surfaces as already-named

### `apps/cli/src/env.package/env-rm.ts`

- L1: env rm is the 12-4 deletion composite: a signed delete_environment entry at the verified head (parent-head CAS); admin+ with the environment in scope
- L64: Deletion is terminal: an already-deleted environment is a typed error even though the desired state holds; the verified statement's name drives confirmation
- L86: Pre-deletion name record (AUDIT_SPEC 7): names are printed while still verifiable; a failed flag read is a note, never the confirmation
- L184: Journal-before-send (3-F): if persisting the intent fails, nothing is sent (fail-closed)
- L197: A server refusal (CAS 409 included) means the effect did not occur (settled) — the intent is closed
- L204: Effect confirmation (12-10 (3)): the chain sync must show this run's own delete_environment entry at its seq
- L238: envRmOp: confirmation-gated deletion, CAS-retried over a resynced view, confirmed against the verified chain before success is reported (1-E', 12-10 (3))
- L258: Confirmation happens exactly once before signing/sending/retry; it binds the environment ID, which is never reused (6.2), so re-resolution cannot land on another environment
- L266: On head movement: resync, re-verify, re-sign at the new head; a concurrent deletion surfaces as the determinate 'already deleted' error

### `apps/cli/src/env.package/env-rotate-decrypt.ts`

- L1: env-rotate-decrypt prepares stage (ii) re-encryption material and defines the 'a value cannot be opened' vocabulary
- L15: 'Cannot open' means only no wrap of that epoch is addressed to me; any other decryption failure aborts. A benign absence never stops the run — reported as partial completion
- L47: Never advance the epoch when nothing can be re-encrypted: it would strand every value on the old DEK and is not a revocation; --new-epoch does not help
- L92: Undecryptable means only no wrap of that epoch is addressed to me — a benign absence; a failure despite holding the wrap aborts immediately
- L117: Only a benign absence at or below the current epoch is skipped; a failure despite the wrap is AEAD evidence and aborts like pull/run

### `apps/cli/src/env.package/env-rotate-pass.ts`

- L1: env-rotate-pass is stage (ii)'s bounded pass machinery (CRYPTO_SPEC 7): push pass, rescan, verdict
- L29: remainingExact distinguishes a rescan measurement from the upper bound 'number not completed this pass' when the rescan was never reached
- L35: Post-advance failures are returned as a result, not thrown, so the partial-completion warning cannot be bypassed by an exception
- L42: written aggregates accepted writes across all passes (material for RotationSummary.written)
- L53: Only a push failure corroborated by end-of-pass reality becomes a cause candidate; listing a self-resolved variable's failure would hide another variable's real cause
- L69: Incompleteness cause priority: push failure > unopenable values > conflict; folding unopenable into 'conflict' would send the user chasing a nonexistent concurrent writer
- L83: noteStaleFailures: with a blocking cause nothing happens here; only without one is the no-longer-cause failure left as a warning
- L97: No failure on the last pass means what remains is the conflicts; past failures are not the cause
- L105: Stall judgment looks only at passes that attempted decryption: the final pass's targets are always empty since it does not decrypt
- L119: writerDevice is the device holding this machine's key (device-key.ts)
- L143: epochStaleIds are held as ids, not a count: 'the claim contradicts the chain' may be asserted only when the very claimed variable still remains on the rescan
- L152: unfinishedIds covers variables that could not finish re-encrypting (409, transient failure, epoch conflict)
- L154: written is my accepted writes — the ledger's new baseline
- L156: firstFailure keeps which variable failed so the caller can drop it when the rescan finds that variable resolved (e.g. a concurrent deletion's 404)
- L168: An individual failure never aborts the pass: one transient failure would strand 97 of 100 variables on the old DEK, and stable ordering would make later variables unreachable on every re-run
- L192: Progress denominator is the total known on this pass; a rescan can grow the targets
- L202: Every variable's failure is kept as a warning: only one can be listed as the cause, so without it a permanently-failing variable's reason would never surface
- L245: Promoting an accepted write into the ledger baseline lets later rescans detect a rollback of my own writes
- L264: Known-values ledger: pass targets and accepted writes share one record shape (12-5) — both are values verified as correct
- L292: No separate 409 conflict set is kept: the vanishing warning and alreadyCurrent accounting rest on the unfinished set
- L323: Unverified remaining is neither an upper nor a lower bound — the display labels it includes-unverified (remainingExact = false)
- L335: End-of-pass judgment priority is evidence > contradiction > continue — evidence is resolved by no re-run
- L356: Collected warnings survive a failed rescan via the shared sink — the error channel cannot carry them
- L373: A rescan refusal with evidence (floor violation, checkpoint rule 2) aborts immediately — never downgraded to a re-run-fixable partial
- L385: The rescan's failure takes priority over a single variable's transient failure, which would disguise it as 'a re-run fixes it' guidance
- L403: Cryptographic evidence is the top-priority abort; the epoch-advanced context is conveyed with it, not lost
- L416: An EpochConflict claim contradicting the chain cannot be resolved by re-pushing; abort only when the very claimed variable still remains
- L459: A failure that is no longer the cause stays as a warning with its resolution: listing it as cause misleads, silently dropping it erases that a 502 happened
- L471: Re-encryption (7): push every target, then rescan and verify completion each pass; pushed-everything is not completion evidence
- L498: Warnings go to a sink shared with the caller: an abort escapes as an exception, so returning them would lose them exactly on failure
- L512: Blocking failures are never carried across passes: a resolved pass-1 failure shown later would hide the real current cause
- L524: staleCount is fixed by each pass's rescan; no initial value is held — initializing it would dress an unreportable number as a default
- L589: Completion means the re-verified view has no active value below the target epoch; a resolved transient failure stays a warning
- L614: When the passes run out, the remaining count is a measurement through the final pass's rescan

### `apps/cli/src/env.package/env-rotate-push.ts`

- L1: env-rotate-push: stage (ii) writes are ordinary pushes signed by the performer as writer (7 / 4.1); the verified rescan drives completion and 12-5 409 re-planning
- L26: A conflict PushAttempt carries back the 409's claimed version
- L28: An accepted write becomes later rescans' consistency baseline; the floor is a SHOULD whose write can fail, so rollback checks never rely on the floor alone
- L41: A concurrent deletion (404): a deleted variable has no current value to re-encrypt
- L43: Epoch-conflict cause is decided by the rescan's chain re-verification, not here — 'concurrent rotation' vs 'server claim contradicts the chain' is indistinguishable until then
- L53: A re-encryption push is an ordinary push signed by the performer as writer (7 / 4.1) with no dedicated wire or authorization
- L66: prev is the self-computed hash of the verified latest value — never chain-sign onto the server-claimed hash (12-5 evidence-chain contamination)
- L88: sameValueAs declares value lineage (AUTH_SPEC 12-5 SHOULD): a re-encryption inherits the origin and never clears the needs-rotation flag (AUDIT_SPEC 4.1-5)
- L99: On VersionConflict, never decide on the 409's claimed value — the caller re-fetches and re-verifies reality
- L108: Concurrent deletion handling aligns with the rescan side: warn and drop from targets; remaining variables' processing is not stopped
- L114: Never make the server's claim the source of truth: chain re-verification happens in the rescan
- L123: A floor write failure never turns an accepted re-encryption into unfinished (acceptance cannot be taken back); the lost SHOULD detection material is conveyed as a warning
- L151: An accepted write is assembled from the signed subject itself — not a server echo
- L169: The consistency check runs before the adopt-or-not question: evidence must not hide behind the no-re-encryption-needed shortcut
- L183: Unfinished set covers 409, transient failure, 404 and epoch conflict — otherwise the run's totals would not add up
- L202: A variable that vanished while unfinished is a concurrent deletion — warned, never silently dropped from targets
- L228: stale (active values below the target epoch) is the correct side for the completion judgment and remaining count
- L234: Targets are empty on the final pass: decrypting with no next pass would build one unusable plaintext per variable
- L240: Unopenable reasons are judged even on the final pass (wrap presence only) so only-unopenable-remains can always be reported
- L249: Cryptographic evidence is an immediate abort — never mixed with re-run-resolvable failures
- L257: Rescan has two roles: the completion check (incl. variables created in the window) and 12-5 re-planning of 409 conflicts
- L280: known is not limited to 409 variables: a rescan-recovered variable also becomes the next pass's prev anchor
- L288: Unfinished variables that vanish are warned as concurrent deletions — never dropped silently
- L295: Warnings flow into a shared receptacle because the error channel cannot carry them on failure
- L302: forceResync: on an epoch-conflict pass the chain is always re-fetched, else a concurrent rotation reads as a server contradiction
- L311: decryptRemaining is true only when a next pass exists — decryption only right before use, no unusable plaintext
- L328: Warnings flow before any judgment: even on a pass aborted by a concurrent rotation, this pull's SHOULD warnings must not be lost
- L359: Completion check covers every active value below the target epoch, not only conflicts — a variable created in the window also appears
- L364: Even without decryption, 'can it be opened' is judged from wrap presence (a Map lookup, no plaintext), else the final-pass cause would be disguised as the default 'conflict' wording
- L370: Per-variable warnings are emitted on the final pass too, else which variables were stranded is invisible when a push failure took priority
- L386: A benign missing wrap never fails the rescan (that would fail even the pushable share); a value unopenable despite holding the wrap is evidence and must not be downgraded

### `apps/cli/src/env.package/env-rotate-send.ts`

- L1: env-rotate-send is stage (i): signing/sending the rotate_epoch composite, probing an ambiguous send, confirming acceptance on the chain (12-10 (3))
- L41: Resolving the signing device and signing share one place (chain-append.ts, DK K13-12)
- L56: The op check exists because signChainEntry persists the input's op (narrowing)
- L63: Acceptance is confirmed by my own DEK commitment matching on the chain (12-10 (3)); the accepted family advances the floor even on an error exit path
- L71: rejected is settled: refused with the server's own error body, no effect has occurred
- L73: not-accepted is settled: the chain advanced past the declared head, so this attempt's CAS can no longer hold (prev is signed)
- L83: send-pending: chain still at the declared head means the composite could still land — never settle to not-accepted; the intent stays unresolved for later reconciliation
- L90: acceptance-unknown: could not confirm acceptance (probe failure) — never advance the floor
- L93: Ambiguous send results are probed on the chain before saying anything: 'it didn't arrive' is not guaranteed, and the raw transport error would present the most dangerous state as 'nothing happened'
- L106: dekCommitmentHex judges whether mine was the accepted share
- L108: declaredHead is the vanished attempt's CAS parent — material for judging landing possibility
- L127: Acceptance judgment is a commitment match, never read off the current epoch: conditioning on the current epoch would report 'not accepted' after another member rotated further
- L152: Below-target epoch splits on declared-head position: past it, the CAS can no longer hold (settled); still at it, an in-transit request could land — never settle to not-accepted
- L186: RotateValuesConflictError is its own tag so the bounded retry catches it via passthrough; the unclassified mapping would erase it
- L206: Sending the rotate_epoch composite (12-4) with CAS retry; after acceptance the commitment match is confirmed (5.2 discipline)
- L223: Bundled-manifest material comes from a verified pull; the meta set is unchanged by a rotate (4.3)
- L237: Checkpoint values are the values actually read for re-encryption (active only, 12-7) — no additional reads happen
- L250: member is the row used for acceptance; under CAS resync its fingerprint may differ and write attribution uses this one
- L272: ambiguousSend is set only when a send was attempted: probing a pre-send failure would attach it-may-have-arrived to a local failure
- L281: The last sent attempt's intent and manifest become floor-advance material when the probe confirms acceptance
- L302: The manifest is re-issued with the new epoch baked in (12-4 / 4.3) even though the meta set is unchanged; re-signed under CAS retry
- L321: Journal-before-send (3-F) for a security-critical mutation: never send when persisting failed (fail-closed)
- L340: The boundary checkpoint (H+2, 12-4) covers the one tuple of this environment; re-signed with entry and manifest under CAS retry
- L388: A server refusal (CAS 409 included) is settled — close the intent; a resolution-append failure may be swallowed (open is safe)
- L399: A 404 on a tombstone rotate is never collapsed into environment-not-found (7 discipline: interrupt and warn)
- L425: A manifest CAS conflict means the meta set may have changed — re-signing in this run cannot resolve it; a re-run re-fetches
- L439: CheckpointStateMismatch is the 422 of the boundary checkpoint's values_digest cross-check (12-4); envRotateOp retries it bounded from a verified pull
- L450: ChainHeadConflict-class errors pass through as-is for retryOnConflict's classify
- L457: RotateValuesConflictError bypasses classification: it is the outer bounded retry's signal, and the unclassified path's toCliError mapping would erase the distinction
- L477: On a concurrent rotation, abort without reusing the generated DEK/commitment/wrap set — they are dedicated to that epoch (5 / 5.2 preimage carries the epoch)
- L498: Settled refusals and recover-decided aborts know whether acceptance happened, so they need no probe or extra guidance
- L506: A send failure never reads as nothing happened: probe the chain and always return a failure
- L511: Post-acceptance confirmation uses chain re-verification, not the server's claimed currentEpoch (12-10 (3))
- L527: Floor promotion runs unconditionally once the on-chain commitment match is confirmed, even on an error exit; failure is a warning
- L555: A resolution-append failure may be swallowed: an intent left open is the safe side
- L568: Settling a vanished response: the accepted family advances the floor even on error exit; acceptance-unknown does neither
- L592: Acceptance confirmed on the chain advances the floor even when the command exits with an error
- L608: send-pending and acceptance-unknown are never settled: the intent stays unresolved for the next run's reconciliation
- L614: Post-acceptance failures surface the cause without losing the operational state (epoch moved, re-encryption not done)
- L644: A 2xx is only a transport-layer fact (12-10 (3)): unconfirmed effect means the floor is not advanced and the intent stays unresolved
- L652: Never use a DEK in any cryptographic operation until the commitment match succeeds (5.2) — including a self-generated DEK
- L665: accepted-but-superseded: keep the self-issued manifest as a minimum floor (pinned by the '200 + another rotate right after' test)
- L677: accepted-and-current ordering: floor promotion, intent resolution, then success (12-10 (3))

### `apps/cli/src/env.package/env-rotate-shared.ts`

- L1: env-rotate-shared holds the two stages' shared vocabulary: RotateInput contract, re-encryption material types, small shared helpers
- L18: One pass = a push to every target plus re-fetch/re-verify of the conflicts (pass limit semantics)
- L26: reason undefined means --reason itself was not given — distinct from the empty string (checkReasonLength)
- L32: forceNewEpoch guarantees a new epoch exists after the run even with unfinished re-encryption (needed by all-environment rotation on member removal, 7)
- L41: resync is full chain re-verification, used for CAS conflicts and post-acceptance confirmation
- L43: floor is the local floor (6.3): checks/commits internal pulls and advances on re-encryption pushes
- L50: plaintext is memory-only (no disk, logs, or error messages) and Redacted-wrapped because it holds the value itself; unwrapping happens only inside encryptAndSignPayload
- L59: ConflictedTarget keeps the known latest needed for verifying the winner and the claimed version
- L64: currentVersion is the input of the winner-consistency check — never the basis of adopt/reject
- L68: Warning dedup: pull-wide SHOULD warnings repeat on every pass, so naive listing prints the same line 4 times and buries run-specific warnings
- L78: ensureRotatable drops before the pull (fetching values records var.read); with grant_server the complete wrap set includes a server-key wrap (12-4 / 7)
- L91: Membership and the device's effective role/scope checks are shared with env create
- L106: ReencryptContext bundles the invariants the 3 re-encryption functions share, avoiding the same long argument list at every call site
- L117: epoch is the post-rotation new epoch, or the current epoch on a resume
- L127: asOutcome: post-advance failures are carried back as values, never thrown — an exception would lose the operational state

### `apps/cli/src/env.package/env-rotate.ts`

- L1: Rotation is two stages (CRYPTO_SPEC 7/5.2/6.2, AUTH_SPEC 12-4/12-5): composite acceptance of the wrap set, then re-encryption as ordinary pushes — not bundled, to avoid a giant value-size-dependent request
- L75: written lists only accepted writes (same plaintext across versions) as receipt-advance material; alreadyCurrent and unfinished are excluded

### `apps/cli/src/failure.ts`

- L150: Manifest suppression (§6.3) is pulled ahead of the generic schema renderer: unlike other schema failures it names a server-side act, and the generic 'check values/versions' guidance would misdirect at this verdict
- L491: §6.3 manifest suppression is pulled out ahead of the generic schema renderer because its verdict names a server-side act, not an input or version problem

### `apps/cli/src/floor-check.ts`

- L1: Floor rules (a)(b)(c) (§6.3): all inputs already passed signature verification, so any floor disagreement is non-repudiable evidence and every case is refused; a meta floor detects rollback only (§14.3-5 non-guarantee)
- L82: In a value-bearing response, declared variables legitimately carry no value (declared is the only legitimate valueless state, §6.3)
- L94: A metadata-only snapshot's floor check is limited to the meta level — value rollback, equivocation, and rule (c) cannot be checked from this shape and are never pretended to be
- L110: The schema column is a declaration (§4.2): agreement with the value is not guaranteed, so display and validation are advisory (§14.3-7)
- L119: maxAgeDays (PF6 R9 expiring values, §4.2) is advisory like the declared type
- L287: Chain floor check (rule (a)): the synced chain must contain the floor's head — headSeq regression or a hash mismatch at the floor's seq position fails; seq advancing past the floor is normal
- L386: Every signed field including epoch goes into the signed bytes, so one hash comparison at the same manifestVersion covers any content difference (§4.3)
- L394: Manifest rule-(c) baseline is the max of pullEpoch, the floor manifest's own epoch, and observedEpoch: manifest epochs are non-decreasing (§4.3), so a legitimate newer manifest can only be at or above a known verified epoch
- L445: Every signed field including epoch goes into the signed bytes, so one hash comparison at the same version covers any content difference (§4.1)
- L468: For a deleted variable: an advanced metaVersion is a legitimate deletion, a different status at the same metaVersion is rule-(b) evidence, a regression is rule (a)
- L489: A declared floor's legitimate successors are activation, schema re-issuance, or deletion (all advanced); regression or a same-version difference is rule (a)/(b), omission is variable-omitted
- L517: Unauthorized undeletion (rule (a)): no legitimate path re-activates a deleted variable — both server acceptance and predecessor verification refuse it
- L529: Deleted is a terminal state with no legitimate successor statement, so an exact floor match is required: regression = (a), difference = (b), advancement = post-deletion forgery
- L576: Floor variable keys satisfy §12-1's form by construction (keysAreIds); an out-of-form key here is an internal inconsistency, not untrusted input
- L582: For declared/deleted meta checks a declared distribution can serve as evidence; an active floor requires the value to exist (no legitimate active → declared transition, §4.2)
- L634: Rule (c): a distribution newer than the floor (absent = version 0) with epoch below the pull-time baseline is forward-injection evidence; at-or-above is accepted (legitimate old-epoch values right after rotation, §12-7)
- L657: Metadata-only floor check covers meta-level (a)(b), omission, undeletion, and tombstone replacement only; the environment-level floor commit after it passes is the caller's job
- L688: The manifest is distributed even in metadata-only mode (§12-7), so manifest rules (a)(b) and rule (c) applied to manifests are checked there too
- L699: Floor update order (§6.3): checks run against the previous baseline, and the rule-(c) baseline advance is committed atomically with the variable floors only after verification succeeds
- L751: The in-process floor cache syncs on every commit to the store's folded state, not a send-snapshot, so detection material from a concurrent CLI's log join is not missed by later checks in the same command
- L784: commitMetadata never fabricates a value floor and never advances the pull baseline — only environment meta, manifest, coordinate (ii), and chain head advance
- L793: Skipping manifest floor promotion after confirmed acceptance would leave the floor at the old manifestVersion and open a window where rule (a) cannot detect a server still distributing the old version
- L803: appendIntent (3-F): the send never happens before the intent's persistence (fsync-equivalent) succeeds — fail-closed
- L816: Intent rejection closes only on a server-body rejection (effect never happened); a transport failure stays unresolved for the next reconciliation, and a failed resolution append may be swallowed (open is the safe side)
- L879: The in-process baseline advances first even if the disk write fails (the accepted manifestVersion stays detection material), but a conflicting join is not adopted as the baseline — that would discard equivocation evidence

### `apps/cli/src/floor-evidence.ts`

- L1: Fork evidence (§6.3/§14.2-5) is reported with both coordinates, signed-bytes hashes, and declared heads in third-party-presentable form; no plaintext values or key material (diskless invariant)
- L283: A contradictory-head declaration (§6.6(a)) already passed signature verification, so a contradiction with our view is non-repudiable evidence of server equivocation or attester key compromise (§14.2-5)
- L303: A same-coordinate fold conflict (join undefined, §6.3 rule (b)) is non-repudiable equivocation evidence; the append-only log preserves it, so only preservation is guided

### `apps/cli/src/floor-log-decode.ts`

- L1: Floor-log records decode strictly per record kind via Schema; a line matching no member is undecodable and ignored by fold (self-healing), with unknown-field tolerance matching the previous hand-written decoders
- L63: Record keys are form-checked on the decoded key set because a Record key schema only selects keys (an out-of-form key would be silently dropped); this structurally excludes __proto__ while keeping legitimate 'constructor' IDs
- L82: The environment floor admits bottom coordinates (pullEpoch/observedEpoch/metaVersion = 0); the meta hash is paired with metaVersion — empty at bottom, a 64-hex hash once observed
- L138: An environment deletion issues no manifest (§6.2), so its intent record carries no manifest fields
- L202: Snapshot compaction: fold is the snapshot state joined with records from its `folded` position onward — idempotence/commutativity make a double fold harmless, and a corrupt position falls back to folding all records (§6.3)

### `apps/cli/src/floor-log-fold.ts`

- L30: Re-derived conflicts and snapshot duplicates are identified by coordinates plus both evidence values, with evidence ordering normalized independently of the join's representative selection
- L91: A manifest is a verified observation, so its epoch also joins as an environment-level epoch observation (coordinate (ii)) — the pull baseline (i) is not moved
- L136: Dropped-line positions scope the torn-line warning to after the fold base: lines inside the snapshot-folded prefix retire with compaction, so an old torn line does not ring forever alongside equivocation warnings
- L157: Torn-line self-healing: a conflict's evidence line is valid JSON, so it is never lost to the dropped-line path
- L168: Fold base is the latest valid snapshot; a corrupt `folded` position falls back to folding all records — join idempotence/commutativity keep correctness invariant, only cost changes (§6.3)
- L208: Only dropped lines after the fold base are counted: earlier ones are inside the snapshot-folded prefix and must not re-warn forever

### `apps/cli/src/floor-log.ts`

- L1: Floor storage is an append-only observation log + fold (§6.3 3-E/3-F): overwrite-merge is rejected because concurrent observations would be lost and evidence loss becomes inexpressible; compaction appends snapshot records only, never rewrites
- L58: The compaction trigger is a relative threshold (records since the latest snapshot), not total file size — a total-size basis, once exceeded, would hold forever; the relative basis itself bounds fold cost
- L86: appendAll: one logical append is one write syscall (O_APPEND's atomicity unit); a short write is never spliced (it would interleave and split a record silently) — the whole payload is rewritten, and still-unwritten means failure
- L117: Only a non-zero short write is retried within the rewrite budget; a 0-byte write fails immediately and the last attempt's ShortWriteError propagates when the budget runs out
- L155: The attested-head file's `v: 1` is a format-version marker: a file without it, or with another version, reads as corrupt
- L171: projectId's form is enforced before it enters a file name, preventing untrusted strings from mixing into path assembly
- L179: Every floor-log write is newline-prefixed so a record is always isolated as a fresh line even after a concurrent torn line; the read-the-tail-byte alternative races a torn line slipping in between check and write
- L240: An append that runs out unwritten fails (the caller never treats it as persisted); duplicate records are harmless via the join's idempotence
- L269: Compaction only appends a snapshot record, never rewrites; two concurrent snapshots are harmless (fold bases on the latest, position basis + join idempotence keep a double fold correct)
- L316: Evidence appending is kept separate from the floor log's appendRecords (that one is floor-record-specific) while the physical discipline is shared via appendAll
- L424: A resolution record is not failed on an existing-conflict check: recording a resolution only ever works toward more evidence
- L471: Missing and corrupt attested-head both become null (best-effort tracking): the consequence of losing it is resubmitting the same seq, which the server's idempotent 204 absorbs
- L492: The attested head is written tmp → rename so a reader never sees a partial write; tracking is a separate overwritable class, not a verified observation

### `apps/cli/src/floor.ts`

- L1: Floor semantics (§6.3): the floor is the monotonic join of verified facts, not the last pull's snapshot; on-disk and in-process merges share one join implementation, and epoch observations join as two kept-apart typed coordinates
- L58: A declared variable floor holds the meta side only (the value floor stays empty until activation), so rule (c)'s 'absent = version 0' applies naturally at the first pull after activation
- L91: The manifest floor is detection material for rule (a) regression, (b) same-version difference, and (c) old-epoch injection on an advanced manifestVersion (§6.3)
- L110: pullEpoch (rule (c) baseline) advances only on observations established atomically with value-floor coverage: a chain sync alone must never advance it (both edges — false rejection after rotation and lost detection)
- L120: observedEpoch (coordinate (ii)) joins regardless of provenance and feeds manifest rule-(c) baselines: having no path that could misreject a value, it advances more broadly than the pull baseline
- L128: The environment-meta floor is for rollback detection only — forward injection is not guaranteed (§14.3-5)
- L137: A same-coordinate conflict preserves both observations' evidence: under the append-only storage form, evidence loss via overwrite is inexpressible and fold surfaces the conflict in this shape (§6.3)
- L177: An intent record is not a verified fact and does not enter the join's lattice — fold surfaces an unresolved intent as 'needs reconciliation' (3-F)
- L205: A deletion intent's matching material is only the entry itself: no manifest is issued, and the CAS fixes the slot after the declared head where the delete_environment entry can land (§6.2)
- L233: Attestation evidence is deliberately not entered into the floor's join lattice: one member's false head attestation (leaked key) would otherwise cause every command's permanent refusal (§6.6/§14.2-5)
- L274: droppedRecords is surfaced so the caller warns: partial corruption must not silently become 'less detection material' (same visibility as the whole-corruption warning)
- L299: A metadata-only commit fabricates no value floor and never advances the pull baseline — only environment meta, manifest, coordinate (ii), and chain head advance (session-31 §3)
- L316: Manifest promotion joins the environment-level epoch observation at the manifest's epoch (a verified observation, coordinate (ii)); pullEpoch and variable floors do not move
- L328: Every floor commit is append (through fsync-equivalent durability, 3-E′) → fold, and a fold detecting a same-coordinate conflict fails with a typed error while the evidence remains in the log (§6.3)
- L361: appendIntent (3-F): sending may proceed only after the append's fsync-equivalent durability — on failure nothing is sent (fail-closed)
- L377: The attested-head record is a separate class outside the join lattice (one's own send record, not a verified observation): losing it only causes an idempotent resubmission, so it bears no safety; missing/corrupt = null
- L404: listProjectIds reads file names only and is never used as decision material — only as an information supplement to device add's 'nowhere to be found' range (K13-7)
- L421: floorRecordGet is own-property only: 'constructor'/'prototype' are legitimate §12-1 IDs, so a plain lookup would resolve an absent ID to an inherited Object property and misbehave
- L443: Floor record keys' brand is taken back through the same §12-1 guard the decode side enforced; an out-of-form key at join time is an internal inconsistency, not untrusted input
- L459: Same-version/different-hash join keeps the lexicographically larger hash as representative (commutative, idempotent, fold-order independent); the conflict's existence is the refusal condition, so the choice does not affect detection
- L559: Deleted is a terminal state (§4.2): a live observation beyond it has no legitimate path (unauthorized resurrection evidence), and the representative stays deleted
- L573: A different status at the same metaVersion always means different signed bytes — rule (b) evidence
- L587: Live variable floors join value and meta sides independently; when either side is active the representative stays active (no legitimate active → declared transition, ruling CS)
- L642: Deleted is a terminal state, never overwritten by active/declared; both inputs passed §6.3 verification, so every same-coordinate difference is equivocation evidence
- L659: With only one side deleted, deleted is the representative regardless of metaVersion ordering: an advanced live side is undeletion, a same-version one is rule-(b) evidence
- L737: Variable keys are unioned, never dropped: a legitimate floor's keys never disappear (a deletion stays as a tombstone record), so a key present on only one side is kept
- L742: A variables map's keys satisfy §12-1 by construction (the decode side refuses out-of-form keys); an out-of-form key at join time is an internal inconsistency, so the brand is re-taken through the same guard

### `apps/cli/src/fp-words.ts`

- L1: Word display of a fingerprint (BIP39 English 12 words — CRYPTO_SPEC §3) and the shared implementation of the explicit out-of-band
- L22: Number of re-entry attempts (shared from server-grant's CONFIRM_ATTEMPTS).
- L25: FP hex (16 bytes) to BIP39 12 words (§3). `invalidMessage` is the wording for malformed input.
- L39: One-line numbered display of the 12 words (shared from server-grant's display format).
- L44: Explicit confirmation by re-entering the last word (the ADR-0014 ceremony). Blocks the form where the user proceeds without reading the
- L53: The prompt body up to just before `(n/3): `.

### `apps/cli/src/github-signing-keys.ts`

- L1: The backing source `github-signing-keys` (CRYPTO_SPEC §6.5 — IV2). Machine-checks via GitHub's public API whether the peer's (acceptor's /
- L33: The fixed host (not swappable).
- L36: Time allowed for one inquiry (a check is "grounds to skip", so do not wait long).
- L39: One element of GitHub's `GET /users/{login/ssh_signing_keys` (only the fields needed).
- L44: The check's result (a closed type — the caller decides whether to return to the ceremony).
- L46: The named login's signing-key list contains the target sig public key byte-for-byte.
- L48: The list was fetched but the target key is absent (the peer is unregistered / registered a different key).
- L50: The login does not exist on GitHub (404).
- L52: Unfetchable (offline, rate-limited, response of the wrong shape). The reason is a short display string.
- L55: Result of fetching the list (the stage before checking — key lines not yet parsed).
- L61: `GET /users/{login/ssh_signing_keys` (unauthenticated, fixed host, with timeout).
- L78: Transport-layer failure / timeout: no body or headers are carried in (only a short kind)
- L101: Checks whether the `sigPubHex` key is contained in the login's signing-key list. Failures and inabilities alike are returned in the type
- L124: Kinds other than ssh-ed25519 (RSA / ECDSA / sk-*) and broken lines are out of scope — an InvalidInput is skipped, the same as the
- L141: Interprets the response body (a JSON array + `key` string; null when the shape differs).
- L151: Description of a transport-layer failure (kind only; no body, headers, or URL).
- L165: Short display text for a check result (presenting the reason to return to the ceremony).

### `apps/cli/src/guardian.package/guardian.ts`

- L1: Guardian design: segments are sealed to each guardian's currently valid device keys (§8.3 device expansion, no global key directory); key confirmation follows the §6.5 ceremony; approve (renamed from key approve, K4-15) re-seals the my-addressed segment to E.pub on the spot since the server does not relay E.pub; plaintext KEK/segments/B exist only in local variables.
- L90: MAX_GUARDIANS is the same cap as the acceptance policy (AUTH_SPEC §13-8), giving guidance ahead of the server's 422.
- L93: Guardian naming takes the sensitive-terminal gate (ADR-0016 decision 7): interactive human terminal only, no flag route, so a non-interactive caller can never decide where key material is sealed; the piped-stdin ceremony form is dropped too.
- L112: Guardian key confirmation applies the §6.5 fulfilment form: a fingerprint-book hit excuses the re-reading, but a per-naming yes remains, and what is confirmed is the FP of each device the segment is sealed to.
- L166: Naming preconditions state the same rules as the server's 422, here first.
- L203: Guardian candidates resolve from the chain's current members (§8.3) — no public-key directory is built.
- L218: A guardian's keys are all of the person's currently valid device keys: the same segment is sealed once per device (§8.3).
- L270: B is wrapped with a random KEK and the KEK is split into segments sealed to each guardian's each device (§8.3).
- L329: guardian add's openReserve runs exactly once, after input checks and the ceremony, just before sealing — opening the ledger is the qualification for changing it (K4-2).
- L370: Changing the ledger requires opening the reserve key (CRYPTO_SPEC §8 revision (4)).
- L466: shareIndexes come from the rows themselves: a segment always has at least one row.
- L480: Some devices revoked: propose recreation without waiting for every device to be revoked (K1-13 SHOULD).
- L579: Section for guardian approve (§8.4); the old-device approval path was removed in the 2026-09-19 DK revision.
- L647: Approval confirmation sends nothing for anything but an explicit yes.
- L720: Approving opens the my-addressed segment with this device's key and re-seals it to E.pub on the spot (§8.4).
- L779: guardian approve was formerly `key approve`, renamed when the old-device path was removed (K4-15).
- L792: The server never shows the request to the ward themself (§13-7), but the response is not trusted — the ward is refused locally too.

### `apps/cli/src/invite-link.ts`

- L1: Building and interpreting invite links (AUTH_SPEC §15-3 — 2026-09-13 IV revision, v2). Link format
- L50: Cap on scope's environment list (CRYPTO_SPEC §6.2 — the same 256 as grant_server's scope).
- L52: Invite id (ULID — 26 Crockford Base32 chars. Identical to api-schema's InviteIdSchema).
- L54: GitHub login (1–39 chars of alphanumerics and hyphens; no leading/trailing hyphen).
- L57: Roles grantable via an invite (owner is never granted via an invite — §15-1).
- L60: The issuance statement + seed + backing-source check material a link carries (the §15-3 v2 parameters).
- L63: The link key's seed (32-byte hex — the invite's secret).
- L72: The scope to be granted (2026-09-14 ES — covered by the issue signature. With `all`, the environment list is empty).
- L75: The inviter's GitHub login (self-declared, unsigned; null when omitted).
- L80: Builds a §15-3 link (parameter order is fixed to the spec's listed order). The return value embeds the seed too, so it is returned still
- L95: Why it is unwrapped: assembling the link string itself. The result is wrapped in Redacted again so the raw string never leaves this function
- L115: Reason for a parse failure (the caller maps it to an error message).
- L121: Fetches a fragment parameter with pattern validation (mismatch = null).
- L127: Interprets `s=` (the verified head seq) (decimal positive integers only).
- L137: Interprets `il=` (the inviter's GitHub login): omitted = null; when present, only the login shape.
- L175: Interprets `sk=` / `se=` (the scope to be granted): kind is a closed set; with `all`, `se` is empty; `listed` is a comma-separated
- L199: every() does not narrow the element brand — filter does (the length check keeps `malformed = null` identical)
- L213: Interprets the link data from the fragment (v=2 verified) (malformed = null).
- L249: Interprets the `<link>` input. Missing required parameters, malformed formats, the old version (`v=1`), and raw tokens are all errors (a
- L262: Why it is unwrapped: parsing the link's syntax needs the byte string itself. The input arrives still Redacted from the argument layer

### `apps/cli/src/invite.package/command.ts`

- L68: An invite link embeds the link-key seed, so it is received as Argument.Redacted and passed still Redacted to invite-link.ts's interpretation boundary; the link carries the project ID (v2 — the raw-token path is gone), so it takes no --project.
- L112: The issuance signature (§6.5) is made with the inviter's chain sig key, so creating an invite requires the master key.
- L114: The link's il is a display snapshot of the inviter's GitHub login; if it is unfetchable the issuance still succeeds and the acceptor falls back to the ceremony.
- L148: The accept link arrives still Redacted (it embeds the link-key seed) and is not unwrapped here — syntax interpretation is left to invite-link.ts's boundary.
- L202: invite list performs §6.5's independent verification of the acceptance blocks plus the issuance-pin cross-check.
- L215: A signature-verification failure or pin mismatch is a detection of evidence, not a successful read — the exit code is never 0 then, so a script can use list as a health check.

### `apps/cli/src/invite.package/invite-accept.ts`

- L59: The inviter FP is derived from ie ‖ is per §3.
- L74: Issue-signature failure means do not accept, never overridden by the out-of-band check: it is either tampering on the link's path or a third party's link ghost-added with the inviter's public key.
- L112: Mutual confirmation (§6.5): a mechanical check against the chain is impossible at acceptance time (a non-member's chain GET is a flat 404), so it happens at the first sync after add_member; the fingerprint ledger waives the 12-word re-read on a hit but never the explicit yes, and is usable only on interactive terminals.
- L152: A ledger hit is usable only on the interactive-terminals + no-flag + non-agent path; then the two read-out instruction lines are dropped.
- L190: The ceremony is never performed by an AI agent environment, and a ledger hit is not grounds for acting on one's behalf either — only an explicit flag is the non-interactive path.
- L221: Master-key preparation for accept carries ruling A′'s 3 guards: never generated under an agent environment; existing recovery registration steers to key recover instead of overwriting; explicit interactive confirmation; an interrupted run resumes idempotently at acceptance.
- L285: Sufficiency form 4 (IV2): when the backing source confirms the inviter's sig key belongs to the named login, the invitee's "was expecting an invite from that login" declaration satisfies confirmation; an impossible check falls back to forms 1–3, but a --from/il mismatch is refused as a swapped-in link.
- L354: Form 4's interactive declaration is a yes naming the login; non-interactively only the --from flag is the path — agent environments are refused and non-terminals fall back to the ceremony.
- L404: §15-3's order: verify the issue signature, mutual confirmation (form 4 then 1–3), key generation when absent, joint signature, accept, and pin the anchor only after the acceptance is established.
- L458: A project/role mismatch between the issue-signed link and the server's response means the server contradicts itself or a row was swapped — refuse.
- L476: Scope is covered by the issue signature, so a response scope disagreeing with the signed link is likewise the server contradicting itself — refuse (AUTH_SPEC §15-3).
- L487: The anchor pin comes only after the acceptance is established and reconciled.
- L496: When a key was born inside this acceptance, GitHub registration is offered here so the inviter can add the invitee ceremony-free (supplement 21, ruling G ⑥ (b)).
- L505: A failed anchor pin is a SHOULD-level degradation: the acceptance itself is already established.
- L511: An existing anchor already machine-checked is never overwritten: the chain is append-only so its containment check holds forever, there is no gain in replacing it, and leaving no overwrite path narrows the attack surface; an unchecked anchor is replaced by the latest acceptance.
- L531: Pinning is SHOULD-level local defense, so a pin failure does not fail the acceptance (the link is consumed; re-running can only yield 410); a corrupt pin file is left un-overwritten with a warning making the degradation explicit.
- L562: Replacing an unchecked anchor is surfaced in one line: with zero trace, substitution by a fake link (a DoS path) would be unauditable.
- L602: On the completion display, when a backing source exists "register" is the primary path and the 12-word read-out its fallback (ruling G ⑥ (a)).

### `apps/cli/src/invite.package/invite-create.ts`

- L48: The issued link contains the link key's seed — never unwrapped except for display.
- L80: id/link key are random so a collision effectively never happens; if it does, the error directs re-running to draw a fresh one.
- L88: Pre-issuance checks run before communicating: the §6.2-level role rules, and that the local master key matches one's own key on the chain, otherwise the issuance fails the invitee's and one's own later verification.
- L109: The local key must be one of the inviter's device keys (signer is per device); only once the device is resolved is the effective permission (person ∩ device cap) defined, so the permission check runs afterwards — issuing from a cap-narrowed device would trap both sides of the ceremony.
- L140: Scope is checked before communicating (K4-G): every --env id must exist on the chain and the effective scope must contain the invite's scope; the server does not check, but a pass would make the post-acceptance add_member fall to consensus — a trap for the invitee — so do not issue, with no escape hatch.
- L207: Issuance authorization is enforced by the server, but the role rules are dropped locally before communicating for clear wording.
- L222: The addressee's GitHub login is kept only on the issuance pin.
- L233: Under an AI agent environment, displaying the invite link would persist the seed into the transcript — a leak path before person-to-person handover; since a seed cannot be re-displayed, "issue without displaying" is not an option and issuance itself is refused.
- L241: The same scope goes onto all four places: the issuance, the issue body, the link, and the issuance pin (K4).
- L294: The issuance pin (SHOULD) is cross-checked at member add against the server's claimed row and retains the addressee login; the seed is not saved, and a save failure does not fail an already-established issuance since the link can be shown only once.

### `apps/cli/src/invite.package/invite-list.ts`

- L70: "Checked and passed" and "no check material" must not get the same look (S12): on a row missing §6.5's extra material, only the issue signature pins it.

### `apps/cli/src/invite.package/invite.ts`

- L1: Invite design: the link key's seed exists only on the wire (the link) and in display — never persisted (the pin holds only the public key) and the server never receives it; accept's chain check happens on the first sync after add_member.
- L83: The granted scope is part of the issuance; add_member signs this scope.
- L105: Each crypto failure verification can produce folds to "does not verify" (the pre-bridge !ok folding); any other error kind is an invariant break and dies.
- L133: Issuance is verified under the inviter's current key derived from the chain — independent of the issuance pin (ruling A ⑦) — so a different admin running member add detects a swapped row by the same check.
- L150: The issue signature's verification key is any of the inviter's current devices (K4-16): if any verifies, the row is genuine; a row issued by a revoked device does not pass and the inviter reissues.
- L198: The acceptance block is verified independently: signed_bytes are reconstructed locally from the listing's material and the verified projectId, never trusting the server's declared verification result.
- L281: Unwrapping reason: displaying the link is this command's very function, and displayability was already decided by the TTY + agent gate at the head of inviteCreateOp.
- L307: Unwrapping reason: key derivation needs the seed bytes themselves; the seed is consumed here and from here on only the non-extractable CryptoKey and the public key flow.
- L320: The issuance-pin cross-check (§6.5 SHOULD): a server-claimed row disagreeing with the issuance-time link_pub/role/scope signals a swapped row or false claim; with no pin, only the issue signature's verification pins the row.

### `apps/cli/src/key-record.ts`

- L1: Generating a key record (`StoredMasterKey` — the common shape of CRYPTO_SPEC §3's device key / reserve key). The device key (keygen.ts) and
- L27: A WebCrypto reject surfaces as `CryptoRejected` through the bridge and is mapped to a typed failure, not a defect (do not flow an
- L35: Generates a fresh (enc, sig) key record with the private halves redacted.

### `apps/cli/src/key.package/handoff.ts`

- L1: Handoff design: the ephemeral key E is never persisted and the recovered B does not persist (downstream issues a new device key, signs add_device with B, then discards B); the old-device approval path was removed in DK K4 because everyday devices do not hold B; ceremonies run only on a human's interactive terminal; plaintext exists only in local variables.
- L192: The ephemeral key E exists only in this process's memory (§8.4).
- L250: The approval-wait deadline is judged at the loop's top, before the request — not during the wait between polls.
- L342: Once the request has served its purpose its row is still deleted: the approvals become worthless together with E, but the row is removed anyway.

### `apps/cli/src/key.package/key-publish.ts`

- L1: Key publish design: only public key material, so no ceremony or display gate; --gh calls an installed gh CLI (never fetched) because maruhi holds no GitHub token and direct API is not allowed (§4); post-generation registration is offered only interactively and never done silently, since it changes the user's GitHub account.
- L126: Post-generation registration (ruling G ⑥ (b)): only interactive + non-agent + yes completes registration via gh; everything else shows guidance only, and a failure here must not affect the key generation's success.

### `apps/cli/src/key.package/key-recover.ts`

- L1: Recovery design (K4-10/K16): B obtained from the ledger is used only for issuing the device key and is then discarded (written to neither keychain nor agent memory); B is recorded as reserve only when the ledger content carries the reserve mark and it is revoked nowhere; rotate deletes the old B's passkey/guardian rows so no false trust remains.
- L163: Registration's keyless prologue runs floor, anchors and gossip but not attestation submission or first-sync registration (the new device is not yet on the chain; signing is manual with B); the standing judgment lives in one place (device-standing.ts) and a sync failure folds into "could not sync" (K14-1).
- L259: Recording the opened key as reserve (DK K16): if it is revoked somewhere or lacks the reserve mark, record nothing; otherwise record it without asking.
- L288: finishRecovery is the common tail of every recovery path (K4-10, revised by DK K14), ending with discarding the reserve key.
- L320: The reserve-recording judgment runs on the chains opened for registration (no doubled syncs, K14-1/K14-5); projects that could not sync are already named in their reports, so no Note for the unchecked range is emitted.
- L331: B's secret finishes its duty here: the reference is released, and the save paths are closed by types (reserve.ts).
- L350: --resume backfills even when already registered, with the reserve key — the only route in a recovery where no other device exists; device approve is not named because a registered key cannot create a request (K11-5).
- L380: A machine that already has a key is refused before touching the ceremony or the server; --resume is the only exception, for continuing an interrupted recovery.
- L442: --replace never opens the ledger, so `via` plays no part in it; the command refuses --passkey with --replace before any network.
- L470: Separation targets (DK K16) are a ledger key without the reserve mark or revoked somewhere; everything else goes to resealing and recording.
- L514: --replace is the escape route for a lost/leaked code (K4-38): it seals a new reserve key without opening the ledger, and since the old B cannot be opened, the old keys' revocations are signed by this device key; an old reserve key absent from the records cannot be revoked, which is warned about.
- L527: Before --replace writes, the warning names what disappears; the ledger listing's counts are read only for the warning's wording, and an unreadable listing does not stop the replacement (it is the escape route of a user who lost the code) but becomes a Note.
- L658: The old-FP set includes keys left behind by an interrupted re-run, so nothing stale survives a resumed rotate.
- L771: A failed backfill to the new reserve key is exit code 1, not folded invisibly into a count (K11 G9): the old reserve key is revoked right after, so a script must be able to detect the new key's gap (K11-14, owner's ruling: align with approve/recover).
- L811: The stale-reserve FP set is the opened B plus every locally recorded "reserve" row regardless of a revoked mark — picking up a key that got only the mark written before an interruption — minus the new key.
- L838: Deleting the old B's passkey/guardian rows (K4-11): when the advance listing was unreadable (null), the deletion is skipped and the removal procedure goes into a Note — the intervening writes never touched these rows, so the command is not failed on the same failure after the writes are done.
- L886: Rotate's signing keys are verified before opening the ledger (the code entry), since the revocation and registration are signed by this device key.
- L890: The opened B proceeds only when it carries the reserve mark and is revoked nowhere (DK K16); an unmarked one is left untouched.
- L898: Revocation targets are the opened B plus locally recorded reserve keys (revoked marks included), minus the new key: after an interrupted run that replaced only the ledger, B is the previous run's new key while the original stays recorded and on-chain; appendRevokeDevice is idempotent.

### `apps/cli/src/key.package/keygen.ts`

- L1: Key generation design: one identity (K4-19) — generating on an account with a ledger is a second device, guided to device add, and an unfetchable ledger state refuses fail-closed; --new-identity is the specifically-named opt-in; overwriting an existing key is refused; the secret key is never displayed.
- L69: One identity (K4-19): when a ledger exists, generation is "a second device" and routes to device addition.
- L90: The record is re-imported for self-verification before storing — never leave a record that failed verification in the keychain — and the failure wording is specific to this path: the default wording points at a stored record that does not exist here, and an environment cause (WebCrypto unsupported) is distinguished from a key problem.
- L106: Nothing is stored yet on this failure path, so the message states that nothing was written and shares only the next step, rather than pointing at "the stored key".
- L116: Never JSON.stringify the record for storage: the private side would be stored redacted, leaving an unrecoverable keychain record; storing detects overwrite because a concurrent run between the guard and generation could otherwise silently erase one key with a last-write-wins set.
- L133: The GitHub registration route is offered only after the recovery-code ceremony finishes (ruling G ⑥ (b)).
- L151: The FP word display (§3) is the re-display path for reading/carrying the word list in invite mutual confirmation (§6.5) and device addition (device approve).
- L156: The reserve key lives only in the ledger; the local record is public-side only.
- L162: Custody reminder: the recovery registration state is always shown, but a failure to check it does not fail key show (whose job is displaying the local key) — it degrades with an explicit "could not check", usable offline and with an expired token.

### `apps/cli/src/keychain.ts`

- L1: The OS keychain boundary (Effect service) and the shape of stored records. The only secrets the CLI may persist are the maruhi API token
- L29: Where the records live: the OS keychain, or the memory of a running `maruhi agent` (KL2 — agent.ts). The distinction exists so success text
- L36: OS keychain boundary. Names are scoped by tokenEntryName / masterKeyEntryName.
- L49: Name for the store (for success text). Saying "stored in the OS keychain" inside an agent session would point at a place that does not
- L63: Whether an entry name is an API-token entry (the only kind `maruhi mcp` may read — pf5-design.md ruling M7).
- L73: Whether an entry name is a master-key entry (the agent's `--key-ttl` applies to these only).
- L78: The maruhi API token record stored in the keychain (AUTH_SPEC §4-5).
- L83: Expiry fixed at issuance (AUTH_SPEC §6 — W3a). Non-sensitive metadata used for the early expiry warning (W3a ruling CL — a local check with
- L91: The master keypair record stored in the keychain (CRYPTO_SPEC §3). Only the secret halves (`encSkHex` / `sigSkSeedHex`) are wrapped. The
- L105: `"reserve"` = the client created this key as the reserve key (CRYPTO_SPEC §8 — DK K16). Carried inside the sealed ledger blob only; a
- L116: The very output of `Redacted.toString()` / `toJSON()` (including labelled forms).
- L119: The public version, for checking whether the redaction placeholder itself arrived outside stored records (e.g. environment variables).
- L131: Whether a stored record has the redaction placeholder written into it (detection at the read boundary). As the note at the top says
- L165: Explanation of how the placeholder got in (the caller appends the recovery steps per record kind). The broken artifact is an argument
- L179: Name for the token record (sentence-initial; varies by store — never names a place that does not exist). The fix (`maruhi login` overwrites
- L190: Name for a record that stored the placeholder (varies by store — never names a place that does not exist).
- L197: Wording when the placeholder was stored in a token record. Split because the recovery means **differ by record kind**. Since `maruhi login`
- L209: Wording when MARUHI_TOKEN holds the placeholder itself. Here the cause is not a maruhi bug but **a paste mistake**: the redacted display
- L220: Display of an entry name (escaped, plus a note that it is escaped). Dropping the note would make **the displayed name not exist** for a
- L232: The shared "delete it by hand, then proceed as follows" part (the exit is the same for placeholder and corruption alike). The point is
- L253: An agent session's record exists only in this process's memory. "Delete it from the OS keychain by hand" would be unexecutable guidance
- L267: entryName contains user_id (a free-form string distributed by the server). It is sanitized before reaching the terminal, but **escaped, not
- L280: Whether the current format's fields are all present (the contents of the values are not questioned).
- L287: Classification of an unreadable record. This is **the decision of whether deletion may be recommended**, and getting it wrong loses the key
- L314: Not even JSON = a shape no version of maruhi writes. Safe to delete
- L317: Arrays stay on the keep side — a future version could plausibly use one as a container holding multiple keys
- L322: A JSON scalar (null, number, string, boolean) = a shape no version of maruhi writes as a key record. Leaning toward "maybe another format"
- L330: Unreadable despite having **all** fields of the current shape = the contents are broken (parseStoredMasterKey fails only when a value is
- L343: Anything else (a different suite, no suite, nested, etc.) is **possibly another format**. Do not bet on a single field name to judge "safe
- L350: Wording for a record this version cannot read (a future version may have written it). **The default is to not recommend deletion**.
- L373: An agent session's record can neither be deleted by hand nor copied out (it lives only in memory). Reaching this branch means a newer
- L388: Name for the record (varies by store — never names a place that does not exist).
- L405: Wording when a master-key record is corrupt and unreadable (damage other than the placeholder). As with the placeholder, the point is **not
- L420: Wording when the placeholder was stored in a master-key record. This one cannot be fixed by commands alone: the overwrite-protection guard
- L438: entryName contains user_id (a free-form string distributed by the server). It is sanitized before reaching the terminal, but **escaped, not
- L466: The stored record is the token's persisted half: its user id is minted where it is read back
- L478: Serializes a token record for the keychain, unwrapping the token. Why unwrap: what is written to the keychain must be the raw value.
- L509: The marker (DK K16) is absent or "reserve" only; unknown values are treated as a corrupt record
- L528: Serializes a master-key record, unwrapping the private halves. Why unwrap: same as serializeStoredToken — what is written to the keychain

### `apps/cli/src/known-fingerprints.ts`

- L1: The verified-fingerprint ledger (KF — ROADMAP / integration-options.md §3 supplement 17, turn A). Because keys **belong to devices and
- L61: When the human performed the out-of-band confirmation (not refreshed on a hit — a record of the verification's fact).
- L70: The whole file (known-fingerprints.json). Keys are origin → user_id → fingerprint set (v2 — DK).
- L79: The lookup result. corrupt is distinguished from miss (the caller emits the warning).
- L87: The file path for display (the path that lets deleting an entry force the ceremony to re-run).
- L90: A read-merge-write append (adds a fingerprint to the same person's set; the same fingerprint refreshes its confirmation time).
- L102: Where the ledger lives (same family as the config: <parent of config.json>/known-fingerprints.json).
- L109: The matching ledger entry (null = no hit / mismatch / corrupt = needs the usual ceremony or a flag). A hit goes to confirmKnownFingerprint
- L118: The file path for display (the path that lets deleting an entry force the ceremony to re-run).
- L120: The warning for a **mismatch** between the ledger's records and the presented fingerprint (a no-op on match or no records). Called
- L130: The append called **after** the ceremony / flag check succeeds. A write failure degrades to a warning (fail-open — the ledger is
- L138: The pre-ceremony ledger consultation (shared by member add's acceptance-key check and invite accept's inviter check): a match = the 12-word
- L187: Judges whether a ledger hit may actually be used (no flag + non-agent + stdin / stdout interactive terminals) and returns only a usable
- L213: Name the side that failed (the DP5 supplement G discipline — describeNonTerminal)
- L222: The per-acceptance explicit confirmation on a ledger hit: re-running the 12-word out-of-band read-out is waived, but **the consent to this
- L265: Strict decode (v2). One invalid entry treats the whole as corrupt (no partial reads — same as pins).
- L268: The set → the lookup result's entry list (ascending FP).
- L282: *Only** uncreated (NotFound) folds into "none". Folding EACCES / EISDIR / EIO etc. into "none" would let record overwrite with an empty
- L306: own-property lookup (floor.ts's discipline — never pick up a value via the prototype)
- L314: Writing an off-form key would make the next load wholly corrupt (strict decode), so refuse beforehand (the caller degrades to a warning
- L322: Refuse to overwrite a corrupt file (the same discipline as pins' merge — never silently erase the traces of an unintended change)

### `apps/cli/src/lease.package/lease-client.ts`

- L1: Lease responses are self-contained and verification material is never fetched from other endpoints (the chain API 404s non-members, §14-2); obligations (1)–(6) map to specific stages, obligation (6) runs before any wrap is opened, and no floor is used — the workload is a floorless first-sync class whose main mitigation is the repository anchor.
- L81: Declared variables carry statements only, no values (§14-2); they are the material of ci run's presence check, and absent means nothing declared.
- L87: The manifest is required on the wire: the schema refuses an omission at decode — the same verdict as a dropped environment statement (§9.1 (5) / §6.3).
- L93: The checkpoint snapshot is the material of anchor rule 2 (§14-2); a response omitting it despite a baseline on the bundled chain is refused by checkpoint-integrity.ts.
- L114: The DEK never leaves unwrapOneLease until the §5.2 commitment check succeeds, and the check coordinates are built from my own verified values (genesis hash, requested environment).
- L176: Lease wrap set checks follow the same discipline as deks.ts's pre-loop stage: declared epoch vs the chain cap, duplicate refusal, commitment presence.
- L201: LeaseGrantCheck is minted only by requireLeaseGrant and required by unwrapLeases, so no lease wrap can be opened on a path that skipped the authorization check — the order is carried by the types, not only statement order.
- L214: Lease authorization (§9.1 (6)) unions over active grants because the workload cannot authenticate which server key served it; the lease policy is not evaluated here (the server enforces it); a refusal is evidence of a non-conforming server, so the message never suggests widening the grant, and without an anchor this is defense in depth only.
- L234: This return is the single mint site of the LeaseGrantCheck brand.
- L245: unwrapLeases applies deks.ts's discipline to lease wraps that carry no §5.1 registration signature, and takes the obligation-(6) proof for the same chain view and environment: nothing is opened without it.
- L264: A mismatched grant proof is a caller defect, refused fail-closed before any wrap is opened.
- L273: Only the verified entry point computeLeaseClaimsDigest is used for the claims digest; using the builder directly would bypass the empty-field guards.
- L303: The opened DEK is wrapped in Redacted only here, after passing the §5.2 check — a pre-check DEK never leaves unwrapOneLease.
- L310: verifyLeaseResponse trusts nothing in the response before it passes: the chain is re-verified against the pre-pinned genesis, declared coordinates are cross-checked, every signature is verified, and every DEK must match its chain-published commitment before use (§9.1 (1)–(6)).
- L329: Declared-coordinate inconsistency is surfaced first with what differed, though later verification would drop such a response anyway (the §6.3-5 posture).
- L350: The repository anchor check substitutes for a floor in CI: containment of the pinned head plus epoch non-regression detects rewind distribution.
- L356: A deleted or unknown environment is refused first with its own message, because a deletion also prunes the id from every grant scope (§6.2).
- L359: Lease authorization (6) runs before any lease wrap is opened.
- L362: Only the chain-derived value is used for the current epoch (§6.2); the declared currentEpoch is checked only for agreement — declared values are not trusted.
- L395: Decryption uses the same decryptVerifiedValue as run/rotate with a context built from verified coordinates; a missing wrap for a value's epoch is a strict failure.

### `apps/cli/src/ledger-open.ts`

- L1: Opening the ledger (CRYPTO_SPEC §8 revision (4) — 2026-09-19 DK; design record dk-design.md §9 K4-2). Changing the ledger (re-issuing a
- L41: Opens the ledger blob B and loads it as the reserve key (memory only).
- L61: Opens the ledger for a change (passkey sealing / guardian designation): the key must carry the reserve-key mark and be revoked nowhere (DK
- L71: The re-run command embedded in the refusal wording (e.g. "maruhi guardian add …").
- L74: Loading the device key comes before opening (a device without a key is not qualified to change the ledger)
- L87: Whether the opened ledger key may be used by a ledger-changing command (DK K16): if it is revoked anywhere or lacks the reserve-key mark
- L123: Names, in a Note, the range where the ledger key's revocation could not be checked (DK K16-6: unverifiable projects do not stop the

### `apps/cli/src/manifest.ts`

- L1: The CLI's shared implementation of issuing and verifying the environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5). Issuance (env
- L44: The evidence material of a verified manifest (§14.2-5's self-containedness — the comparison target of the floor's manifest extension, the
- L52: The current epoch at issuance time (§4.3's freshness anchor — the material of floor rule (c)'s manifest application).
- L58: The self-computed signed-bytes hash (floor rule (b)'s comparison target, the basis of the next prev).
- L67: The input of variables_digest (the latest form of verified statements — tombstones included, §4.3).
- L70: Issuance input: the previous manifest (none = env create's v1) and the post-issuance meta state.
- L74: The current epoch at issuance time (rotate compound = new_epoch; otherwise = the verified view's current epoch).
- L76: The verified previous manifest (null = no stored manifest → manifestVersion 1).
- L81: Every variable entry of the post-issuance meta state (tombstones included — §4.3 (3)'s recomputation target).
- L83: The latest form of the post-issuance environment meta statement.
- L87: The declared head. Compound (env create / rotate) = the current head before the append (§12-4); meta operation = the last verified chain
- L99: The self-computed hash that, once accepted, becomes the local floor's manifest record (§6.3).
- L101: The signed manifestVersion / epoch (for floor records and display).
- L106: Issues the next environment manifest (CRYPTO_SPEC §4.3): computes the canonical variables digest from the post-operation statement set
- L139: The wire is entirely derived from the signed context (this module's reason to exist. suite is a Literal — the context is built with
- L161: The distributed manifest's verification result (future = the entry to bounded re-sync — values.ts's shared convention).
- L167: Verifies one distributed environment manifest against the verified chain history and the **verified** statement set (CRYPTO_SPEC §4.3 /
- L196: The local floor's manifest record (the predecessor of adjacent-prev verification — null = no floor).
- L236: Only an adjacent version gets the floor-derived predecessor (above). Otherwise it follows latest-only's known constraint — detecting
- L272: An adjacent-prev mismatch is a contradiction against the floor (the verified previous manifest) = evidence of a fork in the manifest chain.
- L284: user_id is a length-constrained free-form string on the wire — neutralize before showing on the terminal

### `apps/cli/src/master-ops.ts`

- L1: The narrow crypto operations of the ledger (CRYPTO_SPEC §8.3 / §8.4 — KL3 / DK). Only the 3 "compute once with a key" operations gather
- L39: Opens the segment addressed to me as a guardian (called right before approving; the result is resealed immediately).
- L45: info is assembled by openGuardianShare in the spec's field order (a transplant fails decryption — §8.3)
- L61: Wraps the reserve key's blob B with the KEK (§8.1's master-wrap form). The shared body of passkey registration (kind = passkey-prf — §8.2)
- L74: JSON.stringify(record) is not used (the private side would be redacted — the note in keychain.ts)
- L81: Seals a 32-byte value to the requester's ephemeral public key (the E.pub decoded from the code).
- L92: The ledger's client-issued id (ULID). wrap_id / group_id are bound by AAD / info, so the client decides them before encryption (AUTH_SPEC
- L100: hex (32 bytes) → key material. A malformed server response is refused as an implementation bug / tampering.

### `apps/cli/src/member.package/command.ts`

- L117: member add performs §6.5's mutual confirmation plus add_member and the backfill.
- L166: member remove is accompanied by the forced rotation of every environment (§7).
- L188: Proposing a self-remove: a proposal is not an application, but the consequence is shown to the person before asking an approver (K6-N′).
- L214: The rotation checklist reports the needs-rotation count and route (§4.1): a rotation only distributes a new DEK — an already-read value itself cannot be un-read.
- L226: If the op became a proposal (K6-A), report and exit 0; if applied, continue to the aftermath report.
- L237: change-role is the full replacement of (role, scope) (§6.2); an omission is kept as-is (K4-A), the widened part is backfilled, and the demoted/narrowed part carries §7's rotation duty.
- L290: A demotion/narrowing raised the change_role trigger flags (§4.1), so the leaver checklist is reported for the narrowed part.
- L302: change-role's input requires at least one of --role/--env/--all-envs (omission = kept as-is, K4-A); a malformed format drops as usage (2) before any communication.
- L334: member list applies no value-display gate (zero values — ruling M/K4-E, the same permissive side as schema) and requires no master key (the keyless class of project verify).

### `apps/cli/src/member.package/member-add-ceremony.ts`

- L68: Completed rows are never auto-selected (every past member's row stays completed forever — ambiguous); a backfill resume for an already-added invite takes the explicit-id path.
- L88: The ceremony is not skipped even on a backfill-only re-run (never skip verifying the key wraps about to be dealt to); the fingerprint book waives the 12-word recital on a hit but never the explicit yes, is never an auto-pass in agent environments, and is usable only on interactive terminals — on a pipe/CI the full ceremony returns fail-closed.
- L131: On a usable book hit the two recital-instruction lines are dropped — never say "not needed" right after instructing the call.
- L198: The addressee login resolves from --github or the issuance pin only: no interactive input, because it would mix with the ceremony's re-input prompt and a typo would become a query for someone else's GitHub.
- L224: When the counterpart's GitHub carries no key, ask before entering the ceremony — "ask them and re-run" or "ceremony right now" (ruling D ④) — only on interactive terminal + non-agent + no flag.
- L258: Adequacy form 4 (§6.5 IV2): when the backing source confirms the acceptance's sig key is the named counterpart's key, add_member may proceed without a confirmation input (the naming was the explicit act at issuance); --expect-fingerprint is required on top when given, and an impossible match falls back to forms 1–3.

### `apps/cli/src/member.package/member-add.ts`

- L83: The key-FP re-registration warning (K5-K/K6-I) warns but does not refuse — §6.2 permits a return under the same key; it distinguishes the same user_id's past membership from a different user_id's, and is shown before signing on both the direct and proposal paths.
- L162: Already appended by a previous run's interruption or a concurrent run: resume as backfill-only.
- L176: Principle 1 (§6.2 scope-not-contained) is checked after the duplicate family, before the ceremony: add's permission-change set is the invite's new scope, judged for the add's actor independently of the issuer's issuance-time check (S1); an already-appended resume asks no containment.
- L194: add_member's scope is the invite row's granted scope: an inviter cannot grant a different scope after acceptance — the consent's range is fixed by the issuance signature (§15-2).
- L234: Backfill covers every epoch (a new member can read history too, §7); a per-epoch 409 may be a stale-key wrap from a previous membership, judged by exact comparison of the 409's stored recipient enc pub key with the acceptance key, and repaired via §12-6 delete → re-register instead of being folded into already-registered invisibly.
- L259: The backfill registers per device: of the target's all devices, those whose effective scope includes E (the device expansion of R(E), §6.2 DK K4), each with its own slot.
- L302: Whether the occupied slot is a stale-key wrap is the exact comparison against the response's stored enc public key: a match means registered under the current key (idempotent).
- L334: delete → re-register is not atomic: if the re-register fails the slot stays empty, so the state is made explicit instead of blending into a generic failure — and a re-run (direct registration into the empty slot) is itself the recovery path.
- L355: The ceremony runs regardless of whether an append happens — even on a backfill-only re-run, never skip verifying the key wraps are about to be dealt to (the server-grant discipline).
- L367: --github beats the issuance pin's destination as the backing source's match target.
- L385: The row's issuance signature is verified with the chain-derived inviter key (for my own row, my key settles "is it my issuance", independent of the pin); failure means the row was substituted or tampered — refuse.
- L397: The issuance-pin cross-check is a SHOULD: without a pin (another device, past retention) only the issuance signature's verification pins the row — the IV revision moved the source of truth to the signature.
- L416: §6.5's independent verification never trusts the server's claimed verification result.
- L463: One environment's backfill failure doesn't stop the rest (§7).
- L478: The backfill set is the target scope's chain-derived environments (chain-deleted excluded) × every epoch (§7, ES K4); the explicit list form serves change-role's widening backfill.
- L514: backfillNewMember is shared between a direct append's add and the completing approver's fulfillment under four-eyes (§12-6's fifth path).
- L534: Re-addition guidance only: the 409 judgment is the exact comparison against the stored enc pub key, the server auto-cleans stale-key wraps on add_member acceptance, and "a different key" means a history binding matching none of the target's current device set (a current device's key is not stale — DK K4).
- L594: Under four-eyes the ceremony was done by the proposer and the backfill is done by the approver who completes the application (K6-A/K6-D).

### `apps/cli/src/member.package/member-change-role.ts`

- L99: An owner's scope is always all (§6.2 scope-role-mismatch), so combining --env with an owner role is a contradiction.
- L140: Principle 1 pre-judgment (§6.2): when the role changes, old ∪ new must be contained; for scope-only, the symmetric difference — if either side is all, the difference becomes U \ X, so only an all-scoped actor can do it (K4-I's set-algebra derivation).
- L176: all △ all = ∅ (no change); all △ listed = U \ X, which a listed actor cannot contain.
- L188: A demotion/narrowing onto oneself is refused: the person would become unable to fulfill the §7 rotate duty themselves.
- L216: selfObligationReason covers both the direct append (fulfiller = target) and an approve where the approver = the target (K6-N).
- L236: On the proposal path the self-demotion/self-narrowing refusal is dropped because the fulfiller moves to the approver (K6-N).
- L268: Already-appended and no-op shapes let an interrupted demotion/narrowing recovery resume from here; the resume (rotate/backfill) requires member or above (N11).
- L282: The pre-append check order follows §6.2's consensus rules: role rules → last-owner → unknown-environment → scope-not-contained (N2).
- L308: change_role's payload is the full replacement of (role, scope) (§6.2); omitting --role/--env/--all-envs keeps each as-is (K4-A), and an owner is pinned to all.
- L340: The kept-as-is side is resolved from the target's state on the signing view, so a concurrent change_role across a CAS retry is not overwritten (K4-A's "omitted = unchanged", Bugbot's catch).
- L371: The widened part is derived from all change_role entries in the target's history, not only the last: a third party's mid-interruption change_role would otherwise make the widened part empty and never resumed (pullfrog's catch); a 409 is idempotent, so excess converges.
- L389: A change_role applied via a proposal lands on the same applied list (K6-C).
- L409: Historical widenings outside the actor's scope are not my duty (§6.2 corollary, S6): they go to the note and are left to a re-run by a member whose scope carries that environment.
- L424: A chain-deleted environment is dropped from the widened part — never keep emitting an out-of-scope note for an environment nobody can fill (pullfrog's catch); a deletion also prunes the id from every scope (§6.2).
- L458: change_role's proposal (K6-A): after the resync it also confirms the omitted side's re-resolution matches the proposal-time one.
- L490: The direct append must match the request's fixpoint on the post-acceptance resync (the server's claim is never the source of truth): it holds when the requested side is on the chain, even if a concurrent change_role changed the kept side.
- L569: change_role's post-application stage follows K4-B's order (widening backfill → demotion/narrowing rotate) and is shared between a direct append and the completing approver's fulfillment (approval item 22).
- L594: The widening backfill comes first: the actor holds the DEK by the containment rule (§12-6), and it is idempotent via 409.
- L608: Rotate runs second: with no duty entry on the target, no duty ever arose (promotion, widening, born-reader no-op) — others' unconverged duties are not picked up.
- L634: memberChangeRoleOp's order is K4-B: the 3 environment sets are pairwise disjoint, and each stage can resume idempotently.
- L656: The proposal-ization judgment runs on the new (role, scope) resolved on the current view (establishing an owner is always targeted); the §6.2 check order belongs to ensureRoleChangeable.
- L686: Under four-eyes (K6-A) the op proposes and finishes: the widening backfill and narrowing sweep are fulfilled by the approver after application (item 22), and the omitted side is fixed to the proposal-time view's state.

### `apps/cli/src/member.package/member-remove.ts`

- L46: On the proposal path remove's self-remove refusal is dropped because the fulfiller moves to the approver (K6-N).
- L79: Resuming from deleted requires a remove of that user_id on the chain (never run the sweep on a mistyped user_id; a proposal-applied remove lands on the same list, K6-C) and a resuming actor of member or above.
- L103: remove_member's §6.2 pre-judgment order: role → scope-not-contained → last-owner.
- L113: Principle 1 for remove: the permission-change environment set is the target's current scope — "can remove = can fulfill rotate" (ruling D), the same pre-judgment as change-role.
- L164: Under four-eyes (K6-A) remove proposes and finishes (the approver's sweep fulfils the rotate duty, P7/P8); a resume (already deleted) is never proposed.
- L213: The target's duty entry (this remove's or a historical one) becomes the sweep baseline; a confirmed deletion with no duty entry at all is an internal contradiction of the derivation.

### `apps/cli/src/member.package/member.ts`

- L1: Member design: removing or demoting yourself below member is refused — the consensus rules don't forbid it, but the CLI never creates a shape where the §7 duty is structurally orphaned; a re-addition 409 suggesting a stale-key wrap auto-repairs via §12-6 delete → re-register behind a key-history gate.
- L69: Section for the rotation-duty environment set and baseline seq: the interruption-recovery baseline is chain-derived only.
- L73: memberMandatesFor uses rotation-sweep's single derivation (the same as the always-on warning) to prevent judgment drift structurally, and is target-scoped so a no-op re-run never picks up someone else's unconverged duty and starts a rotation.
- L94: The device-revocation duty is fulfilled by device revoke's own sweep; member commands' re-runs never pick up another operation's duty.
- L122: Duty environments outside the signing device's effective scope are excluded from the rotate targets (§7 — even the actor cannot rotate outside scope, S2); the always-on warning keeps displaying them.
- L150: The actor's fulfillable range is the signing device's effective scope (person ∩ device, K4-17); below member it is empty, and non-members and unregistered devices are empty too — fail-closed, staying on the always-on warning.
- L212: On a seq tie between duty kinds for an environment's baseline reason, demotion wins.
- L232: The membership CAS append: on each head conflict the four-eyes policy must still leave the inner op to a direct append and recheck redoes the pre-check; if a concurrent run already committed the same change, the op continues without appending.
- L281: The pre-flight judges by effective authority (person ∩ device cap, §6.2 effectivePermissionOf) because the consensus does; skipping the effective-side check would only advance to the append-time refusal.
- L290: For a signing key absent from the chain (unregistered/revoked), a typed failure precedes the person's-authority wording — the same order as device-ops.ts.

### `apps/cli/src/meta-confirm.ts`

- L1: Shared implementation of effect-confirmation for meta operations (variable creation, activation, schema set) (AUTH_SPEC §12-10 (3) — 1-E′)
- L35: The shared first half of a meta operation's compound send (push's create / activation, schema set): issuing a manifest that reflects the
- L53: The meta set after the operation is applied (tombstones included — §4.3 (3)'s recomputation target).
- L59: The intent's collation coordinate (the meta operation's target variable; null = the environment's own statement — env rename).
- L91: Confirms one accepted meta mutation against the verified distribution (AUTH_SPEC §12-10 (3)): resolves the 3-F intent on success, and fails
- L104: The id of the intent (3-F) appended before sending (null = the call shape with no intent).
- L108: Effect confirmation for when the manifest version has overtaken the self-issued one (whether this operation's effect is visible from the
- L143: Overtaken by a concurrent meta operation, but this operation's effect exists in the verified set
- L167: Whether a verified statement confirms an issued one (1-E′ — §12-10 (3)): a later metaVersion (overtaken by a concurrent meta operation
- L184: confirmMetaMutation over one accepted attempt's own material (the view it signed over, its self-issued manifest, its 3-F intent and its

### `apps/cli/src/meta-statement.ts`

- L1: Shared implementation of author-signing and wire derivation for create statements (metaVersion 1, active, prev empty — AUTH_SPEC §12-4 /
- L34: The client-issued variable ID (AUTH_SPEC §12-1 format). It is a random ID independent of the name: so it does not collide with the ban on
- L47: Shared implementation of signing + self-computing the signed-bytes hash (the v1 create form = this module; the layout-v3 form =
- L67: The create statement's target (§4.2's target — a variable or the environment itself).
- L76: The display name (NFC-normalized by the caller — §4.2 / §12-1).
- L82: The single construction point of the context to sign. The declared head is "the last verified chain head" (same as value signing). If the
- L126: Derives the wire statement mechanically from the signed context. Every field's source is always the context (never re-enumerate an
- L153: The self-computed hash that, once accepted, becomes the local floor's meta record (§6.3 — not a server declaration).
- L157: Author-signs a creation statement (metaVersion 1, active, empty prev) and derives the wire statement mechanically from the very context

### `apps/cli/src/own-devices.ts`

- L1: Recording the provenance of my device keys (design record dk-design.md §9 K4-3 / K4-4 — DK-D's 3 conditions). The keys that first-sync
- L59: One recorded key of the user's own (non-secret: public keys, cap, provenance).
- L66: Display label chosen at `device add` / `approve` (this machine's copy — not the registry).
- L68: The device that appended the `add_device` when observed on a chain (null for the first key / unknown).
- L70: The project the key was first observed on (observed rows only).
- L73: Set when the key was revoked (by this machine or observed on a verified chain). Never re-added.
- L82: Load result (fail-open: `corrupt` is distinguishable from `missing`).
- L92: Upsert one record (read-merge-write). A re-approval overwrites a revoked row.
- L98: Marks fingerprints revoked (rows that do not exist are created as revoked "observed" rows only when keys are given).
- L111: The record's location (same family as the config: <config.json's parent>/own-devices.json).
- L116: The cap a record declares (`add_device` payload — CRYPTO_SPEC §6.2).
- L132: The fields the stored and the held entry share, before and after the scope (only the scope's shape differs between them).
- L148: The entry as stored: the scope is the wire pair scopeKind + scopeEnvironmentIds (the §6.2 normalization field order — the all scope carries
- L165: The entry as held: the scope is the derived MemberScope (the union member for `listed` carries the id-format / at most 256 / no duplicates
- L180: One codec: the wire pair ↔ the derived scope (memberScopeOf / scopePayloadFieldsOf — the same transform every scope-carrying payload uses).
- L206: Strict decoding (no partial reads — same as pins / the fingerprint ledger).
- L219: Reads are fail-open at the ledger level: only NotFound is `missing`, and an unreadable file (EACCES / EISDIR / EIO) is the `corrupt` state
- L241: Refuse overwriting a corrupt file (same discipline as pins / the fingerprint ledger)

### `apps/cli/src/passkey.package/passkey-listener.ts`

- L1: PRF listener security design (ruling A): one-time URL token gates GET and POST, Host and Origin must exact-match, failures return a uniform reasonless 404, the first correct POST settles single-consumption, and a 6-digit terminal-displayed confirmation code is required because the token rides on the browser launch's argv readable by another UID — code mismatches 404 without consuming, with a brute-force cutoff; PRF output never reaches logs, errors, or the DOM.
- L228: Routing order is Host exact match → token → method/path; a page opened at /<token> without the trailing slash would chase /app.js and break (a common hand-typing/port-forwarding failure), so it is steered to the correct form.
- L257: startPrfListener accepts a POST only with the terminal-shown confirmation code; the first accepted POST settles the outcome, everything after is 404, and mismatching codes 404 without consuming the ceremony up to a small cap that then fails it.
- L270: The outcome promise's resolvers are settled from outside the Promise; the executor runs synchronously, so the assignment is always done before use.
- L356: A failure of the server itself after listen is passed to the caller as a ceremony failure, not left as an unhandled "error"; a per-connection failure just closes the connection.

### `apps/cli/src/passkey.package/passkey-page.ts`

- L1: Passkey page invariants (ruling C): assets are bundled as string constants (text imports would need extra vitest/tsc infra), the page makes only the 2 WebAuthn calls and one fetch, no inline script or third parties, and errors return enumerated reason codes only; the confirmation code exists because the URL token is readable via /proc/<pid>/cmdline by another UID, so the code travels only between the user's terminal and browser.
- L44: The user handle is a per-registration 16-byte random: a deterministic value would make a syncing passkey manager replace the existing credential (ruling G).
- L48: excludeCredentialIdsHex carries the ledger's existing credentials to prevent making a second one on the same authenticator (excludeCredentials).
- L61: Page failures are reported as enumerated reason codes only — no free-form text is carried from the page.
- L115: Registration obtains the PRF through the same get path as restore, structurally ruling out "registered but restore produced a different value" (ruling G); userVerification is required because on an authenticator without UV the PRF silently goes missing.

### `apps/cli/src/passkey.package/passkey.ts`

- L1: Passkey design: the ledger write happens only once, at the end, when every material is in place (no half-written rows on a mid-failure); ceremonies run only behind the interactive-terminal/agent gate and the listener stands only behind it; plaintext exists only in function locals; restore fetches only the selected row's wrap, after the ceremony, so a cancelled ceremony does not consume the rate window.
- L60: The confirmation code is a uniform-random 6 digits with modulo bias eliminated by rejection; it is not key material — it demonstrates co-presence with the page.
- L261: sealPasskeyOp's reserve is obtained by opening the ledger — opening is the qualification for changing the ledger (K4-2).
- L287: wrap_id is bound by AAD, so it is issued before encryption; prf_salt and the user handle are per-registration randoms (ruling G).
- L398: Recovery runs the ceremony with every credential first, then fetches only the response-selected row's wrap (rulings F/I): since the blob fetch is after the ceremony, a cancel consumes no window.

### `apps/cli/src/pins.ts`

- L1: The persistence layer of invite non-secret pinning (CRYPTO_SPEC §6.3 out-of-band anchor (a) and its inviter-side counterpart = the
- L51: The acceptor-side invite-link anchor (§6.3 (a)).
- L58: The inviter's sig public key (the link's `is=`). Collated against the on-chain key in addition to the FP at first sync.
- L60: My view's head seq at the time the first mechanical collation succeeded (not yet collated = null).
- L64: The issuer-side pin (invite id → the content settled at issue time. IV revision — link public key + destination login).
- L66: The link public key (hex 64). Collated against the row's link_pub of the server declaration (SHOULD).
- L69: The scope to be granted (2026-09-15 ES K4 — extra collation material of the same standing as role. The source of truth is the issue
- L73: The destination's GitHub login (`invite create --github` — the backing source's check target. Kept only at hand: never written to the
- L81: The pin file for one project (invites/<projectId>.json).
- L89: The load result (fail-open — the caller emits a state-specific warning).
- L98: Saves the anchor (read-merge-write. Existing issued pins are kept).
- L103: Appends an issued pin (read-merge-write + sweeping rows long past their expiry).
- L113: The pins directory (a location of the same family as the config: <config.json's parent>/invites).
- L118: The issued pin's retention window: rows past this much time after expiry are swept. An accepted invite's add_member is possible even after
- L128: The invite id is server-issued (ULID) but does not depend on the format (the same posture as AUTH_SPEC §11-1's ID-format independence).
- L147: The scope pair's structural rules are CRYPTO_SPEC §6.2's (kind's closed set, at most 256 ids, no duplicates, id format — the listed/all
- L169: Reads an issued pin (own-property — floor.ts's discipline).
- L197: Writing onto a corrupt file is refused (same discipline as the floor's "a write failure is never fail-open"). Rebuilding from empty would
- L228: Only missing (NotFound) **alone** folds into "none". EACCES / EISDIR etc. are a "could not read the existing pins" failure — folding them
- L242: Writing an out-of-format id makes the next load wholly corrupt (strict decoding), so refuse beforehand

### `apps/cli/src/project.package/command.ts`

- L153: Head gossip is part of verify: a contradictory claim is hard evidence of a split view — abort and preserve the evidence; no submission happens (verify is a read command needing no master key), and the floor head advances inside reconcileGossip only after every check passes.
- L266: policy approvals: no flags displays the current policy keyless; enable/change/off are an owner's signature; while the policy is enabled, set_approval_policy itself is a four-eyes target and becomes a proposal (§6.2).
- L333: The enablement prerequisites (owner ≥ required + 1, every owner's recovery registration) are kept as guidance, never a prompt (approval item 17, owner selection (i)).
- L438: The export's anchor is built only from the verified view (the keyless prologue of verify).
- L519: Checkpoint issuance accompanies a chain append (an Ed25519 signature), so it requires the master key; building the verified view is the checkpoint's material itself, so its value fetches are correctly recorded as var.read (an explicit operation).

### `apps/cli/src/project.package/project-init.ts`

- L1: Project creation is genesis init: orgId is required with no org-creation API (pick from /auth/me's orgs), and the project ID — the genesis entry hash — is precomputed client-side so the server's response is collated against it (the server is not trusted).
- L113: The server's issued project ID is not trusted: init fails unless it exactly matches the client-precomputed genesis hash.

### `apps/cli/src/pull.ts`

- L1: Bulk pull and decryption (AUTH_SPEC §12-7 + CRYPTO_SPEC §4.1 / §5.1 / §5.2). Verification order (§6.3): (1) verify every value's value
- L40: One decrypted variable (plaintext bytes live in memory only).
- L42: The name from the verified meta statement (§4.2 — never trust a bare name).
- L47: The declared type (the schema column of §4.2 layout v3. v1 / unspecified = ""). Used only by the advisory type check just before injection
- L53: The required declaration (layout v3's schema column. v1 = false). Used by `maruhi sync`'s completeness check.
- L55: The max age the schema declares (layout v3 — PF6 R9; null = none). Input of the point-of-use note of `maruhi run` / `pull` (max-age.ts).
- L60: The plaintext bytes (memory only. Unwrapped only in run / show / re-encryption).
- L64: One declared variable (a schema-only declaration with no value — CRYPTO_SPEC §4.2 layout v3). Material for `maruhi run` / `ci run`'s
- L78: The decrypted variables, declared declarations, and the SHOULD warnings collected during verification (non-NFC name distribution etc.).
- L80: The view used for verification (it may have advanced via the future head's bounded resync). Later writes inherit it.
- L83: The verified declared (valueless — outside injection scope. The presence check is the caller's).
- L86: Filling the missing epochs of the same person's other devices (only when `fillOwnDeviceGaps` is passed — DK K11).
- L90: Verified declared statements → the presence check's material. declared is layout v3-only (§4.2 — a v1 declared was already refused at the
- L108: The reason sentence for "no wrap for that epoch was addressed to me". Placed on **the side that builds the decryption's failure reason**
- L123: Decrypts one already-verified value (values.ts's product, passed through §6.3). The decryption context (AAD) coordinates are assembled from
- L141: The chain-derived current epoch (the declared epoch's cap — the defense line against a derivation inconsistency).
- L145: The value signature's verification (§6.3-4) already guarantees "the current epoch at declared head = the value's epoch", and by epoch
- L170: Reason for unwrapping: the decryption's key input (the crypto boundary)
- L189: The decryption's product is wrapped here. From here on the plaintext flows only as a Redacted
- L193: Narrowing the variables to decrypt (omitted `select` = all). Applies only to the verified set.
- L201: Pulls one environment, verifies every value's write signature and every metadata statement (§4.1 / §4.2 — before any decryption; names come
- L215: The bounded resync on a future head (§6.3-2b).
- L217: The local floor (§6.3 — the checks and the atomic commit after verification succeeds).
- L219: Narrows the variables to decrypt by name (`maruhi sync`'s integrated token — never materializes the environment's other variables'
- L227: Derives and fills the missing epochs of the same person's other devices from the bundled rows (DK K11-1 / K11-4 — only `maruhi pull` passes
- L236: (0) Target environment ∈ one's own scope (CRYPTO_SPEC §6.3 — never wait for the server's 403. 2026-09-15 ES K4, design record K4-C). This
- L249: (1) Verifying the value signatures (before decryption). On a future head, a view advanced by the bounded resync comes back — the later
- L255: (2) The wraps' §5.1 / §5.2 verification and unwrap (no DEK is used until the commitment match also succeeds). The current epoch
- L268: The difference check against §7's all-epoch distribution (the self-side detection of an unfinished backfill — the B2 ruling): every member
- L287: Decryptions are independent per variable, so they run in parallel. The failure contract is unchanged — the first failure **in input
- L315: A duplicate active name was already refused by the statement verification (values-verify.ts) (§4.2 — `maruhi run`'s environment variable
- L329: Filling the sibling devices' gaps (DK K11): only after decryption is done (a failed pull fills nothing). A failure folds into the result

### `apps/cli/src/push.package/command.ts`

- L52: stdin is where plaintext enters as raw bytes: it is wrapped in Redacted here and flows only as Redacted, unwrapped only at push.ts's encryption boundary.

### `apps/cli/src/push.package/push-resolve.ts`

- L28: An activation never doubles as a rename — the server enforces it with 422 (§12-5).
- L30: An activation takes the declaration-time schema column over byte-exact — the partial-update principle; the layout stays v3.
- L34: A push target has 3 shapes (§12-5): creation (value v1 + metaVersion 1), activation (first value onto a declared variable: value v1 + a v3 active statement + a manifest), and a normal push (meta untouched).
- L64: The bundled DEK is a raw wire shape on the premise it is verified and unwrapped under the same view as `verified` (§12-7 — eliminating the double fetch with listMine, session-11 ruling 3).
- L77: Resolution is a byte-exact comparison against verified statements of a metadata-only pull (no values or DEKs, so no var.read is recorded); a value-carrying pull runs only for an existing variable, because the prev chain needs the verified latest value's signed-bytes hash — "don't record as read what was never read" (ruling 3).
- L103: A duplicate same-name pair is already refused by the verification side, but the check is kept as a defensive line so push-target identification does not depend on the response ordering (§4.2).
- L115: A push to an existing active variable issues no manifest — the issuing triggers are limited (§4.3) — so its resolution sets issueBase to null.
- L131: The first value push onto a declared variable is the activation composite (§12-5): no value-carrying pull is made (don't let an unread value be recorded as read), and the schema column and name take the declaration-time values over byte-exact.
- L138: A declared variable is layout-v3-only (§4.2); a v1 declared is already refused at the verification stage.
- L165: A concurrent deletion or cross-response inconsistency is refused explicitly instead of falling back to a creation with a wrong prev.
- L176: A concurrent rename is refused: never aim a push at a variable that moved to a name different from the input; latest.name is the verified statement's name, so a byte-exact comparison suffices (§12-2).

### `apps/cli/src/push.package/push-state.ts`

- L1: push-state maps §12-5's retry procedure: initial resolution + DEK fetch, winner adoption after VersionConflict, re-resolution after VariableConflict, epoch re-derivation after EpochConflict.
- L58: A create's name/metaVersion/manifestVersion conflict is re-resolved from the name (§12-5's retry: re-fetch → verify → re-sign both statement and manifest); ActivationRequired is not a resync but a switch-to-activation signal (design doc §3 row S3).
- L86: A rollback declares its lineage (§12-5) and every attempt — including a conflict retry — must land as a normal push to exactly this variable, only on top of the exact version the user confirmed: a concurrent push by another member is never silently overwritten with the restored value.
- L121: The current epoch and the DEK set are derived together from the same verified view, and the DEK is fetched exactly once per path (session-11 ruling 3's double-fetch elimination).
- L163: The winner re-fetch identifies the winner by its stable id and re-points prev at its signed-bytes hash; the 409 response is never asked for the winner's hash (§12-5).
- L215: The re-resolution's DEK prefers the on-hand set of a known epoch and is re-fetched only when the epoch advanced; resolved.deks is for the first resolution only — don't redo the unwrapping on the rare conflict-retry path.
- L252: The epoch's source of truth is the chain (§6.3): resync with the extension check and use the derived value; prev stays the verified predecessor hash.
- L270: If the chain-derived epoch is unchanged after resyncing, the server's EpochConflict claim contradicts the chain — a retry cannot resolve it.

### `apps/cli/src/push.package/push-winner.ts`

- L9: On an honest server latest_version is monotonically increasing (a deletion is tombstone + delete-all-rows), so every regression from the verified latest is evidence of a rollback or equivocation — no false rejection.
- L25: A regression from this session's verified latest is rollback evidence: adopting it and re-pointing prev would chain my own signature onto a rolled-back branch.
- L31: Two valid signatures with different content at the same coordinates are cryptographic evidence of equivocation.
- L34: Epoch monotonicity (§4.1) is transitive, so once the winner is newer than the verified latest, epoch non-decrease is required regardless of version-number gaps — closing an old-epoch injection that bypassed the adjacent check via version-number choice (review loop 2).
- L43: When the adjacent predecessor is held, §6.3-6's prev-existence match can be checked for free (review loop 1 — the exception to pull's latest-only constraint).
- L55: The meta side gets the same-shape rollback/fork check as the value side (§12-5's meta-retry discipline): on an honest server latest_meta_version is also monotonically increasing, so no false rejection.
- L78: When the adjacent predecessor is held, the meta prev-chain match can be checked for free, the same shape as the value side's §6.3-6 check (review ②).
- L102: The winner check is 2-layered (cross-response consistency, then regression/equivocation/prev), and rotation re-encryption also goes through it: letting just one side chain-sign onto a diverged history would open a hole that relies on the floor (a SHOULD, absent on first sync).

### `apps/cli/src/push.package/push.ts`

- L1: Push design: name resolution goes through verified statements via a metadata-only pull (no var.read recorded); a normal push's prev is the self-rebuilt signed-bytes hash (never chain-sign a server-claimed hash); 409 winners are re-fetched, verified, and adopted with a fresh nonce — never decided from the currentVersion number alone; the value is read from stdin and the plaintext lives in memory only.
- L98: Rotation re-encryption goes through the same encrypt-and-sign implementation as a normal push: splitting the signed-object assembly across two implementations would let only one of them lose the discipline (§7/§4.1).
- L149: The signed-bytes hash promoted to the local floor is a self-computed value, not the server's claim — the same posture as the basis of the next version's prev.
- L181: A meta operation's issued manifest is not promoted to the floor directly: its success holds only once it passes the effect confirmation on a verifiable distributed object (§12-10 (3)); advancing the floor's manifest is the confirmation pull's job.
- L196: A rollback lands only as a normal push to the variable whose history was verified, directly on top of the version the user confirmed (VH): any (re-)resolution to a creation, activation, another variable, or a newer latest is refused before anything is signed.
- L229: Unwrapping reason: an equality check only — nothing is displayed and the bytes never leave this comparison.
- L248: The lineage declaration (SHOULD, §12-5): re-pushing a value identical to the verified latest declares that version, because it is not a new value and must not look like one to rotation-needed detection (VH re-check round); the comparison runs only when this device holds the latest's DEK.
- L285: Manifest issuance journals the intent before sending (3-F, §12-10): if persistence fails, do not send (fail-closed) — what a crash loses is the record of the confirmation duty, not the belief that it succeeded.
- L371: The randomly assigned variableId cannot already exist in the verified set; if it did, fail explicitly as an internal inconsistency instead of dropping it from the digest, which would surface as a server 422 with the cause far away.
- L407: A refusal in the server's own error body means the effect never happened (decided), so the intent is closed.
- L507: A value push to an existing variable is out of 1-E′/3-F scope (§12-10 (3)): the only distributed object usable for effect confirmation is a value pull, which would bring var.read auditing into the write path; success is carried by the server's CAS + signature verification and the floor's commitPush.
- L530: Effect confirmation for a creation/activation (1-E′, §12-10 (3)): creation = the existence of my randomly assigned variableId; activation = a statement/tombstone at or above the issued metaVersion — a different hash winning at the same version must not be misread as the effect having landed.
- L549: A statement at the issued version must match my hash (same version, different hash = lost to a concurrent activation); a shape advanced past the issued version cannot have its ancestry checked under the latest-only constraint (the §14.3 leftover class).
- L584: pushVariable counts a creation as successful only after the 1-E′ effect confirmation passes: recording to the floor and reporting success happen only after confirmation (§12-10 (3)); the chain, not the server's claim, stays the epoch authority.
- L604: The client performs NFC normalization before signing (§4.2/§12-1): both the lookup key and the name signed on creation are put in NFC form.
- L618: Recording to the floor happens only after the effect confirmation passes (§12-10 (3)): planting my own write into the floor on a 2xx alone would, if the server never stored it, leave the floor demanding a variable that is never distributed — every later pull permanently refused as variable-omitted.
- L634: The accepted write is promoted into the floor before reporting success (journal-before-release, §6.3) so later pulls can detect even a rollback of my own write; the rule (c) baseline does not move, and a floor write failure is reported as such.
- L643: The floor key is the variable ID I signed — the server echo is not trusted.
- L652: The coordinates reported as success are the locally signed values; the server echo is used only for cross-checking, and a disagreement surfaces as a typed error (promoting the echo into the display would let the user cite server-claimed coordinates as fact).

### `apps/cli/src/recovery-code.ts`

- L1: The human-readable representation of the recovery code (CRYPTO_SPEC §8: a 256-bit random value as a grouped Base32 (RFC 4648) string). This
- L25: Formats a 256-bit recovery secret as grouped Base32 (`XXXX-XXXX-…`). Why it is unwrapped: input for Base32 encoding. The formatted code is
- L63: Parses a recovery code back into its 32-byte secret. Case-insensitive; hyphens and whitespace are ignored. Returns null for anything that
- L91: Zero-padding check of the last 4 bits: non-zero is a transcription error (not identified with another code one symbol away)

### `apps/cli/src/recovery.ts`

- L1: Issuing / reissuing / opening a recovery code (CRYPTO_SPEC §8 / AUTH_SPEC §13). - The recovery code (256-bit) exists only in process memory
- L63: The retry count for save confirmation / code entry (forgiving typos. Exceeding it is an explicit error).
- L84: Issues (or reissues) the recovery code for the reserve key `record`: generate → wrap → register → display → save confirmation. The shared
- L100: Replacing an existing registration (reissue) is announced beforehand (the previous code stops working with this operation)
- L109: Never use JSON.stringify(record) — the secret side would be wrapped still redacted, registering a recovery blob that "restores but the key
- L116: Reason for unwrapping: the recovery wrap's key-derivation input (the crypto boundary)
- L132: The code's display block goes wholly to stderr (the same channel as the prompt). stdout may be redirected / piped: the code is key material
- L142: Reason for unwrapping: displaying the code is issuance's very function (it is never shown again). Displayability was already decided by the
- L159: Confirm the save by re-typing the displayed code's last group (the loss-prevention UX).
- L164: Reason for unwrapping: the matching material for the last group. The code is already displayed, and the substring taken here is never
- L185: Opens the recovery blob with a prompted recovery code and returns the reserve key record (memory only — nothing is stored). Shared by
- L199: A line symmetric to the issuing side: the code is key material, and no path for typing it through an agent-mediated stdin is built either
- L228: Code entry → decryption retries locally (never consumes the fetch's rate-limit window)
- L237: The re-registration procedure itself (identical for every cause).
- L241: The common exit when the blob is unusable (this device cannot fix it). "This code cannot restore the key" is true **only for corruption /
- L251: The mapping for when the opened blob cannot be loaded as key material (importMasterKeys's failure) (used by key-recover.ts /
- L275: The wording for when the environment is incompatible (this route's version). This route has passed through ensureNoStoredMasterKey, so this
- L288: The wording for when the blob parses but its key material cannot be loaded. **Never declare the cause "corrupt"**: this fork only receives
- L305: The wording for when the blob was written under a suite the current version does not know. Unlike a keychain record, **there is nothing to
- L319: Interpreting the decrypted blob. Carved out so that **no string holding plaintext key material (hex) leaves this function**: the caller
- L329: The classification when uninterpretable (the same criteria as the keychain side).
- L331: The suite an uninterpretable blob claims (null when it claims none).
- L335: The classification and suite extraction also happen **inside this function**: both need the blob's raw string, so doing them outside would
- L353: The entered code is key material itself. **Wrap it at the boundary** (left as a bare string, it could be loaded onto the logError in the
- L372: A crypto failure on the entered code (or a blob that does not open under it) means the same thing to the user: warn and let them re-enter
- L378: Reason for unwrapping: the recovery-blob decryption's key-derivation input (the crypto boundary)
- L393: Decryption succeeded yet the content is corrupt = the blob was malformed at registration (not a code mistake, so no re-entry is prompted).
- L404: What is corrupt is the **server-registered blob**, not a keychain record (this route passed through ensureNoStoredMasterKey, so no master
- L409: It may only be a different shape (a blob a future version wrote). Use the same classification as the keychain side, and for what cannot be
- L429: `maruhi key generate`'s tail: generating the reserve key and its first sealing (K4-2 — a reserve key is born at the first ledger sealing).
- L464: Generates a reserve key, seals it with a fresh recovery code and records its public side locally (K4-1's order: seal → record. Chain

### `apps/cli/src/reserve.ts`

- L1: The reserve key (CRYPTO_SPEC §3 / §8 — 2026-09-19 DK; design record dk-design.md §9 K4-1 / K4-2). Of the key pairs shaped like a device
- L35: The reserve key, imported and ready to use, held in memory only. The brand keeps it out of every keychain-storing function (those take
- L47: Loads a record decrypted from the ledger (or a generated record) as the reserve key.
- L65: Generates a fresh reserve key (memory only — the caller seals it into the ledger). The record carries the reserve-key mark (`kind
- L76: Whether the key opened from the ledger carries the mark this CLI wrote when generating it as a reserve key (DK K16-6).
- L81: The own-devices row for a reserve key (cap (owner, all) — CRYPTO_SPEC §3).
- L98: Records the reserve key's public side locally (K4-3 (1)). A write failure is reported as a typed failure: without the record the reserve
- L112: The locally recorded reserve keys (not revoked), newest first.
- L126: When the ledger's key is found to be revoked and this device has it recorded as reserve, attach the revocation mark (DK K14-4 4-g). No row

### `apps/cli/src/rotation-proposals.ts`

- L1: `maruhi rotation proposals | accept | reject`: the member side of sealed value proposals (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5 — PF7b). A
- L41: A proposal's variables for display: the verified name when known, else the identifier.
- L55: `maruhi rotation proposals [--env]`: the pending proposals with their next step (no value is opened).
- L100: Finds the pending proposal with the given id (a full id; a unique prefix of at least 8 characters is accepted).
- L129: true = skip the confirmation (the only non-interactive path).
- L136: The proposed values an earlier accept had already pushed (resolved now, not pushed again).
- L145: The version that already holds this value (an earlier accept pushed it but did not get to resolve) — nothing to push; null = to push on top
- L151: The opened value's shape, for the report (D-8) — computed where the value was opened, so the report unwraps nothing.
- L153: The verified current value's shape, opened on this device for the report's comparison (D-18).
- L157: The verified current value, decrypted on this device: its shape stands beside the proposed value's in the acceptance (D-18 — the acceptor
- L186: The device cannot open the current value (no wrap for its epoch — the post-add_device backfill is missing — or the environment is outside
- L203: The verified current value a proposed variable targets (missing or behind the base = refused).
- L228: Opens the wrap sealed to this device (by its enc key) under the §5.3 info of the proposed variable.
- L273: Opens this device's wrap of one proposed variable after checking the target still is the verified current version.
- L282: Reason for unwrapping: the shape and the byte comparison (both values are this device's to know)
- L284: A current version past the base is either an earlier accept's own push (the same bytes — nothing to push, only to resolve) or a move, which
- L305: `maruhi rotation accept <id>`: opens this device's wraps, confirms, pushes every proposed value as an ordinary signed version (companions
- L328: The server's variable order is the minted order (companions first)
- L333: A line count that changed is worth a look before the push, here where the decision is made (D-18; the CI job's report already showed it)
- L372: The confirmation's lines: what is pushed, what is already stored, who minted it, and the connector's facts.
- L387: The shape of each value to push, from the opened plaintext on this device (D-8), beside the current value's (D-18): a job that produced
- L398: Pushes the opened values that are not stored yet, in the proposal's order, as ordinary signed versions.
- L433: Tells the server the proposal is accepted, naming the versions that hold its values (a failure says how to finish).
- L460: The report lines of an acceptance (values never appear).
- L477: `maruhi rotation reject <id>`: drops the proposal; the credential it created at the issuer is named for retirement.

### `apps/cli/src/schema.package/command.ts`

- L117: Schema display is keyless and agent-gate-free (1-1 permissive side): zero values; ADR-0016's gate covers value-displaying commands only

### `apps/cli/src/schema.package/env-file.ts`

- L226: observeValue returns only the inferred type and a boolean — the value itself never leaves the function (4.2 closed set)

### `apps/cli/src/schema.package/schema-statement.ts`

- L1: schema-statement: the signed context is built exactly once and the wire derived mechanically — two independent literals would make a one-field discrepancy a silent failure
- L172: signDeclareStatement: the only value-free variable creation (4.2) — metaVersion 1, status declared, empty prev
- L189: Continuation validity is guaranteed by the caller deciding status from the verified previous statement; the server is the acceptance authority (12-5)
- L222: Deletion statement fields must carry the previous statement's values byte-exactly — the server enforces a mismatch as 422

### `apps/cli/src/schema.package/schema.ts`

- L1: schema display/set (1-1/1-2): display is verified statements only, no agent gate; descriptions always neutralized (CK/CW)
- L64: The untrusted-data framing header prefixes non-TTY output (CW: a signed description may still be malicious); shared with the MCP server
- L75: SchemaRow is the single projection behind CLI table and MCP results so the surfaces cannot drift in content or neutralization; verified is never attached (14.3)
- L318: Target resolution is shared by schema set and var rm: splitting it would lose the same-name-duplicate (equivocation) refusal on one side
- L603: schema set: partial update issued as a v3 statement + manifest composite, confirmed against the verified distribution before success (12-10 (3))

### `apps/cli/src/scope.ts`

- L1: The CLI-side shared predicates of a member's environment scope (CRYPTO_SPEC §6.2 / §6.3, AUTH_SPEC §9-2 / §12-3) (2026-09-15 ES K4 — design
- L42: The user-facing scope display (`all` / `no environments` / an enumeration of environment ids. Ids are neutralized).
- L53: scope equality (compared as sets — generation is ascending SHOULD, verification is set-based. CRYPTO_SPEC §6.2).
- L70: Maps both the wire form (`scopeKind` / `scopeEnvironmentIds`) and the derived form to the derived form.
- L80: Containment `actor ⊇ target` (CRYPTO_SPEC §6.2 principle 1's predicate used for pre-communication guidance). `all` is U including future
- L93: Assembling a scope from `--env <id>` (repeatable) / `--all-envs` / `--no-envs` (shared by `invite create` / `member change-role` / `device
- L108: `--no-envs` = `listed{` (§6.2's empty listed — an admin who only manages, or a member to be admitted later).
- L143: Code-point ascending order (§6.2's generation SHOULD. Locale-independent).
- L148: Each id of `listed` exists on the chain and is not deleted there (the pre-communication judgment of the consensus rules
- L182: The refusal for operating on an environment the verified chain shows as deleted (§6.3 "Chain-deleted environments").
- L190: Refuses an environment the verified chain shows as deleted, before any request about it (§6.3 "Chain-deleted environments"). An environment
- L205: The wording for when I point at an environment outside my scope (K4-C — does not wait for the server's 403).
- L208: The device that signs / opens (when given, distinguishes the device's scope cap — DK K4-17).
- L215: When the person's scope contains it but the device's scope cap excludes it, the party to ask for expansion is different (not an admin — my
- L227: Target environment ∈ my scope (the pre-communication judgment of AUTH_SPEC §12-3's "environment ∈ scope" row). When I am not a current
- L248: A chain-deleted environment first: the deletion pruned it from every listed scope, so the scope judgment below would misreport it (§6.2)
- L272: Concretizing the obligation's environment set (K4-J): of the environments that existed at `seq` (`createdAtSeq <= seq`), those contained in
- L292: Concretizes the diff of a scope replacement old → new onto the environment set at `seq`: the grown part (new \ old — the backfill

### `apps/cli/src/server-disclosure.ts`

- L1: The constant display of server disclosure (CRYPTO_SPEC §9): "this project is disclosed to the server" while the verified chain carries an
- L25: One active grant that discloses at least one environment to a server key.
- L28: The grant's scope (ID ascending; never empty — a grant whose scope was emptied by deletions discloses nothing).
- L30: The number of lease-policy elements (0 = no lease path — §9.1).
- L36: The verified chain's disclosing grants, fingerprint ascending (empty = pure E2EE).
- L49: The server keys an environment is disclosed to (fingerprint ascending; empty = none).
- L59: "environment prod" / "environments prod, staging" (IDs neutralized).
- L64: The Note's text for one grant (names the project: a multi-project sweep prints one per project, and the ledger keeps identical lines once).
- L74: The prologue's standing Note (§9 — one line per disclosing grant; nothing for a project without one). A Note, not a Warning: the grant is

### `apps/cli/src/server.package/command.ts`

- L185: §9: a grant always indicates that disclosure is happening, and the revocation path is guided on the spot.
- L252: When the CAS-conflict resync finds the targeted grant already revoked by a concurrent run, that fact is made explicit — someone revoking the same key is operationally significant — and the flow proceeds to rotation.

### `apps/cli/src/server.package/lease-policy.ts`

- L11: The lease_policy input-file limits carry the same values as the consensus rules: an excess becomes invalid-payload at chain verification, so it is dropped at the input stage first (§6.2).
- L18: The lease_policy field bound is on UTF-8 bytes, not characters — the §6.2 consensus bound is on bytes.
- L38: The lease_policy file format writes claimConstraints as an object so contradictory duplicate constraints on the same claim (always false under exact-match AND) cannot be expressed structurally; the §6.2 SHOULD (code-point ascending, no duplicates) is applied when converting to the chain form.
- L110: Constraints are sorted code-point ascending (§6.2's SHOULD); names are unique because they are object keys.
- L116: Element canonicalization (sort + dedup) does not affect semantics — evaluation is existential (§14-1) — but it makes the signed bytes deterministic.

### `apps/cli/src/server.package/server-grant.ts`

- L1: Server grant design: the FP is recomputed and verified against /auth/config (machine detection of transport corruption/config drift) and confirmed by the §9 ceremony; the backfill keeps going past a per-epoch 409 so a re-run always converges — the distributed state is the resumption state, with no progress file.
- L102: The duplicate-server-key comparison target is every device key of the current member set (§6.2, 2026-09-19 DK).
- L113: On a re-grant the scope may only grow (§6.3): a narrowing is guided toward revoke_server, which carries the all-environment rotation mandate; lease_policy is freely revised.
- L171: What the recomputed FP is checked against is the out-of-band record (the ceremony); the recomputation here is the response's self-consistency check — machine detection of transport corruption or a mix-up of sources.
- L205: The server key's confirmation ceremony (§9) is not waived: a grant makes the server "member N+1", so the §6.5-style authenticity confirmation applies — interactively re-typing the last word, non-interactively matching the out-of-band --expect-fingerprint.
- L251: An AI-agent environment never performs the server-key ceremony on the user's behalf — the matching is a human's out-of-band confirmation (§9 / ADR-0014).
- L271: A per-epoch 409 in the server backfill is absorbed as "already registered": there is no list API for server-addressed wraps (distribution is to-the-principal only, §12-6), so treating a 409 as done is the only and sufficient means of reconciliation.
- L318: backfillServerGrant is shared by a directly appended grant and the completing approver's fulfillment under four-eyes (§12-6's fifth path).
- L374: The granted scope is normalized to ascending code-point order with no duplicates (§6.2's SHOULD).
- L386: The server-key ceremony (§9) runs whether or not an append happens — even on a backfill-only re-run, never skip matching the key that will continue to receive disclosure.
- L403: Under four-eyes (K6-A) grant proposes and stops: the server-addressed backfill is performed by the approver who completes the application (item 22); the proposer has already done the ceremony.
- L408: Never propose when a grant of identical content is already valid after the resync — that would be a redundant proposal.

### `apps/cli/src/server.package/server-revoke.ts`

- L1: Server revoke design: the revocation's effectiveness is carried by forced rotation of every environment (a revoke without rotation is the pretense of having stopped disclosure); interruption recovery is derived from the distributed state around the last revoke_server's seq, and a deleted environment is skipped only when its delete_environment entry is on the verified chain — never on the server's 404 declaration alone (§7).
- L121: sweepAfterRevoke is shared by the direct-append revoke and the fulfiller of an approval that completed the application under four-eyes.
- L138: Chain-deleted environments are excluded from the rotation targets only on the basis of the delete_environment entry on the verified chain — never skipped silently on the server's 404 declaration alone (§7).
- L148: The revoke obligation's environment set is every environment at the revoke's point (§7 — revoke_server is immutable; the server key cannot hold a later-created environment's DEK); the derivation is shared with rotationMandates.
- L172: The rotate injection's two modes: force = fixed reason + forceNewEpoch (§7's force); verify = no reason + no forceNewEpoch, resuming an incomplete re-encryption if any and check-only otherwise (creates no new epoch).
- L189: A resume (no valid grant) appends nothing and is not proposed.
- L195: Under four-eyes (K6-A) revoke proposes and finishes: the whole-environment rotate is done by the approver who completed the application (item 22).
- L246: The rotation targets derive from the last revoke's seq: on a run that appended it is this run's append itself; on a run that did not append (interruption recovery) it is taken from the chain history.

### `apps/cli/src/values-floor.ts`

- L1: The floor discipline of a verified distribution (CRYPTO_SPEC §6.3): check against the last successful pull's baseline, then commit the new
- L25: Reconciling meta-op intents against a verified distribution (§6.3 record discipline (ii) — 3-F). If the verified manifest reached or passed
- L62: The floor check (§6.3's (a)(b)(c)) and the floor commit (the update ordering norm: checks run against the last successful pull's baseline
- L79: The view used to derive the rule (c) baseline. **It must be the view verified before the pull response was fetched**: deriving the baseline
- L93: The view used for verification (the commit value of the floor's chain head).
- L100: Refuse + presentable evidence (coordinates, both signed-bytes hashes, declared heads). A floor violation is a contradiction between
- L113: A distribution that passes verification for an environment absent from the chain stops here (meta carries no epoch anchor, so in an
- L118: The rule (c) baseline's advance value = the pre-response-fetch view's chain-derived current epoch (§6.2 — the server-claimed currentEpoch
- L123: The rare race where the environment was created between the response fetch and the resync: there is no view to derive the baseline from
- L135: A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)
- L139: The floor check of a metadata-only pull (the valueless shape — only the meta-level rules (a)(b) and omission / undeletion. See
- L168: A floor violation is a contradiction between properly signed data = evidence (same as the value pull's enforceFloor)
- L178: A distribution that passes verification for an environment absent from the chain stops here (the same phantom-environment check as
- L182: The join of verified facts (§6.3 — a single recording rule, not an enumeration of recording triggers). journal-before-release: persisting
- L198: A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)

### `apps/cli/src/values-verify.ts`

- L1: Per-statement verification of distributed values and metadata (CRYPTO_SPEC §6.3): the wire layout interpretation, the failure
- L42: One pulled variable whose write signature and statement passed §6.3.
- L45: The verified statement's name (no other name is trusted — §12-2).
- L51: The signed prev (the signed-bytes hash of the immediately preceding version. Empty for version 1).
- L53: Locally recomputed hash of the value's signed bytes — the prev anchor for pushing the next version (the §4.1 chain) and the comparator for
- L59: The verified statement's metaVersion (the basis of the rollback / fork checks).
- L61: The statement's signed-bytes hash (self-computed — the same-metaVersion difference check).
- L63: The signed prev (the signed-bytes hash of the immediately preceding metaVersion. Empty for metaVersion 1).
- L65: The value signature's declared head (included in the fork evidence of a floor check — §6.3 / §14.2-5).
- L71: The verified value signature and its attribution (self-contained fork evidence — §14.2-5).
- L75: The verified statement signature and its attribution (same).
- L79: The statement's wire layoutVersion (omitted = 1 — §12-2).
- L81: The schema column of layout v3 (null for v1. The type is a declaration — advisory §14.3-7).
- L85: One pulled variable on the wire (statement + value — AUTH_SPEC §12-7 / §14-2).
- L98: Whether it is evidence (a contradiction between signed distributed data and the chain notarization / coordinates — a re-run does not
- L109: Whether the claimed AAD's coordinate components match the expected coordinates (verified genesis / requested env / response's outer id)
- L123: Verification failure reasons → future / rejected. chain-head-future and "a head beyond the own view declared by a new member of an unsynced
- L136: Whether a failure can be classified as future (the bounded-resync entry) (§6.3-2b).
- L164: An honest breaking mode (the client needs an update) — not evidence of tampering (ruling CR)
- L179: Verified statement → the shared evidence-material fields (§14.2-5's self-containedness). The mapping of the 7 fields the floor check and
- L201: Interpreting a variable statement's wire schema-layout fields (§12-2): a v1 has all of them absent, a v3 has all of them present
- L251: Layout v3 carries maxAgeDays (null = none — §12-2; its absence is the same partial-set refusal). Any other layout is refused later as
- L260: The refusal message for a distribution carrying a partial schema-layout field set (§12-2's all-or-nothing rule).
- L265: The schema-layout fields passed to crypto's signed context (required and max_age_days in the signature convention's string forms — §4.2).
- L276: "" = no declaration
- L282: The composite verification of a statement (§6.3). The context is assembled locally from the expected coordinates. A variable statement's
- L330: Verifying a variable statement (the entry of verifyStatement with the wire schema-layout interpretation). A partial field set is refused
- L369: Coordinate agreement (§6.3-5): verification and decryption run on the expected coordinates, so a mismatch fails either way — the explicit
- L388: The name → variableId mapping must go through a verified statement (§4.2 / §12-7)
- L399: deleted = the transport shape of an unauthorized undeletion; declared = juxtaposing a value onto a valueless declaration (declared is the
- L476: The latest statements of declared variables (§12-7 — no value or version exists). Absent = no declared.
- L481: The latest manifest (§12-7 — required on the wire; the schema refuses an omission at decode — the same verdict as a dropped environment
- L487: The enumeration of value snapshots at the checkpoint (§12-7 — rule 2's material. An omission on an environment with a baseline is refused
- L495: Verifying the environment's own statement (including that it is active). Returns the evidence material.
- L501: The verified chain is the authority for deletion (CRYPTO_SPEC §6.3 "Chain-deleted environments"): a server distributing a chain-deleted
- L539: Verifying a deleted variable's tombstone statement (a juxtaposition with the active / declared side = the transport shape of an
- L546: Each statement's signature verification is independent, so they run in parallel; the checks below then replay in input order and the
- L590: deleted keeps the immediately preceding active name (§4.2) — the only verified source of a deleted variable's display name (name resolution
- L601: The name check of the verified live (active + declared) set: a duplicate same name = resolution refusal (§4.2), non-NFC = a warning
- L608: Uniqueness is a byte-exact comparison (§12-1. Equivalent to NFC equality when every accepted name is NFC)
- L622: Verifying the variable statements of a metadata-only pull (§12-7's metadata-only mode). The coordinate-agreement and variableId-duplicate
- L687: Parallel signature verifications; the checks replay in input order so the first reported failure is unchanged (P-5).
- L702: The coordinate and duplicate refusals shared by the live and declared lists, applied before any per-list judgment: a statement served under
- L732: Verifying the declaredVariables (§12-7) of a value-bearing response. The implementation point of CRYPTO_SPEC §6.3's value-distribution
- L770: An active appearing here = the value of a verified active statement is missing from the value-bearing response (a value omission, G6
- L799: Verifying the active variables (including the variableId-duplicate refusal).
- L807: Per-variable verification (statement signature + value signature) is independent, so it runs in parallel; the duplicate-id check and the
- L817: A duplicate variableId within one response is refused unconditionally (covers the transport shape of equivocation that juxtaposes different

### `apps/cli/src/values.ts`

- L1: Verification of distributed values and metadata statements (CRYPTO_SPEC §6.3). Before decryption or name resolution, every value's §4.1
- L78: A bulk pull whose values and statements all passed verification (§12-7 / §6.3).
- L80: The view used for verification (may have advanced via a future head's bounded resync).
- L83: Verified declared statements (valueless declarations — §4.2 layout v3). declared is the only legitimate valueless state (CRYPTO_SPEC §6.3's
- L89: Verified tombstones (digest material for manifest issuance — §4.3).
- L91: The verified environment meta-statement (the envMeta material for manifest issuance).
- L93: The verified manifest (§4.3 — an omission is already refused, §6.3).
- L95: The wraps addressed to me (verification is the §5.1 / §5.2 path of deks.ts).
- L97: SHOULD warnings such as a distributed non-NFC name (displayed by the caller).
- L101: The result of running a verification stage (rejected is already folded into the failure channel — the 2 values future | ok).
- L104: The shared wrapper of a verification stage: folds a crypto-execution failure into a CliError and a rejected into the failure channel (each
- L118: Signed distributed data that fails verification = evidence (a re-run does not resolve it — errors.ts's definition of evidence; it must not
- L131: The manifest stage (§4.3 / §6.3): a required response field — the wire schema already refuses an omission at decode (the same verdict as a
- L144: The floor's manifest record (the predecessor of the adjacent prev verification — M1-A1. null when there is no floor).
- L149: A manifest refusal is a contradiction between signed distributed data = evidence (manifest.ts's result type carries no evidence, so it is
- L170: The shared verification skeleton of a pull response (§6.3): environment statement → the active set (swapped by shape: value-bearing /
- L195: One verified active → the variables_digest entry (the recomputation material of §4.3 (3)).
- L197: The floor's manifest record (the adjacent prev verification — M1-A1. Paths with no floor pass null).
- L296: The head seq of the view **at the moment the response was fetched** (pull = the fetch-time view, lease = the bundled chain's head). Since
- L330: Rule 2 of checkpoint integrity (§6.3 — the value-carrying path only. metadata-only is out of scope since it carries no values, §12-7). The
- L372: The shared skeleton of the pull family (§6.3-2b): fetch → verify → floor check (accept). A future (a declared head beyond the own view =
- L387: The bounded resync on a future head (once).
- L397: The floor check / commit. view = the view used for verification (may have advanced via the resync).
- L416: A distribution bound to a chain position that still does not exist after the resync = evidence of a fork / forgery
- L420: Pulls one environment and verifies every value's write signature and every metadata statement (environment, active variables, tombstones)
- L431: The bounded resync on a future head (once).
- L433: The local floor (§6.3). Carries the check (rules (a)(b)(c)) and the atomic commit after verification succeeds.
- L450: The adjacent-version prev verification (M1-A1): the floor's manifest record is passed as the predecessor
- L452: The response was fetched under input.verified's view (even on a post-resync re-verification the fetch moment does not change — the baseline
- L469: Verification uses the (possibly advanced) view; the rule (c) baseline is derived from the pre-response-fetch view (enforceFloor's
- L494: Verifies the distribution material of a workload-lease response (CRYPTO_SPEC §9.1 duty (4): environment statement, every active variable's
- L515: The verified declared (§14-2 — material for ci run's presence check).
- L521: Manifest verification is mandatory (CRYPTO_SPEC §9.1 (5)) and a required response field — the wire schema refuses an omission at decode
- L547: The no-baseline warning (§6.3 SHOULD — a client with no floor warns when it detects that an environment it received a value-carrying
- L567: The verified response of a metadata-only pull (§12-7's metadata-only mode).
- L569: The view used for verification (may have advanced via a future head's bounded resync).
- L571: The verified statements of all non-deleted variables (active and declared mixed — §12-7).
- L573: Verified tombstones (the only source of name resolution for deleted variables — AUDIT_SPEC §7).
- L575: The verified environment meta-statement (the envMeta material for manifest issuance).
- L577: The verified manifest (required on the wire — an omission is refused at decode, same as the with-values pull).
- L579: The server-claimed schemaPolicy (§12-7 / §12-11 — advisory). **Never an input to a verification rule** — its only use is UX (advance
- L589: The issuing material of a meta operation's bundled manifest (§12-5): the previous manifest of a verified metadata pull, the current meta
- L600: The current meta set (tombstones included) — the caller appends the new variable's entry per attempt.
- L605: Assembles the manifest issuing material from a verified metadata pull (shared by push's create / activate and schema set / var rm — built
- L642: The advisory bundling of schemaPolicy (§12-7).
- L646: The verified intermediate value of a metadata-only pull (pullWithBoundedResync's TVerified).
- L675: In metadata-only mode declared is mixed into variables (§12-7) — a separate declared list exists only on a value-bearing response
- L681: The active / declared distinction is the verified statement's status (§4.3's entry includes status — pinning "active" would make the digest
- L693: Pulls only the metadata of one environment (§12-7 metadata-only mode: no values, no DEKs — the server records no `var.read`) and verifies
- L706: The bounded resync on a future head (once).
- L708: The local floor (§6.3). The meta-level check + the environment-level commit (enforceMetadataFloor — M1-A3).
- L725: The adjacent-version prev verification (M1-A1): identical on the metadata-only / value pull paths
- L771: advisory (§12-11): an unverified claimed value — UX use only

### `apps/cli/src/var.package/command.ts`

- L232: var history is metadata only (§12-7): keyless, scope-agnostic, no value is read — the agent gate does not apply (zero values, the permissive side).

### `apps/cli/src/var.package/var-history.ts`

- L1: History/rollback design (VH): history rows are server-declared and the output says so; rollback never trusts that metadata — the target is accepted only as a verified ancestor of the verified latest (full §6.3 verification, prev-hash link, epoch monotonicity), and the restore declares sameValueAs so rotation-needed detection sees the lineage; confirmation is fail-closed but not a ceremony, so an agent with --force may run it.
- L68: Name resolution goes through a verified metadata-only pull (§12-7 — no var.read); duplicate live statements are equivocation.
- L100: The fetched history is display metadata — never a write or invalidation target.
- L145: The note column's lineage kind is derived, never declared (AUTH_SPEC §12-5).
- L199: The JSON output carries serverDeclared: true so a consumer never mistakes the history for verified data.
- L351: The fetched range is verified as an ancestry of the verified latest (§4.1/§6.3): every value signature, the prev-hash link and epoch monotonicity between consecutive versions, and the last version byte-identical to the bulk pull's verified latest.
- L424: Rollback confirmation is fail-closed (--force proceeds with the facts still stated; non-interactive without --force refuses; interactive asks y/N) but asks no name retyping, because a rollback is reversible — history stays append-only.
- L548: The default rollback target (the version right before the latest) is derived from the verified latest, never from the server-declared history: which credential a finalize destroys must not be the server's to steer.
- L584: The rollback target is decrypted in memory and a no-op is refused — the current value already equal would only burn a version.
- L669: verifiedAncestorRange applies the rollback's evidence rule to every earlier version; the server's history metadata never picks the invalidation target.
- L716: An ancestor this device cannot decrypt is skipped with a warning, not fatal — whatever the reason, the id set it feeds can only shrink, which never widens what a finalize invalidates; its signature and lineage were verified above.
- L760: The confirmation's advisory exposure count is server-derived — it compares audit seqs, which never reach the client.

### `apps/cli/src/var.package/var-rm.ts`

- L1: var rm design: deleting a v3 variable keeps the schema fields and layout byte-exactly from the previous statement (§4.2's deletion convention, a mismatch is a server 422), deletion is terminal and rides the 3-F + 1-E′ meta-operation discipline; the command sits in the var group, not schema, because what disappears is the variable and the value itself.
- L102: Deletion is terminal (§4.2): rm on an already-deleted name reaches the desired state but the call's precondition (this run deletes it) does not hold, so it is an explicit error.
- L156: A v1 variable's deletion statement keeps the v1 form — never silently raises the layout.
- L172: The deletion statement's name keeps the last active name as-is (§4.2 — deletion never empties the name field).
- L223: Deleting a v3 variable uses that form — schema fields and layout kept byte-exactly from the previous statement (§12-5's deletion convention); a v1 variable's deletion keeps the v1 form.
- L299: A concurrent meta operation re-resolves the confirmed ID (§12-5's retry: refetch → verify → re-sign the statement and the manifest); losing to a concurrent deletion surfaces from re-resolution as the determinate "already deleted" error.
- L309: varRmOp deletes with a signed deletion statement + manifest composite, gated by an explicit confirmation, and confirmed against the verified distribution (1-E′) before the local floor advances to the tombstone.
- L323: The deletion confirmation binds the variableId, not the name (an ID never changes and is never reused), so a conflict retry re-resolves by that ID: a concurrent rename keeps the confirmed target, and another variable taking the name can never become the target.
- L349: Effect confirmation (1-E′): a deletion's effect is a tombstone at or above the issued metaVersion, and same-version requires hash equality — never misread a 2xx lost to a concurrent operation as effective.
- L360: The floor's tombstone advance (§6.3) happens before the success report (journal-before-release) so a later pull can detect the deletion being silently undone; a floor write failure is reported as such.

### `apps/cli/src/var.package/var-rotate.ts`

- L200: Unwrapping reason: the connector consumes the admin credential in memory to call the issuer's API; it is never displayed, written, or sent anywhere but the issuer.
- L442: A companion's current value comes from the verified pull, and nothing server-declared (the history's versions or times) takes part in the invalidation decision.
- L450: The previous credential's companions are positional (C-7): a companion version pairs with the primary's only when the primary's previous version is also the one directly before — one rotation pushes the pair together; otherwise no pairing is claimed and the finalize sees the ancestors alone.

### `apps/server/src/attestation-accept.ts`

- L1: Acceptance of head attestations (CRYPTO_SPEC §6.4 / §6.6, AUTH_SPEC §16-1).
- L51: Wire submission content (attester is the caller — same shape as api-schema's submission).
- L59: Mapping of crypto's detailed reasons onto the wire's 3 reasons (the same folding as VALUE_REJECT_REASONS in verify-value.ts).
- L77: Acceptance program for PUT /projects/:projectId/head-attestation (runs under the DO's permit — no interruption between the decision and…
- L88: 1. Membership (reader or higher — §16-1's "chain role reader or higher")
- L93: 2. Fixed window per member (check → consume immediately:
- L107: 3. §6.6 verification (applies the same implementation as the client to the acceptance-time history index.
- L136: Every other kind is unreachable (InvalidInput / KeyImportFailed with a Schema-validated wire + a key derived from a verified chain; the…
- L162: 4. Monotonic seq advance (regression 409 / same seq idempotent 204 / advance upsert) — only against the same device's stored row (no…
- L170: The same seq that passed the head-existence match (step 3) has the same hash, and deterministic Ed25519 gives the same signature = a…

### `apps/server/src/checkpoint-accept.ts`

- L1: Acceptance of standalone (periodic) checkpoints and the shared implementation of checkpoint content matching (CRYPTO_SPEC §6.4 /…
- L55: Content match of a checkpoint's values_digest (CRYPTO_SPEC §6.4).
- L66: Malformed input derived from stored rows is an implementation bug (no secrets in error values)
- L77: Existence/position check of a non-empty audit_head_hash (CRYPTO_SPEC §6.4 / AUDIT_SPEC §5.1).
- L108: DO storage-total guard (AUTH_SPEC §12-8):
- L128: Acceptance-time match of one environment tuple (§6.4):
- L168: Acceptance of a standalone checkpoint (the checkpoint branch of the generic chain append — called from programs-chain.ts's appendProgram).
- L186: §11-2: non-members get nothing back (the worker maps to 404).
- L190: §16-2: a non-empty audit_head_hash requires chain role admin or higher (insufficient → 403.
- L196: Stage 2 (design record §8 K3-1): repeat the role check with the effective permission of the device the entry's actor FP names (an FP…
- L210: §12-3: every tuple's environment ∈ the caller's scope, then the signing device's (403 insufficient-scope — before verifyChain; the…
- L221: The 4 acceptance steps (size → capacity → verifyChain = §6.2's consensus rules) are shared with the other paths
- L224: Content match against the stored state at acceptance time (before applying) (§6.4).
- L235: The snapshot store (§6.4) commits atomically in the same synchronous block as the chain insert and mirror (commitAcceptedEntry's extraSync)
- L255: checkpoint is a non-proposable op (CRYPTO_SPEC §6.2) — no proposal was applied

### `apps/server/src/dek-wraps.ts`

- L1: Acceptance verification of DEK wraps (AUTH_SPEC §12-6 = the server side of the CRYPTO_SPEC §6.3 ghost-member countermeasure) and…
- L43: Duplicate-detection key of (epoch × recipient class × recipient × device key) — the deletion path (programs-dek).

### `apps/server/src/handlers/handlers-key-wraps.ts`

- L1: Handlers for the master-key wrap ledger API (AUTH_SPEC §13-6–13-10 — KL3; the server side of CRYPTO_SPEC §8's classes S / G / H).
- L61: Only the ledger's 3 windows (the device-add-request window `device-request` is mapped onto its own typed 429 by the devices group —…
- L74: The public parameters of a passkey row (§13-9 — the server returns the JSON it wrote verbatim).
- L85: A stored label of an unexpected shape is filtered out below (not a decode failure — the same "drop a non-string label" as before)
- L93: The only writer is this file's passkeyRegister (JSON-ifying Schema-validated values).
- L110: Structural check of a segment set (§13-7 / §13-8 — device rows.
- L127: Folds device rows into logical segments (per share_index).
- L189: The roles a caller may take for a request's query / approval (§13-7 — 2026-09-19 DK K4):
- L209: One role per logical segment (group × share_index) — device rows are folded (DK)
- L222: Column of device rows → per-logical-segment roles (the same (group, share_index) appears once).

### `apps/server/src/key-wrap-domain.ts`

- L1: Domain types of the master-key wrap ledger (AUTH_SPEC §13-6–13-10 — KL3).
- L11: The guardian group's threshold mode (CRYPTO_SPEC §8.3).
- L14: The wrap of B (the master-key blob) (AES-256-GCM; §13-9 MasterKeyWrap).
- L21: A class-S (passkey-prf) ledger row. `params` is the JSON string of public parameters.
- L30: A class-G segment row (an HPKE Seal to the guardian's enc public key).
- L40: A class-G group row (segments included).
- L50: The guardian's own segment as the guardian sees it (with ward info).
- L53: A display snapshot of linked_identities.provider_login (not an identifier)
- L58: The sealed-to device key (the guardian's device — identifies the row)
- L66: A class-H handoff request (does not hold E.pub — request_id is a derivative of it).
- L75: A class-H approval (response scope — disappears with the request).

### `apps/server/src/server-key.ts`

- L1: Derivation of the deployment keypair (CRYPTO_SPEC §9), provision of the public info, and at lease time the "unseal the wrap addressed to…
- L52: The public face of the deployment keypair (distributed by /auth/config — AUTH_SPEC §4).
- L55: Computed from the derived public key (the actor FP of `server.*` audit rows — AUDIT_SPEC §3.5).
- L59: A stored server-addressed wrap (one row of dek_wraps — §12-6).
- L67: One lease wrap (response scope; never persisted — §9.1).
- L80: reseal failure reasons (all are server-internal inconsistencies; the reason is not exposed in the response).
- L84: The public face if configured; null when unset (or malformed).
- L86: Unseals a server-addressed wrap and re-wraps the same epoch DEK to the workload's ephemeral public key (CRYPTO_SPEC §9.1).
- L106: The derived server key (the public face + the keypair used for unsealing).
- L112: The domain error `derive` folds every wrapped crypto error into:
- L128: The IKM's only unwrap: the hex decodes straight into the derivation input (worker-env.ts wraps it at the env read)
- L135: A rejection of the bare-Promise export is a platform defect, not "unusable material" — the same defect the pre-bridge code let the…
- L154: Zero-fills the buffer of an unsealed DEK.
- L164: The env-facing construction: resolves the IKM from whichever binding shape the deployment carries (worker-env.ts — a failed Secrets…
- L181: A service built once at worker / DO startup.
- L189: Effect.cached allocates its memo cell synchronously:
- L195: Accesses hold the memo evaluation uninterruptibly, so the one derivation always completes and is stored even when every caller waiting…
- L221: Import can fail even through the wire Schema (32-byte hex) — an X25519 public key that is invalid as a point.
- L239: The unsealed DEK is a resource: the unwrap is the acquire (run uninterruptibly by acquireUseRelease, so a DEK it produces always reaches…
- L254: §9: a server-addressed wrap carries the server-key FP in the recipient position of its info
- L260: An undecryptable poisoned wrap (a target of §12-6's repair path).

### `packages/core/src/crypto-errors.ts`

- L1: Crypto bridging: two wrappers matched to crypto's two async return shapes; a bare-Promise rejection's cause is dropped on purpose so no key material can ride along in an error
- L101: An unwrapped DEK not matching the chain-published commitment for its coordinates is a poison wrap (§5.2)
- L127: Unsupported meta layout is a distinct error from invalid statement so callers can show an honest 'update required' instead of a tampering warning
- L167: CryptoPromiseOperation is derived from @maruhi/crypto's public surface: a new bare-Promise export widens the union automatically, and an export switching to CryptoResult drops out
- L187: CryptoRejectedError deliberately keeps no rejection cause and stays outside WrappedCryptoError — that union mirrors CryptoError kinds 1:1 and a rejection is not a CryptoError value
- L199: CryptoContractViolationError carries no part of the rejection value and a fixed static message — the whole diagnostic is the _tag plus a constant, so nothing can leak into crash output
- L292: cryptoEffect: a rejection is a bug and surfaces as a defect — the rejection value is replaced inside the thunk before Effect.promise can embed it, so nothing leaks into crash output
- L318: cryptoPromise pins the thunk's return type to the named export's so operation and run cannot disagree; the rejection cause is never kept

### `packages/crypto/src/index.ts`

- L1: Package charter: CRYPTO_SPEC is sole source of truth, human review required, WebCrypto+hpke only, typed errors not Effect
- L13: Export group anchor: §1-§2 common (suite id, §2.1 encoding, result types)
- L25: §3 anchor: BIP39 dictionary is §3's fixed display dictionary, completeness pinned by upstream-hash test
- L52: §4 anchor: AES-GCM variable encryption with coordinate-bound AAD
- L61: §4.1 anchor: value write signatures export group
- L74: §4.2 anchor: signed variable/environment metadata statements incl. layout v3
- L96: §4.3 anchor: env manifest is the meta freshness anchor; canonical impl lives here, shared by server/CLI
- L115: §5 anchor: HPKE key wrap export group
- L124: §5.1 anchor: DEK wrap registration signatures
- L132: §5.2 anchor: epoch DEK commitment bound by the chain
- L140: §6 anchor: membership log — entry format, roles/ops incl. ES scope and PF1 four-eyes, verification, derived state
- L221: R(E)/W(E) recipient sets have one shared definition behind CLI wrap sets and server checks
- L233: AUDIT_SPEC §5.1 anchor: audit-head rolling hash shared by project DO generation and admin verification
- L243: §6.5 anchor: invite crypto reuses §3 fingerprint words and §6.3 link anchor rather than new primitives
- L267: §6.6 anchor: head attestation form of §6.3 gossip; submission AUTH_SPEC §16-1, verification §6.4
- L281: §7 has no export surface — workflow rules only (absence is deliberate)
- L283: §8 anchor: master-key wrap ledger recovery-code path, unchanged
- L291: §8.1-8.4 (KL3) anchor: ledger recipient classes — passkey-prf KEK, guardian XOR split + HPKE Seal, handoff
- L319: §5.3 anchor: sealed value proposals reuse the §5 primitive with proposal/variable-bound info
- L333: §9 anchor: selective disclosure server keys
- L336: §9.1 anchor: lease wraps are response-scoped and never persisted

### `packages/crypto/src/internal.package/audit-head.ts`

- L1: AUDIT_SPEC §5.1 digest formula: NULL tagged 0x00 vs 0x01+bytes so NULL and empty string never share a preimage
- L32: AuditHeadRow: 17-column fixed enumeration; null digested distinctly from empty string; payload used as stored
- L63: Tagged byte string definition pinned by §5.1 (NULL=0x00, non-NULL=0x01+bytes)
- L81: computeAuditRowDigest rejects non-safe-integer numerics per §2.1 bounds — fail-closed
- L130: Audit-head recurrence h_n formula; h_0 is the empty string

### `packages/crypto/src/internal.package/bip39-english.ts`

- L1: BIP39 dictionary identical to upstream, pinned by SHA-256 test; display encoding only, not key material; do not hand-edit
- L9: BIP39 word list is CRYPTO_SPEC §3's fixed dictionary

### `packages/crypto/src/internal.package/bytes.ts`

- L1: Hex is fixed lowercase per chain normalization's binary_encoding convention
- L10: encodeHex output is the canonical text form for all binary values in maruhi structures
- L22: decodeHex rejects uppercase: canonical chain/FP form is lowercase only; null (not throw) on malformed input
- L29: Runtime defense over TS types: non-string input from untrusted JSON returns null rather than throwing

### `packages/crypto/src/internal.package/chain-canonical.ts`

- L1: §6.1 canonicalization definition pinned by chain-entries.json; per-op nested-LP payload conventions
- L35: Lease policy canonical form: three-level nested LP; empty policy encodes to empty bytes = no lease path
- L59: Checkpoint environments canonical form: nested LP of tuples; empty list = audit-head-only checkpoint
- L83: Canonical payload bytes follow each op's fixed field order, fixed by chain-entries.json
- L94: ES revision: scope fields appended at end of add_member payload (§6.2), same nested-LP hex as grant_server scope
- L122: delete_environment payload is one field; domain separation comes from the op name inside signed_bytes
- L150: PF1 four-eyes: set_approval_policy ops use nested-LP hex; inner payload can nest two or more levels
- L169: DK device keys: add_device/revoke_device canonical field orders; revoke FP list order is signed over
- L192: canonicalChainSignedBytes is the §6.1 Ed25519-signed byte string
- L208: Entry bytes = signed fields + signature; its SHA-256 is the next entry's prev_hash
- L227: Entry hash = SHA-256(entry_bytes) as lowercase hex

### `packages/crypto/src/internal.package/chain-device.ts`

- L1: Device-keys principle: keys belong to devices, permission to the person; effective permission computed only here, branded type (K2-4)
- L21: ROLE_RANK is the single role order used by every comparison (§6.2 role table)
- L27: minRole = min(person role, role_cap) per §3
- L32: DeviceCap semantics: role upper bound + DEK environment subset; owner = no bound; first key structurally (owner, all)
- L43: FIRST_DEVICE_CAP: a member's first key is structurally (owner, all) since the payload is unchanged
- L46: ChainDevice identified by key fingerprint: FP = SHA-256(enc‖sig)[:16] names the device (§3)
- L55: addedSeq records which entry (genesis/add_member/add_device) put the key on chain, inclusive
- L59: EffectivePermission is branded so a member's raw (role, scope) cannot be passed where device permission is required
- L70: Scope intersection contract: all is identity; listed∩listed keeps a's order
- L82: effectivePermissionOf is the single computation point for (min(role,cap), scope∩device scope)
- L97: Cap monotonicity D2 judged cap-to-cap, not vs effective permission, so a member can register an (owner,all) reserve key (Bugbot finding)
- L119: soleDeviceOf is fail-closed: multi-device returns undefined rather than picking an arbitrary first key (K2/K3/K4)

### `packages/crypto/src/internal.package/chain-history.ts`

- L1: History index design (ruling A): final ChainState nor naive keyHistory can express tenure/point-in-time; inclusive seq conventions pinned
- L47: MemberStateAtSeq has no single key field (DK): keys belong to devices; key resolved via deviceStateAt
- L56: MemberStateAtSeq.scope is the §6.3 3′ head-time scope-check input
- L58: Devices active at seq use inclusive intervals (§6.2), keyed by fingerprint
- L64: DeviceStateAtSeq pairs the device with its effective permission at that seq (§6.3-1 input)
- L76: Checkpoint tuple lookup: values digest deliberately excluded from conflict comparison — re-attestation at same mv is legitimate (ruling B)
- L100: EnvironmentStateAtSeq is the input of §6.3-4
- L104: Epoch currency convention: epoch N is current from its start seq
- L106: deletedAtSeq semantics pinned by §6.2 (delete entry seq or null)
- L110: ChainHistoryIndex is obtainable only via verifyChainWithHistory — no index exists for an unverified chain
- L118: entryHashAt is 1-based; undefined beyond the head
- L120: memberStateAt applies seq inclusively; undefined when not a member at that point
- L126: deviceStateAt: validity interval from add seq until just before revoke seq (§6.3-1); carries effective permission at seq
- L141: environmentStateAt applies seq inclusively; undefined before create_environment
- L149: sigKeyByFingerprint spans all tenures so signature verifies first, then head validity rejects as writer-key-mismatch-at-head
- L157: checkpointTupleFor binding is internal, not caller-supplied, so a forgotten lookup cannot reopen the strict path (ruling A)
- L169: latestCheckpointFor mirrors ChainState.checkpoints as the §6.3 per-environment baseline
- L177: MemberSpan starts at fromSeq inclusive
- L184: DeviceRecord validity interval [addedSeq, revokedSeq); delete_environment pruning appends cap changes ascending
- L192: revokedSeq: device invalid at that seq itself (inclusive)
- L199: endSeq: member invalid at the remove_member seq itself (inclusive)
- L201: Devices kept in order of addition; first is the genesis/add_member key
- L208: epochStarts ascending [epoch, startSeq]; epoch 1 = createdAtSeq
- L223: change_role makes the new (role, scope) valid at the entry's own seq (inclusive)
- L236: Device validity: valid at add_device seq, invalid at revoke_device seq (inclusive — §6.2)
- L241: Device cap at seq = latest pruning at or before seq, else the cap it was added with
- L264: Epoch currency: epoch N is current from its start seq
- L282: delete_environment pruning: only principals actually pruned get a new interval
- L343: Remove is invalid at endSeq itself, so the valid interval is [startSeq, endSeq)
- L413: Key selection by FP over all tenures incl. revoked (§6.3-1); same FP = same key pair even across revoke→re-register
- L456: ChainHistoryBuilder is internal only — indexes are handed out solely for fully verified chains
- L481: Tenure start: first device has structural cap (owner, all) (§6.2); firstDevice.addedSeq must equal startSeq
- L506: add_device: device active from its addedSeq inclusive (§6.2)
- L511: revoke_device: listed devices invalid from seq inclusive (§6.2)
- L525: change_role: new (role, scope) current from seq inclusive — full replacement (§6.2)
- L545: delete_environment history pruning mirrors verification state; latest-checkpoint baseline dropped; all never pruned
- L573: Checkpoint conflict demotion on differing (epoch, manifest_sig_hash); values_digest excluded — may legitimately change at same mv (ruling B)

### `packages/crypto/src/internal.package/chain-sign.ts`

- L1: WebCrypto Ed25519 is RFC 8032 deterministic, matching the test vectors (§6.1)
- L9: signChainEntry signs the §6.1 canonical signed bytes

### `packages/crypto/src/internal.package/chain-types.ts`

- L1: Identity rule (absolute): actors identified by internal user_id + key fingerprint only; provider ids/emails never enter the chain
- L10: Role is the §6.2 project role type
- L13: ChainOp history: four-eyes ops added PF1 2026-09-14, device ops DK 2026-09-19, delete_environment 2026-10-07
- L36: ApprovalTargetOp excludes data/safety ops, genesis and approval ops themselves — they can never be targets
- L49: APPROVAL_TARGET_OPS closed set shared by structure check and CLI input validation
- L61: UserId brand rationale: provenance only, no runtime form; minted only at upper-layer trust boundaries, never in this package
- L79: KeyFingerprintHex: FP = SHA-256(enc‖sig)[:16] (§3) / server §9; brand records format + provenance; mints enumerated
- L103: ProjectId = lowercase-hex SHA-256 of genesis entry (§6.4), cryptographically bound; minted only at trust boundaries
- L123: EnvironmentId brand: provenance only; its form is an API acceptance policy, not a chain-validity rule (§6.1)
- L142: VariableId brand: same provenance rule as EnvironmentId; minted only at trust boundaries
- L153: ChainActor carries internal user id + fingerprint only — never provider ids (identity rule)
- L164: add_member payload: scope as two trailing canonical fields since ES revision; owner must carry scopeKind=all
- L181: change_role replaces (role, scope) in full; shrunk part carries §7 rotate duty, grown part is backfill
- L193: Epoch-1 DEK commitment: chain verification checks format only; matching against unwrapped DEK is the recipient's §5.2 duty
- L201: delete_environment: chain is the sole authority on deletion; no off-chain statement records it
- L214: Epoch is strictly numeric in this API; decoders MUST coerce wire decimal strings before verifyChain or invalid-payload
- L222: New-epoch DEK commitment format pinned by §5.2 (lowercase hex, 64 chars)
- L226: Lease claim constraint: v1 exact-match semantics live in AUTH_SPEC §14; chain fixes structure only
- L236: Lease policy element semantics: constraints AND within an element, any element matching authorizes (existential — AUTH_SPEC §14-1)
- L251: Server grant scope: re-grant may only widen (old ⊆ new); narrowing must go through revoke_server with its §7 rotation duty
- L261: Lease policy freely revisable on re-grant, unlike scope: it is an ACL over the lease path and does not change known DEKs (§6.3)
- L278: Checkpoint tuple: manifest/values contents not chain-verifiable; content matching is server §6.4 / client §6.3 duty
- L291: manifestSigHashHex = SHA-256 of the manifest's signed bytes (§4.3)
- L293: valuesDigestHex is the canonical env values digest (§6.2)
- L298: Checkpoint environments: subset coverage valid (full coverage is SHOULD not consensus); order is signed; verification does not normalize
- L306: Non-empty auditHeadHashHex requires the actor to hold admin at that entry (consensus rule — §6.2)
- L314: set_approval_policy: requiredApprovals 0=off or ≥2; enabling requires owner count to reach it; policy monotonicity on targets
- L329: ProposableOperation excludes approval ops themselves — nesting rejected at structure stage; proposals never policy targets
- L339: propose: expiry is the only timestamp consensus reads (§6.2 proposal-expired) — a safeguard for honest approvers, not a guarantee
- L353: ApprovePayload.proposalHashHex is the entry hash of the pending propose entry
- L358: WithdrawPayload.proposalHashHex is the entry hash of the pending propose entry to close
- L363: add_device payload: actor-only (no target field); canonical field order and consensus rules incl. D2 cap bound
- L378: roleCap: owner means no role bound
- L382: revoke_device: order signed but verification treats FPs as a set; 1..256, no duplicates; last-device-protected
- L417: UnsignedChainEntry is a chain entry before signing (§6.1)
- L426: ChainEntry is the complete signed entry (§6.1)
- L429: ChainMember: no 'member's key' — signatures attribute to one device and carry its effective permission, never raw (role, scope)
- L441: ChainMember.scope is the input of R(E) / environment-targeting ops / §6.3 3′
- L443: ChainMember.devices is the §6.2 verification-state device set keyed by fingerprint
- L447: ApprovalPolicy is the active four-eyes policy from a verified chain; null = off (§6.2)
- L450: Invariant: requiredApprovals at least 2 while a policy is active
- L454: ApprovalVote bound to (user id, key FP): a re-added approver under a new key no longer carries the vote (2026-09-15)
- L466: PendingProposal vote count never read from the record alone — recomputed at every approve against current members (principle 2)
- L479: proposerKeyFingerprintHex fixed at proposal time; proposal-void on change
- L481: Owner proposer's signature counts as 1 vote; later promotion does not change that — the promoted proposer may approve instead (ruling ②)
- L493: ServerGrant is an active server grant from a verified chain (§9)
- L497: grantSeq is the sole source of server.lease_issued's grant_chain_seq (AUDIT_SPEC §3.5) — re-grant rules stay in the verifier
- L506: ServerGrant.leasePolicy is the latest accepted grant's policy (§6.2)
- L510: EnvironmentChainState: deleted environment stays in the set; its id is never reusable
- L520: createdAtSeq is epoch 1's start seq
- L522: deletedAtSeq: the verified chain is the only authority for deletion (§6.2/§6.3)
- L528: epochStartSeqs maps epoch → seq of the entry that made it current (create / rotate)
- L530: dekCommitments maps epoch → dek_commitment_hex (§5.2)
- L534: EnvironmentCheckpointState is the §6.3 checkpoint-integrity baseline per environment
- L548: ChainState: environments exist only via create_environment — no implicit epoch-1 default for unknown ids
- L560: ChainState.checkpoints is the checkpoint-regression and §6.3 integrity baseline; uncovered environments absent
- L566: ChainState.approvalPolicy: active four-eyes policy or null (§6.2)
- L568: ChainState.pendingProposals is the §6.2 verification state keyed by propose entry hash
- L570: namedServerKeys covers every grant-named server key, valid or revoked; pending/withdrawn proposals name none (§6.2 uniqueness)

### `packages/crypto/src/internal.package/chain-verify.ts`

- L1: Verification order fixed (framing→structure→actor→signature→authz) to match vectors' expected_reason; checks use device effective permission
- L88: MAX_FIELD_BYTES is a §6.1 consensus rule guarding verifying clients against resource consumption via oversized payloads
- L92: Lease policy limits chosen so a spec-conformant grant_server entry stays mathematically below the §6.4 acceptance limit
- L98: Four-eyes required approvals: 0 = off, otherwise 2 or more (§6.2)
- L100: revoke_device FP list limit: 1..256, no duplicates (§6.2)
- L106: MutableEnvironmentState.deletedAtSeq: delete entry seq (§6.2, 2026-10-07), null while live
- L112: MutablePendingProposal.approvals holds accepted approve signatures (user_id, key FP), ordered (§6.2 state)
- L127: Environments map doubles as the every-ID-ever-used set: delete marks but never removes, so duplicate check needs no extra index
- L132: Checkpoints map is the checkpoint-regression comparison target and §6.3 consistency basis
- L136: Key-uniqueness index soundness: the invariant makes Set deletions in remove/revoke safe; hex normalized so string equality = byte equality
- L145: namedServerKeys never shrinks: revoke_server leaves the key named; pending proposals name nothing (§6.2, 2026-10-25)
- L150: Four-eyes state: current policy (null = off) and pending proposals keyed by entry hash (§6.2)
- L156: ActorContext carries only the branded EffectivePermission to checks — the person's (role, scope) is never passed directly
- L169: AppliedOperation pairs an applied op with its attributed subject for history recording
- L175: Shape predicates never throw on cast JSON input: malformed chain data lands on invalid-payload, verification never aborted
- L182: Cheap length check before real UTF-8 encode avoids allocating huge strings (byte count ≥ code-unit count)
- L188: isBoundedId: non-empty and ≤ MAX_FIELD_BYTES UTF-8 (§6.1)
- L194: Exact-length check rejects wrong-length hex in O(1) before decodeHex — fail-fast against CPU/memory burn
- L208: isApprovalTargetOp is public so client policy parsing uses the same guard as the consensus rule
- L221: userFingerprintHex is the package's own KeyFingerprintHex mint: 16 digest bytes = 32 lowercase hex by construction (§3)
- L230: FP = SHA-256(enc‖sig)[:16]; hex shape already verified before the call
- L265: Exact-length checks fail fast so huge hex strings never reach decodeHex or normalization (§6.1)
- L285: shapeScope is the §6.2 scope structure rule, preceding authorization
- L311: dek_commitment_hex format check belongs to the payload-structure stage, before authorization (§6.2)
- L333: Lease claim shape: claim_name non-empty identifier; claim_value may be empty (an OIDC claim value can be empty); §6.1 limit applies
- L375: lease_policy consensus covers structure only; evaluation semantics are AUTH_SPEC §14; missing policy = invalid-payload
- L384: Duplicate environment_ids rejected at structure stage — allowing them would make §6.3 basis and regression target nondeterministic
- L422: audit_head_hash: empty string means no notarization; otherwise lowercase hex, 64 chars
- L426: set_approval_policy structure: ops treated as a set (duplicates not rejected); required_approvals 0 or safe integer ≥2 (§6.2)
- L442: propose structure: nesting one level only, rejected at structure stage; no recursive shape check; expires_at_ms non-negative safe integer
- L465: add_device structure: keys lowercase hex 64; scope follows member-scope rule (all ⇒ empty list, ≤256, no duplicates)
- L482: revoke_device structure: FPs lowercase hex 32, 1..256, no duplicates; order signed but verification treats as set
- L502: PAYLOAD_SHAPES as exhaustive Record table so adding an op without a shape check is a type error
- L513: delete_environment shape: a non-empty id within §6.1's limit (§6.2, 2026-10-07)
- L530: Unknown-op check before table lookup: unchecked indexing on cast JSON could throw, violating never-throw contract; hasOwn rejects __proto__
- L551: resolveActorSigPub: genesis is self-describing via its payload
- L567: Declared FP picks a currently-valid device; revoked/unregistered keys are actor-key-mismatch (§6.2)
- L582: Do not hoist normalization out of the try: confining encoder throws to bad-signature preserves verifyChain's never-throw contract
- L616: actorContextOf: EffectivePermission's single computation point is effectivePermissionOf (§6.2)
- L621: indexDeviceKeys maintains the §6.2 key-uniqueness index over current devices
- L632: Key uniqueness judged per individual key, not per FP: reusing only one of the two keys is still rejected
- L650: firstDeviceOf: genesis/add_member first device cap is structurally (owner, all)
- L668: Principle 1 derived from the role table, not an enumeration; all treated as U; absent target treated as U (fail-closed)
- L695: isApprovalTarget is one shared predicate for propose/approve/direct-append; public so clients pre-submit with the same definition
- L714: Unlisted ops (create/rotate/checkpoint/genesis) can never be policy targets
- L720: establishesOwner captures the always-targets of policy monotonicity (a)
- L728: Principle 2 signer set S: votes are owner-role signatures; an admin proposer's signature does not enter S, even after promotion (ruling ②)
- L744: Vote liveness: revoked-device/removed-member votes dead, but re-registering the same FP revives a vote — revocation not monotonic (DK)
- L756: ownerVotersOf judged on state before the entry applies (ruling ⑤); public so clients re-tally with the same definition
- L789: Reachability invariant generalizes last-owner-protected: post-apply owner count must reach post-apply required_approvals (monotonicity (b))
- L809: ownersRemovedBy: removing or demoting an owner counts 1
- L820: Role rules stage is the part of authorization independent of target existence
- L823: checkpoint role rule: member+ to checkpoint; admin+ to notarize a non-empty audit head (AUTH_SPEC §16-2)
- L846: add_member role rule: admin+; granting admin/owner is owner-only
- L851: ROLE_RULES split: actor-only part here, target-dependent in targetRoleReason; add_device role-agnostic; exhaustive Record prevents missed ru
- L874: delete_environment requires the admin level the data-plane deletion had (§6.2, 2026-10-07)
- L914: Consensus rules stage: runs after role rules and approval-required; must not mutate state
- L917: isDeletedEnvironment reads the §6.2 delete marker (2026-10-07)
- L922: Environment existence stage order: unknown-environment → environment-deleted (§6.2)
- L937: Scope existence checked stage-wise: every id for existence before any for deletion (fixed by authz-add-member-unknown-precedes-deleted)
- L956: Owner-establishing add/change allow only scope=all (scope-role-mismatch, §6.2)
- L961: memberScopeReason fixes the shared check order: unknown-environment → scope-role-mismatch → scope-not-contained (principle 1)
- L986: resolveTargetedOp fixes front-half order: unknown-target → target role rule → last-owner protection (§6.2)
- L1018: add_member check order fixed by vectors: duplicate-member → duplicate-member-key → unknown-env → scope-role-mismatch → scope-not-contained
- L1024: Key uniqueness covers only current devices: a returning member's same keys are allowed unless a grant named the enc key since (§6.2)
- L1039: change_role check order fixed by vectors incl. approval-quorum-unreachable last
- L1057: remove_member check order fixed by vectors incl. approval-quorum-unreachable last
- L1075: add_device check order fixed by vectors; cap judged against signing device's own cap, effective permissions not compared (D2)
- L1100: revoke_device check order fixed by vectors; scope containment judged on the target person's scope (principle 1)
- L1130: FPs are duplicate-free by the structure stage, so list length equals devices revoked
- L1148: grant_server authz order fixed by vectors; FP consistency right after role (historical position kept); server FP = SHA-256(enc)[:16] (§9)
- L1161: No later entry may name a deleted environment; deletion already pruned the id from active grants, so re-grant needs no deleted id (§6.2)
- L1167: Re-grant ruling: scope widening only (narrowing would bypass revoke_server + §7 rotation); lease_policy freely revisable per field (§6.3)
- L1185: Grant-side key uniqueness: a server enc key held by a current device is rejected (recipient-class-crossing uniqueness)
- L1197: create_environment: id unique across whole history; recreating a deleted id rejected; creation requires scope=all actor, one predicate
- L1219: rotate_epoch order fixed by vectors; no 'initial value 1 if unobserved' fallback — a preceding create_environment is required
- L1234: Epoch is always +1 (owner ruling, option 3): rollback, duplicates and jumps (ceiling DoS) all rejected
- L1242: delete_environment check order fixed by vectors: role → unknown-environment → environment-deleted → out-of-scope
- L1262: checkpoint checks stage-wise across entries (ruling C); epoch strictly equals entry-time epoch; tuple content is reconciliation side (§6.4/§
- L1298: Checkpoint non-regression allows equality: post-rotation re-encryption legitimately re-notarizes same mv with new values_digest (§6.3)
- L1309: CONSENSUS_RULES shared by direct append, propose pre-check and approve re-check; does not mutate; exhaustive Record prevents a missed rule
- L1322: genesis consensus is unreachable as an inner op — never a policy target, fails earlier on approval-not-required
- L1356: INITIAL_EPOCH = 1, the value right after create_environment (§3/§6.2)
- L1363: Genesis key = first device, cap structurally (owner, all); FP already matched in resolveActorSigPub
- L1368: Genesis creator's scope is structurally all — genesis carries no scope in its payload (§6.2)
- L1372: Member set empty at genesis so duplication cannot arise; owner key still indexed as comparison target for later adds
- L1394: applyAddDevice: target = actor (§6.2)
- L1421: applyRevokeDevice removes listed devices from the target's set and the key index
- L1449: change_role replaces (role, scope) wholesale (§6.2)
- L1461: remove_member ends all of the target's devices at once (§6.2)
- L1474: Server key stays named after revoke_server (§6.2 key uniqueness)
- L1479: Re-grant replaces the establishing entry so grantSeq advances; origin of AUDIT_SPEC §3.5 grant_chain_seq, pinned by vector
- L1507: delete_environment: id never reusable, id pruned from every listed scope, latest-checkpoint baseline dropped (§6.2)
- L1581: required_approvals=0 means policy off; ops is a set, deduplicated for storage (§6.2)
- L1591: OPERATION_APPLIERS is an exhaustive Record so a missed apply fails the type; seq/actor attribution conventions (§6.3)
- L1605: genesis is unreachable as an inner op; direct append goes through applyGenesis which needs the actor
- L1636: Direct append check order: role rules, then approval-required (policy target cannot reach quorum), then consensus (§6.2)
- L1662: propose check order; a passing proposal is recorded in pending keyed by the proposal entry's entry_hash (§6.2)
- L1699: approve pipeline and quorum rule: votes = |S ∩ current owners| reaching required (principle 2, §6.2)
- L1725: Vote set semantics; if policy were somehow null, fall to the side that cannot reach quorum (fail-safe)
- L1740: approve pre-vote check order and live-vote definition: revoked-device and cross-tenure votes are not live (DK, §6.2)
- L1771: Apply-on-quorum re-checks proposer and inner op against state at apply time; failed approve leaves proposal pending (§6.2)
- L1799: The applied inner op's actor is attributed to the proposer, not the final approver
- L1809: Withdraw role rule: a non-owner must be the referenced proposal's proposer; unknown proposal fails role first (vector-fixed)
- L1823: evaluateEntry is verification stage 5; propose/withdraw/short-of-quorum approve yield null (no state transition)
- L1838: Actor existence and device were already confirmed by resolveActorSigPub, so no re-check here
- L1892: History recording uses the applying entry's own seq as boundary (inclusive convention, §6.3); some ops record nothing
- L1923: delete_environment is a history change point like change_role: pruned spans/caps get new intervals from its seq (§6.2)
- L1962: Pre-apply checks run in verification-stage order: framing, payload structure, actor resolution, signature
- L1973: Entry check does not throw even when a crafted array slot is null or a non-object (untrusted input)
- L2005: sealChainState mints map keys from verified entry slots only; deliberately does not re-check §12-1 id form (server write-time policy)
- L2079: entry_hash computed only after signature verification normalized the fields; needed pre-apply as the propose identifier (§6.2)
- L2097: verifyChain is fail-fast with seq+reason; entries are untrusted, every field re-validated at runtime regardless of types (§6.3)
- L2117: History index is built inside the verification loop so it can only exist for a fully verified chain (ruling A)

### `packages/crypto/src/internal.package/dek-commitment.ts`

- L1: §5.2 DEK commitment formula; coordinates in preimage prevent cross-context reuse/leak; only uniform 256-bit DEKs may be committed
- L30: Suite binding is carried by the domain string, so a commitment never transplants across suites (§5.2)
- L56: encodeHex is the only producer of dek_hex here, so an uppercase variant can never enter the preimage; builder assumes validated input
- L76: Commitment is the value published on chain by create_environment / rotate_epoch (§5.2/§6.2)
- L97: An unwrapped DEK must not be used in any crypto operation until it matches the commitment; mismatch = poisoned wrap (§5.2/§6.3)
- L108: Expected commitment accepts only the lowercase 64-char normalized form; uppercase would split the reconciliation judgment

### `packages/crypto/src/internal.package/dek-wrap-sign.ts`

- L1: §5.1 wrap registration signed-bytes formula; semantics are attribution, not freshness (no timestamp/nonce); signer id is an independent defense layer
- L32: Fields bound by a DEK-wrap registration signature: full wire form plus storage coordinates (§5.1)
- L42: For server-destined wraps the server-key fingerprint stands in the recipient_user_id position (§9)
- L51: signerUserId binds attribution to the identity (§5.1)
- L55: Hex fields are lowercase fixed-length only: uppercase would give one wrap multiple normalized forms and break signature uniqueness
- L83: Domain string embeds the suite so a signature never transplants across suites; builder assumes validated input (§5.1)
- L103: Wrap registration signature returned as lowercase hex, the wire form of WrappedDek.signatureHex (AUTH_SPEC §12-2)
- L119: Server verifies with the caller's chain-derived key at acceptance; clients verify with the key chain history binds to the signer (§5.1)

### `packages/crypto/src/internal.package/dek-wrap.ts`

- L1: §5 wrap info formula, aad empty (info carries context binding); Open is KeyPair-only because a bare private key would force extractable=true (§2, spike-c)
- L14: DekWrapContext cryptographically binds a wrapped DEK to its recipient (§5)
- L19: For server-destined wraps the server-key fingerprint stands in the recipient_user_id position (§9)
- L41: Epoch is Result-validated against the LP encoder precondition; a typed error is returned rather than accidental containment via try
- L48: DEK wrap HPKE info formula; opening under any other project/epoch/environment/recipient context fails (§5)
- L88: unwrapDek takes the full key pair so the private key can stay non-extractable (§2)

### `packages/crypto/src/internal.package/encoding.ts`

- L1: §2.1 LP encoding has a single shared implementation for AAD/info/chain normalization — a spec requirement
- L7: LP field conversion rules: strings UTF-8, numbers decimal string, byte arrays as-is (§2.1)
- L15: Single shared LP encoder removes concatenation ambiguity; precondition violations throw TypeError as programmer errors, not typed errors (§2.1)

### `packages/crypto/src/internal.package/errors.ts`

- L1: Error design: pure values, no Effect dependency (wrapping is core-side); discriminator is kind; errors never contain secrets or exception text
- L38: Duplicate environment_ids in a checkpoint belong to the payload structure check (invalid-payload), no dedicated reason code
- L44: Scope structure rule violations are invalid-payload; existence of each scope id reuses unknown-environment (§6.2 ES)
- L50: approve's owner check reuses insufficient-role; no dedicated reason code (PF1, §6.2)
- L59: DK reason-code allocation: uniqueness break is duplicate-member-key, revoked-device signature is actor-key-mismatch (§6.2)
- L67: Second deletion and later entries naming a deleted environment use environment-deleted; id reuse stays duplicate-environment (§6.2)
- L73: ValueInvalidReason vocabulary semantics fixed by value-signature.json rule negatives (§4.1/§6.3), incl. mismatch vs future head distinction
- L117: MetaInvalidReason vocabulary fixed by metadata-signature.json negatives (§4.2/§6.3); role floor is admin only for environment deletion
- L174: ManifestInvalidReason vocabulary (§4.3/§6.3); essential difference from meta codes is the epoch anchor / checkpoint binding
- L222: AttestationInvalidReason vocabulary (§6.6); mismatch with verified signature is hard fork evidence, other reasons are not reconciliation material
- L276: AeadOperation distinguishes variable (§4), recovery (§8 unchanged) and master-wrap (§8 ledger) contexts
- L311: DekWrapSignatureInvalid anchors to the §5.1 registration signature
- L313: InviteAcceptSignatureInvalid anchors to §6.5 acceptance co-signature
- L315: InviteLinkSignatureInvalid is the §6.5 link-key half of the co-signature
- L317: InviteIssueSignatureInvalid is the §6.5 inviter's issuance statement
- L319: DekCommitmentMismatch marks a poison wrap under §5.2
- L324: ValueInvalid covers §4.1/§6.3 write signature, declared head, head-time authorization/epoch and predecessor chaining
- L330: MetaStatementInvalid covers §4.2/§6.3 author signature, declared head, head-time authorization and predecessor chaining
- L336: UnsupportedMetaLayout: supported layouts are {1,3} (ruling CR, layout 2 retired); checked before signature verification so outdated clients get an honest error
- L344: EnvManifestInvalid covers §4.3/§6.3 issuer signature, head, authorization/epoch integrity, digest recomputation and chaining
- L351: HeadAttestationInvalid covers §6.6 attester signature, declared head (2-way §6.3-2 distinction) and head-time binding
- L360: CryptoResult returns errors as values, never thrown, so callers can wrap them into their own effect system

### `packages/crypto/src/internal.package/fingerprint-words.ts`

- L1: FP words always use the single English BIP39 list regardless of locale, and are never truncated (truncation would weaken second-preimage resistance) (§3)
- L18: Fingerprint display layout: 128-bit entropy + 4-bit checksum = 12 x 11-bit indexes (§3)
- L26: fingerprintToWords encoding definition (§3); applies to both user fingerprints (§3) and server key fingerprints (§9)
- L40: 132-bit stream layout: FP 128 bits followed by the upper 4 bits of byte 17 as checksum
- L54: Word-index range check is unreachable defense against a corrupted dictionary

### `packages/crypto/src/internal.package/head-attestation.ts`

- L1: §6.6 head attestation definition and semantics: attribution/context binding, not freshness or head authenticity; current-membership gate is outside this module
- L50: Head attestation binds hash and seq together — both are signed, so a mismatched pair never verifies (§6.6)
- L59: attesterUserId binds attribution, same shape as §5.1's signer_user_id
- L67: Hex is lowercase fixed-length only (uppercase would break signature uniqueness); chain_head_seq bounded by §2.1 plus 1-based seq
- L91: Domain string binds suite and project_id binds context, so an attestation never transplants; builder assumes validated input (§6.6)
- L108: Signed-bytes hash is the evidence digest a verifier records when an attestation contradicts its view (§6.6/§14.2-5)
- L123: Attestation signature returned as lowercase hex, the wire form of the submission's signatureHex (AUTH_SPEC §16-1)
- L139: verifyHeadAttestationSignature is the raw signature check only; head binding and membership are the history-based checks elsewhere (§6.6)
- L166: Coordinate integrity (§6.3-5) of the expected context is the caller's responsibility
- L183: Reason mapping folds roleInsufficientAtHead into membership mismatch: the reader floor means it can never fire structurally (§6.6)
- L197: Distributed attestation verification contract: chain-head-mismatch is hard evidence (branch a), future is bounded resync (branch b), others are not reconciliation material (§6.6)
- L232: Key selection covers all tenures first so a broken signature is ruled out before the head-time binding check

### `packages/crypto/src/internal.package/hpke.ts`

- L1: hpke.ts is the single construction point of the §2 suite (X25519/HKDF-SHA256/AES-256-GCM, Base single-shot); panva hpke exact pin per spike-c

### `packages/crypto/src/internal.package/invite-accept-sign.ts`

- L1: §6.5 v2 acceptance co-signature: signed bytes are self-binding (verification keys inside the signed data); link seed never reaches the server
- L47: Declared keys are the verification keys: accept signature under inviteeSigPubHex, link signature under linkPubHex (§6.5)
- L58: linkPubHex is the link public key only — never the seed (§6.5)
- L60: The server requires caller == invitee for the acceptance (§6.5)
- L66: Hex fields lowercase fixed-length (normalized-form uniqueness); project_id is format-agnostic like AUTH_SPEC §11-1
- L91: Domain string embeds the suite, so a signature never transplants across suites or from the retired v1 form (§6.5)
- L109: Acceptance signature verifies only under the declared inviteeSigPubHex; returns the wire form acceptSignatureHex (AUTH_SPEC §15-2)
- L127: Link co-signature is the 'holder of the link approves this key' half (§6.5); returns wire form linkSignatureHex
- L155: decodeHex null branch is unreachable defensive code since contextInvalidField already guarantees the hex form
- L172: Verification key is imported from the declared inviteeSigPubHex, so a swapped signing key can never validate (§6.5)
- L193: Link co-signature check against the issued link key makes a server-side key swap cryptographically impossible (§6.5)

### `packages/crypto/src/internal.package/invite-link.ts`

- L1: §6.5 link key derivation via RFC 8410 PKCS#8 prefix + seed (WebCrypto has no seed-only import); issuance statement is self-binding; ES scope fields appended 2026-09-14
- L59: PKCS#8 prefix is spelled out as bytes so a typo cannot silently degrade to an empty prefix
- L85: The link seed lives only in the link fragment; the server never receives it (§6.5)
- L105: Derived link private key is non-extractable; seed-to-public-key form pinned by the invite-link.json vector (§6.5)
- L121: Extractable probe import is used only to read the public key x; the JWK's d is discarded and the returned private key is non-extractable
- L154: Issue context binds the inviter's verified chain head (§6.3 (a) anchor) and the granted (role, scope) as trailing §6.2 fields (ES) (§6.5)
- L184: Role is the §6.2 closed set — only the canonical form is signed, so a misspelling cannot become a different valid signature
- L192: Scope follows §6.2 structure rules, symmetric with the chain side's add_member
- L201: Environment id bound is the §6.1 free-string bound (1024 bytes), the same rule as chain-verify's isBoundedId
- L236: Builder assumes the context was validated first (sign/verify do) (§6.5)
- L258: Issue signature returns lowercase hex, the sig= link parameter and issueSignatureHex wire forms (AUTH_SPEC §15-2/§15-3)
- L275: Inviter fields must be filled from the inviter's own key or the verified chain — never from the server row — or the check proves nothing (§6.5)
- L321: Base64 shape is checked strictly first because atob is lenient (whitespace, missing padding)
- L338: OpenSSH line form is the one GitHub accepts as an SSH signing key (§6.5)
- L351: OpenSSH parse accepts only ssh-ed25519 with exact blob shape; third-party data (GitHub response) is never guessed at
- L359: Runtime type mismatch in third-party JSON yields InvalidInput, not an exception (same discipline as decodeHex)
- L369: Oversized input is rejected by length before decoding — never decode a huge string wholesale

### `packages/crypto/src/internal.package/keys.ts`

- L1: §3 key hierarchy: enc via panva hpke API for Open-path consistency, sig via WebCrypto Ed25519; private keys non-extractable by default
- L18: HPKE Open requires the full key pair (§2)
- L33: Encryption private key is non-extractable unless extractable is set — true only when the key must be serialized (e.g. recovery blob)
- L45: Server key (§9) is DeriveKeyPair from a 32-byte ikm in the Workers Secret, re-derived at startup so one secret yields both keys (RFC 9180)
- L99: Importing the full pair keeps the non-extractable path usable because HPKE Open takes the full pair (§2)
- L128: Private key export is only for persisting a freshly generated master key into the OS keychain (§3); in-use keys stay non-extractable and fail
- L191: Ed25519 seed is read from the JWK d field because WebCrypto has no raw private-key export; keychain persistence only (§3)
- L211: Ed25519 key pair import goes through the JWK (OKP) form because WebCrypto has no raw private-key import
- L251: User fingerprint = first 16 bytes of SHA-256(enc||sig); plain concatenation because both keys are fixed-length, LP not applicable (§3)
- L274: Server fingerprint hashes the enc key alone because the server holds no signing key (§9); pinned by chain-entries.json

### `packages/crypto/src/internal.package/lease-wrap.ts`

- L1: §9.1 lease wrap reuses the §5 primitive; only the binding target (claims digest) and domain string differ; lease wraps are never persisted; same-context token replay is an explicit non-guarantee
- L49: Lease claims are the verified OIDC claims; neither side transmits the digest — both compute it independently (§9.1)
- L77: buildLeaseClaimsBytes is exposed so the LP field order is fixed by the test vector; (ab,c) vs (a,bc) must not collide (§9.1)
- L92: Empty claim fields are rejected: an empty value would let distinct workload contexts collide into one digest (§9.1)
- L111: Epoch form is checked here only; the epoch boundary itself is held by the caller (chain-derived state), as in dek-wrap
- L118: Claims digest form check excludes passing raw claims and uppercase-hex divergence producing 'same digest, different info'
- L127: Lease wrap HPKE info formula; opening under any other context or a §5 persistent-wrap info fails (§9.1)
- L144: Lease wrap result is response-scoped and must never be persisted into the DEK wrap store (§9.1 / AUTH_SPEC §12-6)
- L173: Unwrap takes the full pair so the key stays non-extractable (§2); the DEK must still be matched against the §5.2 commitment before use

### `packages/crypto/src/internal.package/manifest-sign.ts`

- L1: §4.3 manifest signed-bytes and variables-digest definitions: entries in byte-ascending variable_id order, tombstones included, empty set valid
- L44: Layout v3 leaves the digest encoder unchanged: declared appears only as a new status string value (§4.3)
- L76: Variables digest applies canonical byte-ascending order internally and rejects duplicate ids; skeleton shared with §6.2 values_digest
- L103: Manifest context binds the epoch burned in at issuance — the freshness anchor of the metadata layer (§4.3)
- L113: epoch is the environment's current epoch at issuance — the core anchor (§4.3)
- L115: manifestVersion is a 1-based counter: creation = 1, each meta op / rotate increments
- L122: prevManifestSigHashHex is the empty string for manifestVersion 1 (the §4.3 chaining convention, same as §4.1/§4.2)
- L127: issuerUserId binds attribution to the identity (§4.3)
- L131: Both head hash and seq are signed; a mismatched pair fails (§4.3)
- L151: Binary fields are lowercase hex only: uppercase would give one value multiple normalized forms and break signature uniqueness (§4.3)
- L173: Suite, coordinates and issuer must be non-empty — the same check level as meta-sign.ts; no legitimate call signs empty coordinates
- L197: Domain string embeds the suite so a manifest signature never transplants across suites; builder assumes validated input (§4.3)
- L221: Signed-bytes hash is the next manifest's prev anchor and same-version fork evidence (§4.3 chaining / §14.2-5)
- L237: Signing enforces the manifestVersion-prev coupling because producing a rule-violating manifest is a caller bug; verification instead rejects with a typed reason (§4.3)
- L273: verifyEnvManifestSignature is the raw signature check only; composite checks live in verifyDistributedEnvManifest (§4.3)

### `packages/crypto/src/internal.package/manifest-verify.ts`

- L1: Manifest verification is isomorphic to value/meta verification — the canonical implementation lives exactly once in packages/crypto (§4.3/§6.3/§6.4)
- L92: The predecessor anchor must itself be verified by the caller; chaining onto unverified data would poison the evidence chain (§4.3)
- L119: entries must be the verified statement set — every variable's latest statement including tombstones (§4.3 (3))
- L126: predecessor is the verified previous manifest, the ruling-B isomorph (§4.3)
- L137: Head binding / authorization reason mapping delegates to the shared headAuthorizationReason in validate.ts (§6.3-1 to -3)
- L148: Epoch integrity reconciles both epoch and manifest_sig_hash (hash alone misses a false notarization); env-existence check is skipped when a tuple exists (§4.3 (2))
- L174: Strict epoch equality at the declared head: deletion and demotion both carry an all-environment rotation (§7), so a demoted key cannot sign at the current epoch
- L185: Checkpoint integrity rule 1: manifestVersion/epoch must not regress below the latest checkpoint baseline; baseline-less environments are out of scope (§6.3)
- L213: Environment-meta integrity: the bound statement's coordinates must match the verified latest form (AUTH_SPEC §12-5 (7))
- L222: Digest is recomputed from the verified statement set; a mismatch means omission, injection or ordering violation (§4.3 (3))
- L227: A structure violation in verified entries is a caller bug, folded into variables-digest-mismatch (contains no secrets)
- L237: Prev shape is always checked even under latest-only verification: v1 = empty, >1 = 64 hex (§4.3)
- L247: Chaining integrity: a prev mismatch must not collapse into an Ed25519 failure (same ruling as value-verify) (§4.3)
- L261: Server passes the caller's acceptance-time identity so head-time key binding must equal acceptance-time key (§12-5 (1)); returns the signed-bytes hash anchor
- L327: Prev chaining (§4.3 (1)) precedes epoch integrity (2) — the vectors pin that shape checks land before the binding judgment
- L334: The manifest's own signed-bytes hash is computed early because it is the reconciliation target of checkpoint binding (2)

### `packages/crypto/src/internal.package/master-wrap.ts`

- L1: §8 wrap ledger recipient classes S/G/H definitions; device handoff approval removed by DK (approvers are guardians only); recovery-code path unchanged
- L57: Handoff code length derivation: 36 bytes = 288 bits = 58 Base32 symbols, last symbol carries 2 zero padding bits
- L61: MAX_SHARES is the AUTH_SPEC §13-8 receipt policy ceiling, enforced here as an input bound
- L64: The device wrap kind was removed by the DK revision: everyday devices never hold blob B, so approvers are guardians only; AAD layout unchanged (§8)
- L72: Guardian mode semantics: any = 1-of-n, all = n-of-n (§8.3)
- L75: mode is required for guardian wraps and must be absent otherwise (encoded as the empty string) in the master-wrap AAD (§8.1)
- L98: Handoff source is the guardian group_id; the old-device 'device' source was removed by DK (§8.4)
- L130: Binding mode in the AAD (and again in the share info) makes a server-side any/all relabel fail closed at decryption (§8.1)
- L145: HKDF salt is empty because the PRF output is already uniformly random (RFC 5869 §3.1); domain separation is carried by info (§8.2)
- L221: unwrapMasterBlob contract: any mismatch (wrong KEK, other user's ledger, relabelled kind/ref/mode, tampering) yields DecryptFailed (§8.1)
- L266: XOR split construction: shares 1..n-1 random, share n = KEK XOR the rest, so any n-1 shares are independent of the KEK (§8.3)
- L307: joinGuardianShares: any takes exactly one share, all takes every share so a missing share is rejected here, not as an opaque decrypt failure (§8.3)
- L358: Guardian share HPKE info formula (§8.3)
- L398: An opened guardian share must be re-sealed to the requester's ephemeral key at once and never persisted (§8.4)
- L438: Handoff approval HPKE info formula (§8.4)
- L507: Handoff request id formula; requester and approver derive it independently from the hand-carried code (§8.4)
- L541: Handoff code is Base32 of E_pub plus 4-byte checksum in groups of 4; the code is public information, not key material (§8.4)
- L567: Handoff code decoding is strict (length, alphabet, padding bits, checksum) so a one-symbol transcription error is never read as a different key (§8.4)

### `packages/crypto/src/internal.package/member-scope.ts`

- L1: §6.2 ES scope: wire representation, structure rules, and fail-closed set algebra (all = U incl. future environments; cofinite differences are uncontainable)
- L27: Every scope-carrying payload ends with the two scope wire fields in the §6.2 normalization field order
- L34: MemberScope semantics: all includes environments created later; empty listed is valid and receives no DEK at all (§6.2)
- L43: EnvironmentSet algebra: all stands for U or any cofinite subset, which no listed scope can contain (principle 1, §6.2)
- L55: Listed scope upper bound is 256, the same as grant_server's scope_environments (§6.1)
- L77: scopeShapeOk is the §6.2 structure rule (payload-structure stage); runtime-typed so hostile chain JSON yields invalid-payload instead of throwing
- L108: scopeWithout is the one pruning rule shared by the verification state and the history index; listed stays listed, all unchanged (§6.2)
- L130: Union semantics: all absorbs everything (§6.2 set algebra)
- L138: Symmetric difference: all △ listed{X} = U \ X is cofinite, reported as all (fail-closed; Bugbot finding, §6.2)
- L167: Principle 1 containment: listed{X} contains only finite listed{Y} with Y ⊆ X, never all (which may include uncreated environments) (§6.2)

### `packages/crypto/src/internal.package/meta-sign.ts`

- L1: §4.2 var/env meta signed-bytes formulas; layout v3 adds schema fields (rulings CR/CS, PF6 R9); layout 2 retired in 0.15-draft and refused
- L57: declared status exists only in variable layout v3 (ruling CS: v1 unchanged) (§4.2)
- L64: MetaVarType is a closed set, '' = unspecified, no validation DSL/defaults (ruling CT); the declaration is advisory (§14.3-7)
- L74: Schema fields are bound byte-exactly; required is mandatory-explicit so no client default can diverge; verifiers never normalize description (§4.2)
- L86: max_age_days is a signed decimal string 1..3650 or '' (PF6 R9); mandatory fail-closed; advisory like the type (§14.3-7)
- L97: Max declarable max age is 3650 days (ten years); a longer interval counts as no interval
- L100: Signed form of max_age_days has no leading zeros: one value = one byte string (signature uniqueness)
- L110: Supported meta layouts are {1, 3}; layout 2 is retired (0.15-draft) and refused like v4+ (§4.2)
- L117: layoutVersion is a carrier field outside the signed bytes; omission means layout 1 (§4.2 / AUTH_SPEC §12-2)
- L128: Variable and environment statements use distinct domain strings, so signatures never transplant across kinds (§4.2)
- L137: Statement context binds the name byte-exactly as UTF-8; hashes are lowercase hex (§4.2)
- L149: layoutVersion selects which layout's signed bytes are computed; layout 3 is variable-only and requires schema (§4.2)
- L158: metaVersion is a 1-based counter: creation = 1, each rename/delete increments
- L160: prevMetaSigHashHex is the empty string for metaVersion 1 (the §4.2 chaining convention, same as §4.1)
- L165: authorUserId binds attribution to the identity (§4.2)
- L169: Both head hash and seq are signed; a mismatched pair fails (§4.2)
- L183: Binary values are lowercase hex only: uppercase would give one value multiple normalized forms and break signature uniqueness
- L199: Non-empty coordinate checks are defensive consistency (LP makes empty unambiguous); the check level is kept uniform across fields
- L217: MetaLayout is produced only by selectMetaLayout, so encoder and validator share one selection and never substitute layouts (§4.2)
- L232: Layout selection (ruling CR): unsupported layout yields typed UnsupportedMetaLayout; the context must carry exactly that layout's field set (§4.2)
- L257: Fail-closed if SUPPORTED_META_LAYOUT_VERSIONS ever grows ahead of the encoder
- L283: Layout-1 status rules: declared is v3-only (ruling CS); environment statements are active-only because deletion is the chain op delete_environment (§6.2)
- L296: Layout-3 structure checks are fail-closed: closed var_type set, mandatory required/max_age_days, pinned by vectors (§4.2)
- L312: A wire-derived context may lack maxAgeDays despite the type — checked fail-closed (v3-missing-max-age vector)
- L322: The metaVersion-prev coupling is deliberately not checked at structure stage: verify must first verify rule-violating statements' signatures (sign/verify asymmetry)
- L364: Check order fixed by §4.2 ruling CR: layout selection before field validation and before signature verification, so unsupported layouts surface as 'client update required'
- L379: The layout switch is exhaustive so no layout falls through to another layout's encoding (§4.2)
- L385: Schema fields are encoded under the layout's own domain string (v3 never verifies under v1 — §1 principle 6); encoding is total over field values
- L434: buildMetaSignedBytes is fail-closed on layout and never substitutes another layout's bytes; field values unvalidated here so negative vectors can be reproduced (§4.2)
- L457: Signed-bytes hash is the next statement's prev anchor and same-coordinate fork evidence (§4.2 chaining / §14.2-5)
- L476: Signing enforces the metaVersion-prev coupling and creation-never-deleted; producing a rule-violating statement is a caller bug, unlike verification (§4.2)
- L517: verifyMetaStatementSignature is the raw signature check only; composite checks live in verifyDistributedMetaStatement (§4.2)

### `packages/crypto/src/internal.package/meta-verify.ts`

- L1: Meta verification design (§6.3/§6.4): items 1-3 and 6, role levels per §4.2/§12-3, environment deletion is a chain op; coordinate integrity is the caller's duty
- L63: The predecessor anchor must itself be verified by the caller; chaining onto unverified data would poison the evidence chain (§6.3-6)
- L73: MetaPredecessor.layoutVersion is required, not optional-with-default: an omitted-means-1 default would make the layout monotonicity check fail-open (§4.2)
- L97: predecessor is the verified previous statement, the ruling-B isomorph (§6.3)
- L108: Required role for statements is member; environment deletion is the admin chain op delete_environment, not a statement (§4.2/§6.2)
- L115: Head binding / authorization reason mapping delegates to the shared headAuthorizationReason in validate.ts (§6.3-1 to -3)
- L128: Meta has no epoch integrity (§6.3-4), so the shared head check is the whole authorization check as-is
- L139: Scope check (§6.3 3′): all meta statements are environment-targeting; a creation-compound statement holds vacuously since the creator's scope is all
- L150: Layer boundary: delete-statement schema/name preservation is an acceptance check (AUTH_SPEC §12-5), mandatory there; the crypto layer intentionally does not check it
- L169: Prev shape is always checked even under latest-only: metaVersion 1 = empty, >1 = 64 hex
- L179: A prev mismatch must not collapse into an Ed25519 failure (same ruling as value-verify) (§6.3-6)
- L185: A tombstone is terminal: any successor of a deleted statement is rejected regardless of status, including declared (§4.2)
- L193: active → declared is forbidden (no rewinding representation of a value's existence); declared → declared is legitimate (§4.2)
- L200: Per-variable layout monotonicity: a v1 successor of a v3 predecessor is rejected, else one rename could silently erase the schema fields (§4.2)
- L213: Server passes the caller's acceptance-time identity so head-time key binding must equal acceptance-time key (§12-5); returns the signed-bytes hash anchor (§6.3/§6.4)
- L227: Layout rejection via metaContextRejection happens before signature verification (ruling CR)

### `packages/crypto/src/internal.package/recipient-set.ts`

- L1: R(E)/W(E) definitions (§6.2/§5.3): wrap addresses are unique (key uniqueness), a member id colliding with a grant FP yields two addresses (README convention 33)
- L40: R(E) is a set of (person, device) pairs (§6.2)
- L47: WrapRecipient classes: a member's device or a valid grant's server key (AUTH_SPEC §12-6 recipient class)
- L55: Both recipient lists use UTF-16 code-unit order — the one fixed order (§6.2)
- L60: R(E)'s member-side predicate uses the effective scope; effectivePermissionOf is the only place that computes it (§6.2)
- L73: Member devices are enumerated in fixed order: members by user id, each member's devices by key fingerprint
- L84: R(E) is the recipient set of environment E's complete DEK-wrap set (§6.2)
- L103: W(E) is R(E)'s member devices whose effective role is member or above (§5.3)

### `packages/crypto/src/internal.package/recovery.ts`

- L1: §8 recovery wrap formula; HKDF salt empty because the secret is uniformly random 256-bit (RFC 5869 §3.1); a passphrase-derived key requires a spec revision; blob is opaque
- L56: The blob's serialization format is out of scope here, decided with the CLI implementation (§8)
- L85: Unexpected WebCrypto failures are returned as values, symmetric with unwrap
- L90: unwrapMasterSecret contract: any mismatch (wrong secret, another user's blob, tampering) yields DecryptFailed (§8)

### `packages/crypto/src/internal.package/sealed-value.ts`

- L1: §5.3 sealed values reuse the §5 primitive; three differences (value plaintext, proposal-bound info, domain string); no §5.1 signature — attribution is the lease's claims digest
- L40: Proposal id form: 16 random bytes as lowercase hex, client-chosen (§5.3)
- L44: Max sealed plaintext is the §4 value cap: 64 KiB of ciphertext minus the 16-byte tag
- L53: baseVersion is the version the proposal replaces; the accepting client pushes base_version + 1 on exactly this version (§5.3)
- L74: Proposal id form is checked structurally: an uppercase or differently sized id would diverge the info between minting and accepting clients
- L80: Base version form is checked here (starts at 1, §4.1); the boundary itself is the caller's
- L97: Sealed value HPKE info formula; opening under any other context or a §5/§9.1 info fails (§5.3)
- L117: The plaintext never leaves the minting process in the clear; the sealed result is what the server stores (§5.3)
- L142: Seal failure reuses DekWrapFailed so the error vocabulary stays closed — no caller distinguishes it from a §5 wrap failure
- L149: Open takes the full pair so the key stays non-extractable (§2); the accepting client must verify the proposal targets a verified active statement (§5.3)
- L174: Open failure reuses DekUnwrapFailed, the same failure class as a §5 unwrap, for the same closed-vocabulary reason

### `packages/crypto/src/internal.package/sorted-digest.ts`

- L1: The digest skeleton lives in one shared implementation (CLAUDE.md 'one implementation only'); callers supply only field sequence and validation (§4.3/§6.2)
- L17: Canonical order is UTF-8 byte comparison — locale- and case-independent
- L31: Sorting happens inside the digest function so callers cannot produce a non-canonical digest; duplicate ids are a caller bug; empty set valid
- L47: The entry's canonical LP field order is fixed by the test vectors

### `packages/crypto/src/internal.package/suite.ts`

- L1: Every persistent structure, AAD and info carries the suite identifier for crypto agility (§2)

### `packages/crypto/src/internal.package/validate.ts`

- L1: validate.ts holds shared check logic only; per-spec error vocabularies are intentionally not unified, and only lowercase hex is a normalized form
- L17: ROLE_RANK is defined only in chain-device.ts and re-exported here for the signature modules
- L30: invalidInput carries the field name only — never secrets or input fragments
- L43: Shared sign core performs only signing + hex encoding; WebCrypto exception messages are never propagated (errors.ts absolute rule)
- L64: Shared verify core returns the caller-injected onInvalid as-is; WebCrypto exception messages are never propagated (errors.ts absolute rule)
- L95: The distributed-verification prologue is shared; only the actor-FP field name differs per caller and is injected
- L123: Key selection covers all tenure and the head binding is checked after signature verification, so a broken signature is ruled out first (§6.3-1)
- L147: Unreachable defensive line: a key derived from a verified chain is always normalized hex
- L154: The head-authorization reason vocabulary is owned by the caller and not unified in validate.ts (§6.3-1 to -3)
- L167: §6.3 3′ scope check applies only to environment-targeting signatures — do not pass it for head attestations
- L179: headAuthorizationReason: future vs mismatch head distinction, tenure-crossing and revoked-device rejection, and the signing device's effective permission as the single substitution point (K2-4)

### `packages/crypto/src/internal.package/value-sign.ts`

- L1: §4.1 value signed-bytes formula; semantics are attribution/content authenticity/authorization-time binding — not plaintext correctness, freshness, or name authenticity (§4.2 owns names)
- L31: Ciphertext hex lower bound comes from the AES-256-GCM 16-byte tag (wire shape of AUTH_SPEC §12-2)
- L34: Value signature context binds the full wire form of one version plus its authorization anchor (§4.1)
- L48: prevValueSigHashHex is the empty string for version 1 (the §4.1 chaining convention)
- L53: writerUserId binds attribution to the identity (§4.1)
- L57: Both head hash and seq are signed; a mismatched pair fails (§4.1)
- L75: Binary values are lowercase hex only: uppercase would give one value multiple normalized forms and break signature uniqueness
- L101: The version-prev coupling is deliberately not checked at structure stage: verify must first verify rule-violating values' signatures (rule negatives)
- L111: Non-empty coordinate checks are defensive consistency (LP makes empty unambiguous); the check level is kept uniform across fields
- L121: variableId is required non-empty at the same level as other coordinates; the API schema already rejects empties on the wire
- L139: Domain string embeds the suite so a signature never transplants across suites; builder assumes validated input (§4.1)
- L163: Signed-bytes hash is the next version's prev anchor and same-coordinate fork evidence (§4.1 chaining / §14.2-5)
- L179: Signing enforces the version-prev coupling: producing a rule-violating signature is a caller bug, unlike verification (§4.1)
- L214: verifyValueSignature is the raw signature check only; composite checks live in verifyDistributedValue (§4.1)

### `packages/crypto/src/internal.package/value-verify.ts`

- L1: Value verification design (§6.3/§6.4): items 1-4 and 6, coordinate integrity is the caller's duty, latest-only limits per ruling B
- L49: The predecessor anchor must itself be verified by the caller; chaining onto unverified data would poison the evidence chain (§6.3-6)
- L70: predecessor is the verified previous version (ruling B) (§6.3)
- L81: Head binding / authorization reason mapping delegates to the shared headAuthorizationReason in validate.ts (§6.3-1 to -3)
- L111: Epoch integrity (§6.3-4): a pre-environment-creation head is rejected with no default fallback
- L125: Prev shape is always checked even under latest-only (ruling B): version 1 = empty, >1 = 64 hex
- L135: Chaining integrity: a prev mismatch must not collapse into an Ed25519 failure (rulings B/C) (§6.3-6)
- L147: Server passes the caller's acceptance-time identity so head-time key binding must equal acceptance-time key (§12-5); returns the signed-bytes hash anchor (§6.3/§6.4)

### `packages/crypto/src/internal.package/values-digest.ts`

- L1: §6.2 values_digest definition: active variables only (tombstones on the manifest side, declared has no value coordinates); empty set valid
- L30: A values-digest entry is one active variable's latest version plus the SHA-256 of its value_signed_bytes (§6.2/§4.1)
- L54: The source type makes value coordinates unrepresentable for declared/deleted variables (§6.2 target selection)
- L68: Target selection is the only status-aware step; the digest encoder itself is unchanged by layout v3 (§6.2)
- L91: Values digest applies canonical byte-ascending order internally, rejects duplicate ids, and the empty set is valid (§6.2)

### `packages/crypto/src/internal.package/variable.ts`

- L1: §4 variable AAD formula; the nonce is 96-bit random and reuse is never allowed
- L33: Numeric fields are Result-validated against the LP precondition because skipping it would make buildVariableAad throw, breaking the errors-as-values contract
- L46: Variable AAD formula; reuse of a ciphertext outside this context fails decryption (§4)
- L66: The nonce is freshly random per call and never caller-supplied: nonce reuse must stay impossible by construction (§4)
- L99: Unexpected WebCrypto failures are returned as values, symmetric with decrypt
- L104: decryptVariable contract: any context/nonce/ciphertext mismatch yields DecryptFailed — no further detail, by design (§4)

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
