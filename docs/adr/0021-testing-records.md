# ADR-0021: Test-suite decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 3591 comments on the test suites were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/test/agent.test.ts`

- L1: Test-scope contract for maruhi agent: protocol rejection, socket perms 0700/0600, child env/exit inheritance, restore wiring
- L55: win32 skipped because unix sockets differ there (named pipes) and the implementation already errors explicitly on win32
- L102: Property pinned: protocol version mismatches are rejected, not silently parsed
- L105: Case set pinned: malformed requests (missing value, empty name, unknown op, non-JSON, array) are all rejected
- L111: Protocol fact pinned: list takes no name (it serves status)
- L182: Property pinned: re-setting a key carries a fresh TTL deadline
- L188: Scenario: at deadline the key expires but the token remains, including in status's list
- L194: Property pinned: without a TTL no deadline is attached
- L216: Property pinned: other store entries are independent of the removed one
- L247: Property pinned: server responds once a full line arrives even if split across chunks
- L283: Hostile/broken-client shape: a peer that stays silent without sending a line
- L288: server.close only ends when connections end naturally, so the test verifies close itself cuts idle connections before the 5s timeout
- L309: ScriptedAgent is a trusted socket (0600 in a 0700 dir) whose answers the test scripts
- L319: scriptedAgent listens with chmod 0600 specifically so the client's assertTrustedSocket passes
- L354: The error swallow is deliberate: tests provoke EPIPE/ECONNRESET server-side; the outcome under test is asserted from the client side
- L423: acrossTheTimeout technique: hold the connection just before the 5s limit on TestClock, then cross it, to pin timeout behavior
- L437: The real-I/O turn exists so a premature disconnect would be observable before asserting the connection is held
- L457: Property pinned: interruption cleanup destroys the client socket, seen from the agent side
- L461: Case split: the same timeout through the Keychain implementation surfaces the protocol message to the user
- L505: Shape chosen so only the size cap can end the conversation: one byte over MAX_MESSAGE_BYTES, no newline, connection kept open
- L527: Scenario: socket inode moved aside before close leaves a listener-less 0600 socket behind
- L551: Connects as the child would; in production the child's maruhi picks this path in live.ts
- L565: Property pinned: after child exit the socket and directory are gone and the memory record is unreachable
- L573: Property pinned: guidance goes to stderr only and no key material is printed
- L577: Property pinned: the agent reaches the child only via the env var when no parent agent is present
- L607: Deadlock shape pinned: parent agent died leaving only the shell; start-new vs refuse-nesting must not deadlock
- L627: Scenario: a plain file swapped in as the socket destination is refused
- L632: Security property: even a real socket is refused if other users can touch it
- L638: Property pinned: restoring 0600 makes the socket pass (the shape one's own agent creates)
- L649: Property pinned: a positional argument before -- is diagnosed the same as run (usage error)
- L666: K7-4 path forward pinned: a vanished device key is re-registered as a new device and the forgotten key revoked, not recovered
- L701: Regression shape: an origin containing :: (IPv6 loopback) must not break the key delimiter
- L733: Scenario: complete record shape with broken hex takes the corruption side's guidance
- L753: Because exit is irreversible, the message pins ordering (re-enter without exiting) and condition (exit only while the code exists)
- L761: Property pinned: the OS-keychain procedure is not printed in agent mode because it cannot be run there
- L793: Section anchors the restore-path wiring tests to supplement 12: fetch, decrypt, into L2 memory
- L806: wrappedBlobHandler serves the same blob shape as recovery.test.ts so the agent-side restore case reproduces it
- L834: DK / §8.1: reserve key B only issues the device key and is stored nowhere; the stored device key's destination (agent memory) is pinned
- L842: Fixture note: the project list the restore tail scans (AUTH_SPEC §11-5) is empty here
- L851: Setup mirrors production: maruhi login writes the logged-in state via the same agent path
- L867: Scenario: with no projects, no reserve-key confirmation appears (DK K14-2's nowhere case)
- L870: Mirrors live.ts's swap on MARUHI_AGENT_SOCK: only Keychain is redirected to the agent implementation
- L875: Property pinned: the recovered key lands in agent memory; the OS-equivalent test keychain stays empty
- L883: Property pinned: what is stored is the new device key; the ledger's reserve key B is stored nowhere
- L902: Scenario: later commands in the same session read the agent's key (key show)

### `apps/cli/test/approval-propose.test.ts`

- L1: Test-scope contract for auto-proposal (CRYPTO_SPEC §6.2, PF1 K6): propose-instead-of-append, idempotency, ceremony, self-remove, expiry
- L110: Fixture composition: 2 owners, 1 member, 1 environment, policy over given ops with required 2
- L155: The 48h lifetime assertion allows tolerance because expiry is signing time + 48h
- L166: Idempotency pinned: re-running with a pending proposal for the same inner op adds no new proposal
- L208: Scenario rationale: with 3 owners, required 2 is reachable even without owner2, so the propose-time quorum check passes
- L219: K6-N pinned: self-remove is not refused at propose time because the fulfiller is the approver
- L224: K6-N' pinned: a self-removing proposal shows the consequence once applied instead of refusing
- L248: Property pinned: an untargeted op keeps the direct append; owner establishment is always targeted
- L311: Scenario: a run skipping the ceremony (no flag, non-interactive) stops before proposing
- L360: Concurrency shape: the policy was activated concurrently with the submission, making the op targeted

### `apps/cli/test/approval-rules.test.ts`

- L1: Scope contract: CLI delegates target/tally to crypto's public API (K6-G), pinned by a differential test vs verifyChain
- L65: verifiedOf uses the same path as chain-sync.ts so the test exercises the production verified view
- L77: Fixture composition: prefix of 4 owners + 1 member + policy (remove_member / required)
- L112: Policy monotonicity (a) pinned: an owner-establishing change_role is always targeted regardless of the policy listing
- L142: Setup rationale: after demoting owner2 the required owners stay reachable via owner/owner3/owner4
- L149: Property pinned: a demoted owner's recorded vote remains but the recount counts only current owners
- L159: State pinned: at 2 votes the CLI reports needed=0, meaning it completes on the next approve
- L173: Property pinned: an already-voted owner and a demoted owner cannot approve
- L184: Property pinned: owner4's approve completes the proposal in verifyChain (pending gone, member removed)
- L195: K6-C pinned: the applied-operations list carries the inner op at the approve's seq
- L216: Scenario: changing the policy itself is four-eyes with required 3 (propose plus 3 owner signatures)
- L261: Setup: policy changed to change_role only via propose + owner2's approve
- L302: K6-F' pinned: a proposal entry can also be referenced by its #<seq>
- L313: Property pinned: ids of completed/withdrawn proposals are reported as not pending

### `apps/cli/test/approval.test.ts`

- L1: Scope contract for approval commands (§6.2/§7, K6): list/show recount, approve pre-flight/resync, withdraw note rule, policy activation
- L93: Fixture composition: 2 owners (optional third), 1 member, policy (remove_member, required 2), plus owner's proposal
- L167: Property pinned: the proposer sees a duplicate-approval preview because self-approval counts as a duplicate
- L203: §7 pinned: on removal the new epoch is wrapped to every current member except the removal target (reason = member-removed)
- L224: Scenario: owner2 completes the raise to required 3 under the current required-2 policy; later remove proposals need 3 votes
- L326: Concurrency shape: an unrelated concurrent append (add_member is not a policy target here)
- L437: Concurrency shape: an unrelated concurrent append (add_member is not a policy target here)
- L550: Property pinned: re-specifying the same policy setting is a no-op
- L570: Concurrency shape: the same policy change was applied via proposal + approval concurrently with the submission

### `apps/cli/test/attestation.test.ts`

- L1: Test-scope contract for head gossip (CRYPTO_SPEC §6.3/§6.6): two-way split at own head, floor-evidence format, submission only on advance
- L62: verifiedViewOf builds the view directly because the check is pure and network-independent
- L79: attestationBy signs and builds a §6.6 attestation wire with the attester's key
- L131: Standard fixture chain: genesis, add_member(member), remove_member (3 entries)
- L146: Security rationale: a forged signature is not checking material, which also keeps out a warning-triggering DoS
- L152: Property pinned: an attester outside the history is not checking material
- L166: §6.6 nuance pinned: an in-tenure attestation passes shape verification but a non-current member's attestation is not checking material
- L181: Scenario shape: a current member attesting to a different head at the same seq is the split-view cross-distribution shape
- L196: Property pinned: evidence (attestation + own view's chain digest) lands in the append-only floor file
- L228: Scenario: own view is stale at seq 2; resync returns all 3 entries plus the same attestation set
- L246: Scenario: attestation to seq 5 beyond own head (3) stays unreachable even after resync
- L265: Dedup rationale: the same attestation in both sets must yield one evidence record, else it reads as two members contradicting each other
- L276: Scenario label: the genuine seq-5 attestation is the shape that stays unresolved after resync (vs the forged twin below)
- L283: Attack shape pinned: partial-key dedup must not drop the genuine record on a key clash with a forged twin, or no interruption would occur
- L302: Property pinned: the genuine attestation remains as unresolved-after-resync evidence; the forged record never becomes checking material
- L344: Floor invariant: a checked view's head is still recorded; floor advance happens after checks pass but success must not drop floor material
- L367: Floor invariant: an interrupted view's head is never recorded, else the rejected fork would poison the floor for every later honest chain
- L425: Property pinned: a non-advancing re-run does not submit (last-attestation tracking in attested.json)
- L453: Equivocation shape: tracked hash differs at the same seq, so submission is not suppressed — preserving fork detection via this attestation
- L493: Scenario: all endpoints 404 (an old server without the attestation PUT)
- L499: Property pinned: when submission does not happen the tracking does not advance, so it retries next time

### `apps/cli/test/audit-reconcile.test.ts`

- L1: Scope contract for audit reconcile (§6): membership/position violations as tampering vs acceptance-policy evidence; bounded 503 retries
- L56: idOf is deterministic test-only material; the real server assigns row ids randomly
- L61: orderOf recovers ordering from the id because idOf encodes seq in hex, so even a negative dropping seq can be ordered
- L69: SeedRow is the shared material for both the wire form and the computation-input form
- L77: wireRowOf is the admin-visible wire form, which carries seq (unlike the D1 form)
- L90: headRowOf mirrors the CLI's recomputation mapping (the 17 columns of §5.1)
- L113: headsOf convention: index 0 = h_1, computed with the canonical implementation
- L138: Field semantics: served defaults to all of rows
- L142: Field semantics: onAuditHead undefined means return the attestation with 200
- L152: makeReconcileServer covers every endpoint reconcile needs: chain, auth/me, audit-head, audit/events
- L216: Fixture maps each §6 check: checkpoint 2 notarizes h_1 ((c) vacuous), checkpoint 3 notarizes h_2 (floor, (b) non-regression)
- L225: Field purpose: headAtChain2/3 override the notarized head from the recomputed sequence to build violation cases
- L261: §6 residual pinned: on success one stderr Note states the un-notarized prefix is unprotected; stdout carries only command output
- L268: Fixture: genesis-only chain with its single mirror row (no notarized checkpoints)
- L284: Scope caveat pinned: only missing-seq and attestation membership were verified; (a)(b)(c) passing is not claimed
- L309: §6 wording pinned: a membership violation is reported as rows altered or deleted after notarization
- L315: Predicate split pinned: (b) admits equality so the stale head passes; (c)'s position floor drops it (same predicate as acceptance check)
- L334: Category separation pinned: h_1 exists so this is not reported as row-tampering evidence
- L363: Scenario: dropping seq 3 (checkpoint 3's mirror row) is the trace-of-deletion shape
- L375: Rationale: past the gap the chain disagrees entirely, so the membership check is never reached and false attributions are not mass-produced
- L429: Property pinned: below effective admin the cross-check never starts (zero row and attestation fetches)

### `apps/cli/test/audit.test.ts`

- L1: Scope contract for maruhi audit (§6/§7): TCB name discipline, mirror cross-check, bijection verify, usage errors before network
- L63: Fixture composition: base chain genesis, environment creation, member add, with no pending obligations
- L74: idOf is deterministic test-only material; the real server assigns row ids randomly
- L79: assignPresent mirrors the wire's optionalKey shape: entries with undefined values are dropped
- L88: proposalIndexOf uses the same core derivation as the server, as input to the four-eyes rows
- L101: wireMirrorRows is built from the same shared mapping as the server's
- L130: Invariant: audit seq differs from chain seq on four-eyes chains because a completed approve produces 2 rows (AUDIT_SPEC §3.4)
- L144: Mock semantics mirror the server's: seq-descending, row-id cursor, unknown id = empty page; eventPrefix is a prefix match (§7)
- L184: Field semantics: metadataAvailable false models the 404 degradation path for name resolution
- L257: pushRow builds a var.version_pushed row for checking name resolution and payload display
- L273: aggregatedReadRow models the AUDIT_SPEC §3.3 aggregated form: one row per environment per valued pull
- L315: Fixture note: seq=5 carries an authMethod payload other than the variable list
- L327: Property pinned: the listing payload is neither folded into the line as recorded= nor expanded
- L330: Property pinned: a non-listing payload still shows under recorded=, with the listing excluded
- L336: Property pinned: the aggregated-form guidance is a Note on stderr, not mixed into the stdout list
- L349: Property pinned: expansion display names come from verified statements; an absent variable shows only its id
- L355: Property pinned: with --var the matching variable's entries are attached inline without expansion
- L394: Property pinned: the enumeration is summarized, not dumped; the rest of the payload remains
- L397: Property pinned: the epoch column is the exposure bound (exposureEpoch) and aggregate rows carry no var=
- L401: Property pinned: with --var the matched variable's basis is attached inline
- L415: TCB discipline pinned: the payload's name snapshot is a server claim and is never promoted to the display-name position
- L430: TCB discipline pinned: display names come only from verified statements; the payload snapshot appears only inside recorded=
- L492: Scenario: a row planted at seq=9 with earlier rows requested via the row-id cursor
- L515: Cursor semantics pinned: the cursor row itself is excluded; only earlier rows return
- L536: Shape rationale: a dropped mirror row is an omission invisible in principle to per-row cross-checking, so verify must catch it
- L601: Attack shape: a forged row far beyond head must not be counted as unverified and reported OK
- L618: Fetch rationale: exact-match fetching would never retrieve an unknown-op row, so rows are fetched by prefix match and unknown ops dropped
- L665: Race shape: the chain grew one entry right after syncing (chain_seq = head + 1)
- L695: Fixture relies on deterministic signing: the same prefix yields the same propose hash, referenced after building once
- L725: Count explained: 8 entries yield 9 rows because the seq-8 approve produces chain.approved + chain.member_removed
- L772: Property pinned: with 1 vote under required=3 only chain.approved (completed = false) is correct
- L818: AUDIT_SPEC §3.4 cap pinned: even a completed approve yields at most 2 rows at one chain_seq
- L857: AUDIT_SPEC §7 pinned: D1 responses carry no seq because the global counter is not disclosed
- L912: AUDIT_SPEC §7 fixture shape: D1 responses carry no seq
- L936: Property pinned: the watch-worthy event's implication is emitted as a Note on stderr

### `apps/cli/test/byte-replace.test.ts`

- L1: Scope contract for the byte replacer: exact raw-byte matching, longest first, chunk-boundary carry-over, non-UTF-8 transparency, scrub rule
- L71: Stream state pinned: with nothing resembling the secret, the whole chunk is released, mid-line included
- L74: Stream state pinned: a tail that is a prefix of the secret is held
- L77: Stream rule pinned: held bytes are released as source on divergence or replaced on completion
- L98: Rule pinned: a shorter line match is never taken while the whole value could still complete
- L105: Stream state pinned: on divergence the held beginning is rescanned and its first line matches as a fragment
- L114: Fixture consequence: every line is under the 8-byte floor, so only the whole value is a scrub pattern
- L173: Scrub rule pinned: a JSON value's brace lines are dropped and its long lines kept as patterns
- L179: Property pinned: output containing a short value stays byte-identical (below the scrub floor)
- L182: Boundary pinned: a value exactly at the 8-byte floor is scrubbed

### `apps/cli/test/chain-sync.test.ts`

- L1: Scope contract for chain-sync (§6.3): verifyChain delegation, genesis-hash = project-ID check, head consistency, key history index
- L98: §6.2 pinned: the environment set is chain-derived (current epoch, creation seq, epoch-start seq, per-epoch commitments)
- L106: §5.1 pinned: a removed member's key-at-the-time resolves from the append-only key history
- L150: Attack shape: serving a valid but different project's chain under the requested project ID is a server-side substitution

### `apps/cli/test/checkpoint-integrity.test.ts`

- L1: Scope contract for checkpoint rule 2 (§6.3): acceptance/rejection paths, locator classes (ruling S), floor cross-layer (ruling W)
- L59: CHECKPOINT_SEQ derivation: baseSteps' 3 entries + checkpoint = seq 4
- L65: Fixture composition: baseChain is genesis, create ENV (epoch 1), rotate (epoch 2), with no checkpoint
- L67: Fixture composition: chain is baseChain plus a checkpoint covering ENV (rule 2's baseline)
- L73: Fixture state: valueA is va v2 epoch 2, the latest as of the checkpoint
- L75: Fixture state: valueB is vb v1 epoch 1, the legitimate post-rotation pre-re-encryption state (§12-7)
- L77: snapshot is the correct enumeration for the checkpoint, modelling the server-stored rows
- L79: manifestMain is the mv1 manifest the checkpoint tuple binds ([A active, B active])
- L81: checkpointOperation covers ENV and is reused by the benign-race test as a second checkpoint
- L95: Two-pass construction: deterministic signing/timestamps mean rebuilding the same steps yields the same entries, fixing head/digest
- L216: Field semantics: checkpointSnapshot null = distribute no enumeration (negative); omitted = the correct enumeration
- L255: startPhase switches phases within the same TestEnv (same floor), the same idiom as floor-detection
- L267: manifestNext builds the mv2 manifest with prev = mv1's real hash, for cases where the served set changes
- L379: Benign-race model: first fetch lacks the checkpoint; the pull response carries its enumeration (it landed before the response was built)
- L464: Fixture reasoning: a different ciphertext at the same coordinates; the nonce differs so the signed bytes differ too
- L498: Scenario: a declared head positioned where epoch 1 was current still passes signature verification
- L594: Fixture contract: laterCheckpoint re-notarizes ENV's identical tuple or omits ENV; served enumeration names the latest checkpoint with ENV
- L662: Ruling pinned: an honest locator/baseline disagreement is rejected with re-pull guidance, not escalated to evidence a re-run cannot clear
- L710: Case split pinned: no enumeration with the baseline landed after the fetch view is retriable
- L721: Case split pinned: no enumeration with the baseline already stored at the fetch view is evidence rejection
- L732: Case split pinned: an enumeration at the old position with the baseline already stored is stale-distribution evidence rejection
- L748: Phase setup: phase 1 establishes the floor with va v3, advanced past baseline v2 at epoch 2
- L773: Cross-layer ruling W pinned: rule 2 passes the rollback (same version/hash as snapshot) but floor rule (a) drops it as below v3
- L799: Type note: the test's Wire* structural types match the api-schema distribution types structurally (support/crypto.ts)

### `apps/cli/test/checkpoint-retry.test.ts`

- L1: Test-scope contract for fetchAuditHead's 503 retry: exponential backoff, unchanged 10-attempt budget, exhaustion message, TestClock-driven
- L21: run harness contract: returns the exit, every auditHead call timestamp, and the retry lines logged between attempts
- L87: Backoff schedule pinned: waits 5..1280 ms (~2.5 s total); the acceptance path's retry shares the same base

### `apps/cli/test/checkpoint.test.ts`

- L1: Scope contract for checkpoint issuance (§6.3/§16-2): self-computed tuple, admin judged up front, bounded 422 retries, changed-only cover
- L73: Fixture intent: alpha < dev is a byte-order discrimination pair
- L100: Field purpose: nextValues swaps the value on each pull (the busy environment of the subset-fallback test)
- L102: Field semantics: checkpointSnapshot is the latest checkpoint's enumeration for the environment (§12-7, required once it has a baseline)
- L111: Field semantics: onAuditHead undefined means return the attestation with 200
- L113: Field semantics: onAppend undefined means accept and append
- L115: Field models a lying 2xx server (accept without appending), the §12-10 (3) check target
- L117: Field purpose: firstFetchEntries models a checkpoint landing after the opening view
- L133: makeCheckpointServer covers every endpoint the issuance flow needs; accepted entries are reflected onto the chain
- L207: Handler note: per-environment pull is valued (§12-7)
- L244: Fixture composition: one environment with one variable + manifest
- L326: tupleOf builds the tuple the issuer builds for a fixture environment (what a checkpoint notarizes)
- L341: appendSignedCheckpoint exists because buildChain's timestamps all lie past the 7-day line; it signs at a chosen time
- L378: Fixture intent: environments deliberately listed descending to discriminate the issuer-side ascending normalization
- L414: Property pinned: environments are byte-ascending (alpha < dev) and the tuple is self-computed from the verified view
- L424: Property pinned: with effective-permission admin the notarized attestation is the one fetched after the CAS parent was fixed
- L502: Property pinned: out-of-scope environments get no valued pull (no var.read recorded, no 403 stepped on)
- L580: §16-2 pinned: the audit-head attestation is re-fetched per attempt
- L584: Fixture scope: shared AuditHeadNotReady retry fixture (single-environment issuance by admin)
- L626: Property pinned: two 503s are absorbed and issuance happens exactly once, on the third attestation
- L640: AUDIT_SPEC §5.1 rationale: resending re-fetches the attestation because the server's extension has already advanced
- L654: Budget invariant: the shared notReady counter caps the acceptance path too (10 appends, each preceded by a fresh attestation, §16-2)
- L660: Backoff pinned between appends (5..1280 ms); gaps are lower bounds only since each also carries a rebuild + attestation + send round-trip
- L688: Budget arithmetic pinned: the attempt after a 422 keeps the five 503 attempts already spent, so the shared budget ends at 11 appends, not 16
- L733: Property pinned: an environment matching its baseline is neither covered nor reported as skipped
- L753: Scenario: ENV_B's version advances on every pull (concurrent push); prev chains to the self-computed hash of the preceding version (§4.1)
- L784: Fixture behavior: any issuance including ENV_B always 422s because the at-acceptance match never converges (busy environment)
- L813: Fixture rationale: buildChain's deterministic past timestamps put every checkpoint past 7 days, so a fresh baseline is hand-signed at now
- L840: Setup: a mock with only /auth/me, used to judge admin's effective permission
- L864: Case progression pinned for member: no baseline proposes; a fresh baseline (notarization not required) does not
- L867: DP5 ruling C: never-issued counts as baseline = genesis; within 7 days no proposal, past 7 days propose; admin uses the same threshold
- L898: Scenario rationale: a fresh un-notarized baseline does not satisfy admin's trigger, so a member's issuance must not kill it
- L965: Fixture states: alpha unchanged since baseline, dev has no baseline, ops has an empty value set landed after its baseline
- L1013: Rationale: the unchanged environment was still pulled because only its verified tuple shows it equals the baseline
- L1023: Fixture contract: one environment whose baseline equals its current tuple; freshMs signs that baseline at a chosen time
- L1219: Setup note: the baseline is older than 7 days in both compared variants

### `apps/cli/test/ci-rotate.test.ts`

- L1: Scope contract for ci rotate (§5.3/§14-5): client-side pins only; server decisions pinned in apps/server/test/rotation-proposals.test.ts
- L87: Fixture roles: ownerPhone is a cap-owner recipient device; ownerReaderCap is reader-capped and never a recipient
- L98: addDeviceOp builds add_device with a role cap (CRYPTO_SPEC §6.2 — the actor is a valid device of the same person)
- L194: Field semantics: expSeconds is the exp (seconds) of every token issued; default none
- L196: Field semantics: after failAfter tokens the endpoint answers 500; default never
- L198: Field semantics: after hangAfter tokens the endpoint answers only after a minute; the fetch's bound ends the wait
- L200: Field semantics: after delayAfter tokens the endpoint answers late, after delayMs (a slow runner endpoint; default 3 s)
- L205: issuanceOutage models the endpoint's injected outage after issued tokens: a 500 or a minute-late answer
- L221: issuanceDelay returns a delayed null (the token is issued, late) after delayAfter tokens
- L365: Field semantics: reject is an injected refusal; undefined = accept
- L367: Field semantics: rejectOnce is an injected refusal of the next mint only
- L390: Mock behavior: the server sets the receipt instant from the days
- L422: Field semantics: reject is an injected refusal; undefined = ok
- L447: Field semantics: oidc counters track issuance; a fetch in flight already holds its bound
- L451: startCi seeds neither login nor config; CI mode's independence is pinned by this setup itself
- L501: ciRotateOnClock runs the same rotation against a TestClock the job's clock reads come from
- L513: realNowClock pins TestClock at the real instant so the job's clock stays consistent with the mock server and real-time code outside Effect
- L537: oidcFetches waits until the issuance endpoint has been hit count times; the fetch then holds its bound
- L587: ownerDevicesInOrder returns the devices in the order the client seals to them (fingerprint order, devicesOf)
- L594: openedByOwnerDevices opens each wrap with the device it is addressed to, in ownerDevicesInOrder order
- L609: onlyMint asserts the run minted exactly once (a missing or second mint fails the test)
- L615: jtiOf reads the token's jti, which in the mock encodes the issuance order of its tokens
- L633: Property pinned: the script saw the leased credential and admin input in memory only
- L641: Ordering pinned (O-4): the pre-flight ran before the connector, under the lease's own credential, naming the leased versions
- L650: O-11 pinned: the set the job seals to is named before the issuer is touched
- L657: K-5 pinned: one mint under the lease's ephemeral key with a token minted after the connector, because the lease's token may have aged out
- L665: D-8 pinned: the value's shape is shown locally and never stored with the proposal
- L674: W(E) pinned: member-or-above devices are recipients; reader and reader-capped are not (could open the value but never push it)
- L697: Property pinned: crosswise opening fails (one Seal per device)
- L741: Ordering contract: companions first, because the server stores this order and accept pushes in it
- L759: Property pinned: the script's fact is scrubbed of the produced values
- L768: Contract pinned: the lifetime travels as days; the report shows the server's instant
- L781: O-15 pinned: re-lease presents the newest unexpired token for the lease's key; if issuance stops after the mint's token, recovery uses it
- L799: O-13/O-15 pinned (§14-1 idempotent re-claim): re-lease presents the mint's token (jti 2, newest); second mint falls back to it when down
- L821: O-17 pinned: a token within the reuse margin of expiry is still presented when no fresh one can be minted
- L838: Property pinned: a second mismatch produces the recovery message, not a retry loop
- L855: Bound arithmetic: mint fetch bound = lease token's remaining life minus margin; clock crosses it under expiry, keeping a live token
- L865: Step state: the mint's fetch is in flight with its bound taken before the hang
- L875: Bound rationale: with the lease token already expired there is no fallback to protect, so the mint fetch gets the default 30 s bound
- L910: Case condition: with less than margin plus floor left there is no fallback to protect, so the bound is the default
- L933: Regression rationale: the run's clock is a minute ahead, so reverting the catch's clock read to Date.now() would exit 0 — fails then
- L982: Property pinned: only the lease's token was minted; no fresh token exists for a mint that never happened
- L1021: Race shape: the storage guard can be crossed between the pre-flight and the mint
- L1035: Refusal pinned: a >64KiB value is refused by sealProposedValue (MAX_SEALED_VALUE_BYTES); its message folds into the recovery notice

### `apps/cli/test/ci-run.test.ts`

- L1: Scope contract for ci run (§9.1/§14): client behavior only — verification duties, retry discipline, error guidance
- L55: Fixture fact: OTHER_ENV_ID (staging) is an environment only the second grant (B) covers
- L57: Fixture seq map for extended: before any grant, grant B only (staging), grant A (prod) added, A revoked, prod deleted
- L80: Field semantics: built is the served happy-path chain, extended's first GRANTED_SEQ entries
- L82: Fixture chain composition whose prefixes are the §9.1 (6) lease authorization cases (see chainPrefix)
- L102: Fixture design: chain carries a real-DEK commitment and an active grant for the leased env (§9.1 (6)); a second grant covers only staging
- L126: Fixture shape (§12-7): latest version's epoch differs per variable — ALPHA epoch 2, BETA stays epoch 1, never re-encrypted after rotation
- L196: fakeJwt uses a dummy signature because the client does not verify it (§14-1)
- L201: jwtPayload reads the claims from the presented token's payload, the same path as the server
- L213: Field semantics: issued counts tokens issued so far and is embedded into jti, distinguishing tokens in the replay check
- L217: oidcHandler impersonates the GitHub Actions OIDC issuance endpoint and returns { value }
- L229: Mock rationale: sub varies per issuance because claims_digest binds only iss/sub/aud; a jti-only difference would let a claims-reuser slip
- L248: Field purpose: claims substitutes the claims bound to the lease wrap (a wrap repurposed for another job context)
- L250: Field purpose: dekForEpoch substitutes the per-epoch DEK (poisoned wrap = commitment mismatch)
- L253: Field semantics: headHashHex defaults to the last hash of fixture.built
- L255: Field purpose: garbageLeases replaces every lease wrap with well-formed garbage so no wrap can be opened
- L260: Field purpose: declaredVariables bundles the declared variables (§14-2, material for ci run's presence check)
- L262: Field purpose: extraLeases adds wraps for the negative cases (duplicate epochs, off-chain epochs)
- L266: leaseClaimsDigestOf takes the presented token's claims via the server's path, plus overrides to fake the repurposed shape
- L283: leaseWrapFor builds a real wrapLeaseDek to the ephemeral key (the CRYPTO_SPEC §9.1 info construction)
- L315: leaseResponseFor builds a response lease-wrapped with real crypto to the request's ephemeral key (AUTH_SPEC §14-2)
- L357: Fixture note: the declared head sits where the declared epoch is current (create = 2, rotate = 3)
- L402: manifestlessLeaseHandler models a manifest-suppressing server: manifest required since 0.28-draft, so it is built complete then stripped
- L430: startCiEnv seeds neither login nor config: CI mode's keychain/config independence is pinned by this setup — any dependency fails the command
- L439: Setup intent: the runner-supplied issuance URL already has a query, which also exercises the &-joining branch
- L462: expectNoSecretLeak is the shared check that no plaintext or token leaks into the output
- L468: Leak-check extension: the fakeJwt payload segment (the token body) must not be printed either
- L481: Property pinned: injection is memory only, via ProcessRunner's extraEnv
- L487: §14-2 pinned: the response is self-contained — only OIDC issuance and lease calls were made (no chain API, no pull API)
- L490: AUTH_SPEC §14-1 pinned: the audience defaults to the server origin, the recommended value
- L496: Property pinned: ci run is keychain/config independent — it succeeds in an environment where nothing is seeded
- L498: Output discipline pinned: verification success goes to stderr because stdout is kept clear for the child process
- L501: Property pinned: §9's constant display reaches the workload too, from the bundled chain
- L576: Swapped shape: a CI config pinning a different project ID is served the original chain, declared projectId faked to match
- L626: Repurposed-wrap shape: a wrap made for another sub fails the HPKE info claims_digest and decryption (design principle 3)
- L645: Key distinction: pull may resolve a future head via re-sync (§6.3-2b), but a lease bundles the chain in the response (§14-2) — reject now
- L669: Property pinned: no extra fetch equivalent to a re-sync (exactly one OIDC issuance and one lease call)
- L694: Ordering note: in this shape the epoch-1 wrap fails the open first because the leases list is epoch-ordered
- L725: Pinning rationale: the lease response decodes in ci-lease.ts (not pull's decode), so the dedicated renderer's wording is pinned here too
- L742: chainPrefix serves fixture.extended's first seq entries with a consistent declared head
- L760: Ordering pinned: refusal happens before any lease wrap is opened
- L787: Message ordering: a deletion prunes the id from every grant scope (§6.2) so (6) would also refuse, but the deletion is named first
- L818: Property pinned: both active grants are stated (§9), the leased environment's among them
- L832: Setup: the server serves the prefix in which the grant is still active
- L883: §14-1 pinned: on retry a fresh token (different jti) is presented with the same ephemeral key — binding is per token, key not rotated
- L972: §4-1 (1) pinned: source-IP limit fails closed on a missing binding; guidance calls it a deploy config fix, not credential; not retried
- L991: §14-1 existence hiding: unknown project, no grant, policy mismatch, out-of-scope all return the same 404; CI guidance lists policy mismatch
- L1006: Retry classification pinned: no retry, because it is neither a credential problem nor transient
- L1028: Abnormal shape: issuance returns a multi-audience token, on a separate env-routed path so it does not collide with the default oidcHandler
- L1048: Verification pinned via an unroutable TEST-NET-1 address: correct verification means no communication at all (by response time/wording)
- L1058: Attack shape pinned: 127.evil.com is not a 127.0.0.0/8 literal but a public DNS name; prefix matching would let plaintext http through
- L1085: Property pinned: no re-send to the redirect target on the legitimate issuance path
- L1271: Round-trip consistency pinned: the emitted anchor passes ci run --anchor verification as-is

### `apps/cli/test/ci-sync.test.ts`

- L1: Scope contract for ci sync (ruling D): receipts neither read nor written (no §4.1 key), so re-applying never deletes; leases share one key
- L221: leaseHandler is the per-environment lease handler, wrapping to the request's ephemeral key with real crypto
- L269: startCi seeds neither login nor config; CI mode's independence is pinned by this setup
- L348: §14-1 pinned: leasing 2 environments uses the same ephemeral key and the OIDC token is issued once
- L365: Property pinned: no writes (receipts) to the maruhi server at all; reads are lease only
- L479: Env contract: the only extra env for the child is telemetry off; GH_TOKEN inherited (buildChildEnvironment passes all but MARUHI_*)
- L600: Shape note: the tokens environment's lease is a uniform 404 (AUTH_SPEC §14-1 existence hiding)

### `apps/cli/test/cli-formatter.test.ts`

- L1: Design note: cli-formatter's diagnostics are rebuilt from effect/cli's structured error fields, so a typed value never reaches them
- L12: Leak rationale: effect/cli's default wording contains the typed value; maruhi emits only the declared name and the expected type
- L29: Upstream leak pinned: Param.filter builds expected from onNone, so an interpolating onNone leaks plaintext; mismatched expected not shown
- L47: Upstream change: rc.117 makes 0 of Argument.atLeast(1) a MissingArgument rather than InvalidValue; other missing-arg wording unchanged

### `apps/cli/test/cli-teardown.test.ts`

- L1: Test-scope contract for exit codes: error types carry Runtime.errorExitCode and maruhiTeardown maps ShowHelp so a usage mistake exits 2
- L14: Reference point: Runtime.defaultTeardown is the default teardown BunRuntime.runMain uses
- L25: Contract rationale: upstream ShowHelp's errorExitCode is 1 with errors, so the default teardown would break the 0/1/2 contract (usage = 1)
- L42: Case rationale: a run that explicitly asked for --help/--version (errors empty) is not a mistake
- L50: Case rationale: errors empty without explicit help/version means a bare parent command requiring a subcommand — a usage mistake (2)

### `apps/cli/test/command-specs.test.ts`

- L1: Design contract: COMMAND_SPECS is the single declaration read by diagnostics, --help walk and wording checks; three drift detectors pin it
- L30: CommandNode holds the public fields the walk reads; effect/cli's generics are irrelevant to a name comparison
- L58: helpNames extracts the names a --help section lists, in order (--server under FLAGS; path for path... under ARGUMENTS)

### `apps/cli/test/config-command.test.ts`

- L1: Test-scope note: the argument layer of maruhi config (commands/config.ts, ADR-0016 stage 3), driven through the real runCli
- L25: Attack shape: an ANSI word could erase lines and fake success; the diagnostic shows only the possible values, never the typed word
- L36: Same discipline pinned for the unknown-subcommand diagnostic: a word in the operation-name position is never returned either
- L46: Accident blocked by the declaration: config set defaultProject "$PROJ" unset form would overwrite with empty and report success
- L64: Upstream behavior relied on: the parser folds positionals around -- into one array (POSIX hatch); excess stays an extra positional (exit 2)
- L83: Property pinned: the positional count is never underreported (an optional slot must not absorb it)
- L104: Stdout contract pinned: V=$(maruhi config get server) must never catch anything but the value

### `apps/cli/test/config.test.ts`

- L1: Scope split: this file pins non-sensitive config and config get/set behavior; the argument layer is pinned in config-command.test.ts
- L32: Regression blocked: the report names the config key, so a declaration-object mix-up cannot print Effect's internal representation to stdout
- L45: Classification pinned: a typo is a usage error (2), distinguished from an execution failure (1)
- L60: Scenario: set can discard and rebuild a non-sensitive-only config file
- L73: Scenario: a directory placed where the config file goes produces EISDIR, a read failure that is not ENOENT
- L80: Property pinned: set likewise must not silently replace an existing unreadable config; it fails for the same reason
- L102: Decision 9 pinned: bare maruhi is a help request (exit 0, stderr); the list is drawn from the command definitions (hand-written goes stale)
- L110: Check design: a substring match would be satisfied by other commands' text, so entries are checked as lines in the SUBCOMMANDS section

### `apps/cli/test/connector.test.ts`

- L1: Scope contract for the connector frame (PF6 R2–R4): grace-period creation per issuer, finalize invalidates exactly the previous credential
- L106: deps wires the connector's services: fake issuer fetch, recorder SqlRunner, fake script runner, deterministic ConnectorCrypto, TestClock
- L138: Fixture mechanism: deterministic bytes make every password AAAA… shifted by a counter
- L186: Sampling rule pinned: bytes at or above the rejection limit (248+) are skipped, never biased in
- L266: Property pinned: the self-rotation admin connection is the current credential
- L309: Property pinned: when no admin is named, the current (new) credential authenticates the finalize
- L397: SigV4 design: IAM recomputes the signature from received headers, so re-signing what arrived must reproduce the sent Authorization header
- L541: Discrimination pinned: the probe is signed by the candidate pair (the old key id + the previous secret)
- L563: Discrimination pinned: the finalize is signed by the current credential (the new key)
- L592: Scenario pinned: a hand-created key (no version of the key id variable held it) is untouched, with no probe
- L610: Scenario pinned: a stored key id that does not pair with the previous secret (pushed by hand) is untouched
- L629: Scenario pinned: when only the current key exists there is nothing to deactivate (no probe)
- L759: Semantics pinned: verify answering result: null reads as a token Cloudflare did not verify
- L804: Finalize semantics pinned: a previous token whose verify carries result: null is already done
- L917: Property pinned: one trailing newline is dropped from the script value; nothing else is touched
- L921: D-8 pinned: the value's shape is for the local report and acceptance (script chatter seen before push), never a fact the server stores
- L925: D-16/D-19 pinned: the current value's shape is carried beside the new one as numbers, for the report's line-count comparison
- L983: Property pinned: the script's words are kept as facts, scrubbed of every credential it could echo
- L1045: Property pinned: the new value is scrubbed out of the script's facts
- L1049: Report contract pinned: every value to push is shaped in the local report (primary first, then companions by name — the acceptance's parity)
- L1074: Leak discipline pinned: the script's words (an unknown key, an undeclared companion name) never reach the message
- L1083: Property pinned: a produced value must be text a process environment can carry (NUL rejected)
- L1123: Finalize report pinned: the exit code and the scrubbed stderr; the previous credential is never shown
- L1170: D-11 classification pinned: a script maruhi stopped (flooded stdout) is not a launch failure
- L1178: D-14 pinned: a leftover process's output is refused with the recovery when the script itself exited 0
- L1189: Property pinned: a credential that is not text cannot ride in an environment variable
- L1201: Classification pinned: a missing rotation site is an internal inconsistency, not a user error

### `apps/cli/test/dek-wrap.test.ts`

- L1: Contract: wrapAndSignFor folds every crypto failure into a reason string embedded verbatim; driven as backfill.ts consumes it
- L93: Property pinned: the wrap is real — §5.1 signature verifies under the signer's key, HPKE wrap opens to the input DEK

### `apps/cli/test/dev-setup.test.ts`

- L1: Supply-chain contract: Bun, pnpm, test browser reach a machine only via a digest-checked fetch, on every setup path; offline stubs
- L56: systemTool locates a system tool so a stubbed PATH can still reach it
- L72: zipOf builds a stored (uncompressed) zip whose entries keep the given Unix modes
- L144: Strictness rationale: the action line is matched whole so nothing (|| true, another flag) can ride along
- L162: Stub design: installer runs in a scratch repo; curl serves a real zip whose executable leaves a marker if ever run; grep answers AVX2
- L277: Field purpose: repin pins the served zip's own SHA-256 in the copy so the check passes
- L282: Field semantics: parallel is how many copies run at once, each with curl taking a moment to answer
- L319: Stub design: script runs with a HOME holding an older install; curl serves a real zip whose executable creates a marker if ever run
- L419: Property pinned: the work dir is on the same filesystem as the install, so the tree is renamed into place, never copied
- L474: Field semantics: bun is the version ~/.bun/bin/bun reports, or undefined when it is not installed
- L478: Field semantics: corepack is corepack's exit status, or undefined when it is not on PATH
- L483: runHook runs the real hook against logging stubs only; calls outside that PATH are unseen — an accepted stub limit, stated openly
- L590: Rationale: an older bun stays on disk, so carrying on after an installer failure would still find a bun to run — the hook must stop
- L635: Fixture intent: the .bashrc holds commented-out copies of every line; only the exact line counts as present
- L646: Field semantics: headlessAt is where the stub installer says it installed the browser, relative to HOME
- L650: Stub design: runSetup runs the real script in a scratch project with logging-stub installers/fetchers and an unverified ms-playwright cache
- L712: Discrimination setup: a stray bun sits ahead of ~/.bun/bin unless the script puts the installed Bun first on PATH
- L780: Property pinned: the setup stops on the installer's own failure status itself

### `apps/cli/test/device-add.test.ts`

- L1: Scope contract for device commands (§3/§6.2/§7, §13-11, DK K4): real-crypto signing vs a wire mock; add refuses by default (K4-18)
- L66: Rationale pinned: an existing key never creates a request, so it never spends the server's 5-per-hour window
- L71: Flow pinned for --replace: show the discarded key's standing, generate a new key, request, swap, signal, confirm on the chain
- L93: Principle pinned: the chain is the truth — sync after the signal and count the projects the registration has not landed on yet
- L97: K7-2 guidance: the note states the approver's work is done and the request spent; registration happens on the next covered keyed command
- L104: K10-5 interpretation pinned: the prelude is one command per project, so the guidance calls it a keyed command aimed at that project
- L125: Mock fact: the default mock returns 404 for GET /auth/devices/requests/:fp
- L156: Guidance scope pinned: the new key is on no chain, so the nothing-is-lost wording carries its scope
- L160: Property pinned: the new key has no live request, so no request lookup is made
- L168: Timing setup: the request is pretended created 6 minutes ago (deadline = creation + 15 min), with no signal yet
- L186: Clock rationale: anchored at wall time, the 6-minute-old request crosses the hint threshold on the first registry fetch — no advance needed
- L191: Round progression: after round 1 (no signal, guidance), a row equivalent to the approver's PUT is placed; round 2 picks up the signal
- L210: Test mechanics: the run is parked in the 3-second poll wait, so it is fast-forwarded
- L214: Measurement pinned: elapsed is measured for real (a resumed wait exceeds the threshold) — here threshold + 1 minute
- L244: K7-1/K4-21 pinned: re-running is refused, so guidance points to --replace (approver registered nothing); never 'rebuild with same key'
- L249: K9-3 T3 branch: approver registered but could not list it, nobody re-ran by deadline — key is on chain; --replace must not discard it
- L255: K13-4 pinned: the guidance carries the chain's current fact, appended while keeping the conditions
- L259: Property pinned: the key stays generated; it is discarded only when a human types --replace
- L264: Fixture design (DK K12): dev2's device-add re-run — registry row is the signal (no request); chain: genesis, env, rotate, add_device
- L272: Field purpose: pending places dev2's live request (the resume-wait, signal, Approved path — DK K13-2)
- L301: deviceRowsOf builds a device-addressed distribution row in the new server's shape (recipientEncPubHex, owner's registration signature)
- L331: Counting rule: only epoch 1 is addressed to dev2; resume waits on the live request and checks after the registry-row signal
- L357: K11 pinned: the new device lacks the missing DEKs so it does not fill them; the sibling device's pull fills them
- L384: Classification pinned: a row outside the cap that cannot be opened is neither missing nor a check failure — it never enters the enumeration
- L419: Structural pin: 'Approved: … 0 projects' can never appear because no path waits on the registry row as the signal in this shape
- L439: Scenario: on another project (different genesis key, different id, same person) dev2 is valid
- L453: K13-2/K13-3 pinned: a valid project with add_device provenance gives a usable key (exit 0); no approval happened so it never says Approved
- L492: Property pinned: no note when the registry has a row — the note is only for a missing row
- L544: Fixture intent: non-ID-shaped names and sidecar files are planted to prove they are not counted
- L627: Property pinned: resuming a live request never creates a request (never spends the window; no hole-5 path exists)
- L660: Scenario: the list's first entry syncs with dev2 absent; the second cannot be synced
- L675: T3 state pinned: the registry row stays missing (the approver's PUT dropped) and the request has expired
- L778: Race shape: a value written by another process (the guard only compares the value)
- L785: Race shape: another process rewrites the keychain while the request is being created

### `apps/cli/test/device-approve.test.ts`

- L1: Scope contract for device approve (DK K4): ceremony gate before fetching; FP recomputed from the request row's key (K4-6)
- L50: addsOf collects an add_device append for a given device key across all projects, with project id and cap role
- L73: Flow pinned: the device lands on the chain and the later stages (record, registry, cancellation) run; pull fills the gap
- L119: Property pinned: owner's device signed and appended the add_device (default cap = owner / all)
- L131: Backfill pinned: env-app's epoch 1 was registered addressed to the new device's enc key
- L140: Record pinned: the local record is approved, with the approving device's FP as the provenance
- L149: Ordering pinned: the registry PUT (the signal) comes last, plus the request's cancellation
- L163: K7-7 FP provenance: compare with the screen of the machine being added, never a sent FP — anyone with an admin token can place a request
- L240: §3 no-truncation rule pinned: prefixes or 11 words are not accepted as the fingerprint
- L249: Scenario: the session is member (not on the chain), so it is skipped on the only project
- L267: Scenario fact: dev2 is a device key of the same person as owner but is not on this project's chain
- L280: Guidance discipline pinned: it never guides toward an unachievable procedure (request-less approval)
- L321: Check placement pinned: a scope naming a nonexistent environment fails on the only project as a pre-communication check
- L331: Property pinned: only the first-sync observation (this device) is recorded; no approved row is written
- L348: K8-5 round 3 pinned: it did land on the chain, so it is not a failure (exit 0)
- L355: Property pinned: the signal could not be raised, so its material (the request) is kept
- L359: Wording pin: the two sentences devices.mdx quotes sit adjacent on both branches (PR #196 pullfrog)
- L363: DK K10-1 pinned: the re-issue command carries the same cap (a flagless re-run is the default owner / all)
- L368: Convergence flow pinned: the approver clears rows and re-runs — every project already done, then PUT, then cancellation
- L441: State reconstructed: the previous approval (member / env-app) left the request behind on a PUT failure or interruption
- L456: Flagless semantics pinned: flagless is the default owner / all (the widening direction — the person who typed the K9 Note flagless)
- L465: DK K12-7 pinned: the re-add procedure is spelled in one function — a revoked key never comes back, so a new key + approval
- L473: Property pinned: the record is not overwritten by the approval; the row stays as the sync observation wrote it, with the chain's cap
- L478: Convergence pinned: re-issuing via the emitted command converges (already, record, PUT, cancellation)
- L500: Fixture split: dev2 is present on P1 as member / all and absent on P2 (genesis's device differs = a different project id)
- L520: Cap discipline pinned: no add_device with this run's cap (owner / all) appears; registration on P2 would use the chain's cap (member)
- L530: Convergence pinned: the same-cap re-issue lands as member on both projects and converges
- L565: Property pinned: dev2 is appended nowhere; the sync appending another device (genesis's reserve key) is a different path
- L594: K4-1 pinned: the reserve key's secret never lands on the local record (public side only)

### `apps/cli/test/device-gaps.test.ts`

- L1: Scope contract for gap-filling (DK K11): pull derives other devices' missing epochs from bundled wraps; wraps only those to the sibling
- L51: Fixture role: sibling is owner's second device, the one with a missing epoch
- L53: Fixture role: narrow is owner's third device whose cap's scope is only OTHER_ENV_ID — not a recipient of ENV_ID
- L98: rowFor builds a distribution row destined to a device key in the new-server shape (carries recipientEncPubHex)
- L119: start builds chain + a valued pull of a 0-variable environment with swappable bundled rows + wrap registration
- L187: Fixture state: owner holds epochs 1 and 2, sibling has only 2 (1 missing); narrow is not a recipient of ENV_ID
- L199: Discrimination pinned: the registered row opens under the sibling's key to the epoch-1 DEK and the registration signature verifies
- L252: Scenario pinned: owner doesn't hold epoch 1 either, so sibling's epoch 1 can't be filled (not wrapped)
- L275: Partial-gap reporting: on failure the message names only the epoch it tried to wrap (2); epoch 1 (not held either) is also mentioned

### `apps/cli/test/device-key-recovery.test.ts`

- L1: Test-scope contract for device key recovery (CRYPTO_SPEC §3/§6.2/§7, AUTH_SPEC §13-11, DK K4): real-crypto signing against a wire-level mock
- L40: Fixture state: previous run interrupted at the ledger swap — ledger holds N1, original reserve O (dev2) marked revoked, both on chain
- L48: Field semantics: retiringOnChain controls whether the old reserve key is on the chain (default true; false = neither revocation nor cleanup)
- L129: Interrupted state: ledger swapped to N1, O marked revoked, chain carries both, no environment (cleanup not examined here)
- L138: Targeting pinned: revoke_device targets both O and N1, not N1 alone
- L149: Record state pinned: O and N1 revoked; only the new key is a valid reserve key
- L156: Property pinned: the reserve key's secret never remains in the keychain
- L163: K11-14 ruling: never putting the old reserve key on the chain means no revocation or cleanup; exit code from the backfill failure alone
- L184: Scene: the chain has owner's device + the old reserve key; the ledger cannot be opened (the code is lost)
- L224: Property pinned: the ledger is replaced without being read (no GET /auth/recovery)
- L233: Record state pinned: the old reserve key revoked; only the new reserve key valid
- L241: Property pinned: the reserve key's secret never remains in the keychain
- L251: recoverFixture sets the scene of typing key recover on a keyless device (the ledger = ledgerKey); answers are the responses after the code
- L281: recoveryFixture sets the scene of typing key recovery on a device that has device key device (the ledger = ledgerKey, already registered)
- L292: Field semantics: projectsStatus is the project-list GET's response status (default 200)
- L294: Field purpose: extra handlers, e.g. the invite-create issuance used for the pre-hiding sync
- L316: Handler note: the ledger rows read by rotate's tail (the old reserve key's passkey / guardian) are none
- L344: DK K16 marking pinned: the test's reserve is a CLI-generated reserve key (marked); owner etc. are replicas of pre-DK device keys (unmarked)
- L371: Ordering pinned: registration is already done before the judgment (the reserve key signs the new device key's add_device)
- L377: Scene: ledger is dev2's key (unmarked, not a CLI-generated reserve), add_device-issued everywhere — where K14's inference would ask
- L391: K4-10 pinned: registration happens regardless of the mark, because recovery's purpose is registering a new device key
- L508: Wording pinned: with nowhere still valid it never says 'still registered'
- L517: Judgment inputs: on p1 the reserve key is already revoked; on p3 dev2 created and add_device'd it (neither is its first key) — revoked
- L578: Reporting pinned: registration/revocation on unsyncable projects is a failure (exit 1 — a re-run continues)
- L581: Reporting pinned: instead of stopping, it names the range it could not check
- L655: Property pinned: neither ledger, chain, nor record changes
- L759: Property pinned: only the newly generated reserve key is recorded, not the opened dev2 key

### `apps/cli/test/device-revoke.test.ts`

- L1: Test-scope contract for device revoke (DK K4): revoke settles by FP and the last device cannot be revoked (last-device-protected)
- L76: Obligation pinned: revoking dev2 (owner / all) rotates only env-a; env-b's obligation remains
- L99: Scope arithmetic: dev2 is (owner, {}), target reserve (owner, all) — env-a/env-b obligations are outside dev2's scope; cannot rotate
- L129: Failure shape pinned: the environment's rotation answers 404 while the chain shows it live, so the post-acceptance sweep fails
- L151: Follow-up pinned: the local record is revoked and the registry row is deleted
- L198: K4-13 pinned: if the token inventory cannot be read, just convey the fact
- L213: Concurrency shape: an unrelated concurrent append (another device of the same person)
- L329: tokenRow builds one row of the token inventory (the GET /auth/tokens response — K4-13's match target)
- L338: Decodes the expiresAtMs literal: 2026-01-01 00:00 UTC
- L344: setup prepares a chain, registry and local record holding dev2 as a registered device
- L380: Matching rule pinned: even when the name is cli:<label>, a row with a tokenId is matched by tokenId alone
- L485: Fixture state: partlyRevoked is revoked on P1, valid on P2 (revocation on only some projects); the key at hand is dev2

### `apps/cli/test/device-sync.test.ts`

- L1: Scope contract for device sync (DK K4): first sync appends only the record's 3 provenances, never the registry (K4-3/K4-4)
- L46: inviteHandler is the issuance POST of a command that passes through the keyed prelude (invite create)
- L75: Setup: a command passing through the keyed prelude (invite create) — registration runs as a side effect of the sync
- L93: DK K10-3 pinned: the appended cap is emitted at the point the record's cap is in force
- L95: Decision-input discipline: the registry is never an input — not even read, so a registry-only device is never appended
- L97: K4-9 warning condition: fires only when your devices are just this one and the record holds no reserve key; here it ends at 2 devices
- L132: Attack shape: the planted row is an unsigned file whose provenance poses as approved
- L139: Property pinned: the keyed prelude (first sync) runs, but registration is skipped in this mode
- L152: DK K10-5 pinned: the prelude is one command per project, so the guidance emits a command aimed at this project
- L181: K4-9 pinned: only this device and no reserve-key record, so the no-reserve-key warning fires
- L230: Setup/transcription pinned: reserve was previously recorded active here; the chain's revocation is transcribed into the record
- L243: Property pinned: your own device is recorded too, and no Note is shown
- L259: Property pinned: a revoked device is never re-registered
- L270: Fixture step: owner's second device has a cap holding env-b only
- L275: Fixture step: member's scope is env-a only (1 device, no cap)
- L281: Count explained: env-a recipients are owner's 1st device (all) + member = 2; owner's 2nd device does not hold env-a
- L283: Count explained: env-b recipients are owner's 1st + 2nd devices = 2; member is out of scope

### `apps/cli/test/display.test.ts`

- L1: Scope contract for display.ts: total timestamp formatters, showValues (post-decryption defense), decodeValueText (value-decoding policy)
- L24: Edge rationale: years outside 0-9999 make toISOString return an expanded-year form shifting a fixed slice — they degrade explicitly
- L28: Fixture label: this literal is year 10000
- L29: Fixture label: this literal is year -1
- L43: silentIo discards output; this check only observes that display is never reached
- L77: Defense-in-depth: pull checks before decryption; this line keeps a future direct showValues caller from reaching display unchecked
- L89: Shape pinned: the most common CI / non-interactive shape is both non-terminal (pins all 3 branches)
- L112: Attack rationale: a co-editor newline streamed verbatim would fabricate a line for a nonexistent variable, deceiving a pull --show user
- L144: Property pinned: a forged line never appears in NAME=value form (it carries a marker)
- L150: Counting rationale: 'a\nb\n' is 2 lines + trailing newline; a naive split fabricates an empty third line — the newline is part of the value
- L187: Neutralization parity: bidi overrides and zero-width chars in values are neutralized by the same list as the name side; never one side only
- L224: Kept characters: ZWNJ (some scripts) and newlines (PEMs) kept; multi-line values print with a marker from line 2 (cannot forge NAME=value)
- L231: Disclosure pinned: neutralization is not silent — the warning says the display differs from the actual value, without showing the value
- L243: Shared fatal policy pinned (--show / run): no substitution-character camouflage; the caller raises an explicit error

### `apps/cli/test/effect-cli.test.ts`

- L1: Scope contract for the argument layer: 12 argv pitfall shapes via the real runCli; usage = exit 2, diagnostics to stderr, no typed values
- L33: Suggestion discipline: candidates come from declared names (typed spelling never returned), matched exactly — partial would miss ----show
- L42: Measurement setup: the environment ID is broken to force a fail before any communication (pins --show never reached value display)
- L50: Diagnosis pinned: it fails at the flag's brand schema (env id mints at the flag declaration), i.e. --show was read as a value-taking option
- L68: Hazard pinned: pull --no-show with --show inside $FLAGS would show all secrets; a bare Flag.Boolean resolves duplicates silently by order
- L84: Interpretation pinned: the target is preserved and it reaches communication (pull), so the argument layer accepted it
- L95: Failure point pinned: it fails while resolving the empty token as the command name (never skipped and executed with the levels shifted)
- L106: Hazard pinned: resolving across -- as run would hand the first token after -- (the command name itself) over as the execution target
- L134: Diagnostic honesty: the lexer cuts at the first --, so create is env's leftover, never a resolved subcommand; claiming otherwise is a lie
- L141: Wording pinned: the diagnostic states the actual shape (an argument the env level does not take)
- L143: Wording pinned: it never lies that the operation was recognized
- L149: Accident pinned: push API_KEY --env "$ENV" with ENV unset would write to the default environment; one Schema declaration rejects both forms
- L159: Positive-side pin: SAFE_EXPECTATIONS is alive — the brand schema's authored expected annotation is echoed; a rewording drops it honestly
- L167: Property pinned: the typed value (whitespace) never appears in the diagnostic
- L186: Attack surface: effect/cli defaults add wizard/completions/log-level; --wizard launches one (measured); CliConfig narrows to help/version
- L205: Spy purpose: catches any code that bypasses Console / CliIo and writes to the real stdout
- L208: Accident pinned: --help is not a mistake (exit 0) and never reaches stdout — same shape as V=$(maruhi config get server) catching the banner
- L224: Net rationale: a console.log spy cannot catch a write to the real fd; collectingConsole stubs every method, but a net is needed here too
- L229: Stub technique: stash the original methods, not bound wrappers — restoring a bound one stacks a level per call and hides the write
- L237: Property pinned: the real fd is untouched on all 3 paths (diagnostics exit 2, help exit 0, run failure exit 1)
- L248: Judgment criterion: the window mixes in vitest's reporter output, so the property is no maruhi word on the real fd — not that nobody writes
- L262: Property pinned: sections appearing only in the full text (FLAGS etc.) are never mixed into the error diagnostic
- L269: Property pinned: the declarations' description text appears in help (dropping it would thin help to names and types)
- L276: Rationale: if all of argv were examined, a child-process flag in a maruhi usage mistake would surface full help and bury the diagnostic
- L287: Discipline pinned: an upstream Error's message can carry a typed value; control-char neutralization can't keep it out — never passed on
- L306: Case: -- is present but the target is empty (the unset form of maruhi run -- "$CMD")
- L312: Reporting order: even with an empty token after --, the written mistake (extra positional) is reported first, not the generic 'no target'
- L323: Counting rule: for a forgotten --, the count comes from the parser-resolved array — flag values are not counted
- L344: Folding rationale: on an unresolved command flags match root's declarations, so a correct --show would list as unknown too — folded
- L371: Construction pinned: the diagnostic for maruhi --show pull is built from root's declarations; the leaf's would self-contradict
- L383: Decision 9 / addendum 2: V=$(maruhi --version) is the command's output; under --help --version Help wins and never goes to stdout
- L396: Accepted upstream behavior (addendum 7): built-ins short-circuit first, so a same-argv usage mistake is never reported; value path unreached
- L406: Property pinned: no maruhi subcommand exists under root — just an unknown command (never registered under its own name)
- L417: Refusal shape: a rule runs after parsing, before the handler — refusal reads like a parse error (usage + fixed message, exit 2)
- L478: Regression pinned: the pair was checked after that request, so with no reserve key yet it was ignored and a new reserve key created
- L519: Stage pinned: --finalize syncs nothing, so the pair passes as before; the run stops at the next check (missing rotation config)
- L552: Stage pinned: this pair was previously checked inside the rotation, after the session was opened and the chain synced
- L578: History pinned: both forms previously reached the body and failed exit 1 with missing-target guidance (a bare dismiss still gets it)
- L616: Ordering pinned: --role is checked in the command body, which reported it first before
- L644: Discipline pinned: a usage mistake is a usage error (2) and the supplied value itself is not echoed
- L654: Check placement pinned: the environment ID format check runs before any network access (session resolution)
- L662: Classification rationale: nothing was typed on the command line, so reporting it as 2 would be a usage error with nothing to fix
- L674: Strictness rationale: 'only the type name is attached' is pinned strictly — a partial match would pass a regressed 'internal error: <msg>'
- L677: Discipline pinned: a defect's message is not shown — even wording embedding the typed value could reach here

### `apps/cli/test/env-command.test.ts`

- L1: Scope note: the argument layer of maruhi env (ADR-0016 decision 6) via the real runCli; some cases also check root / maruhi server
- L14: Structural rationale: because declarations are split per operation, a cross-operation flag fails structurally as an undeclared flag
- L23: Impact rationale: mixed with a run failure (1), a script would treat a typo as an execution failure — so it must be 2 with Unknown flag
- L61: Accident shape blocked: the unset form of --reason "$REASON" — the NonBlank declaration blocks an empty reason reaching the chain
- L74: Upstream behavior: the token after a boolean is consumed only if a boolean literal (asBooleanLiteral); a normal env ID stays
- L84: Residual: an env ID shaped like a boolean literal (on/off) is consumed as its value and fails loudly (exit 2), never rotates another env
- L96: Interpretation pinned (shape #2): --new-epoch=false reads as false; it passes the argument layer and reaches the body — not a refusal
- L105: Spelling pinned: the negated form (--no-new-epoch) is also a declared spelling, so the guidance target exists
- L159: Folding pinned: the leading empty token resolves as root's UnknownSubcommand; following flags are not piled on as unknown
- L174: Teardown distinction: upstream makes 'no subcommand' a ShowHelp (exit 0); maruhi treats it as a usage mistake (exit 2), cli-teardown.ts
- L192: Wording pinned: under nesting a parent-level flag is undeclared — the diagnostic never lies that it does not exist; it says how to fix it
- L205: Construction pinned: --new-epoch rotate leaves the subcommand in argv, so declarations are chosen by the level upstream reports

### `apps/cli/test/env-create.test.ts`

- L1: Scope contract for composite env creation (§12-4): epoch-1 commitment signing, parent-head CAS, wrap set = verified member set
- L44: CompositeCreateBody is the body of the composite create request (api-schema's environments.create payload)
- L59: Field shape: the bundled manifest (§12-4 — manifestVersion 1, empty variable set, empty prev)
- L111: Mock rationale: the mock mimics real server transitions (appends accepted entries) — the check is a chain sync; a 200-only mock fails
- L121: Field semantics: concurrent = the chain after a racing append; that send gets ChainHeadConflict (409), later fetches serve it plus accepts
- L127: Field semantics: onCreate is a per-call override for create (undefined = accept); it skips acceptance
- L129: Field purpose: acceptedResponse overrides the response returned after accepting, for the lying-attestation negative
- L192: verifyAndUnwrapWrap verifies one wrap's §5.1 signature (signer = owner) and unwraps it as the recipient, returning the DEK
- L263: Placement pinned (§12-4): the display name rides on the EnvironmentMetaStatement (metaVersion 1); declared head = pre-append head
- L274: CAS pinned: parent-head CAS and the entry is signed by actor = the calling principal, placed right after the current head (seq = head + 1)
- L282: Ghost-member defense pinned: wrap recipients are exactly the verified current-member set (nothing addressed to removed members)
- L287: Property pinned: each wrap carries a §5.1 signature (signer = calling principal) and its recipient can decrypt; same DEK for all
- L305: Commitment pinned: the entry's dek_commitment_hex is the bundled DEK's §5.2 commitment (recipients check the unwrapped DEK against it)
- L321: Bundle pinned (§12-4): manifestVersion 1, digest of the empty variable set, empty prev, epoch 1; declared head = pre-append head
- L356: Setup: a chain extended by a concurrent append (same genesis + add_member)
- L363: Serving plan: the first sync serves chainA; post-409 resyncs serve chainB plus the accepted entry
- L376: Retry pinned: the retry re-signs the entry with the new head as parent (seq / prev / signature all change)
- L383: Re-signing pinned (§12-4): the statement is also re-signed (declared head = the new head before the append)
- L388: Stability pinned: the commitment (the already-generated DEK) stays unchanged across the retry
- L390: Rebuild trigger pinned: the member set changed (other was added), so the wrap set is rebuilt
- L395: Reporting pinned: the completion report's member count is the size of the wrap set actually registered, not the starting view's 1
- L404: Rollback shape (§6.3-2b): post-409 chain shorter than first-seen = rollback; entry not re-signed, wrap set not rebuilt
- L449: Property pinned: no re-signing on the rolled-back view (the send happened exactly once)
- L457: Fixture note: chain grew, member set unchanged — change_role rename isn't allowed, so the head advances via add-then-remove
- L480: Discrimination pinned: entry re-signed (prev changes) but wrap set not rebuilt — HPKE Seal is randomized, a re-wrap would change enc/ct
- L490: Concurrency shape: another run created staging while this one was sending
- L533: Defense-in-depth: args layer rejects the missing positional (usage 2); the handler's undefined guard is a second layer; no HTTP either way
- L555: Early-refusal rationale: waiting for the server's generic 403 would run DEK generation + per-member wraps + signing before refusal
- L589: Fixture note: a scope that pre-disclosed a not-yet-created ID (the consensus rules have no existence check for scopes)
- L605: Complete set pinned: current members (owner) + the in-scope grant's server key; server wrap puts the server-key FP as recipient (§9)
- L615: Interpretation pinned: §6.2 doesn't define empty scope, but the §12-4 check keys on 'environments in scope' — empty = nothing targeted
- L646: Truth discipline: the server's self-assertion is not the source of truth; create_environment always establishes epoch 1, so report 1
- L655: Lying-attestation shape: mock accepts (appends) but lies in the attestation (real server returns 1); chain-derived check still succeeds
- L687: Floor pinned (empty variable set): env meta v1, self-issued manifest v1 (epoch 1), rule (c) baseline = 1, established atomically
- L695: Property pinned: the intent is closed since the effect check (§12-10 (3)) passed
- L702: Lying-2xx shape: returns 200 but never appends to the chain (a malicious or buggy server)
- L725: Floor discipline pinned: the floor did not advance — don't write your own assumptions onto the floor
- L728: Obligation pinned: the check-obligation record (intent) remains unresolved, the next run's reconciliation target
- L740: Acceptance-unknown phase 1: the append happens but the check resync (second fetch) fails — errors out, the intent remains
- L796: Phase 2 pinned: the next run reconciles the intent in its pre-phase via chain sync, confirms acceptance, the floor advances
- L814: Recovery pinned: the reconciliation recovered the interrupted create's self-issued manifest onto the floor
- L820: Property pinned: staging2's own v1 floor and intent resolution proceed as usual
- L833: Guard pinned: don't fire a security-critical mutation without the check-obligation record
- L853: Property pinned: no environment-creation HTTP call occurred (only the chain fetch)

### `apps/cli/test/env-diff.test.ts`

- L1: Scope contract for env diff: metadata-only pull (§3.3), name-sorted output, neutralization, NFC/NFD, floor discipline, skew disclosure
- L64: loadFloor reads the floor (the fold of the observation log) — floor-log.ts's append-only JSONL
- L85: Fixture intent: the 4th entry only builds the shape where both pulls trigger a bounded resync (seq 2 → 3 → 4); not a diff target
- L113: Field semantics: variableOf builds one verified statement; the declared head defaults to genesis
- L130: Mock design: chainHandlerOf advances heads per call ('short at sync → grows via resync'); prefixes cut from the same build
- L153: Position fact: CREATED_AT_SEQ is the seq of create_environment; the manifest's declared head must be at or after it
- L156: pullMetadataHandlerOf serves a metadata-only pull (§12-7) carrying neither values nor DEKs (the manifest is bundled)
- L162: Declared-head rule: larger of creation seq and statements' max declared seq — resync advances the view only to a statement's declared seq
- L198: Parameter semantics: chainHeads is the length of the chain distributed per sync (default is always full length)
- L218: expectNoValueFetches asserts no value path was touched; /pull/metadata returns no values/DEKs, so a suffix match distinguishes it
- L265: Invariant 1 pinned: the value pull / DEK distribution are never touched (pullMetadata only)
- L270: Invariant 5 rationale: the prelude runs once (one chain sync) — per-env syncing would verify twice on possibly disagreeing views
- L279: Skew rationale: envs are read in order, so a mid-run push shows on one side only = fake diff; an un-undoable push must not be believed
- L291: Output discipline pinned: the skew advice is not mixed into stdout (the diff list)
- L296: Zero-diff disclosure: a deletion after the first read shows as present on both, ending at zero diff = a real diff missed; never silent
- L312: Defense-in-depth: declarations check env ID format pre-run, but display does not lean on that invariant (a cast carries control chars)
- L339: Assumption pinned: the env ID is not necessarily verified, nor the warning body neutralized by future producers — whole line neutralized
- L360: Recording rule (§6.3): the verified env-level observation (meta, manifest, coordinate (ii)) is joined — a verified fact is always joined
- L367: Floor discipline pinned: since no value was read, the value floor and the rule (c) pull criterion are never fabricated
- L420: NFC/NFD pinned: byte-different look-alike names are reported as a diff on both sides, with the §12-1 SHOULD warning on the non-NFC side
- L438: Warning scoping pinned: the warning fires only on the side that distributed the non-NFC name
- L445: Folding hazard: the same non-NFC name in both envs gives exactly matching warning wording — folding by set would erase one side's fact
- L464: Fixture state: at sync time only 2 of the chain's 3 entries are distributed, so prod does not yet exist in our view
- L476: Handover pinned: dev's statement is bound to a head beyond our view, so pull 1 advances it via §6.3-2b resync and hands that view to pull 2
- L484: Floor rationale: the advanced head is kept in the floor — staying at the openProject head would leave rollbacks into that gap undetectable
- L489: M1-A3 pinned: no value was read, so no value floor is built (environment-level observation only)
- L495: Shape pinned: both pulls trigger a bounded resync (seq 2 → 3 → 4); stopping at the first view would lose the second's advance from the floor
- L513: Write timing: pull/push write the head to the floor per response; lumping at the end would lose pull 1's resync result if pull 2 fails
- L519: Setup: the second environment cannot be fetched (standing in for network / authorization failure)
- L531: Record pinned: the first pull advanced the floor to seq 3, never left at the openProject-time seq 2
- L537: Emission discipline: carrying warnings in the return value and emitting them at the end would silently lose them on the failure path
- L556: State constructed: a session exists but no device key is in the keychain (a MARUHI_TOKEN run, or a terminal that has not recovered its key)
- L566: schemaVariableOf builds a layout-v3 statement (status / schema specified form)
- L612: Display pinned: v1 (no schema column) stays name-only as before — never fabricate required
- L614: Display discipline: description is never shown in diff output (§2 consumption-point discipline) and the word 'verified' is not used (§14.3)
- L623: Fixture case: a state disagreement (dev = set / prod = declared)
- L628: Fixture case: a required disagreement (dev = required / prod = optional)
- L633: Fixture case: v3 × v1 (prod has no schema column)
- L638: Fixture case: full agreement (not reported)
- L675: Count contract: present-on-both stays as before; contract disagreements are a subset of shared names; values neither fetched nor decrypted
- L742: Spelling pinned: the negated form (--no-new-epoch) is also refused as a spelling of the same option
- L752: Wording capability pinned: create is a nested subcommand, so the diagnostic can say the only positional it takes is environment-id
- L781: Reporting order: subcommand resolution runs before positional checking, so the unknown operation is reported first (exit code still 2)

### `apps/cli/test/env-list.test.ts`

- L1: Scope contract for env list: the set is the verified chain's create_environment entries; status chain-derived (§6.2), fail-closed
- L44: Fixture note: oldStatement is env-old's statement from before its chain deletion (serving it is a resurrection)
- L93: Mock note: listHandler serves the given statements; the server's advisory epoch is a decoy
- L141: Source-of-truth pinned: the epoch is chain-derived (the rotation), not the server's advisory value
- L146: Display pinned: the deleted environment is hidden without --all, and that is said
- L219: Race rationale: the list carries no head, so an omission may be a delete_environment the view hasn't seen; the bounded resync settles it

### `apps/cli/test/env-rename-rm.test.ts`

- L1: Scope contract for env rename/rm (§12-4/§12-5): rename signs over the verified statement, CAS re-signs, deletion terminal, success = effect
- L63: Fixture composition: deletedChain is built plus the owner's delete_environment of ENV_ID (seq 4 — a concurrent deletion)
- L82: Fixture determinism: same steps (Ed25519 signing is deterministic), so the prefix is identical
- L106: startEnv starts the honest in-memory environment (optional handlers first — injected refusals / concurrent changes) and a logged-in CLI
- L138: loadFloor reads the floor (the fold of the observation log)
- L157: deletionBodyOf reads the environment deletion composite's body (AUTH_SPEC §12-4)
- L165: headConflict builds a chain-head CAS conflict answer; the head the mock claims is irrelevant because the client re-syncs
- L186: concurrentRename lands a concurrent rename (metaVersion 2 + manifest chained to v1): material a 409 retry must re-verify
- L214: conflictOnce answers the first method call on the environment once, after an optional concurrent change
- L249: Advance pinned (§4.3): the manifest advances by one, keeps the meta set and copies the new envMeta
- L259: Floor pinned: the confirmation pull joined the new statement into the floor
- L324: Retry pinned (§12-5): prev chains to the concurrent winner (refetched and re-verified)
- L389: Placement pinned: the deletion is a chain entry at the verified head (parent-head CAS)
- L397: §12-4 pinned: no statement or manifest travels with a deletion
- L419: Derivation pinned: the refusals are chain-derived — neither run asked about the environment itself
- L466: Ordering pinned: the record comes before the confirmation line
- L532: Confirmation semantics pinned: the name shown changed, so one line says so; the confirmation binds the ID, so there is no second prompt
- L594: Lost-response shape: the server applies the deletion but the response is lost (gateway error, no server error body) — intent stays open
- L613: Reconciliation pinned: the next run's prologue finds this machine's entry after the declared head and closes the intent as accepted

### `apps/cli/test/env-rotate-composite.test.ts`

- L1: Scope contract for env rotate: composite request (§12-4), exact wrap set, §5.1 signatures, re-encryption (§7/§4.1), interruption recovery
- L110: CAS pinned: parent-head CAS and the entry sits right after the current head (seq = head + 1), actor = the caller
- L116: Payload pinned: new_epoch = current epoch + 1; the reason lands on the chain (§6.2)
- L120: Ghost-member defense pinned (§6.3): wrap targets are exactly the verified current member set
- L125: Property pinned (§5.2): every recipient gets the same new DEK, matching the entry's commitment
- L148: Re-encryption pinned: every active variable is pushed at the new epoch, next version
- L155: Property pinned: plaintext is preserved (decryptable under the new DEK)
- L158: Chain pinned (§4.1): prev is the signed-bytes hash of the verified immediately-prior version
- L197: Refusal placement (§6.3): an out-of-scope environment is refused before communication — before a value-carrying pull (a var.read record)
- L239: Tail identified: the periodic checkpoint after re-encryption completes (standalone, after the boundary's H+2)
- L248: Notarization subject pinned: the data state after re-encryption completed (new-epoch values)
- L261: Permission pinned: effective permission admin (the mock's /auth/me = admin scope), so it notarizes the audit head
- L289: Crash shape: the server falls on the second variable's push (a crash mid-re-encryption)
- L304: Failure plan: only vbb keeps failing throughout run 1 (never recovers even on in-pass retries)
- L310: Run 1 outcome pinned: the rotation was accepted, but re-encryption interrupts at 1 variable
- L318: Resume semantics: run 2 keeps epoch 2, re-encrypts only the remainder, never calls rotate; with --reason, a resumed run must not exit 0
- L331: Disclosure pinned: the resume is made explicit, and the --reason is never recorded on the chain
- L334: Report honesty: a resume is not the requested rotation — the report never hides that no new epoch was made
- L339: Wording pinned: on a run that had a request, it states explicitly 'switched without running the request'
- L381: Consequence pinned: only vbb keeps failing through run 1 = crash mid-re-encryption; run 1 never completes, so no periodic checkpoint issues
- L389: Chain outcome pinned: run 1's tail gains no checkpoint (only the 2 entries: rotate + boundary checkpoint)
- L396: Run 2 pinned: no reason = the guided resume; it re-encrypts the remaining variable and completes, so the periodic checkpoint is issued
- L409: Notarization subject pinned: the data state after re-encryption completed (both variables on the new epoch)
- L464: Reporting pinned: composite accepted = epoch advanced; never end on the raw error — convey 'advanced, re-encryption remains' + resume means
- L467: Wording pinned: all passes spent (each rescan ran), so the remaining count is measured; says neither 'interrupted' nor 'includes unverified'
- L505: Failure plan: pass 1 is a transient 503; from then on it keeps returning 404 (the cause blocking it now)
- L560: Failure plan: vaa is a 502 only on pass 1 (succeeds on pass 2); vbb keeps conflicting to the end
- L572: Cause selection: only the conflicting share remains, so the cause is conflict; the resolved 502 would mislead toward verification failure
- L577: Record pinned: the fact that a now-resolved failure happened is kept as a warning
- L609: Failure plan: let the first pull through, then fail the pass-end rescan (the actual state cannot be checked)
- L617: Assertion discipline pinned: the conflicting share may have been resolved by another member, so it is never asserted

### `apps/cli/test/env-rotate-config.test.ts`

- L48: Section design (SY2 2b — M1): rotated env (dev) + receipt env (ops, epoch 1) in one mock: rotate → receipt write → sync on shared state
- L69: Fixture composition: genesis + create dev (epoch 1, dek1) + create ops (epoch 1, dekReceipts)
- L98: Fixture composition: the rotated environment's 2 variables (DATABASE_URL v1 / API_KEY takes a version)
- L124: storedReceipt builds the existing receipt placed in the receipt environment (the previous sync's result)
- L164: Fixture composition: the default config is a Vercel target web synced from dev; the receipt is ops
- L185: Field purpose: before handlers are injected at the front (e.g. injecting a receipt-environment write failure)
- L198: Handler order pinned: the rotated environment's handlers go first (the chain follows makeServer's mutable current form)
- L224: receiptVariablesOf decrypts the receipt environment's latest receipt and returns the variable mapping
- L254: Write discipline: re-encryption is the 2 variables' new versions (values unchanged); the receipt is written as a new version exactly once
- L262: Leak pinned: no plaintext appears in the output (the receipt carries only names and versions)
- L266: Idempotence pinned: the plan after that is all unchanged; apply has nothing to write (never writes twice)
- L296: Counting method note: since it cannot be injected after startFixture, receipt-environment reads are counted via the server's records
- L308: Consequence noted: since nothing advanced, the plan is all changed (harmless — the next apply rewrites the same plaintext)
- L320: Fixture move: API_KEY was pushed once more after the sync to version 2 (the receipt stays at 1)
- L331: Version discipline pinned: DATABASE_URL's receipt stays at 1 (advancing to 3 would hide version 2's unsynced diff)
- L353: Fixture state: DATABASE_URL has not reached the sync destination (absent from the receipt); API_KEY is lagging
- L379: Shape identified: the 'winner another member wrote on the new epoch' visible on the re-fetch after the 409 (the plaintext differs)
- L411: Resume scope pinned: on the resume path (unfinished against epoch 2) only DATABASE_URL is re-encrypted by us
- L419: Visibility pinned: the winner's plaintext was never synced, so plan shows update (never hidden)
- L452: Failure plan: only vbb keeps failing throughout run 1 (never recovers even on in-pass retries)
- L461: Isolation pinned: run 1 has no --config, so the receipt is untouched
- L464: Advance rule: run 2 = resume + --config — only API_KEY advances; DATABASE_URL has no 'unchanged' evidence this run and is left untouched
- L483: Fixture arrangement: the receipt sits on dev and the sync source is ops (the value environment, pinned at epoch 1)
- L524: Treatment pinned: the receipt variable itself is re-encrypted like a normal variable; no receipt is written
- L529: Consequence pinned: the new-version receipt's contents are unchanged, so plan is unchanged
- L569: Failure plan: only web's receipt write is failed
- L603: Failure plan: only the chain fetch after re-encryption finished (the cleanup resync) is failed
- L617: Guidance pinned: the guidance after the cleanup (the anchor update) also comes out
- L669: Setup: first establish the receipt environment's floor via plan (records version 2 as verified)
- L673: Attack shape: the server redistributes an old version (a rollback)
- L679: Reporting order pinned: the rotation itself is done (its report comes out first); the evidence never morphs into 're-run apply'
- L684: Ordering pinned: since the epoch advanced, the anchor-update guidance comes out ahead of the evidence
- L701: Rollback shape: after re-encryption it serves a shorter chain on the same genesis (no rotate) — verifies, yet not an extension of the view
- L744: Forgery model: serves a value with a broken signature (models a forged distribution)
- L768: Future-format shape: an unknown layoutVersion (a future CLI's statement, v3 fields present) is rejected before signature verification
- L785: Mock note: the mock's manifest is built from the original statement so its assembly doesn't trip on the layout; CLI rejects at verify

### `apps/cli/test/env-rotate-conflict.test.ts`

- L1: Scope contract for env rotate (conflict file): pillars 3 (recovery) and 4 (CAS/concurrent/partial/authz); mock mimics real transitions
- L63: Equivocation shape: the winner's prev doesn't point at the verified v1 hash = diverged history; our signature never chains into it
- L103: Warning preservation pinned: even on abort, collected warnings are not lost (the no-floor proviso matters most exactly on abort)
- L105: Classification pinned: cryptographic evidence is never collapsed into partial completion + resume guidance; it aborts at once (as push)
- L144: Timing shape: right after the final pass's (3rd) conflict, another member's current-epoch write settles
- L183: Deletion form pinned (§12-5): the deletion is a tombstone (status deleted, metaVersion + 1) + deletion of all versions
- L214: Race shape: another member deleted it right before the re-encryption
- L226: Target-set pinned: the deleted variable drops out of the target set; the rest are re-encrypted
- L229: Cause lifecycle: the 404 is the abort's cause, and at completion becomes a 'happened but resolved' warning — never morphs into 'conflict'
- L235: Morphing hazard: 'refuses 404 yet distributes as active' is neither deletion nor conflict; unrecorded, the report would morph to conflict
- L305: Lying-server shape: claims 'latest is version 9' yet distributes only version 1 on re-fetch
- L342: Stuck shape: 409 every time; even on re-fetch the latest value stays on the old epoch, so re-encryption never completes
- L349: Report honesty pinned: it never ends with a 'completed' face (the summary itself declares partial completion)
- L355: Disclosure pinned: it explicitly states that old-epoch DEK holders can still read the current values
- L360: Guard scope: first sync sees 3 entries, statement declares seq 4 → bounded resync; the resume path never builds the wrap set, guard skips it
- L396: Serving plan: first serves 4 entries without the removal (runner is a member, epoch 2); the resync serves 5
- L446: Property pinned: even on the resume path it never proceeds to writing
- L472: Contradiction shape: the chain stays at epoch 2, yet the server claims an epoch conflict every time
- L479: Classification pinned: never report 'another member rotated' while the chain-derived epoch is unchanged — a contradictory response
- L497: Hidden fact: behind the claim, another member wrote everything on the same epoch
- L529: Decision basis: re-encryption completion is decided by the verified actual state, not the server's self-claim
- L536: Treatment pinned: the contradictory claim itself stays as an investigation target, but no abort
- L542: Reporting hazard: vaa resolved by another's write, only vbb remains (502) — 're-run won't resolve' would strand a re-runnable state
- L591: Timing shape: simultaneously with the claim, another member's current-epoch write settles
- L602: Wording discipline: the contradictory claim stays an investigation target (no abort) and never says 'confirmed everything is in place'
- L607: Path pinned: an abort would never reach partial-completion reporting, so neither the remaining count nor resume guidance would come out
- L636: Race shape: the first sync is epoch 2; mid-re-encryption another member advances to epoch 3
- L687: Classification pinned: the forced resync confirmed the chain actually advanced — not a server contradiction (a benign race, not foul play)

### `apps/cli/test/env-rotate-deletion-race.test.ts`

- L1: Scope contract for the rotate/delete race: stale head answered 409, re-synced chain carries the deletion; refusal is deletion-derived (§6.2)

### `apps/cli/test/env-rotate-failure.test.ts`

- L1: Scope contract for env rotate (failure file): pillars 3 (recovery) and 4 (branches); mock mimics real transitions, crash → resume end-to-end
- L45: Security rationale: the member-removal run — if one unopenable value stopped the epoch advancing, the removed member's old DEK stays valid
- L73: Fixture fact: no wrap addressed to self at epoch 1
- L85: Outcome pinned: the epoch did advance (the revocation itself is achieved)
- L88: Split pinned: openable values go to the new epoch; unopenable ones are reported unfinished
- L96: Dangerous state: lost response (502/timeout) — DO accepted it, client sees only the transport error; raw error hides the epoch advance
- L126: Mock behavior: accepts it (appended to the chain), but the response returns 502
- L135: M1-A4 pinned: once the self commitment is confirmed matching on-chain, the floor (self-issued manifest) advanced even if the command errors
- L143: Closure pinned: with the effect confirmed, the intent (3-F) is closed too
- L148: Hazard pinned: a member with no wrap addressed to them — epoch-only advance leaves every value under the old DEK, no revocation achieved
- L175: Substitution shape: the epoch reached the target, but what landed is another member's DEK commitment — our rotation was never accepted
- L191: Timing shape: the send is a 502; behind it, another member has already rotated to epoch 2
- L201: Wording pinned: it never reads as our share having been accepted
- L203: M1-A4 pinned: the on-chain commitment differs, so the floor never advances; non-acceptance confirmed, intent closes as not-accepted
- L212: Judgment basis: another member rotates further before confirmation; per-epoch commitments remain, so our share is distinguishable
- L229: Timing shape: accepts it (our entry lands on the chain) but the response is 502; after that another member advances further to epoch 3
- L241: M1-A4 pinned: even when overtaken, our manifest (v2) stays as the minimum floor
- L251: Shape pinned: 200 returned (acceptance certain), another member reached epoch 3 first; errors 3 ≠ 2, yet our epoch-2 floor advances
- L290: Defense in depth: honest server answers a rotate over a pre-deletion view with 409 (§12-4); a 404 is re-synced too, chain has deletion
- L329: Probe discipline: rejection in the server's error body = acceptance definitively known, no probe needed; a 404 is definitive and recurs
- L363: Wording pinned (§7): the dedicated message comes out, never collapsed into the generic 'environment not found'
- L371: Fetch count pinned: no acceptance probe — the first sync plus the one re-sync checking whether the 404 is an unseen delete_environment
- L393: Failure plan: the chain re-fetch for confirmation also fails (the connectivity failure persists)
- L402: M1-A4 pinned: a probe failure = acceptance-unknown — never written to the floor (no advance); the intent (3-F) stays for the next run's sync
- L437: Assertion discipline: the chain still sits at the declared head, so a request in transit could land later — never asserts 'not accepted'
- L441: Intent pinned (3-F): the intent is left unresolved rather than settled; the match after the chain moves settles accepted / rejected
- L467: Guard pinned: a security-critical mutation is never fired without a confirmation-obligation record
- L473: Classification pinned: a self-addressed wrap exists yet decryption fails = ciphertext swap; never a benign 'waiting for a wrap'
- L506: Guidance pinned: never treated as a benign gap — no means to step over it is offered
- L512: Dangerous case: it appears after the epoch advanced — treating it as a transient rescan failure would morph it into resumable completion
- L529: Evidence shape: an old-epoch value absent from pull 1 appears after acceptance (rescan); rule 2 (§6.3) rejects it as backdated creation
- L565: Distinction pinned: unlike the first-pull case, the rotation itself did happen here
- L568: Classification pinned (PR-M3): rejected as evidence of rule-2 backdated creation
- L571: Guidance pinned: never demoted into 'a re-run will clear it' style guidance
- L577: Transitional state (§12-7): a member holding the epoch-2 wrap but not epoch 1's (added after the rotation / epoch-1 re-wrap unregistered)
- L605: Fixture fact: no wrap addressed to self at epoch 1 (only epochs 2 / 3)
- L614: Split pinned: the 1 unopenable value is reported unfinished, but the 1 openable one is pushed
- L623: Wording pinned: the cause never morphs into the default wording (conflict)
- L626: Dedup hazard: the same variable's warning appears once — if the wording split between resume path and rescan, dedupeWarnings would pass both
- L645: Shape identified: the 'on the current epoch but prev does not connect' successor visible on the rescan after the 502
- L667: Classification note: a transient failure rather than a 409 (this variable never enters the conflicted set)
- L713: Disclosure pinned: first sync (no floor) — the target set's only provenance is the server response, so a consistent omission is undetectable

### `apps/cli/test/env-rotate-report.test.ts`

- L1: Scope contract for env rotate (report file): pillars 3 (recovery) and 4 (branches); mock mimics real transitions, crash → resume end-to-end
- L77: Push-back shape: vcc is made to conflict into pass 2; vbb's accepted write (version 2) is never reflected — the rescan keeps it at version 1
- L82: Mock behavior: it accepts but never persists (the shape where the server swallows our write)
- L92: Detection pinned: fail only the floor commit of the accepted push — the floor is a SHOULD; detection must work even when unwritable
- L97: Evidence pinned: even without a floor, regressing from a version we signed is evidence of a rollback
- L104: Dedup pinned: a non-NFC name warns on every pull — still one line across 3 passes
- L182: Ordering rationale: only the leading variable always fails; the order is stable, so aborting would strand later variables on every re-run
- L192: Scope pinned: the 2 following variables did move to the new epoch (the partial completion is the poison variable only)
- L198: Cause-collapse hazard: conflicting vbb written out by another on pass 2, only unopenable vaa left; defaulting to 'conflict' misleads
- L239: Fixture fact: no wrap addressed to self at epoch 1 (= vaa cannot be opened)
- L245: Timing plan: vbb keeps conflicting, but another member writes it out on the current epoch after pass 2
- L263: Rescan design: the pushable target keeps conflicting so passes run out; the final rescan never decrypts (no never-pushed plaintext)
- L295: Fixture fact: no wrap addressed to self at epoch 1 (= vaa cannot be opened)
- L301: Fixture plan: vbb keeps conflicting to the end (a push target remains on every pass, so it never aborts)
- L307: Path pinned: no push accepted (409 every pass); vbb stays a pushable target every pass, so no abort — reaches the final rescan
- L318: Guidance rationale: a member who joined after the interrupted rotation has no current wrap — resume impossible, but --new-epoch works
- L353: Surfacing pinned: only 1 item is raised as the cause; dropping the rest would leave a failing variable's reason (too-large value) unsurfaced
- L386: Retention pinned: both reasons remain with variable names, even though only one reaches the cause field
- L392: Guidance consistency: with no self-addressed wrap, even --new-epoch is rejected by ensureRotationIsUseful; recommending it contradicts
- L420: Scope split: invocation mistakes are owned by the shared check (args.test.ts); here the env-specific applicability — rotate fails the same
- L431: Hazard pinned: a misspelling — left alone, the intent 'always a new epoch' silently falls to the weaker resume path
- L436: Refusal pinned: a create-only option passed to rotate is also refused (the env-specific check)
- L441: Interpretation pinned: effect/cli reads both the inline (=false) and space-separated forms as the boolean's value — not mistakes
- L451: Consumption pinned: the value is not dropped into an extra positional arg — it is consumed as the flag's value
- L453: Mix-up hazard: writing the positional's name as an option is refused without discarding the value; an env ID is unique across history (§6.2)
- L465: Check placement pinned: the mix-up check runs before any communication (never leaves a var.read under the wrong ID)
- L467: Derivation pinned: the allowed set derives from the argument table (no hand-written list to drift) — pinned to succeed, not just not-refused
- L478: Communication pinned: on the refused examples no HTTP happens at all (only the 2 normal-run examples communicate)
- L516: Complete set pinned (§7 re-wrap): current members (owner) + the in-scope grant's server key — without the re-wrap the lease path stops
- L525: Scope judgment (§3, §6.2): epochs advance per environment; a dev-only grant blocking prod's rotation would stall member removal
- L572: Reach pinned: it never even reaches a pull (a var.read record)
- L584: Guidance landing: where the partial-completion re-run lands; requiring --reason here would demand one from the guided user (and re-rotate)
- L601: Check placement: --new-epoch always signs, so a reason is mandatory; refused before the session opens — no ciphertext fetch, no var.read
- L621: Unset shape: --reason "$UNSET_VAR" — as unspecified, a removal script would believe a new epoch was made while nothing was sent
- L631: Empty-form pinned: a whitespace-only value is also failed as empty by the shared check (the unset form of "$VAR" can become "" or " ")

### `apps/cli/test/env-rotate-retry.test.ts`

- L1: Scope contract for env rotate (retry file): pillars 3 (recovery) and 4 (branches); mock mimics real transitions, crash → resume end-to-end
- L46: Fixture fact: already re-encrypted to epoch 2 (declared head = the rotate entry itself)
- L80: Exit-code contract: the guidance says 're-run to resume without advancing'; a guided run (no reason) exits successfully once nothing is left
- L91: Lineage pinned (§12-5, §4.1-5): the re-encryption push declares sameValueAs = previous version, so it doesn't resolve the rotation flag
- L97: Wording pinned: never tell a run that requested nothing 'switched without running the request'
- L115: Window shape (§12-4): between pull 1 and acceptance another member creates an old-epoch variable; server 422s, retry lands it in target set
- L159: Target-set pinned: vlate, created in the window, also enters the retry's target set and completes only after re-encryption
- L164: Notarization pinned: the retry's boundary checkpoint notarizes the value set including vlate
- L206: Distinction pinned: not a resume but a rotation — an epoch-3 entry is made, old-epoch values go straight to epoch 3 without the middle epoch
- L213: Lineage pinned (§12-5): a forced rotation's re-encryption push also declares the lineage
- L281: Reuse pinned: re-signed (timestamp/signature change), but the DEK's commitment and wrap set are reused as-is for the same epoch
- L314: Retry shape (F-2): a 422 from the boundary checkpoint's digest match = concurrent push; re-signing can't resolve it — restart from a pull
- L348: Discard safety: a pull-restart generates a new DEK — the previous composite was never accepted, epoch never advanced, so it is safe
- L351: Bundle pinned: the boundary checkpoint is bundled on the retry too (the value set is unchanged, so the digest is identical)
- L360: Cross-layer pinned (3-F × F-2): attempt 1's intent closes by the 422, attempt 2's by the acceptance check — none left unresolved
- L393: Bound pinned: abort after the bound (3 attempts) — never pulls forever
- L400: Cross-layer pinned (3-F × retries): 422 = definite rejection, so all 3 intents close as rejected; the floor stays at mv1 from pull 1
- L415: 2-G' consequence (§4.3 (2)): the manifest verifies only on exact match with the boundary tuple (no H+1 exception); hiding is detected
- L445: Detection point pinned: the composite itself is accepted; detection happens in the post-acceptance rescan pull's verification
- L448: Independence pinned: the acceptance check (self commitment on-chain) holds without the checkpoint, so the floor promotion (M1-A4) happens
- L466: Serving plan: from the second sync on, the other member's rotate_epoch is stacked
- L520: Stop pinned: it stops the moment the concurrent rotation is detected (never resends to the bound)
- L535: Winner shape: 'winner another member wrote on the new epoch' seen on the re-fetch after the 409; an honest writer chains prev into v1
- L562: Mock behavior: returns the 409 after settling the state where the concurrent push's winner won
- L570: Outcome pinned: the winner was accepted on the current epoch = re-encryption unneeded; it never goes to overwrite

### `apps/cli/test/failure.test.ts`

- L1: Test-scope contract for failure.ts's toCliError: the terminal neutralization of server-sourced strings
- L18: Guidance rationale: expiry folds into the same 401 as revocation (never distinguished on the wire), so guidance names both + re-login
- L26: Case: 429 ProjectLimit (org project-count cap — only on new init)
- L31: Case: 422 DataLimitExceeded project-storage-bytes (DO total-storage guard) — guidance says delete / read still work under the refusal
- L41: Case: 422 DataLimitExceeded environment-ciphertext-bytes (Sc-3) — freed within the environment
- L48: Case pinned: other §12-8 quantity caps keep the conventional general form
- L54: Attack surface: Schema.String fields are unconstrained on the wire (a malicious server could embed ANSI / newlines)
- L64: Fallback design: all three typed failure kinds are mapped, so only a true unknown reaches here; its message may carry body fragments
- L74: Trail rationale: narrowing the unknown fallback doesn't erase the connection-failure trail — transport failures are explained by name
- L85: Property pinned: the lower cause's text (host, port, etc.) is not passed through
- L90: Upstream-format pin (rc.109): formatting shows only the expected type and location; the body can carry names/ciphertext — values would fail
- L103: Guidance pinned: request-encode failures use the same channel (direction invisible from the type), so guidance lists both directions
- L106: Rendering pinned: newlines are folded into one line before neutralizing (so replacement chars do not make it unreadable)

### `apps/cli/test/floor-detection.test.ts`

- L1: Scope contract for floor wiring (§6.3 (a)(b)(c)): swap mocks against the same TestEnv/floor; tampers carry valid signatures from real keys
- L50: Fixture composition: chain1 = [genesis, create_environment] (epoch 1)
- L52: Fixture composition: chain2 = chain1 + rotate_epoch(2) (a strict extension of chain1 via deterministic builds)
- L54: Fixture composition: chainB = same genesis, but a different chain branched at seq 2
- L77: Branch fact: chainB branches from the same genesis at seq 2 (the create's DEK commitment differs)
- L109: valueOf takes the variable value with the correct declared head per epoch (epoch1 = create, epoch2 = rotate)
- L165: Field semantics: manifestVersion is the bundled manifest's version (advance it when the meta set changes between phases)
- L167: Field semantics: prevManifestSigHashHex is prev for manifestVersion > 1; unspecified = the fixture's dummy
- L184: manifestOf computes the manifest from the distributed set itself (§12-7); Ed25519 is deterministic, so recomputation is byte-exact
- L202: prevOfPhase returns the previous phase's manifest signed-bytes hash (chaining material for the next version's prev)
- L211: Handler behavior: advances on each call (the bounded resync for a future head reveals the next chain)
- L255: pullMetadataHandlerFor serves a metadata-only pull (§12-7 — push's name-resolution path)
- L275: startPhase starts a new server phase against the same TestEnv (= the same floor)
- L288: readFloorFile reads the floor (the fold of the observation log); the log is append-only JSONL (floor-log.ts)
- L298: readFloorRaw returns the floor log's raw bytes (for checking non-confidentiality / evidence preservation)
- L303: establishFloor establishes the floor in phase 1 (an honest distribution) and verifies pull succeeds
- L329: Diskless invariant pinned: the floor log never contains plaintext values / variable names
- L344: Corruption boundary: whole-file corruption with no parseable record (a partially torn line is not corruption but a self-recovery target)
- L385: Evidence contents pinned: the fork evidence carries the floor-side and distributed-side signed-bytes hashes, declared head, coordinates
- L390: Evidence hygiene pinned: the plaintext value is not in the evidence
- L396: Prototype-collision pin: a §12-1 ID colliding with an Object.prototype name ('constructor') — a bare lookup resolves absent IDs to Function
- L502: Tamper shape: an environment statement at the same metaVersion 1 differing only in name (valid signature)
- L521: Coordinate pinned: the environment meta's evidence coordinates stop at the environment (no variable=)
- L539: Monotonicity shape (§4.1): version 4 > floor 3 but epoch 1 < floor's epoch 2 = a monotonicity violation
- L567: Resync outcome: still chain1 after the resync (the second chain fetch) = a true shortening
- L583: Setup state: the floor is already established through chain2 (seq 3)
- L594: Race shape: first sync grabs the old view — a sibling advanced the floor in between, so the shortening resolves via a single resync
- L624: Phase 2 plan: drop BETA from the distribution (selective trimming), likewise on the metadata pull — the floor's meta check is the target
- L696: Phase 1: pull on the epoch-1 chain (criterion = 1)
- L702: Legitimate state (rule (c) edge): chain rotated (epoch 2) but v2 (epoch 1), pushed before the rotate, still latest — no false refusal
- L713: Assembly note: the adjacent version's (v2) prev is strictly verified against the floor's manifest hash, so a legitimate chain is assembled
- L722: Shape: the rotate composite has already re-issued the manifest (§12-4)
- L728: Atomicity pinned: after verification succeeds, the criterion has advanced to 2 atomically with the variable floor
- L733: Phase 3 shape (rule (c) edge): under criterion 2, a v3 newer than the floor's version at epoch 1 = forward injection by the old key
- L748: Fixture note: the meta set is identical to phase 2, so the same v2 manifest is distributed (byte-exact)
- L763: Setup: establish a criterion-2 floor (the post-rotate chain)
- L774: Injection shape: a new variable 'created' after the previous pull at epoch 1 = below the criterion (creation is at the current epoch)
- L790: Shape pinned: 'vc was created' with the manifest also advanced (adjacent, prev chains) — a check independent of prev verification
- L819: Replacement shape: different content under the same version 1 (fresh nonce, different plaintext) — signature valid under the legitimate key
- L882: Shape: the deletion meta op already re-issued the manifest (§12-4); the adjacent prev is strictly verified against the floor's v1 hash
- L911: Terminal state: a deleted variableId distributed as active is refused regardless of metaVersion — deleted is terminal
- L960: Branch shape: chainB shares genesis, branches at seq 2, and is longer than the floor (3) = a branch, not a shortening
- L978: Resync shape: declared head seq 3 (post-rotate) is beyond our view (chain1); the resync reveals chain2 (an extension) — accepted
- L993: Shape: the rotate composite has already re-issued the manifest (§12-4) (an adjacent version — satisfies the prev chain)
- L1002: Criterion timing (§6.3, resync path): rule (c)'s criterion derives from the pre-fetch view (epoch 1); a sync alone never advances it
- L1021: Forgery shape: declared head seq 3 beyond chain1, but the chain stays chain1 after resync = bound to a nonexistent head
- L1052: Phase 1 flow: push (metadata resolution → v1 verified by a value-bearing pull → v2 accepted)
- L1068: Criterion pinned: the rule (c) criterion does not move on push (stays at pull time)
- L1071: Phase 2 shape: the server distributes the pre-push v1 (a rollback of your own write)
- L1083: Non-guarantee pinned (§4.2): a meta statement has no epoch anchor, so no value-side rule (c) exists; the floor detects rollback only
- L1096: Non-guarantee shape (§14.3-5): forged metaVersion 2 as next of the latest (valid signature, interval key + server collusion) — floor silent
- L1109: Non-guarantee extended: a colluding injection can also advance the manifest and chain prev correctly (server knows the hash) — unchanged
- L1123: §14.3-5 pinned environment-side too: forward injection holds for any meta where the attacking key held author credentials in its interval
- L1148: Shape note: the same shape as the variable side — the manifest advances with it (§14.3-5; the colluding server can chain prev correctly too)
- L1160: Intent-judgment rationale: a CAS retry re-signs with the same DEK; judging a refused attempt 'accepted' on commitment alone corrupts floor
- L1174: Matching note: the accepted intent shares the hash of the v2 manifest the pull distributes (the re-issued rotate composite) — bundled
- L1184: Case (a): the accepted attempt — declared head = seq 2 (right after create), so slot seq 3 holds this intent's rotate entry
- L1198: Case (b): the refused old attempt — same commitment, declared head old (seq 1), its slot (seq 2) holds a different entry = can never land
- L1213: Case (c): the intent awaiting landing — declared head = current head (seq 3), slot seq 4 empty = could be in transit; never settle it
- L1245: Promotion pinned: only the accepted attempt's manifest is in the floor; the old attempt's hash is not promoted — no typed conflict
- L1253: Residue pinned: only the pending intent remains as needing reconciliation
- L1262: Phase 1 scope: project verify (chain floor check + head advance only; no environment floor)
- L1269: Phase 2: pull establishes the environment floor (including the rule (c) criterion)

### `apps/cli/test/floor-log-decode.test.ts`

- L1: Scope contract for the floor-log decoder (§6.3): a non-strict line is ignored by fold; every reject case mutates exactly one field
- L33: UNSAFE_TOKEN is a sentinel replaced in the JSON text, so a literal the JS number type cannot hold survives
- L85: VALID holds one valid record per r kind (§6.3's observation / ledger / snapshot records)
- L116: withField sets value at path in a deep copy of base (undefined deletes the key)
- L135: withProtoKey defines a JSON property named __proto__ (an own key, as JSON.parse produces it)
- L194: Binding pinned: a deletion intent still binds the declared head (the slot it reconciles against)
- L476: Anchoring rationale: decoded types derive from the Schema; these checks anchor them to floor.ts's hand-written types (mutual assignability)

### `apps/cli/test/floor.test.ts`

- L1: Scope contract for the floor (§6.3): append + fold's monotone join, typed conflicts keeping both evidence pieces, torn-tail recovery
- L93: Counting rule: past the snapshot threshold the torn line enters the folded prefix and is no longer counted (only post-fold records warned)
- L134: Join scope pinned: the other environment's floor is preserved (the join is per-environment)
- L183: Semilattice pinned: each coordinate is independent — pull baseline and env meta stay bottom while only the variable floor stands
- L236: Join pinned: the manifest's epoch also joins into coordinate (ii) (observedEpoch)
- L239: Rule (c) pinned: the pull baseline does not move (a chain sync or acceptance check alone never advances it)
- L248: Concurrency shape: 2 processes depart from the same old floor and commit independently
- L309: Conflict rule: a later same-version differing-hash does not 'win last' — typed conflict (append-only; overwriting is inexpressible)
- L322: Preservation pinned: both observations remain in the log (append-only — the earlier evidence doesn't disappear)
- L395: Terminal-state pinned: the representative stays deleted (the terminal state isn't overwritten by active)
- L404: Concurrency setup: process B has already committed a newer generation (pullEpoch 3, va v5)
- L427: Concurrency setup: process A's older pull (pullEpoch 2, va v3, with vb's tombstone) lands later
- L442: Union pinned: a variable present on only one side (vb) is kept by the union
- L457: Crash shape: a concurrent process crashing mid-write (a partial line with no trailing newline)
- L463: Recovery pinned: the next append prepends a newline to isolate the torn line — the new observation lands correctly
- L527: Setup intent: create one conflict (pins that the evidence survives across the snapshot)
- L537: Append discipline: stacking past the threshold (4 records) — commits onto a conflicted floor keep failing, but appends still happen
- L549: Fold semantics pinned: after the snapshot lands, fold's semantics are unchanged (the conflict doesn't disappear)
- L553: Append-only pinned: no physical collection — all records still remain in the log after the snapshot (no torn rewrite occurred)
- L585: Failure shape: place a directory at the floor log's path (readFile → EISDIR)
- L590: Write-path pinned: the write path also aborts (don't create a silently dead floor)
- L611: Concurrency setup: the sibling process has already established vb's tombstone (after this process's openProject)
- L620: Staleness setup: this process's handle starts from the stale snapshot (no floor)
- L646: Adoption pinned: the folded floor — not the sent snapshot — is adopted: tombstone, newer va (v3), higher baseline carry to later checks
- L676: Join pinned: coordinate (ii) advances under the same join too
- L702: Idempotence pinned: a double resolution is a no-op (no extra resolution is logged)
- L721: Parsing setup explained: an append prepends an isolating newline — the first non-empty line is the record
- L725: Storage pinned (§6.3): only hashes, counters, and op kinds are stored

### `apps/cli/test/guardian.test.ts`

- L1: Scope contract for guardian commands (§8.3/§13-7, KL3, DK K4): wrap target B is the reserve key, not a device key; §6.5 ceremony per device
- L52: Fixture identity: reserve is ward's reserve key (the B the ledger seals — a different key from the device key ward)
- L104: recordOf builds the ledger / reserve-key record (same shape as seedSession)
- L112: DK K16 marking: the test's reserve is a CLI-generated reserve key (marked); everything else is a device key
- L118: serializedReserve is the serialized reserve-key record (the wrap's plaintext = the value the opened wrap must equal)
- L123: recoveryHandler serves GET /auth/recovery: the ledger — ward's reserve-key record wrapped with the recovery code (unsealed first, K4-2)
- L133: Construction trap noted: JSON.stringify(record) won't work — the secret side gets wrapped in redactions (same trap as recovery.ts)
- L164: createCount counts the registration sends (for the check that must fail before sending)
- L171: lastWordOf returns the final word of the guardian's fingerprint (the §6.5 ceremony response)
- L186: openShareAs has guardian user open the share addressed to them (same shape as the server's share distribution)
- L229: Order pinned: ceremony (the guardian's final word per device) → unsealing the ledger (recovery code)
- L236: Shape pinned: one share row per guardian device (the fixture's guardian has 1 device)
- L242: Mode semantics pinned: any — share = the KEK itself; the wrap's contents are the ledger's reserve key, not ward's device key
- L249: Fetch pinned: the ledger is unsealed once (GET /auth/recovery)
- L253: Display pinned: the ceremony display is the word list (stdout); key material and the code appear nowhere
- L294: Threshold pinned: a single share alone cannot open it (all mode)
- L315: Ordering pinned: if the ceremony doesn't pass, it never reaches unsealing the ledger (code entry)
- L351: Refusal pinned: the piped-stdin form of answering the ceremony prompt (non-terminal) is also refused

### `apps/cli/test/handoff.test.ts`

- L1: Scope contract for the reserve-key handoff (§8.4/§13-7): requester prints the code (E.pub = public) to stderr, stores no B, E.pub never sent
- L63: Fixture identity: reserve is ward's reserve key (the B the ledger seals — a different key from the device key)
- L87: recordOf builds the key record the ledger holds (same shape as seedSession)
- L95: DK K16 marking: the test's reserve is a CLI-generated reserve key (marked); everything else is a device key
- L127: displayedCode extracts the handoff code the requester printed to stderr (4 chars × 15 groups = 58 symbols + separators)
- L136: decodeDisplayed recovers E.pub and request_id from the code (the same derivation as the approver side)
- L148: ApprovalWire is the approval's distribution form (HandoffApprovalResult — no blob column)
- L159: wrappedReserve builds the ledger's group wrap (ward's reserve key B wrapped under the KEK — any: the KEK is the only share)
- L176: guardianApprovalFor builds the approval server-side: re-seals the share (KEK) to the E.pub from the requester's display (human-carried)
- L226: aliceAnyGroup builds an any group of alice alone (ledger state — share rows are per device)
- L242: Handler contract: POST /auth/handoff receives only request_id (E.pub never rides along)
- L250: Mock behavior: GET /auth/handoff/:id/approvals returns the built approvals regardless of the path's request_id
- L258: Handler contract: GET /auth/key-wraps/guardians/:groupId is the ledger's group wrap (carries no shares)
- L274: Handler contract: GET /projects is the project list the recovery tail scans (empty = nowhere to register)
- L287: Ledger setup: ward's reserve key B wrapped under the KEK, and the KEK (= the any share) already sealed to alice
- L307: Prompt setup (DK K14): the recovery tail's single confirmation question (the reserve key is a key ward's device added via add_device)
- L311: Wire pinned: request_id matches the code's derivation, and E.pub itself was never sent
- L316: Storage pinned: the keychain gets the new device key; the ledger's reserve key (B) is not stored
- L342: DK K16-3 / K16-6 pinned: a key marked as a reserve key is recorded without asking
- L348: Leak pinned: no key material appears in the output
- L351: Cleanup pinned: it fetches the ledger wrap and deletes the request that served its purpose
- L366: Mismatch shape: the sealing context's approver (ward) differs from the attested approver (alice), so it cannot be opened
- L396: TTL mechanics: 2-second TTL — round 1 fetches while valid, parks in the 3s wait; the round past the deadline ends without fetching
- L414: Timing pinned: one fetch lands while valid; the next wake lands past the 2s TTL, so the round past the deadline is the terminal one
- L453: makeRequester builds the requester's ephemeral key and code (the test plays the requester)
- L467: ApproveBody is the approval's payload (HandoffApproval — no blob column)
- L476: lookupOf builds the lookup response (roles is only the guardian-share shape — the legacy 'device' is gone)
- L497: sealedShareFor builds the ledger's share (the KEK sealed to guardian's device key)
- L519: myShareHandler serves GET /auth/guardian/shares/:groupId: the leading row's fields plus deviceShares (all of your device rows — K3-10)
- L547: Ledger setup: a share row for alice's device key and a dummy row for another (e.g. revoked) device
- L600: Leak pinned: the share, KEK, and secret key never appear in the output
- L611: Row shape: only a row addressed to alice's other device (no row with this device's FP)
- L634: Local-refusal pinned: even if the server wrongly shows the request to ward themself, refuse locally
- L694: Tamper shape: well-formed but undecryptable — one flipped ciphertext character (e.g. the ward sealed to a previous key of this device)

### `apps/cli/test/help.test.ts`

- L1: Scope contract for --help consistency (DP5 ruling F): every command level + bare maruhi pinned against the golden file; one verb-led line
- L30: Output discipline pinned (ADR-0016 decision 9): help does not pollute stdout
- L72: Extraction rule: the line right after DESCRIPTION is the description; it starts with a capitalized verb (sentence case)

### `apps/cli/test/identity-backing.test.ts`

- L1: Scope contract for the github-signing-keys source (§6.5, IV2): sends only the login with a fixed host, fails closed as types, never CliError
- L61: Literal decoded: 2100-01-01 (outside the near-expiry warning window)
- L67: saveConfirmation returns the correct answer to the recovery-code save confirmation (the final group from the shown stderr)
- L102: Wire pinned: only the login is sent (no query, no body)
- L122: Classification pinned: a malformed login never even issues the query (treated as impossible)
- L201: Semantics pinned: EOF (answers exhausted) also means 'do not register'
- L216: Agent discipline pinned: an agent environment performs neither recovery-code issuance nor the registration prompt for you (guidance only)

### `apps/cli/test/installer.test.ts`

- L1: Scope contract for the installer: pins install.sh and the Homebrew formula to the target table — three copies of the table can drift
- L40: Drift rationale: if producer (build-binaries.ts) and fetcher (install.sh) disagree on naming, it surfaces as a 404 in the real-OS tests

### `apps/cli/test/invite-anchor.test.ts`

- L1: Scope contract for the invite-link anchor cross-check (§6.3 (a)/§6.5): first sync after add_member checks pinned head inclusion + inviter FP
- L60: memberEnv builds the accepted chain (genesis → the acceptor's add_member) and the acceptor's session
- L106: Message discipline pinned: the second time doesn't repeat the success message (the check itself runs every time)
- L121: Mismatch shape: a hash differing from the real seq 2 = the history the inviter saw is not part of the distribution
- L146: Forgery shape: the link's ie= / is= point at a different key (forged link / forged chain)
- L168: Cross-check pinned: the FP matches but the sig key differs (both FP and key are cross-checked — a disguise of only one never passes)

### `apps/cli/test/invite-command.test.ts`

- L1: Test-scope note: the argument layer of maruhi invite (ADR-0016 decision 6), driven through the real runCli as in effect-cli.test.ts
- L53: Leak discipline: input neither link nor token (could be a plaintext value) never appears in the diagnostic; target is Argument.Redacted
- L70: Leak pinned: a raw token never appears in the diagnostic

### `apps/cli/test/invite.test.ts`

- L1: Scope contract for invite commands (§15/§6.5, IV v2): link assembly/parsing, no compat path; create owner-only; accept's verification order
- L101: seedTokenOnly seeds a logged-in state (no device key) — for key-generation-path tests
- L107: Literal decoded: 2100-01-01 (outside the near-expiry warning window)
- L161: Assertion design: the seed is compared unwrapped — toEqual does not inspect Redacted's contents, so a wrapped comparison would be vacuous
- L253: Verification pinned (§6.5): the issuance signature verifies with the inviter's chain key
- L266: Issuance scope pinned: the K2 CLI issues only scope = all (carried on both the issuance body and the issuance signature)
- L273: Secrecy pinned: the seed is never sent to the server (only the public key and issuance text)
- L286: Consistency pinned: the displayed link parses and matches the issuance text (the public key derived from the seed = the link_pub sent)
- L305: Pin pinned (§6.5 SHOULD, the inviter-side counterpart): link_pub and role go to non-secret local storage
- L344: Privacy pinned: the destination login is never sent to the server (only into the issuance pin) — the guidance mentions the GitHub match
- L347: Check placement pinned: a malformed login form fails before issuance (usage)
- L353: Backing-off pinned: with identityBacking = none, il is not built (an environment that does not use the backing source)
- L425: Coverage pinned (§6.5): the issuance signature covers the scope
- L455: Two checks pinned: a duplicate flag is usage (2); an environment absent from the chain is refused pre-communication (unknown-env check)
- L499: Containment pinned: omitted = all is not contained for a listed admin (all is U, including future environments)
- L545: Shape: the same user_id with a different key (the shape of regenerating on another device)
- L577: Refusal placement pinned: refuses before the issuance POST (no pending is created server-side)
- L614: Fixture state: a corrupt pins file (merge refuses to overwrite — the pins.ts rule)
- L618: Failure isolation pinned: the link is displayed exactly once — a pin-save failure must not fail the already-succeeded issuance
- L622: Preservation pinned: the corrupt file is not overwritten (preserving detectability)
- L686: verifyBody independently verifies both signatures on the acceptance POST body per §6.5
- L722: Verification pinned (§6.5): acceptance/link signatures verify (bound to project/link_pub/parties/keys); the seed is never sent to the server
- L732: Anchor pinning pinned (§6.3 (a)): unmatched = verifiedAtSeq null; it also keeps the inviter's sig key
- L764: Tamper case: seed substitution (link_pub does not match the issuance text)
- L841: Line drawn pinned: an explicit flag allows acceptance (never stand in for the ceremony's out-of-band match)
- L859: Run 1 flow: the ceremony (last-word re-entry) → the success is recorded to the book
- L872: Book semantics: run 2 (another invite, same inviter) — a book hit exempts the 12-word read-out re-run, but the explicit yes remains
- L885: Run 3 pinned (agent environment): a book hit does not allow standing in (the flag is required — symmetric with the member-add side)
- L895: Run 4 pinned (non-interactive): a book hit does not advance to yes; it returns to the full ceremony — a blind printf yes cannot pass
- L925: Prompt mechanism: recovery-code save verification (reads the last group from the displayed stderr)
- L939: Verification pinned: the self-bound signature with the generated key passes verification (declared key = verification key)
- L1067: Acceptance rule pinned: anything but yes is not accepted
- L1109: Agent rule pinned: even when registered, yes is never stood in for — only an explicit --from is the path
- L1163: Ordering rationale: pinning before acceptance would let a crafted link with a failing acceptance replace an existing anchor (self-DoS)
- L1204: Replacement rule pinned: for an unmatched anchor (verifiedAtSeq: null), the last proper acceptance wins
- L1224: Auditability pinned: replacement leaves a trace (substitution via a fake link = auditability of the DoS path)
- L1231: Misguidance hazard: acceptance already succeeded server-side (link consumed) — treating a pin failure as failure misguides to a 410 re-run
- L1244: Report consistency pinned: the completion report does not contradict the warning — no machine-match promise, guides the degradation
- L1253: Mismatch pinned: a link signed r=admin with the response's role member is refused (contradicts the issuance signature)
- L1264: Mismatch pinned: the response's projectId differs from the signed target = server self-contradiction → refuse
- L1358: Coverage note: role tampering in the issuance text (covered by the issuance signature)
- L1363: Tamper case pinned: reassignment to another user_id breaks both signatures' invitee_user_id binding — the link signature is reported first
- L1406: Substitution shape prepared: a local issuance-time pin with a different link key — the shape where the server's row was substituted
- L1459: Difference isolated: the link key and role match; only the scope differs (the row is all)
- L1505: Classification pinned: a crypto failure other than the signature (non-hex link key) also means the block doesn't verify — a rejection

### `apps/cli/test/key-project-command.test.ts`

- L1: Scope note: the argument layer of maruhi key and project (ADR-0016 stage 3) via the real runCli; groups share a file (cases check both)
- L15: Ordering rationale: behind session resolution, key bogus would fail as 'Not logged in' (exit 1) and the typo never conveyed
- L33: Attack shape: an ANSI word erasing lines and faking success; the wording lists only possible operations — the typed word never shown
- L57: Check-placement rationale: checked only where the project resolves, a typo would hide behind 'Not logged in'; the value is never shown

### `apps/cli/test/keychain.test.ts`

- L21: Assertion discipline: always unwrap before comparing raw values (toEqual on wrapped values does not inspect the contents)
- L27: Round-trip pinned against storage: serializeStoredToken → parseStoredToken returns the raw value (a redacting serialization fails here)
- L34: Record rule pinned: the expiry is required (absence = corruption)

### `apps/cli/test/keygen-project.test.ts`

- L42: recoveryStatusHandler serves the recovery-registration status response (called by the tail of key show / generate)
- L50: recoveryPutHandler accepts the recovery-wrap registration (the PUT of generate / recovery)
- L55: displayedRecoveryCode extracts the recovery-code line from stderr; as key material, the code never goes to stdout (redirectable)
- L68: queueSaveConfirmation lazily queues the correct answer (the code's final group) to the save-confirmation prompt
- L90: Inspection note: the secret side is a Redacted — inspecting the raw value (length, no leakage into output) unwraps it first
- L95: Storage pinned: no redaction was stored = a record capable of restoring the key was written
- L98: Leak pinned: no secret-key material leaks into the output
- L130: Wording pinned: it names the cause (which suite)
- L132: Preservation pinned: unlike corruption it must not be deleted — deleting a future version's key is permanent loss
- L137: Guidance pinned: the escape hatch is shown only in its reversible form (copy the value down before deleting)
- L158: Setup state: no recovery/status handler = the situation where the server does not respond
- L201: initHandler accepts genesis and returns the entry hash as the ID, like the real server
- L229: Behavior pinned (§9-1): the personal org is auto-selected (display doesn't show org); the submitted genesis verifies on its own

### `apps/cli/test/known-fingerprints.test.ts`

- L1: Scope contract for the fingerprint book's persistence (KF): lookup without mixing origin/user; corrupt reads as corrupt, never overwritten
- L62: Prototype discipline (as floor.ts): users['constructor'] would resolve Object.prototype.constructor — lookups must be own-property checks
- L76: Set semantics pinned: USER_A's second device (the ceremony succeeding again) adds to the set (doesn't erase the first)
- L87: Format pinned: the file is readable JSON (the path for users to delete an entry and force a fresh ceremony); v2 = a set
- L129: Preservation pinned: the corrupt content stays as-is (never silently rebuilt)
- L146: Version discipline pinned: a version other than v2 is not read, even if its contents have the v2 shape
- L158: Structural exclusion: the __proto__ key (JSON.parse creates it as an own property) is rejected as whole-file corruption by the leading-_ ban
- L185: Health pinned: a rejected write creates no file, so subsequent loads stay healthy

### `apps/cli/test/lazy-imports.test.ts`

- L1: Convention pinned (P-6): fallow credits an import()-consumed export only when read off the module in .then — binds exactly the used names
- L29: normalized produces formatting-independent source: trailing commas dropped, whitespace collapsed, no padding inside parentheses
- L96: Tripwire rationale: 192 imports at introduction, 115 once commands/lazy.ts took over — a walk that stops matching fails here first

### `apps/cli/test/live-agent.test.ts`

- L1: Scope contract for live-agent: pins maruhi agent's production path (runAgentSession — Bun.spawn, signal passthrough, teardown), real process
- L39: Child script: prints the socket path to stdout, fetches status from inside the session, exits with 7
- L60: Reach pinned: status from inside the session reaches the agent (it holds nothing yet)

### `apps/cli/test/live-exec.test.ts`

- L1: Scope contract for live-exec: pins the production ProcessRunner's exec (maruhi sync's exec-driver boundary) with a real process
- L38: Timeout rationale: spawnSync blocks the event loop — keep it below vitest's hook timeout
- L43: Channel pinned: the parent's stdout is just the probe's single JSON line (the child's output doesn't pass straight through)
- L50: Ordering pinned: the output comes back whole, uncut (cutting happens after the redaction — sync-exec.ts)
- L54: Behavior pinned: an uninstalled command is a typed error (doesn't go fetch it) — maruhi never downloads a vendor CLI
- L58: Error distinction pinned: a missing cwd is named distinctly from a missing executable
- L62: Capture pinned: stdout whole (300,000 bytes) and stderr as text; a flood past 1 MiB is refused with the script stopped
- L73: D-10 pinned: the script ran on — its value arrived whole
- L75: D-12 pinned: a process the script left behind holds the pipes; the capture ends after the grace with the script's answer and says so
- L80: D-13 pinned: a script that ignores the stop is killed after the grace
- L83: D-14 pinned: bytes after the exit are told from the answer and refused, never pushed and never reported as 'the script was stopped'
- L90: D-15 pinned: a script that failed on its own is reported as such, leftover or not

### `apps/cli/test/live-io.test.ts`

- L1: Scope contract for live-io: makeStdinLineReader retains unconsumed lines across prompts (close-each-time dropped the next line), CRLF, EOF
- L22: fakeTty builds a pseudo stdin with a raw-mode stub
- L79: Filtering pinned: sandwiched between a left arrow (ESC [ D) and a tab, only printable characters remain
- L120: EPIPE shape (maruhi … | head -1): writeSync throws EPIPE from line 2 but swallows silently like console.log; verified with a real process
- L131: Assertion basis: stderr attached so a failure's cause is readable; bash exit is always 0 (trailing echo) — assertions use the writer's code
- L138: Timeout rationale: a real bun process + 200k swallowed EPIPE writes takes 1.3-2 s on the 2-core CI runner — headroom as other live-* tests

### `apps/cli/test/live-proxy.test.ts`

- L1: Scope contract for live-proxy: pins the forward proxy under the production runtime (Bun) with real clients — curl, Bun fetch, a blind tunnel
- L29: Isolation pinned: nothing of this process's proxy settings may reach the probe
- L43: Round-trip pinned (Bun fetch): placeholder out, real value at the origin, placeholder back in the echo
- L46: Tunnel pinned: the blind tunnel is not inspected — the placeholder reached the origin as it was
- L49: Client shape: curl (OpenSSL) as a child with the control environment only
- L54: Refusal pinned: a plain request without the run's proxy credential is refused before anything else

### `apps/cli/test/live-run.test.ts`

- L1: Scope contract for live-run: pins the run-output redaction of the production ProcessRunner (relayRedacted, Phase 3), real child under Bun
- L23: Scrub pinned: never the secret, in any of its forms
- L30: Carry-over pinned: across the two writes, the whole value is one match
- L33: Transparency pinned: binary transparency — the 256 byte values arrive as written
- L47: EPIPE shape: the probe's stdout is read by head -c 200 then closed; without EPIPE handling the relay would read the flooding child forever
- L58: Termination pinned: the child died of SIGPIPE (sh reports 141 = 128 + 13) or was ended; never hung
- L76: Grace pinned: the child itself returns at once; the relay waits at most the grace, not the grandchild's 20 s

### `apps/cli/test/login-logout-command.test.ts`

- L1: Scope note: the argument layer of maruhi login and maruhi logout (ADR-0016 stage 3) via the real runCli as in effect-cli.test.ts
- L12: Disclosure rule pinned: the expected type may be shown (from the declaration), but the given value could contain plaintext — never shown
- L23: Classification pinned: a number option with no value is an InvalidValue = a usage mistake (exit 2), never an internal error (exit 1)
- L38: Stale shortcut pinned: the hidden test-only shortcut was removed with the polling rewrite — an unknown flag is a usage error (2)

### `apps/cli/test/login.test.ts`

- L1: Scope contract for login/logout (§4): server-brokered web-flow handoff; logout = token revocation + keychain removal; no direct IdP talk
- L23: Fixture: EXPIRES_AT_MS is the exchange response's expiry fixture (AUTH_SPEC §6: 2099-01-01T00:00:00Z)
- L26: Fixture: FLOW_ID is the public correlator (128-bit hex — matches api-schema's CliFlowIdSchema)
- L29: Fixture (§4-1 (1)): FLOW_TOKEN is the CLI-only bearer token (opaque to the CLI)
- L46: approvedResponse builds the approved poll response (§4-1 (5) — the raw token appears on the wire only this once)
- L63: fakeHandoff models the maruhi side (start + n pending polls → final); the start's pollIntervalSeconds is 0 (clamped to the wire minimum)
- L72: Field semantics: finalPoll is the final poll response (default: approved)
- L74: Field purpose: startOverrides overrides the start response (for expiry / interval edge cases)
- L125: Ordering hazard: if the argument layer skipped the cap (MAX_TOKEN_NAME_LENGTH), an overlong name surfaces as an encode failure post-approval
- L138: Ordering pinned: start is never even called (no browser approval requested)
- L144: Cap rationale: shared with api-schema's MAX_TOKEN_TTL_DAYS — never surface a usage mistake after the browser approval has completed
- L168: Wire pinned: when omitted, the server default (90 days) applies — the key itself is not sent
- L170: Display pinned: the validity period is fixed at issuance; when re-login will be needed is displayed
- L183: Placement pinned (§4-1 (1)): the issuance parameters ride on start (fixed at start, not at issuance)
- L185: Wire pinned (§4-1 (5)): poll carries only the two flow-credential identifiers
- L188: Guidance placement (§4-1 (2), D-2): verification URL and user code go to the interactive guidance (stderr) as phishing-match material
- L195: Output pinned: the result (stdout) is a single success line + the expiry
- L197: Secrecy pinned (§4-1 (1)): flowToken is a credential — it appears on neither the browser channel nor the terminal output
- L206: Record contents pinned: the record also carries the local decision material for the expiry-approaching warning (ruling CL)
- L210: Display pinned: the raw token never reaches the terminal output (no --show-token)
- L215: handoffWithConfig builds a handoff set where /auth/config declares a signupPolicy
- L255: Guard classification pinned: a misoperation guard (not authorization) — never begins a wasted browser round trip
- L305: Setup case: absent — no /auth/config handler (404), fakeHandoff left plain
- L320: Environment fact: the default TestEnv = interactive terminal × non-agent
- L328: Degraded-path design: one degraded path (display + polling) covers every environment — not a new security gate; login still succeeds
- L345: Claim discipline pinned: since no auto-launch was attempted, it also never claims 'could not open'
- L360: Claim discipline pinned: a failed launch is never claimed as 'opened' (the manual-open guidance for the URL is always shown)
- L366: Validation pinned: the OS URL handler dispatches arbitrary schemes; verificationUrl is untrusted server input, validated before the opener
- L374: Environment fact: the default TestEnv = interactive terminal × non-agent (the auto-launch target environment)
- L382: Neutralization pinned: ANSI injection from a hostile / compromised server never reaches the terminal raw (displayText)
- L425: Oracle discipline: credential mismatch, re-polling a consumed flow, etc. all get the same response (no flow-state oracle)
- L470: Deadline shape: remaining deadline 1ms × interval 10s — the flow would expire while waiting, so it ends with no wasted sleep or request
- L488: Wait arithmetic: expiresInSeconds 12 with the 5s minimum interval admits waits at 0 and 5, ends at 10 (two polls, then expired)
- L509: Interval arithmetic: retryAfterSeconds 8 raises the interval 5→8 after poll 1; the next check (5+8>12) ends the flow — one poll, expired
- L541: Wording rule: truncated to minutes; only sub-minute in seconds; the CLI holds no constant (can't disagree if the server changes TTL)
- L560: Rounding pinned: non-numeric / non-positive values round to the default (15 minutes, the server's drafted value) for the guidance
- L575: Stdout pinned: stdout carries only the result (no URL / code / waiting display mixed in)
- L616: Range hazard: expiresAtMs is unbounded on the wire — a value outside the Date range (±8.64e15) in toISOString would be a RangeError defect
- L638: Guidance pinned (ruling CM): the provisioned-login identity-swap note — 'a plain re-login' must not be recommended (it revokes this token)
- L646: Independence pinned: keychain saving is independent of whether the token is shown (display is one additional place, not a substitute)
- L651: Guidance scoping: provisioned under a different name, a plain re-login (default rotation) never touches the provisioned token — only here
- L667: Escaping choice: token is an unconstrained Schema.String; the copy-meant display uses escapeText (injection visible), not displayText
- L679: Terminal hygiene pinned: raw ESC / fake appended lines never reach the terminal (visualized as escape sequences)
- L686: Ordering rationale: completing approval in a refused environment would only revoke the old token via same-name rotation, with no new value
- L722: Path ordering pinned (K7-4): if a device remains, add; otherwise, recover
- L755: Setup state: recovery/status handler absent = the situation where the status check fails
- L762: No-silent-skip pinned (CLAUDE.md: do not swallow silently in a catch): the skip is surfaced in the output
- L806: Classification pinned: nothing was typed on the command line, so it is not 'a usage mistake (2)'
- L855: Ordering rationale: deletion before revocation — if revocation succeeded and deletion failed, an invalid token remains, all commands 401
- L905: Table rationale: both are states where the next command fails, but the fixes differ (re-paste / add one)
- L909: Wording pinned: the reason the shape cannot be used is shown in the resolver's own wording (not paraphrased)
- L939: Wording accuracy: resolveSession requires the origin binding; a mismatch fails pre-keychain — 'keeps authenticating' would contradict it
- L963: Consistency pinned: resolveSession treats empty-after-trim as unset; the raw value alone would contradict the next 'Not logged in'

### `apps/cli/test/manifest.test.ts`

- L1: Scope contract for manifest wiring (§4.3/§6.3, §12): distribution-time verification in crypto's shared impl + floor manifest extension
- L49: Fixture role: reader is a member with role reader (for the issuer-role-insufficiency negative)
- L51: Fixture role: member2 is a second member with role member (for same-version difference = equivocation's different issuer)
- L55: Fixture composition: chain1 = [genesis, add reader, add member2, create ENV] (epoch 1)
- L57: Fixture composition: chain2 = chain1 + rotate_epoch(2) (a strict extension of chain1)
- L155: Field semantics: manifest undefined = do not distribute a manifest (for the absence negative)
- L157: Field behavior: a fixture that stacks a baseline checkpoint on the chain bundles the corresponding enumeration (§12-7)
- L193: startPhase is a phase switch into the same TestEnv (= the same floor) — same style as floor-detection
- L207: manifestV1 builds the honest manifest (epoch 1, chain1 head, [ALPHA]); overrides build the negatives
- L215: Field purpose: prevManifestSigHashHex is prev for version > 1 (for fixtures satisfying the adjacent prev check — M1-A1)
- L235: Verdict pinned (§6.3): the omission fails the wire schema's decode before verification — the same verdict as a dropped environment statement
- L251: Mismatch direction pinned: the manifest is signed with the empty set's digest while the distribution contains ALPHA = recomputation mismatch
- L278: Digest scope pinned: the manifest's digest is signed over actives only (without the tombstone)
- L294: Burn-in shape: a manifest that burns epoch 1 into the post-rotate head (seq 5 = epoch 2)
- L344: Phase 1: establish the floor with the v2 manifest
- L356: Phase 2 shape: v1 over the same set (an old valid manifest that passes every check standalone)
- L374: Cross-layer pinned: checkpoint notarizes mv1, floor knows v3; a v2 distribution passes §4.3 (4) but floor rule (a) rejects it
- L381: Fixture value: the baseline checkpoint's values_digest is the actual computed value of the set ([ALPHA v1]); enumeration bundled (rule 2)
- L421: Phase 1: establish the floor with v3 (a different version from the mv1 tuple — verified on the strict path)
- L434: Phase 2: v2 (at-or-above the chain baseline mv1, below the floor's v3)
- L464: Equivocation shape: same version, same set, but a different issuer = valid signatures over different signed bytes
- L480: Phase 1: establish an epoch-2 floor (pull-time epoch criterion = 2)
- L496: Gap shape (rule (c), manifests): version advances ≥2 from floor v2, so the adjacent-prev check doesn't apply — floor rule (c) rejects
- L520: Criterion hazard: in the resync shape pullEpoch stays at the old epoch while the floor manifest knows epoch 2 — pullEpoch-only slips
- L541: Phase 1 outcome: from the old view (chain1), the epoch-2 value + v2 manifest (head seq 5 = future) is accepted by bounded resync
- L559: Phase 2 pinned: version advances by 4 (gap ≥2, outside adjacent-prev check) but burns in epoch 1 — rejected via floor manifest epoch (2)
- L581: metadataHandler serves a metadata-only pull (§12-7) — for pinning push's name-resolution path = the metadata path
- L597: establishV1Floor establishes the floor with a v1 manifest (phase 1) and returns its signed-bytes hash
- L630: Forgery shape: holds a valid signature, correct digest, and correct epoch, but prev is an arbitrary 64-hex
- L647: Evidence pinned (M1-A1 amendment 3): the floor-side hash, the distributed prev, issuer, declared head
- L657: Honesty pinned: intermediate versions (v2) are never distributed by design, so prev's actual-equality is uncheckable — a fixture dummy
- L688: Check pinned: the floor's predecessor carries hash and epoch (§4.1 isomorphic check); adjacent old-epoch burn-in is rejected here
- L729: makeRotateAcceptingServer accepts the rotate composite then distributes the accepted manifest (always bundled — required since 0.28-draft)
- L738: Field semantics: built is the initial chain (default = chain1)
- L761: Material note (§16-2, PR-M3): the stored checkpoint snapshot is saved at boundary acceptance, bundled into later value pulls (rule 2)
- L824: Mock behavior: accepts the 2 entries rotate + boundary checkpoint (§12-4)
- L830: Atomicity pinned (§16-2): snapshot save in the same transaction as acceptance (the enumeration of the distributed set at acceptance time)
- L876: Detection layering: rotate promotes its signed manifestVersion into the floor at acceptance; old-manifest distribution rejected (§4.3 (4))
- L886: Rollback model: keeps distributing v1 without storing the accepted v2 (models a rollback server)
- L891: Detection point pinned: the composite itself was accepted (the refusal is the verification of the post-acceptance rescan pull)
- L897: Layering pinned: even if commitManifest's write fails, the accepted rotate's boundary checkpoint stays the chain baseline — swallow rejected
- L907: Setup: establish the floor via a prior pull (only the write during rotate fails)

### `apps/cli/test/mcp-protocol.test.ts`

- L1: Scope contract for mcp-protocol: the same registrationsLayer the stdio transport serves, driven in memory over the real JSON-RPC encoding

### `apps/cli/test/mcp.test.ts`

- L1: Scope contract for maruhi mcp (PF5): end to end over real stdio framing vs a mock server; one read-only tool + the resource pair (M3)
- L167: Launch shape: the shape a host launches it in — pipes on every stream
- L196: mcpSession runs one session: initialize, then requests (ids 2, 3, …); stdin open until all responses arrive, then EOF
- L227: Deadline rationale: below vitest's 5 s test timeout, so a regression fails on the assertions, not a bare timeout
- L250: Shutdown pinned: stdin EOF (the host went away) is a clean shutdown
- L267: Stdio discipline pinned: stdout carried only the protocol — nothing went through CliIo.log
- L313: Projection pinned: a v1 statement — no schema fields, nothing fabricated
- L322: Call shape pinned (M5): one call = one keyless schema — only the chain and metadata pull, never the value pull, a DEK, or a version range
- L342: Consistency pinned: the same row the CLI table prints
- L364: Caching pinned: no cache — each call synced the chain again
- L434: Regression shape (review's reproduction): right after accepting an invite the anchor is unverified, yet the prologue printed 'anchor passed'
- L481: Notice discipline pinned: once per call (a fresh notice ledger per read), without the prefix

### `apps/cli/test/member-add.test.ts`

- L1: Scope contract for member add (§6.2/§6.5/§7, §12-6/§15): add_member from the acceptance block; §6.5 verification + FP ceremony pre-append
- L78: Fixture mechanism: issuedByProject holds issued invites per project (with the inviter's issuance signature), prepared by acceptanceFor
- L99: acceptanceFor builds the accepter's own proper acceptance block (with the §6.5 acceptance signature + link signature)
- L135: Mock design: makeAddServer simulates dek_wraps slot occupancy — registering into an occupied (env:epoch:recipient) slot returns 409 (§12-6)
- L147: Field semantics (§12-6): occupiedSlotEncPub maps slot → the stored recipient enc public key (the 409's storedRecipientEncPubHex)
- L154: Field semantics: onAppend is injection into chain appends (e.g. 409); undefined = accept
- L156: Field semantics: when onAppend injects, the chain is replaced with chainAfterConflict from then on (a concurrent append)
- L158: Field semantics: onRegister is injection into dek_wraps registration (call-count based); undefined = normal processing
- L357: Payload pinned: add_member payload = the acceptance block's key + the invite row's role
- L366: Signing pinned (§15-2): signs with the invite row's scope (the K2 CLI issues only all)
- L371: Backfill pinned: wraps epochs 1-2 to the new member (accepted as a single batch)
- L393: Scope setup: the invite row is all (issuer = owner); a dev-only admin runs add
- L410: Reach pinned: neither the ceremony (agent refusal) nor the append is reached
- L421: Construction pinned (§6.5): the issuance text covers the scope, so the acceptance block is built from the listed issuance text
- L476: Scope pinned: prod is outside the target scope — no wrap is made (making one gets the server to return 422 scope-out-of-range)
- L479: Isolation pinned: a chain built by the same steps gets the same projectId — do not leak the listed issuance text into other tests
- L489: Concurrency shape: a chain grown by another member's append concurrent with the send (an extension of the same prefix)
- L527: Retry pinned: the append is attempted twice (409 → re-sync + re-sign → accepted); the accepted entry is a child of the new head
- L541: Atomicity hazard: delete → re-register is not atomic — a failure in between leaves the target with no wrap for that epoch
- L575: Call order pinned: 0 = batch (409) → 1 = epoch-1 single (409) → delete → 2 = re-register
- L635: Agent rule pinned: in an agent environment, no --expect-fingerprint is refused (never let it stand in for the ceremony)
- L669: State: the previous run already registered (membership under the acceptance key = no repair needed)
- L679: Gate pinned: membership under the same key never triggers delete (repair) (the 409's stored key = the acceptance key)
- L687: Fixture identity: the old key identity for the same user_id (past membership)
- L718: Occupancy: the old-key wrap from the past membership occupies the epoch-1 slot
- L728: Repair flow pinned: epoch 1 is deleted → re-registered (repair); epoch 2 registers normally
- L745: Repair substance pinned: the re-registered epoch-1 wrap is addressed to the new key
- L754: Detection pinned (§12-6 suppl.): a rerun after a partial add under the current key — the 409 carries the stored enc key (= current key)
- L765: Resume scope pinned: re-adding under the current key was already accepted (the previous run interrupted) — resume backfill only
- L791: State: the previous run already registered epoch 1 under the current key (partial completion)
- L800: Idempotence pinned: a match = already registered — not a single delete (mis-deletion) fires
- L808: Verdict basis pinned: the key history has no other key, but the 409's field declares another; verdict = exact comparison with the field
- L838: Repair pinned: a mismatch = repair (delete → re-register), independent of the key-history gate
- L861: Interruption shape: add_member already ran (the server updated the row to completed) + the backfill was interrupted
- L880: Selection pinned: with no id, a completed row is never auto-selected (past rows accumulate); the error guides to resume (explicit id)
- L890: Resume pinned: explicit id — completed row + same-key membership → no append; resume backfill only
- L914: Tamper case pinned: role tampering (covered by the issuance signature — fails issuance-text verification)
- L919: Tamper case pinned: key swapping breaks the declared-key binding of both signatures — the link signature is reported first
- L943: Substitution shape: a server declaration whose issuance pin and link_pub disagree (row substitution)
- L980: Attack-shape note: an attacker declaring the inviter's key verbatim — signature is self-bound, so only the early consensus check is tested
- L1047: backedState adds an impersonated GitHub signing-key list to a server state with an accepted invite + one environment
- L1099: Book discipline pinned (ruling D ②): a successful machine match is not recorded to the book (the book records human confirmation)
- L1157: Case pinned: unregistered + empty answer → stops without appending
- L1168: Case pinned: unregistered + yes → to the ceremony (last word)
- L1177: Case pinned: unreachable (cap) → note + ceremony (no two-way choice)
- L1186: Case pinned: identityBacking = none → no match (note + ceremony)
- L1227: Run 1 flow pinned: the ceremony (last-word re-entry) → the success is recorded to the book
- L1232: Book semantics pinned (DK): added to the set — old records are not erased; they remain as the same person's other devices
- L1238: Book semantics: run 2 (already a member → backfill-only rerun) — a book hit exempts the 12-word read-out re-run, but the yes remains
- L1250: Run 3 pinned (agent environment): a book hit does not allow standing in (the flag is required)
- L1258: Run 4 pinned (non-interactive): a book hit does not advance to yes; it returns to the full ceremony — a blind printf yes cannot pass
- L1269: Run 5 pinned (stdout redirected): the boundary is stdin AND stdout (&&) — pins a single-sided implementation mistake
- L1319: Book update pinned: interactively the warning + ceremony are not skipped; success overwrites the book with the new fingerprint
- L1329: Book semantics pinned (DK): added to the set — old records are not erased; they remain as the same person's other devices
- L1334: Refusal pinned: agent environment + mismatch + no flag = refused as before (never auto-passes)
- L1366: Stale-record shape: re-running with the flag after a legitimate key update — flag matches the actual FP, so no 'check required again'
- L1387: Book semantics pinned (DK): added to the set — old records are not erased; they remain as the same person's other devices

### `apps/cli/test/member-command.test.ts`

- L1: Test-scope note: the argument layer of maruhi member (ADR-0016 decision 6), driven through the real runCli as in effect-cli.test.ts
- L76: Parser pinned: the FP format check is the shared parser (fingerprint-flag.ts); the typed value is never shown

### `apps/cli/test/member-list.test.ts`

- L1: Scope contract for member list (ES K4, ruling M / K4-E): user id, role, scope, key FP from the verified chain; zero values = keyless class
- L118: Device list pinned (DK K4-20): FP + cap; the concatenated keyFingerprintHex was removed
- L131: Keyless pinned: no master key (equivalent to a MARUHI_TOKEN run — works in the keyless class)

### `apps/cli/test/member-remove.test.ts`

- L1: Scope contract for member remove / change-role (§6.2/§7): remove appends remove_member + forced rotation; recovery is chain-derived
- L76: WireFlag is the wire form of one rotation flag (AUDIT_SPEC §3.3)
- L91: Field: registerBodies holds the dek_wraps registrations (the change-role widening backfill — §12-6)
- L96: Mock design: makeRemoveServer is a stateful mock for remove / change-role: chain GET / append POST, env list, pull, rotate acceptance
- L106: Field semantics: onAppend is an insert into the chain append (409 etc.); undefined = accept
- L108: Field semantics: when onAppend inserts, subsequent chains swap to chainAfterConflict (a concurrent append)
- L110: Field semantics: rotator = the principal sending the rotate composite (default owner) — issuer of manifests, recipient of the self wrap
- L112: Field purpose (PF6 R3): flags are the rotation flags the server reports after the removal (the checklist's input)
- L114: Field purpose: variableStatements are the verified variable statements per environment (the checklist resolves names from them)
- L128: Store semantics: manifests holds the per-environment stored latest manifest (lazily issued on first pull → replaced on rotate acceptance)
- L130: Store semantics (§16-2): checkpointSnapshots holds the per-environment stored checkpoint snapshot (no variables = empty enumeration)
- L144: Mock design (PF6 R3, §4.3): the metadata-only pull — statements listed under a manifest continuing the stored one; manifest must bind them
- L276: Bundling rule (§12-7): always bundle the baseline checkpoint's stored row when one exists (rule 2's material)
- L297: Mock behavior: two entries accepted — rotate + boundary checkpoint (§12-4)
- L303: Atomicity (§16-2): the snapshot is stored in the same transaction as acceptance (no variables = empty)
- L311: Promotion (§12-4/§12-5): the accepted bundled manifest becomes the stored latest fed to distribution
- L344: Route note: dek_wraps — fetching your own = the backfill's input; registering = the widening's output
- L415: §7 pinned: forced rotation — complete wrap set = every current member after the removal (incl. continuing admin2); removed target excluded
- L470: Checklist scope pinned: another member's flag is not part of this checklist
- L488: Guidance pinned: with no rotation config in the working directory, the by-hand route with the runbooks is shown
- L501: Concurrency shape: concurrently with the send, another owner device had removed the same target (an extension chain)
- L530: Idempotence pinned: the append was attempted once (409) only — the resync detected the removal and no double-append happens
- L534: Mandate pinned (§7): the sweep is fulfilled as one's own share (reason = member-removed)
- L591: Warning discipline: a converging command doesn't emit the always-on unconverged-mandate warning — its own sweep report is more precise
- L678: Scope pinned: the K2 CLI keeps the target's current scope (all) (--env arrived in K4)
- L685: Wrap semantics pinned (§7): the demoted member keeps receiving the new epoch's wrap as a reader (mandate = epoch-anchor soundness)
- L779: Mandate-scoping hazard: target born a reader (no own mandate); admin2's remove follows unconverged — a global criterion rotates everything
- L824: Section scope: environment scope (2026-09-15 ES K4 — CRYPTO_SPEC §6.2 / §7, design record es-design.md §10)
- L832: twoEnvironments builds a mock's environment set holding the two envs dev / prod (epoch 1), with owner-bound wraps
- L882: Payload pinned: role stays as-is (--role omitted); scope is fully replaced (§6.2)
- L891: Complete set pinned (§6.3): the new epoch's complete set = R(prod) = { owner } (excludes the narrowed target)
- L926: Widening pinned: the widened portion = prod only (dev is already held); recipient = the target, epoch 1
- L966: Concurrency shape: concurrently with the send, another owner device had promoted the target to member (an extension chain)
- L993: Re-sign pinned: a run that only changes scope — the re-sign keeps the post-promotion role (member)
- L1026: Check placement pinned: an unknown environment ID stops at the on-chain existence check (the pre-judgement for unknown-environment)
- L1061: Scope behavior pinned: a meta-only pull (maruhi schema) issues the request even outside scope (mock lacks it → 404, no scope-refusal stop)
- L1080: Interruption shape: widening (backfill interrupted) → a third party appends a change_role that only changes the role
- L1178: Scope arithmetic: owner narrowed target {dev, prod} → {dev}, prod's rotate unconverged; a dev-only admin demotes to reader ({dev} ⊆ {dev})
- L1189: Mock arrangement: the distributed self-destined wraps are for the caller (devAdmin) (the mock doesn't filter by recipient, so swap them)
- L1221: Resume shape: owner widened target {dev} → {dev, prod}, prod's backfill unconverged; a dev-only admin re-runs the same scope (difference ∅)
- L1249: Mandate-vanishing pinned (§12-6, §6.2): another's widening unconverged, but prod has since been deleted on-chain (scope pruned) — no note
- L1270: Refusal placement pinned: a scope naming the deleted environment is refused before signing (the verifier's environment-deleted)
- L1309: Scope arithmetic pinned: symmetric difference {prod} ⊄ {dev} — a dev-only admin cannot sign a narrowing away from prod
- L1318: Scope arithmetic pinned: when the role changes, old ∪ new = {dev, prod} ⊄ {dev}

### `apps/cli/test/message-style.test.ts`

- L1: Wording conventions turned into a mechanical check (DP5 supp. E); scope and the deliberate cutoff (formatting functions not followed) recorded
- L28: Command names derived from COMMAND_SPECS; a handwritten copy would silently miss a name when a command is added
- L35: Regex matches the literal after a wording call; caveat: does not span escaped quotes
- L43: File-body text is a document, not a terminal line, so a final period is legitimate — excluded via name suffix
- L57: Recursive src walk so a file in a new subdirectory is not silently skipped and the corpus cannot shrink unnoticed
- L95: Count floors at ~90% of main 94d3b72 so a scan that stops walking files fails before conventions can silently pass
- L113: Defines what counts as a bare command name in prose (the lookbehind character set) for convention 2

### `apps/cli/test/mirror-commands.test.ts`

- L1: Mirror client tests anchored to AUTH_SPEC §11-7 / PF2; properties 1-2 pinned
- L45: Fixture is a fork of `built` sharing the genesis; entries are deterministic so the fork is reproducible
- L93: Fixture state convention: null means a writable primary with no marks; a test sets and resets it
- L155: Mirror's recorded source is the pair's server; a sync refuses any other (H-15)
- L197: Verified view is rebuilt before the restarted pass (H-13); report compares committed head with the exported view
- L275: Expected output ends in its zone once because formatUtcMinutes prints 'UTC'
- L280: A 'current' tick is only status reads — no chain download, no export (ruling H revision, round 4)
- L288: Floor below source head is proved on the chain by the view once (H-14), advancing the floor (H-16)
- L315: A moved attestation mark alone, or a moved mutation counter alone, brings a replica — each isolated as its own case
- L324: A source behind this machine's floor is not 'current'; the replicating path's floor check decides (H-11)
- L391: Unreadable source mark: promotion refused unless forced because it may leave two writable copies (ruling C rev, round 5)
- L416: A source whose mark says it holds the project writable is refused, with the planned order
- L447: --force still reads the source and says what it overrides (ruling C rev, round 9), as consequence not remedy (round 12)
- L454: Source already frozen as a mirror of this deployment: promotion goes through without a probe (planned order)
- L465: Exception: mirror lacking the frozen source's last writes is refused (planned order's last sync skipped; ruling C rev, round 7)
- L478: Forced past a lagging mirror: entries the source holds past the mirror are named as what becomes unreachable (round 12)
- L519: Source is a mirror of another deployment: promoting this copy is the split brain, refused with the re-point unless forced (ruling C rev, round 4)
- L549: Forced consequence names the two copies and the mark that stops the split while this copy has taken no write (round 13)
- L560: Source answers nothing: the mark proceeds with a warning and the promotion goes through
- L575: Contract pinned: --source is required and must not be the server itself
- L588: Planned-failover freeze scenario: primary P ahead of mirror M (prefix chain), last sync named as next step
- L592: Scenario state: source M is a mirror of the project being marked — the freeze case
- L612: Source holds the project writable: no sync can bring entries into it, so the mark is refused naming the direction (ruling C rev, round 9)
- L643: Source is itself a mirror of a third origin: the mark goes against that origin (the star), unless forced
- L677: Two chains sharing only the genesis: neither head is an entry of the other — refused unless forced
- L706: --force still reads the source and says what it overrides (round 10)
- L710: Forced output omits the refusal's own escape clause (round 11)
- L723: Equal to a source frozen for this project: both copies frozen after the mark; note names the promotion to run (round 10)
- L740: The mark's read fails alone: the chain check still runs (round 10)
- L762: Chain read fails alone while mark says frozen for this deployment: the undo note stands on the mark (round 11)
- L787: Mark read fails while this project is ahead: the note hedges the sync on what the source holds (round 11)
- L804: Source frozen under another hostname: star instruction would be a self-mark, so the way out is the mark under that name (round 11)
- L857: Frozen at seq 1 with a foreign entry: a fork no sync can repair, and the refusal says so (no sync suggested)
- L875: At the mirror's height with another hash: same fork, no chain fetch needed (round 10)
- L890: Frozen source restored from an older backup: strict prefix holds nothing the mirror lacks — promoted; its audit rows are uncountable from here (ruling C rev, round 9)
- L912: Planned failover (frozen head is the mirror's, a replication from it recorded): the rows are counted
- L941: Source that synced back from this mirror: its own record counts exactly, whatever the mirror's record says (round 10)
- L1006: Server frozen for this mirror with a replication record is a source all the same; the pair stays consistent (round 9)
- L1024: Planned failover's last sync (frozen, nothing replicated yet) goes through; --force overrides the star rule
- L1071: Behind case: the server exported a chain shorter than the one it served
- L1093: Ahead case: view retaken after the commit (honest race is a write in between) yet server still serves seq 2 — it exported entries it no longer serves
- L1121: Report never calls it a write that landed (round 10); on the sync path it names the sync's own causes only (round 11)
- L1128: Post-commit view fails (local floor refuses the served chain): failure names the replica held and the no-promotion advice (round 10)
- L1162: Server stops answering after the commit: verification did not fail — the replica is unchecked, not condemned (round 11)
- L1192: Session refused on the re-read: neither condemned nor unreachable (round 12)
- L1261: Promoted copy diverging from the server: two writable copies, not a mirror to 'not promote' (round 12)
- L1277: Mirror of another source: judged against the wrong server
- L1303: No session for the mirror: refused with mirror-specific guidance
- L1324: Fixture chain shares the genesis of `built` (deterministic entries) plus a grant to a foreign key

### `apps/cli/test/mirror-fallback.test.ts`

- L1: Mirror read-only fallback tests anchored to AUTH_SPEC §11-7 / PF2; properties 3-4 pinned
- L41: Mirror session has no device key there: the key is the person's, stored for the server origin only — defines the fixture's credential shape
- L102: Invariant pinned: the mirror's own word never moves a member's writes
- L165: Mock response is deliberately never ended to simulate a stalled body
- L283: Fixture arrangement: only the device key is in the keychain (stored for the server origin); credentials are env vars
- L364: Case point: the mirror answers (404) — the fallback fired, with a second token minted for the mirror's audience
- L370: An explicit --audience is kept on the retry; a flag goes before `--`

### `apps/cli/test/mirror-server-grant.test.ts`

- L1: server grant --key-from tests anchored to AUTH_SPEC §11-7 / PF2; property 6 pinned

### `apps/cli/test/notice.test.ts`

- L1: Notice discipline pinned: three prefixes only, stderr only, color on prefix alone, color enablement order (DP5 rulings A/B)

### `apps/cli/test/npm-dist.test.ts`

- L1: npm distribution properties pinned; bundle built once because bundling takes seconds
- L18: Fixture cwd stands in for a cloned repo: its .env points MARUHI_CONFIG_DIR at a config with SERVER_FROM_DOTENV and its bunfig preload exits
- L29: Transpiler cache dir must stay empty while Bun takes bin.js as already bundled — the variable exists to assert that invariant
- L32: Run env deliberately omits MARUHI_CONFIG_DIR so only the fixture .env can set it; empty XDG_CONFIG_HOME replaces the developer's config
- L64: spawnSync blocks the event loop so vitest's hook timeout cannot interrupt it — kill the child before the hook's ceiling (25s < 30s)
- L93: bin values must be ./-free: npm 11 normalization silently drops a ./bin.js entry (measured in the v0.1.0-rc.1 publish failure)
- L99: Workspace deps and the effect beta are folded into the bundle (ADR-0015); a resurrected dependency would point at unpublished @maruhi/*
- L111: --env-file=/dev/null covers Bun before 1.3.3, which ignores --no-env-file; on current Bun either flag alone suffices, so only this line pins both
- L142: Case: the directory works on plain Bun — its preload runs and, without bunfig.toml, its .env sets the server
- L156: cli.ts's package.json import must stay named (version only) to tree-shake; a default import would duplicate the manifest into the bundle (measured, bun 1.3.14); probe token chosen to avoid false failures

### `apps/cli/test/oidc-github.test.ts`

- L1: OIDC issuance fetch tests (AUTH_SPEC §14-1): stub Fetch pins request shape and every failure's exact message
- L100: Exactly the three headers — above all no trace headers leak into the OIDC request
- L145: Regression: without { local: true } the issuance fetch's provide resolves to the ambient HttpClient build and redirect: 'manual' silently drops

### `apps/cli/test/own-devices.test.ts`

- L1: Own-devices persistence properties pinned, incl. fail-open load: an unreadable file reads as corrupt, not a failure
- L64: Consumers of load degrade on any non-loaded state — a merely unreadable file must not fail key show / key recover
- L83: Invariant: corrupt content stays as-is, never silently rebuilt

### `apps/cli/test/package-entries.test.ts`

- L1: Entry discipline (CLAUDE.md CLI layout): package command.ts imported only by commands/index.ts; a re-export would widen the surface and close a real import cycle
- L22: Recursive src walk so a file in a new subdirectory is not silently skipped (same walk as message-style.test.ts)
- L47: A bare ./command.ts inside the package counts the same as an outside ../<name>.package/command.ts import
- L70: Floor of 3 entry imports at introduction so a walk/pattern that stops matching fails before the exclusive-set check can pass on an empty collection

### `apps/cli/test/passkey-listener.test.ts`

- L1: Passkey listener properties pinned (integration-options supp. 20 rulings A/C): all rejection shapes are the same reason-free 404, accept exactly once
- L141: Mismatched confirmation code is a 404 and not consumed — the correct POST below still passes
- L155: Case: a too-large body is cut unread (no response, or 404)
- L168: Case: a malformed POST doesn't close the listener — a correct POST still passes
- L224: parsePrfPost contract pinned: the code is a 6-digit numeric string only; absent, short, or numeric-typed are all null
- L248: Security: the confirmation code's value only rides the POST — no key material enters the DOM
- L262: WebAuthn requires UV; on authenticators without UV the PRF silently goes missing — hence userVerification required

### `apps/cli/test/passkey.test.ts`

- L1: Passkey PRF integration tests (CRYPTO_SPEC §8.2 / AUTH_SPEC §13-7, KL3 K5); real crypto, wire-level mock, test plays the browser (ruling J)
- L54: Fixture roles: the reserve key is the side that never enters the keychain — the distinction the sealing tests rely on
- L161: displayedCode returns the latest code: when two ceremonies run back to back it is the later one (unseal then register)
- L207: The test's reserve is a CLI-generated reserve key (marked, DK K16); everything else is a device key — drives the conditional kind field
- L225: Ledger assembly note: the AAD's user_id is the session's user (the owner)
- L235: JSON.stringify won't work here — the secret side gets wrapped in redactions (same trap as production recovery.ts)
- L265: TS narrows a value assigned inside a closure, so the captured body is received in a box
- L292: The salt the page used and the salt sent to the ledger must be the same value — a disagreement would make recovery impossible
- L319: Property pinned: what gets sealed is the reserve key opened from the ledger, not the device key in the keychain
- L325: Transplanted to a different wrap_id it won't open — the AAD binding
- L342: Unlistable projects = unconfirmed, but a key carrying the reserve-key mark is sealed as a reserve key (DK K16-6: a marked key can never be a device key)
- L442: Ordering pinned: the cap check happens after unsealing the ledger (unsealing is the qualification) and before the listener stands up
- L478: Threat shape: a different-UID user picks up the token and sends a fake PRF — equivalent to not knowing the code
- L592: A different salt per row pins the evalByCredential mapping — identical salts couldn't detect a mix-up
- L600: The reserve key is a key an owner's device added via add_device (DK K14) — judged along the same path as the ledger
- L619: Blob fetch count captured at ceremony time: the grounds for an abort not consuming the window
- L637: No interaction after the ceremony; a reserve-marked key is recorded without asking (DK K16-3)
- L647: The opened reserve key is not stored; a new device key for this device is generated and stored (K4-1 / K4-10)
- L710: Case: a server returning a wrap disagreeing with the row is fail-closed
- L736: Case shape: a well-formed 32-byte PRF output that simply does not match the registration
- L780: Case: a device holding a device key is refused before touching the ceremony or the server
- L824: Gate provenance differs per ceremony: sealing's first gate is unsealing the ledger (recovery.ts); recovery/removal use the passkey ceremony's gate (passkey.ts)
- L918: list carries no gate because it exposes public information only

### `apps/cli/test/pins.test.ts`

- L1: Invite-pin persistence properties pinned, incl. schema-rejected pins refused at write time and __proto__ keys reading as corrupt (AUTH_SPEC §12-1)
- L36: Fixture expiry is far inside the retention window so the next write never sweeps it
- L72: Raw text is edited because JSON.stringify cannot produce an own __proto__ key — the only way to build this fixture

### `apps/cli/test/project-export.test.ts`

- L1: Project export tests (AUTH_SPEC §11-6, PF3): paging, gzip exactness, 409 restart, trailer cross-check pinned
- L59: Race shape: a real foreign file lands after ensureAbsent; the wx open refuses EEXIST and no open event ever fires
- L282: Case: a project that never settles gives up with the server rejection's wording
- L327: Case point: the next run is not refused as an overwrite (cleanup left no residue)
- L331: The companion failing removes the data file too — a migration needs both
- L342: Stub client answers the first page then holds the continuation forever, so the export sits mid-write with a partial file when the interrupt arrives
- L387: The wx open is asynchronous: the partial file must provably exist before the interrupt, or the stat rejections below would pass vacuously
- L393: Fiber.interrupt waits for the fiber's exit, so the uninterruptible release (stream teardown + file removal) has completed by now
- L412: The defect is delayed so the partial file provably exists when it lands — otherwise the release could remove it before the stat sees it
- L439: The defect must land on a file that provably exists, or the stat rejections below would pass without the release doing anything
- L451: writeFileString's wx create honors the abort signal: an interrupt mid-write must let the write finish or keep it from starting; a written-but-unowned companion is the orphan guarded against
- L494: Interrupt lands while the payload may still be flushing — a tight poll, or the detection latency itself swallows the window

### `apps/cli/test/project-list.test.ts`

- L1: Project list wire tests (AUTH_SPEC §11-5): cursor paging, stdout/stderr data discipline, empty-list wording, page cap pinned

### `apps/cli/test/project-policy-schema.test.ts`

- L1: Policy schema wire tests (AUTH_SPEC §12-11): bare = show, --set closed set incl. removed `disabled`, same-value PUT still sent, pinned

### `apps/cli/test/proxy-cert.test.ts`

- L1: Ephemeral CA tests (PF4 ruling P3): hand-encoded X.509 accepted by an independent parser, chain verifies, real TLS handshake succeeds
- L99: Case: a client trusting only the CA refuses a different CA's leaf

### `apps/cli/test/proxy-config.test.ts`

- L1: Proxy config parser tests (PF4 ruling P5): host grammar, shorthands, defaults, unknown keys, 'a consumed input is never injected'; error wording never echoes a typed value
- L56: *.localhost is the one single-label wildcard (RFC 6761) and every name under .localhost is loopback (§21 R-4)
- L71: Plain HTTP would carry a value in cleartext — only the loopback is accepted
- L162: A value no member of an optional/nullable key accepts reports the key's own wording, never the union's default message
- L199: Table semantics: entry by entry, the first bad entry decides the reason
- L258: Case: one placeholder inside another is refused like a duplicate
- L318: Case: an explicit withhold on a consumed input is consistent and accepted

### `apps/cli/test/proxy-connector.test.ts`

- L1: Connector frame / github-app tests (PF4 ruling P8): JWT verifies under the App key, token cached and re-minted before expiry, failures never name an input
- L155: Both current and previous tokens are known for scrubbing — the old one may still be valid

### `apps/cli/test/proxy-guard.test.ts`

- L1: Host-local guard tests (§21 R-12) and authority formatting (§21 R-11)
- L27: Addresses classified by value, not by text (§21 R-16): expanded, compressed, hex-mapped, bracketed, zoned forms
- L36: Case data identified: the AWS IPv6 metadata service and the shared address space (Alibaba Cloud's endpoint)
- L41: Case data identified: Oracle Cloud's metadata endpoint and Azure's wire server (§21 R-22)
- L87: Alibaba Cloud's metadata endpoint sits in the shared address space (§21 R-20)
- L101: Invariant: the checked address travels with the clearance — the connection goes there, not to a second lookup (anti-rebinding)
- L111: A literal in any form never reaches the resolver and is classified by value

### `apps/cli/test/proxy-run.test.ts`

- L1: proxy run end-to-end tests (PF4): env pulled and verified, placeholders for brokered vars, real values only for pass-through, temp dir gone afterwards
- L178: CA files land under XDG_RUNTIME_DIR when set, so the test can see them vanish
- L180: Fixture default: a person accepted the config on this machine (§21 R-8 / R-14), unless a test says otherwise
- L294: Redaction set: pass-through values, brokered values known at start (defence in depth), and the run's proxy credential (§21 R-10)
- L348: The acceptance record lives under the account home, not the config dir itself (§21 R-23)
- L353: Case: under an agent before anyone accepted the file — refused before any network, child not started
- L362: Rule pinned: an agent cannot accept its own rules
- L368: Case: without a terminal (a pipe) acceptance is refused too, naming the command
- L379: A person at a terminal is not accepted by the way either — the act is explicit (§21 R-14)
- L387: The person accepts (recorded outside the repository, rules summarized) — the agent may use it from then on
- L394: R-18: the project is marked at acceptance — deleting the file before any brokered run is gated already
- L410: Agent rewrites the accepted file (passthrough everything): refused again until a person accepts the change
- L427: R-24: a file accepted for another project is not accepted for this one — acceptance is per project
- L457: Explains the pop: that run is excluded from the counts below
- L459: The acceptance record is keyed by the resolved path: maruhi.proxy.json from the working directory is the same entry
- L466: R-13: deleting the file is not a way around the rules — the project is brokered on this machine
- L474: Continuation: nor is a pipe a way around; a person at a terminal may delete, and is told what is happening
- L491: Running from another directory is the same gate
- L495: A corrupt acceptance record is reported, never overwritten
- L505: The no-config gate fails closed on a corrupt record too — a corrupt record is not 'never brokered'
- L580: Malformed --project is refused at parse time (usage line, exit 2): not a config mismatch, not hidden behind a missing file; the value is never shown
- L601: With neither flag nor config project, the default project names it; a malformed setting is the config's to fix (exit 1)
- L617: Case: plain `run` brokers — a placeholder, the pass-through value, the proxy variables
- L627: Case: --plain from a human terminal — the real values, the config not applied
- L637: Case: --plain under a detected agent — refused before any decryption, child not started
- L648: Case: --plain without a terminal (pipe, CI) refused too; plain `run` still brokers there
- L673: Case: no config in the working directory — --plain changes nothing
- L717: An IPv6 advertised address is bracketed in the URL the command receives (§21 R-11)

### `apps/cli/test/proxy-server.test.ts`

- L1: Forward-proxy tests (PF4 rulings P1/P2/P4/P6/P7) over real sockets: substitution toward origin only, response scrubbing, untouched tunnelling, misuse refusals pinned
- L226: The proxy's own Base64 of a re-encoded header is scrubbed back to the blob the client sent (§21 R-21)
- L237: Case: PLAIN_KEY's rule names only the plain host; using it toward the brokered API host is refused
- L295: Fixture wiring: other.example.test is served by the same origin (leaf for api.example.test), so the client must trust the origin's CA and name the origin's host
- L462: Invariant: the proxy credential is a hop-by-hop header — never forwarded to the origin
- L489: Case: a brokered request using only GITHUB_TOKEN does not touch the connector
- L531: Regression shape: the origin's JSON echo carries the value escaped; the scrub still catches it
- L568: Rebinding resolver fixture: answers a public address first and the metadata service next, with query counting (§21 R-19)
- L618: Case: CONNECT to the loopback by literal is refused
- L622: Case: the loopback and metadata services in other textual forms are refused (§21 R-16 / R-20)
- L634: Case: a name resolving to the metadata service's link-local address is refused
- L638: Case: a name that cannot be resolved is refused too (fail closed)
- L642: Case: plain HTTP toward localhost by name, and a bracketed IPv6 literal (classified, not resolved)
- L661: A public destination is tunnelled, and the connection is asked for the address the guard checked, not the name
- L668: Rebinding case: the one lookup's answer is what the proxy connects to
- L675: Plain HTTP toward a cleared name goes to the checked address too
- L686: A host a rule names is the member's decision: http://plain.localhost still brokers
- L756: A multi-line value substituted only into the body is sent as it is (§21 R-9)
- L774: The origin echoes the URL percent-encoded — the proxy's own wire form is scrubbed too (§21 R-21)
- L804: Case: `api.example.test.` (trailing dot) is the same host
- L813: Case: an open blind tunnel does not hold close() open

### `apps/cli/test/pull-run-max-age.test.ts`

- L1: Pull/run test header: §5.1 distribution-time verification, §12-7 all-epoch DEKs, and the AI-agent-detection boundary (display refused / run allowed)

### `apps/cli/test/pull-run-meta.test.ts`

- L1: Pull/run test header: §5.1 distribution-time verification, §12-7 all-epoch DEKs, and the AI-agent-detection boundary (display refused / run allowed)
- L52: Tamper shape: keep the signature honest but rewrite only the name field — rejected by the byte-exact signature
- L103: A status-deleted environment statement cannot be signed at all (deletion is the chain op delete_environment, CRYPTO_SPEC §4.2/§6.2); chain-deleted is refused before any pull
- L110: Happy path: a distribution of only a deleted statement is accepted and never surfaces in values
- L125: Case: the same variableId distributed as both active and deleted is a refusal
- L133: Case: a tampered tombstone signature is refused too — as long as it is distributed, it is verified
- L170: Scenario timeline: author removed at seq 4; a statement declaring head seq 3 verifies under the key of that time against the whole post-removal chain
- L222: The manifest issuer is a current member; the author's removal is independent — the §4.3 issuer-membership check applies only to the issuer itself
- L292: Spec analysis: declaring a post-removal head is rejected by the membership check (§6.3-3); a during-membership head forward injection is undetected in v1 (§14.3-5)
- L358: Scenario: old view to seq 2, statement declares seq 3 — first verification is chain-head-future, the resync reveals the extension, re-verification accepts

### `apps/cli/test/pull-run-pull.test.ts`

- L1: Pull/run test header: §5.1 distribution-time verification, §12-7 all-epoch DEKs, and the AI-agent-detection boundary (display refused / run allowed)
- L51: All active values are epoch 2 so decryption succeeds — a silent gap current values alone would never surface; SHOULD-warn that no wrap for self exists at epoch 1
- L61: The device-side scenario is a sibling device's pull, not a re-run of approval (DK K11-5)
- L67: Case: no warning when every epoch is covered (no false positive)
- L81: Safety net placed on the one command where a decrypted value can appear, in case an upstream rendering path opens a hole to real fds
- L87: Capture the original methods themselves, not bound wrappers — no extra layer stacked on each restore
- L98: The capture window mixes in vitest's reporter output, so judging is by maruhi's words
- L106: Both --show=false spellings read as false; misreading into true would print every secret — the point is being read correctly, not refusal
- L122: Resolving a duplicate silently (first-wins) could drop an explicit --no-show and print every secret; Flag.atMost(1) rejects regardless of order
- L132: The duplicate check precedes any communication — the plaintext is never produced in the first place
- L135: The reverse order (--no-show last) is treated identically; a 'pass when it leans safe' rule would hide that a written flag was dropped
- L141: Case: same-spelling duplicates are also rejected (--show --show)
- L146: A lone --no-show passes as false exactly as written; only duplicates are refused
- L153: Fixture values: one saved by a malicious co-editor (ESC + BEL) plus a legitimate multi-line PEM-style value
- L177: Newlines are kept (multi-line secrets stay intact), but lines from the second onward are marked — emitted raw, the value could forge a NAME=value line
- L185: Case: a value whose plaintext is an invalid UTF-8 byte sequence (0xff/0xfe never appear in UTF-8)
- L208: All-or-nothing: even ALPHA, which sorts first and decodes fine, is not partially printed
- L218: Rule: never suggest `run` as a bypass for value display — do not hand the agent a bypass recipe
- L221: The refusal is fixed at the command entrance (pre-decryption): it never proceeds to sync, decrypt, or metadata display
- L226: A deny-list would have let this through; when stdout is a pipe/redirect the value is never shown even if the detection list misses it
- L265: Fixture shape: the server falsely claims the signer is owner (the signature stays the stranger's)
- L327: Honestly constructed wrap: §5.1 signature valid over the declared coordinates, but the HPKE wrap is addressed to a different enc key, so failure surfaces only at the open (DK K4-16)
- L422: Case: BETA's ciphertext in ALPHA's slot — the §6.3-5 coordinate match detects the declared-AAD / outer-metadata mismatch before decryption
- L438: Even owner-signed, a wrap for epoch 3 (no rotate_epoch on chain) is not accepted — the client side of §12-6, the main line of server distrust
- L457: A nonexistent epoch never matches 'the current epoch at the declared head'; §6.3-4 value-signature verification refuses before decryption
- L482: Even an owner-signed wrap for a real epoch is refused when its DEK does not match the on-chain commitment — blocks fake-DEK injection by server + key-holder collusion (CRYPTO_SPEC §14.2-1)
- L502: §5.2(2): a comparison before the DEK is used blocks the push toward encrypting with a fake DEK the attacker can read
- L515: GAMMA does not exist, so name resolution pulls only metadata (§12-7); the DEK is fetched exactly once via listMine — the poisoned wrap is mixed into that distribution
- L552: Never grant the default epoch to an environment the chain does not know (§6.2); §6.3-4 refuses a pre-creation head before decryption
- L593: A meta statement never checks the environment's existence (the §12-4 asymmetry), so the ghost statement verifies; the value signature (§6.3-4) rejects it
- L642: Case: a value whose environmentId is another env's, distributed as prod — the §6.3-5 coordinate match detects it before decryption
- L668: Scenario: signer signs with its membership-time keyset, is removed, re-added with a new keyset; the FP match selects the key of that time (chain is append-only, CRYPTO_SPEC §5.1)
- L690: The value is signed with the key of that time (§4.1); the declared head is within the membership interval and verifies against the whole post-removal chain (§6.3-1)
- L817: Scenario: signature stays owner's while writer is claimed as another user_id + FP — no such binding exists in chain history, so no verification key can be selected
- L834: Case: a value declaring a post-removal head is refused on membership at the declared head even with a valid signature (fresh injection by a removed member's key)
- L928: Scenario: old view is genesis only; writer unknown under it, but the declared seq is beyond our head, so it resyncs instead of refusing outright, and accepts
- L1015: Scenario: old view to seq 2, value declares seq 3 — chain-head-future, the resync reveals a 3-entry extension, re-verification accepts
- L1049: Scenario: old view is the honest 3 entries; value declares seq 4 and the resync returns a branched chain — the old head's hash mismatches
- L1056: Fixture entry differing from the honest chain's seq 3 (rotate epoch 2) constitutes the branch

### `apps/cli/test/pull-run-run.test.ts`

- L1: Pull/run test header: §5.1 distribution-time verification, §12-7 all-epoch DEKs, and the AI-agent-detection boundary (display refused / run allowed)
- L25: Trigger matrix: a human terminal (all stdio terminals) — stdio inherited, no redaction
- L29: Trigger matrix: a known agent on a PTY (stdout is a terminal) — the secondary layer triggers
- L34: Trigger matrix: stderr redirected to a file (stdout still a terminal) — triggers
- L39: Trigger matrix: stdin from a heredoc alone does not trigger (the child's TTY is kept)
- L49: run passes without a terminal (CI/pipe): run is a consumption path injecting values into the child's env, not a display path — outside the TTY boundary
- L73: A run with nothing to execute is a usage error; letting it through would decrypt every variable before saying the same thing — plaintext produced and never used
- L93: Dropping an empty-string argument on a truthiness check would silently shrink the child's argv; everything after -- passes through verbatim
- L102: The upstream parser merges tokens around -- into one array, so a leading empty string lands in the executable position; Argument.filter rejects it — a whitespace-only child argument is not rejected
- L115: Because the parser merges positionals around --, `run stray -- printenv` would morph into running stray; rejected by matching --'s position and count in Stdio.args (ADR-0016 decision 8)
- L125: Never print the contents — a positional arg could contain plaintext
- L132: Only the first -- is maruhi's terminator; inner --s stay as child arguments (dropping them would break npm/cargo/docker-style forwarding)
- L140: The strict argument-usage check must not reach the child's arguments, or `run -- <cmd>` could no longer run arbitrary commands

### `apps/cli/test/push-command.test.ts`

- L1: Push argument-layer tests (push.package/command.ts, ADR-0016 stage 3) driven through the real runCli
- L11: The likely typo `push API_KEY "$SECRET"`: the refused argument's contents are never shown (could be plaintext); the fix is always attached, since otherwise there is no way to fix it
- L17: Case: after -- too, push never reads it (only run does) — rejected, not silently dropped
- L56: Collapsing an empty value into 'unspecified' would turn `--env "$ENV"` unset into a write to the default environment (un-undoable); the NonBlank declaration blocks it
- L72: Value-like words are never written out by the refusal diagnostic; candidates come only from declared names. -hunter2 is not used: its -h resolves to built-in help, so the shape is pinned with a non-help leading character

### `apps/cli/test/push-create.test.ts`

- L1: Push tests (§12-5 CAS): create / new version, 409 retries (resync, re-encrypt, retry), and the raw out-of-schema 413 branch
- L46: Mock contract: on acceptance, later metadata pulls distribute the created body (§12-10 (3))
- L109: Name resolution for a creation uses a metadata-only pull (§12-7) and never a value-bearing pull — a path where the server records no var.read (session-11 ruling 3)
- L115: The positive side is pinned here; the negative side ('never write unconfirmed') is pinned by the old-server test — a confirmed creation promotes its own write into the floor
- L145: Mock shape: accepts, but makes the echo's version disagree with the locally signed value
- L169: Promotion into the floor completes with the locally signed value — the echo comparison runs after the floor commit
- L203: Rule: never fire a security-critical mutation without recording the confirmation obligation
- L209: Old-server shape (§12-10 (1)): returns 200 for creation but never stores the bundled manifest; success is defined as confirmation over verifiable distributed artifacts, so this is not success and no self-issued manifest is written to the floor
- L231: Mock shape detail: after acceptance the statement is stored (even by an old server) but the manifest stays v1 — the shape of silent dropping
- L279: The self-issued manifest is not written to the floor — only verified observations are; pinning an unstored manifest would make every later absence misjudged as an omission
- L284: The variable floor is not written either (§12-10 (3)): planting a 2xx-only belief into the floor would make later pulls permanently refuse with variable-omitted if the server never stored it
- L296: Attack shape: server distributes a verifiable manifest of different content under the issued version; §4.3 verification passes, so only comparison against the self-issued (version, hash) detects it
- L340: Shape detail: prev chains correctly to v1, passing the adjacent prev check — deliberately, to pin the hash comparison

### `apps/cli/test/push-meta-conflict.test.ts`

- L1: Push tests (§12-5 CAS): create / new version, 409 retries (resync, re-encrypt, retry), and the raw out-of-schema 413 branch
- L38: Scenario: the client verified metaVersion-2; the post-409 refetch distributing metaVersion-1 is evidence of a metadata rollback
- L124: Scenario: the refetched metaVersion-2's prev not matching the verified signed-bytes hash — refuse to follow a branched prev chain
- L190: Mock detail: the second time, the metaVersion-2 winner also advances the manifest by one (adjacent, prev chains to v1) — only the winner statement's prev mismatch is pinned
- L244: Case: valid statements under the same metaVersion with differing name are evidence of a rename fork
- L352: Case: push with an NFD (combining-character) name — the bundled statement's name is the NFC normal form
- L394: Scenario: the server keeps returning the same currentVersion with the same distribution — every winner check passes but nothing advances; cut off at the generic attempt cap
- L433: Scenario: metadata resolution sees API_KEY; the value-bearing pull sees it already renamed to API_KEY_V2 — blocks a push aimed at a variable whose name changed from the typed one
- L461: Mock assembly: the concurrent rename also advances the manifest to v2 (§12-5) — a same-version set difference would be equivocation, so it is assembled as an honest rename
- L486: A metadata-only pull is under the same verification discipline as a value-bearing one; with no values, verification completes on the statement side alone

### `apps/cli/test/push-version-conflict.test.ts`

- L1: Push tests (§12-5 CAS): create / new version, 409 retries (resync, re-encrypt, retry), and the raw out-of-schema 413 branch
- L70: No listMine handler placed deliberately: a push to an existing variable uses the DEK bundled in the value-bearing pull and never double-fetches via listMine (session-11 ruling 3); calling it would 404
- L115: prev re-points after the 409 to the refetched, verified winner's signed-bytes hash — self-computed, not the server-claimed hash
- L134: Attack scenario: client verified v4; a malicious server returns a 409 rolled back to v2 and the refetch distributes the rolled-back view (passes standalone) — refused as a regression from the verified latest held in the session
- L198: Scenario: the winner is v5 but its prev chains to a different history (a fork) — refused by the adjacent-predecessor §6.3-6 check
- L264: Attack shape: winner is version 6 (gap of 2, adjacent prev check inapplicable) but epoch 1 — a version-number-shifting injection under a removed member's old-epoch key; floor rule (a) detects it first, the winner check remains as a defense layer
- L422: Case: a valid signature with different content at the same coordinates (version 4) — the §14.2-5 evidence shape
- L461: Assumption recorded: support/push.ts assumes 'two states over the same genesis', which holds via Ed25519's deterministic signatures + fixed timestamps
- L478: Regression pin: the server-claimed currentEpoch is a lie (5); the source of truth is the chain-derived value (2) — using the claimed value would set aad.epoch=5
- L520: Case: the server keeps returning EpochConflict — the attempt cap is reached, but a definite contradiction error is reported rather than the generic 'the conflict does not resolve'
- L674: Guard: a response create may return per the schema but never does in practice — never regress into falling onto the push path with the random ID still in place (a push to a nonexistent ID)
- L734: Name resolution is a metadata-only pull — a duplicate same-name active is refused by its verification

### `apps/cli/test/push.test.ts`

- L1: Unit tests for push.ts's stdin normalization (normalizeStdinValue)

### `apps/cli/test/recovery.test.ts`

- L1: Recovery tests (CRYPTO_SPEC §8 / AUTH_SPEC §13; 2026-09-19 DK: the ledger seals a reserve key, not the device key); real crypto, wire-level mock
- L108: The recovery code is key material, so it is shown only on stderr — the same channel as the prompt
- L133: Raw-value comparison is always done unwrapped — toEqual on wrapped values does not inspect the contents
- L146: Case: 0 / 1 are outside the Base32 alphabet (no guessed substitution into O / I)
- L151: Case: corrupting the last symbol's low bits (the zero-padded region) is rejected
- L158: Compare via serializeStoredMasterKey: JSON.stringify redacts the secret side, so comparing records directly would degenerate into a vacuous 'any key matches'
- L245: The registered wrap decrypts with the displayed code into a well-formed reserve-key record — a broken wrap is detectable before the code is lost
- L250: The generated reserve key carries the mark (CRYPTO_SPEC §8, DK K16); the keychain device key does not
- L252: DK rule: the ledger's content is a different reserve key, not the device key — a device-key copy is never sealed
- L257: The reserve key's public side is recorded in own-devices.json with origin 'reserve' (K4-3)
- L286: An explicit naming generates regardless of a ledger's presence — it is issued as a replacement, not refused
- L363: A reserve key that failed to seal is not recorded (seal then record ordering, K4-1)
- L473: Case: --passkey is incompatible with --replace (the ledger is never opened) — a usage error with nothing written
- L611: Scenario setup: the person restoring (the session) and reserve key B sealed in the ledger are different keys
- L637: A key carrying the reserve-key mark is recorded as a reserve key without asking (DK K16-6); the check's positive/negative cases live in device-key-recovery.test.ts
- L677: Scenario: a blob registered by a newer maruhi on another device — it decrypts but the key material is unreadable; it is not 'corrupt', so the exits (update, or re-register) are shown
- L707: Wording rationale: an unknown suite is not 'this code cannot be restored' — corruption wording would make users discard a usable code
- L716: Case taxonomy: two kinds decrypt but fail to parse — current shape with broken contents (re-register) vs a different shape (possibly a future version, update first)
- L736: At this fork 'broken' and 'future-version encoding' cannot be told apart by observation, so nothing is asserted and it is sent to re-registration (revoking the code)
- L811: Case: one flipped bit in the served ciphertext — the blob does not open even under the right code, and the wording cannot distinguish that from a mistyped code

### `apps/cli/test/redacted-display-gate.test.ts`

- L1: Redacted regression header: secret material wrapped in Redacted is the 4th layer after ADR-0016's display gate; tokens cannot yield raw values without a type-level unwrap
- L22: Fixture trick: after Redacted.wipeUnsafe an unwrap throws a defect, making 'was it unwrapped' observable from outside; production never uses wipeUnsafe, so no defect path is built there
- L74: Failing as a CliError instead of a defect proves the decision settled before the display gate
- L84: Failing as a typed Fail (not Die) proves it settled at the gate; reaching the unwrap would throw a defect on the wiped handle
- L93: Control case: through the gate the same input reaches the unwrap and defects — without it, the previous test would also pass on an implementation that never unwraps at all

### `apps/cli/test/redacted-keychain.test.ts`

- L1: Redacted regression header (file 2 of 3): the keychain round trip (save, read-back, real use) is not broken by a redacted save
- L130: The 3 stages run in one pass: if redaction mixes in anywhere it fails here as 'saved but authentication fails' — a path type checking never catches
- L190: A forgotten unwrap at serialization is the one path types cannot stop; undetected on the read side it becomes a misattributed diagnosis ('401 = revoked') and the save-side cause is never reached
- L212: Positive control: a normal record passes — the detection is not over-eager
- L227: Wording rationale: folded into a generic 'it is broken', neither cause nor recovery gets across; recoverability differs by record kind, so the wording splits there too
- L246: Recovery differs by record kind: a token is overwritten by logging in again; a master key is blocked by the overwrite guard, so it guides toward manual deletion
- L253: On an agent session the message never points at a nonexistent keychain — the fix is the same
- L256: The broken record's name follows the same pair — it fails if the agent side regresses to the keychain
- L260: Wording never flatly claims 'always fixable' — if a bug remains in the current version it recurs
- L268: The escape-rule explanation must match the implementation; a drift would have the user read an escaped name as the literal name and never find the deletion target
- L271: The wording never asserts the digit count — astral-plane escapes exceed 4 digits
- L273: Both post-deletion paths are shown: which applies depends on whether the user holds a recovery code; showing only one sends a user without it toward guidance they cannot run
- L279: A user_id with control characters is never streamed raw yet kept restorable — collapsing it to replacement characters would make the sole recovery step (manual deletion) impossible
- L295: Reversibility requirement: an escaped form never collides with a string that always looked that way — a collision makes 'which entry name' undecidable; this holds only if the backslash itself is escaped
- L299: Quotes: entry names are shown quoted, so a user_id closing a quote could make following text read as maruhi's own guidance — the server decides user_id freely
- L308: The wording states explicitly that the name is escaped — otherwise the user hunts for the displayed name, never finds it, and the sole recovery step cannot run
- L311: Bidi overrides and zero-widths are escaped like control characters: passed through they break 'displayed name = actual name' and can reorder the terminal line
- L320: Astral-plane escapes (5 hex digits) must also be restorable — a fixed 4-digit \uXXXX would produce a notation the entry name cannot be recovered from
- L324: Lone surrogates unescaped turn into U+FFFD and the name mismatches; paired surrogates count as one code point and are not broken
- L327: Allowlist-based, so all non-ASCII including emoji are escaped uniformly — the aim is identity as an operation target, not readability
- L344: Fixture setup reproduces a forgotten unwrap at serialization — a save-side bug
- L365: A bidi override can reorder the display: collapsing only ANSI escapes never closes 'fake lines / injected guidance' — names can be forged in pull's list
- L374: Case: format characters insertable invisibly — API_KEY and API<FEFF>KEY can be made to look identical
- L379: ZWNJ / ZWJ are kept — Persian, Devanagari, and emoji joins need them (they decide character joining itself)
- L383: Variation selectors deciding an emoji's presentation are kept too — collapsing them changes the emoji
- L388: A changed shape fails the current parse but is a valid key of another version, not corruption — advising 'please delete it' leaves a user without a recovery code unable to restore it
- L396: The default is 'do not delete', but no dead end: the escape is shown only in a reversible form (stash, then delete); conditioning on a recovery code would land on 'deleted and unrestorable' exactly when the blob is the new format too
- L400: Replacing the stash instruction when adding the disposal one would erase what the stash is for — both are needed
- L403: The stash is the master secret key itself, so the message also says to destroy it; the disposal condition is 'when hand-restoration is no longer needed', never worded as 'key recover succeeding' (recover itself can fail on this path)
- L413: The message states the entry name is shown escaped — without it the name cannot be found
- L419: SUITE_ID identifies the crypto suite, not the storage format's version, so it never grounds a deletion recommendation — different field shapes may be a future format
- L425: Shapes naming no suite or nesting the fields fall on the never-advise-deletion side — where a future format puts them is unknown to today's implementation
- L430: A non-object shape falls on the corruption side: calling it 'another format' would produce 'do not delete, update instead' guidance that updating cannot fix, blocking generate / recover / show with no escape
- L437: An array stays on the keep side — a future version could use it as a container; the explicit array branch must win even when an element is itself a complete current-shape record (never unwrap-and-delete)
- L446: The overwrite guard only checks a record exists, so an unreadable record blocks generate / recover / show; the message guides toward the same exit as the redacted case (show the entry name, delete by hand)
- L452: Even on the corruption side deletion stays reversible: parseStoredMasterKey never inspects the hex's contents, so a well-formed future-format record can fail decodeHex and look corrupted while the key material is fine
- L457: Same disposal-wording discipline as the other-format side: 'when hand-restoration is no longer needed', never 'key recover succeeding'
- L467: 'Already exists' may be said only when a readable record actually exists — returning the refusal wording for an unreadable record contradicts the facts and, showing no exit, blocks generate / recover / show entirely
- L475: Classification rule: current-format fields all present yet unreadable = inner corruption; an incomplete shape may be a future format, so it never falls on the advise-deletion side
- L505: Judging by shape alone returns 'already exists' while loadMasterKeys fails — a contradiction that also shows no exit
- L530: This guard is where both key generate and key recover hit first: saying 'already exists' reports an unusable key as existing, and the entry name to delete never surfaces until another command
- L556: The master-key side's keychain round trip: if redaction were saved, hex decode or the WebCrypto import would fail — 'saved but cannot decrypt'
- L592: Read-back success criterion: loadMasterKeys imports the key as a non-extractable CryptoKey, so success means usable as a key
- L608: Threat path: pasting a redaction seen in output into the env var believing it is the token is realistic once Redacted exists; sent as-is it 401s and lands on wrong-cause guidance
- L619: Pasted values routinely pick up surrounding whitespace/newlines, so the check must not break on that

### `apps/cli/test/redacted-output.test.ts`

- L1: Redacted regression header (file 1 of 3): a careless toString / JSON.stringify / template expansion produces a redaction

### `apps/cli/test/redacted.test.ts`

- L1: Redacted regression header (file 3 of 3): the unwrap sites (Redacted.value) are kept countable — close to the real aim
- L25: Governance: changes that grow the unwrap-site table are subject to review; when adding one, leave 'why unwrap here' on the implementation side and update this table (notes §7)
- L34: Unwrap justification: wire boundary — the lease request's oidcToken field (A3, AUTH_SPEC §14-2)
- L36: Unwrap justification: ci rotate (PF7b) — leased credential and admin inputs handed to the connector in memory, lease token on pre-flight and mint requests
- L39: Unwrap justification: input to the HPKE wrap (a cryptographic boundary)
- L41: Unwrap justification: byte length for list rows (value never shown) + --show's display (after the gate)
- L43: Unwrap justification: input to the DEK commitment calculation (a cryptographic boundary; the product is a hash)
- L45: Unwrap justification: observing the value's shape for schema import inference — products are a closed set of type names and booleans only; the value never leaves
- L50: Unwrap justification: link-key derivation input (cryptographic boundary) 1 + link display (after the agent gate) 1
- L53: Unwrap justification: link-string assembly (result wrapped again) 1 + parsing the accept input (seed returned wrapped again) 1
- L56: Unwrap justification: serialization is the only persistence path (token 1 + master key's secret side 2)
- L58: Unwrap justification: --show-token's issuance-time terminal display — the one place in AUTH_SPEC §6, after the display gate (ruling CK)
- L61: Unwrap justification: reading the claims of our own OIDC token (decoding the payload segment, A3)
- L63: Unwrap justification: the decryption key input (a cryptographic boundary)
- L65: Unwrap justification: encryption key and plaintext inputs (cryptographic boundary) 2 + in-memory equality check of two plaintexts (VH; no display) 1
- L69: Unwrap justification: Base32-encoding input (the product is wrapped again)
- L71: Unwrap justification: encode input for an explicitly chosen value push (the product is Redacted again)
- L74: Unwrap justification: key-derivation inputs for wrap/unwrap 2 + code display 1 + save-confirmation match 1 + interpreting the entered code 1
- L77: Unwrap justification: right before writing to the vendor CLI's stdin — the only path where a value leaves maruhi; never lands on argv
- L80: Unwrap justification: right before injection into the child process's env, and the fragments of the run-output redaction (searched inside the ProcessRunner only)
- L83: Unwrap justification: proxy run — a brokered value resolved per request, the same value as the response-scrub pattern, and a connector's inputs consumed to mint a credential
- L88: Unwrap justification: importing the master secret key (hex to non-extractable CryptoKey)
- L90: Unwrap justification: assembling sync's stdin body (product Redacted again) 1 + redacting vendor output on failure 2 — neither remains in the product
- L94: Unwrap justification: http driver, right before the value enters the request body — the path where the value leaves maruhi; the integration token is never unwrapped
- L98: Unwrap justification: measuring plaintext length 1 + pre-send constraint check 1 + integration token shape check 1 — products are lengths, booleans, names, or Redacted again
- L102: Unwrap justification: parsing the receipt JSON (a name to version mapping — not a secret value)
- L104: Unwrap justification: var rotate — admin inputs and current credential handed to the connector, previous/current pair for --finalize; every product goes to the issuer or is wrapped again; nothing displayed
- L112: The spelling pattern crosses whitespace so a formatter folding it is not missed (fail-open otherwise); both the counting and no-mentions sides use this one pattern, or an offsetting cancel-out becomes possible
- L118: LINE_COMMENT is a string literal so the comment markers may be written as-is; what it reads is under src/, not this test file
- L124: scanComments consumes comment open/close tokens indivisibly: read char by char, the open token's second character would pair with the following / and misjudge 'closed right after opening' — the spelling can hide inside that sequence
- L165: Judging is over the whole source, not per line: the counting side sees the entire file, so a spelling folded across lines counts as one; string literals are deliberately not tracked (the trade-off is recorded)
- L193: commentMentions uses the same source and match as the counting side, or a lenient-side-only shape becomes a hidden slot (swap a mention for a real unwrap, count never moves); scope: honest changes, not deliberate concealment
- L223: Design policy: err on the fail-closed side — walk recursively (a new src/ directory would otherwise vanish from the table) and never drop comments (naive dropping needs lexing and would erase markers inside string literals)
- L279: Counts collapse to one integer per file, so a prose mention is a hidden slot (delete a mention, add a real unwrap, count never moves); end-of-line comments must be banned too, hence the check is whether the occurrence sits inside a comment
- L289: The scan does not track string literals, so real code after a marker inside a string can land on the violation side — a false positive accepted in exchange for never missing; written so it is clear which side it fell on
- L300: Every carry-out where the spelling never appears is invisible to the inventory (aliases, destructuring); pinned to the discipline that only the Redacted namespace may be taken from effect
- L311: A deep import (effect/Redacted) lets the namespace name be freely renamed — an unwrap could happen without the spelling; blocked at the entry
- L316: A local alias like const R = Redacted is the same — R.value(x) works from then on
- L330: Case: hand-assembling the Authorization header by template expansion is the shape that would send the redaction — pinned as not used

### `apps/cli/test/rotate-config.test.ts`

- L1: Rotation config parser tests (PF6 ruling R1): strict shape, header shared with the other repository configs, per-connector rules and inputs, AWS key id companion uniqueness, rule lookup by companion
- L146: A value no member of an optional/nullable key accepts reports the key's own wording — never the union's default message
- L310: The credential is injected under the rule's own name, so that name must be one a script may carry
- L328: Case: a companion under the rule's own name would overwrite the credential
- L332: Case: collisions are judged case-insensitively (a script may run where names are case-folded)

### `apps/cli/test/rotation-audit-command.test.ts`

- L1: Rotation/audit argument-layer tests: nested subcommands (ADR-0016 stage 3) through the real runCli; the two groups share one describe, kept whole
- L13: Measured behavior: a parent with a handler — the bare parent runs list and reaches the command body, never a usage error
- L28: Since bare `maruhi audit` runs list, upstream's uniform required <subcommand> would be a lie; the decision is declaration-driven — only a level holding both flags and subcommands is fixed
- L66: Upstream does not inherit the parent's local flags into the subcommand; the bare parent's declarations hold the same flag, so listing it under 'accepted' would self-contradict
- L79: Because declarations are split per operation, it fails structurally as an undeclared flag
- L123: --all=false is read as false exactly as written (shape #2 of effect-cli's 12) — reading it as true regardless would turn it into a withdrawal of every flag; a duplicate is rejected by atMost(1)
- L139: Distinguishing method: the regression (turning into true) and resolveAllTargets both always communicate, so the cases are told apart via 'missing-target guidance + zero communication'
- L151: Put behind the prelude's sync, the guidance would be hidden behind a connection error and the round trip wasted — the contradiction rules are Command.validate rules

### `apps/cli/test/rotation-proposals.test.ts`

- L1: Rotation proposals tests (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5, PF7b): accept opens this device's wrap, checks the target version, pushes as an ordinary signed version, resolves naming that version; no value is ever printed
- L414: Scenario: a rotate script whose child wrote junk to stdout produced 'junk\n<credential>' — the acceptance shows both shapes and warns where the decision is made; the push is the member's
- L489: Ordering rationale: the companion was stored first — a deploy between the two pushes sees a consistent pair
- L510: A companion is compared too (every proposed variable is opened on this device) — only its line count differs here

### `apps/cli/test/rotation.test.ts`

- L1: Rotation list/dismiss integration tests (AUDIT_SPEC §4.1/§7, Wave 2 B2): names resolved from verified meta statements only (TCB discipline), dismiss folding, and the always-on unconverged-mandate warning pinned
- L373: Case point: the check cannot pass here — the environment's ages are unknown (A-11)
- L389: A deleted environment stays in the chain's set forever, marked by its delete_environment entry (CRYPTO_SPEC §6.2): it is not walked and the check passes — even with the environment list unreadable, since the deletion is chain-derived
- L399: A scoped member's check covers every environment: the metadata-only pull and the history are read under scope 'any' (A-15)
- L418: Including an environment outside the member's scope: a value past its max age there is due (A-17 pins A-15 against A-14's reading)
- L511: A known pending proposal is still exit 3 — due over unknown (A-10)
- L576: Case: expired 10 days ago — the plain listing still exits 0; --fail-on-due makes it 3
- L592: Case: due in 5 days — past-due-only passes, a 7-day window fails
- L608: Case: --due-within is meaningless without --fail-on-due — a usage error, before any network
- L641: Case: an unreadable list is a failed check, not a passed one
- L682: Case point: the check cannot pass on an age it could not read
- L688: Something known due is due whatever else could not be read (A-10): exit 3 carries the known part and names the unread part on the line
- L841: Scenario: re-added with the same key after the remove (rotation still absent) — the mandate remains, but suggesting a member-remove re-run would have an active member deleted

### `apps/cli/test/run.test.ts`

- L47: The same check as the entry point's argument validation lives here too — a defense line for direct callers; [''] is the 'one element but not runnable' shape
- L98: Case data: 'Path' defends against Windows case-insensitivity (compared after uppercasing)
- L217: Pins the ruling (M2) that no blanket prefix rejection was adopted — legitimate variables like NODE_ENV pass
- L222: npm registry auth is a legitimate secret-injection use of maruhi run: NPM_CONFIG_ as a whole is not rejected — only the execution-control keys are denied individually
- L239: Security: resolveSession checks MARUHI_TOKEN before the keychain, so a co-member creating such a variable could authenticate a nested maruhi as themselves; the whole prefix is blocked rather than individual names, so future MARUHI_* cannot reopen the hole

### `apps/cli/test/schema-export.test.ts`

- L1: Schema export/verify-snapshot tests (design doc §1-6): JSON Schema subset mapping, generated-marker framing, determinism; both commands pinned as the read-only, zero-value keyless class
- L173: Expected artifact semantics: names in UTF-16 ascending order (determinism); v1 = an empty schema (no fabricated constraints); '' type = no type keyword; url = string + format uri; an empty description is omitted
- L181: required holds only statements with required = true — required is never invented (v1 doesn't get in; optional doesn't either)
- L197: Types are treated as declarations — the artifact never uses the word 'verified' either (§14.3)
- L220: Hazard: the name is a free string from a signed statement — plain object assignment is eaten by the __proto__ setter and the variable silently vanishes from properties while surviving in required, a self-contradictory artifact undetectable even by byte comparison
- L337: A different environment's file whose variable set happens to match must not be collapsed into generic formatting-drift wording; the file-side title contents (attacker-writable) stay out of the report

### `apps/cli/test/schema-import.test.ts`

- L1: Schema import tests (design doc §1-3): ceremony-class deny (ADR-0016 decision-7 pattern), values never sent (shape observation only), pinned
- L149: Parser behavior pinned: consecutive comments join into a candidate and a blank line breaks them — a distant comment isn't attached
- L211: Case design: a nonexistent path — if the gate precedes the file read, no file error is emitted
- L407: Case shape: an unclosed quote (line 1 of a multi-line quoted value) — a real value, but this parser can't claim to have reconstructed it faithfully
- L444: The warning itself carries no detected value (which could be a secret) — length and kind only
- L498: The pinned measured shape of finding F': N declarations = 1 initial resolve + N x (1 resolve + 1 create + 1 effect check) — no bulk compound acceptance

### `apps/cli/test/schema-lint.test.ts`

- L1: Schema lint tests (design doc §1-7): best-effort positioning (always-on caveat), name-only reports, exit-code asymmetry (undeclared = 1 / unread only = 0), keyless class pinned
- L232: Case rationale: 'rest' doesn't fit the identifier shape; a non-env right side fails the left-boundary + right-side pinning
- L247: Regression guard: the bare shape keeps being picked up — the boundary addition must not drop the positive case

### `apps/cli/test/schema.test.ts`

- L1: Schema S3 tests (design doc §1-1/§1-2/§1-4, CRYPTO_SPEC §4.2/§6.3, AUTH_SPEC §12-7): display with the pinned agent-gate allowance, set partial updates, digest counting, run fail-fast, push activation, v3 honest failure mode
- L366: Case: even in an environment matching both layers of the 2-layer gate that refuses value display (known-agent + non-interactive), schema works — the pinned agent-gate allowance
- L387: Server acceptance (§12-8) refuses control characters, but a malicious server's or signer's distribution isn't bound — the display side's neutralization is an independent duty
- L417: S2's known gap: unless declared is counted into the digest recomputation, every pull fails on variables-digest-mismatch — success itself is pinned
- L428: Attack shape: a server hiding a value moves the active statement into declaredVariables; the digest still matches (statement intact), so only §6.3's value-distribution mandate detects it
- L472: Honest failure mode: v4 passes decode (no pinned ceiling), and the support-range check refuses it before signature verification — it doesn't masquerade as a Schema error or a bad signature (suspected tampering)
- L500: Case: the former v2 wire shape (v3 field set without maxAgeDays) is refused by the support-range check before signature verification — neither a partial-field-set refusal nor a bad signature
- L547: The error text must not contain the description — an injection surface via logs (session-46 §8 iteration 3)
- L662: Creation defaults: required = true (§1-2 — a declaration is the environment's contract), description = ''
- L686: A run with only --description must not silently drop type and required — full replacement is forbidden (§1-2)
- L752: A v1 statement has nothing to inherit required from (§1-2's partial update is a 'previous value' rule); silently applying the creation default true would put a presence contract the user never typed onto the signature — explicit is required
- L842: Case rationale: a repeating pattern isn't high-entropy (not detected) — real-value likeness grounds on disorder
- L865: The input itself isn't put into the error — it could be a secret
- L948: Scenario: first resolution nonexistent, create; server answers 409 (a concurrent declare landed first); re-resolution = declared, so the activation compound (§12-5's retry = re-fetch, re-sign)

### `apps/cli/test/scope.test.ts`

- L1: Scope-rule unit tests (2026-09-15 ES K4, design record §10): environmentKeysFor doesn't fetch or unseal anything outside scope (K4-F); 'all' covers only environments existing at the mandate's seq (K4-J)
- L235: delete_environment prunes the id from every listed scope, so a scope judgment run first would tell a listed member to widen scope to an environment that can no longer be scoped — both gates refuse the deletion before judging scope

### `apps/cli/test/server-command.test.ts`

- L1: Server argument-layer tests: nested subcommands (ADR-0016 decision 6) through the real runCli
- L65: The FP format check is the shared parser (fingerprint-flag.ts), run after the declaration (NonBlank) passes; the typed value itself never appears in the diagnostic

### `apps/cli/test/server-disclosure.test.ts`

- L1: Server disclosure tests (CRYPTO_SPEC §9): the shared prologue states disclosure on every project-opening command, on stderr so a --json document on stdout is unchanged; nothing said without a grant, after revoke, or once the scope is emptied
- L213: Fixture design: granted in both orders, so the output order cannot be the chain's
- L280: Without the project in the line, two projects granted to the same server key with repeating environment IDs would print identical lines and the run's ledger would print one

### `apps/cli/test/server-grant.test.ts`

- L1: Server grant integration tests (CRYPTO_SPEC §9 / AUTH_SPEC §12-6): server-key confirmation ceremony, the 4-field grant_server append, backfill across every environment x epoch, mid-run 409 recovery pinned at wire level
- L359: Attack shape: the FP is genuine but the enc public key is something else — a malicious server pairing an arbitrary key with the FP the user already verified; if the recomputation check didn't catch it the ceremony would be meaningless

### `apps/cli/test/server-revoke.test.ts`

- L1: Server revoke integration tests (CRYPTO_SPEC §7/§6.2): revoke_server append plus §7's forced rotation of every environment with no server-bound wrap in the compound; mid-run recovery derived from chain and verified statements alone
- L628: GONE_ID has no environment fixture, so pull / rotate would 404 (as a real server after deletion) — pins that the chain deletion means they're never called

### `apps/cli/test/session.test.ts`

- L1: Session unit tests: server URL resolution, master-key saving with overwrite detection, the crypto backend check, the MARUHI_TOKEN env path (login polling rules live in login.test.ts, AUTH_SPEC §4)
- L60: Fixture design: the OS keychain has no conditional write, so all that can be pinned is 'detect last-writer-wins and fail'
- L98: Race shape: another process wrote after ensureNoStoredMasterKey — a plain set would silently erase the other's key as last-writer-wins
- L110: Race shape: another process wrote right after my write — detecting that the read-back is not my record prevents registering a recovery blob for the discarded key
- L125: This check splits 'the key is unreadable' into key vs environment causes; returning false on a working environment turns even a genuinely broken record's diagnosis into 'environment unsupported — do not delete', making the only recovery step (deleting by hand) unreachable
- L132: Only the keychain path can point to a stored key — recover / generate have not stored anything yet, so shared wording written that far would point at something that does not exist
- L263: The most likely cause of this 401 in an unattended environment is expiry (W3a ruling CJ); the guidance names the fix — swapping the env var — and must never regress to the maruhi login-alone keychain guidance
- L281: If the decision were not made on the trimmed value, we would send 'Bearer ' (empty) and land on a 401 with guidance for a different cause
- L317: An env-var value is not a command-line typo, so it is not usage (2) — name the fix target (the env var) and exit with 1
- L323: The value itself is never echoed — a URL with embedded credentials is possible

### `apps/cli/test/sigv4.test.ts`

- L1: SigV4 signer tests pinned to AWS's documented worked example (IAM ListUsers, example credentials, 2015-08-30): canonical request hash, derived signing key, and signature are the documented values

### `apps/cli/test/startup-loads.test.ts`

- L1: P-6's point checked on the running CLI: parsing, help and version never load the implementation graph's heavy modules; commands reach them through lazy loads, pinned by an import trace of every relative import
- L58: spawnSync blocks the event loop, so vitest's timeout can't fire — on a hang, kill the child and fail the test
- L108: Positive control: the trace saw the command declarations — the check isn't idling
- L115: Case: env list opens the project first through commands/lazy.ts's wrapper; with no config that stops at the missing project, before the keychain and the network

### `apps/cli/test/support/argument-layer.ts`

- L1: Support module contract: the shared setup of the argument-layer tests — a logged-in environment whose server records every request and answers 404, plus the check that no typed value reaches the output
- L21: startEnv design: the server never responds (every request is 404) but records — to confirm via 'zero requests' that the rejection happened before the command body ran

### `apps/cli/test/support/chain-handler.ts`

- L1: Records the sharing map of the append helpers: which test servers use injectedAppendResponse / acceptAppendedEntry together and which use acceptAppendedEntry alone (DK K14)
- Added 2026-11-28 (after the audit; no base line): `lastHashOf` throws for a chain without entries, where the handlers used to send a body without `headHashHex`. No test serves an empty chain, and a mock that wants a body the server never sends says so with `offSpec`

### `apps/cli/test/support/env-rotate.ts`

- L299: Mock modeling decision: a checkpoint-hiding server stores no snapshot either (consistent hiding) — distributing an enumeration with no checkpoint on the chain would fail rule 2 right there

### `apps/cli/test/support/env.ts`

- L1: Support design: the real keychain (Bun.secrets) doesn't exist in CI, so it is not wired in — in-memory keychain, output-capturing CliIo, recording ProcessRunner instead
- L112: setTerminal is the primary boundary for whether values may be displayed, so the fake's default is 'a human's interactive terminal' (all stdio terminals); pass false to reproduce pipes, redirects, CI, unknown agents
- L169: failFloorPushCommits purpose: the floor is a SHOULD — used to pin down that detection does not rely on the floor alone when it cannot be written
- L175: failFloorIntentAppends purpose: journal-before-send is the only fail-closed floor write (no send when persisting fails) — used to pin a regression toward fail-open as 'not a single request reaches the server'
- L184: setVendorOrigin exists because production code knows only the preset fixed hosts and offers no override point — the swap happens at the HttpClient layer (the test boundary)
- L366: The browser stand-in must POST while the CLI is waiting, so it returns 'opened' without awaiting completion; the handler's rejection is not swallowed (vitest would fail as unhandled rejection — don't wait out the 5-minute timeout); openBrowser itself only reports launch success in production too
- L565: Trap: JSON.stringify(token) cannot be used — Redacted.toJSON() returns a redacted string, producing a 'seeded but cannot authenticate' test (the same trap as production login.ts)
- L569: Same trap for the master key: JSON.stringify would store the secret side redacted and make it undecryptable

### `apps/cli/test/support/exec-probe.ts`

- L1: Exec probe scope: the value arrives on stdin whole (16 KiB, Vercel's limit), output captured and returned untruncated (truncating before redacting would leak the value's tail), telemetry-off var present but no MARUHI_* in the child's env
- L58: Probe case: the rotation connector's capture reads stdout (the credential) whole up to 1 MiB; past that the script is stopped and nothing of it is kept (D-6)
- L78: Probe case: a flooded stderr is dropped whole (never cut, D-9) and drained — the script runs on and its value is read (D-10; a stopped script would strand the credential it may have created)
- L88: Probe case: a process the script left behind holds its pipes — the capture ends after the grace with the script's own answer (D-12); a script that ignores the stop is killed after the grace (D-13)
- L103: Probe case: bytes a leftover process writes after the script exited are never silently the answer (D-14) — a late line, or a flood past the cap after the exit, is refused naming the script's own exit code
- L107: Probe case: a script that failed on its own reports its own failure; what a leftover wrote is moot since nothing is pushed (D-15)

### `apps/cli/test/support/four-eyes-server.ts`

- L1: Mock fidelity decision: the acceptance side is not verified — the CLI's verified chain is the source of truth for derivation, which is what the tests care about

### `apps/cli/test/support/import-trace.ts`

- L1: Import-trace preload design: it only watches (resolution is left to Bun); Bun does not ask a runtime plugin about package or node: specifiers and erases type-only imports before resolving, so neither shows up — the trace's recorded blind spots

### `apps/cli/test/support/invite.ts`

- L126: acceptanceFixture's overrides exist to build a key-reuse shape: the signature is assembled over the post-override declared keys — used to pin down that the verifier 'verifies with the declared keys'

### `apps/cli/test/support/ledger.ts`

- L40: Trap: JSON.stringify(record) cannot be used — the secret side would be wrapped redacted, producing a blob that 'decrypts fine but the key is unreadable' (the same trap as production recovery.ts)

### `apps/cli/test/support/pipe-probe.ts`

- L1: Pipe-probe purpose: the pipe semantics of the redacted relay (live.ts startRedactedRelay — review finding pf4-design.md §19 C-1), run under Bun by live-run.test.ts (flood and grandchild modes)

### `apps/cli/test/support/proxy-client.ts`

- L69: Platform behavior the client relies on: Node emits 'connect' for every response to a CONNECT whatever its status; a refusal (403 / 502) carries its body on the raw socket
- L118: Platform pitfall: with no agent, Node honours createConnection — an agent of false would make a default one and connect to localhost:80 instead

### `apps/cli/test/support/proxy-probe.ts`

- L1: Proxy probe purpose: runs the forward proxy under Bun (the production runtime) and drives it with real clients (curl, Bun fetch, a ProcessRunner child) because vitest runs on Node; under test is that the TLS-wrap + loopback shape works under Bun's node:tls / node:http

### `apps/cli/test/support/pull-run.ts`

- L110: Fixture shape: the latest version's epoch differs per variable (§12-7) — ALPHA is epoch 2, BETA stays at epoch 1 (never re-encrypted after the rotation); each value signature declares the head where its epoch was current
- L245: Mock design: the manifest is computed from the distributed set itself, matching even sets tampered with / swapped via override — each test's negative verifies it is rejected by statement / value verification, not by the manifest

### `apps/cli/test/support/run-probe.ts`

- L1: Run probe purpose: exercises the production ProcessRunner's run-output redaction (live.ts relayRedacted, ROADMAP Phase 3) under Bun with a real child; the child prints the secret in a line, JSON-escaped, split across a pipe boundary, on stderr, and as every byte value

### `apps/cli/test/support/server.ts`

- L1: Why a wire-level mock server was chosen (session-11.md comparison): a wrangler dev spawn can't use the server's fake-github and needs D1 applied beforehand, while the CLI's client-side verification needs 'a server that returns malformed responses', which a real server can't produce
- L13: ResponseWriter is narrowed to the 2 methods actually used because @types/node's ServerResponse breaks structural compatibility when multiple @types/node versions coexist (a method present in only one of them)
- Added 2026-11-28 (after the audit; no base line): `onEndpoint` takes the method, the path, the path parameters and the body shapes from the `@maruhi/api-schema` definition by endpoint name. The types refuse a wrong name, a missing or mistyped field and another endpoint's body, but they cannot pair a status with its body and they let an extra field through (an arrow function's returned literal is not checked for excess properties). So the handler also decodes every typed reply at run time against the schemas the endpoint declares for that status, with excess properties as errors, sends it with the content type that schema declares (a problem goes out as `application/problem+json`, which the client's decoder selects on), and refuses a reply that brings its own body text or content type: a mock that drifts from the API fails the typecheck or the test that uses it. `offSpec` is the one way to answer outside the definition (a proxy's plain-text 502, a body the server never sends), and a search for it lists the deliberate cases. The `{ _tag: "Internal" }` bodies of the older 5xx mocks are such a case: the server's 500 is an RFC 9457 problem (`HttpApiMiddleware.ProblemDetails`), so they are marked `offSpec` and kept as they were, because the tests pin what the CLI prints for them. `onRequest` stays for the servers that are not maruhi (GitHub, the vendor APIs)

### `apps/cli/test/support/test-clock.ts`

- L1: Test-clock design: runCli provides its service layer once at the run's root, so a Layer.succeed(Clock) merged into the test env's layer overrides the clock for the whole command tree; two clocks serve two needs (virtual vs TestClock)
- L37: The waits/bounds split: a wait under 10 s is virtual; 10 s or more sleeps in real time — the client's 30 s request timeout is a bound on real work that must never be virtualized into cancelling in-flight I/O; a future test waiting 10 s+ per round knowingly costs real time

### `apps/cli/test/support/vendor-api.ts`

- L1: Mock fidelity basis: vendor API responses come back in the real wire shapes, verified against wrangler 4.128.0 / Vercel CLI 59.11.7 / the public REST docs; accepted requests and stored values are exposed as evidence that the value appears only at fixed body positions
- L349: FakeNetlify fidelity: shapes verified against swagger 2.57.1 and netlify-cli; an existing key on create is a 422 whose wording is the real response reported in Netlify Support Forums #88738 (not in swagger); list/create/update responses echo values

### `apps/cli/test/sync-command.test.ts`

- L1: Sync plan/apply tests: values never appear on argv / stdout / stderr / error text, stdin formats per vendor, production defaults to plan only (--yes), only the receipt's diff is written
- L313: Clarification pinned: plan never calls the variable-write API (plan only reads; the head-declaration PUT is part of the earlier sync and touches neither values nor metadata)
- L695: It stops at the first deletion so the second is never attempted — rebuilding the receipt would forget it, so it's named
- L864: The name rules need no plaintext, so they become ! at plan time (apply's check is a defense line)
- L884: On a first-run failure where nothing arrived, don't write an empty receipt — don't waste a version
- L898: Wording: the launch-failure reason continues the body — a process that never ran has no output, so it isn't phrased in the vendor-output slot or as 'Its output is shown above'
- L963: Case shape: the vercel-era receipt still has names 'as delivered' that are illegal under gh's rules — it stops earlier as a receipt mix-up, not as a name-rule error

### `apps/cli/test/sync-http.test.ts`

- L1: Sync http driver tests: values may only be placed in body entries (declarative-preset assembly); values and tokens never appear on URL, headers (other than Authorization), stdout, stderr, or error text
- L748: Wording rule: exhausted attempts aren't a 'refusal' — worded as a send failure
- L1244: Race shape: the same name was created between the list and the send — a POST to an existing key surfaces as the target's failure
- L1338: Wording rule: exhausted attempts aren't a 'refusal' — worded as a send failure
- L1438: Wording rule: don't call something that was never sent 'refused'
- L1512: Wording rule: the list did get a response — word it as a listing failure, not 'nothing sent'

### `apps/cli/test/sync-init.test.ts`

- L1: Sync init tests (SY2 phase 2, ruling F): the assembled config passes the strict parser as-is (round-trip); touches neither network nor files
- L173: Rationale: left to the config's parser, a typo would read as a problem in the config ('The config would be invalid: ...'), not in the flag

### `apps/cli/test/sync-push.test.ts`

- L1: Sync-push tests (SY2 phase 3): onPush targets apply directly as the push's cleanup or kick off CI via gh workflow run; the push report comes first, a cleanup failure is a warning, production is never applied directly

### `apps/cli/test/sync-units.test.ts`

- L120: Rule pinned: even spelled identically to the default, writing the runner in config counts as 'naming it specifically'
- L376: A value no member of an optional/nullable key accepts reports the key's own wording — never the union's default message
- L698: Names: GitHub stores them uppercase — two names differing by case would fold into one secret, so uppercase only
- L735: Scrubbing rationale: truncating to the last 64K chars before scrubbing would leave a straddling value's second half unmatched and displayed as-is — sized so the cut lands at the value's 20th char
- L871: Fixture construction: an object literal's __proto__: becomes the prototype designation, so the receipt is built from JSON
- L889: Case: a leftover receipt name violating today's rules still passes, since a delete carries no value

### `apps/cli/test/targets.test.ts`

- L1: Targets-table test rationale: TARGETS is the single source for binary generation and release.yml's smoke matrix, so a tear in the table directly means a missed build, an unverified artifact published, or a matrix interpretation error
- L32: Case: .exe on Windows only — adding it elsewhere breaks the smoke run path

### `apps/cli/test/test-suite-partition.test.ts`

- L1: Test-suite partition audit: the resolver's failure mode is a project landing in no suite (a static --project list would skip it silently); this test cross-checks the partition against vitest's own resolution of the same config
- L17: Setup: the audit spawns `vitest list` as a nested invocation — keep vitest's own markers out of its environment
- L62: Case data: an app's non-unit config (the web e2e config) has no suite by design — adding one to projects: must fail, not be skipped

### `apps/cli/test/token.test.ts`

- L1: Token list/revoke wire tests (AUTH_SPEC §6, W3a): ordering, scope rendering, empty-list wording, and the 403/404 guidance split pinned

### `apps/cli/test/var-history.test.ts`

- L1: Var history/rollback tests (2026-09-27 VH, rulings V3/V4): history is metadata only and never fetches a value; rollback restores the old plaintext as a new version declaring sameValueAs (§12-5), re-encrypted under the current epoch

### `apps/cli/test/var-rm.test.ts`

- L1: Var rm tests (S4): removing a v3 variable keeps schema fields and layout byte-exact (§4.2 convention); removing a v1 variable stays in v1 form (no silent layout upgrade); removal requires interactive confirmation or --force (fail-closed)
- L271: Scenario: the post-confirmation 409 — a concurrent removal + same-named creation put a different variable under the typed name; the confirmation binds the variableId, so the retry re-resolves that ID, the confirmed variable is already deleted (a determinate error), and nothing is sent toward the replacement

### `apps/cli/test/var-rotate.test.ts`

- L1: Var rotate integration tests (PF6, rulings R2-R6): rotation decrypts the current credential in memory, creates the new one at the issuer, pushes as an ordinary new version; no value is ever printed
- L373: Setup rationale: the due date is computed off the command's Effect clock — pinned to a fixed date here so the whole report line can be asserted
- L666: Scenario: the finalize target is decided against the issuer — the listed key held by version 2 of the key id variable authenticates with version 2's secret, so it is the one deactivated; the history endpoint's versions and times play no part (a server cannot steer the target by backdating rows)
- L744: Scenario: the companion lands as version 2, then the secret's push is refused — the message must not promise that a re-run reclaims the key (two active keys refuse); it names the orphaned key
- L1092: Scenario: an unfilled epoch gap (device holds only the epoch-2 wrap) — the finalize must still run; the undecryptable version is skipped with a warning, and fail-safe: the skipped version can only shrink what gets deactivated

### `apps/cli/test/version.test.ts`

- L1: Version test rationale: releases are premised on the workflow checking tag vs package.json agreement, so the regression wall is 'the package.json version shows up verbatim in --version'
- L22: A lax check would first get bounced at npm publish — after the GitHub Release already exists — leaving Release and npm disagreeing (release.yml's version-check is the same shape)
- L37: spawnSync blocks the event loop, so vitest's timeout can't fire — on a hang, kill the child and fail the test

### `apps/cli/test/workflows-supply-chain.test.ts`

- L1: Workflows supply-chain invariants pinned mechanically so a later edit cannot undo one unnoticed: an executable in a workflow comes from the commit being run or from a digest-verified fetch, no run reads a store another run can write, a release publishes only what its build job produced
- L158: REVIEWED_ACTIONS rationale: actions that could grow a cache are allowed at the reviewed commit only, so a bump re-checks them here; actions/setup-node is deliberately absent — v5+ turns a package-manager cache on by default and downloads Node unverified on a tool-cache miss
- L177: A pinned install script checks the digest, then unpacks, then runs the unpacked binary — in that order, so nothing downloaded runs unverified
- L331: A flag bun ignored would fetch the runtime from npm — this env makes that fail
- L346: bun ignores a misspelled flag, so the probe goes through the same compile call
- L365: An inherited BUN_OPTIONS or BUN_BE_BUN would let a probe that runs code pass, and an inherited probe variable would fail it whatever the flag does
- L451: Byte for byte, so nothing (|| true, a second download, a fallback path) rides along
- L462: No if:, continue-on-error, shell or env can make it skip or soft-fail; it runs background: true so the download overlaps the install prefix, and the id is how the wait step below references it
- L518: playwright-core 1.64 replaces all its mirrors (Chrome for Testing's included) with this host, so `playwright install` fails before unpacking, whoever runs it and however
- L524: Nothing overrides the pinned download host — a PLAYWRIGHT_<browser>_DOWNLOAD_HOST would win over it; the only other PLAYWRIGHT_ variable is the verified executable path the install step exports
- L533: A background step's $GITHUB_ENV write is only visible after a wait that names its id, and only inside the job that ran the install — a browser step in any other job could never see the path at all, so scan every job
- L569: bun runs pre<name> / post<name> around every script, so every script counts
- L698: A custom shell (shell: 'true {0}') would skip the script and still pass — hence shells are asserted absent
- L812: defaults.run.shell or BASH_ENV (sourced before every bash step) at any level would run before or instead of the pinned scripts, and GH_HOST would point publish-github's gh release create at another server — hence workflow.defaults must be undefined
- L857: Retention bound rationale: a re-run may start 30 days after the run and, with the approval gate, wait 30 days more

### `apps/server/test/approval-accept.test.ts`

- L1: Pins four-eyes acceptance: expires_at upper bound, pending cap of 32, typed 422 ProposalLimit, and approve side effects identical to direct acceptance
- L53: OWNER2 is the second owner; four-eyes enablement requires owners >= the required count
- L72: appendRaw is the generic-append variant where the caller judges acceptance; it advances the fixture head on acceptance
- L113: propose returns the accepted proposal entry's hash, which the approve/withdraw calls reference
- L142: Pins the audit-row shape and ordering among a completed approve's side effects
- L161: Pins write order in one acceptance task: detection row after the mirror/applied row
- L233: Exact-equality boundary is pinned in proposal-policy.test.ts; this test covers inside-bound only
- L251: Pre-acceptance rejection precedes CAS/verifyChain and leaves no trace in derived or stored state
- L266: K5-C: an already-expired proposal is accepted but does not count toward the pending cap
- L283: Closing an expired proposal frees no slot because it was never counted toward the cap
- L291: Withdraw frees one slot; the in-term proposal's hash is resolved from the chain
- L333: Direct append under four-eyes is rejected approval-required as a consensus rule
- L340: Nothing happens at proposal time (pre-application, rulings P7/P21)
- L364: Removed member can no longer read (§11-2)
- L398: Membership starts at the approve's seq, so the new member can read from application
- L416: Removal does not erase the epoch-1 wrap (§12-6 — kept for a return under the same key)
- L469: Sweep runs after the applied row within the same acceptance task

### `apps/server/test/attestation.test.ts`

- L1: Pins head-attestation acceptance, storage and distribution: monotonic acceptance, row deletion on remove, distribution to current members only, rate limiting
- L32: READER stays a reader because no change_role is appended in the fixture chain
- L155: DO reset is independent of the D1-side reset+reseed, so the two resets run concurrently
- L184: Acceptance time is not distributed (§16-1, limits behavioral information); pinned via key set
- L203: Re-submitting the same seq is an idempotent 204 — retry-safe success, not a swallowed 200
- L207: A seq regression is 409 + stored seq; it must not quietly swallow floor corruption
- L243: A seq ahead of head is chain-head-unknown (§6.4 — the server has no re-sync branch)
- L252: Guards the premise: MEMBER was added at seq 2, so the head is seq 3
- L254: Crypto-side attester-not-member-at-head folds into the wire's chain-head-state-mismatch
- L271: Server uses the calling principal as attester_user_id, so a key/token mismatch fails the signature
- L301: Window seeded directly instead of 60 PUTs; window semantics are covered in data-store tests
- L340: Attestation row deleted as an acceptance side effect, converging to chain-derived truth
- L344: Re-submission by a removed member gets §11-2's uniform 404

### `apps/server/test/audit-d1.test.ts`

- L1: Pins D1 audit recording via the real HttpApi path; the same-batch append is observed as operation success and event presence always agreeing; identity rule bars provider IDs/logins/emails
- L116: identity_linked carries only the provider kind name; numeric IDs/logins banned by §1-2
- L124: Personal-org auto-creation is also recorded as org events (§3.2)
- L180: Window state lives on the counter row (log is not scanned), so the limit is seeded directly
- L189: Suppression is not silent: the first suppression leaves one marker row
- L194: Marker actor has no user_id; external IDs/IPs are never written (§1-2)
- L204: Marker rows grow only at powers of 10, not per suppression
- L229: Buckets split by auth_method, so Web OAuth failures keep being recorded when the CLI bucket is full
- L266: code-exchange-failed is an independent bucket even under the same auth_method
- L297: User pre-seeded because CLI login is for existing accounts only (ruling DH)
- L304: Approval actor is the looked-up internal user_id; payload carries no provider info (§1-2, §4-2)
- L329: Deleting the replaced token row is part of rotation, not an explicit revocation event (§3.1)
- L351: start→verify is unrecorded (ruling DH); the callback code-exchange failure is the first recording point (§4-1)
- L425: A re-revocation whose delete misses adds no event: one revocation = at most one row
- L490: Ops via a PAT carry the token id as actor (§2)
- L555: Idempotent insert on an existing row adds no event — it must not fabricate a creation event
- L589: Structural typing lets a wider object compile; the store's serialization check refuses it before SQL
- L598: The expected defect's cause is the store check, surfaced via the repository boundary's orDie
- L620: row_id is random hex and may contain digit runs, so it is excluded from the leak scan

### `apps/server/test/audit-head-bounded.test.ts`

- L1: Pins bounded lazy audit-head extension: per-chunk saved progress, retryable 503 AuditHeadNotReady on all three head-reading paths, fail-closed stale judgments
- L43: Seed rows use any non-mirror section 5.1 event; var.version_pushed may carry no payload and does not touch the chain_seq invariant
- L57: Backlog is seeded directly into DO storage because HTTP cannot produce enough rows to reach the limit; the instance is evicted so caches re-read
- L91: Tables are materialized first because a DO is normally materialized at genesis acceptance; this unit test seeds the audit store directly
- L154: The standalone checkpoint uses zero environments plus notarization, a shape valid under the consensus rules
- L179: Fail-closed: the membership check must not run against a partially extended column, or a fabricated head would wrongly become a 422 audit-head-unknown
- L228: Resend is accepted because the saved progress means re-extension covers only the remainder and the real head sits at or above the position lower bound

### `apps/server/test/audit-index.test.ts`

- L1: Pins partial-index selection by the real readers via EXPLAIN QUERY PLAN and the measured size effect; query text is captured from the real audit store to avoid verifier drift
- L37: Tables are materialized first because a DO is normally materialized at genesis acceptance; this test seeds storage directly instead
- L73: SqlStorage wrapper captures executed SQL; everything but exec delegates, and native getters are called with the real object as receiver
- L106: Fixture: one aggregated-form var.read row — target/key FP all NULL, the dominant shape (§3.3)
- L138: Fixture: aggregate rotation.recommended row with exposure bound epoch 1 (§3.3 Sc-5, §4.1-5)
- L266: Range is cut on the index's seq component, not by reading all actor rows and discarding
- L270: Omitted or non-finite range ends are unbounded (the traditional all-seq behavior)
- L299: Rebuild timing is proportional to row count — the estimate source for applying it to an existing DO
- L310: Pins whether freed pages return to databaseSize, the metric the capacity guard reads
- L323: Distinguishes freed pages returning vs staying on the freelist in the migrate-in-place direction
- L362: Corrupt row inserted raw because the payload schema runs on the write path; reader must drop it, never crash
- L399: Flag read is two queries: aggregate rows via ae_event, resolution rows via ae_var
- L422: Malformed fingerprint rows inserted raw; reader must read the fingerprint as null, never crash
- L498: Without the restrict, var-a's flag would leak into var-b's expansion

### `apps/server/test/audit-read-aggregate.test.ts`

- L1: Pins the aggregated var.read shape (one row per environment, NULL id columns), the density measurement, and that aggregation loses no rotation-detection inputs
- L71: Created in reverse order to verify enumeration is pinned to variableId ascending
- L89: Digest input pinned to stored bytes: key order variableId → epoch → version
- L99: Round-trip uses the shared helper — server writer and CLI reader are the same implementation
- L159: Control shape is refused by the current schema, so it is inserted with raw SQL in the store's layout
- L279: A >2x margin under the slack ensures the export line is always accepted (never un-mirrorable)
- L599: Regression shape: the row would be dropped if a per-variable MAX(deleted) were the upper bound
- L659: A below-admin non-actor viewer still sees it (class 1 — no self restriction)

### `apps/server/test/audit-read-paging.test.ts`

- L1: Pins audit read paging bounds, the invite.* permission axis (chain role admin of the project only), and self reads returning only one's own rows
- L54: Loop bound exists so a regression where the cursor stops advancing fails instead of hanging
- L79: Loop bound exists so a regression where the cursor stops advancing fails instead of hanging
- L100: The before cursor accepts only 32-digit lowercase-hex row ids; numeric seqs and short/uppercase hex are Schema-rejected (opaque cursor, AUDIT_SPEC section 7)
- L129: 'Exists but invisible' must answer like 'no such id', else the cursor is an existence oracle
- L146: Server does not verify the issuance document (format check only, AUTH_SPEC §15-2), so fixtures only match the format
- L197: D1 response carries no seq to anyone — the global sequence is a cross-tenant ordinal (AUDIT_SPEC §7)
- L216: Org admin status grants no read access to a project's invite rows (§7)
- L255: Seq is not in the D1 response (§7), so row identity is confirmed via the opaque row id
- L269: Only one's own rows (§6): no row where neither actor nor target is the user

### `apps/server/test/audit-read.test.ts`

- L1: Pins visibility classes: below-admin sees class-1 plus own rows only and class 2 behaves as nonexistent; admin visibility is chain-admin x token-admin
- L60: One's own var.read is visible because self-reads apply regardless of visibility class
- L69: Every row is checked against the visibility predicate itself; below-admin responses carry no seq so class-2 counts cannot be inferred from ordinals (section 7)
- L95: Admin-visible responses carry the stored seq, the material for section 6's gap-equals-deletion-trace detection
- L103: The read-scope token is issued under a distinct name so same-name rotation (AUTH_SPEC section 6) does not revoke the fixture's token
- L115: Rows where the user themself is the actor stay self-readable regardless of class (section 6)
- L143: Aggregated var.read rows have no variable_id column, so the section 7/Q4 filter matches them via the payload enumeration
- L182: verify admits unmapped names deliberately: dropping a forged row server-side would leave a forgery coverage hole for non-admin readers
- L201: Pins that the namespace prefix allowance does not become a class-2 visibility hole for below-admin readers
- L253: Id filters are plain strings because audit rows replay stored text; an out-of-form value matches nothing and is never a decode defect
- L265: Probes that event-prefix filtering is not a LIKE implementation: % and _ must not act as wildcards
- L283: Filtering by someone else's actor id is a data-independent 403 (section 6: cross-searching another's rows is class 2)

### `apps/server/test/audit.test.ts`

- L1: Pins the audit log: gapless monotonic seq, chain mirror carrying actor, chain_seq and both timestamps, identity rule barring provider info and emails from rows
- L158: Pins author key FPs on lifecycle rows: meta-accompanied ops copy the author FP; cascades copy the actor FP (§3.3)
- L207: Genesis's target is the creator — the start of the membership interval (§3.4)
- L215: Scope is also copied into the mirror payload (AUDIT_SPEC §3.4)
- L224: Commitment pinned to the §5.2 computed value, not just shape — rejects mutants copying another epoch's value
- L249: Composite appends a boundary checkpoint at H+2 after create/rotate at H+1 (§12-4), fixing the seq arithmetic
- L257: Boundary checkpoint mirror is recorded at the H+2 seq and copies the environment tuple (§3.4)
- L305: FP = SHA-256(enc public key)[:16] (CRYPTO_SPEC §9); chain verification requires a match
- L345: Metadata-only mode distributes no values, so it adds no audit rows — 'do not record reading what was not read' (§3.3, §12-7)
- L394: Seq is gapless from 1 — a gap would be a trace of deletion (§6)
- L400: Composite environment creation atomically writes chain mirror + env.created + one dek.registered per recipient (§12-4, §3.3)
- L414: A bulk pull with values is one aggregated row per environment (§3.3); the payload carries the enumeration
- L421: Environment deletion atomically writes the chain mirror, then var.deleted cascade and env.deleted (§12-4)
- L446: Signed ops copy the chain-derived key FP at acceptance; signatures/hashes/ciphertexts are not logged (§3.3)
- L457: Aggregated form: variable-grained columns NULL, payload holds the returned-variable enumeration (§3.3)
- L470: var.read is not signature-accompanied, so it has no FP (§3.3 semantics)
- L498: Failure discards the numbering cache; next append continues from live MAX(seq)+1. Only the cache is pinned — production rolls back chunk 1 too
- L525: Even with a violation in the back half, front-half rows are not partially appended across the chunk boundary
- L552: Structural typing lets a wider object compile; the store's check refuses it ahead of sequencing and SQL
- L614: 8 variables exceed the 5-row multi-row INSERT, so the deletion cascade exercises split chunk appends
- L628: Discarding the in-memory next seq simulates a DO restart; numbering must continue from a MAX(seq) re-read
- L654: env.created is meta-statement-accompanied (§4.2), so it copies the author's key FP (§3.3)
- L658: Session-auth data mutation is 403 by the §5 capability restriction and leaves no audit row
- L747: dek.registered copies the registration signature's signer FP (§5.1, §3.3 — for reconciliation)
- L749: Registered via a PAT, so the row carries the token id (§2 actor attribution)
- L832: Deletion is not signature-accompanied, so it has no FP (AUDIT_SPEC §3.3)
- L847: Long hex runs are stripped before scanning: a real provider-ID leak appears as a short standalone value, so detection power is kept
- L864: A broken row is treated as null on read; staged/restored rows with this value are refused before derivation or installation

### `apps/server/test/auth.test.ts`

- L1: Pins the auth/identity foundation (AUTH_SPEC sections 3-6) via the real SELF path; the only stub is the GitHub API outbound fake
- L68: State is stored in a cookie and must match the query — the premise of the §3-2 verification
- L82: TCB policy (CLAUDE.md): session-cookie attribute regressions are detected by this test
- L91: Both Set-Cookie headers must survive index.ts's withSecurityHeaders response rebuild intact
- L104: The state cookie is expired after use (§3-2 single-use)
- L120: Only the GitHub-side verified primary email is stored (§3-3)
- L128: Sessions are DB-backed with only the hash stored — no row holds the raw value
- L206: 512-char limit on code/state fails as a wire-Schema 400 before the handler; the fake GitHub's silence backchecks the cutoff
- L233: The state check holds no server-side state (double submission only); only the per-IP rate limit bounds frequency — this pins that topology
- L269: A different IP is counted independently — pins the rate-limit attribution unit
- L300: Wire-boundary helper premise: no IP attribution means the request is not rate-limited
- L308: DP4 scriptless-page discipline: self-hosted CSS only, CSP allows no inline styles/scripts; real file serving pinned in web tests
- L345: flowToken does not ride the browser channel (verificationUrl) (§4-1 (1))
- L348: start records nothing (ruling DH): no flow row, no user-side event
- L354: A poll before the browser leg is a typed pending — no row is the happy path (§4-1 (5))
- L365: Clickjacking defense: frame-ancestors does not fall back to default-src, so its explicit presence is pinned
- L374: Confirmation code is the page's largest element on its own element (verification UX, §4-1 (4))
- L407: Issuance parameters are the values settled at start, issued from the row's stored values (§4-1 (1)/(4))
- L419: The DB holds no raw token value — hash only (§6)
- L433: Single-use issuance: a re-poll on a consumed flow is a uniform rejection (§4-2)
- L441: CF-Connecting-IP is overwritten by the production edge; the burst of 2 windows + 2 is sized to observe the 429 without flaking
- L466: A different IP is counted independently — pins the rate-limit attribution unit
- L476: Limiting runs before verification, so even a fabricated credential burns no CPU
- L518: Rotation is an atomic delete+insert batch; concurrent handoffs never leave more than one same-name token
- L529: Cap of 100 tokens: the 101st new name is 429 at issuance, while same-name rotation keeps working (§6)
- L549: An issuance failure after CAS success ends as consumed — fail-closed, no half-distribution
- L564: Seed design: names differ so there is no UNIQUE contention — if admission were non-atomic, all 8 would get in
- L635: Control and bidi control chars in tokenName are rejected at the wire boundary (§6); non-retroactive — existing rows are not migrated
- L644: The flowToken's MAC covers the flowId, so recombining another's flowId with one's own token is a uniform mismatch (§4-2)
- L662: Extending the self-declared expiry fails at the MAC — the expiry check comes after the MAC; only signed values are trusted
- L680: A valid-MAC but expired token is typed differently from recombination (invalid)
- L697: Tampering with an issuance parameter fails at the vsig with a uniform scriptless error page (§4-2)
- L707: A missing vsig gets the same uniform page — absence and tampering are not distinguished
- L717: Regression shape: dropping the callback's vsig re-verification would let flowId knowledge bind arbitrary parameters to another's flow
- L759: A vsig-valid value failing scope decode is an implementation bug / key compromise — a defect (500), not a uniform refusal
- L795: An expired URL signed by the real key is also fail-closed at verify
- L815: Pins the uniform page's substance (same HTML + CSP as the tampering path), not just the status
- L823: CLI login is existing-accounts-only (no get-or-create): an absent account ends on the guidance page with no user or flow-row creation
- L860: Re-arrival under a different user_id is a uniform error — neither a hijack nor a ticket-revocation DoS; the ticket does not rotate
- L883: Re-arrival under the same user_id is idempotent: the approval page re-renders and the ticket is replaced
- L890: Only the newest ticket is ever valid — replacement expires the old ticket
- L902: Pins the approval CAS expiry guard: dropping it would record a false auth.login_succeeded for an expired row
- L942: denied is a typed state for the legitimate flowToken holder (§4-2 — it carries no new information)
- L965: flowToken is a bearer: concurrent polls are expected input; only the CAS winner issues — double-distribution is structurally eliminated
- L986: Concurrent first starts converge: first-write-wins (INSERT OR IGNORE) + read-back yield the same stored signing key
- L1005: Cap boundary pinned from both sides (Nth admitted, N+1th rejected) — detects off-by-one and non-atomic admission
- L1031: Capacity exhaustion gets the uniform error page (§4-2) — reaching the cap is not distinguished
- L1043: Consumed/denied rows are ineligible for opportunistic deletion until expiry + grace (§4-1 (5)); pins the boundary from both sides
- L1148: Token + cookie without the CSRF header passes as the token principal — safe because a cross-site request cannot attach Authorization
- L1226: A token-principal logout neither revokes the Web session nor returns a cookie expiry, even with Bearer + cookie sent together
- L1299: Not only the DB sliding extension — the browser cookie expiry is refreshed on every response
- L1322: A resolve right after issuance skips the UPDATE when the extension gain is < 1 hour (write thinning)
- L1339: Premise: the real workerd D1 error message carries a ': SQLITE_CONSTRAINT (extended: ...)' tail
- L1345: Pins that unique-violation classification accepts both error shapes: a plain Error on the batch path and DrizzleQueryError's cause on the single-query path
- L1370: The captured constraint must be exactly the target, never the tail — the invites race maps on this text, so pollution would silently become a 500
- L1386: Pins the real D1 message shape end-to-end with an actual duplicate insert, not just synthetic text
- L1430: Request shaping works around a known workers-types gap: fetch requires IncomingRequestCfProperties, a constructed Request is CfProperties
- L1441: The default test binding sets the server key (§14 lease-path tests need a real key); client_id returned unauthenticated is this test's subject
- L1457: Missing GitHub vars also fall to 503 — passing through would make /auth/config an encode defect redirecting with client_id=undefined
- L1467: An unregistered secret is 503: passing through would degrade auth to an opaque exchange failure while /auth/config's 200 gives false comfort
- L1474: cliStart also fails closed before issuing flow credentials (§4-1 (1))
- L1500: The keypair is derived via RFC 9180 DeriveKeyPair, so the same ikm always yields the same public surface
- L1514: FP = SHA-256(enc_pub)[:16] (§9), recomputed here — the same computation the CLI verifies with
- L1537: signupPolicy is an always-present advisory (AUTH_SPEC §3, default 'open')
- L1546: A malformed server key is treated as unconfigured but is deliberately NOT fail-closed — the key is an optional feature; see SELF_HOSTING.md
- L1566: Every response gets nosniff + no-store because some paths carry raw tokens/ciphertexts/wraps; HSTS too since the API worker can take a custom domain
- L1584: The pre-router 413 path for the 8 MiB body cap also goes through withSecurityHeaders — pinned here

### `apps/server/test/cf-env.test.ts`

- L1: Pins hand-written Env types against cloudflare.config.ts via InferEnv per mode; secret fields are the exception, a union of Workers Secrets (self-host) and Secrets Store bindings (hosted)
- L31: DO bindings are compared by kind with optionality checked separately because InferEnv without GlobalProps types them as DurableObjectNamespace<undefined>
- L43: The parity assertion covers every binding either mode declares; the secret fields are excluded here and pinned separately below
- L48: A binding is required in Env exactly when both modes declare it; the hosted-only OPS_BACKUP_BUCKET stays optional
- L61: Self-host and restore declare no secret fields: on self-host they are Workers Secrets, outside the config entirely
- L65: Env secret fields are string | SecretsStoreSecret, covering self-host plain strings and hosted store binding objects
- L75: Only the OAuth pair is required in Env; the IKM and the webhook URL back optional features

### `apps/server/test/chain-capacity-frame.test.ts`

- L1: Pins the chain byte cap against the DO RPC frame: a full 12 MiB chain answers in one frame, a full-environment lease spans separate results, one more byte is a typed 422
- L52: RPC_FRAME_BYTES is workerd's refusal threshold for a serialized DO RPC result, the reason for the caps
- L74: A tuple-less checkpoint's canonical size varies only with the seq digit count
- L94: Chain is filled with rotate_epoch entries at ~1.1x serialized-to-canonical ratio, a worst case for the frame, leaving exactly one checkpoint of room
- L144: Pins that rows written outside an append do not show through the parsed-chain cache

### `apps/server/test/data-checkpoint.test.ts`

- L1: Pins standalone checkpoint acceptance: two authorization levels, the 5 cross-check rejection reasons, atomicity, and audit-head lazy materialization with its position floor
- L65: GITHUB_IDS seed values are copied from data-fixture.ts because that module's copy is private
- L72: The write-scope token is issued under a distinct name so same-name rotation does not revoke the fixture's default token
- L192: First access recomputes from existing audit rows — this doubles as the §5.1 introduction migration (lazy materialize)
- L211: A half-scoped shortfall (admin role × write token) is also 403 — the min of effective permissions
- L296: Attack shape: notarizing a nonexistent future manifest_version would jam later legitimate manifests; the §6.4 acceptance match drops it
- L306: Atomicity: the rejection leaves nothing on the chain or mirrors — no contamination of the baseline
- L321: The consensus rule allows equality, so this rejection comes from the acceptance-time cross-check side
- L338: A live environment without a manifest means a corrupted DO or crafted snapshot — an invariant violation (500), never a 422 (§12-5 (6), §16-2)
- L354: The rejected DO RPC makes workerd log an 'uncaught exception' line even though the worker catches it — expected noise
- L361: Any defect answers the same 500; the direct instance call pins which one fires (append's checkpoint acceptance)
- L396: Fixture shape: an attestation fetched before the CAS parent settled — an issuance that did not re-fetch after a CAS race (§6.4)
- L423: A zero-environment notarization is valid under the consensus rules (§6.2) and no position floor is imposed
- L547: The creation composite's boundary checkpoint (empty enumeration) is the baseline from birth (§12-4)
- L597: A subset re-checkpoint is valid under the consensus rules (§6.2)
- L604: An environment not in the payload keeps its existing snapshot unchanged (§16-2)
- L608: Distribution (§12-7) tracks each environment's latest covering checkpoint position
- L615: A chain.checkpointed mirror row is recorded per acceptance (AUDIT_SPEC §3.4)
- L666: Rowid marker design: pushing the max rowid up with another env's row makes replacement (fresh rowids) reliably observable
- L710: Digest of the stored enumeration equals the tuple row's digest — the invariant the skip judgment rests on

### `apps/server/test/data-dek-server.test.ts`

- L1: Suite split: recipient class server (section 12-6 / CRYPTO_SPEC section 9) and expectedWrapRecipientCount live in this file; see data-dek.test.ts header
- L46: The server enc pub is a dummy: any 32 bytes are a formally valid X25519 key, and the server judges wraps on identification and signature only
- L119: A server row carries the FP in target_key_fingerprint — never mix a key identifier into the user_id column (AUDIT_SPEC §3.3, §2)
- L131: No server row leaks into distribution (listMine) — distribution is to oneself only (§12-6)
- L156: An environment created after the grant is out of scope, so the composite's complete set is members only (§12-4)
- L188: The wire union types a server recipient as a key fingerprint, so a member's ULID never reaches the DO's recipient check
- L199: Both the FP and the enc public key must match (§12-6)
- L238: A complete set including the server direction is accepted, signed by the rotation's executor (§7)
- L256: add_member's user_id is free-form with no existence check (§11-1); the stored row's PK is the device axis, so an FP-valued user_id is possible
- L321: The same id and same key never coexists: §6.2 key uniqueness keeps grant-named keys off current devices, so add_member is refused at append
- L413: Pointing at a member wrap as class server is refused at decode (400); passing it through would hide the deletion from the audit index (AUDIT_SPEC §1-2)
- L431: Reverse direction: an FP is a valid user-id string, so it decodes and then mismatches the stored row's class = 404
- L467: Pointing at one (epoch, recipient) as both classes is refused at decode, rejecting the whole request before either ref resolves
- L496: Fixture premise: a one-device member with its own key bytes — no two devices share a key (CRYPTO_SPEC §6.2)
- L504: One initial key = one device; the cap is structurally (owner, all) (CRYPTO_SPEC §6.2 DK)
- L534: A member can carry a grant's FP as user_id (§11-1), but wraps are addressed by (id, enc pub), so member and grant are two slots (§6.2)

### `apps/server/test/data-dek-signature.test.ts`

- L1: Suite split: DEK wrap registration signatures (section 12-6 / CRYPTO_SPEC section 5.1) live in this file; see data-dek.test.ts header
- L55: Repair-path re-registration carried in by a non-signer is rejected: caller must strictly equal signer; nothing is inserted and no audit row remains
- L101: A correct signature transplanted from another wrap fails verification because the signed_bytes differ per recipient
- L167: CRYPTO_SPEC §5.1 scenario: re-submitting another's wrap into a deleted slot is closed by signer mismatch; the sock-account form is unbuildable under §6.2
- L202: Re-submitting a MEMBER-signed wrap verbatim is a 422 — strict equality of caller = signer (§12-6)
- L244: §6.2 member-key uniqueness removes the re-attribution root cause (defense in depth); vector coverage lives in membership.test.ts
- L278: A signature is attribution, not a freshness proof: re-registration by the original signer with identical signature is valid (no timestamps/nonces by design)
- L323: Empty deks: [] is rejected — a silent 204 no-op would hide a client bug mistaking an empty send for a completed registration
- L384: Verification fails on a forged declared signer — signer_user_id is part of the signed data (CRYPTO_SPEC §5.1)
- L412: An undecryptable wrap is accepted if the caller's signature is correct — the server cannot verify contents (E2EE); attribution is pinned via signature + FP
- L481: Attribution cross-check via dek.registered signer FPs (§3.3): creation-bundled OWNER-signed, then MEMBER-signed re-registration

### `apps/server/test/data-dek.test.ts`

- L1: Pins DEK distribution and the new-member backfill/repair paths (sections 12-6/7) via SELF and DO SQLite; the suite is split across the data-dek files
- L112: The inviter wraps the existing epoch's DEK for the new member and registers it (§7)
- L225: Environment creation is on §5's explicit-deny surface: uniformly 403 for sessions regardless of the CSRF header — capability judgment comes first
- L244: Control: the same body is accepted for a token principal, proving the rejection stems from the session principal
- L280: Re-registration goes through the shortfall-append path (§12-6)
- L344: The project itself is hidden from non-members (404 — §11-2)
- L389: A rejected deletion leaves no dek.deleted audit row at all — separation of verification and writing
- L476: An empty deletion list is a 400 — destructive call shapes leaving zero audit trace are not allowed (§12-6)
- L481: The count cap is the registration side's MAX_DEK_WRAPS_PER_REQUEST and is judged before existence checks

### `apps/server/test/data-environment-ciphertext.test.ts`

- L1: Pins the 8 MiB per-environment current-ciphertext cap judged on push, creation-with-value and activation, and frame fit of a full pull and lease
- L56: RPC_FRAME_BYTES is workerd's refusal threshold for a serialized DO RPC result, the reason for the cap
- L206: Regression shape: a tombstoned variable's kept version row must be skipped via deleted_at IS NULL, not merely because rows are gone

### `apps/server/test/data-environment-rotation.test.ts`

- L1: Pins epochs and rotation (sections 12-4/12-5/12-6) and in-composite boundary-checkpoint consistency; environment management lives in data-environment.test.ts
- L68: Rotation is a composite (§12-4): bundling a subset is a 422 recipient-missing and no chain entry is appended (atomicity)
- L110: The composite appends two entries: rotate (H+1) + boundary checkpoint (H+2) (§12-4)
- L117: A push under the old epoch is a 409 returning the current epoch — the client re-encrypts and retries
- L156: A pre-rotation variable keeps its epoch (§7); the push follows the §4.1 rotation-execution shape (declared head, prev chain, monotonic epoch)
- L250: A rotate to a never-created environment is a missing data row = 404; on the server the data-row check comes first
- L282: From epoch 1 the only valid rotate is to 2 (CRYPTO_SPEC §6.3 — verifyChain is authoritative)
- L294: In-composite consistency check (§12-4): an entry for one environment × a URL for another is not accepted
- L317: A bundled wrap's epoch must equal the entry's new_epoch (§12-4) — even a wrap for an already-registered epoch is rejected
- L378: Fixture design: a dummy prev is fine because the bundled-contents match check runs before chain acceptance verification
- L440: A non-empty audit_head_hash is accepted under §16-2 (admin + §6.4 checks); a fabricated notarization absent from the stored column is dropped
- L458: Strict actor equality across both chain entries — a MEMBER-signed checkpoint in an OWNER composite violates it
- L479: Changing only manifest_sig_hash passes shape and chain checks but is dropped by §4.3 (2)'s exact-match binding
- L522: Mismatch shape of a push concurrent with head finalization (§12-4): the client re-pulls and retries; the digest names a variable absent from the stored enumeration

### `apps/server/test/data-environment.test.ts`

- L1: Pins environment management (section 12-4 composite) and creation-composite DEK-wrap verification (section 12-6); epochs/rotation live in the rotation file
- L144: A duplicate environment ID is rejected because ID uniqueness is a consensus rule (CRYPTO_SPEC section 6.2)
- L158: Deletion is a chain entry at the head; the chain, not the row, is the authority for whether an environment is deleted
- L195: A deleted id stays in the chain-derived environment set, so re-creation is rejected by whole-history uniqueness (§6.2, §12-4)
- L225: Stale prev / stale parent combinations are malformed before the CAS is judged — never a 409 (judgment order)
- L244: An entry without its data deletion would leave data the chain says no longer exists (§6, §12-4)
- L264: The generic path must not bypass the composite endpoint's atomicity (§6, §12-4)
- L311: A parent-head CAS failure requires re-signing the entry; a stale parent returns 409 + current head and a corrected retry proceeds (§12-4)
- L421: The chain entry's actor must strictly equal the calling principal (§12-4, same discipline as §11-1)
- L483: Existence hiding precedes signature verification (§12-3), so the non-member deletion case is sent as an unsigned dummy
- L513: An empty recipient set would create an environment no one can hold a DEK for — closed by the explicit count = member count check
- L522: Composite atomicity (§12-4): a failed wrap check appends no chain entry — no 'commitment exists but wraps do not' state
- L574: The current epoch at environment creation is always 1 (§12-4); epoch 2 is out of range

### `apps/server/test/data-manifest.test.ts`

- L1: Pins manifest composite acceptance: meta-op bundling, manifestVersion CAS (the 409 carries only the latest number), server-side digest recomputation, latest-copy-only retention
- L141: The digest is over the tombstone-including set (§12-7 — the same level in both modes)
- L213: A rename manifest copying the old envMeta (metaVersion 1) does not match the post-rename recomputation (metaVersion 2)
- L290: Attesting beyond the latest returns 409 with currentManifestVersion; the winner's hash is not carried (§12-5 discipline)
- L338: MEMBER carrying an OWNER-signed manifest fails — the verification key is the calling principal's
- L393: A rotate manifest whose epoch disagrees with new_epoch is a 422 at the in-composite consistency check (§12-4)
- L494: Outside creation an environment always has a stored manifest (§12-4 atomic write); a manifest-less live env is an invariant violation refused as a defect (500)
- L505: Each rejected DO RPC logs an 'uncaught exception' line although caught — expected; the direct instance call pins which defect fires
- L530: The CAS's latest-0 state exists only inside the creation composite — a meta op is never accepted as v1
- L577: A single DEK serves both the wrap and the commitment — the member-directed wrap must open to the DEK the chain's commitment names
- L639: A stale v1 against an initialized environment falls to the CAS 409, joining the legitimate client's re-fetch / re-sign loop

### `apps/server/test/data-meta-check-order.test.ts`

- L1: Pins the meta check order: state-dependent checks run after the metaVersion CAS, so stale-view statements get a 409 (re-verify and re-sign) and a 422 always means malformed or forged

### `apps/server/test/data-policy.test.ts`

- L1: Pins data-plane suite persistence, quantity policy, judgment order and error-contract derivation (sections 12-2/12-3/12-8)
- L136: Real generation is unrealistic, so rows are seeded directly via SQL to verify the judgment plumbing
- L215: The count cap is judged before recipient and signature verification, so a structurally-correct fake suffices (judgment order)
- L237: Pure-function judgment — registering a million rows is unrealistic (same shape as projectBytesExceeded)
- L253: Path 1: the cap also binds a composite rotation's bundled set; on overflow the chain entry itself is rejected (atomicity)
- L341: Even a non-member gets a 422 when the AAD disagrees with the request — it carries no existence information and stops before signature verification (§12-3)
- L353: If the AAD is self-consistent, a non-member gets a 404 (§11-2)
- L364: The CAS parent-head format is pinned as Sha256Hex — a malformed one falls at the Schema 400 and never reaches the 409
- L407: The §12-1 format is enforced on the environment_id inside a composite entry too — a laxer format would create environments unreachable from URL-param endpoints
- L426: The statement side is a 400 under the same EnvironmentIdSchema, kept aligned with the entry to pin the Schema boundary
- L474: Tag set is read from the Schema.TaggedError identifier annotation via a path independent of runtime judgment; fail explicitly if an effect update changes its shape
- L499: DO rejections are screened by a set derived from the endpoint's contract declarations — no hand-written allowed list; the correspondence itself is pinned
- L508: dek-wrap-exists is declared even though currently unreachable: if chain rules loosen it must surface as a typed 409, not fall to a defect (500)
- L530: The 409 carries the occupying wrap's stored recipient enc public key (§12-6 — material for the re-add backfill's repair judgment)
- L542: variables.pull declares only ProjectNotFound / Forbidden / EnvironmentNotFound — a leaked version-conflict rejection dies as an implementation bug
- L568: `satisfies` type-forces coverage of all DataRejection kinds — adding a kind fails compilation unless added here
- L664: Golden table pinning data-http.ts's rejectionErrors mapping; `satisfies` type-forces coverage of all kinds
- L714: The worker ↔ DO correspondence is what this endpoint × kind table pins
- L725: audit.self is D1-only (no DO), but is pinned under the same mapping/declaration discipline
- L778: Drift detector against effect updates (changes in Schema.is meaning / endpoint.error)
- L784: Defense against a broken enumeration passing unconditionally — update this count when endpoints are added

### `apps/server/test/data-schema-locked.test.ts`

- L1: Suite split: schema-locked one-time creation check (section 12-11), description acceptance (section 12-8) and unsupported layouts including retired layout 2 live here
- L226: The honest answer to a v4 client is always 'server update required'; schema-required must not be returned first (ruling CR)
- L262: A v4 successor settles as unsupported-layout before the CAS 409, even with a stale metaVersion (judgment order)
- L303: A v4 activation is unsupported-layout, not a guard/CAS outcome — the activate path takes the same hoisting as rename / delete
- L337: The support-range check settles before the signature, the CAS, and the monotonicity check (judgment order)

### `apps/server/test/data-schema-transitions.test.ts`

- L1: Pins layout v3 transitions and layout monotonicity, delete statements' just-before match, schema re-issuance and reversibility, and max age (sections 12-5/12-11)
- L183: declared → deleted is an allowed transition (CRYPTO_SPEC §4.2)
- L233: Deletion requires byte-exact preservation; the §12-8 description policy does not apply — the 'no blocking deletions via the cap' principle
- L325: A name-unchanged re-issuance is audited as var.schema_reissued, not var.renamed (§3.3); the payload holds only the name snapshot
- L397: The re-issuance branch is a byte comparison of names only — independent of the previous layout
- L528: The signing API refuses this shape, so the field was dropped after signing — the server's shape check settles before the signature
- L539: The manifest is bundled from the well-formed statement; the shape check settles before the manifest check

### `apps/server/test/data-schema.test.ts`

- L1: Pins the layout v3 acceptance surface: section 12-5 declared/activation items, section 12-8 description check, section 12-11 schemaPolicy, section 12-7 declared distribution; suite split noted
- L91: Config-change audit rows carry no key fingerprint because this config operation carries no signature (AUDIT_SPEC section 3.3)
- L139: A rejected DO RPC makes workerd log an 'uncaught exception' line even though the worker catches it; that log line is expected, not a failure
- L143: A direct call on the DO instance pins which defect fires, since any defect would surface as the same HTTP 500
- L209: Stored version stays 0 on an active declared row (§12-5 — declared is the only legitimate version-0 state; it counts toward the cap)
- L213: The interval starts at acceptance of metaVersion 1 (§3.3); with no value signature, the FP is the statement author's key FP
- L241: A declared variable does not appear in values — 'declared is the only legitimate valueless state' (§6.3, supply side)
- L263: Distributing a declared variable records no var.read — no value was distributed (AUDIT_SPEC §3.3)
- L350: An explicit target guard, independent of the value CAS: latest+1 passes both CASes, so only the guard answers 422 for an active target
- L382: The status guard stops a value push from riding the activation composite — the value CAS alone cannot reject latest+1

### `apps/server/test/data-variable.test.ts`

- L1: Pins variable push-pull-client decrypt and the metadata-only mode (sections 12-5/12-7) via SELF and DO SQLite
- L102: pull carries the statement + author info, not a bare name (§12-2, §12-7)
- L128: Pushing a new version makes pull return only the latest; prev chains to v1's signed_bytes hash (§4.1)
- L196: The worker checks coordinates before the token scope and the DO, so unsigned Schema-passing bodies reach the checks (judgment order)
- L253: The 409 returns only currentVersion — the winner's hash is not carried (no chain-signing onto an unverified value, §12-5)
- L453: Environment deletion requires admin scope; the scope check precedes signature verification (§12-3), so an unsigned dummy suffices
- L557: Seeding rationale: 1,000 real pushes are unrealistic; the quantity policy sits after the value signature (ruling D), so the shape must pass verification
- L607: Pure-function judgment — do not actually generate 1 GiB
- L695: The distributed statement passes §6.3 client-side verification — the bundling obligation matches the valued pull (§12-7)
- L729: Obtainable with reader role + read scope — the same row as pull (§12-3)
- L737: Non-members get a 404 (existence hiding — §11-2)
- L770: A valued bulk pull is §5's explicit rejection surface (W2b — eliminates the surface SECURITY_REVIEW L-1 occurs on); capability judgment precedes the CSRF check
- L782: Attaching a CSRF header changes nothing — same-origin XSS can attach headers (design doc §6); closing this surface is W2b's purpose
- L791: A rejected pull records no var.read row — do not record as read what was not read (AUDIT_SPEC §3.3)
- L799: Bearer (token principal) is unaffected — the CLI and maruhi ui are token principals (§5)
- L808: Metadata-only mode is in §5's allowed enumeration and records no var.read, so a session needs no CSRF header either

### `apps/server/test/data-verify-meta.test.ts`

- L1: Pins meta statement acceptance verification (section 12-5 meta rules = CRYPTO_SPEC section 4.2) via SELF and DO SQLite
- L58: Helper pins rejection side-effect-freeness: statement rows, the variable-name cache and audits do not change
- L67: Both rename-path audit events are counted so the accepted-meta-op invariant does not silently break if a name-unchanged acceptance case is added later
- L111: The deleted statement (name keeps the just-prior active name) keeps being stored and distributed (§12-5)
- L165: Attesting metaVersion 3 against latest 1 returns 409 currentMetaVersion 1; the winner's hash is not carried (§12-5 discipline)
- L194: An NFD name is only inspected, never normalized — normalization would break byte-exact signatures
- L268: A carried-in rename signed by OWNER fails — the verification key is the calling principal's acceptance-time chain key
- L295: Meta does not check the environment's existence (the §12-4 asymmetry), so this rejection reduces to membership at the declared head only
- L395: Author info is distributed as of acceptance time, not re-derived from the current member set
- L398: Client-side verification (§6.3): the declared head lies within the membership interval, so it verifies under the key of that time
- L479: The CAS drops it first — the 409 prompts a retry even though the statement's declared head is stale too
- L482: The retry re-signs both the entry (changed prev) and the statement (changed declared head) (§12-4)
- L507: Seeding rationale: 1,000 renames are unrealistic; the seeded state preserves the invariant that a latest_meta_version row always exists (findVariable's JOIN premise)
- L553: The cap must not block deletions — a resource rename-spammed to the cap would become permanently undeletable; a tombstone is the terminus and adds at most one row
- L595: A deleted variable's name keeps the just-prior active name (§4.2)
- L603: Even at the cap the bundled manifest is required as usual — the manifest itself is outside the row-count cap (§12-8, latest copy only)
- L614: The tombstone statement keeps being stored and distributed (§12-5)

### `apps/server/test/data-verify-value.test.ts`

- L1: Pins value-signature acceptance verification (section 12-5 = CRYPTO_SPEC sections 4.1/6.4) via SELF and DO SQLite
- L63: Helper pins rejection side-effect-freeness: variables, versions, latest and audits do not change
- L83: A value signed by OWNER but carried in by MEMBER fails: the verification key is the calling principal's acceptance-time chain key
- L158: Existence of the exact (seq, hash) pair is the acceptance condition for the declared head
- L239: Declaring a pre-creation head is rejected — forbids backfilling an epoch-undefined head with a default (§12-5 item 4, second half)
- L272: A prev mismatch with a valid signature is pinned as its own rejection — not crushed into an Ed25519 failure
- L365: The server-recomputed signed_bytes hash is not distributed (§12-2)
- L398: Writer info is distributed as of acceptance time, not re-derived — verifiability of a removed writer's past values
- L420: Verification passes on the full post-removal chain because the declared head lies within the membership interval (§6.3-1/3)
- L446: A removed writer's new push is rejected at acceptance; the 404 existence hiding takes precedence (§11-2)
- L460: Server-API counterpart of the crypto vector key-from-other-tenure: key bound at the declared head must equal the key at acceptance (§12-5 item 3)
- L473: Re-adding under a fresh key is forced by §6.2 uniqueness; the acceptance-time bound key becomes the new key, so old-tenure heads fail
- L502: Attack construction: signing with the new key while declaring an old-tenure head fails — head-bound key (old) ≠ acceptance key (new)

### `apps/server/test/device-ops.test.ts`

- L1: Pins device-key ops: acceptance side effects, per-(person, device) wrap sets, two-stage authorization, revoke_device effects, and the DeviceLimit of 16 per member per project
- L353: The actor is the device that signed the append (the primary key); the target is self — only one's own devices can be added
- L362: The mirror row carries no provider info such as GitHub — internal user_id and FP only
- L573: Rotation-needed detection: one aggregate row per environment right after the mirror (§3.3 Sc-5), trigger = revoke_device
- L607: Existing wraps are not swept — the sweep rule is unchanged; they are replaced on the next rotation
- L626: A signature by the revoked device is invalid — the device cannot be resolved from the signing key
- L687: A mix of own-device and other-member recipients is judged on the whole set — likewise 403
- L695: §6.3 authorization at the declared head (K2: deviceStateAt) runs first inside signature verification, so insufficient device cap settles as 422 before the server's 403 stage
- L826: A device-less backfill (the pre-K2 append path) still returns 204

### `apps/server/test/devices-registry.test.ts`

- L1: Pins only the registry's HTTP contract: the registry is advisory and feeds neither verification nor authorization; FP recomputation, limits, TTL and uniform 404s are pinned
- L174: Another user's row is looked up as the caller's own row, so deleting it is a 404 (existence hiding)
- L312: Rows are keyed on the (user, fp) axis, so another user can register the same public key
- L333: Cancelling does not restore the window — it is a fixed window

### `apps/server/test/do-schema.test.ts`

- L1: Pins DO schema migrations on real SqlStorage: base step recorded as version 9, fail-closed refusal below base, rollback/rerun, no-op re-apply; the constructor no longer materializes fresh DOs
- L79: The tables declaration PROJECT_DO_TABLES is derived from must not drift from the real schema
- L101: The refusal happens before any DDL: the version is not rewritten and no table was created
- L142: The base is not re-run — its CREATE TABLE has no IF NOT EXISTS and would throw; the later step records version 10
- L186: The rerun completes from the step's head; mig_test_c's CREATE without IF NOT EXISTS would throw if a partial application remained
- L229: The CHECK constraint covers only id; version's type is not enforced (SQLite is dynamically typed)
- L232: Pin: a corrupt version does not fall into being treated as 0 and re-running the base, whose CREATEs would collide with the applied schema
- L289: data-store's real queries are captured and fed to EXPLAIN — avoiding verifier drift from duplicating statements (same technique as audit-index.test.ts)

### `apps/server/test/env.d.ts`

- L23: TEST_RUN_WORKER_FIRST is injected from wrangler.jsonc's assets.run_worker_first for the coverage sweep in serving-topology.test.ts

### `apps/server/test/export.test.ts`

- L1: Pins project export/import (PF3): evacuation page format, the restore path accepting pages unchanged, owner-only access, stale cursor 409, per-project window 429, identity continuity on import
- L75: Tests empty restore/ first because the restore worker scans that prefix and R2 sits outside storage isolation
- L193: A pre-check-refused import never touches the DO, and a reset DO holds nothing until genesis / restore materializes it (Sc-7 / A-4)
- L254: The trailer's counts are the live tables' counts — not only self-consistent
- L259: The export's own audit row is appended before the marks are taken, so the first page's audit seq is that row's seq
- L266: chain_entries is the last table — the restore's 'chain comes last' rule
- L331: Rows appended past the bound between pages are not exported and the trailer says the bound, not the live maximum (ruling C revision, round 3)
- L369: A page passes the byte bound by at most its last line (the row that crossed it)
- L385: An admin is not an owner either (ruling E)
- L394: The export row is class 2: an owner sees it in the audit read, a member does not
- L437: A read between pages does not restart the export: the log is exported up to the mark; rows past it belong to the next export (ruling C revision)
- L444: The cursor is the exporting owner's: another owner continuing it is refused — their export would have no audit row or window of its own (ruling D revision)
- L470: A cursor from another schema version (an export spanning a schema-migrating deploy) restarts at the source (ruling C revision, round 5)
- L489: A cursor past the table order is refused too — never a 500
- L513: A continuation is not window-counted — the cursor path skips the window
- L558: A payload column that is not JSON, is not the bound object, or names another head never binds — the continuation restarts like a foreign cursor
- L709: Identity continuity: a login with the owner's GitHub id resolves to the chain's user id, so the project is theirs on the destination
- L716: Re-running the job: the DO refuses (not-empty); D1 keeps the exporter's project row and provisions only what is missing (ruling I revision)
- L776: The results carry no project id — the same discipline as restores
- L804: No other table carries a trigger — the mutation triggers go on the declared tables only (ruling C revision, round 5)
- L819: A write-class audit row moves the mutation counter; a read-path row does not (ruling C revision, round 6)
- L833: A fresh DO's audit write trigger is the text the re-assert expects: its first re-open performs no DDL (round 9)
- L846: The trigger's deny list is re-asserted at every open (ruling C revision, round 7) — a deployed trigger naming fewer read-path rows is re-created
- L861: Any other drift of the trigger's text is re-created too — the whole stored text is compared (ruling C revision, round 8)
- L872: An up-to-date trigger is left alone at open: no DDL — the schema row stays the same row
- L918: The co-owner's re-export is a re-run of the row under the first owner's org, not someone else's project (ruling I revision)
- L945: A snapshot with an altered chain is refused before the restore — the DO's load verifier runs first
- L999: Retry shape: the pre-check refused before touching the DO, so resubmission restores it; a job whose D1 step failed after restore retries the same way on the not-empty DO
- L1055: The companion is confirmed against the chain before anything is written

### `apps/server/test/github.test.ts`

- L1: Pins GitHub client failure shapes unreachable end-to-end: per-call timeout (it used to hang forever), schema-mismatch bodies, /user/emails non-ok degrading to no-email; fetch is swapped via the Fetch context, not globalThis
- L119: Unset and empty both reach makeGitHubApi as undefined (worker-env.ts); the field is omitted
- L138: A never-responding endpoint fails through the typed error once REQUEST_TIMEOUT (5 s — the same bound as the JWKS fetch) elapses; the TestClock makes the wait instant
- L194: Regression shape: JSON null is not an absent key — the schema rejects it where the cast used to read it as 'no login'
- L218: Regression shape: a malformed body used to be cast and read as 'no email'; it now takes the same failure path as an unreachable GitHub
- L231: Regression shape: the cast used to skip a null-email entry; the schema now fails the whole call
- L246: A non-ok response is a 'not stored' answer (§3-3), not a dance failure — only transport errors, timeouts, and malformed bodies fold into the error

### `apps/server/test/ids.test.ts`

- L21: Format-invariance: the expected strings were produced by the pre-migration implementations fed the same byte streams, proving the Effect 4.1 service versions changed no byte lengths or encodings
- L125: constantTimeEqual must never receive the cli.-prefixed state (the CLI handler strips the prefix and compares the nonce); pinned so a mistaken pass cannot silently always mismatch
- L146: Identical malformed strings are not equal — there is no fallback to a plain string comparison

### `apps/server/test/invites-accept.test.ts`

- L1: Pins invite acceptance: judgment order 404-410-422 link-422 accept-CAS, real joint-signature verification, same-batch invite.* audit writes, and the CAS-loss guard
- L83: Invite audit payload invariant (section 3.2): only the invite id and the acceptance key FP; no link public key, signatures or backing-source login are written
- L114: The concurrent-loser case is reproduced via a direct repository call because over HTTP the pre-read 410 fires first; this verifies the same-batch changes() guard itself
- L327: Session-based acceptance is rejected uniformly: acceptance is CLI-only (section 15-3) so a session XSS plus a leaked invite link cannot bind an attacker key to the victim's user_id
- L338: The row stays pending — the rejection settles before the acceptance CAS
- L400: The inviter client's re-verification (CRYPTO_SPEC §6.5): issuance document under one's own key, the acceptance signature, the link signature
- L469: Re-revoking is 410 revoked (no silent success) and the audit does not grow
- L497: Listing (a read) is allowed for a session with chain role admin or above (§15-2)
- L504: Revocation is a credential-reducing mutation (ADR-0018 rev. 2 boundary principle); a session actor's audit attribution is auth_method, no token id (AUDIT_SPEC §2)
- L540: Only the accepted invite whose keys match is reconciled to completed (§15-2)
- L544: The update to completed writes no separate event — chain.member_added is the evidence (§15-4)
- L580: Only the invite whose granted role and scope equal the add_member's is reconciled to completed (§15-2)
- L592: Scope is a set (§6.2): neither wire schema enforces sorted order, so completion must not depend on the stored list's order; the environments are created first (unknown-environment rule)
- L628: Pins the precondition: the stored scope text really is in reverse order
- L648: Set-different invites stay accepted — equality, not containment: the subset does not complete either
- L658: The D1 write is made to fail deterministically by stashing the table; without the guard the committed append would 500
- L674: The reconciliation is dropped and the invite stays accepted — a recoverable state; the 'fail on the drop side' behavior handlers-membership.ts declares

### `apps/server/test/invites.test.ts`

- L1: Pins the invite API: per-reason authorization, existence hiding, the acceptance decision order, real CRYPTO_SPEC section 6.5 signatures, and same-batch invite.* audit with the CAS-loss guard
- L62: The issuance statement (public values) is stored as-is; the server does not verify it at issuance
- L184: Fixture design pins that the pending limit is judged first when both the cap and the window conditions hold

### `apps/server/test/json-stream.test.ts`

- L1: Pins the chunked JSON body: its bytes are exactly JSON.stringify's and no chunk holds much more than one piece of the value (the section 14-2 lease)

### `apps/server/test/key-wraps.test.ts`

- L1: Pins the wrap ledger: wraps, shares and approvals are opaque ciphertext to the server so format-valid hex fixtures suffice; authorization, acceptance policy, fixed windows, existence hiding and audit 1:1 are pinned
- L175: Public parameters (§13-7, 2026-09-13 revision): the restoring client reads them before the ceremony
- L207: A row the v1 write path cannot produce is DB corruption / an implementation bug: the decode failure is a defect (500), not silently redistributed in another shape
- L270: The refused insert writes nothing — what was not accepted is not recorded
- L399: Re-registering the same id is 422 duplicate-id, judged before the limit
- L403: Audit rows are conditioned on changes() = 1 checks at the batch's end — only the one accepted registration remains
- L486: The ward themself cannot approve their own request: 422 even with their own group id

### `apps/server/test/lease-authz.test.ts`

- L1: Pins lease authorization existence hiding: no grant, policy mismatch, out-of-scope, missing environment and uninitialized project are all the same uniform 404
- L46: Out-of-scope precondition: registering a server wrap for an out-of-scope environment is itself a 422 (section 12-6), so 'no wrap but a grant exists' is the right setup
- L126: A probe of a never-initialized project leaves no storage at all, so the unauthenticated path cannot bloat operator storage
- L152: Denial bodies as well as status codes are pinned identical, with the branches forced separately via a real policy so each path is genuinely taken
- L203: Denial bodies carry only the echo of the caller's own projectId, so every case but the unknown-project one must be identical
- L319: External identifiers (sub / repo name) are not written (§14-4, AUDIT_SPEC §1-2)

### `apps/server/test/lease-binding.test.ts`

- L1: Suite header: pins the workload-lease first-come binding (§14-1) and the source-IP rate limit; suite split documented at the top of lease.test.ts
- L52: A lease_denied audit row remains (§3.5) whose claims_digest equals the legitimate issuance's — the owner can cross-reference which workload's token was stolen
- L64: The rejection does not consume the rate window (§14-3)
- L73: Idempotent retry (§14-1) so retries keep working even if a pre-issued issuer that cannot re-issue at runtime (GitLab etc.) is added later
- L97: The binding judgment precedes environment existence (§14-3) — a 401-vs-404 difference must not reveal whether the environment exists
- L123: The binding is per-token, shared across project DOs: a job leasing N environments with one token must present the same ephemeral key on every request (§14-1 client obligation)
- L149: Rotating the key on a different environment is a 401 — the per-token binding also blocks leasing another environment with a stolen token
- L165: If the binding's retention were shorter than the ±60 s skew acceptance window, the difference alone would be a replay window — policy.ts derives the retention margin from skew
- L178: The binding row's lifetime = exp + retention margin, with margin ≥ skew guaranteed by the derivation
- L213: Regression guard: the binding key hashes the signing input, not the raw token — a base64url tail malleation would otherwise change the hash, miss the binding, and let the replay through
- L228: Premise check: the malleated token differs as a raw string, so a naive hash would differ
- L236: The mutation passes signature verification but hits the binding (signing input unchanged) → token-replayed; a 200 would restore one-character replay evasion
- L245: The rate limit sits before projectStub, so a barrage against a nonexistent project creates no DO; the shape passes the Schema so the requests are counted at OIDC verification
- L260: The judgment is by IP alone, so exposing the 429 does not break existence hiding (§11-2); the parallel burst (2 windows + 2) avoids window-boundary flaking
- L283: The 429 carries an RFC 9110 Retry-After header — backoff material for clients other than the maruhi CLI (index.ts's withRetryAfterHeader)
- L291: The test timeout is extended because a 124-request burst can exceed the default 15 s under full-suite load (measured); hang detection stays bounded

### `apps/server/test/lease-chain-grants.test.ts`

- L1: The chain-read grants of issued leases (do/lease-chain-grants.ts — AUTH_SPEC §14-2): a token opens exactly its own head, once, until the...

### `apps/server/test/lease-policy.test.ts`

- L1: Integration tests for workload-lease 503s and auditing (AUTH_SPEC §14-3 / AUDIT_SPEC §3.5), deployments with an unset server key, and...
- L62: Grant exists but never backfilled = the CRYPTO_SPEC §7 re-wrap is unfinished. Do not make this an opaque failure (the A1 ruling: the...
- L77: A rotation composite on an environment with a valid grant requires the complete wrap set including the server key (§12-4), so a gap...
- L131: One row per environment (no per-variable granularity option — §3.5)
- L136: grant_chain_seq is the chain-derived grant_seq (not re-implemented on the server side). **Pin by value**: watching only the type would...
- L161: var.read is the evidence of a human actor's read; disclosure to a workload is carried by the server.* events (AUDIT_SPEC §3.3 / §14-4)
- L173: The DO derives its keypair from its own env (chain-do.ts), so handing the worker a different env changes nothing on the DO side. What is...
- L209: makeServerKey(undefined) = an unset-key deployment. DataStore / AuditStore are unreachable, so this path also pins that they are never...
- L216: The storage guard's observation point (§12-8) is just before issuance = unreachable on this path
- L251: Fill the window directly (300 real requests do not justify the runtime). The counter is the lease_windows row in DO SQLite; go through...
- L266: Since the window was seeded just now with window_start = now, the remainder is fixed to near the window length (1 hour). Checking only >...
- L275: If the 503 path consumed the window, a backfill-missed project's CI would eat slots on every retry, and past the 300th the "fixable...
- L314: A policy mismatch (404) does not consume the issuance window — if it did, a third party could starve a legitimate workload's leases

### `apps/server/test/lease.test.ts`

- L1: Integration tests for the workload-lease API (AUTH_SPEC §14 = CRYPTO_SPEC §9.1) — issuance (§14-2) and the OIDC verification stage...
- L73: Written in chunks (handlers/json-stream.ts — no single buffer of the whole body), and still a valid §14-2 response
- L80: The response bundles the chain (non-members get a 404 from the chain API — §11-2). The length is exactly determined by the fixture, so...
- L88: Bundles the latest environment manifest + issuer info (§14-2 — material for the workload's verification obligation §9.1 (5). A required...
- L93: The lease wrap carries no registered signature or signer info (server-generated and response-scoped — no signer can exist on the chain —...
- L106: Invariant that the leased DEK is the original epoch DEK.
- L113: A live environment without a stored manifest can only come from a corrupted DO or a crafted snapshot — an invariant violation, refused...
- L122: The rejected DO RPC makes workerd log an "uncaught exception" line even though the worker catches it — expected
- L133: Any defect would answer the same 500; the direct call on the instance pins which one fires (the facts the worker hands over for the...
- L154: A stored value no response schema accepts (a corrupted row): the body is encoded whole before the stream starts, so the lease is a 500...
- L183: The supply source is the stored row from checkpoint acceptance itself (§16-2 — the environment creation's boundary checkpoint is the...
- L279: The manifest digest covers the declared statement, so a workload refuses a lease that leaves it out (CRYPTO_SPEC §6.3)
- L420: `aud` does exist (there are merely several). Kept as a separate vocabulary so an operator guided by the reason code does not go looking...
- L446: `none` satisfies Schema's compact-JWS shape (3 segments) and then falls at the alg allowlist — an implementation that trusts the...

### `apps/server/test/log-hygiene.test.ts`

- L1: Regression check for log hygiene (hosted-ops.md §1 Workers Logs row, DC-2). There are two paths by which a request URL (= the...
- L44: A project id that does not exist but is well-formed (64 hex). Even on the path rejected before authorization, Effect's default logger...

### `apps/server/test/membership-authz.test.ts`

- L1: Integration tests for the membership log's chain-API authorization (AUTH_SPEC §11) + GET /chain + CAS (the CRYPTO_SPEC §6.4 optimistic...
- L42: The user-table names of a project DO (empty = never materialized — Sc-7 / A-4).
- L74: Signatures are rejected at membership before verification (no current-head info is returned either)
- L100: user-member-0002 is removed at seq 5. Later writes (rotate goes through the composite) are rejected not by chain verification (422) but...
- L170: seq 3 (create_environment) and seq 4 (rotate_epoch) are write requirements via the composite endpoint and pass under a write-scope...
- L192: Since the creation composite's boundary checkpoint (H+2) advances the head, the rotate is re-signed at the real head (op / payload /...
- L241: Chain appends and init are §5's explicit rejection surface: uniformly 403 session-not-allowed regardless of the CSRF header (the...
- L258: The same body is accepted under a token principal (proving the rejection was due to the session principal)
- L271: The DO's tables are created only at genesis acceptance: an authenticated GET to an arbitrary project ID leaves no storage (Sc-7 / A-4).
- L307: CAS is checked with a test-time-signed remove_member (seq 3, an op subject to generic append) (vector seq 3 is create_environment and...
- L339: The format of the CAS comparison target is pinned as Sha256Hex (64 lowercase hex chars): a malformed one never reaches the 409 (with...
- L354: A write to a never-initialized project folds to 404 without materializing the DO (Sc-7 / A-4).
- L360: These call the DO's init RPC directly: the tables must be created after every refusal branch (verifyAcceptableEntry, the...

### `apps/server/test/membership-negatives-append.test.ts`

- L1: Server-side verification (CRYPTO_SPEC §6.4 = verifyChain re-run) — rejection tests for the authorization negative vectors that go...
- L30: Generic-append tests for the checkpoint op: a fixed-length-hex format violation is rejected first at 400 by api-schema's hex Schema (the...
- L64: Among ES / PF1's (2026-09-14) structural negatives, the ones where api-schema's closed-set literals (scope_kind / ops / inner op),...
- L73: Among the structural negatives, shapes the test-time signing API (signChainEntry) does not accept (a negative expires_at_ms is outside...
- L91: Device keys (DK): closed-set literals (role_cap / ops) and fixed-length hex (public key, FP) are rejected by api-schema at 400 first....
- L109: Replay the prerequisite chain, then send the original with only seq / prev re-pointed at the real head (not re-signed).
- L119: A shape the signing API refuses (negative expires_at_ms) cannot be re-signed. Since structural checks precede signature verification...
- L141: Rejection at a consensus rule (verifyChain) — re-sign at the real head and send; pin the reason code and seq.
- L143: For a non-member actor, §11-2's existence hiding (404) acts before verifyChain
- L171: Splitting the authz negatives (pullfrog round 3): pin each branch's count exactly so the suite cannot quietly empty as the judgment...
- L220: A negative's branch (the judgment order is fixed): checkpoint → composite (create / rotate / delete) → the four-eyes (PF1) 4 ops and...
- L273: Reconstructing the vector negative "tampered-payload-role": rewrite entry 2's payload role while keeping the original signature →...

### `apps/server/test/membership-negatives-composite.test.ts`

- L1: Server-side verification (CRYPTO_SPEC §6.4 = verifyChain re-run) — rejection tests for the authorization negative vectors that go...
- L24: A create_environment / rotate_epoch negative goes through the composite endpoint, where the server's judgment order (§12-3 / §12-4) can...
- L63: Environment scope (2026-09-14 ES — CRYPTO_SPEC §6.2's environment-targeted ops): since K3 (2026-09-15) the acceptance surface returns...
- L84: create's scope judgment (403) precedes verifyChain (duplicate-environment 422): the negative's actor is a listed admin, so it falls at scope
- L88: Device keys (2026-09-19 DK — since K3 the acceptance surface judges by the device's effective permissions. Design record dk-design.md §8...
- L100: Environment deletion on the chain (2026-10-07 — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4). Signed over the current head, a rotate of a deleted...
- L111: The deletion composite's acceptance surface (§12-4's judgment order: role 403 → the URL / entry match → CAS 409 → scope 403 →...
- L131: The routable path of a deletion negative (an empty id is refused by the payload schema, not the router).

### `apps/server/test/membership-policy.test.ts`

- L1: Integration tests for the membership log admission policy (CRYPTO_SPEC §6.4 size limits). Shared fixtures and vector replay helpers live...
- L35: A giant entry that violates the §6.1 field limit (1024 B) but can still be canonicalized. The admission-policy check (1 MiB) runs before...
- L69: Even a stream body that does not declare Content-Length (chunked-equivalent) must hit the cap by actual measurement and become 413...
- L116: The size pre-check runs before the actor match (403) — resource protection comes first
- L125: Build a valid 2-entry chain, then raise only the cumulative byte count to the cap (§11-2 means membership determination = chain...
- L137: Directly rewriting a stored row (outside the append-only invariant) does not show up in the instance's incremental-load cache, so evict...
- L156: Generating 10,000 valid chain entries is impractical, so verify the decision function directly (the cumulative-bytes test exercises the...

### `apps/server/test/membership.test.ts`

- L1: Integration tests for server-side membership-log storage (CRYPTO_SPEC §6.4) + authorization (AUTH_SPEC §11) — genesis acceptance,...
- L126: The canonical chain's full 24 entries (2026-09-14 ES + PF1 — including the four-eyes 4 ops at seq 20-24. K5 removed the acceptance guard...
- L132: A boundary checkpoint (H+2) is inserted per composite (vector seq 3 / 4 / 8 / 10 / 11) (§12-4). The vector's seq 1-24 are all accepted...
- L210: The canonical chain's seq 20-24 = set_approval_policy / propose(change_role: devmember → reader listed{dev} — proposer owner-0001's...
- L227: One row per entry (a bijection) — only the completed approve has a second row (the applied row)
- L244: The inner payload is not copied (the chain is the source of truth)
- L272: devmember got a projection row when seq 13's add_member was accepted (§11-5 (2)); the demotion (an applied change_role) does not remove it
- L279: The derived chain proposal-completed (base 23): approve@24 (owner-0014 — 1 vote, incomplete) → approve@25 (owner-0015 — completes at...
- L312: §11-5 (3): an applied remove_member drops the projection row (the worker's D1 post-processing — K5-H)
- L339: Replaying seq 1-12 alternates "append (incremental reflection) → read (incremental load)" every step, and composite acceptance (the...
- L346: DO eviction = discarding the in-memory cache. The next read must fall back to a full load and return exactly what the warm cache returned

### `apps/server/test/mirror.test.ts`

- L1: Integration tests for mirrors (PF2 — AUTH_SPEC §11-7, docs/notes/pf2-design.md). The HttpApi and the DO via SELF on...
- L130: Restores an exported replica into the emptied DO (the mirror's bootstrap = the §11-6 import).
- L136: A mirror bootstrap restores into a fresh destination (§11-6). The DO is materialized at import time in production (opsRestore);...
- L140: The stream is created inside the DO's context (an I/O object of the test context cannot be read on behalf of the DO)
- L161: Materialize the fresh destination before restoring (Sc-7 / A-4 — the reset left no tables; opsRestore does this in production).
- L263: The source's first-come bindings travel with the export (merged into the mirror's own at commit, never replacing one — ruling D revision)
- L290: A mark naming another source re-points the mirror without a writable window (ruling C revision, round 4); the same source is still a...
- L304: Writes are refused after the membership check (a non-member keeps the uniform 404 — the mark is not an oracle), before any state change
- L372: A reader sees the mark, the source and the chain head — never the audit seq or the replication history (AUDIT_SPEC §7 C1)
- L392: The mirror's own binding stays ('ab' → 'cd', not the source's 'zz'); the source's other live one is merged; expired ones of either side...
- L440: A replica of the same length whose audit log is not the replicated one (the cumulative hash at the position differs) is refused — the...
- L459: … and one whose column differs BELOW the position: the served heads are the mirror's own derivation, so the uploaded column is a claim...
- L495: The prefix checks join the staged log on an index, never a scan of it (ruling J revision, round 8): the staging tables carry the live...
- L512: … and so is one that rewrites a row at or below the replicated position while carrying the column untouched: the prefix is compared row...
- L555: The switch-over order of §11-6: the source is marked (frozen) first, then exported. Its audit rows between the mark and the export's own...
- L583: A re-point resets the audit floor (ruling C revision, round 5): every row of the log is the mirror's own against the new source — and...
- L590: A carried row is the mirror's own row byte for byte: a replica that carries one of its row ids with other content cannot rewrite the...
- L654: A seq at 0 (the live primary key accepts it; the log would not be hashable)
- L666: A head column longer than the log (no audit rows, the full column): the first replica after a mark installs the column, so phantom heads...
- L742: A server_ts the canonical form refuses (the schema accepts it)
- L752: A first replica whose uploaded column's tail is no head hash (with the column reaching the log's end, nothing would have derived from it...
- L830: … and a bad row in such a replica is refused before anything live is touched (every row is derived over). A re-point makes the next...
- L879: Foreign row ids (the carried-row rule never matches), and one column of one row rewritten; the uploaded head column is dropped so every...
- L902: A row id set of its own per variant: a carried row id with other content is a rewrite, refused for its own reason
- L938: A fractional seq is refused at the trailer, not at the swap's rowid
- L1039: A chain whose hashes match but whose entries do not verify never replaces the live one (the replica's content, not only its hashes)
- L1105: An audit log behind the last replicated position (contiguous — a log that is not 1..N is malformed before any position is compared,...
- L1125: The same replica (no change) commits — and sets the audit position: the mark itself starts the position at 0 (ruling C revision, round...
- L1142: A string count in the trailer's rows: refused at decode, before the count check (a well-typed wrong count is row-count-mismatch, above)
- L1146: A string schemaVersion: refused at decode (a numeric mismatch is schema-mismatch, above)
- L1152: The restore's reader decodes the same wire union: the same forged trailer is malformed on the import too
- L1271: A manifest from the older export paired with the newer chain and audit segments. Against the live mirror state this is an equal version...
- L1384: Explains direct attestation-row insertion parallels production.
- L1399: Under the locked policy a creation must carry a varType (the one-time schema check at creation, §12-11): the v3 typed path
- L1472: Wholesale wrap deletion: staging zero wrap rows fires no epoch check, but every live wrap must be preserved — refused
- L1476: A same-primary-key wrap rewrite (ciphertext swap): preservation is row for row, not key for key — refused
- L1487: An attestation mark forged at an equal seq (accepted_at is part of the row's identity there; the commit reads MAX(accepted_at) back)

### `apps/server/test/oidc.test.ts`

- L1: Unit tests for OIDC verification and the JWKS cache (AUTH_SPEC §14-1). Where the lease integration tests (lease.test.ts) pin the...
- L59: A `fetch` stub serving discovery / JWKS. Swap `jwks` to simulate key rotation; `failJwks` for an issuer-side outage; `hang` for an...
- L82: A defect, not a typed failure: reading the body throws inside the load, the way an unrecoverable internal error would
- L115: A runtime whose Clock reference is a fresh `TestClock`, started well past the forced-refresh sentinel: a fresh cache records...
- L142: The verifier's crypto services (the signing-input hash's Digest, effect/jose's Signature) come from the same composed layer production wires
- L184: A byte-identical re-spelling of a segment: a different final character that decodes to the same bytes (the unused bits of the final...
- L265: Hold the winner's JWKS fetch at the gate until every caller has joined — a caller that arrives after settle would be served by the TTL...
- L307: An unknown kid within the cooldown is not re-fetched (a nonexistent kid must not hammer the issuer)
- L353: Even if an unknown kid (which an attacker can choose freely) triggers a forced refresh while the issuer is down, the old in-TTL document...
- L360: A failed forced refresh also starts the cooldown (the issuer is not hammered)
- L374: Even with no good value, nothing is re-fetched during the failure cooldown (cold + issuer outage must not become "1 request = 1 fetch")....
- L405: On TTL expiry + issuer outage, `isUsable` returns false at the TTL branch, so the forced-refresh cooldown is never reached. Without an...
- L438: A defect inside the single-flight load must still complete the Deferred and drop the in-flight entry (the old Promise always rejected...
- L454: An external fetch inducible via an unauthenticated path, so an unresponsive issuer must not hold the request open (FETCH_TIMEOUT_MS via...
- L460: No ordering assumption about which tick the detached fetch fiber registers its timeout sleep on: yield the runtime's scheduler and...
- L487: A transient outage must not be reported as "bad credentials (401)" — a CI job would treat it as a non-retryable failure...
- L551: crit declares "extensions that must not be accepted unless understood"; this implementation supports no extensions, so every crit value...
- L578: §14-1 (2): `none` is refused. lease.test.ts pins the header variant on the HTTP path (alg "none" with a signature still attached); this...
- L593: The classic confusion: the token claims HS256 and is MACed with the verification key's public material as the HMAC secret, so an...
- L627: RFC 7515 §4.1.3's `jwk` header parameter carries a key chosen by the token's author. Accepting it makes verification self-asserted (the...
- L655: The counterpart pin: the parameter is inert, not refused — a token signed by the issuer's key verifies even when it carries a (decoy)...
- L676: Deliberate (§14-1's first-come binding): a re-spelling of the signature segment's final character that decodes to the same bytes must...
- L711: Only the signature segment gets the canonical re-encode: the header segment's spelling is part of the signed content, so a re-spelling...
- L733: Control: the token as signed verifies — the refusal below is the re-spelling, not the `cty` member
- L745: Same pin as the header's, for the payload segment: the signed content is the received spelling, never a decode → re-encode product
- L751: A segment is re-spellable only when its byte length leaves unused bits in the final base64url group (length % 3 !== 0); padding the...
- L779: Compact JWS segments are unpadded base64url (RFC 7515 Appendix C). The upstream decoder is lenient about `=` padding and the length...
- L812: The worked examples of RFC 7515 Appendix A.2 (RS256) and A.3 (ES256), transcribed from the RFC (the signature values were cross-checked...
- L841: One payload character changed — the tamper control proving the positive verifies are not vacuous.
- L866: The verifier's one adaptation (verifier.ts): the signature segment is re-encoded canonically from its decoded bytes before effect/jose...

### `apps/server/test/ops-alerts.test.ts`

- L1: Operations foundation — tripwire counting, evaluation, and notification (docs/notes/hosted-ops.md §2-A / §2-B / §3). - Sources of...
- L203: The body carries no identifiers (user IDs, 64-hex project IDs, token shapes)
- L242: An unreachable URL (the outbound fake answers 500) returns false (resent next time) with the same static line — never swallowed silently
- L251: The URL is a secret: it appears in no warn line
- L260: The webhook path runs inside the cron Effect (scheduled()) — not in a workerd request handler — so the clock is drivable by TestClock....
- L320: The transport kind name only — the same second argument main's raw-fetch catch logged (never the URL or the body)
- L335: Stored rows the cast accepted (or crashed on) but the Schema decode rejects — unparseable text, JSON null (the cast's TypeError defect),...

### `apps/server/test/ops-backup.test.ts`

- L1: Operations foundation — DO -> R2 evacuation and restore (docs/notes/hosted-ops.md §2-D / §2-E / §4-2). Against a real project DO...
- L95: key = do/<image of idFromName>/<timestamp>.ndjson.gz — carries no capability (project id)
- L265: Neither NULL nor 32 lowercase hex: the shape check refuses it before any head is derived over the restored table (its stored-row decode...
- L311: A second environments segment holding one extra row on a disjoint primary key, with the trailer counting only that segment (1): the...
- L441: Every present row is genuine and the trailer counts the omission, but the staged chain holds the environment live and its creation...
- L504: The added row copies the genuine row (its declared head still resolves to the staged chain) under an environment the chain has no...
- L588: The format admits a snapshot with no chain table at all (an empty project's evacuation shape): with no staged chain there is no...
- L670: An import restores the body its pre-check verified, by etag (ruling H revision, round 4): another etag is `object-changed` before any...
- L702: Read the live column lists before the reset: a reset now drops the tables (a DO is never-initialized until genesis acceptance — Sc-7 /...
- L788: The head-attestation upsert writes neither a chain row nor an audit row (AUTH_SPEC §16-1), but counts as a content change that lifts the...
- L849: Evacuate twice with the same nowMs (= same header, same key): the first run measures the compressed total, and the second uses exactly...
- L874: Seed hard-to-compress rows (random-hex ciphertexts) directly to push the compressed size past 5 MiB. The filler rows declare the chain...
- L901: Materialize the audit-head column first (the restore side extends it up to MAX(seq), so evacuating before materialization would make...
- L924: The sweep enumerates D1 `projects` (only an accepted genesis writes one), so a never-initialized DO is not reached in production; the...
- L941: The scheduled() root's logger (index.ts) — without it the converted Effect.logWarning lines do not reach the console spies
- L1001: Seed one failure first: verifies that recording an oversize resets the counter to 0 on the UPDATE branch too (starting from no row would...
- L1030: A namespace whose stub rejects opsBackup (the shape of an unreachable DO or a DO-side defect). The rejection text stands in for DO error...

### `apps/server/test/ops-restore.test.ts`

- L1: Operations foundation — the restore worker's job processing (docs/notes/hosted-ops.md §2-E / §5-2). The restore worker has no HTTP: it...
- L27: The restore worker scans the product key layout (restore/jobs/ etc.), and this file requires an exact match on the scan result (the set...
- L100: The restore materializes the destination only after the object is fetched, so an object-missing refusal on a never-initialized DO leaves...
- L120: While the restore RPC runs, the jobs/ key must already be gone and moved into running/ (a restore can take minutes — this invariant...
- L153: A corrupt snapshot (not gzip — the equivalent of a truncated multipart leftover) — the exception is not let through; a static code is...

### `apps/server/test/problem-details.test.ts`

- L6: RFC 9457 problem details (Effect 4.1) — the applied scope and its boundary: - Applied: framework-level failures only, via the...
- L23: The lease payload requires oidcToken + ephemeralPubHex; an empty object fails decoding before any handler logic runs (the lease group is...
- L37: No per-field breakdown and no schema internals leave the server

### `apps/server/test/project-list.test.ts`

- L1: Integration tests for the project-list API (AUTH_SPEC §11-5). Verifies the HttpApi and D1 / DO via SELF on @cloudflare/vitest-plugin...
- L104: Non-member: an empty list (existence hiding §11-2 — it carries no existence information about others' projects)
- L148: Restoring just the projection row after remove_member is accepted = reproducing a revocation window where the acceptance-path delete...
- L184: A scope limited to another project → absent even for a member (a 200 with zero existence information)
- L210: No field of the response shows an out-of-scope id (§11-5's invariant)
- L217: 100 scopes filling the schema cap (the real project + 99 synthetic). As a single IN clause, together with userId / after / limit it...
- L244: Mix in a DO with a corrupted chain (a stored row that fails JSON conformance) — the shape that makes memberRoleFor a defect. Use a...
- L252: Materialize the DO first (a project is normally materialized at genesis acceptance — Sc-7 / A-4), then seed a row that fails JSON decode...
- L260: No eviction needed: the DO re-checks storage when its #initialized flag is false (#latchInitialized), so the instance that seeded the...
- L266: Each rejected DO RPC below makes workerd log an "uncaught exception" line even though the worker catches it — expected
- L272: The rejected RPC arrives as RpcCallError and leaves the static line + the rejection's error class name (the DO's ChainInvalid defect, as...
- L282: Only the class name crosses the RPC, and any ChainInvalid would log it; the direct call on the instance pins which one fires (the stored...
- L288: The same rejection on a site with no recovery stays a defect (Effect.orDie): 500, as before RpcCallError — the chain get...
- L299: The row is kept (ghost deletion applies only to a definite non-member answer — so it can reappear once the outage clears)
- L316: Insert a page's worth of synthetic IDs that sort before the real project in ascending order (their DO side is uninitialized = ghost — a...

### `apps/server/test/project-quota.test.ts`

- L1: Integration tests for the per-org project-count admission limit (AUTH_SPEC §11-3). Verifies the HttpApi over SELF plus D1 / DO under...
- L71: The DO wrote nothing (admitFresh = false is report-only): fetching the chain is uninitialized = 404 (§11-2), and the DO materialized no...
- L131: The repair overshoots the limit by 1 (surfacing a project that really exists in the DO into D1 takes precedence — the §11-3 acceptance)

### `apps/server/test/proposal-policy.test.ts`

- L1: Decision logic of the four-eyes admission policy (AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — pure functions in quotas.ts). Wiring into the...
- L51: A past expiry does not hit the upper bound (expired proposals are admitted — design record §11 K5-C)

### `apps/server/test/rate-limit-binding.test.ts`

- L1: The failure directions of the per-source-IP rate-limit binding pattern (AUTH_SPEC §4-1 (1) — 2026-10-11 S-2): every endpoint the pattern...
- L240: Judged ahead of the source-address attribution: an unattributable request (no CF-Connecting-IP) does not slip past a missing binding
- L278: An IPv6 source is keyed by its /64 (rateLimitKeyOf): rotating the lower 64 bits must not mint a fresh window
- L312: Neither the address (the limiter key) nor the failure's message reaches any log line

### `apps/server/test/rate-limit-key.test.ts`

- L1: Unit tests for rate-limit key normalization (worker-env.ts). The point is IPv6 /64 aggregation: if rotating the low bits inside the...
- L40: Shapes that would slip through a Number() coercion fall back to the raw string key (= they neither become a different bucket nor fold a...

### `apps/server/test/recovery.test.ts`

- L1: Integration tests for the recovery-blob API (AUTH_SPEC §13; the server side of CRYPTO_SPEC §8). Verifies the real path via SELF on...
- L61: Neither registration nor fetch has a legitimate path from a session (W0 ruling). Even with the CSRF header it is 403 session-not-allowed
- L78: The shape of a cross-site navigation where only the Lax cookie rides along (no custom header). The capability judgment (§5) precedes the...
- L179: Over-limit concurrent requests: since counting is a conditional relative UPDATE (a single statement), exactly the limit succeeds under...
- L198: The audit rows (auth.recovery_blob_fetched) are 1:1 with permitted fetches (the §5.2 same-transaction principle preserved)
- L210: Create a row the v1 write path cannot produce, directly (the assumption of a future-version write / DB corruption). It must not be...
- L245: Registration is done under a differently-named token for the same user (a session cannot register under §5's capability restriction....

### `apps/server/test/reorder-d1-dump.test.ts`

- L1: Pins the pure-function part of scripts/reorder-d1-dump.ts (the D1 restore runbook's tool — hosted-ops.md §5-1 (3)) with a synthetic...

### `apps/server/test/rotation-proposals.test.ts`

- L1: Integration tests for sealed value proposals (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5 / AUDIT_SPEC §3.3 — PF7b). Verifies the HttpApi and DO...
- L78: One ephemeral key per test: the fake issuer mints byte-identical tokens within a second (same claims, same iat), so two mints in one...
- L206: The pre-flight of a mint (AUTH_SPEC §14-5 — the mint's checks before the issuer is touched). The recipient set defaults to W(E).
- L429: The lifetime is a bounded duration on the wire (1 to 30 days): out of range is a payload refusal, never a reason after the issuer was...
- L520: The ids sort the other way round (USER_VAR > VAR), so an id-ordered store would invert the push order
- L698: The recipient set the job will seal to is checked here too (ruling O revision, round 4): exactly W(E) passes (above), a missing writer...
- L725: A stored proposal makes the same variable pending for the next job — at the mint as well as at the pre-flight (two jobs that both...
- L789: A member who began the resolution before the expiry reaches the row until a sweep drops it: the outcome is theirs, not "nobody's"
- L798: The member list sweeps too (ruling P revision, round 4): a project whose rotation job is gone still closes its expired proposals'...
- L870: Explains why the case distinguishes row deletion from scope filtering.
- L883: A valid workload credential aimed at an arbitrary (never-initialized) project ID: the mint and the pre-flight fold to the uniform 404...

### `apps/server/test/rotation.test.ts`

- L1: Integration tests for rotation-needed detection (AUDIT_SPEC §4.1) + the flag view / dismissals (§6 / §7) + recipient-key consistency...
- L288: Recording rules (§3.3 Sc-5 — the aggregate form): one row per environment, actor = system, variable_id NULL, the chain_seq column unused...
- L310: The detection row sits at the seq right after the mirror (chain.member_removed) (a same-acceptance append — §4.1-4)
- L321: Deleting the variable does not erase past readability (the upstream credential is not revoked)
- L329: A deleted variable cannot be pushed — the only resolution path is dismissal (admin)
- L346: Resolution is seq-ordered (§4.1-5): detection on the post- dismissal re-add → re-remove revives
- L403: VAR is detected at both removals (2 live flag rows on one pair — the interval union). The gap variable overlaps no membership interval...
- L421: A new value pushed before the mandated rotation is still encrypted under a DEK the removed member holds — it does not resolve
- L450: A fresh value at the new epoch (= the upstream credential rotated and stored under a key the removed member never held) resolves
- L465: Readers can see it too (detection's purpose is prompting everyone — limiting it to admins would not work)
- L489: A request containing a pair with no live flag rejects the whole thing with 404 (no silent success)
- L718: The expanded re-grant (the chain's consensus rule accepts only a widening to the same key FP — CRYPTO_SPEC §6.2)
- L744: A variable in the widened environment is detected (pinning to the first scope would fail open)
- L753: A variable deleted before the widening does not overlap the window (the window is not brought forward to the interval's start — doing so...
- L818: Other members' legitimate wraps are untouched (the overwrite-forbidden invariant holds)
- L919: The history: metadata, the lineage, and the per-version count; reading it records no var.read (no ciphertext is distributed)
- L1104: 0 fails the query Schema (400); past the latest is the range check (422)

### `apps/server/test/rpc-call.test.ts`

- L1: rpcCall (worker-env.ts): a DO RPC's rejection is a typed RpcCallError, not a defect, and the error carries only the rejection's error...

### `apps/server/test/scope-authz.test.ts`

- L1: ES K3 — scope authorization for environment-targeted ops (AUTH_SPEC §9-2 / §12-3 / §12-7 = the acceptance surface of the scope derived...
- L98: Create two environments (ENV / OTHER) and add DEV as member, listed{ENV}. Since a listed scope can only enumerate created environments...
- L218: fail-closed: a rejected pull records no var.read (§12-7's recording condition = having returned ciphertext; outside scope returns nothing)
- L241: The client derives its own scope from the verified chain — the server-declared "inside scope" is not an input to the verification rules...
- L302: DEK-wrap registration (registrar = signer = the calling principal's scope — §12-6's end = the same judgment as §12-3 → 403. Before the...
- L333: The deletion composite judges scope after the CAS (§12-4), so the entry is signed at the real head
- L356: scope precedes existence: an uncreated environment id cannot be in a listed scope
- L439: Value: at acceptance time (the current head) OTHER ∈ scope so it passes the 403, but at the declared head (pre-widening) it is outside...
- L535: The same write declaring the current head is accepted (inside scope both at acceptance and at the declared head — confirming that only...

### `apps/server/test/scope-dek.test.ts`

- L1: ES K3 — the DEK-wrap recipient set R(E) (CRYPTO_SPEC §6.2 / §6.3, AUTH_SPEC §12-4 / §12-6; design record docs/notes/es-design.md §9...

### `apps/server/test/scope-invariants.test.ts`

- L1: ES K3 — what scope does not change (design record docs/notes/es-design.md §9 / §1-4): - The lease path (AUTH_SPEC §14-1): member scopes...

### `apps/server/test/scope-invites.test.ts`

- L1: ES K3 — scope on invite rows (AUTH_SPEC §15 — format checking only; pins behavior already implemented in K2. Item 4 of the design record...
- L72: The issue-signature producer side (@maruhi/crypto) rejects `all` + non-empty as malformed, so build a valid `all` issuance first and...

### `apps/server/test/scope-rotation.test.ts`

- L1: ES K3 — the rotation-needed detection's per-environment access windows and the change_role variants (AUDIT_SPEC §3.3 / §3.4 / §4.1 /...
- L275: The later removal also flags OTHER (the old window), but bounded at epoch 1 — the member never held OTHER's epoch 2 key — so it is...
- L344: The demoted member stays enrolled: a later removal makes the same environments candidates again (the window did not close)
- L768: a narrowing re-grant (the consensus rules would reject it, but detection is fail-safe): env-b's window stays open until revocation
- L841: Fail-safe semantics: scope null treated as all.
- L864: Every chunk carries the same exposure bound (epoch), subject and trigger — a later chunk missing the epoch would leave its flags...

### `apps/server/test/server-key.test.ts`

- L1: server-key.ts's Effect-cached derivation (W2-S2): one derivation per isolate however many calls race, a null "unconfigured" result...
- L67: The pinned suite's derivation signs exactly twice (HKDF extract + expand — CRYPTO_SPEC §2, §9). An empty-wraps reseal adds no sign (its...
- L93: Gate the derivation's first HKDF sign so the first caller's fiber is suspended mid-derivation when the interrupt lands — without it the...
- L110: Interrupt while the fiber is suspended inside the derivation. The uninterruptible mask around each memo access means the evaluation...
- L198: Gate the HPKE Open's AES-GCM decrypt (the unwrap's last WebCrypto step) so the interrupt deterministically lands while the fiber is...

### `apps/server/test/server-logger.test.ts`

- L1: The server logger (server-logger.ts): Effect log calls reach the console exactly as the plain console.warn / console.error lines they...

### `apps/server/test/serving-topology.test.ts`

- L1: Coverage sweep for the serving topology (W2 ruling BM — docs/notes/session-43.md). maruhi-server serves web assets from the same Worker...
- L43: Does one run_worker_first rule cover a path? Workers Static Assets rules are globs (`*` = any continuation); this repository uses only...
- L69: Only the list form is valid: `true` (all Worker) would break /invite and all asset serving, while an omission would drop the whole API...
- L87: Pin that /invite (a static guidance page — AUTH_SPEC §15-3) and the SPA route space (the /dashboard prefix — ruling BO) stay served by...

### `apps/server/test/session-capability.test.ts`

- L1: Pinned tests for the session principal's capability restriction (AUTH_SPEC §5). The allow / deny matrix of every endpoint × the session...
- L80: Concretizing path parameters. Uses the real project (the fixture — OWNER is the chain owner) so that verifying an allowed surface...
- L122: A dummy body suffices: the capability judgment (middleware) runs before payload decode, so a denied surface does not depend on the...
- L144: The implemented surfaces §5 enumerates as explicit denials (a pin against the spec text). Independent of the derived matrix, this pins...
- L206: The fail-closed target set is not empty (detects the shape where the derivation broke and collapsed to allow-all)
- L231: The load-time sweep already reconciled the allowed enumeration's declaration (api-schema) against the registered surfaces. Here the...
- L248: A coarse sanity check that allowed surfaces are not all failing for other reasons (a 401 would mean session resolution regressed)

### `apps/server/test/signup-policy.test.ts`

- L1: Integration tests for the sign-up controls (AUTH_SPEC §3 — H1). The skeleton of the checks: - the default (no row in...
- L104: The operator warning (Effect.logWarning in identities.ts) goes through the server logger provided at the HTTP root (server-logger.ts):...
- L128: The rejection page states explicitly that no account was created (§3 — surfaced as the outcome row in DP4)
- L138: The rejection does not record the external provider ID (AUDIT_SPEC §1-2)
- L225: If it was consumed between start and callback (reproducing a concurrent consumption), the callback side also rejects
- L264: The cookie carries only the hash (the raw value appears on the wire just once, at start — the cookie store never holds it. AUTH_SPEC §3)
- L334: The code is not burned (the consumption CAS is conditioned on the acceptance-time policy being 'invite')

### `apps/server/test/storage-guard.test.ts`

- L1: Tests for the DO total-storage guard (AUTH_SPEC §12-8). Generating a real 8-9 GB is impractical, so this is pinned in two layers: 1. the...
- L156: Under a meter with a fixed measured size, run programs against the real project DO's SqlStorage (the same layer composition as...
- L198: The DO runtime's logger (chain-do.ts) — without it the converted Effect.logWarning / logError lines do not reach the console spies
- L236: Wire-shape dummies (the support wire types carry suite as string) → DO inputs. Since the guard stands before signature verification,...
- L286: Under either interpretation — 10 GB (decimal) / 10 GiB (binary) — the rejection threshold sits below the floor (§12-8)
- L494: not a growth surface, but a settings change that piles up audit rows without helping exit / release / remediation
- L624: Revocation-kind entries with a mismatched parent head: limit-exceeded if the guard was called, chain-head-conflict if not (the guard...
- L649: The deletion composite checks the declared parent against the entry's own prev before the CAS (§12-4), so its entry chains onto the...
- L786: (h) dismissal — succeeds (audit rows bounded by the flag count). Changing schemaPolicy is a rejection target (the growth-surface test...
- L854: A stale base version would be base-version-stale: the guard precedes the semantic checks
- L906: The storage level is project state: never answered before authorization (§11-2 / §14-3)
- L956: No read is served without its audit row (an unrecorded read of a member nobody can remove at the floor)
- L976: Audit rows exist but the derived column is not yet materialized (nobody has read the audit head yet) → materialization requires a write...
- L986: A standalone checkpoint of a non-empty attestation stops on the same input (placed before the parent-head check = after...
- L1161: At the line for the first chunk, below it afterwards: storing never resumes mid-derivation (a gap), and the convergence afterwards...
- L1204: Stores the first chunk (50 rows), then the line is reached; a predicate that says yes again must not resume storing
- L1269: A project whose dominant growth term is var.read crosses 8 GB → 9 GB with no growth-surface writes. If the observation points covered...

### `apps/server/test/strict-payload.test.ts`

- L1: Pinned tests for the effectiveness of strict acceptance (AUTH_SPEC §12-10 (1)). The targets are every implemented endpoint's payload...
- L157: The zero-signature control passes Schema and falls to the acceptance check's 422 (signature-invalid). A non-400 alone would miss...
- L262: §12-4's mandatory bundling: a create / rotate composite without the checkpoint field fails closed as a Schema-stage 400 (session-33...
- L343: Pinning on the v3 branch that strict annotations propagate across the Union (§12-10 (1)). The control is the handler stage's 4xx...

### `apps/server/test/support/audit-read-scenario.ts`

- L1: Shared helpers for the audit read API (AUDIT_SPEC §6 / §7) integration tests. Assumes the fixture of data-scenario.ts...

### `apps/server/test/support/auth.ts`

- L1: Shared helpers for authenticated integration tests (run inside workerd). Policy (AUTH_SPEC §11-1 ruling): sessions / tokens are always...
- L61: Also delete the flow signing key (AUTH_SPEC §4-2) = each test goes through the first-time generation path (idempotent,...
- L270: Run the CLI login handoff (real path) to completion and get the complete issuance result. The GitHub side is faked (code-<id> →...
- L313: Get a raw PAT via the CLI login handoff (real path). When `tokenName` is omitted the default name is used — reissuing for the same user...

### `apps/server/test/support/chain-vectors.ts`

- L1: A server-test view over packages/crypto/test-vectors/chain-entries.json. The vector JSON -> typed entry conversion reuses the...

### `apps/server/test/support/data-crypto.ts`

- L1: Real crypto helpers for data-plane integration tests (run inside workerd). Real data is built using only the public API of...
- L71: Key borrowing for user IDs not in the fixed vector key set. The data fixture's reader (user-reader-0003) uses the third vector key...
- L127: Sign an entry with a vector seed. If the actor block's FP matches any vector key (including device keys), sign with that key (after DK a...
- L177: Re-sign an existing entry (vector main line or negative) keeping its op / payload / actor while renumbering seq / prev. For replaying...
- L196: approve's timestamp_ms is an input to the consensus rule (§6.2 `proposal-expired` — the only place this spec uses a timestamp), so keep...
- L714: SHA-256 of meta_signed_bytes (used for the next metaVersion's prevMetaSigHashHex — the §4.2 chain). author does not appear on the wire,...
- L816: SHA-256 of env_manifest_signed_bytes (used for the next manifestVersion's prevManifestSigHashHex — the §4.3 chain). issuer does not...
- Added 2026-11-28 (after the audit; no base line): this file is the server suite's table from user id to vector identity: `identityOf` (through the alias and the device-key override above), `signerOf` (for re-signing an entry: the key whose fingerprint its actor block names, or the user id's key when no vector key has that fingerprint, the L127 rule above) and one loop over the table (`wrapDekForAll`). The builders are the kit's, called with an identity: `signEntryAt({ actor: identityOf(OWNER), … })`, so the key that signs is named at the call. The server tests keep naming actors by user id, as the server under test does (the seeded rows, the sessions, the membership it serves). The wrappers this file had when the kit was added, which took a user id and called the kit, are gone: seven had the name of a kit function under another signature, and each restated a kit input shape by hand. The L177 to L816 records above describe code that is now in `packages/test-kit/lib/`

### `apps/server/test/support/data-fixture.ts`

- L1: Shared fixture for data-plane integration tests (run inside workerd). Base setup: a test-time-signed 3-entry chain (owner / member /...
- L42: A member with the reader role. Its signing key borrows the third vector key (user-admin-0003) (VECTOR_KEY_ALIASES in data-crypto.ts —...
- L99: The DO reset is independent of the D1-side reset + reseed, so the two run concurrently, as reseedAuthDb runs its users: fresh state and...
- L132: Seed a user outside the base chain into D1 and get a PAT (a listed member in scope tests — a vector-key user such as...
- L310: Read the stored value-level latest form (each active variable's latest_version + value-signature signed_bytes hash — the §6.2...
- L558: An unsigned deletion-composite body (a zero signature over a well-formed delete_environment entry at the fixture head) — for checks that...
- L652: Send an environment-creation request with an arbitrary wrap set. When dekCommitmentHex is omitted it is computed from a throwaway DEK...
- L727: In a URL-vs-entry mismatch negative, the DO's entry-vs-URL check must be reached before the worker's manifest-coordinate check...

### `apps/server/test/support/data-scenario.ts`

- L1: Shared scenario for data-plane integration tests. fixture / varStatements are exported as ESM live bindings; each test file registers...
- L213: A deleted statement's name keeps the immediately preceding active name (§4.2)
- L221: Unsigned dummy statement for tests that only need to pass Schema (400 / 403 / 404 are decided before signature verification) — a...
- L244: Unsigned dummy manifest for tests that only need to pass Schema (400 / 403 / 404 are decided before signature verification) — a formally...
- L265: Fake ciphertext for acceptance-policy tests (the server cannot decrypt the contents). The value signature (§12-5) is verified by the...
- L287: The default prev for version > 1 is a dummy 64-hex (for tests rejected at an earlier stage than the prev check — CAS etc. Tests that...
- L299: Unsigned fake for tests that are certain never to reach signature verification (Schema 400 / AAD 422 / non-member 404). STRANGER has no...
- L462: The value's version (default 1 = a legitimate activation). Anything other than 1 is for negatives — reproducing the bypass shape "send...

### `apps/server/test/support/fake-github.ts`

- L1: Fake GitHub plugged into miniflare's outboundService (runs on the Node side). It intercepts outbound fetches from the worker (destined...
- L46: Real GitHub: unless Accept is JSON it returns a form-encoded string.
- L56: RFC 6749 §4.1.3: the body is form-urlencoded (an implementation regression that sends JSON breaks here).
- L66: GitHub returns 200 + an error body even for an invalid code (match the real behavior)
- L109: Verify Basic auth: the path's {client_id} must match the Basic-side client_id and the secret must be non-empty (checking the...
- L142: Other-App-issued and invalid tokens alike get 404 (real GitHub behavior)
- L178: Real GitHub: api.github.com requires a User-Agent.

### `apps/server/test/support/invites-scenario.ts`

- L1: Shared helpers for the invite API (AUTH_SPEC §15 — IV revision) integration tests. The issuance statement (issue signature) and the...
- L44: A user's signing key pair (the signer of issue signatures). Users with a fixed vector key get that key; users without one (STRANGER etc....
- L305: Directly seeds an invitation row for tests (builds the precondition state for admission-policy / state-transition tests). The issuance...

### `apps/server/test/support/lease-scenario.ts`

- L1: Shared helpers for workload-lease integration tests. Assumes the fixture of data-scenario.ts (registerDataScenario): each test file...
- L171: Replaces the final character of the signature segment with "a different character that decodes to the same bytes under the server's...

### `apps/server/test/support/lease.ts`

- L1: Test helpers for workload leases (AUTH_SPEC §14). - Building and ES256-signing OIDC tokens (the key is the dummy in...
- L41: The public side of the deployment key actually derived from SERVER_ENC_KEY_IKM. Identical to what the server derives in `server-key.ts`...
- L101: Builds and signs an ES256 OIDC token. `alg` / `kid` are replaceable so that rejection of a non-allowlisted alg and an unknown kid can be...

### `apps/server/test/support/membership-scenario.ts`

- L1: Shared scenario for membership-log integration tests (the same "shared fixture + register" pattern as data-scenario.ts). History of the...
- L112: The vector's dummy DEK for (environment, epoch) (paired with the computed commitment). For a negative's invalid coordinates (a...
- L438: When the head matches the vector, re-signing is deterministically identical, so the entry keeps the original bytes.
- L493: Called once at the top of each test file: registers the fixture's beforeEach. The storage-isolation unit of this...
- L505: The DO reset is independent of the D1-side reset + reseed, so the two run concurrently, as reseedAuthDb runs its users: every test gets...

### `apps/server/test/support/node-fs.d.ts`

- L1: Minimal type declarations of node:fs used by vitest.config.ts (vite-node = runs under Node). The server tsconfig has only workers-types...

### `apps/server/test/support/oidc-issuer.ts`

- L1: Fake materials for the test OIDC issuer (AUTH_SPEC §14-1). A shared module read from **both** vitest.config.ts's outboundService (the...
- L53: A router called from outboundService (returns null when not addressed to the issuer — the caller forwards to other fakes). Returns...

### `apps/server/test/support/project-do.ts`

- L1: Resets the project DO between tests (runs inside workerd). The storage isolation unit of this @cloudflare/vitest-plugin configuration is...
- L39: Evicts the instance and drops the in-memory cache of derived ChainState (for returning to a full load after directly mutating stored...
- L49: Calls an RPC method on the project DO instance itself, bypassing the RPC transport: a defect then rejects with its own error (message,...

### `apps/server/test/support/read-dev-vars.ts`

- L1: Reads `.dev.vars.example` (KEY=value lines) into the dummy bindings the server tests run with, so the example stays the single source of...

### `apps/server/test/support/read-migrations.ts`

- L1: Loads drizzle-kit v1's folder form (drizzle/<name>/migration.sql) into the D1Migration[] that cloudflare:test's applyD1Migrations...

### `apps/server/test/support/schema-scenario.ts`

- L1: Shared helpers for layout v3 (valueless schema) integration tests. Assumes the fixture of data-scenario.ts (registerDataScenario).

### `apps/server/test/tokens.test.ts`

- L1: Integration tests for the token-management API + the default TTL (AUTH_SPEC §6 — W3a). - the TTL is fixed at issuance (§6: deliberately...
- L87: The path by which unattended use (a PAT on a lease-less environment — ruling CF) observes its own expiry. Even a scope-limited token can...
- L138: Raw values / hashes do not exist even as fields (§6: not returned)
- L232: Even the response body is uniform (cannot distinguish whether the id exists)
- L234: The other user's token is not deleted and no audit is recorded (the discipline of not letting it silently succeed)
- L283: Make explicit that beforeEach's resetAuthDb has applied the migrations (the response's precondition is not left implicit —...

### `apps/server/test/worker-secrets.test.ts`

- L1: The worker's secret configuration values travel as Redacted (worker-env.ts readWorkerSecrets): GITHUB_CLIENT_SECRET, SERVER_ENC_KEY_IKM...
- L91: The client_id is public, so it renders in the clear; the three secret values render only as their labels
- L99: The worker and the test share one isolate, so a console spy here sees what Effect's logger writes for the worker
- L172: A .get() rejection is indistinguishable from unset by design: the OAuth pair then fails closed with 503 SetupIncomplete, the IKM leaves...

### `apps/server/vitest.config.ts`

- L13: wrangler.jsonc's real values are read on the Node side (workerd cannot read fs) for the run_worker_first coverage sweep
- L28: Outbound fetches to GitHub are replaced with the fake: real network is forbidden in tests
- L30: A local R2 OPS_BACKUP_BUCKET binding reproduces the hosted environment's shape in tests; it is absent from wrangler.jsonc's top level
- L35: Tests run a configured server with .dev.vars.example dummy values, the single source shared with local cf dev
- L52: D1Migration[] is widened for the Miniflare Json assignment because the interface lacks an index signature (miniflare 5 type tightening)
- L72: fsModuleCache off: the plugin would inline 34-40 MiB into one WebSocket message, over workerd's 32 MiB limit (workers-sdk#16349); remove once bounded
- L84: testTimeout 60s: measured flakes over the 5s default under load and 30s+ vector-replay tests on slow CI, while keeping hang detection bounded
- L91: hookTimeout 30s: the fixture issues a PAT via the real CLI handoff (6 round-trips; §11-1 forbids stubbing) and replays the base chain
- L98: isolate:false reuses one workerd per worker (measured 160s to 51s); safe because fixtures reset shared D1/DO state; file order is shuffled (T-2)
- L149: silent passed-only: the per-response INFO log produced roughly 97k lines per CI run; failing tests still show output in full
- L157: The shuffle is re-declared here for the direct apps/server vitest path (T-2); under the root config a project's own sequence.shuffle is ignored

### `apps/site/test/e2e.test.ts`

- L1: The apex e2e serves the built dist under production serving semantics and pins the web-design-pass §4 items: same-origin only, zero CSP violations, self-hosted fonts.
- L119: CI, Cursor Cloud and Claude Code on the web pass the Chromium path via PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH.
- L235: Terminal examples keep no aria-label treatment difference: <pre> has the generic role and assistive tech may or may not read a label, so every example is treated the same.
- L254: Figure placement is pinned so a sighted reader meets the same order a screen reader reads in the DOM: figure right of or below the text, never left or above.
- L292: The figure-layout test first verifies Martian Mono actually loaded, because a narrower fallback face would pass the label-overlap checks unnoticed.
- L373: Astro 7 compressHTML jsx drops line breaks between text and elements, so sources write {" "}; a missing one renders glued words like 'Docs ·License'.
- L568: Page dates use the author date (%aI) as getLastUpdated reads it, and the check needs full git history (fetch-depth: 0) — a shallow clone would date every page at the boundary commit.

### `apps/site/test/unit/adr-record-headings.test.ts`

- Added 2026-11-28 (after the audit; no base line): a heading of the record ADRs (0021–0030) follows its file. When a file moves, its heading is rewritten to the new path and the first line under it keeps the path the file had at the audit base commit, which the L numbers refer to (`Moved <date> from`). A reader starts from the file in front of them, so the current path has to find the records, and every record of one file stays under one heading. The test fails on a heading that is not one path in backticks, on a heading that names no tracked file, on headings out of code-point order or repeated, and on a `Moved` line whose old path still exists. It does not know which headings were rewritten, so a missing `Moved` line is caught in review, not here

### `apps/site/test/unit/cli-vocabulary.test.ts`

- L1: Docs must copy CLI vocabulary from the help golden (K7-A/K6-O); rulings a machine can decide become checks (K6-T), covering command paths, flags and required positionals in sh blocks.
- L135: Only a maruhi at line start or after a shell conjunction counts as an invocation; the word inside prose quoting the CLI's wording is not a check target.
- L258: The K6-T pins convert rulings into structure: each replaces checking the wording with a check, scoped to only what the PR asserts.
- L264: K6-A: devices.mdx covers every device/token subcommand and key reserve; if a group gains subcommands, write them on this page or re-rule.
- L279: K6-D: dashboard wording in docs is copied from the web implementation with no paraphrasing.
- L291: K6-H/K7-5: no pre-device-key vocabulary ('master key') remains in docs or CLI help after K7 rewrote the agent help.
- L302: K7-7: the FP-provenance discipline is an unremovable duplication stated in its own words by both the docs and device approve's output, so the copied phrase is pinned on both.
- L312: K9-3: that a failed registry write leaves the request in place is stated by both device approve's Note and the docs, so the Note phrase is pinned on both sides.
- L325: K6-U: the ledger-changing enumeration names no opening material because guardian add accepts no --passkey; existence is pinned too so the check can't go vacuous.
- L343: K6-L: recipes.test.ts executes only deploy-targets.mdx's blocks; no other page's sh block may accidentally match that shape.
- L357: K10-6: devices.mdx quote fragments are netted against the CLI's literal wording by shape, so a wording change cannot leave a quote behind; vacuity and short-fragment matches are denied.
- L381: Quote fragments split on … count only at 12+ characters because short fragments match the CLI wording by chance.
- L423: K6-Y: doc mentions of limits/TTLs are pinned by occurrence count, not existence, so editing a duplicated sentence onward cannot pass silently.

### `apps/site/test/unit/doc-paths.test.ts`

- L1: Doc/source file references must resolve against the tracked tree; an extractor under-count fails first, and legitimate non-repo references live in ALLOWED with a reason each.
- Added 2026-11-28 (after the audit; no base line): a brace path such as `src/do/{chain-do,do-schema}.ts` is expanded into one path per alternative before extraction; before that the extractor stopped at the brace and checked none of them. A group expands only inside a path run, without spaces, with a letter in it; nested groups stay unchecked.
- L43: The extension alternation is longest-first with a trailing word boundary, and env is deliberately absent because .env-suffixed tokens are env-var namespaces in practice.
- L155: URLs are stripped before comment extraction so a // inside a scheme is never mistaken for a comment start.

### `apps/site/test/unit/recipes.test.ts`

- L1: Docs recipes are executed verbatim from the page; pins: no plaintext on argv or in set -x traces, values reach only vendor stdin, POSIX sh (rulings H/C).
- L34: Recipes are selected by the maruhi run prefix shape, not document order, because maruhi sync usage blocks live on the same page.
- L139: PS4's default differs per shell, so the proof tracing happened is a line starting with + showing the outer maruhi run command.
- L145: Dash writes trace words per process and the pipeline's two sides interleave arbitrarily on stderr under load, so the check must not depend on word order.
- L171: Invariant: recipes and sync examples never write shapes that put a value on argv, on disk (except /dev/null/fds), or fetch it.
- L185: Without jq the Workers cases skip locally, but CI must not silently degrade, so jq presence is asserted there.
- L192: The page promises bash/zsh/dash run the recipes unchanged; locally only installed shells run, in CI all four shells' presence is asserted.
- L264: The inner sh's trace words may interleave with the other pipeline side's, so the xtrace evidence check must not depend on word order.

### `apps/site/test/unit/related-pages.test.ts`

- L1: Every docs page but the index must name 2-4 related pages, because the route renders only listed cards and a forgotten field silently ships without them.

### `apps/site/test/unit/reviewing-map.test.ts`

- L1: REVIEWING.md tables are pinned per-column because doc-paths' bare-filename existence check is too weak: several names exist in both crypto and the CLI.
- L72: A trailing -k is list item k inside the section in CRYPTO/AUDIT specs; AUTH uses -k in its own headings, so it never reaches this resolver.

### `apps/site/test/unit/shims/maruhi.ts`

- L1: The maruhi test shim mimics only what the recipes rely on: env injection from RECIPE_TEST_VALUES, inherited stdio, child exit code; real flags are recorded.

### `apps/site/test/unit/theme.test.ts`

- L1: Ruling B: the site's generated theme artifacts are a mapping of apps/web/theme/maruhi.css and committed content must match a fresh regeneration.

### `apps/site/test/unit/threat-model.test.ts`

- L1: THREAT_MODEL.md must match CRYPTO_SPEC §14.3's non-guarantee numbering one to one, since §14 claims it lists every §14.3 item.
- L34: The spec-item count is floored at 10 so a heading rename or list-format change fails before the comparison can pass on two empty lists.

### `apps/site/test/unit/workflows.test.ts`

- L1: Workflow templates are checked verbatim from the page (ruling H): invocation contract, least permissions, SHA pinning, plaintext stays inside CI, ci sync flags.
- L126: GH_SECRETS_TOKEN is the single exception to 'no secrets. references': the bootstrap token gh signs in with when a github-actions target writes GitHub secrets.
- L161: A step running maruhi writes nothing to runner files and echoes nothing; its env holds only the target name and the bootstrap token.
- L235: Existence of the contract's dispatch input is asserted first so the check cannot silently pass if the input disappears or is renamed.
- L280: Workflow expressions reach the shell only via env, as GitHub script-injection hardening.
- L334: Two overlapping rotate runs would both create a credential at the issuer while only one proposal per variable can be pending (PF7b ruling O-8), so concurrency is pinned.
- L364: A custom if may replace the implicit success(), so success() is stated explicitly to not start sync when targets failed.

### `apps/web/test/e2e.test.ts`

- L1: Web e2e serves the built dist in the combined production configuration (rulings BM/BT) and verifies shell hydration, strict-CSP operation, SPA/MPA degradation, theme application and serving topology.
- L66: The e2e port is not pinned; the OS assigns a free one so CI's parallel runs cannot collide.
- L88: cf dev output is buffered, not discarded, and printed on the two failure paths (startup timeout, SIGTERM failure) before the runner kill leaves nothing.
- L115: Shutdown falls back to SIGKILL when SIGTERM does not end the dev server; with SIGTERM alone CI actually hung to the 30-minute job limit.
- L137: The stdio pipes' read ends are destroyed unconditionally because a surviving dev-server descendant holding the write end would keep vitest from ever exiting.
- L151: The e2e boots apps/server's deployed cloudflare.config.ts itself as the serving layer (combined configuration, ruling BT).
- L170: CI, Cursor Cloud and Claude Code on the web pass the Chromium path via PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH.
- L220: The hidden-panel check exists because without the StyleX compiler the override silently renders unstyled and every panel shows.
- L231: defineTheme derives the accent palette via HCT, so the final --color-accent is a derived value, not the given hex; the check pins difference from the Astryx default and agreement with the generated CSS.
- L349: The canonical /invite path must pass through the 200 shield unswallowed by the catch-all; if the shield dropped and looped, the 3xx here would catch it.
- L391: The ceremony-page check arrives via the uniform error page because the approval page itself needs OAuth; a server-side test checks the same page() output.
- L424: Regression pin: in the first version a var() on an undefined token silently dropped font-weight, leaving the h1 and outcome line at normal weight.
- L494: W2 dashboard e2e (ruling BS): serving, rendering and CSP stay real (cf dev + Chromium); only API responses are swapped via page.route, staying same-origin so the connect-src 'self' verification is not weakened.
- L514: Every authenticated screen's test registers the session mock because a real server's 401 response keeps networkidle from settling without its body being read.
- L569: run_worker_first's effect is pinned against the deployed configuration: a bare 503/401 JSON response is itself evidence the Worker was reached and not swallowed by the SPA shell.
- L586: Regression test for the session-43 §9 defect: on an enumeration miss, _redirects' lowercase catch-all 301s the acceptance POST into /invite.
- L598: Fixtures are decoded against the real Schemas so mock/wire drift is a machine check; Schema code runs only in the test process, never in the bundle.
- L634: The CSP header's presence is pinned directly because the zero-violation checks would also pass when the header is missing entirely.
- L696: The error Banner gets role=alert explicitly because Banner derives no live-region role from its status.
- L852: An unselected panel is empty (height 0), so isVisible() cannot detect a display override losing; the computed display is pinned directly.
- L969: The resume marker is written by a real click, not injected by the test, so a regression in Link's marker write or the consume guard fails here; only the real OAuth flow is e2e-impossible (ruling BS).
- L1002: Request collection pins that ruling BU has not regressed into BP's rejected approach of a constant /auth/me check on the landing.
- L1045: The Overview tab's consumed surfaces are also mocked because a real server's 401 keeps networkidle from settling with its body unread — the reason the W2 tests are fully mocked.
- L1215: The refetch check is scoped to the list because Astryx's announcer keeps the initial load's 'Loading tokens' announcement in the DOM; a page-wide query would count that instead.
- L1243: If another row could be armed mid-DELETE, the late completion would overwrite the armed state and misattribute the failure (the use-revocation guard); the modal stays open while it runs.
- L1393: DP3 amendment 11: screens are children of the pathless parent route, so the shell never remounts; the no-remount check is that the sidebar's DOM node stays identical.
- L1651: The empty-device check is scoped to the empty notice because Astryx's announcer also speaks the title into its role=status region under body.

### `apps/web/test/fixtures.ts`

- L1: Fixtures are literals conforming to the api-schema-derived types (tsc detects divergence), with the Schema decode check in e2e.test.ts (ruling BV); this module is test-process-only and never enters the shipped bundle.
- L61: The empty-page fixture carries nextAfter (§11-5): ghost exclusion and failed confirmations can empty a candidate page, and the UI must not misjudge it as the end of the list.
- L309: S8/S9 fixture expiry values are fixed far in the future (2100) and past (2023) because ruling CQ's Expired display compares against the client clock — nothing near the boundary is used.

### `apps/web/test/screenshots.ts`

- L1: Screenshots (ruling F): no preview routes or mock data in the shipped app — only the API is swapped as in e2e; empty states are shot explicitly because the non-empty fixtures never render them.
- L55: mockApi's empty mode exists because fixtures alone never draw the empty states, whose heading hierarchy differs from when a collection exists.
- L93: Variable names are never emptied even in empty mode: they are fetched only when an environment row opens, and with no environments the variable-names empty state cannot be drawn.
- L218: The revocation-modal shot waits for the dialog to appear so it does not silently capture the bare table.

### `apps/web/test/unit/api.test.ts`

- L1: The CSRF header's actually sent value is collated against api-schema's CSRF_HEADER_NAME as the second layer complementary to the satisfies type binding (ruling CN); value imports are test-process-only (ruling BV).

### `apps/web/test/unit/chain-view-drift.test.ts`

- L1: Drift tests keep the web's tally copy because the bundle may not contain crypto code (ADR-0018); the intentional difference is fail-closed — the web may show fewer voters than crypto, never more (K5-2).
- L125: Extended chains' prefixes up to base_seq are canonical prefixes, so vectorChains skips them — they are compared once, with the canonical chain.
- L417: The chain vectors hold no pending proposal with two or more counted votes (a second counted vote applies them under required-2), so the built chains supply those cases.
- L562: Intentional difference: members with unresolved revocations keep the revoked rows on the web, so their device rows are not compared against crypto; role and scope still are (K5-1).

### `apps/web/test/unit/chain-view.test.ts`

- L1: chain-view.test pins the display fold (not verification) with fixtures conforming to api-schema's wire types, bound by tsc.
- L1259: A propose carrying delete_environment is approval-not-required on a verified chain, so like the device ops (K5-4) the fold applies it only as a direct entry.

### `apps/web/test/unit/endpoints.test.ts`

- L1: The endpoints sweep (ruling BW) collates the dashboard's catalog against the registered HttpApi so path agreement and session allowance fail loud; it is the client-side counterpart of serving-topology.test.ts.
- L48: An unknown template parameter stays in place and fails the equality comparison, forcing a catalog revision (fail-loud).
- L71: Session surfaces must be inside the session-allowance enumeration so a screen calling an unlisted API fails here, not as a runtime 403; unauthenticated funnels are checked symmetrically.
- L98: The cursor name must be declared in api-schema's query Schema: renaming it fails here, not as silently unresponsive paging — the server ignores an unknown query, so no runtime error ever surfaces.
- L112: The builders' attached cursor names are pinned with deliberate expected-value literals, avoiding tautological repetition between builders.
- L127: Source tripwire (rulings BY/CA): no API- or /dashboard-prefixed path literal may appear under src/ outside the two builder homes, so a builder-bypassing consumer is dropped as drift.
- L168: The import sweep anchors at line start because without it a match would bridge from the word 'import' in a comment to a real import's from clause (the api.ts ruling-CN comment was the first trip); re-exports, side-effect imports, import() and require() are in scope.
- L203: SPA_ROUTES's authority rests on route() declarations living only in routes.ts; an inline route() in App.tsx would silently narrow the non-intersection sweep. bindRoute is a different name and never false-positives.
- L231: The tripwire scans every JS/TS extension form so a module extension cannot step around a sweep; exclusions compare by resolved path, since a filename comparison would silently exempt a same-named file elsewhere.
- L246: The path-literal scan covers only quoted strings: backticks collide with path examples inside comments, and the resulting evasion gap is accepted as good-faith drift detection (the word-hash tripwire's standing, BG).
- L271: Envelope sweep (K8-2/K8-7): wire types must derive from api-schema Schemas (ruling BR) because a hand-written copy silently goes stale; both claims compare counts to counts and fail rather than pass vacuously.
- L355: The envelope sweep reaches the whole consumption surface, not just types.ts, because a hand-written supertype (any, optional fields) at a call site would hide api-schema drift that tsc cannot catch.
- L389: The envelope sweep never passes vacuously: each entrance is found at least at its own declaration, and some site lies outside the declaring modules.
- L411: RSC boundary: server-graph files may import dashboard modules only behind a 'use client' boundary or the routes.ts allowlist; routes.ts itself may carry no relative import, or any module could enter the server graph via the allowlist.
- L514: Even a type-only relative import in routes.ts is banned, because it could be the entry of a dependency via the allowlist.

### `apps/web/test/unit/spa-topology.test.ts`

- L1: Non-intersection sweep (ruling BZ): the SPA-vs-Worker direction was hand-checked only until now; an over-broad run_worker_first prefix would send SPA navigations to the Worker's 404 JSON and the screen would disappear.
- L70: Adding a path builder must come with SPA_ROUTES registration (becoming a sweep target), and parameter substitution must be complete — a missed :param is a runtime 404.

### `packages/api-schema/test/index.test.ts`

- L159: Test pins the API-level RedactedNames declaration covering the OAuth code/state, signup_code, CLI verify code/vsig, and the credential headers

### `packages/api-schema/test/strict.test.ts`

- L1: Strict unit tests restate the rc.113 wrapper context; the real 400 rejection on the acceptance path is covered by apps/server's strict-payload test
- L81: The expected endpoint list in this test is regression protection for the strict list, including §16-1 head attestation
- L117: Regression protection for the exempt list: only surfaces outside §12-10 (1) (no signed structure, ciphertext, or key material) may appear
- L145: Test scenario: an unclassified new endpoint does not silently stay non-strict — it fails at load time
- L162: Test scenario: the exempt side also gets an existence check, so a lingering exemption cannot masquerade as 'deliberately exempt' for a reused name

### `packages/core/test/audit-inserts.test.ts`

- L1: Audit-inserts tripwire: every new audit row goes through a store's checked serialization point; the replication and restore paths are out of scope by design (they copy existing rows and write no new event)

### `packages/core/test/audit-payloads.test.ts`

- L71: Test documents AuditText's exclusion limit: a union with a plain string widens to string — the runtime check and per-event key set close a payload, not this exclusion

### `packages/core/test/audit.test.ts`

- L1: Audit mirror test pins indexProposals' completion derivation, which depends on crypto's verifier removing a proposal from the pending set in exactly two places — an expired proposal stays pending; each branch is pinned directly

### `packages/core/test/auth.test.ts`

- L1: Token-scope combination rules (multiple entries, wildcard coexistence, empty array) pin their intent in this test
- L37: Intent pinned: scope entries are additive (strongest match) — while * × admin exists, adding an individual read entry leaves the project's permission at admin
- L76: The hand-written guard accepted any string for project; TokenScopeSchema requires a ProjectId (64 lowercase hex) or '*' — pinned here

### `packages/core/test/brand-casts.test.ts`

- L1: Brand-casts tripwire pins the assertion route around the lint gate, and its last block keeps the lint rule's mint-site allowlist honest (every listed file must still import a mint)
- L18: The brand-assertion pattern covers the seven brands; $type<UserId>() on a Drizzle column is a branded column — the sanctioned DB mint, not an assertion
- L26: A hand-written type predicate returning a brand is a mint with no boundary; such predicates live only in packages/core/src as module-private functions feeding the Schema.refine mints
- L37: The one sanctioned mint file is crypto's chain verifier; its brand-assertion count is pinned so a sixth cast fails loudly
- L50: The repo walk never descends into node_modules, dist, or dot-directories — CI's parallel group builds into them while this test runs, so walking them would race the build

### `packages/core/test/effect-tsgo-rules.test.ts`

- L85: A schema restructure or config refactor must fail this test loudly rather than let the coverage check pass vacuously

### `packages/core/test/egress.test.ts`

- L74: Egress test scenario: in the CLI command environment a build-time RequestInit would be dropped (the ambient client build is reused) and a redirect would re-send the caller's credentials
- L97: A client built from scratch with HttpClient.make would bypass the oxlint import pin, so that construction is pinned in this test instead

### `packages/core/test/ids.test.ts`

- L7: Format-invariance: the expected strings were produced by the pre-migration ambient-WebCrypto implementation fed the same byte streams, so equality proves the SecureRandom migration changed neither algorithm nor encoding

### `packages/core/test/index.test.ts`

- L64: Static exhaustiveness check: if a CryptoError kind is added on the crypto side, this fails to compile
- L130: The bare-Promise operations list is pinned to the derived union both ways: satisfies keeps it inside, AllOperationsCovered fails compilation if the union grows
- L229: Guard boundary pinned directly: __proto__ is rejected (out of form) while constructor / prototype are accepted as legitimate IDs — the guards also validate storage record keys
- L244: An inherited-property name is a legitimate ID if it fits the form — the reading side defends via own-property checks

### `packages/crypto/test-vectors/tools/bunfig.toml`

- L1: test-vectors/tools is resolved as an independent project, the same technique as spikes/ (docs/notes/spike-c.md)

### `packages/crypto/test-vectors/tools/generate-dek-wrap.mjs`

- L1: Vector generator uses hpke-js, an implementation family independent of the product's panva hpke, because Seal can be pinned deterministically via ekm derandomize; disposable tool, dummy keys
- L16: The generator's LP encoding is the same §2.1 definition as generate_reference.py
- L51: Server recipient class (§9): the server key is a DeriveKeyPair from fixed ikm and its FP rides in the recipient_user_id position (a server has no user_id)
- L75: §5: context binding is carried by info; aad is empty
- L88: The same DEK is also wrapped to the server key, matching a real recipient set — the §7 wrap-complete set

### `packages/crypto/test-vectors/tools/generate-lease-wrap.mjs`

- L1: Lease vector is generated by re-wrapping dek-wrap.json's server-basic DEK to the workload key, making §9.1's intermediary handoff traceable; regeneration order is fixed
- L25: tools/ is disposable, so by convention each file carries its own independent LP definition rather than sharing a module
- L70: The prior-epoch vector represents §14-2's past-epoch portion and shows the DEK is independent per epoch
- L76: Fixed-ikm determinism for the workload ephemeral key is a vector-specific convenience, not part of the spec (§9.1)
- L85: claims_digest formula: lower_hex(SHA-256(LP('<suite>/lease-claims', issuer_url, subject, audience))) (§9.1)
- L92: otherSubject is the material for the negative pinning that reuse of a lease response in another context fails decryption (§9.1)
- L106: Lease wrap info formula: LP('<suite>/lease-wrap', project_id, environment_id, epoch, claims_digest_hex) (§9.1)
- L114: Same as §5: context binding is carried by info; aad is empty

### `packages/crypto/test-vectors/tools/generate-master-key-wrap.mjs`

- L1: Master-key-wrap vectors regenerated at KL3/DK deleting the device handoff route — an intentional exception to README convention 28; all routes pack the same blob B inherited from recovery-wrap.json
- L48: tools/ is disposable, so by convention each generator carries its own independent LP definition rather than sharing a module
- L277: The old-device approval was removed at 2026-09-20 DK; handoff approvers are guardians only (§8.4)
- L415: mode exists only for guardian in the AAD (§8.1); a passkey-prf-relabeled AAD carries the empty string as its mode field

### `packages/crypto/test-vectors/tools/generate-sealed-value.mjs`

- L1: Sealed-value vector seals to the same device key as dek-wrap's basic vector at the same coordinates (W(E) ⊆ R(E), §5.3); disposable tool, dummy values
- L22: tools/ is disposable, so each tool carries its own independent LP definition
- L65: The proposal id is client-chosen (16 random bytes as lowercase hex, §5.3); a fixed pattern is used for the vector
- L77: Sealed-value info formula; base_version is under the seal so a server cannot re-label a stale proposal as current (§5.3)
- L104: Same as §5: context binding is carried by info; aad is empty
- L122: The tampered-ciphertext negative pins that the AES-GCM tag covers the whole body

### `packages/crypto/test-vectors/tools/generate_reference.py`

- L30: §2.1 LP encoding definition: UTF-8 fields as uint32-BE length + body, numbers decimal-stringified first
- L191: Chain-entry canonicalization definition pinned by this vector: signed_bytes / payload_bytes / entry_bytes / entry_hash forms (§6)
- L206: ES (0.11-draft §6.2): scope fields appended to add_member/change_role payloads; the old form has no compatibility path and negatives pin it
- L217: create_environment became a chain op (0.4-draft §6.2) and dek_commitment_hex was appended to the rotate_epoch payload
- L222: grant_server lease_policy_lp_hex appended at the end (0.5-draft §6.2) — settled before release as the last format window, no grandfathering
- L232: Checkpoint environments ride as one field: the hex string of the same nested LP as scope_environments (0.7-draft §6.2)
- L237: PF1 four-eyes canonical forms: ops_lp_hex, inner_payload_lp_hex and proposal_hash_hex definitions (0.11-draft §6.2)
- L246: DK device-key canonical forms: add_device scope fields reuse the environment-scope encoding; revoke_device carries the nested LP of the FP list (0.12-draft §6.2)
- L253: delete_environment domain separation is the op name inside signed_bytes, like every chain op — no new domain string (0.17-draft §6.2)
- L259: §6.2 checkpoint values_digest definition: active variables only, byte order, empty set valid
- L324: Checkpoint environments nested-LP form; list order is part of the signed payload (generation SHOULD be byte order, verification is not normative about order)
- L345: §5.2 DEK commitment definition; the domain string binds the suite and the coordinates enter the preimage
- L368: FP = first 16 bytes of SHA-256(enc_pub || sig_pub); raw concatenation because both keys are fixed 32B (§3)
- L381: Server-key FP hashes the enc key alone because a server holds no signing key (§9) — a deliberate deviation from §3's user FP definition, flagged for review
- L394: grant_server scope is a nested LP carried as one hex field; list order is part of the signed byte string and verification reconstructs as-signed
- L404: Lease policy canonicalization is a 3-level nested LP (§6.2/§9.1); list order is signed; an empty list = no lease path, hex is the empty string
- L446: Approval ops list order is part of the signed payload (generation SHOULD be code-point order; verification treats it as a set)
- L463: inner_payload_lp_hex nesting becomes 2-level when the inner op itself carries a nested LP (§6.1)
- L559: Duplicate (issuer, audience) lease-policy elements with different constraints are a legitimate representation (multiple branches under exact-match); fixture values are dummies (§6.2 / AUTH_SPEC §14-1)
- L600: Project ID = the genesis entry hash (§6.4), used as the §5.2 commitment preimage coordinate so chain and commitment coordinates form one run of real data
- L605: Dummy DEKs carry actually-computed commitments (chain verification cannot verify contents, §6.2) so implementation tests can check the §5.2 DEK-to-commitment comparison
- L634: Canonical chain design: env-stage-0003 is left unrotated (epoch 1) to pin the first-rotate-to-2 boundary and epoch-1 head state
- L664: ES+PF1 appends leave seq 1-12 unchanged in meaning; proposal expiry is the CLI default t0+7d, within AUTH_SPEC §12-8's 30-day bound
- L708: Negative design: payload tampering with the signature kept must fail verification
- L770: The flat scope mis-encoding (raw concatenation without nested LP) pins that canonicalization never produces this ambiguous byte string
- L776: The lease_policy order (elements and constraints) is also signed
- L792: The flattened lease-policy mis-encoding pins the 3-level nested LP: flattening erases element/constraint boundaries and breeds ambiguity
- L807: Substituting the payload under the original signature must fail verification
- L847: Old 3-field form pin: an old-format implementation cannot verify the new chain — the 4 fields are mandatory
- L877: dek_commitment_hex is part of the signed payload: substituting it fails verification (§5.2)
- L893: Authorization negatives are constructed with valid signatures and hash linkage so rejection must come from §6.2's authorization rules
- L957: Re-grants that narrow scope are rejected (2026-08-02 owner ruling): narrowing goes through revoke_server + rotate_epoch (§7); only widening is accepted
- L972: Two-layer re-grant rule (§6.3): judgment is independent per field — a free lease_policy revision does not excuse a scope narrowing
- L983: Check-order pin: a narrowing re-grant by an admin is rejected by the role rule before the re-grant rule
- L994: Server key uniqueness (§6.2): the FP is made consistent under the §9 definition so the rejection reason is key duplication, not payload mismatch
- L1020: Check-order pin: a duplicate-key grant by an admin is rejected by the role rule before the duplication check
- L1031: lease_policy size limits (at most 8 elements, 8 constraints per issuer) are a §6.2 consensus rule failing at the structural stage
- L1077: Key uniqueness second clause (0.22-draft §6.2): the old derived chain became itself invalid, so the chain and its two negatives are retired; the entry stays byte-for-byte as a negative
- L1117: Check-order pins place the grant clause of duplicate-member-key on both sides, since the shared reason code makes adjacent-pair pins blind to a misplaced comparison
- L1135: Environment-lifecycle binding (§6.2): create ids are chain-unique, rotate requires a preceding create; check order role → duplicate/unknown → epoch is pinned to reason codes
- L1180: Epoch-order rule (2026-08-02 owner ruling, option 3): rotate is always +1; rollback, duplicates and jumps (epoch burn-out DoS) are rejected
- L1198: The wrong-epoch commitment is formally valid, pinning that the rejection reason is epoch order, not the commitment
- L1214: Commitment format violations are structural-stage negatives (structure → actor → signature → authorization); the signature is valid over the violating string itself
- L1250: Field size limits (2026-08-02 owner ruling, option 2): 1024-byte free strings and 256 scope elements are consensus rules countering verification-client resource consumption
- L1274: Member-key uniqueness is judged per individual key (2026-08-03, session 10): reusing only one of enc/sig is also rejected, not an FP equality check
- L1301: Check-order pin: role rule precedes the key-duplication check (insufficient-role, not duplicate-member-key)
- L1314: Check-order pin: user_id duplication precedes key duplication (duplicate-member, not duplicate-member-key)
- L1326: Impersonation negative: declared FP and signing key are the member's while user_id claims the owner
- L1344: Valid-append positives pin the permissive side: removed members' keys are reusable (uniqueness bans only the current set) and create + first rotate of an unused id are accepted
- L1369: grant_seq is the seq of the entry that established the active grant; it is AUDIT_SPEC §3.5 grant_chain_seq's only source, so it is pinned as derived state
- L1432: Re-grant two-layer acceptance side (§6.3): shrinking lease_policy with scope unchanged is accepted — the policy is the lease ACL and tightening it incurs no rotation
- L1444: grant_seq advances to the re-grant entry's own seq; an implementation keeping the old seq fails this vector
- L1452: Key uniqueness counts a device only while current (§6.2): a removed member's enc key can become a server key, FP per the §9 definition
- L1479: Derived env state: the 'initial value 1 if unobserved' default is abolished — an environment with no create_environment on chain does not exist (§6.2/§6.3)
- L1496: Four-eyes derived state: votes are counted anew per approve from distinct owner principals in S; role-at-proposal is informational, not a vote-counting input (K2-6)
- L1509: A vote is (user_id, key FP at signing) (2026-09-15 owner delegation ruling ⑤, K2-11)
- L1606: PF1 snapshot: the inner change_role applies at the approve's seq 22 (inclusive) — devmember is reader{dev} from seq 22
- L1628: Checkpoint vectors use deterministic dummy values because consensus verifies only form, actor role and coordinate consistency; tuple content is on the comparison side (§6.2)
- L1671: A re-attestation of the same (environment, manifest_version) with a new values digest after re-encryption is legitimate (§6.3 issuance SHOULD (i); §4.3)
- L1735: Checkpoint authorization check order is stage-wise across all entries (ruling C): role → admin-for-audit-head → unknown-environment → epoch-mismatch → regression
- L1812: The checkpoint payload structural check (invalid-payload) precedes the authorization decision in the check-stage order
- L1859: Checkpoint signature negatives: tampered environments and flattened nested LP fail the original signature; canonicalization never produces these byte strings
- L1947: Values-digest unit vectors pin the §6.2 canonical form the same way as env-manifest.json's digests section
- L1994: Surrogate-boundary pair discriminates UTF-8 byte order from UTF-16 code-unit comparison (U+FFE5 sorts before U+1F511 only in byte order)
- L2025: ES+PF1 negatives are enumerated per the design record §3-ter's two principles: signature, structural/authorization negatives, derived chains, and the permissive side
- L2052: Old-format signed_bytes pin: an old implementation cannot verify the new chain — no compatibility path (same shape as grant-server-lease-policy-dropped)
- L2263: Principle 1 enumeration: per op and set-algebra shape, the forms where an authorization-change element falls outside the actor's scope are enumerated (§6.2)
- L2334: Environment-targeted ops (ruling E): the target environment must be in the actor's scope; create_environment is all-actors only
- L2446: Principle 2 (authorization by the signer set S) and policy monotonicity negatives are enumerated at head 24 with the policy in force
- L2505: Design record §8-ter: approval-required sits right after the role rule, before op-specific checks — pairs found unpinned by K2-8's mechanical cross-check
- L2704: Boundary pin: a first vote at timestamp = expires_at_ms exactly is valid (the expiry boundary is ≤)
- L2737: Principle 2 time-of-check: the demoted proposer's vote lapses but the proposal is not proposal-void (the proposer retains the remove_member role as admin)
- L2915: Check-order case: proposal-void is judged before the inner op's consensus rules (neither proposer nor target exists)
- L2968: Literal reading (ruling K2-11): a proposal signature made as admin does not enter S; after promotion the same person's owner approve counts and is not a duplicate
- L3027: Voter key-binding (ruling ⑤, K2-11): an S element is (user_id, key FP at signing); re-addition with different keys lapses the old vote and allows re-voting
- L3095: Flip side of ⑤: re-addition with the same key keeps the old vote alive — tenure (membership-interval) binding was explicitly not adopted (K2-11)
- L3215: Turning the policy off (required 0) also requires four-eyes; after it is off, propose is invalid
- L3238: Applied grant/revoke proposals (convention 32): widening the policy to target revoke_server is itself a four-eyes application (policy monotonicity (a))
- L3305: Key uniqueness through four-eyes (0.22-draft §6.2): a grant applied by approve names its key at the approve's seq; a pending proposal names none
- L3546: Mirror case: a grant proposed while its key was free, completed after a device took the key — the registration entry is reused byte-for-byte
- L3574: Returning-member grant clause: a grant that named a removed member's enc key keeps that key out even though the first clause lets the member back with its own keys
- L3603: DK section design: the canonical chain seq 1-24 does not change one byte; device cases live on a derived chain (extend-by-append, K2-10) with the device casting's caps spelled out
- L3650: device_fingerprints_lp_hex order is signed: generators SHOULD emit ascending, verifiers treat it as a set
- L3668: The first key of genesis / add_member is structurally cap (owner, all) (§6.2)
- L3721: Derived state with devices: an existing state omitting devices means one first key = cap (owner, all) — existing vector bytes are not changed (K2-1)
- L3817: A reader may add its own device: add_device is role-agnostic (readers allowed)
- L3927: DK authorization negatives follow the check-stage order structure → actor → signature → authorization, with §6.2 device-key reason codes
- L3980: add_device authorization check order: actor rule → duplicate-member-key → unknown-environment → device-cap-exceeded
- L4043: revoke_device authorization check order: unknown-target → unknown-device → target-dependent role rule → last-device-protected → scope-not-contained
- L4090: Effective-authority substitution: chain ops' role, containment and environment-target checks use the signing device's effective authority (§1 principle 7)
- L4216: delete_environment (0.17-draft §6.2) design: payload, role/scope rules, once-only, no later references; canonical chain and existing vectors untouched
- L4521: Precedence pin: environment-deleted precedes duplicate-server-key on a key's first grant; the old transitive pin is gone because re-grant and duplication never co-occur (§6.2)
- L4543: Op-label swap negative: delete_environment and remove_member payloads are both [one id], so the op label inside signed_bytes is the only domain separation (§6.1/§6.2)
- L4630: DK key records are keyed '<user_id>@<label>'; a verifier picks the key by the actor's (user_id, FP) — the FP points at the device (§1 principle 7)
- L4645: Chain payloads carry the real §5.2 commitment computed from the dummy DEKs, so implementation tests can check the DEK → recompute → chain-value comparison end to end
- L4675: §5.1 section design: signer_user_id in the signed bytes prevents attribution relabeling via key reuse; the wrap body is read from dek-wrap.json's basic vector
- L4824: Server recipient class (§9 / AUTH_SPEC §12-6): the server key FP takes the recipient_user_id position in signed_bytes, the same substitution as the HPKE info
- L4886: Recorded fix: signer_user_id was missing from the description's LP enumeration (signed_fields_order was correct); fixed in PR-2 per the session-12 handoff
- L4926: §5.2 section design: rewrap_invariance pins that the commitment depends on neither the recipient set nor the wrap ciphertext
- L5055: §4.1 section design: chain-state rule families reference chain-entries.json's canonical chain (cross-file precedent); the ciphertext is a real AES-GCM ciphertext so signature → decrypt is one run of concrete data
- L5174: Value positives pin the declared-head-time inclusive convention (§6.3) at the boundary
- L5222: fork-same-version (§14.3-5): two individually valid signatures on the same coordinates become equivocation evidence only as a pair, judged by the signed-bytes hash difference
- L5241: Cross-tenure derived chain: the canonical chain is unchanged; re-adding member-0002 with new keys at seq 13 makes old-key × new-interval head rejectable by §6.3-1
- L5296: Signature-family negatives: tampering/transplantation keeps the original signature over substituted signed_bytes and pins that Ed25519 verification fails
- L5389: Verification-rule negatives have valid signatures but must be rejected under §6.3's rules against a verified chain history; expected_reason pins the reason code
- L5549: 3′ scope check position: right after the role check (3) and before epoch consistency (4) (§6.3 ES)
- L5588: Device axis (DK): key selection uses the device's validity interval and 3/3′ are judged by effective authority; existing vectors' meaning is unchanged (convention 28)
- L5693: §4.2 section design: signed-bytes formulas; the name is bound byte-exact (NFC normalization is the signing client's responsibility); meta statements carry no epoch anchor
- L5731: Layout v3 (session 46 + PF6 R9): schema fields inserted right after status under a new domain string; environment meta stays v1 (§4.2)
- L5746: The retired layout v2 encoder is kept only to build the v2-layout-unsupported negative (a validly signed v2 statement the implementation must refuse)
- L5762: A context missing max_age_days is signed as if empty: the bytes are a legitimate v3 statement and rejection is the context-side shape check
- L5849: Meta positives pin the declared-head-time inclusive convention (§6.3), the create → rename → delete prev chaining, and name retention on delete
- L5910: Layout-v3 positives are added by appending — the v1 vectors do not change by one byte (§11); the retired v2 rules are re-pinned on v3 statements
- L6005: rename-fork (§14.2-5): two individually valid statements on the same coordinates become equivocation evidence only as a pair (signed-bytes hash difference)
- L6024: name-swap: the proper statements bind the name to the variable_id by signature, blocking a server relabeling names ↔ ciphertexts (§4.2)
- L6123: Signature-family negatives: tampering/transplantation keeps the original signature over substituted signed_bytes and pins that Ed25519 verification fails
- L6227: Meta rule negatives deliberately omit the epoch-family reasons: meta has no epoch consistency (§6.3-4), per §14.3-5
- L6366: Layout-v3 negatives are enumerated per §11's 0.8/0.13/0.15-draft entries, in signature, rule and structural families
- L6384: Layout confusion pins ruling CR's known residual: a false layoutVersion declaration degenerates into recomputing under the other layout = a signature mismatch (§1 principle 6)
- L6522: Structural violations are rejected with typed InvalidInput before signature or history verification (fail-closed); the signature itself is valid
- L6603: The retired v2 statement must be refused with typed UnsupportedMetaLayout before signature verification — never as an invalid signature or InvalidInput (0.15-draft §4.2)
- L6641: 3′ scope check (§6.3 ES): both variable and environment meta are environment-targeted; the check sits right after the role check (3)
- L6679: Device axis (DK): meta positives/negatives reference the derived device-ops chain; existing meaning is unchanged (convention 28)
- L6742: Deletion axis: a delete_environment is a change point of the history index — pruned scopes are pruned from its seq on (§6.2)
- L6811: §4.3 section design: manifest signed-bytes and variables-digest formulas (byte-ascending, tombstones included, empty set allowed); compound issue heads and epoch burning rules
- L6935: env-dev-0002's env meta is bundled with the creation compound (declared head = the head before the append), the binding target of the listed issuer's in-scope manifest (permissive side of 3′)
- L6955: A layout-v3 declared statement enters the manifest digest only as a new status string value; the manifest layer is unchanged (§4.3)
- L7034: Manifest positives chain by issue trigger: mv1 create → mv2 rotate → mv3 removed issuer's coordinates → mv4 variable create → mv5 rename → mv6 delete with tombstone
- L7091: Manifest fork (§14.2-5): two individually valid manifests on the same coordinates become equivocation evidence only as a pair
- L7116: Surrogate-boundary discriminants with a tombstone mixed in also pin that a non-ASCII variable_id puts status/meta_version on the canonical form
- L7159: Surrogate boundary (session-31 M1-T2): U+FFE5 < U+1F511 in UTF-8 byte order but reversed under UTF-16 code-unit comparison — the pair discriminates the implementations
- L7245: Signature-family negatives: tampering/transplantation keeps the original signature over substituted signed_bytes and pins that Ed25519 verification fails
- L7313: Manifest rule negatives: verify_entries / verify_env_meta express the form where the verifier's recomputation set disagrees with what was signed (omission, injection, hidden tombstone)
- L7510: Checkpoint-binding negatives (§4.3 (2), session 33 = PR-F3b): the old H+1 exception is abolished; comparison targets are the boundary-checkpoint derived chains
- L7575: 3′ scope check position: right after the role check (3), before prev / epoch consistency (§6.3 ES)
- L7614: Device axis (DK): manifest cases reference the derived device-ops chain; existing meaning is unchanged (convention 28)
- L7716: Boundary-checkpoint derived chains pin the mandatory bundling of create/rotate compounds; appended only, after gen_env_manifest, since they need the real manifest hashes (§4.3 (2) / AUTH_SPEC §12-4)
- L7750: The rotate boundary's values_digest is the empty set — an honest value under AUTH_SPEC §12-4 (built from the current values at acceptance time, which are none in this chain)
- L7780: A second checkpoint on the same coordinates under a different hash is valid under chain consensus but manifest verification rejects the coexistence as equivocation (§4.3 (2))
- L7852: Invite-accept regenerated as v2 (IV revision): the old token_hash-bound form is not kept; both signatures are self-binding (verify keys inside the signed data) (§6.5)
- L7879: The link seed pattern avoids 0xD4/0xD8/0xDC, which chain-entries.json's environment DEKs use (fixture non-overlap)
- L7925: The verify key is always the key declared inside the context (accept = invitee_sig_pub_hex, link = link_pub_hex)
- L7992: legacy-domain negative pins the structural rejection of the old v1 form (AUTH_SPEC §12-10 (2)): the signature is valid over the v1 byte string but fails under v2
- L8103: §6.5 invite-link design: the issue signature's verify key is inside the signed data (self-binding); the OpenSSH line interoperates with GitHub's SSH signing-key list (RFC 4253 §6.6 / RFC 8709)
- L8121: ES appends the to-be-granted scope to the end of the issue document (§6.5); the old 10-field form has no compat route (scope-dropped negative)
- L8177: Verifying a proper signature over the old 10-field form (no scope) must fail
- L8210: The issue signature also covers scope, pinning the scope of consent at issue time (ES, §6.5)
- L8313: §6.6 section design: no timestamp/nonce (attribution, not freshness; chain_head_seq orders recency); attester burning is §5.1's anti-relabeling measure; a removed member's in-tenure attestation is never a distribution target
- L8430: Signature-family negatives: keep the original signature over substituted signed_bytes and pin that Ed25519 verification fails
- L8483: Attestation rule negatives: valid signatures rejected under §6.6 / §6.3-2's rules; expected_reason pins the reason code
- L8537: Device axis (§6.6): validity at the attested-head time is judged by the device's validity interval; the referenced chain is device-ops (convention 28)
- L8597: AUDIT_SPEC §5.1 design: nullable columns are tagged byte strings (NULL = 0x00, never the same preimage as empty); payload is the stored TEXT verbatim; h values enter the LP as lowercase hex strings, pinning the uniform representation
- L8623: AUDIT_ROW_COLUMNS is AUDIT_SPEC §5.1's fixed 17-column order; None = NULL (tag 0x00)
- L8677: Row 3's non-ASCII payload pins that the stored TEXT's bytes are used verbatim — no JSON normalization (§5.1)
- L8686: Row 4 pins the NULL-vs-empty-string discriminant: non-NULL empty strings carry the 0x01 tag, unlike row 2's NULLs (§5.1)
- L8739: RFC 5869: an unspecified salt is a HashLen-byte zero string — the implementation form of §8's 'salt = empty' provision
- L8743: The master blob is treated as an opaque fixed 64 bytes because its serialization format is an implementation concern (§8)
- L8803: checkpoint-digest.json pins only the target-selection rule (active only; declared has no value coordinates; tombstones are the manifest side's) — the encoder was already pinned and chain-entries.json is unchanged (§6.2)
- L8890: recipient-sets.json design: R(E)/W(E) definitions; wrap addresses are unique by key uniqueness, though one id can name both a member and a grant (convention 33); crypto took the one definition in 2026-10-24
- L9050: The order fixture pins no order itself: its ids sort one way in UTF-16 code-unit order and the other case-insensitively, discriminating the order check in test/checks/recipient-sets.ts
- L9073: Every recipient-set fixture is a state a valid chain reaches (§6.2 key uniqueness), checked here and by verify_reference.mjs

### `packages/crypto/test-vectors/tools/regen-check.mjs`

- L1: Regen check design: comparison is parsed-JSON (formatting ignored, key order included); the scratch copy starts without generated files so a dropped vector is reported missing; the committed checkout is never written to
- L51: Key order counts in the comparison: the generators emit a fixed order and oxfmt keeps it
- L62: The scratch copy leaves the generated files out so the generator has to produce every one
- L102: Probe python3/cryptography first to fail early with a readable reason instead of a Python traceback halfway through the generator chain

### `packages/crypto/test-vectors/tools/vector-delta.mjs`

- L1: Vector-delta is a review aid that never approves anything: it prints every fact behind its conservative R0–R3 class and picks the higher class whenever a rule cannot tell
- L23: R0 canonicalization requires two independent checks to agree (token text and transpiled runtime form), so a lexer mistake can only hide a type-level edit, never a runtime one
- L175: sourceFacts counts both string case labels and op: declarations because the dispatch's written shape (constant, default branch, table) can hide a label
- L221: An op: declaration's union run is read through leading-pipe wrapping (`op:` then `| "a"` lines)
- L233: External import bindings are tracked because hpke's suite constants are how a new KEM/KDF/AEAD would arrive
- L270: Outcome keys are an explicit allow-list; every other key is data, so an unlisted key is classified upward; kind is an outcome only in a negative
- L303: Keyed fixture maps are an explicit list: structural detection cannot tell a map of records from one record with object fields, and splitting wrongly would turn a byte change into an 'added' part (a downward error)
- L356: A listed map is always split so a scalar sibling cannot flip the split, remove every member at once and hand their hex to markRebased
- L385: leafKind treats sentence-like text as prose; this hides nothing because the regeneration check pins every input to its output bytes
- L420: lpShape: suite-led encodings (§6.1 chain entries, §4 AAD) expose only suite + field count; op and payload order surface through the chain-op and field-order facts
- L457: vectorFacts keeps two layers: negatives never vouch for a surface — comparisons that could lower a class read accepted, only 'what head carries' reads all (erring upward)
- L481: Chain op keys are domain separation even though a chain entry's signed bytes begin with the bare suite (§6.1)
- L514: Retired surface is computed from shapes and suites, not domain presence alone: a retired layout's negatives keep its domain alive
- L545: A field order's identity includes its map key (the op table) but not the *_order key itself: renaming a declaration adds no encoding
- L582: Entry name references are read only through the reference keys (base / prev_base / predecessor), never from free text
- L606: The * of a name-v${layout} pattern stands for a layout number only — it covers name-v3, never name-vault or name-v2-hybrid
- L622: Python has no runtime form to compare, so only whitespace is ignored there — a comment edit in the generator counts as a logic change
- L673: markRebased: an entry is rebased when its old version referenced only removed/changed non-negative material; it cannot hide an encoding change because the unchanged vectors of that encoding would also move; removed negatives never explain a byte change
- L690: A keyed-map member is not rebase material: a rename would otherwise explain a re-key of every vector it signs
- L716: A negative built from retired material also exercised that surface when it references (by name or uncarried hex) a removed positive that exercised it
- L766: Removing a positive can only narrow; removing a negative counts as narrowing only together with the surface it exercised
- L825: grown() compares like with like (accepted vs accepted, all vs all); both halves err upward and a surviving unchanged negative adds nothing
- L917: Risk classes: R3 = encoding surface grows, R2 = surface kept but behavior moves, R1 = narrowing only, R0 = docs/prose/comment edits only; highest class wins
- L1130: Every git call runs at the repository root (ls-tree paths are relative otherwise); the root is resolved on first use, not on import
- L1174: Not transpilable means the runtime cannot be shown unchanged, so the file counts as a logic change (the conservative side)

### `packages/crypto/test-vectors/tools/vector-delta.test.mjs`

- L1: Vector-delta tests use synthetic snapshots shaped like the real files; real-history runs are the CLI's job, and the workerd/browser configs only include test/**
- L92: The test runtimeForm stand-in uses canonicalSource: comments and formatting do not reach the runtime form, anything else does
- L106: Test rationale: a regex holding a quote, misread as a division, would open a string and swallow the comment in canonicalSource
- L274: Guarded-case rationale: the rejection and the throw are both gone while the v1 shape stays accepted, so acceptance may widen
- L367: legacy-transplant carries v1 bytes but replays the removed v2 positive's signature — the case design behind markDerivedFromRetired
- L784: Regression pin: a scalar member added beside keyed records must not flip the split (every base member 'removed', their hex handed to markRebased)

### `packages/crypto/test-vectors/tools/verify_reference.mjs`

- L1: verify_reference verifies every vector with an implementation family separate from the generators, confirming both that expected values are correct and that they reproduce on the planned shipping stack
- L15: DK chain reference: a vector's chain is canonical unless named in extended_chains; the signing key is selected by (user_id, FP) — the FP points at a device
- L24: A derived chain shares the canonical prefix only up to its base_seq (environment-deleted branches at 19, inside the canonical 24)
- L64: Field order is authoritative as hardcoded from the spec; the vector JSON's declaration is only checked for agreement (a JSON-derived order could not pin the order independently — session-15 review (3))
- L72: ES: the canonical form appends scope_kind / scope_environments_lp_hex at the end; the old 4/2-field form has no compatibility path (§6.2)
- L87: grant_server canonical form is 4 fields with lease_policy_lp_hex appended at the end (0.5-draft §6.2)
- L96: Checkpoint environments are one hex-string field of the same nested LP as scope_environments (0.7-draft §6.2, PR-F3a)
- L105: DK field forms: add_device's scope is the same nested LP as member scope; revoke_device's FP list is a nested LP (0.12-draft §6.2)
- L110: delete_environment has one field; domain separation is the op name inside signed_bytes, no separate domain string (0.17-draft §6.2)
- L116: Member scopes / policy ops use the nested-LP hex form; an inner payload is the hex of the inner op's payload_bytes (§6.2)
- L124: Checkpoint environments LP definition: entry = LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex, values_digest_hex), list as one hex field (§6.2)
- L142: Checkpoint values_digest definition: entries in variable_id UTF-8 byte order under the env-values-digest domain (§6.2)
- L192: The retired v2 field order is kept only to cross-check the v2-layout-unsupported negative's signature over the retired encoding (§4.2)
- L231: The meta domain string binds the suite, the var-vs-env distinction and the layout version (§4.2)
- L294: Chain verification runs in the spec-hardcoded order; the JSON's declared field order is checked for agreement with it
- L307: The signing key is selected by the actor's (user_id, FP) — the FP points at a device (§1 principle 7); device and derived-chain keys are searched by the same rule, falling back to the person's first key
- L367: Derived-chain keys pass the same FP derivation check: picking the signing key on the declared FP alone would let a crafted override pass a forged signature
- L398: An empty lease policy encodes to the empty hex string — the form regrant-lease-policy-revised uses (§6.2)
- L412: The closed scope-kind set {all, listed} is asserted only on positives; negatives (scope-kind-unknown) are out of scope
- L432: DK: the device scope is the same nested LP as member scope; role_cap is a closed set asserted only on positives
- L445: DK: positives' revoked-FP lists have 1+ elements, no duplicates, 32 lowercase hex chars
- L479: scope_kind = all carries the empty list (hex empty string) — asserted on the canonical chain's add_member / change_role
- L487: approve / withdraw reference a proposal entry's hash; this pins that canonical seq 22 / 24 point at seq 21 / 23
- L499: DK derived-chain prefixes are byte-identical to device-ops, and add_device's public keys correspond to device entries in keys matching the actor's user_id
- L540: Environment-deletion positives name an environment created earlier on their own chain, at most once; the consensus judgment is the implementation tests' job, this pins the positive column's internal consistency (§6.2)
- L599: Zero checkpoint environment entries encode to the empty hex string (checkpoint-empty-environments)
- L615: The §5.2 commitment is recomputed from the dummy DEKs in environment_deks and matched against the published values and the chain payloads
- L647: valid_appends are the permissive-side boundary of the consensus rules (§6.2's forbidden range is the current member set only); acceptance itself is the implementation tests' job
- L671: An append's entry_bytes / entry_hash are checked to the canonical standard so a third-party implementation chaining onto that hash never silently passes a stale value (review loop 2)
- L686: An append connects immediately after the canonical entry its seq points at; a chain-qualified append connects to the derived chain's tail (ES/PF1)
- L725: Derived-chain signing keys are selected by (user_id, declared FP) across derived-chain-specific and canonical keys by the same rule
- L777: Authorization negatives are confirmed cryptographically valid here (signature, canonicalization, prev_hash); rejection by §6.2's rules is the implementation tests' job
- L799: A chain-qualified negative connects to the derived chain's tail, pinning that its prev matches the derived chain's last entry
- L841: The wrap body is identical to dek-wrap.json's basic vector — one continuous run of real data (§5.1)
- L849: Server recipient class (§9 / §12-6): the recipient position is the server key FP and the wrap body is identical to server-basic
- L895: The signed field order is authoritative as hardcoded from the spec (same discipline as dek-wrap-sig)
- L907: The accepter's declared keys match the invitee block — signer = invitee self-binding (§6.5)
- L915: The link public key is derivable from the seed via PKCS#8 because WebCrypto has no standalone Ed25519 seed import (RFC 8410 prefix + seed, read the JWK x)
- L967: Pins that the verification key is always the declared key inside the signed payload (§6.5 self-binding)
- L977: Pins both halves: the signature is valid in the old v1 format and does not pass over a byte string rebuilt with the v2 domain
- L1021: ES: the to-be-granted scope (same encoding as §6.2) is appended at the end of the issue signed bytes
- L1070: The flat-concatenation encoding kind: canonicalization never produces this byte string and a canonical signature fails over it
- L1143: The DEK and coordinates are identical to dek-wrap.json's basic — wrap → §5.2 comparison is one continuous run of real data
- L1335: Rule-kind negatives are confirmed cryptographically valid here; rejection via expected_reason is the implementation tests' job (§6.3)
- L1371: Verification runs in the spec-hardcoded order; the JSON declaration is checked for agreement with it
- L1389: The context's layout_version (omitted = 1) carries the layout selection (§4.2 ruling CR)
- L1402: A v3 context missing max_age_days is signed as the empty declaration: the bytes are a legitimate v3 statement and the rejection is the context's shape, not the signature
- L1459: An environment statement is active only (§4.2 — deletion is the chain op delete_environment); the retired form is pinned as an invalid-input negative
- L1477: A deletion statement retains the name of the immediately preceding active statement (§4.2 — deletion does not empty the name)
- L1506: name-swap: a byte string with only the name field swapped fails the original signature (§4.2)
- L1574: Rule, structural and unsupported-layout kinds are confirmed cryptographically valid, guaranteeing the rejection is not a cryptographic verification failure
- L1604: Layout v3 checks pin the declared → activation linkage, the legitimate v1 → v3 upgrade direction, verbatim schema fields on a v3 deletion, and the refused shapes (§4.2)
- L1666: nfc-variant pins that the NFD variant of a name signed in NFC canonical form produces a different byte string
- L1686: Verification runs in the spec-hardcoded order; the JSON declaration is checked for agreement with it (§4.3)
- L1767: Digest recomputation (§4.3 (3)): entries are the canonical form of the set the manifest signed
- L1807: The manifest digest includes tombstones (§4.3): manifest-var-delete includes the deleted entry in the enumeration
- L1836: Rule-kind negatives are confirmed cryptographically valid here; rejection via expected_reason is the implementation tests' job (§6.3)
- L1850: The digest kind pins omissions, tombstone hiding and order violations: recomputation over the verifier-side set does not match the signed digest
- L1887: The audit-head column order is authoritative as hardcoded from AUDIT_SPEC §5.1; the JSON declaration is checked for agreement
- L2011: Open by passing a KeyPair is the standard route (§2 — compatible with non-extractable keys); the key pair is resolved per recipient class
- L2073: Lease-wrap verification design: the generate/verify cross-check plus independent claims-digest recomputation and the dek-wrap server-basic inheritance (§9.1)
- L2088: Open by passing a KeyPair (§2 — compatible with non-extractable keys)
- L2118: The coordinates/DEK inheritance is a concrete-data expression of §9.1's 'the server is the DEK's intermediary'
- L2133: info is reassembled from the spec's field order, not the vector declaration (a JSON-derived order could not pin the order independently — session-15 review (3))
- L2166: Sealed-value verification design: the cross-check plus spec-order info, inheritance of dek-wrap basic's key/coordinates, and a proposal id shared across positives (§5.3)
- L2247: checkpoint-digest pins the §6.2 selection only (declared excluded, 0.8-draft); the encoder's canonical form is already pinned by chain-entries.json
- L2271: declared / deleted variables carry no value coordinates (version / value_sig_hash_hex) (§6.2)
- L2305: Recipient-sets verification design: sets are recomputed by the set-builder definitions (no effective-permission code), FPs re-derived, fixtures checked to be valid-chain-reachable, lists compared as sets (§6.2/§5.3)
- L2360: Key uniqueness check: no two devices share an enc or sig key and no device holds a grant's enc key (§6.2)
- L2417: The fingerprint-named case's premise is checked: a member named by server-z's fingerprint has a device whose key is its own
- L2433: Master-key-wrap verification design: B and user_id inherited from recovery-wrap.json, AAD/info/request_id in spec field order, all-mode XOR returns the KEK, handoff code recomputed independently (§8)
- L2589: DK: handoff approvers are guardians only (handoff-device was removed)
- L2607: DK: the old-device approval was removed — the wrap kind set is closed to {passkey-prf, guardian} (§8)
- L2622: Handoff code decoding checks length, alphabet, zero padding and checksum — all of them

### `packages/crypto/test/all-checks.ts`

- L1: all-checks is the shared entry point for vitest (node/workerd/browser) and direct Bun execution; checks are added here as each layer's implementation progresses
- L33: MIN_TOTAL_CHECKS is a floor detecting check groups silently dropping out; a change that deliberately reduces checks lowers it in the same change
- L38: The floor must stay close to the population (it once sat at 1699 against 2774 checks) or a dropped group hides in the slack; outgrowing the slack fraction forces raising the floor
- L45: Check layers are mutually independent but run serially so concurrent WebCrypto calls do not obscure which one failed

### `packages/crypto/test/checks/audit-head.ts`

- L1: Audit-head checks scope: vector reproduction, the NULL vs empty-string preimage difference, and invalid-input rejections pinned on the harness side under convention 21 (AUDIT_SPEC §5.1)
- L150: MAX_SAFE_INTEGER itself is accepted — the flip side of the §2.1 numeric boundary

### `packages/crypto/test/checks/chain-history.ts`

- L1: Chain-history checks pin seq → entry hash, member/environment state at the declared head (inclusive) and tenure separation (§6.3 / ruling A)
- L63: Checkpoint-boundary derived chains serve as the comparison chains for checkpoint-bound manifest verification (§4.3 (2))
- L117: Inclusive-convention pin: the owner is valid at genesis's own seq (§6.3)
- L119: Inclusive-convention pin: the target is valid at add_member's own seq and not yet a member at seq 1 (§6.3)
- L127: Inclusive-convention pin: the target is invalid at remove_member's own seq, valid up to the preceding seq (§6.3)
- L143: The device at membership start is the single first key, whose cap is structurally (owner, all) (§6.2)
- L162: Point-in-time device lookup: the same key is valid only inside its membership interval (§6.3-1)
- L182: Inclusive-convention pin: the new role is valid at change_role's own seq (§6.3)
- L210: Inclusive-convention pin: seq 13 joins as member of listed{dev} (§6.3)
- L220: Inclusive-convention pin: the seq 17 scope widening is valid at its own seq (§6.3)
- L233: Application via proposal (PF1): the change point is the seq of the approve entry that reaches quorum (inclusive)
- L254: Inclusive-convention pin: epoch 1 is valid at create_environment's own seq; the environment does not exist at the preceding seq (§6.3)
- L265: Inclusive-convention pin: the new epoch is valid at rotate_epoch's own seq (§6.3)
- L322: Tenure separation: remove → re-add is a separate tenure — the old interval keeps the old key, the new interval binds the new key
- L341: An old-interval key × a new-interval head is not a valid device (crossing tenures — §6.3-1)
- L368: DK checks are pinned against the derived chain device-ops (base 24, seq 25-37 — convention 28): device validity intervals and effective permission (§6.2/§6.3)
- L390: Inclusive-convention pin: a device is valid at its add_device seq (§6.2)
- L405: Inclusive-convention pin: a device is invalid at its revoke_device seq; the person stays a member and the first key remains (§6.2)
- L417: A revoked device's key still resolves by FP — key selection spans all intervals (§6.3-1); validity is deviceStateAt's job
- L433: The phone's cap is (owner, listed{}); effective permission = (min(person role, role_cap), person scope ∩ device scope) (§3)
- L457: The first key's effective permission equals the person's permission — cap (owner, all) means uncapped
- L472: The history index must agree with the verified state at the head (roles, scopes, device caps, deletion seqs, checkpoint baselines) — the invariant delete_environment pruning must keep (§6.2)
- L525: delete_environment as a change point on a member scope: the listed scope is pruned from the deletion's own seq (inclusive), earlier intervals unchanged, an all scope gets no new interval (§6.2)
- L563: The same delete_environment pruning applies to a device cap (CI box C's (member, listed{dev, stage}) cap) (§6.2)

### `packages/crypto/test/checks/chain-negative.ts`

- L1: Chain-negative checks scope (§6): tampering/transplant/reorder must-fail vectors, authorization vectors with valid signatures, and the permissive-side boundaries (valid_appends)
- L60: Harness convention: vector-fixed keys — a missing key is fixture corruption and throws (same convention as entryAt)
- L77: Harness convention: the vector entry of the expected op — a mismatch is fixture corruption and throws
- L86: Harness convention: the expected-op entry of a derived chain — a mismatch/missing entry is fixture corruption and throws
- L115: Harness convention: the vector's (environment, epoch) commitment — a missing one is fixture corruption and throws
- L159: The deleted environment is signed — a server cannot redirect a deletion (§6.2)
- L180: The device cap (role_cap / scope) is signed — it guards against relabeling the cap
- L196: The order of a device scope's nested LP is also signed (same shape as add_member's scope)
- L210: The registered device key is signed — it guards against a server swapping the key
- L218: The revocation FP list's order is also signed (generators SHOULD emit ascending; verification is set-based)
- L259: The order of scope_environments is also signed (nested LP — same shape as grant_server's scope)
- L272: Relabeling scope_kind (listed{dev} → all) relabels the granted range and fails the signature
- L293: The order of the policy ops is also signed (generators SHOULD emit ascending; verification is set-based)
- L305: A propose's inner payload (inner_payload_lp_hex) and expiry are signed
- L361: The order of lease_policy (elements and constraints) is also signed (§6.2)
- L399: dek_commitment_hex is also signed (§5.2): substitution fails verification
- L434: Coverage guard: when vector regeneration adds negatives, every new name must belong to the covered set so the name-hardcoded checks do not silently drop newcomers
- L441: The negative kind vocabulary is pinned to two values (undefined / authorization); a third kind would quietly escape both coverage sieves
- L517: Bytes-level negatives catalogue: byte strings this implementation cannot produce — flat concats, dropped-field old forms (pinning the new form as canonical, no compatibility acceptance), and inner-payload splicing (§6.2)
- L543: A deletion's bytes relabeled as remove_member or under another suite: the op name is the domain separation (§6.2)
- L583: Checkpoint tamper check design: the canonical 12 entries contain no checkpoint op, so the base entry is pulled via the vector's chain field (derived-chain counterpart of payloadTamperVariants)
- L627: Authorization kind: signature and chaining are valid; the entry must be rejected only by §6.2's authorization rules
- L644: Extended chains pin derived state: grant key-naming timing (§6.2), legitimate re-notarization at the same manifest_version, and four-eyes vote re-tallying (departed voters' votes are not counted — principle 2)
- L667: Named server keys semantics: seq 9's key stays named after its grant's revocation at seq 12, a pending grant proposal names none, and an applying approve names its key (§6.2)
- L786: The dummy commitment is formally valid: its content is the §5.2 comparison target; chain verification checks form only
- L828: Check-order pin (§6.2): when both target user_id and key are duplicates, duplicate-member is judged before duplicate-member-key
- L905: Checkpoints match: vectors without expected_checkpoints pass as out of scope (§6.2 derived state)
- L980: A valid append's attach point is right after the canonical (or derived-chain) entry its seq points to — seq 25 = terminal head, seq 10 = the seq-9 head, seq 20 = head 19
- L999: Permissive-side boundaries pinned by valid_appends: (1) key uniqueness counts devices only while current and server keys only once named, (2) environment lifecycle acceptance, (3) ES/PF1 in-scope and post-policy appends
- L1020: Index re-formation: once a re-add returns a key to the current member set, the same key under a different user_id is duplicate-member-key again — closing both directions
- L1140: A malicious/corrupt entry whose runtime types diverge from the TS types becomes invalid-payload, not an exception (verifier contract)
- L1155: The dummy signatureHex must be shape-valid (64-byte): a shorter value would short-circuit every malformed case at the signature-length check and stop testing the intended fields
- L1469: Unknown-op case pins the public verifier's contract: invalid input returns invalid-payload and never throws (defense-in-depth against the PAYLOAD_SHAPES lookup)
- L1501: A scope-widening re-grant (old ⊆ new) is accepted and the scope updated; the narrowing rejection is pinned by the authz-grant-scope-narrowed vector
- L1539: Two-layer rule independence: even a re-grant touching only the scope replaces lease_policy with the new payload's value
- L1546: Field size limit boundary (§6.1): exactly 1024 bytes is accepted; the limit is judged by byte count
- L1576: The multibyte case pins that the field limit is byte-based: 342 code units of a 3-byte character = 1026 bytes is rejected
- L1608: grant_server / remove_member become policy targets at seq 20 (approval-required precedes, right after role), so op-specific reasons are checked by appending onto the pre-policy head 19

### `packages/crypto/test/checks/chain-op-coverage.ts`

- L1: Chain op coverage design (§6.1/§6.2): (1) declared field order and implementation encoding are one, and swapping any two fields breaks some positive payload; (2) every op has an accepted positive; (3) applied-proposal coverage is derived from the verifier, not the vector's prose
- L80: APPLIED_PROPOSAL_GAPS is empty: every four-eyes target op has an applied-proposal positive; a future gap must be listed here with a justification and a covered entry fails as stale
- L226: Unpinned field pairs: pairs no positive payload tells apart (swapping still re-encodes every sample) are the part of the order the vectors do not pin

### `packages/crypto/test/checks/chain-vector.ts`

- L75: grant_seq is the seq of the entry that established the active grant; it advances on re-grant (§6.3 / AUDIT_SPEC §3.5)
- L94: Expected device state is FP → cap + added seq — the §6.2 verification state (DK)
- L101: Omitting devices in an expected member state means 'only the first key (cap (owner, all))' (convention 28 — existing expectations unchanged)
- L127: Approve vote signatures are (user_id, key FP) pairs — the 2026-09-15 ruling ⑤ key binding of votes
- L145: Deleted environments map to the delete_environment seq (§6.2); an absent expectation means none deleted
- L162: Environment-deletion chains carry the environment set, deletions and grants as expectations (§6.2)
- L196: Device-set match convention (§6.2 DK): an expectation without devices requires only 'one device, cap (owner, all)' and the added seq is not checked
- L315: The derived active-grant set match includes scope + lease_policy (§6.2); shared by chain.ts / chain-negative.ts
- L333: lease_policy is part of the derived state and is matched including order (as-signed order) (§6.2)
- L359: Key record convention: a device key's record key is '<user_id>@<label>' (DK, convention 28); the signer is selected by (user_id, FP)
- L371: The key fingerprint is computed by the reference generator from the two public keys — the vectors are the tests' trust boundary
- L377: vectorKeyFor selects the signing key by (user_id, key FP) across top-level and derived-chain keys — signers are identified per device (§6.2)
- L410: The dummy DEKs carry actually computed §5.2 commitments per (environment, epoch)
- L425: The scope fields are the last two fields of add_member / change_role payloads (§6.2)
- L438: The conversion table replaces a high-cyclomatic switch — the same shape as the implementation's PAYLOAD_SHAPES / OPERATION_APPLIERS
- L533: A propose's inner op is decoded recursively via the same conversion table (§6.2 PF1)
- L560: revoke_device's FP list is carried in signature order (§6.2 DK)
- L582: decodeInner carries a structural negative's raw payload as-is so the subject under test is the implementation's structural check landing it on invalid-payload without throwing
- L623: importVectorSigner is the shared preamble of the 4 signature harnesses (value / meta / manifest / attestation); returns null when the key is missing or import fails

### `packages/crypto/test/checks/chain.ts`

- L1: Chain checks scope (§6 positives): canonical byte strings, deterministic signatures, hash chaining, verification and state derivation
- L32: Appended entries of valid_appends / extended_chains pin canonicalization to the same level — the checkpoint op never appears in the canonical chain, so an appended entry's byte equality is its only direct pin
- L66: WebCrypto Ed25519 is RFC 8032 deterministic, so re-signing with the vector's seed must match signature_hex exactly — pinning canonicalization and signing together; device keys are chosen by (user_id, FP)
- L140: The environment set is chain-derived (§6.2): no environment absent from the expectation may be derived — there is no 'initial value 1 if unobserved' default
- L166: Each expected_head_states point is verified by prefix verification — the basis of incremental sync

### `packages/crypto/test/checks/checkpoint-digest.ts`

- L1: checkpoint-digest checks pin only the subject-selection rule of selectEnvValuesDigestEntries; the LP canonical form is already pinned by chain-entries.json's values_digests (§6.2)
- L76: An environment with only declared variables has the empty-set digest — the boundary form of 'declared does not appear in values_digest' (§6.2)

### `packages/crypto/test/checks/checkpoint.ts`

- L1: Checkpoint checks design: equivocation downgrade per ruling B — a difference in (epoch, manifest_sig_hash) is conflicting, a values_digest difference is a legitimate re-attestation; the rejection side is pinned in chain-negative.ts (§6.2)
- L58: The digest normalizes to the canonical form regardless of input order (byte-ascending is the function's internal convention)
- L69: A duplicate variable_id violates the invariant 'one latest version per active variable'
- L94: MAX_SAFE_INTEGER + 1 is the float64 precision-loss range where decimal stringification is not unique (§2.1)
- L141: (env-prod, 2) carried by two entries with the same (epoch, manifest_sig_hash) stays unique with seq = first occurrence — a values_digest-only difference is a legitimate re-attestation
- L185: Equivocation downgrade (ruling B): the append is valid under consensus rules, but the history lookup falls to conflicting and becomes the material manifest verification (§4.3 (2)) rejects as hard evidence
- L248: Consistency invariant: latestCheckpointFor mirrors ChainState.checkpoints between derived state and history index

### `packages/crypto/test/checks/dek-commitment.ts`

- L1: Dek-commitment checks additionally pin the cross-check against chain-entries.json's environment_deks and re-wrap invariance at implementation level (§5.2)
- L70: The uppercase-hex negative is reinterpreted as pinning that this implementation cannot generate an uppercase-hex preimage (encodeHex is the only generation point)
- L130: Re-wrap invariance (§5.2): re-wrapping the same DEK to a new recipient (backfill / repair — Seal is randomized) still verifies against the same commitment
- L165: The new wrap's ciphertext differs from the vector's (Seal randomness) yet commitment verification succeeds — the preimage has no wrap-related fields

### `packages/crypto/test/checks/dek-wrap-signature.ts`

- L1: Dek-wrap-signature checks design: negatives pin that the implementation's canonicalization reproduces the vector's verify-side byte string and the original signature then fails (tampering, transplants, key/suite mismatch) (§5.1)
- L64: Positives cover both the member class and the server class (server key FP in the recipient position, §5.1/§9); deterministic Ed25519 makes the sign direction match exactly

### `packages/crypto/test/checks/dek-wrap.ts`

- L1: Dek-wrap checks design: panva hpke cannot derandomize a single-shot Seal (spike-c), so fixed vectors are verified in the Open direction and Seal is covered by round-trip; RFC 9180 vectors live in rfc9180.ts (§5)
- L37: Recipient class server (§9): the recipient position of info holds the server key FP
- L127: The implementation recomputes FP = SHA-256(server_enc_pub)[:16] and the FP-in-recipient-position construction matches the vector (§9)
- L157: The server vector wraps the same DEK as basic — one DEK × multiple recipient classes, the §7 complete wrap set shape
- L249: A non-(non-negative safe integer) epoch returns InvalidInput rather than throwing

### `packages/crypto/test/checks/encoding.ts`

- L21: Numbers produce the same byte string as their decimal stringification (§2.1)
- L27: Numeric bounds (§2.1): non-integers, MAX_SAFE_INTEGER + 1 (precision-loss region) and negatives are rejected with TypeError — the split keeping this out of the JSON vectors is the session-34.md ruling
- L41: MAX_SAFE_INTEGER itself has a unique decimal stringification and is accepted (inside the §2.1 bound)

### `packages/crypto/test/checks/env-manifest.ts`

- L1: Env-manifest checks design (§4.3): digest canonical form, checkpoint-binding epoch consistency (composite positives pass on boundary chains, same data rejected on the canonical chain), and epoch-regression as the core predecessor negative
- L188: The variables digest normalizes to canonical form regardless of input order (byte-ascending is the function's internal convention)
- L199: A duplicate variable_id violates the 'one latest form per variable' invariant = InvalidInput (§4.3)
- L216: The surrogate-boundary vector is the only meta-check of ruling G (session-34.md): a missing vector is a failure, not a skip — no shape where a rename or deletion stays green with fewer PASSes
- L237: Numeric/hex boundary rejection (session-34 ruling): same-length uppercase hex is rejected because an accept-and-lowercase implementation would create multiple canonical forms for one value
- L300: The two composite-issuance positives are verified under checkpoint binding (§4.3 (2)) against the boundary-checkpoint derived chains; everything else uses the canonical chain (strict — no tuples)
- L386: Fork branches each pass all checks on their own — prevention is impossible; the point is the evidence recording of §14.2-5
- L421: Reason-space exhaustiveness: the MANIFEST_REASON_COVERAGE Record enforces sync with the reason union at compile time (consideration 7)
- L529: The negative kind vocabulary is pinned — a third value would escape both sieves
- L592: The version-prev coupling check is signing-side only; the verify side instead rejects asymmetrically with a reason code (same shape as meta-sign)
- L648: A false attestation whose tuple epoch contradicts the manifest content cannot be expressed by vectors, so it is pinned with a runtime-signed chain: an implementation comparing only hashes fails here (§4.3 (2))
- L658: False-attestation material: the checkpoint's tuple epoch matches the epoch current at entry time (2), so the chain itself is valid under consensus rules

### `packages/crypto/test/checks/fingerprint-words.ts`

- L1: Fingerprint-words checks design (§3): 3-layer wordlist integrity (upstream hash pin, official BIP39 vectors, structural invariants) plus server FP word sequences from a third independent implementation (python-mnemonic) — the §9 grant ceremony comparison target
- L89: BIP39 property: the first 4 letters uniquely determine a word — the basis of error tolerance in verbal comparison

### `packages/crypto/test/checks/head-attestation.ts`

- L1: Head-attestation checks design (§6.6): removed-attester-in-tenure is positive but the distribution gate is the implementation test's responsibility; the role floor is reader; chain-head-mismatch is the hard-evidence entry — only the reason code is pinned here
- L161: Distribution-gate material pin (§6.6 (1) first half): the removed attester passes verification but is not a current member
- L242: The negative kind vocabulary is pinned — introducing a third value would slip past both sieves

### `packages/crypto/test/checks/invite-accept-signature.ts`

- L1: Invite-accept checks design (§6.5 v2): the verification key is derived by the implementation from the declared key inside the signed material (self-binding) — there is no path to pass a key from outside
- L112: Negatives pin (1) canonicalization reproduction of the verify-side byte string, (2) the declared key inside the signed material as the verification key, (3) failure with InviteAcceptSignatureInvalid; only legacy-domain's reproduction must differ (always v2)
- L237: Swapping the declared key to another key fails verification — self-binding: a signing/declared key mismatch does not pass (§6.5)

### `packages/crypto/test/checks/invite-link.ts`

- L1: Invite-link checks design (§6.5): OpenSSH parsing decodes third-party data (GitHub responses), so its acceptance boundary (type, key length, in-blob type, extra bytes, base64) is pinned with vectors
- L142: Negative kind semantics: 'encoding' = a byte string this implementation would never produce (legacy form, flattened); unspecified = tampering / transplant
- L177: Encoding-family negatives pin that canonicalization does not produce the vector's byte string and there is no compat-acceptance path (README convention 27)
- L224: The scope structural rules are the same as §6.2: all ⇒ empty list, no duplicates, closed-set kind, non-empty id
- L253: The scope id bound is 1024 bytes (§6.1) — symmetric to add_member on the chain side
- L298: Transplanting the issue text to a different invite id fails verification — the server cannot transplant it to another row (§6.5)
- L304: Ghost-adder shape: even with the declared key set to the inviter's public key, a signature by another key does not pass (§6.5)

### `packages/crypto/test/checks/keys.ts`

- L1: Keys checks scope (§3): fingerprints are pinned by the keys / server_key of chain-entries.json
- L64: RFC 9180 DeriveKeyPair cross-check: the same ikm derives the same public key as dek-wrap.json's hpke-js server keypair — pinning the 'one secret → keypair' deployment path (§9)
- L80: Non-extractable is the default (the server-side operational posture): exporting the derived private key is KeyExportFailed
- L148: A functional check pins the exported private key's correctness (public key equality would be a trivial restore of the input) — the CLI's OS keychain path (§3)

### `packages/crypto/test/checks/lease-wrap.ts`

- L1: Lease-wrap checks layout (§9.1): fixed vectors verified in the Open direction, Seal by roundtrip — panva cannot derandomize a one-shot Seal (spike-c finding)
- L67: claims_digest pin (§9.1): two contexts sharing issuer/audience but differing in subject produce different digests — the basis of the binding preventing lease-response reuse by another job
- L91: Empty claim fields are InvalidInput: allowing empty could collapse different contexts into the same digest (§9.1)
- L121: Coordinates and DEK are inherited from dek-wrap.json's server-basic (§9.1: the server only opens its own wrap and re-wraps — it creates neither values nor DEKs)
- L133: The DEK is independent per epoch (a single lease response carries multiple epochs — AUTH_SPEC §14-2)
- L150: A domain-substitution negative only gets the info match checked: the implementation's LeaseWrapContext cannot swap the domain (fixed by the type); the Open failure is pinned by verify_reference.mjs
- L199: Domain separation from the §5 wrap is pinned via the dek-wrap-side info builder because the lease API cannot swap the domain
- L227: claims_digest accepts only 64-char lowercase hex: it rules out passing raw claims by mistake and uppercase-hex drift producing 'same digest, different info'
- L282: Open fails under a different claims_digest — a lease response cannot be reused in another workload context (§9.1)
- L297: Open fails with a different ephemeral key: once the key disappears at job end, the response is worthless (§9.1)

### `packages/crypto/test/checks/manifest-history.ts`

- L1: manifest-history is built from env-manifest.json's own tenure_extension entries for the self-containedness of the manifest vectors, so the checked target does not drift if the files diverge (same judgment as meta-history.ts)

### `packages/crypto/test/checks/master-key-wrap.ts`

- L1: Master-key-wrap checks layout (§8 KL3): fixed vectors verified in the Open direction, Seal by roundtrip; the recovery-code path is unchanged and still lives in checks/recovery.ts
- L159: B and user_id are inherited from recovery-wrap.json — the ledger is the set of wraps of the same B (§8)
- L275: Only a guardian may approve a handoff (DK — the old-device approval handoff-device was removed from §8.4)
- L317: The kind-axis substitution is rebuilt on a guardian base (DK, 2026-09-20) because device left the kind set; mode is a guardian-only field, so a passkey-prf context carrying one would be InvalidInput
- L336: suite-mismatch: the implementation API cannot swap the domain string (fixed by the type); only the expected AAD bytes are checked here and the decryption failure is pinned by verify_reference.mjs
- L371: share-missing: joinGuardianShares rejects an insufficient segment count as InvalidInput first; a KEK assembled with a faked segment count fails decryption (§8.3)
- L483: Handoff code characters outside the alphabet (0 / 1 / 8 / 9) are rejected rather than guessed-substituted (§8.4)
- L666: Any 2 segments of an all-mode split are independent of the KEK: their XOR does not equal the KEK (§8.3)
- L715: A different ephemeral key cannot open a handoff approval — once the requester process ends, the approval is worthless (§8.4)

### `packages/crypto/test/checks/meta-history.ts`

- L1: meta-history is built from metadata-signature.json's own tenure_extension entries for the metadata vectors' self-containedness, so the checked target does not drift if the two files diverge

### `packages/crypto/test/checks/metadata-signature.ts`

- L1: Metadata checks design (§4.2): var-meta-head-before-env-create is a positive (no epoch anchor — an intentional asymmetry, §14.3-5 / AUTH_SPEC §12-4); revive-after-delete and the retired v2's pre-verification refusal are pinned
- L132: The schema fields exist as one set (§4.2); max_age_days rides only when the vector has the key — its absence is the v3-missing-max-age shape negative, and the cast carries that wire shape into the implementation, whose validation must refuse it
- L182: layoutVersion is required on the MetaPredecessor side (fail-closed); a vector omission means v1
- L275: A v3 deletion fully retains the schema fields (max_age_days included) and the layout from the previous statement, under the same convention as the name (§4.2 layout v3)
- L304: Fork branches each pass all checks on their own — prevention is impossible; the point is the evidence recording of §14.2-5
- L318: Each name-swap statement verifies on its own — the name ↔ ID binding is carried by the signature (§4.2)
- L348: Reason-space exhaustiveness: the META_REASON_COVERAGE Record enforces compile-time sync with the union, so a new rejection rule without a negative is caught by type + test
- L434: Structural negatives (kind = invalid-input) are rejected with InvalidInput before signature verification is reached (ruling CS) — the signature is valid, confirmed by the reference implementation (§4.2)
- L444: The encoder is total over field values (it refuses only an unselectable layout), so it also reproduces the structural negatives' signed_bytes
- L478: Retired-layout negatives: every entry point refuses the v2 statement with typed UnsupportedMetaLayout before signature verification; the builder's refusal proves it never falls back to the v1 encoding (§4.2)
- L554: The negative kind vocabulary is pinned — a third value would escape every sieve
- L612: Signing-side-only checks (non-empty prev on metaVersion 1, deleted on metaVersion 1): the verify side instead rejects asymmetrically with a reason code (§4.2)
- L643: Layout-dependent structural violations are the split of duties not expressed as JSON vectors (schema fields on v1, missing schema on v3, closed-set violation, v3 on environment meta) (§4.2)
- L695: Layout selection (ruling CR, convention-21 split): an unsupported layoutVersion is rejected with UnsupportedMetaLayout before signature verification — an honest failure mode, not collapsed into invalid signature or InvalidInput; explicit 1 ≡ omitted
- L710: The supported set is {1, 3}: the retired 2 and the first future 4 are both unsupported
- L722: The layout rejection never even reaches signing-key resolution — pinned by passing an FP that does not exist in the history
- L752: Structural violations of layoutVersion (0 / non-integer) are InvalidInput — a broken wire form, not version negotiation
- L765: An explicit layoutVersion 1 is equivalent to omitted (§4.2 — omitted = 1)
- L782: Layout field-set rule (§4.2): a context whose fields do not match its declared layout selects no layout, so every entry point refuses it with the same InvalidInput and the builder never encodes it under the other layout (convention 21 split)
- L851: Layout selection precedes field-value validation: a context failing both reports the layout (parse the layout, then validate and encode under it)
- L867: Domain-separation property check (§4.2): v1/v3 signed_bytes of the same coordinate must always differ — generative, so an implementation dropping the domain string cannot fake it; a degenerate all-empty v3 must still not collide (separation rests on the domain tag)
- L896: Degenerate case: even with all schema fields empty, the domain tag prevents collision with v1 (the encoder is total over field values)
- L914: Any successor of a deleted predecessor is rejected regardless of status (§4.2 — a tombstone is terminal)
- L930: deleted → deleted (overwriting a deletion) is also rejected as revived-after-delete (§4.2)

### `packages/crypto/test/checks/recipient-sets.ts`

- L1: Recipient-set checks: the sets match the vectors, deviceReceivesEnvironment agrees with R(E) on every device, W(E) ⊆ R(E), and both lists come in the documented order whatever order the state's maps were built in — the vectors pin the sets only, the order is pinned here (§6.2/§5.3)
- L93: Fixture state construction: reversed insertion checks the lists do not follow the maps' insertion order; the sets read no seq and no lease policy, so those are fixed placeholders
- L180: The documented recipient order: members before server keys, then by user id and device fingerprint, or by server fingerprint (§6.2)

### `packages/crypto/test/checks/recovery.ts`

- L1: Recovery checks (§8): the KEK derivation (salt = empty) is implicitly pinned by the vector ciphertext's successful decryption; the wrong-salt case fails with the vector's decrypt_kek_hex
- L30: Unwrapping the fixed vector implicitly pins the KEK derivation with salt = empty (§8)
- L65: wrong-salt: the implementation API cannot inject a salt by design, so the KEK derived from a non-empty salt is checked directly with WebCrypto (§8)

### `packages/crypto/test/checks/rfc9180.ts`

- L1: RFC 9180 header (§11): the adopted panva hpke is verified directly against the official vectors — DeriveKeyPair match + Open-direction match, since panva cannot derandomize the Seal direction

### `packages/crypto/test/checks/sealed-value.ts`

- L1: Sealed-value checks layout (§5.3): fixed vectors (hpke-js ekm derandomize) verified in the Open direction, Seal by roundtrip — panva cannot derandomize a one-shot Seal (spike-c finding)
- L78: Recipient and coordinates are inherited from dek-wrap.json's basic (§5.3: W(E) ⊆ R(E) — the same device key receives both the DEK wrap and sealed values)
- L110: The domain-substitution negative cannot be built through the typed context (domain fixed by the type) — only the info byte string is matched here; the Open failure is pinned by verify_reference.mjs
- L164: Domain separation from the §5 persistent wrap is pinned by assembling §5's domain over the §5.3 fields (the generator's shape); the Open failure is pinned by verify_reference.mjs
- L206: A proposal id outside the 32-lowercase-hex form is InvalidInput — an uppercase id would make 'the same proposal, a different info'

### `packages/crypto/test/checks/support.ts`

- L1: Check infrastructure is environment-independent by design: the same checks are invoked from vitest (node / workerd / browser) and from direct Bun execution (test/run-in-bun.ts)
- L35: expectRejectedReason design (viewpoint 7 — exhaustive pinning of the reason space): shared by the negative sieves of meta / value / manifest; the caller pre-narrows the reason because the kind unions differ per layer
- L58: Reason coverage (viewpoint 7): the coverage Record forces compile-time sync with the reason union, catching 'implemented a new rejection rule but there is no negative case' via type + test

### `packages/crypto/test/checks/value-signature.ts`

- L1: Value-signature header (§4.1): Ed25519 is RFC 8032 deterministic so the signing direction is verified byte-for-byte; authorization-kind negatives pin 'valid signature rejected by §6.3 history verification with expected_reason' via verifyDistributedValue
- L203: Fork branches each pass all checks on their own — prevention is impossible; the point is the evidence recording of §14.2-5
- L218: Reason-space exhaustiveness pin (consideration 7): the VALUE_REASON_COVERAGE Record enforces compile-time sync with the union, same shape as META_REASON_COVERAGE
- L316: The negative kind vocabulary is pinned — a third value would escape both sieves
- L392: Signing-side-only check: never sign a version 1 with a non-empty prev; the verify side instead rejects asymmetrically with the reason code 'valid signature + prev-shape-mismatch'

### `packages/crypto/test/checks/variable.ts`

- L1: Variable header (§4): there is no fixed-nonce encryption API (nonce reuse is structurally impossible), so the fixed vector is verified in the decrypt direction — GCM determinism also guarantees encrypt-direction equivalence
- L93: A numeric context field failing the LP encoder's precondition returns a CryptoResult of InvalidInput rather than throwing (both encrypt and decrypt)
- L149: Nonce check rationale (§4 / §11): nonces are randomly generated and reuse is forbidden — repeated encryption of the same input must produce no duplicate nonce and differing ciphertexts

### `packages/crypto/test/checks/vector-inventory.ts`

- L1: Vector inventory design: the case-name sets are duplicated into test code and pinned fail-closed because iterating the JSON's own vectors would let a deletion/rename silently shrink the checked set; JSON-side metadata is deliberately not added (a declaration could be modified along with the data)
- L1088: The chain-dependency classification (§11 / README convention 27, es-design.md §8 K2-11-bis) is mechanically enforced and pinned in code rather than prose — §11's prose once miscounted head-attestation.json as invariant

### `packages/crypto/test/run-in-bun.ts`

- L1: run-in-bun rationale (§11): vitest runs on Node, so Bun — the CLI's runtime environment — is verified by direct execution of the same checks

### `packages/crypto/test/support/fixture.ts`

- L1: Fixture core design: shared by the cli / server test supports and uses only @maruhi/crypto's public API; the two sides source keys differently (cli generated / server vector-pinned), so the caller injects the chain-signing means as signEntry
- L40: testUserId is a test-only mint: the package itself never mints a UserId (production goes through UserIdSchema in @maruhi/core); test data is the test suites' trust boundary and this plain cast is the one cast serving it (AUTH_SPEC §11-1)
- L51: testKeyFingerprintHex is a test-only mint with no format check: production mints only through the package's fingerprint computation and @maruhi/core's format-checked mints; negative vectors carry malformed fingerprints on purpose
- L63: testProjectId / testEnvironmentId / testVariableId are test-only plain casts: the package never mints them (production uses @maruhi/core's format-checked schemas); negative vectors carry malformed ids on purpose
- L92: LazyChainOperation exists because the §5.2 commitment preimage contains project_id: create_environment / rotate_epoch payloads cannot be finalized until the genesis is assembled

### `packages/crypto/test/support/index.ts`

- L1: Test-support surface rule: only the accessors for test vectors and shared fixtures go on this surface — internal implementations in src/ (internal.package) must not be exposed through it

### `packages/crypto/test/vectors.test.ts`

- L1: Conformance checks (§11) run identically across the 3 projects node / workerd / browser; the Bun runtime runs the same checks via test/run-in-bun.ts

### `packages/crypto/vitest.browser.config.ts`

- L25: The Chromium executable can be swapped via the same env var as the apps/web e2e (SHA-256-verified headless shell in CI / Cursor Cloud, or a pre-installed browser); default resolution when unset

### `packages/crypto/vitest.workerd.config.ts`

- L1: Workerd config rationale (§11): tests run under the real Cloudflare Workers environment; not picked up by the root vitest glob, run from a dedicated CI step (the spike-c setup)

### `packages/test-kit/lib/api-route.ts`

- Added 2026-11-28 (after the audit; no base line): the wire shape of an endpoint is read from its type as `["~Success"]["schema"]["Encoded"]` (the same for `~Error`, `~Payload` and `~Params`): `HttpApiEndpoint` wraps each schema in `Schema.toCodecJson`, whose own `Encoded` is `Json`, and keeps the schema it wraps under `schema`. The middleware errors come from `HttpApiMiddleware.ErrorSchema`, so an endpoint without the auth middleware has no 401. The `Encoded` side is the wire shape as long as the API's schemas are JSON-native, which they are. The method, the path and the schemas of each declared status come from `HttpApi.reflect` at run time; `reflect` types them as `Schema.Top`, whose decoding services are unknown, so the decoder is built behind one cast (the API's schemas need no service). It is its own package entry (`@maruhi/test-kit/api`) because it imports `@maruhi/api-schema` and `effect` as values, which the builders of the index do not: a test file that only builds test data does not load the API definition

### `packages/test-kit/lib/chain.ts`

- Moved 2026-11-28 from `apps/cli/test/support/crypto.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L203: The commitment is computed from the fixture's real DEK, so the pull side's §5.2 check passes on real data
- Added 2026-11-28 (after the audit; no base line): `signEntryAt` and `resignEntryAt` stamp an entry `BASE_TIME_MS + seq * 1000`, one second later than `buildChain` stamps the same seq (`buildChainWith` in `@maruhi/crypto/test-support` counts from index 0). Both are kept as they were in the two support files, because the server tests append entries after built and vector chains that were written against these times. The scope list of a member, device or role operation is sorted before it goes into the payload (`grantServerOp` passes its list as given); a test of an unsorted list writes the payload itself

### `packages/test-kit/lib/identity.ts`

- Moved 2026-11-28 from `apps/cli/test/support/crypto.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L1: Support design: real crypto fixtures from freshly generated keys each run, public @maruhi/crypto API only; the shared core lives in @maruhi/crypto/test-support (session-11 §5 ruling)
- Added 2026-11-28 (after the audit; no base line): one key model for both test suites. A `TestIdentity` is a user id, the hex of both key pairs and the fingerprint. `generateIdentity` makes fresh keys on each run (the CLI suite's source); `vectorIdentity` reads the pinned vector keys (the server suite's source, so that entries appended in a test continue the vector chain). Every builder takes the identity as an argument and the kit keeps no table from user id to key. The server support file keeps its own table (the alias and the device-key override recorded under `apps/server/test/support/data-crypto.ts`), and a server test resolves a user id to an identity through it (`identityOf`) where it calls the kit

### `packages/test-kit/lib/index.ts`

- Added 2026-11-28 (after the audit; no base line): `apps/cli/test/support/crypto.ts` and `apps/server/test/support/data-crypto.ts` built the same signed data twice, on two key models, and a change of the wire had to be made in both. This package holds the one implementation (owner decision 2026-11-28); the CLI file is gone, its tests use the kit's names, and the server file is now only the server suite's table from user id to vector identity (recorded under `apps/server/test/support/data-crypto.ts`). The package sits above `api-schema`, where the wire types come from. Its code is under `lib/`, not `src/`: the `packages/*/src/**` lint rules describe shipped code (no test mints, no `@maruhi/crypto/test-support`), and the kit is neither shipped nor imported by a `src` file (no zone in `.fallowrc.json` lists `test-kit`). The builders come in two layers: what a client sends (`wrapDekTo`, `encryptValue`, `signMetaStatement`, `signManifest`), which the server tests use, and what the server returns (`distributed*`), with which the CLI tests fill a mock server; the second layer is built on the first. The records of the CLI file are under this package's headings, and those under the server file's heading describe code that now lives here, except where that file's own record says otherwise

### `packages/test-kit/lib/manifests.ts`

- Moved 2026-11-28 from `apps/cli/test/support/crypto.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L642: Fixture contract: the digest is computed for real from the given statements — pass the same set as the pull fixture's statements / deletedVariables (a mismatch makes the client's digest recomputation reject, itself a way to build a negative)

### `packages/test-kit/lib/values.ts`

- Moved 2026-11-28 from `apps/cli/test/support/crypto.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L770: encryptValueFor contract (the function is `distributedValue` here): the declared head is the chain head the writer last verified at signing; for version > 1 the prev is specified by the test (default dummy — pull is latest-only, so prev existence is out of scope, ruling B)

### `packages/test-kit/lib/wire.ts`

- Added 2026-11-28 (after the audit; no base line): a wire shape is the `Encoded` side of its `api-schema` schema, not a hand-written interface, so a field that is renamed, added or retyped on the wire fails the typecheck of the tests that build it. The signer inputs (`UnsignedWrap`, `UnsignedMetaStatement`, `UnsignedManifest`) take any string as `suite`, so that a test can sign a shape the schema refuses

### `packaging/install-test.sh`

- L2: install-test.sh is a live-run test of install.sh (positive + tampered negative cases) on local artifacts, independent of a real release
- L85: python3 is required only for the local http fixture; install.sh itself needs only curl / tar / sha256-family tools
- L113: The port is taken by the script and printed flushed because http.server's startup message is block-buffered to a file and varies by version
- L128: The server is disowned from the job table because the cleanup kill otherwise makes bash emit a 'Terminated' notice into the log tail
- L152: check() counts by exit status directly: the `A && pass || fail` shape would run fail even when A is true if pass itself fails
- L240: Case 4 is exercised separately: it is the only link_alias branch that can reach `ln -sf`, a different path than case 3's regular-file branch
- L267: Only the first hex character is replaced and the format kept, so the case exercises the SHA-256 comparison itself, not the format check
- L304: Tampering is conditional/deterministic because overwriting with a fixed character would flake (1/256) when the byte already equals it
- L343: This destination shape blocks the failure mode where mv slips inside a non-regular-file destination

### `scripts/check-english.mjs`

- L80: addedLines also covers untracked files' whole contents because the diff never mentions them

### `scripts/test-suite.mjs`

- L1: test-suite.mjs derives suites from the root vitest.config.ts projects list and fails loudly on an unmatched project instead of skipping it
- L45: Suite path rules are ordered and explicit: an entry matching nothing is a design decision, so the resolver throws rather than guessing
- L59: projects entries must stay plain quoted literals: after stripping comments/strings only punctuation may remain, so no entry can be missed
- L92: Literal projects entries must exist and globs must match at least one file: both fail loudly on a typo or rename
- L109: Project names must stay plain literals because importing configs executes arbitrary code (server config reads wrangler.jsonc, .dev.vars)
- L129: The full audit runs on every invocation, not just the requested suite, so a new unmatched project fails every test:* call

### `scripts/vitest-aliases.ts`

- L7: vitest/worker and vitest/runtime are aliased to vite-plus's bundled vitest because no standalone vitest is installed at the root
- L21: The ResolveAlias annotation is required: the inferred literal type makes defineConfig's UserConfig comparison exceed the checker stack depth

### `vitest.config.ts`

- L5: Suite layout: crypto/core/cli run in the normal environment, server in workerd; web and site e2e are separate steps assuming a built dist
- L10: For root invocations the Cloudflare pool resolves its in-workerd entry through this config's vite instance (see scripts/vitest-aliases.ts)
- L15: File-order shuffle lives at the root because Vitest 5.0 derives file order from the root sequencer alone; it enforces order independence
- L29: Web's e2e stays a separate step assuming a built dist (CI 9); only the unit project is integrated here
- L32: Site's e2e is likewise a separate step (CI 9b); only unit (generated-theme drift detection) is integrated here

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
