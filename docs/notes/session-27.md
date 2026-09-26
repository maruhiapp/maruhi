# Session 27 notes (Phase 2 Wave 3 D — head gossip + environment manifest + checkpoint design exploration and spec drafting. docs/spec-only)

Date: 2026-08-18. Premise: Wave 2 fully complete (A1 #63 / A2 #65 / replay
first-come binding #67 / B1a #68 / B1b #69 / B2 #70 / C1 #71 / A3 #79) on main.
Scope: **design exploration and spec drafting only**. No changes to
implementation code in `packages/crypto` · server · CLI, test-vector bodies,
or api-schema Schema definitions.
**Merging this PR = the owner's approval of the spec** (same discipline as
session-22's spec-drafting PR). Implementation comes in a separate
post-approval PR, test vectors first (§14's split plan).

**Note on session-number correspondence (anti-confusion)**: the spec's Status
line already used "session 26" (no notes file) for the C1 ruling (2026-08-16)
and "session 25" for the B2 ruling (2026-08-15); the latter is already
double-used by the A3 notes `session-25.md` (2026-08-17). These notes are 27,
and from here on note numbers match the Status line's session numbers.

Starting point: resolving CRYPTO_SPEC §13 unresolved #12 (environment
manifest · checkpoints — "outcome of examining session-12 notes §4 option
C"). It consolidates the remainder of unresolved #4 (periodic · exhaustive
checkpoints) and AUDIT_SPEC §8 unresolved #2 (checkpoints of the audit head
into the chain). The precise definition of the residual to close is
CRYPTO_SPEC §14 (G5/G6/G7, §14.3-3/-4/-5).

## 1. Problem statement (what is still unguaranteed)

Reorganizing the post-§4.1 / §4.2 / §5.2 / §6.3 (floor · out-of-band anchors ·
head binding) remaining non-guarantees (CRYPTO_SPEC §14.3) by verifier class:

1. **§14.3-3 (per-view rollback — G5/G6)**: against a first-sync client with no
   floor, the server can distribute "an internally consistent old view" (a
   truncated chain + the values · statements set of that time). Mitigated only
   for the 2 classes holding an out-of-band channel (invite-link anchor = new
   members, repository anchor = workloads). **Even with chain-head freshness
   guaranteed, the data layer's (values · meta) completeness · freshness is
   not derivable from the chain** (the chain carries neither values nor meta)
   — anchors alone leave the combination "new chain + old data" possible (the
   epoch-non-regression check is the only partial mitigation)
2. **§14.3-4 (split view — G7)**: distributing different internally
   consistent views per member is mechanically undetectable in v1 (until
   evidencing via prev chaining · head binding)
3. **§14.3-5 (forward injection)**: values are detected by floor-holding
   clients via epoch monotonicity + floor rule (c), but **meta statements
   have no freshness anchor analogous to the epoch, and even to a
   floor-holding client the injection of a forward meta_version (a deleted
   member or compromised key using an in-tenure declared head) is
   undetected**. The most important hole, asymmetric with values (the §14.2-4
   note)
4. **G6 (variable-set omission)**: dropping a whole variable (tombstones
   included) from a pull response is detected via floor union for
   floor-holders, but is undetectable without a floor
5. **Audit-log tampering (AUDIT_SPEC §6 / unresolved #2)**: the audit log is
   server-managed data with no cryptographic tamper-evidence. Its
   chain-mirror portion is reconstructible by chain reconciliation, but
   post-hoc tampering · deletion of behavior-kind rows (var.read etc.) has no
   detection material (only seq gaps)

## 2. Verifier classes and the ceiling of reachable guarantees

Before designing, "what is in-principle reachable for which class" was fixed
(don't write unreachable things as reachable — the §14 discipline):

| Class | Chain-head freshness | Data-layer freshness · completeness |
|---|---|---|
| Floor-holding returning client | Floor (existing) | Floor (existing) + this design closes meta forward-injection |
| No floor + invite-link anchor (new member) | Anchor (existing) | **Reached for the first time by this design's checkpoints** |
| No floor + repository anchor (workload) | Anchor (existing. Including epoch non-regression) | Same as above |
| No floor + no anchor | **In-principle impossible** (no freshness guarantee exists from zero trust anchors) | Same (§14.3-3's residual shrinks to this class) |

On split view (G7): since gossip via the server lets the server selectively
drop attestations (omission = G8 = unpreventable), **guaranteed detection
against an actively malicious server is impossible under any design**. What
is reachable stops at (i) added detectability (forcing sustained · complete
omission = raising the attack's operating cost), (ii) non-repudiable
evidencing of cross-distributed contradictory attestations, (iii) shrinking
by composition with an external meeting point (repository anchor = git).
This ceiling is written honestly into the spec (§14).

## 3. Course of the design exploration (3 rounds)

- **Round 1 (naive option)**: manifest = a signed statement of the
  variable-set digest; checkpoint = a chain op of audit (seq, hash) +
  manifest hash; gossip = attestation storage · distribution. → Round 2
  detected 2 structural defects
- **Round 2 (strictly-better 1: freshness-anchor composition)**: (a) unless
  the manifest itself carries a freshness anchor, "manifest forward
  injection" recurses the same problem (the detection mechanism itself gets
  forged). **Baking in the current epoch + epoch-consistency verification**
  (same shape as §6.3-4 for values) gives the meta layer a time proxy
  symmetric with values. (b) Manifest freshness is pinned by the on-chain
  checkpoint; chain-head freshness is carried by floors · anchors · gossip —
  producing the one-way verification chain "anchor → chain → checkpoint →
  manifest → meta/values" and the cycle disappears (§6)
- **Round 3 (strictly-better 2: removing the info leak + adding the value
  head)**: (a) putting an audit seq on a checkpoint leaks the audit row count
  to below-admin via the chain (distributed to every member), colliding
  head-on with the C1 ruling (AUDIT_SPEC §7's "don't leak even the count" ·
  seq is disclosed to admins only) — **the audit head is represented only by
  its accumulated hash** (reconciliation is against a computed column and
  needs no seq — §5.3). (b) Unresolved #4/#12's wording asks for "**value** ·
  audit-log heads"; for floorless detection of value rollback the checkpoint
  is the only path — a per-environment **value-snapshot digest** was added to
  the payload, and the pull / lease responses carry the snapshot listing,
  enabling per-variable non-regression checks (§5.2). No strictly-better
  option appeared in subsequent rounds

## 4. Mechanism (a): head gossip (signed head attestations)

The concretization of §6.3's default policy (writes are carried by §4.1/§4.2
head binding; Phase 2 adds reader-side attestations and their mutual
distribution via the server).

### 4-1. Attestation format

```
head_attestation_signed_bytes = LP("maruhi/v1/head-attestation",
                                   project_id, attester_user_id,
                                   chain_head_hash_hex, chain_head_seq)
```

- **Signature mandatory (Ed25519)**: unsigned, the server could synthesize
  fake attestations and use them both for warning-inducing DoS and false
  reassurance. Signed, cross-distributed contradictory attestations become
  non-repudiable evidence of "server equivocation or key compromise" (same
  status as §14.2-5's evidencing)
- Baking in `attester_user_id` is the same anti-rebinding measure as §5.1's
  signer_user_id. Context-bound by project_id (transplanting to another
  project fails verification)
- **No timestamp · nonce inside the signed bytes**: the signature's semantics
  is the attribution "verified up to this head", not a freshness proof
  (§5.1's lesson). An attestation's recency is naturally ordered by
  chain_head_seq; redistributing an old attestation is equivalent to the
  server omitting it (making the attestation look stale) = reduces to G8,
  which crypto cannot prevent. A variant including a timestamp was dismissed
  because it only adds behavioral info ("when did they sync") without adding
  detection capability (§7's privacy consideration)

### 4-2. Storage and distribution

- The server stores **one latest attestation row per member** in the project
  DO (not on the chain — an attestation is high-frequency mutable data
  refreshed on every read; making it a chain op would let sync activity
  consume §6.4's entry cap. Same line as §6.2's "the chain is not a ledger of
  mutable metadata")
- Acceptance verification (the dishonest-client wheel of §6.4's pair): exact
  match of caller = attester; signature verification under a current-member
  (reader or above) sig key at acceptance time; head_hash matches the entry
  hash at that seq position of the own chain; monotone forward progression of
  seq from the stored attestation (regression is 409 — the discipline of not
  silently succeeding)
- Distribution bundles the current members' attestation set into the chain
  fetch response (the natural position — reconciliation happens right after
  sync verification). On `remove_member` acceptance the member's attestation
  row is deleted (only current members are distributed — same-shaped
  convergence to derived state as §12-6's old-key wrap cleanup)
- Submission is a client SHOULD: after chain sync + verification succeed,
  submit when the verified head has advanced past the previous attestation
  (every member including readers — per §6.3's 2026-08-01 addendum)

### 4-3. Behavior on detection

Reconciling other members' attestations against one's own view is a 2-case
distinction of the same shape as §6.3-2's head-binding reconciliation:

- (a) attested seq ≤ own head with a hash mismatch = **hard evidence of a
  fork or a forgery** —
  suspend use of that sync's artifacts and warn; save the evidence (the
  attestation + the chain digest of one's own view) into non-confidential
  local state (§14.2-5's evidencing; implementation follows the existing
  floor-evidence format)
- (b) attested seq > own head = possibly just self being stale — if a re-sync
  · re-verify resolves it as an extension of one's own chain, normal; if not,
  (a)
- **No evidence-reporting API to the server is built**: handing evidence to a
  server suspected of equivocation is pointless (it only tells the attacker
  that detection succeeded); local save + out-of-band sharing is the correct
  handling (AUDIT_SPEC §7's "dedicated narrow reporting endpoint" future
  exception is not used)

### 4-4. Classes that do not participate

- **Workloads (CI) do not participate in attestation**: workloads hold no
  Ed25519 signing key (only an ephemeral X25519), and unsigned attestations
  are forgeable with zero evidence value. Behavior records are already
  carried by `server.lease_issued`. Other members' attestations are also not
  bundled into lease responses — a malicious server can attach the
  period's attestations to an old consistent view, so it adds no detection
  and only adds a spec surface that misleads into "verified" (workload
  defense is carried by the repository anchor + checkpoints — §6)

## 5. Mechanisms (b)(c): the environment manifest and checkpoints

### 5-1. The environment manifest (a signed statement of the data plane)

The issuer signs the environment-level "full picture of the meta state"
every time the meta state changes:

```
env_manifest_signed_bytes = LP("maruhi/v1/env-manifest-sig",
                               project_id, environment_id,
                               epoch, manifest_version,
                               variables_digest_hex,
                               env_meta_version, env_meta_sig_hash_hex,
                               prev_manifest_sig_hash_hex,
                               issuer_user_id, chain_head_hash_hex, chain_head_seq)

variables_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/env-manifest-vars",
                                            entry_1, …, entry_n)))
entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)
          (variable_id in ascending byte order. All statements including
           tombstones. May be empty)
```

- **The baked-in epoch is the main body**: the verification rule "manifest
  epoch = that environment's current epoch at the declared head" (same shape
  as §6.3-4 for values) gives the meta layer a freshness anchor symmetric
  with values. Deletion · demotion are accompanied by an all-environment
  rotate (§7), so a key that has lost its tenure interval cannot sign a
  manifest for the current epoch — **a forged meta statement alone drops on
  manifest inconsistency, and even with a forged manifest bundled, one
  addressed to the current epoch is impossible**. This is the manifest
  version of floor rule (c); the residual for floor-holders shrinks to the
  same (i)(ii)(iii) as values (§14.3-5)
- **Issuance trigger = every operation that changes the meta state**
  (variable create · rename · delete, environment rename, rotate [reflects
  epoch advancement], environment creation [manifest_version 1, empty
  variable set]). **Not issued on value push** (the manifest carries no value
  version — this avoids session-12 option C-2's dismissal reason (i)
  [every-push-through-manifest-CAS hot-path serialization] as-is. Value
  rollback is carried by the checkpoint's value snapshot — §5.2). Meta
  operations are low-frequency, and the manifest_version CAS resolves at the
  same time as the existing metaVersion CAS
- **Issuer = that operation's performer** (1 extra signature). The role
  level is the same as the operation itself (doesn't change §12-3's table).
  On environment deletion the manifest is not re-issued — the subordinate
  meta is cascade-deleted and the distribution channel disappears (§12-4's
  existing arrangement). The environment's own deleted statement is the
  terminal detection material
- **The server can fully verify** (meta is plaintext): on top of signature ·
  head · authorization time · epoch consistency · prev chaining, **recomputed
  digest equality** can be an acceptance condition too (unlike a value's
  AAD, E2EE imposes no constraint). A dishonest client's forged manifest is
  all dropped at the acceptance stage
- Client verification: individual verification of every distributed
  statement (tombstones included) (§6.3) → digest recomputation → reconcile
  against the manifest → the manifest's own signature · head · authorization
  time · epoch consistency → checkpoint consistency (§5.2). A digest
  mismatch = detection of a missing / injected statement
- **The prev chain is held for evidencing, but verification needs only the
  latest manifest**: "succession since the checkpoint" is verifiable via
  manifest_version monotonicity + epoch consistency, without needing
  distribution · verification of intermediate manifests (a variant requiring
  full-chain distribution invites unbounded distribution of
  manifest_version rows — dismissed). Equivocation (different valid
  signatures on the same manifest_version) is the same non-repudiable
  evidence as §14.2-5

### 5-2. The checkpoint (new chain op `checkpoint`)

A client (member or above) notarizes the data-state digest of their verified
view into the chain. Only when the issuer's effective permission is admin
does the same entry also notarize the server-declared audit head
(non-admin-effective = empty string = no notarization):

```
payload (canonical field order): [environments_lp_hex, audit_head_hash_hex]
environments_lp_hex = LP(entry_1, …, entry_n)   (environment_id in ascending byte order)
entry_i = LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
             values_digest_hex)
values_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/env-values-digest",
                                         v_1, …, v_m)))
v_j = LP(variable_id, version, value_sig_hash_hex)
      (variable_id in ascending byte order. active variables only —
       tombstones live on the manifest side)
```

- **Why it's on the chain**: the chain is already "the authenticated
  broadcast everyone verifies" (same judgment as session-12 option B-4), and
  a checkpoint's freshness reduces to the chain head's freshness. Chain-head
  freshness is the job of floors · anchors · gossip — this stops the
  recursion of "rolling back the rollback-detection mechanism itself" (§6's
  acyclic argument)
- **Issuers are clients only** (structural necessity): a chain op requires
  the actor's Ed25519 signature, which the server cannot produce. So
  "periodic" is not a server cron but client-driven. Issuance triggers: (i)
  after a rotate + re-encryption of current values completes (SHOULD), (ii)
  an explicit operation (`maruhi project checkpoint`), (iii) a proposal
  (SHOULD. draft value) when a push / pull success detects >7 days since the
  reference checkpoint or none issued. The reference for trigger (iii) is
  split by effective permission: for admin, the latest **notarizing**
  checkpoint; otherwise the latest checkpoint. Issuance covers every
  non-deleted environment in the verified view (SHOULD). If acceptance-time
  agreement does not converge within a bounded retry, issuing over the subset
  of environments whose agreement could be confirmed is allowed. The append
  path is the generic chain-append API — there is no client-supplied
  companion data, and no other input that a composite would need to bundle
  atomically. However, the server stores a value-snapshot listing
  reconstituted from the acceptance-time state inside the same acceptance
  processing as the checkpoint append (the opposite arrangement from the
  composite acceptance that bundles client-supplied data for
  create_environment / rotate_epoch)
- **Consensus rules (chain validity) are format · the actor's chain role ·
  coordinate consistency**: payload structure (hex lengths ·
  rejecting duplicate environment_ids = MUST. Ascending order is a
  generation SHOULD and verification does not norm ordering — since the
  entry carries tuples, allowing duplicates would make the reference ·
  regression comparison non-deterministic. Review round 3), an actor with a
  non-empty audit_head_hash must be admin or above
  (`checkpoint-audit-role-insufficient`. The API acceptance side additionally
  requires token-scope admin), each environment_id must follow a
  `create_environment` (unknown-environment), each environment's epoch must
  exactly match the chain-derived current epoch at entry time (before
  applying the entry itself), **each environment's manifest_version must be
  at least that of the most recent prior checkpoint containing the same
  environment (`checkpoint-regression` — review-loop 1 finding 1: blocks, at
  the chain layer, a malicious member rolling back the detection baseline.
  §16)**. The environment set may be a subset (full coverage is not a
  consensus rule — don't race environment creation). The **contents** of
  manifest_sig_hash / values_digest / audit_head_hash cannot be verified by
  chain verification (same boundary as §5.2's DEK commitment — "format in
  consensus rules, content on the reconciliation side")
- **Server acceptance verification (acceptance policy)**: the manifest
  references and values_digest are an **exact match against stored state at
  acceptance time** (if the issuer's view is stale or a concurrent write
  intervened: 422 → re-fetch · re-sign · retry — the same structure as the
  chain CAS 409. The digests' preimages are not carried on the wire — the
  server reconstitutes them uniquely from acceptance-time state.
  Review-loop 1 finding 4: the original "also allow notarizing a past state
  + bundle the preimage" option was simplified to acceptance-time matching —
  it complicated the acceptance rules (per-variable monotonicity checks,
  active-set coverage checks) while its only gain was "not racing a
  concurrent push with a 422", not worth it for a low-frequency checkpoint).
  Entries for deleted environments are also rejected at acceptance. A
  non-empty audit_head_hash requires the API caller's effective permission
  admin, and additionally checks **membership + a position floor** against
  the stored accumulated-hash column (at or above the `chain.checkpointed`
  mirror row of the immediately preceding checkpoint). A first checkpoint
  carries no position floor. Latest-state equality is not required, since
  the append itself writes an audit mirror. A notarizing issuer fetches the
  audit head after the chain head (CAS parent) settles, and on
  `audit-head-stale` re-fetches the attestation too. This makes the position
  check structurally sound under an honest server, and doesn't turn benign
  concurrent issuance into a tamper accusation. Forged or stale notarization
  points are dropped at acceptance
- **Client verification (consuming a checkpoint)**: the per-environment
  reference = **the latest checkpoint containing an entry for that
  environment** (review-loop 1 finding 2: taking "the latest checkpoint op"
  as the reference would erase an environment's reference whenever a
  checkpoint not containing it is appended). Against the reference: (i) the
  distributed manifest's manifest_version ≥ reference's; on equality the
  sig_hash must match, **and the manifest's epoch ≥ the reference's epoch**;
  (ii) after reconciling the digest of the "checkpoint-time value-snapshot
  listing (variable_id, version, value_sig_hash)" bundled into the pull /
  lease response against the on-chain values_digest, each distributed
  variable's version ≥ the snapshot's; on equality
  the value_sig_hash must match, **and a version newer than the snapshot's
  must have an epoch ≥ the reference epoch (the checkpoint version of floor
  rule (c) — review-loop 1 finding 3. The argument for the reference point's
  soundness is identical to floor rule (c)'s: a regular push after checkpoint
  acceptance can only occur at the then-current epoch = reference epoch or
  later)** · a variable present in the snapshot but absent from the
  distribution is rejected as missing unless a verified tombstone (including
  manifest consistency) exists. **This gives a floorless client (after
  gaining chain freshness via an anchor) detection of value · meta
  rollback · omission · substitution up to the checkpoint point, plus
  detection of forward injection via the epoch reference** (the same shape
  as floor rule (c) where the reference became "checkpoint issuance" instead
  of "the last successful pull" — just coarser than a returning client's
  floor)
- **The audit head is an "issued-unverified notarization" by
  effective-permission admin**: an issuer with effective permission admin
  signs the server-declared accumulated hash without verifying every row.
  Other issuances carry the empty string (no notarization), so no path is
  built that infers class-2 activity windows by polling `GET /audit-head`
  for changes. The value is **pinning and forward-progress**. An admin's
  reconciliation checks, on top of the notarized head's membership, that its
  position does not regress across notarizations and is at or above the
  immediately preceding checkpoint's mirror row. This makes post-hoc
  tampering · deletion of a notarized prefix distinguishable, as evidence,
  from a staleness replay that keeps returning an old real head. How far the
  notarized prefix advances depends on admin-client issuance frequency, and
  falsehood at record time (writing a lie from the start) remains
  unguaranteed as before (AUDIT_SPEC §6)

### 5-3. The audit head's accumulated hash (the resolution form of AUDIT_SPEC unresolved #2)

- The server (project DO) maintains the accumulated hash on each audit-row
  append:
  `h_n = lower_hex(SHA-256(LP("maruhi/v1/audit-head", h_{n-1}, seq, row_digest)))`
  (`h_0` = empty string. row_digest is the LP hash of the row's fixed column
  enumeration — the column order is fixed on the AUDIT_SPEC side. The
  payload uses the stored TEXT bytes verbatim; no JSON canonicalization is
  imported)
- **Checkpoints carry no seq** (round-3 finding): the chain is distributed
  to every member including readers, and audit seq is a gapless shared
  numbering — carrying it would let below-admin infer class-2 row counts ·
  activity volume exactly (a head-on collision with the C1 ruling —
  AUDIT_SPEC §7's "don't leak even the count" · admin-only seq disclosure).
  The accumulated hash is random-looking and carries no ordinal. Admin
  reconciliation recomputes the accumulated-hash column while fetching every
  row and checks (a) the notarized value's membership, (b) non-regression of
  notarized positions, (c) at-or-above the immediately preceding checkpoint
  mirror row. Adding no seq to the chain payload, a staleness replay is
  still detectable
- **The D1 side (user-kind · org-kind) is out of scope**: the checkpoint's
  home is the project chain; there is no place to put audit rows that don't
  belong to a project. The D1 side's tamper resistance stays as before
  (AUDIT_SPEC §6's threat model)

## 6. Composition: the acyclic verification chain (answer to trap 7)

Each mechanism's "who guarantees freshness" closes one direction:

```
out-of-band anchors (invite link / repository) · local floor · head gossip
  → chain-head freshness
    → the latest on-chain checkpoint (a derived value of chain verification)
      → environment manifest (pins manifest_version · sig_hash) + value
        snapshot (per-variable non-regression reference) + audit head
        (pins post-hoc tampering)
        → the meta-statement set (digest equality) → values (variable_id binding)
```

- No reverse dependency such as a manifest guaranteeing a checkpoint's
  freshness
- The manifest's baked-in epoch is a second defense layer independent of
  the chain (depends only on the chain-derived current epoch — even if the
  checkpoint is stale, a post-rotate forged manifest drops on epoch
  consistency)
- For "a client holding neither anchor nor floor" the chain has no starting
  point; §14.3-3's residual shrinks to this class (per §2's ceiling — it
  does not disappear)

## 7. Privacy and DoS (answer to trap 5)

- **Is a head attestation behavioral info?** An attestation carries only
  (attester, head_hash, head_seq, signature). Against AUDIT_SPEC §6's
  boundary ("monitoring info on a person's actions vs. the functioning of a
  disclosure mechanism"), an attestation — unlike variable access (var.read
  = class 2) — only shows "the point a chain sync reached". Since the chain
  itself (every op · every actor) is already distributed to · verified by
  every member as class 1, disclosing "M's view reached seq N" is a small
  increment over existing disclosure, and it is **required material for the
  interest of every member (readers included)**: split-view detection
  (narrowing it to admins would leave split views against non-admins
  undetected — the same shape as R3's "defense-in-appearance"). So
  attestation distribution is **class-1-equivalent (all members)**. The
  increment is still minimized: (i) no timestamp — neither signed nor
  distributed (the stored row's acceptance time is for audit · debugging and
  is not distributed); (ii) no audit-event conversion (high-frequency ·
  low-info — same bloat problem as var.read, contributes nothing to
  rotation-needed detection, and avoids adding a permanent record of "when
  they synced" as behavioral info)
- **DoS side**: accepting an attestation = 1 Ed25519 verification + a
  monotonicity check. Storage is 1 row per member (UPDATE) — no storage
  bloat. Acceptance rate limit (draft value: a fixed window of 60/hour per
  member, 429 on excess). Checkpoints obey the entry cap · cumulative cap
  (§6.4) as ordinary chain appends; an append barrage at member permission
  is inside the existing chain-bloat DoS countermeasure (acceptance policy).
  A manifest is 1:1 with a meta operation and creates no new write path

## 7.5 Mandatory design checks (answers to the task-specified checklist — session-12 §5 format)

| Check | Answer |
|---|---|
| Identity rules (§6.1) | Attestation = attester_user_id + key FP; manifest = issuer_user_id + key FP; checkpoint = chain actor (user_id + FP). **Provider IDs · email addresses appear nowhere**. The audit head is a hash only (carries no row content) |
| Standard parts only (§1 principle 2) | Newly added: 2 Ed25519 signature kinds (manifest · attestation) + 3 SHA-256 digests (variables / values / audit-head) + §2.1 LP only. No external transparency-log infrastructure · no new crypto primitives · no new dependencies. The digests apply §5.2's same "identification by public hash" commitment (no hiding needed — the subjects are public metadata and public hashes) |
| Domain separation | The 5 new domains (`env-manifest-sig` / `env-manifest-vars` / `env-values-digest` / `head-attestation` / `audit-head`) differ from every existing domain in their first LP field — no collision |
| No plaintext values · key material passes through | Everything added to the wire · storage is signatures (public) · hashes · serials only. Same non-confidential class as floors · pins (compatible with the diskless invariant) |
| User-facing wording | None arises in this revision (warning · error-message wording belongs to the implementation PR — ADR-0017) |

## 8. Numeric estimate of chain bloat (answer to trap 6 — follows §6.4's grant_server precedent)

- **Largest checkpoint entry**: environment entry = environment_id (≤ 64
  chars) + epoch / manifest_version (decimal ≤ 10 chars) + 2 hashes
  (64 chars × 2) ≈ ~220 bytes. With LP + nested hex encoding ≈ 2× ≈ 450
  bytes/environment. At the active-environment cap 100 (AUTH_SPEC §12-8)
  that's ~45 KiB + 64 bytes of audit head ≈ **max ~50 KiB / entry** (5% of
  §6.4's 1 MiB cap). In real operation (a few environments) it's 1–3 KiB
- **Frequency and accumulation**: at the recommended frequency (every 7 days
  + after rotate-and-re-encrypt completes), ~50–100 entries/year. Even at
  the largest shape, 100 × 50 KiB = 5 MiB/year → over 6 years to the 32 MiB
  cumulative cap; the entry count reaches 10,000 on the order of 100 years.
  At the real-operation shape (a few KiB) the size is effectively
  negligible. **The dominant term is frequency; instead of explicitly
  forbidding per-push / per-pull issuance in the spec, which would break
  this estimate, the recommended triggers are made normative** (§5.2's
  (i)–(iii). Raising the acceptance policy is possible in self-hosting —
  §6.4's nature)
- **Manifests · attestations are not on the chain** (data plane), so they
  are unrelated to bloat. The server keeps **only the latest 1 manifest**
  (AUTH_SPEC §12-5 — no verification path needs past rows), so rows don't
  accumulate and no row-count cap is placed (the initially drafted
  "manifestVersion rows / environment = 100,000" cap was retracted in
  review round 3 — a pullfrog finding — because joining the variable-side
  metaVersion budget would permanently block even delete operations,
  contradicting the PR #31 ruling. §16)

## 9. Design-option comparison and dismissed options (recorded in re-reviewable form)

### Head gossip

| Variant | Assessment |
|---|---|
| Signed attestations (adopted) | Blocks forged-attestation synthesis and makes contradictory attestations non-repudiable evidence. Cost is 1 signature/sync |
| Unsigned attestations | **Dismissed**: the server could synthesize arbitrary attestations — usable both for warning DoS and false reassurance. Zero evidence value |
| Timestamps on attestations | **Dismissed**: freshness is not provable (§5.1's semantics); only behavioral info (when they synced) grows. head_seq suffices for recency |
| Making attestations a chain op | **Dismissed**: per-sync appends consume the entry cap (the spec would have chain-bloat DoS built in). Also against "the chain is not a ledger of mutable metadata" (§6.2) |
| Attestations as audit events | **Dismissed**: high-frequency · low-info (same bloat problem as var.read) + no contribution to rotation-needed detection + creates a new permanent record of behavioral info |
| Workload participation / bundling attestations in lease responses | **Dismissed**: workloads hold no signing key and can only produce forgeable attestations. The bundling side is neutralized by "old view + the-period's attestations", adding no detection while producing only the false impression of "verified" |
| A server-reporting API for fork evidence | **Dismissed**: the composition of handing evidence to a server suspected of equivocation is inverted. Local save + out-of-band sharing (v1 stops at warn + save) |

### Environment manifest

| Variant | Assessment |
|---|---|
| Issued per meta operation + baked-in epoch (adopted) | Gives the meta layer a freshness anchor symmetric with values and closes §14.3-5's meta asymmetry. Doesn't touch the hot path (push) |
| Also include values' latest version (revisiting C-2's (i)) | **Dismissed (kept)**: a serialization point where every push passes the manifest CAS + permanent contention among concurrent writers. Value rollback is carried by the checkpoint's value snapshot on the low-frequency side |
| No baked-in epoch (set digest only) | **Dismissed**: the manifest's own forward injection recurses — the "detection mechanism gets forged" shape remains (round-2 defect) |
| Issued only at checkpoints (manifest not standing) | **Dismissed**: meta forward injection to floor-holding clients passes in the window between checkpoints — a standing epoch anchor is exactly the counterpart of value monotonicity |
| Manifest as a chain op | **Dismissed**: display edits (rename) consuming the chain is a re-litigation of the judgment §6.2 explicitly rejected |
| Full distribution · verification of the prev chain | **Dismissed**: unbounded distribution of manifest_version rows. Monotonicity + epoch consistency give the same detection with the latest 1 manifest, and equivocation is evidenced by the sig_hash difference |

### Checkpoints

| Variant | Assessment |
|---|---|
| Standalone op `checkpoint` (adopted) | Touches no existing op's payload (chain-entries.json only needs appends — §11); can naturally hold cross-environment state (the audit head) |
| Riding on the rotate_epoch payload | **Dismissed**: the audit head's (environment-independent) coordinates get skewed + every existing vector regenerated + no checkpoint possible in rotate-free periods. The same effect is had by making post-rotate-and-re-encrypt completion a SHOULD trigger |
| (seq, hash) on the audit head | **Dismissed (round 3)**: leaks the audit row count to below-admin via the chain, contradicting the C1 ruling (count non-disclosure · admin-only seq). The hash alone suffices for reconciliation |
| Merkle-tree the value snapshot | **Dismissed (C-4 kept)**: no need for partial proofs (pull fetches every variable of an environment). A flat digest + bundled snapshot listing gives the per-variable check |
| Server-issued checkpoints | **Structurally impossible**: a chain op requires an actor signature, and the server holds no signing key (this isn't a defect but the manifestation of "a server self-notarizing its own state is worthless" — the notarization's value lies in the member's signature) |
| Verifying every audit row at issuance | **Dismissed**: a notarizing admin can browse all rows, but fetching · recomputing all rows per checkpoint is heavy. At notarization the server-declared value is pinned; full verification is separated into a later explicit admin reconciliation |
| Acceptance that also allows notarizing past state + bundling the digest preimage on the wire | **Dismissed (own option replaced in review loop 1)**: against the gain of not racing a concurrent push with a 422, the acceptance rules over-complicate (per-variable monotonicity checks · active-set coverage checks · duplicate preimage delivery). Acceptance-time matching + retry (same structure as the chain CAS 409) suffices |
| Making "the latest checkpoint op" the consumption reference | **Dismissed (review loop 1)**: appending a checkpoint that doesn't contain an environment erases that environment's reference. The reference must be "the latest entry containing that environment" |

## 10. Residual-coverage table (scope 2 — which residual each mechanism closes, at which level)

Levels: **prevent** = cryptographically impossible / **detect** =
mechanically detected (no false positives) / **evidence** = non-repudiable
evidence pinned / **—** = no contribution. Portions already carried by
existing mechanisms are marked "existing"; this design does not
re-implement them.

| Residual (§14.3) | Client class | Existing mechanism | This design's addition | Level reached |
|---|---|---|---|---|
| -3 view rollback (chain) | floor-holding | floor (detect) | — | detected by existing |
| 〃 | no floor + invite anchor | anchor (detect) | — | detected by existing |
| 〃 | no floor + repository anchor | anchor (detect) | — | detected by existing |
| 〃 | no floor + no anchor | none | gossip (attestation reconciliation — avoidable by omission) | stops at evidencing (**residual**) |
| -3 data-layer rollback · omission (chain is new) | floor-holding | floor (detect) | — | detected by existing |
| 〃 | no floor + anchor | epoch non-regression only (partial) | **checkpoint** (manifest · value-snapshot consistency) | **detect** (up to the checkpoint point) |
| -4 split view | all classes | evidencing (prev chaining · head binding) | **gossip** (cross-reconciliation of attestations) + repository anchor (external meeting point) | detectability + evidencing (avoidable by omission — **no guarantee**) |
| -5 value forward injection | floor-holding | epoch monotonicity + floor (c) (detect) | — | detected by existing |
| -5 meta forward injection | floor-holding | **none** (evidencing only) | **manifest** (epoch consistency + the manifest version of floor (c)) | **detect** (shrinks to the value-symmetric residual (i)(ii)(iii)) |
| -5 (i) floorless first sync | floorless | reduces to -3 | checkpoint (when an anchor exists) | detect (up to the checkpoint point) |
| -5 (ii) the remove → rotate-complete window | all classes | §7's operational obligation | — (the observation material grows via manifest bundling into the rotate composite) | **residual** (mechanization is session-12 §10-7 = a separate task) |
| -5 (iii) a returning client with a stale epoch floor | floor-holding | none | noted that the manifest has a same-shaped residual | **residual** (value-symmetric) |
| G6 variable-set omission | floor-holding | floor union (detect) | — | detected by existing |
| 〃 | no floor + anchor | none | **manifest** (digest recomputation) | **detect** |
| audit-log post-hoc tampering | admin (all-rows viewer) | seq gaps only | **checkpoint** (pinning the accumulated hash + position checks in admin reconciliation — the notarization point advances monotonically up to the immediately preceding checkpoint's mirror row. Loop-3 round-2 finding 1) | **detect** (rows in the notarized prefix — prefix freezing by staleness replay is also detected on reconciliation. **Prefix advancement depends on issuance frequency of effective-permission admin** [round 5 — mitigated by trigger (iii)'s admin reference split]. Falsehood at record time remains unguaranteed) |

## 11. Positioning of existing handoffs (answer to trap 8)

| Handoff | Ruling |
|---|---|
| session-25 §8: the anchor-update proposal (on rotate / push success — the second half of §6.3 (b) SHOULD) | **Stays a separate task** (a UX improvement that doesn't change detection's nature — session-25's judgment kept). However, since it shares a pathway with the checkpoint's recommended issuance trigger (after rotate + re-encrypt completes), implementing both together in PR-M2 is natural (noted in §12) |
| session-12 §10-7: making remove + all-environment rotate a composite (mechanizing §14.3-5 (ii)) | **Stays a separate task** (listed in ROADMAP "future"). This design doesn't change that window. The manifest is bundled into the rotate composite, but a checkpoint is appended independently after rotate + re-encrypt completes, so the remove → rotate-complete window is not made atomic. Compositing is a redesign of the chain-append stack (2-entry composite + body size + DO execution time) and is orthogonal to this design |
| AUDIT_SPEC unresolved #2: checkpoints of the audit head | **Integrated into this design and resolved** (§5.3. Accumulated hash only · no seq) |

## 12. Rulings needed (recommended options are already reflected in the spec draft body. Merge = approval of the recommended options; objections go to the PR review)

1. **Introducing the environment manifest** (composite issuance per meta
   operation + baked-in epoch. CRYPTO_SPEC §4.3 / AUTH_SPEC §12-4 · §12-5 ·
   §12-7). Alternative = checkpoints only, no manifest (the meta
   forward-injection window remains — §9). Recommended = introduce
2. **New chain op `checkpoint`** (consensus rules — §6.2. Existing vectors
   only need appends, no regeneration — §13-1). That now-before-release is
   the window where a new op can be added under the "unknown op = chain
   invalid" consensus rule is the same argument as the grant_server
   extension (session-22 §2 R1). An actor carrying a non-empty audit head
   must be chain-role admin or above (`checkpoint-audit-role-insufficient`).
   Recommended = introduce
3. **A value-snapshot digest on the checkpoint + a snapshot listing bundled
   into pull / lease responses** (§5.2). Alternative = a meta-only
   checkpoint (value rollback remains for floorless clients — fails
   unresolved #4/#12's "value head" requirement). Response bloat is ~110
   KiB/environment at the largest shape (1,000 variables); real operation
   is a few KiB. Recommended = introduce (acceptance-time storage in PR-M2;
   pull / lease distribution and client verification can be split into
   PR-M3)
4. **The audit head is the accumulated hash only (no seq)** (§5.3 —
   consistency with the C1 ruling). Recommended = hash only
5. **Attestation visibility and format** (class-1-equivalent distribution ·
   no timestamp · no audit-event conversion — §7). Recommended = as the
   body
6. **Workloads don't participate in gossip + attestations are not bundled
   into lease responses** (§4-4). Recommended = non-participation
7. **checkpoint issuance permission = member or above** (data-layer
   notarization is at the same level as rotate. Only audit-head fetch ·
   notarization is limited to effective-permission admin per ruling-needed
   11 — the permissions are separated). Recommended = member
8. **Token scope for attestation submission = read** (an attestation is a
   sidecar of a read sync, and what can be written is only one's own signed
   attestation row. Requiring write would lock read-token sync clients out
   of attesting under the always-reader authorization model — §6.2).
   Recommended = read
9. **Draft values for the recommended checkpoint frequency** (7 days +
   after rotate + re-encrypt completes — §5.2). For trigger (iii), only
   effective-permission admin takes "the latest notarizing checkpoint" as
   the reference. Tuned in review
10. **Positioning of the existing handoffs** (§11's 3 items). Recommended =
    as the body
11. **Limiting audit-head notarization to effective-permission admin**
    (added in review rounds 4–5 on 2026-08-18 — §16): opening
    `GET /audit-head` to member makes polling for accumulated-hash changes
    a timing side channel leaking class-2 activity windows to below-admin
    (a finding from the automated security review). Fetching and
    notarizing are limited to effective-permission admin
    (min(token scope, chain role)); checkpoint issuance by anyone else
    carries audit_head_hash = empty (no notarization). **As a consequence,
    the notarized prefix's advancement depends on admin issuance
    frequency** (an explicit residual — AUDIT_SPEC §6. Mitigated by
    splitting trigger (iii)'s reference so only admin clients take "the
    latest notarizing checkpoint"). Alternative = open to member + rate
    limit (coarsens the window but the leak remains). Recommended =
    admin-only + trigger split

## 13. Test-vector plan (session-12 §8's format. In the post-approval implementation PR, committed ahead of implementation)

### 13-1. `chain-entries.json` (**appends — no full regeneration needed**. PR-M2)

- **Judgment of whether regeneration is needed (answer to trap 2)**:
  `checkpoint` is the addition of a new op and touches no existing op's
  payload format (unlike grant_server's lease-policy extension = payload
  format change = full regeneration). Every existing canonical chain's
  entry bytes · hashes · existing negatives are invariant; appending a
  checkpoint entry to the canonical chain's **tail + extending
  expected_head_states** (deriving the latest checkpoint — a semantic
  extension of state derivation) suffices. Under the "unknown op = chain
  invalid" consensus rule this revision is a breaking change requiring
  every implementation to update at once, but being pre-release it carries
  no backward-compatibility clause (same premise as §6.2's precedent)
- Added positives: a checkpoint in an environment with variables · a
  manifest (**pinning both sides of the permission split — member actor +
  empty audit_head_hash and admin actor + non-empty audit_head_hash**) /
  zero environments (empty environments) / notarizing a past
  manifest_version (within the monotone range of at-least-the-last-
  checkpoint — **pinned as valid at the consensus-rule layer**. The
  acceptance layer requires acceptance-time matching and rejects it
  [§6.4], but that is outside what the chain-entries vector verifies = the
  domain of acceptance-side implementation tests [13-5])
- Added negatives (authorization kinds): `authz-checkpoint-reader` (role
  insufficient) / `authz-checkpoint-audit-member` (member actor notarizing a
  non-empty audit head — `checkpoint-audit-role-insufficient`) /
  `authz-checkpoint-unknown-environment` /
  `authz-checkpoint-epoch-mismatch` (mismatches the current epoch at entry
  time) / `authz-checkpoint-regression` (a manifest_version smaller than a
  prior checkpoint containing the same environment — including pinning the
  check order role → audit role → unknown → epoch → regression). Payload
  structure checks (before the authorization stage — §6.2's stage order):
  bad hex lengths · duplicate environment-entry IDs · how an ascending-order
  violation is handled (if it's the same "generation is ascending SHOULD ·
  verification is set-wise" as scope_environments, then an ascending
  violation is positive — pin the intent in a vector)

### 13-2. `env-manifest.json` (new. PR-M1)

- Fixture method: references chain-entries.json's canonical chain (the 8-1
  precedent)
- Positives: manifest_version 1 (environment creation — empty variable
  set) / after variable creation / after rename (prev chaining) / after
  deletion (tombstone-inclusive digest) / after rotate (epoch advanced) /
  a past manifest at in-tenure coordinates of a deleted issuer
- negatives: `tampered-signature` / `tampered-digest` / coordinate
  transplants `transplant-project` / `-environment` / `transplant-issuer` +
  `wrong-issuer-key` / `chain-head-swap` + `chain-head-seq-mismatch` /
  `prev-hash-mismatch` / `epoch-regression` (a forward manifest_version
  with the old epoch baked in after rotate — this design's core negative) /
  `epoch-not-current-at-head` / `digest-variable-omitted` (a digest that
  dropped one statement) / `digest-tombstone-omitted` (hiding a tombstone)
  / `digest-order-swap` (canonical-form mismatch on an ascending-order
  violation) / `fork-same-version` (a fork on the same manifest_version —
  pinning evidencing) / `suite-mismatch` / `issuer-role-insufficient`
  (reader signature) / `issuer-removed-at-head`

### 13-3. `head-attestation.json` (new. PR-M4)

- Positives: basic / a reader's attestation / a past attestation to an
  in-tenure head of a deleted member (verifies but is outside distribution
  — pinning the intent)
- negatives: `tampered-signature` / `transplant-project` /
  `transplant-attester` + `wrong-attester-key` / `head-not-in-chain` /
  `head-seq-mismatch` / `suite-mismatch`

### 13-4. `checkpoint-digest.json` (new. PR-M2 / PR-M3)

- Pin the LP canonical forms of variables_digest / values_digest / the
  audit-head accumulated hash (empty set · single element · multiple
  elements · ascending order). Canonicalization vectors in the same family
  as the existing `encoding.json`

### 13-5. Items that can't be vectorized (implementation-test plan. Included in each implementation PR)

- Attestations: monotone acceptance (regression 409) · row deletion on
  remove · the 2-case distinction of distribution reconciliation (mismatch
  with seq ≤ own head = immediate evidence / seq > own head = re-sync →
  resolve) · evidence saving (floor-evidence format)
- Manifest: composite acceptance with a meta operation · manifest_version
  CAS retry (re-issuing both signatures) · the server's digest-recomputation
  verification · pull bundling · the manifest versions of floor rules
  (a)(b)(c) · missing manifest = reject (pinning that there is no
  warning-downgrade branch — loop-3 finding 2)
- Checkpoint: acceptance verification (reconciliation against stored state —
  rejecting forged notarizations · rejecting entries for deleted
  environments · **the audit-head position floor** [`audit-head-stale`:
  re-signing a stale attestation after a CAS race = a benign race is
  type-rejected at acceptance and never appears as a position-check
  violation in admin reconciliation — an acceptance-policy layer, not
  vectorized. Loop 3 round 3]) · snapshot-bundling verification
  (per-variable non-regression · omission = rejecting a tombstoneless
  disappearance · rejecting an elided listing) · maintaining the audit
  accumulated hash + the admin reconciliation flow (membership + position —
  including that **consecutive notarizations of a non-advancing head**
  [staleness replay] are detected by the position check — loop-3 round-2
  finding 1) · rejecting manifest distribution older than a checkpoint ·
  warning on a value-bearing distribution of an environment with no
  reference · falling back to subset issuance when bounded retry is
  exceeded
- Checkpoint permission matrix: (a) admin role × admin token + non-empty
  audit_head_hash = accepted, (b) admin role × write token + non-empty =
  403, (c) member role × admin token + non-empty = 403 (the API's effective
  permission is insufficient. Also `checkpoint-audit-role-insufficient`
  under the chain consensus rules), (d) member role × write token + empty
  string = accepted as a data-layer checkpoint. This is an integration test
  of the API acceptance policy and is kept in a different layer from the
  chain-entries vector's `authz-checkpoint-audit-member`
- Snapshot storage of a subset checkpoint: after references for A / B are
  established, checkpointing only A upserts A's snapshot + checkpoint
  reference in the same DO transaction while B's existing snapshot +
  reference are preserved. No intermediate state of append-succeeded-only
  / save-succeeded-only is created
- lease path: add the verification obligation of manifest · checkpoint
  consistency (§9.1 (5)) to the ci-run client

## 14. Implementation split plan (session-12 §9's format. PRs containing crypto-layer changes follow the layer order "vectors first → crypto → api-schema → server → CLI"; crypto requires human review. Layers needing no change are omitted as enumerated per PR)

1. **PR-M1: environment manifest** — env-manifest.json → crypto (manifest
   sign / verify / digest computation) → api-schema (EnvironmentManifest
   type · compositing the meta operations) → server (composite meta
   acceptance · bundling into the create / rotate composites · pull
   bundling · latest-only retention) → CLI (issuance · verification · the
   floor's manifest extension). The top-priority PR that closes §14.3-5's
   meta asymmetry. **Includes a migration procedure**: since manifest
   verification is missing = reject only (§6.3 — no warning branch),
   internal dogfooding environments created before introduction must issue
   manifest_version 1 via an explicit operation (a dedicated init command
   rather than a no-op rename, or a rotate) before the client-side mandate
   is turned on
2. **PR-M2: the checkpoint op** — chain-entries.json appends +
   checkpoint-digest.json → crypto (the op's consensus-rule verification ·
   latestCheckpoint state derivation) → api-schema (checkpoint payload /
   `CheckpointStateMismatch` / the audit-head fetch API) → server
   (acceptance verification · maintaining the audit accumulated hash ·
   the audit-head fetch endpoint · **storing the acceptance-time
   value-snapshot listing on checkpoint acceptance**) → CLI (`maruhi
   project checkpoint` + manifest-consistency verification + the issuance
   proposal after rotate + re-encrypt completes. session-25 §8's
   anchor-update proposal is also implemented in the same pathway)
3. **PR-M3: value-snapshot distribution · verification** — api-schema
   (snapshot listing in pull / lease responses) → server (bundling the
   stored listing into responses) → CLI / lease client (values_digest
   reconciliation + per-variable non-regression check)
4. **PR-M4: head gossip** — head-attestation.json → crypto (attestation
   sign / verify) → api-schema (attestation POST · chain-fetch response
   extension) → server (acceptance · storage · distribution · cleanup on
   remove) → CLI (submission · reconciliation · evidence saving)
- Order: M1 → M2 → M3 (M2 depends on M1's manifest storage row; M3 depends
  on M2's checkpoint). M4 is independent of M1–M3 and can run in parallel.
  Even in intermediate states guarantees grow monotonically (M1 alone
  closes meta forward injection for floor-holders; M2 adds **meta
  completeness** for floorless clients plus acceptance · storage of the
  value-snapshot reference; M3 closes value-rollback detection via
  distribution · verification of that reference; M4 adds split-view
  detectability)

## 15. What lands in the specs (in-scope vs. out-of-scope)

- **CRYPTO_SPEC 0.6-draft**: §4.3 (environment manifest — new) / §6.2
  (consensus rules for the `checkpoint` op) / §6.3 (concretizing the
  head-gossip paragraph · checkpoint-consistency verification · the floor's
  manifest extension) / §6.4 (acceptance verification for checkpoints ·
  attestations) / §6.6 (head attestations — new) / §11 (vector
  supplement) / §13 (resolving #4 · #12) / §14 (updating the carriers of
  G5/G6/G7 · revising guarantees and non-guarantees)
- **AUTH_SPEC 0.11-draft**: §12-4 (manifest bundling into the create /
  rotate composites) / §12-5 (manifest composite acceptance for meta
  operations) / §12-7 (manifest · snapshot bundling into pull responses) /
  §12-8 (manifests are retained latest-only · no row cap) / §6 (checkpoint
  empty = write / non-empty = admin) / §14-2 (bundling into lease
  responses) / §16 (head attestations · checkpoint support APIs — new)
- **AUDIT_SPEC 1.0-draft**: §3.4 (the `chain.checkpointed` mirror) / §5.1
  (maintaining the accumulated hash) / §6 (adding post-hoc-tamper detection
  via checkpoints · the decision not to make attestations audit events) /
  §8 (resolving unresolved #2)
- **ADR: judged not to need a revision**. ADR-0002 already decided
  "signed membership log · head gossip · context binding · epochs"; this
  revision is a refinement of it (CRYPTO_SPEC's domain). The manifest ·
  checkpoint are likewise inside that ADR's frame of "verifiability is
  guaranteed by client verification" and contain no architecture-choice
  change

## 16. Review → fix loops (inside the PR. session-12 §12's format)

### Loop 1 (self-review right after drafting — 3 lenses: security / correctness · concurrency / spec · wire contract)

1. **[high] Rolling back the checkpoint's own reference (security)**: the
   initial draft's acceptance also allowed "notarizing a past
   manifest_version", so a malicious or careless **current member** could
   append a checkpoint notarizing an old state, lowering the detection
   reference for floorless clients (the detection mechanism's reference
   itself gets rolled back — a trap-7 variant). → Added the consensus rule
   `checkpoint-regression` (manifest_version non-regression against the
   most recent prior checkpoint containing the same environment —
   reconcilable on payload public values alone = client-verifiable). The
   per-variable non-regression of values_digest's contents cannot be
   checked by chain verification due to digest opacity, but that class
   (colluding server + current member) holds regular push permission and
   reduces to G9 (noted in §6.4)
2. **[high] Reference loss via a checkpoint not containing an environment
   (correctness)**: taking "the latest checkpoint op" as the consumption
   reference lets appending a subset checkpoint (valid under consensus
   rules) erase other environments' references. → Changed the reference to
   "the latest checkpoint containing an entry for that environment" (§6.3)
3. **[high] Forward injection to floorless clients undetected
   (security)**: under the initial consumption rule (only version /
   manifest_version non-regression), an old-epoch key could forge "the
   next version / manifest_version past the snapshot" and pass a floorless
   client undetected (no check analogous to floor rule (c)). → Added to
   §6.3 "versions newer than the snapshot · manifest_versions newer than
   the reference have epoch ≥ the reference's epoch" (the checkpoint
   version of floor rule (c)). The argument for the reference point's
   soundness is identical to floor (c)'s; the false-rejection
   counterexample (a legitimate old-epoch value after rotation but before
   re-encryption) is already excluded by "not applying it to versions at or
   below the snapshot"
4. **[medium] Acceptance-verification complexity and concurrent races
   (correctness · contract)**: the initial option (allow notarizing past
   state + bundle the preimage on the wire + per-variable monotonicity
   checks + active-set coverage checks) had bloated the acceptance rules
   to 4 stages just to avoid racing a concurrent push. → Simplified to an
   exact match against stored state at acceptance time (the server
   reconstitutes the preimage; a race is 422 → re-fetch · re-sign — the
   same existing structure as the chain CAS 409. Only the audit head gets a
   "membership" check — since the chain append itself writes the mirror
   row, latest-equality would self-race)
5. **[low] group**: made explicit that manifest acceptance places no
   acceptance-time epoch-independence check (the rotate composite's
   manifestVersion CAS substitutes — AUTH_SPEC §12-5. Same shape as the
   "acceptance is current-epoch only" implied note) / wrote the
   client-verification rules for distributed attestations into §6.6 (key
   selection · tenure · head reconciliation) / noted the accumulated
   hash's introduction migration (initialize by recomputation from
   existing rows) in AUDIT §5.1 / appended the "up to the checkpoint
   point" qualifier to §14.3-3

### Loop 2 (re-verifying the fixes)

Re-scanned loop 1's fixes under the 3 lenses and confirmed no new findings
(zero blocking):

- Security: re-confirmed that the verification chain (§6) gained no reverse
  dependency, that `checkpoint-regression` is always satisfiable by the
  honest flow (refreshing the view before issuance), and that the
  epoch-reference check has no false-rejection counterexample
- Correctness · concurrency: confirmed that the acceptance-time-match
  retry loop converges finitely (the racing counterpart is a low-frequency
  meta operation · push — the same optimistic retry as the chain CAS) and
  that the audit-head membership check doesn't self-race
- Contract: confirmed consistency of cross-references among the 3 specs
  (CRYPTO §4.3/§6.2/§6.3/§6.4/§6.6 ↔ AUTH §12/§16 ↔ AUDIT
  §3.4/§5.1/§6/§8) and the separation of the error reason-code namespaces
  (ChainInvalidReason vs API typed errors)

### Loop 3 (after PR #80 went public — pullfrog review response. 2026-08-18)

pullfrog detected ⚠️ 2 items · 4 line comments · 3 nitpicks. All were valid
and were fixed:

1. **[high] The manifestVersion row cap contradicts the PR #31 ruling
   (line comment)**: the initially drafted "100,000 rows / environment"
   cap — with 1,000 variables × renames, the environment-shared counter
   would exhaust itself while each variable stayed within its metaVersion
   budget, **permanently blocking even delete operations** (a replay of the
   shape PR #31 explicitly rejected with the metaVersion cap). The fix is
   the strong form of pullfrog's proposal (b): on close inspection of the
   verification paths, prev checks · distribution · checkpoint acceptance
   all reference only the latest manifest — **the server's retention is
   specified as latest-only; since rows don't accumulate, the cap itself
   was retracted** (AUTH_SPEC §12-5 / §12-8). The asymmetry vs meta
   statements (every metaVersion retained) is noted as intentional
2. **[high] The warning branch for an uninitialized manifest is a mitigation
   path the attacker can choose (line comment)**: a client can't distinguish
   "uninitialized" from "the server suppressed it" — the branch becomes a
   downgrade path for manifest-hiding (the very attack this mechanism must
   close). And in a pre-release introduction there is no population for the
   branch to protect. → Consolidated to missing = reject (§6.3).
   Initializing existing dogfooding environments is in PR-M1's migration
   procedure (§14)
3. **[medium] The duplicate-environment_id discipline contradicted itself
   across the 3 documents (line comment)**: consensus rule = MUST reject;
   the payload-generation sentence = SHOULD set; the notes = even ascending
   order normative — three different readings. Since the entry carries
   tuples, under set semantics the reference · regression comparison target
   would be non-deterministic — unified to **duplicate = MUST reject,
   ascending = generation SHOULD** (verification does not norm ordering)
   (§6.2 · these notes §5-2)
4. **[medium] Eliding the snapshot listing is a path that voids rule 2
   (line comment)**: the existence of a reference checkpoint can be judged
   server-independently from the verified chain, yet the handling of a
   response missing the listing was unspecified and a "skip" reading was
   possible. → Wrote explicitly "a value-bearing distribution of an
   environment that has a reference but lacks the listing is rejected"
   (§6.3)
5. **[medium] The manifest row on environment deletion and checkpoints to a
   deleted environment were unspecified (overall comment)**: marked
   manifests · snapshots explicitly as cascade targets in §12-4 (subjects
   of the "freed on deletion" principle). A checkpoint containing a deleted
   environment is rejected at acceptance (`environment-deleted`) — also
   noted explicitly that **this cannot be a consensus rule** since the
   chain does not observe the deletion (§6.4). An issuer includes no
   environment whose verified deletion statement exists (§6.3)
6. **[low] group**: appended to §12-5 the implementation note that a
   per-environment manifestVersion CAS serializes concurrent meta
   operations (batch submissions run sequentially) / resolved in AUDIT
   §5.1's row_digest the issue that NULL and the empty string collapse into
   the same preimage, via tagged byte strings (NULL = `0x00`, non-NULL =
   `0x01` + value) / fixed a kanji typo in these notes

### Loop 3 round 2 (re-review of b85a64d — confirming the previous 8 items resolved + new ⚠️ 2 · ℹ️ 3)

1. **[high] Staleness replay of the audit head**: none of the acceptance
   verification (membership only), the consensus rules (manifest_version
   only), or the payload (no seq — C1 compliant) forced the notarization
   point's **advancement**, so a malicious server could keep returning a
   real old h_k on audit-head fetches and pass every checkpoint's
   reconciliation while remaining able to tamper with everything after row
   k indefinitely. → Extended admin reconciliation to "membership +
   position" (AUDIT_SPEC §6): the notarized head's position must not
   regress across checkpoints and must be **at or above the immediately
   preceding checkpoint's own mirror row (chain.checkpointed)** — since a
   checkpoint append itself writes the mirror row, the protected prefix
   advances monotonically. No seq added to the chain · wire (compatible
   with C1); the check completes on the admin side. §14.2-7 · the §10
   table · 13-5 followed
2. **[high] The coverage norm was missing**: with only "a subset is fine"
   (consensus rules) and "don't include deleted environments" (issuance),
   a straightforward implementation of the rotate trigger would become
   "notarize only the environment operated on", and workload-only
   environments (where no member's interactive sync ever runs) would
   permanently never get a reference — the "detect" premise of §10's table
   had no norm behind it. → Added "include every (non-deleted) environment
   in the verified view" to the issuance SHOULD, and floorless clients
   (workloads in particular) warn on a value-bearing distribution of an
   environment with no reference (reference existence is judgeable from the
   chain server-independently — silently tolerating its absence would
   invisibly disable the main guarantee)
3. **[medium] The timing of issuance trigger (i)**: right after a rotate is
   the concentrated interval of re-encryption pushes, which self-races the
   acceptance-time-match check. → Rewrote (i) as "after rotate and the
   attendant re-encryption complete" (the re-encryption writer = the rotate
   performer, so same-client serialization can't collide), and noted the
   boundedness of retries
4. **[low] group**: the leftover "warning on uninitialized environment" in
   these notes' 13-5 (it had become an instruction to re-introduce the
   branch the body deleted) replaced with "missing manifest = reject" /
   added a consensus-rule-layer-only note to 13-1's "notarizing a past
   manifest_version" vector (the acceptance layer rejects via
   acceptance-time matching — pinned the layer distinction into the
   vector's intent) / fixed the missed kanji typo (:115) and a kanji typo
   inside the resolution record itself

### Loop 3 round 3 (re-review of 22f5cb9 — Bugbot Medium 1 + pullfrog ⚠️ 1 · ℹ️ 2. Same root)

1. **[high] Position check (c) turns a benign concurrent issuance into a
   false tamper accusation (Bugbot / pullfrog same root)**: the
   reconciliation position check added in round 2 had no provision forcing
   its satisfiability on either the issuance or the acceptance side —
   trigger (iii) can fire simultaneously in multiple members, and if an
   honest issuer who lost the CAS re-signs with "only the data-layer view
   re-fetched · the audit-head attestation still old", it passes acceptance
   (membership only) and a (c) violation gets permanently pinned into the
   chain (no retry path). → **Added a position floor to acceptance
   verification (§6.4)** (`audit-head-stale`: attested position ≥ the
   immediately preceding checkpoint's mirror row — under an honest server
   (c) is structurally always satisfied. A benign race routes to a typed
   rejection at acceptance → re-fetching the attestation), marked the
   audit-head attestation as a refresh target on issuance · retry (§6.3),
   and separated reconciliation (b)(c) violations' semantics from "row
   tampering" as "evidence of a server not executing the acceptance policy
   (a state permitting staleness replay)" — distinct from a membership
   violation (AUDIT_SPEC §6)
2. **[medium] The composition of all-environment coverage ×
   acceptance-time matching × bounded retry (pullfrog)**: with coverage
   spanning all environments the race surface expands to the whole
   project, and behavior when the bounded retry is exhausted was
   unspecified. → Added the escape path "issuance over the subset of
   environments whose acceptance-time agreement could be confirmed is
   allowed" to §6.3 (§6.2 treats a subset as valid, and a partial reference
   is strictly stronger than zero reference). Restated the race-probability
   basis in §6.4 from "checkpoint frequency" to "issuance duration ×
   project-wide write frequency"
3. **[low] The test intent of 13-5 (pullfrog)**: to the enumeration, which
   had only assumed "non-advancing notarization = malice", appended that a
   benign race is rejected at the acceptance stage (the acceptance-policy
   layer — not vectorized)

### Loop 3 round 4 (re-review of 6e9c2fb — automated security review MEDIUM 1)

1. **[medium] Opening `GET /audit-head` to member is a timing side
   channel**: the accumulated hash itself is random-looking and carries no
   ordinal, but **polling for changes** leaks "audit-row appends unaccompanied
   by a visible class-1 event = class-2 (var.read etc.) activity windows"
   to below-admin — a circumvention of the visibility boundary the C1
   ruling protects. → Changed audit-head fetch · notarization to
   **admin-only** (AUTH_SPEC §16-2 / CRYPTO_SPEC §6.2 · §6.3 / AUDIT_SPEC
   §6. Added as ruling-needed §12-11). The checkpoint issuance permission
   itself (member — ruling-needed §12-7) is unchanged, and issuance by
   below-admin carries audit_head_hash = empty string (no notarization —
   data-layer notarization is independently valid). Since audit-head
   reconciliation could only ever be done by admin, moving the
   notarization's carrier to admin doesn't change the reconciliation's
   carrier (admin is the all-rows-viewing principal anyway, and this
   response carries no new info). The reconciliation · acceptance position
   checks are reorganized to apply to "notarizing (non-empty) checkpoints"

### Loop 3 round 5 (re-review of fe7b408 — pullfrog ⚠️ 1 · ℹ️ 1 + Bugbot Medium 2 + collecting round 4's pullfrog ℹ️ 2. Same root = the ripple of going admin-only)

1. **[high] Trigger (iii) doesn't distinguish notarizing from
   non-notarizing; member issuance kills admin's trigger (pullfrog /
   Bugbot same root)**: since member issuance (no notarization) also
   resets the timer as "the latest checkpoint", in a project where members
   sync more frequently than admins, (iii) never fires for admin and the
   notarized prefix stalls — routine operations by active members alone
   can leave the audit-tamper window open forever. → **Split (iii)'s
   reference by effective permission** (admin = "the latest notarizing
   checkpoint", others = "the latest checkpoint" — §6.3), and noted "the
   prefix's advancement depends on admin issuance frequency" as an
   explicit residual in AUDIT_SPEC §6 · these notes §10 (fixing an
   overclaim — Bugbot Medium 2)
2. **[medium] The issuance · retry rules instructed every issuer to fetch
   the audit head (Bugbot Medium 1)**: even after going admin-only, §6.3
   unconditionally wrote "refresh / re-fetch the audit-head attestation",
   so a compliant member client would hit a 403. → Conditioned fetching ·
   re-fetching on "only when notarizing [effective-permission admin]"
3. **[medium] Mismatched determination axes (pullfrog nit)**: "below-admin
   issuer" (the role axis) and authorization (scope × role) were out of
   alignment — the reading had a role-admin × write-scope token hitting
   403 before falling back. → Unified on **effective permission
   (min(token scope, chain role) — AUTH_SPEC §9-2)** (clients can
   pre-determine). **This round's unification missed 3 places and was
   collected in rounds 6–7** (round 7 also corrected that the original
   record had claimed "unified everywhere", broader than actual — a record
   claims only the range actually unified)
4. **[low] The refresh order (collecting round-4 pullfrog nit)**: fetching
   the audit-head attestation first would drop into acceptance's
   `audit-head-stale` on someone else's checkpoint landing in between. →
   Noted in §6.3 "the attestation is fetched after the chain head (CAS
   parent) settles" (makes audit-head-stale practically unreachable for
   honest clients = purifies it into a server-fault signal)
5. **[low] The position floor's base case (collecting round-4 pullfrog
   nit)**: a project's first checkpoint has no "immediately preceding
   entry". → Noted "when none exists, no check is imposed (vacuously
   true)" in both §6.4 and AUDIT_SPEC §6 (acceptance and reconciliation
   being the same predicate · same base case is the soundness basis)

### Loop 3 round 6 (re-review of 3326666 — Bugbot Medium 2. Missed follow-ups of the effective-permission unification)

1. **[medium] AUTH §16-2's retry wording was still unconditional**:
   CheckpointStateMismatch's retry still instructed every issuer to "also
   re-fetch the audit-head attestation", leaving a reading where a
   non-notarizing issuer (member / write scope) hits a 403. → Conditioned
   on "a notarizing, effective-permission-admin issuer also [re-fetches]"
2. **[medium] CRYPTO §6.2's empty-string explanation was still on the role
   axis**: the wording "below-admin issuer" remained. → Unified on
   effective permission (min(token scope, chain role)) (a miss of round-5
   finding 3)

### Loop 3 round 7 (re-review of 6f39996 — pullfrog ℹ️ 1)

1. **[low] AUTH §16-2's "only audit_head_hash transcribes the attested
   value" was still unconditional (the last miss of round-5 finding 3)**:
   the sentence only landed on the effective-permission-admin limit when
   read together with the neighboring bullet. → Conditioned on "an
   effective-permission-admin issuer transcribes … (others: empty
   string)". Also corrected that this §16's round-5 record had claimed
   "unified everywhere", broader than actual (3 places remained) — a
   record claims only the range actually unified, since the notes are the
   basis material of the follow-up implementation PRs

### Loop 3 round 8 (final consistency review before owner confirmation)

The normative spec was consistent in its post-review-fix form, but the
first half of these notes' design conclusions and §15's landing list still
carried draft-time descriptions. To keep the follow-up implementation from
reading the stale explanations as procedures, the following were synced to
the current spec:

1. Changed the issuance trigger from after-rotate-success to **after
   rotate + re-encryption complete**, and reflected trigger (iii)'s
   effective-permission-split reference · all-environment coverage ·
   subset escape
2. Updated audit-head acceptance from membership-only to **membership +
   position floor**, and reflected the fetch order · `audit-head-stale`
   retry
3. Updated the audit notarization to effective-permission admin only, no
   notarization = empty string, and the residual that the notarized
   prefix's advancement depends on admin issuance frequency
4. Corrected the retracted manifest row cap to **latest-only retention ·
   no cap**
5. Made explicit that notarizing a non-empty audit head is a chain-role
   admin+ consensus rule + an effective-permission-admin API acceptance
   condition, and the vector plan followed
6. Updated the remove + rotate handoff and the M2/M3 split to the current
   spec: a checkpoint is an independent append after re-encryption;
   snapshot storage is M2's acceptance responsibility
7. Updated AUTH §6's token scope to checkpoint empty = write / non-empty =
   admin, and refined §16-2's "pure chain op" to "no client-supplied
   companion data + the server-reconstituted snapshot is stored
   atomically"
8. Marked the chain-bloat annual figure as an operating estimate based on
   the recommended triggers rather than a hard cap, and fixed the
   implementation-split reference at the top from §11 to §14
9. Added the rule · integration test that a subset checkpoint's snapshot
   upserts, in the same DO transaction, each environment's latest
   containing checkpoint while preserving non-included environments'
   references
10. Marked the M2 / M3 api-schema boundary and made precise M2's
    intermediate guarantee (meta completeness + acceptance · storage of
    the snapshot reference) and M3 (distribution · verification)
11. Refined ROADMAP's implementation split to M2 = acceptance-time
    snapshot storage / M3 = distribution · verification, and removed the
    resolved external chain-head checkpoint from "future"
