# maruhi Audit Log Specification (AUDIT_SPEC)

Version: 1.9-draft
Status: through 0.6, owner-approved (0.3 approved by the PR #18 merge on
2026-08-02. Adding the signer key FP to §3.3's `dek.registered` was approved as
CRYPTO_SPEC §5.1 in PR #21. §3.3's actor key FP extension to signed data
operations and §3.4's `chain.environment_created` were approved by the PR #27
merge on 2026-08-04 as a ripple of CRYPTO_SPEC 0.4-draft. 0.6 = §5.2 option A's
D1 implementation and §3.1's recording rules — session 21 on 2026-08-10,
approved by merge). 0.7-draft = drafting of Phase 2 feature rulings (2026-08-12
session 22): §3.2 invite.* / §3.5 revision for workload leases / §4.1
revoke_server variant input update / §6 visibility classes (resolving open item
#1) / §7 read API — **owner approval is by the merge of this revision PR**.
0.8-draft = Wave 2 B2 owner rulings (2026-08-15 session 25): §3.3
`rotation.recommended` / `rotation.dismissed` recording granularity, actor, and
dismissal authority; the `dek.deleted` auto-cleanup variant (AUTH_SPEC §12-6);
`var.version_pushed`'s re-encryption-marker payload / §4.1 step 5's exclusion
of marker-bearing pushes from resolution derivation (resolving a spec-internal
contradiction — automatic false resolution of all flags by re-encryption pushes
of mandatory rotation) / §7 dismissal operation endpoint — **owner approval is
by the merge of an implementation PR containing this revision** (PR #70 merged
= approved). 0.9-draft = Wave 2 C1 owner ruling (2026-08-16 session 26): §5.1
`row_id` column (wire row identifier = random value) / §7 read API's opaque
cursors and row identifiers and admin-only disclosure of `seq` (reconciling
§7's "not even by counts" with §6's "a gap = the trace of a deletion" —
resolving a pullfrog review finding) — **owner approval is by the merge of an
implementation PR containing this revision** (PR #71 merged = approved).
1.0-draft = Wave 3 D drafting (2026-08-18 session 27 — design exploration in
docs/notes/session-27.md): §3.4 `chain.checkpointed` / §5.1 audit-head
cumulative hash / §6 post-hoc tamper detection via checkpoints and the decision
not to eventize head declarations / §8 resolution of open item #2 (integrated
into CRYPTO_SPEC §6.2 `checkpoint`) — **owner approval is by the merge of this
revision PR**. 1.1-draft = W3a (2026-08-30): clarification of §3.1
`auth.token_revoked`'s actor (actor = the executing principal, the target id is
in the payload — accompanies AUTH_SPEC §6's introduction of designated
revocation. No new event is added) — **owner approval is by the merge of an
implementation PR containing this revision**. 1.2-draft = drafting of S0
(value-less schema — CRYPTO_SPEC 0.8-draft / AUTH_SPEC 0.16-draft) (2026-08-30
session 46): §3.3 `project.schema_policy_changed` (AUTH_SPEC §12-11) and a note
on `var.created`'s declared creation — **owner approval is by the merge of this
revision PR**. 1.3-draft = resolving the audit divergence of schema reissuance
(2026-09-01 owner ruling — PR #121 / #123 handoffs. Candidate comparison in PR
#125's handoff-handling thread): newly adding §3.3 `var.schema_reissued`
(meta-statement reissuance with unchanged name — previously recorded as
`var.renamed`, an operation that did not rename was claiming the name
"renamed"). Rejected options = widening `var.renamed`'s meaning (the event name
would misstate the fact forever) / normalizing to a unified event
`var.meta_reissued` (a vocabulary break with past rows) / a payload flag only
(the name's lie remains) / read-side reclassification (a standalone audit row
cannot determine whether a rename happened — the only place where the
determining material exists is the server at write time) — **owner approval is
by the merge of an implementation PR containing this revision**. 1.4-draft =
drafting of H1 (signup control — AUTH_SPEC 0.18-draft §3) (2026-09-01): newly
adding §3.1 `auth.signup_denied` (recording signupPolicy-based rejection of new
creation — material for H3's "counting signup rejections" tripwire; follows
`auth.login_failed`'s fixed-window cap discipline) and adding `signupInviteId`
to the `auth.user_created` payload (cross-check material for creations caused
by invite-code consumption) — **owner approval is by the merge of an
implementation PR containing this revision**. 1.5-draft = audit-log growth
density measure ② (2026-09-02 owner decision — early resolution of open item
4. H0 [docs/notes/hosted-design.md §3-3] had placed aggregation "after
dogfooding measurements", but it is designed and implemented without waiting
for measurements): revising §3.3 `var.read`'s recording granularity from "1 row
per variable" to "1 row per environment per with-values bulk pull (payload
enumerates the returned variables)" (aggregate form) / stating the §4.2 Q3・Q4
index requirements' dependence on payload enumeration / §5.3's quantity
description / §8 resolution of open item 4. Revised together with AUTH_SPEC
0.20-draft §12-7 / §12-8 — **owner approval is by the merge of an
implementation PR containing this revision**. 1.6-draft = drafting of KL3
(master-key wrap ledger — CRYPTO_SPEC 0.9-draft §8 / AUTH_SPEC 0.21-draft
§13-6–13-10) (2026-09-12. Design record in docs/notes/integration-options.md
supplement 19): adding the 9 events `auth.key_wrap_*` / `auth.guardian_*` /
`auth.key_handoff_*` to §3.1 (the existing `auth.recovery_*` are unchanged).
The design's 13 items are owner-approved as of 2026-09-12 — **approval of the
spec wording is by the merge of an implementation PR containing this
revision**. 1.7-draft = IV (2026-09-13. Design record in
docs/notes/integration-options.md supplement 21): a note on §3.2
invite.accepted (payload unchanged; the backing source's login is not written).
No events added — **approval of the spec wording is by the merge of an
implementation PR containing this revision**. 1.8-draft = ES + PF1 (2026-09-14
— CRYPTO_SPEC 0.11-draft / AUTH_SPEC 0.23-draft. Design record
docs/notes/es-design.md, drafting-time drafts docs/notes/es-spec-drafts.md):
§3.3 `rotation.recommended`'s trigger / §3.4's mirror-payload scope and the 4
four-eyes kinds with the applied rows / §4.1's per-environment access windows
and the change_role variant / §6's visibility classes unchanged. The design's
24 items are owner-approved as of 2026-09-14 — **owner approval is by the merge
of this revision PR**. **K3 addendum to 1.8-draft (2026-09-15 — the server's
scope enforcement, design record es-design.md §9)**: add `chain.role_changed`
to §4.2 Q1's enumeration (a description correction of an index requirement —
Q1's row still had the old enumeration even though §4.1 step 2 requires
role_changed's payload to restore the windows and §3.4 already marks it ★ —
not a consensus rule. Indexes unchanged) — **owner approval is by the merge of
an implementation PR containing this addendum**. 1.9-draft = DK (device-key
separation — 2026-09-19. CRYPTO_SPEC 0.12-draft / AUTH_SPEC 0.24-draft. Design
record docs/notes/dk-design.md, drafting-time drafts
docs/notes/dk-spec-drafts.md): §2's note that key FP = device / §3.1's 3 event
descriptions converted to reserve key (event names unchanged) / §3.4's
`chain.device_added` / `chain.device_revoked` / §4.1's `revoke_device` variant
(interval narrowed by device windows; (a) checks user_id — the drafting-time
"check by actor key FP" was corrected in K1 review because `var.read` carries
no FP. A partial correction of approved item 8, design record dk-design.md §6
K1-12) / §4.2 Q1's enumeration / §6's classes unchanged. The design's 16 items
are owner-approved as of 2026-09-20 (design record §4) — **approval of the spec
wording is by the merge of this revision PR**

This document defines the design of maruhi's audit log (what / who / when).
It presumes CRYPTO_SPEC (especially §6 membership log, §7 rotation-needed
detection) and AUTH_SPEC (§2 data model).

---

## 1. Purpose and design principles

1. **Rotation-needed detection must work** (most important): when a member is
   removed or a server is revoked, "the (variable × environment) set that
   principal could have viewed" must be computable from the audit log
   (CRYPTO_SPEC §7). The schema is designed backward from this query
   requirement (§4)
2. **Identity rule (absolute)**: events identify their subject and target by
   **internal user_id and key fingerprint (+ maruhi-issued API token id)
   only**. GitHub ID / provider_user_id / provider login / email address must
   never be written to the audit log (CLAUDE.md. An append-only structure
   cannot be rewritten and must be independent of the authentication
   provider). The authentication means's **kind name** (`github_oauth` /
   `cli_handoff` / the old `device_flow` [replaced by the 2026-08-31 AUTH_SPEC
   §4 revision — remains valid as a historical value on existing rows] etc.;
   the same vocabulary as AUTH_SPEC's auth_method) may be recorded
3. **No secrets**: do not include plaintext values, ciphertexts, nonces, or key
   material in events. Variable names are plaintext metadata in v1 (CRYPTO_SPEC
   §4), so a snapshot may be included in the payload for UI convenience
4. **append-only**: no API updates or deletes audit events. The repository
   service exposes only append and read (enforced at the ImportLint boundary).
   Corrections are expressed by appending cancellation events
5. **The chain is the source of truth, the mirror is derived**: the source of
   truth for membership operations is the signed chain (CRYPTO_SPEC §6). The
   audit log's chain mirror (§3.4) is derived data for unified querying; on
   contradiction the chain wins. The mirror must be reconstructible from the
   chain

## 2. Actor model

Every event has an `actor`:

```
actor: {
  type: "user" | "server" | "system",
  user_id?,             // type=user: internal user_id (ULID)
  key_fingerprint?,     // type=user: user key FP / type=server: server key FP (CRYPTO_SPEC §3)
  api_token_id?,        // when the operation went through an API token. Never the raw token or its hash
  auth_method?          // when the operation went through a session (kind name only, e.g. "github_oauth")
}
```

- `type=server`: an operation by a server (deployment keypair) disclosed via
  grant_server. Has no user_id
- `type=system`: internal processing with no principal, e.g. expiry handling.
  Do not overuse (as a rule, an event has a human or a server)
- The key FP matters as evidence of "the key that user_id was using at that
  point" (after a recovery re-wraps keys, past events keep the FP of their
  time)
- **The key FP identifies the device (2026-09-19 DK)**: after the introduction
  of device keys (CRYPTO_SPEC §3), `key_fingerprint` identifies "the device
  that user_id used for that operation at that point". The actor has no
  separate device field (the identifier stays user_id + key FP — §1-2
  unchanged)

## 3. Recorded events

Event names are `domain.verb` form. ★ = an input to rotation-needed detection
(§4).

### 3.1 Auth events (user / session / token)

| Event | Main attributes | Notes |
|---|---|---|
| `auth.login_succeeded` | auth_method | Web OAuth / CLI login (handoff) approval completed (2026-08-31 AUTH_SPEC §4 revision: `device_flow` → `cli_handoff`. The old value on existing rows remains a historical value) |
| `auth.login_failed` | auth_method, reason kind | State mismatch, verification failure, etc. The presented external ID is **not recorded** |
| `auth.signup_denied` | auth_method, reason kind (`policy-closed` / `invite-required` / `invite-invalid`) | signupPolicy-based rejection of new creation (AUTH_SPEC §3 — 2026-09-01 H1). GitHub auth succeeded, but the presented external ID is **not recorded** (§1-2 — no internal user_id exists at rejection time). The actor is type=user without user_id, same as `auth.login_failed` |
| `auth.session_revoked` | target session id | Explicit logout / server-side revocation |
| `auth.token_created` | token_id, name, scopes | |
| `auth.token_revoked` | token_id | |
| `auth.identity_linked` / `auth.identity_unlinked` | provider kind name only | provider_user_id / login are **not recorded** |
| `auth.recovery_blob_fetched` | — | Fetch of the wrapped reserve key (formerly the master private key — 2026-09-19 DK. Event name unchanged) (CRYPTO_SPEC §8. A security-critical event to monitor) |
| `auth.recovery_code_reissued` | — | Reissuance (includes deleting the old wrap) |
| `auth.key_wrap_registered` | kind (`passkey-prf` / `guardian`), wrapId / groupId, mode, recipientCount | Registration into the reserve-key wrap ledger (formerly master-key wrap ledger — 2026-09-19 DK. Event name unchanged) (AUTH_SPEC §13-7 — 2026-09-12 KL3). actor = ward |
| `auth.key_wrap_removed` | kind, wrapId / groupId | Removal from the ledger. actor = ward |
| `auth.key_wrap_fetched` | kind, wrapId / groupId | Fetch of the wrap body of a passkey / guardian group (**monitor** — same rank as `auth.recovery_blob_fetched`). actor = ward |
| `auth.guardian_designated` / `auth.guardian_released` | groupId, mode, shareIndex | Designation / release of a guardian. actor = ward, **target = guardian** (also appears on the guardian's own axis). One row per segment |
| `auth.guardian_share_fetched` | groupId, shareIndex | A guardian fetched the segment addressed to them (**monitor**). actor = guardian (user_id + key FP), target = ward |
| `auth.key_handoff_requested` | requestId | Creation of a handoff request. actor = ward |
| `auth.key_handoff_approved` | requestId, source (groupId — `device` was removed in 2026-09-19 DK. `device` on existing rows remains a valid historical value), shareIndex | Acceptance of an approval (**monitor**). actor = approver (user_id + key FP = the device used for the approval), target = ward |
| `auth.key_handoff_collected` | requestId, approvalCount | The requester obtained one or more approvals **for the first time** = the fact that a restoration happened (once per request; not recorded on each polling response — AUTH_SPEC §13-6 `collected_at`). actor = ward |
| `auth.user_created` | — | A fresh creation by getOrCreateUser. A creation consuming a signup invite code (AUTH_SPEC §3's `invite` — 2026-09-01 H1) copies `signupInviteId` (the internal ULID of the consumed invite row — not an external identifier) into the payload, allowing a cross-check against the invite row's `used_by_user_id` |

- **Recording rules for the 9 KL3 events (2026-09-12 — `auth.key_wrap_*` /
  `auth.guardian_*` / `auth.key_handoff_*`)**: visibility follows the user
  axis (§6) — a person can read rows where the actor or the target is them (a
  guardian can trace in their own audit what they were designated for and what
  they approved; a ward can trace whom they designated and who approved). The
  identity rule (§1-2) is unchanged — guardians, wards, and approvers are all
  internal user_id + key FP, and display snapshots like `wardLogin` exist only
  in API responses, never written to audit rows. They do not participate in
  rotation-needed detection (§4) (events outside any project). 429 / 404
  rejections are not recorded (AUTH_SPEC §13-10)
- `auth.session_created` is not a separate event because it is 1:1 with
  `auth.login_succeeded`. A Web login's `auth.login_succeeded` copies the
  session id into the payload (the same hash as the stored id — not the raw
  value — AUTH_SPEC §10), allowing a cross-check against `auth.session_revoked`'s
  target session id (2026-08-10)
- `auth.session_revoked` is **explicit revocation only** (logout / server-side
  revocation). Cleanup of expired rows (on resolve, by cron) is not a
  revocation event and is not recorded (2026-08-10)
- `auth.login_failed`'s actor is **type=user with no user_id** (an external
  principal that exists but could not be identified. type=system is for
  principal-less internal processing and is not used for failed attempts — §2)
  (2026-08-10)
- `auth.login_failed` is recorded **with a fixed-window cap** (100 rows per
  hour; excess is not recorded. Best-effort): this event is the only write from
  an unauthenticated path, and the cap bounds D1 write amplification
  (availability / cost attack) by a flood of invalid requests. The flood itself
  is observable as the window reaching its cap, and the event is not an input
  to rotation-needed detection (§4), so SHOULD-record suffices (2026-08-10
  session 21, security-review response)
- The cap is counted in **buckets of `auth_method + reason`** (2026-08-24
  deepsec R4 / 2026-08-27 S5 response): a single frame shared by all actors, or
  a frame keyed by `auth_method` alone, would let an anonymous flood on one
  path or reason silently erase failures of another reason. Current failures
  happen pre-auth and carry no target user_id; the only distinguishable
  classifications an individual row carries are `auth_method` and `reason`, so
  the product of the two becomes independent frames and **does not make
  mutually invisible the attack shapes the audit inherently has**. Attempts
  within the same reason carry no distinguishable target information to begin
  with; post-suppression volume is carried by the reason-marked marker below.
  **Per-origin** (IP / a hash of it) counting remains not adopted — it would
  mean "holding origin identifiers in extra state for the limiter" and breaks
  §1-2's line
- **`auth.signup_denied` recording discipline (2026-09-01 H1)**: follows the
  same fixed-window cap discipline as `auth.login_failed` (a write from an
  unauthenticated path; bounds D1 write amplification by a flood of rejections
  — SHOULD-record). Buckets are per `event name + reason` (an independent
  frame per denial reason — the same "don't blind mutually the attack shapes
  the audit inherently has" argument as login_failed's `auth_method +
  reason`). On windows that hit the cap, an `auth.signup_denied_suppressed`
  marker row is left under the same powers-of-10 discipline as login_failed.
  Having no actor / target user_id, it never appears in the self-axis read
  (§7); visibility is the operator view (direct D1 access) — H3's tripwire
  "counting signup rejections" counts these rows
- Counting uses a **dedicated counter row**, not a scan of the audit log
  (one row of mutable state per bucket; §1-4's append-only is a discipline of
  the audit table, and this counter is not an audit row) (2026-08-24 deepsec
  R5 response): counting the in-window `auth.login_failed` rows on each append
  would scan an ever-growing append-only table every time, making the very
  path meant to bound the flood a cost amplifier. Window reset, increment, and
  cap judgment are done atomically in **a single conditional UPSERT**
  (receiving the new count via `RETURNING`) — the same shape as the recovery
  fetch count (AUTH_SPEC §13-3)
- On a window that drops individual rows on cap, an `auth.login_failed_suppressed`
  row is left (2026-08-24 deepsec M4 / R4 response). To make auditable not only
  that suppression happened but **the amount and reason of suppression**, one
  row is left not per window but when the bucket's suppressed count reaches
  **1, 10, 100, … (powers of 10)** — writes are logarithmically bounded in the
  suppressed count (a few rows per window even under flood), and the row's
  density and last count reveal the suppression's scale. The payload carries
  only `auth_method`, `reason`, window length, cap, and the suppressed count at
  that point (this path does not grow §1-2's forbidden information either —
  external provider IDs, IPs). The actor is type=user with no user_id, same as
  the individual rows. "Auditable" here means, like `auth.login_failed`
  itself, **visibility in the operator view (direct D1 access)** — with no
  actor / target user_id it does not appear in the self-axis read (§7), and an
  operator-facing API is, like L-4 (SECURITY_REVIEW_2026-08-14), unimplemented
  and pending
- Token **use** is not eventized (high frequency, low information.
  api_tokens.last_used_at and data events' actor.api_token_id substitute)
- **`auth.token_revoked`'s actor (2026-08-30 W3a — clarification accompanying
  designated revocation)**: the actor is **the principal that performed the
  revocation**; the revoked token's id is carried by the payload's `tokenId`.
  In self-revocation (CLI logout — the presented token itself), the actor's
  token = the target, so `actor_api_token_id` and `payload.tokenId` match; in
  designated revocation (AUTH_SPEC §6 — a different token of a session
  principal, `*` × admin) they do not (a session-driven revocation copies
  auth_method into the payload per §2 and has no `actor_api_token_id`).
  Rejected designated revocations (uniform 404 / 403) are not recorded (1:1
  with rows that actually disappeared)
- Rotation of a same-named token (AUTH_SPEC §6's replacement) is expressed as a
  single `auth.token_created` row, and the deletion of the replaced old row is
  not made an independent `auth.token_revoked` (the issuance semantics is
  "replacement" — distinguished from explicit revocation) (2026-08-10). That
  one row, however, **carries the replacement's target**: the maruhi-issued
  token id of the vanished row is placed in the payload as `replacedTokenId`
  (2026-08-24 deepsec R6 response. On a fresh issuance the key itself doesn't
  appear = no replacement). Because the device exchange's `tokenName` is
  caller-chosen, a third party who stole a GitHub identity could specify the
  victim's existing token name and **silently disable that token** — with only
  the issuance row, "why it stopped working" cannot be reconstructed from the
  log. The id is picked up from inside the SQL of the audit append placed
  before the delete statement (adding a preceding SELECT would disagree with
  the row that actually vanished under a concurrent rotation between the read
  and the batch)

### 3.2 org events

| Event | Main attributes |
|---|---|
| `org.created` / `org.renamed` / `org.deleted` | org_id (personal-org auto-creation is recorded too) |
| `org.member_added` / `org.member_removed` | target_user_id, org role |
| `org.member_role_changed` | target_user_id, old/new role |
| `org.project_created` / `org.project_deleted` | project_id |
| `invite.created` / `invite.revoked` | project_id, invite id, role (2026-08-12 — AUTH_SPEC §15) |
| `invite.accepted` | project_id, invite id, target_user_id (acceptor), payload carries the accepting key FP. **2026-09-13 IV revision: acceptance involves a joint signature by the link key (AUTH_SPEC §15-2), but the payload is unchanged. The backing source (GitHub)'s login, the check result, the link public key, and the signature are not written (§1-2's identity rule. The check completes inside the client and is not reported to the server)** |

org roles do not participate in project access (AUTH_SPEC §9-2), so org events
do not participate in rotation-needed detection.

- Personal-org auto-creation (AUTH_SPEC §9-1) is recorded as `org.created`
  (payload `personal: true`) + an `org.member_added` of the self as owner. The
  org-name snapshot is **not** copied into the payload — a personal org's name
  derives from providerLogin and is §1-2's forbidden information (2026-08-10)
- **Invite events (2026-08-12 drafting — AUTH_SPEC §15)**: invite records live
  in D1 (acceptance is an operation by a project non-member), so invite.* is
  also placed on the D1 side and appended in **the same batch** as the
  issuance / acceptance / revocation record operation (§5.2's same-transaction
  principle). The project_id column references the target project. The project
  DO-side counterpart is the eventual `chain.member_added` (§3.4); the invite
  lifecycle itself is not doubly recorded in the DO. Visibility is at the same
  level as §6's class 2 (project admin or above)

### 3.3 Project data events ★

All recorded inside the project DO (§5). variable_id / environment_id are
CRYPTO_SPEC §4 identifiers.

| Event | Main attributes | Notes |
|---|---|---|
| `env.created` / `env.renamed` / `env.deleted` | environment_id, name snapshot, **actor_key_fingerprint** | Copies the author key FP of the meta statement (CRYPTO_SPEC §4.2) (2026-08-03. env.created is part of the 12-4 composite) |
| `var.created` ★ | variable_id, environment_id, variable-name snapshot, **actor_key_fingerprint** | Same as above + the writer signature of bundled version 1 (CRYPTO_SPEC §4.1). **Declared creation (no value — AUTH_SPEC §12-5. 2026-08-30) is also this event** (keeps the semantics that the existence interval starts at the acceptance of metaVersion 1): because no value signature exists, actor_key_fingerprint copies only the statement signature's author key FP, and the activation value push is recorded as `var.version_pushed` (version 1). An interval in which no version of a value exists at all is vacuous for rotation-needed detection (§4) (no readable value) and does not mislead detection |
| `var.version_pushed` ★ | variable_id, environment_id, version, epoch, **actor_key_fingerprint** | A value update (does not include plaintext or ciphertext). Copies the key FP of the writer signature (CRYPTO_SPEC §4.1) (2026-08-03) |
| `var.renamed` | variable_id, environment_id, new-name snapshot, **actor_key_fingerprint** | Copies the meta statement's author key FP (2026-08-03). **Only reissuances where the name actually changed** (2026-09-01 — a name-unchanged reissuance is `var.schema_reissued`. The branch is a byte comparison with the immediately preceding statement's name at acceptance). A reissuance that changes the name and the schema field simultaneously is also a single row of this event (the rename is the principal event — the name is the primary key of audit's main uses [name history, §4's existence intervals] — keeping the 1-operation-1-row recording discipline) |
| `var.schema_reissued` | variable_id, environment_id, variable-name snapshot (unchanged), **actor_key_fingerprint** | **Meta-statement reissuance with unchanged name** (added 2026-09-01 — in substance setting/changing the schema field: the schema field is the only field besides name that a reissuance can change — AUTH_SPEC §12-5). **The firing condition is only the name being unchanged; whether the schema field actually changed does not matter** (a no-change reissuance, and a same-name reissuance v1 → v1 that had no schema field, are also this event — the acceptance surface does not check content change [CAS, signature, policy only]; adding a diff check would require a third event for no-change reissuance or leave a recording gap. It is also not rejected at acceptance [422]: dropping a validly signed write on content goes the same direction as silencing an operation that leaves attribution evidence; recording a harmless no-op fits audit's character). Copies the meta statement's author key FP. The schema field's **content** (type, required, description) is not copied into the payload (creates no injection surface or bloat via the log — the source of truth for the change is the statement history). **Note on past rows**: servers before this 2026-09-01 revision recorded this operation as `var.renamed` (audit is append-only and past rows are not revised — `var.renamed` from that period may include name-unchanged reissuances) |
| `var.deleted` ★ | variable_id, environment_id, **actor_key_fingerprint** | Deleting does not erase past viewability (§4). Copies the deletion statement's author key FP (2026-08-03) |
| `var.read` ★ | environment_id, payload = { variables: [{ variableId, epoch, version }, …] } | Recorded for **ciphertext distribution** (pull / web fetch). **1 row per environment per with-values bulk pull** (2026-09-02 revision — aggregate form. Old form: 1 row per variable. The variable_id / epoch / version columns are NULL, and the payload enumerates the returned variables — recording rules below). **Metadata-only mode (AUTH_SPEC §12-7) distributes no ciphertext and is not recorded** (don't record as read what was not read — 2026-08-10) |
| `dek.registered` | environment_id, epoch, target_user_id (recipient), **actor_key_fingerprint (signer key FP)** | DEK-wrap registration (AUTH_SPEC §12-6. **Includes the bundled part of composite requests — epoch 1 of environment creation, the new epoch of rotation (same §12-4. 2026-08-03)**). actor_key_fingerprint copies the signer key FP of the registration signature (CRYPTO_SPEC §5.1) (for cross-check against the signature. Session 07 ruling B) |
| `dek.deleted` | environment_id, epoch, target_user_id (recipient) | Deletion of a poisoned wrap by an admin (AUTH_SPEC §12-6's repair path) |
| `rotation.recommended` | target_user_id (remove / demote / **shrink** variant) / target_key_fingerprint (revoke_server variant), variable_id, environment_id, payload = { basis, triggerChainSeq, **trigger** } | Persists the §4 computation result (for UI / CLI display). **1 row per (variable × environment)** (2026-08-15 clarification — from §4.2 Q5's index requirement. The set is not folded into one row). **`trigger` = `remove_member` \| `change_role` (demotion / shrink — 2026-09-14 ES) \| `revoke_device` (2026-09-19 DK — §4.1's variant) \| `revoke_server`**. Application via four-eyes carries the seq of the completed `approve` entry in `triggerChainSeq` (PF1) |
| `rotation.dismissed` | variable_id, environment_id | An explicit dismissal by a human (the append-only cancellation event). 1 row per target |
| `project.schema_policy_changed` | payload = { old value, new value } | Change of the project setting `schemaPolicy` (AUTH_SPEC §12-11. 2026-08-30). The actor is the changer themself (type=user — a setting operation with no signature, so no FP). The setting value itself is distributed to all members advisory-ly in pull responses, so class 1 |

- **`var.read`'s aggregate form (2026-09-02 owner decision — resolving open
  item 4. Brought forward without waiting for dogfooding measurements —
  docs/notes/hosted-design.md §3-3)**: the highest-frequency event due to
  scheduled pulls from CI; in the old form (1 row per variable) the row count
  grew as "pulls × variable count". The recording unit is revised to **1
  with-values bulk pull (per environment) = 1 row**:
  - **Columns**: environment_id (non-NULL). variable_id / epoch / version are
    NULL (per-variable coordinates are carried by the payload). The actor is
    the reading principal as before (type=user — no signature, so no FP)
  - **payload** = `{ variables: [ { variableId, epoch, version }, … ] }` — the
    **full enumeration** of variables returned with ciphertext in the
    response. epoch / version are the coordinates of the latest versions
    returned (material for rotation-needed detection's per-variable matching
    and for incident response [which version was fetched]). The enumeration is
    in **ascending order of `variableId` (code-unit comparison), no
    duplicates** (one pull returns each active variable at most once — no form
    exists where the same variable appears twice in one pull), and each
    element's key order is fixed at `variableId` → `epoch` → `version` (the
    stored byte string is the input of row_digest — §5.1. The only writer is
    the server, and this fixity is for the stability of recomputation [the
    parse → stringify round trip of `maruhi audit reconcile`])
  - **A pull returning 0 variables writes no row** (no ciphertext was
    distributed — the recording condition "ciphertext was returned in the
    response" is unchanged. The old form also wrote 0 rows)
  - **Do not split the row**: one row's payload is variable count × tens of
    bytes (with the 1,000-variable cap per environment [AUTH_SPEC §12-8], tens
    of KB — §5.3), inside the row size cap (2 MB). Splitting one pull into
    multiple rows of N variables is rejected — it would require every reader
    to reassemble "multiple rows of the same pull" and does not reduce Q4's
    payload-inspection volume. The size of a distribution (§7) page is `limit
    × payload`, controlled by the client via `limit`
  - **Does not degrade the input of rotation-needed detection** (ruling CZ's
    line — docs/notes/session-47.md. Aggregation is a density measure, not a
    row cap): "who read which version of which variable" is fully restorable
    from the payload — stronger than §3.5 `server.lease_issued`'s
    environment-level row (which derives the active variables at issuance
    time), because variable IDs are explicit. §4.1 step 3's (a) decides by
    expanding the aggregate row's enumeration (equivalent to the old form —
    the implementation PR pins this by test)
  - **Mixing with the old form**: rows written by pre-revision servers in the
    1-variable-1-row form (variable_id non-NULL, payload without `variables`)
    are not rewritten and not backfilled (§1-4). Old and aggregate forms
    coexist in the same table; the discriminator is **`variable_id IS NULL`
    (aggregate) / non-NULL (old)**. Every reader — §4's detection, §7's API
    filters (`variable_id` — Q4), Web, CLI (`maruhi audit list` / `verify` /
    `reconcile`), audit head — handles both forms
  - **Visibility stays class 2** (§6 — the self-view [actor is self] judgment
    is by the actor column and unchanged). **The audit head** (§5.1) digests
    aggregate rows as aggregate rows (does not affect the semantics of the
    existing cumulative-hash column or checkpoint notarization)
  - **Metadata-only pulls remain unrecorded; leases are unchanged**
    (`server.lease_issued` is already 1 row per environment — §3.5)
  - Density (workerd measurement — the implementation PR's test
    `audit-read-aggregate.test.ts`. Identifiers are the CLI's real issuance
    form, 25 chars; row + index): the old form is ~300 bytes per variable
    read. The aggregate form is ~250 bytes per pull + ~80 bytes × variable
    count (grows proportional to identifier length). Pulling a 100-variable
    environment once → old: 100 rows / ~30 KB; aggregate: 1 row / ~8.3 KB
    (row count 1/100, bytes ~1/3.6). AUTH_SPEC §12-8's "headroom accounting"
    (i) is updated with these values
- **`var.read` semantics (2026-08-10 session 20)**: the recording condition is
  "ciphertext was included in the response"; reads returning only metadata —
  name resolution, listing, etc. — are out of scope (AUTH_SPEC §12-7's
  metadata-only mode). This discipline protects the input purity of §4's
  "definitely fetched" rank (the presence/absence of `var.read` inside the
  membership interval) — if a member's resolve operations that fetched no
  value were mixed into `var.read`, rotation-needed detection would
  over-report "fetched" and mislead the human reading the audit log
- **Data events carrying actor_key_fingerprint (2026-08-03 session 12
  revision)**: data events' actors have in principle only user_id (+ token id
  / auth_method) and no key FP (FP is carried by the chain mirror §3.4); this
  exception is now generalized as the type "**operations accompanied by a
  client signature**" — in addition to `dek.registered` (registration
  signature = CRYPTO_SPEC §5.1. 2026-08-02 session 09), `var.version_pushed` /
  `var.created` (value-write signature = same §4.1) and `var.renamed` /
  `var.schema_reissued` / `var.deleted` / `env.created` / `env.renamed` /
  `env.deleted` (meta-statement signature = same §4.2) copy the signer key FP
  into the actor_key_fingerprint column. It records for cross-checking the
  audit row (server-managed data) against the off-chain signature (client
  signature = unforgeable by the server), within §2's actor model (type=user's
  key_fingerprint). `dek.deleted` is a signature-less operation and still
  carries no FP (this asymmetry preserves the semantics "FP = evidence of a
  signature" and is not flattened)
- `dek.registered` / `dek.deleted` granularity is **1 row per recipient**
  (2026-08-02 session 08 proposal): §5.1's column structure is 1 row 1 target
  (target_user_id is single-valued), and per-recipient rows let "when was the
  wrap for this recipient registered / deleted" be fetched directly via the
  index (target_user_id, seq). Registration is a low-frequency event (only on
  rotation / member addition), and the row count is bounded by AUTH_SPEC
  §12-8's wrap-row cap. It does not participate in rotation-needed detection
  (§4.1) (the candidate set is the per-environment access window derived from
  the chain mirror's scope — 2026-09-14 ES. Old: all members × all
  environments), but it preserves the evidence of "who received which epoch's
  DEK"
- "New version push" is also the resolution condition of the rotation-needed
  flag (§4 — **except pushes bearing the re-encryption marker** — below)
- **`var.version_pushed`'s re-encryption marker (2026-08-15 session 25 owner
  ruling — Wave 2 B2)**: the push request's `reencryption` declaration
  (AUTH_SPEC §12-5 — the writer's self-declaration; the server cannot verify
  it) is copied into the payload (`{ reencryption: true }`. Undeclared or
  false is not copied). §4.1 step 5's resolution derivation does not treat a
  marker-bearing push as resolution — CRYPTO_SPEC §7's mandatory rotation is a
  re-encryption of all active variables = comes with ordinary pushes, so
  without this exclusion the mandatory sweep run right after `remove_member`
  would auto-resolve all flags just recorded, breaking detection's purpose
  (prompting upstream credential rotation). Verifying "the upstream was
  actually rotated" is impossible in principle under E2EE (the server never
  sees plaintext), so the resolution signal is inherently a writer declaration
  — the marker corrects that declaration's granularity from "pushed" to
  "pushed a new value". The false direction is the safe side (§12-5)
- **`rotation.recommended` recording rules (2026-08-15 session 25 owner
  ruling)**: actor is `{ type: "system" }` (detection is a server-side
  derivation accompanying acceptance of a removal / revocation entry, not the
  remover's own act — the actor is held by the chain mirror recorded at the
  same time, cross-checkable via the payload's `triggerChainSeq`). The
  payload's `basis` is `"read"` (§4.1 step 3 (a) definitely fetched) |
  `"readable"` ((b) was fetchable). The `chain_seq` column is not used (per
  §5.1 it is the chain mirror's own — the trigger's chain seq is carried in
  the payload). The append is, per §4.1, in the same transaction as the
  acceptance of the removal / revocation entry (same discipline as the mirror
  — don't create a shape where a crash loses only the flags)
- **`rotation.dismissed` issuance authority and path (2026-08-15 session 25
  owner ruling — resolving a part §6 left unspecified)**: dismissal can be
  declared by **chain role admin or above × token scope admin** (same level as
  §12-3's wrap deletion — a governance operation accepting the risk of
  erasing a class-1 warning from all members without a real rotation). Per
  §7, no raw-event append API is created; a dedicated operation endpoint
  (enumerate one or more target (variable × environment); the server
  generates the event) is used. **A dismissal against a pair with no
  currently effective flag (§4.1 step 5's derivation) is rejected with 404**
  (the don't-silently-succeed discipline — don't pile a cancellation event
  whose discard target doesn't exist). The actor is the dismissing human
  (type=user)
- **`dek.deleted`'s auto-cleanup variant (2026-08-15 session 25 owner ruling —
  AUTH_SPEC §12-6's cleanup on re-add acceptance)**: the server's cleanup of
  wraps addressed to the old key accompanying an `add_member` acceptance is
  recorded as the same `dek.deleted` as the admin repair path, with actor
  `{ type: "system" }` + payload `{ cause: "member-readded", triggerChainSeq }`
  (a signature-less automatic process, so no FP — the semantics "FP = evidence
  of a signature" is unchanged. A human delete operation and mechanical
  invariant enforcement are distinguished by actor type)

### 3.4 Mirror of chain operations ★

On acceptance of a chain append (after passing server verification), the
corresponding audit event is appended to the same project DO. `chain_seq`
references the source entry, and the actor copies the chain entry's actor
(user_id + key FP) verbatim. Both the chain entry's client time and the
server's acceptance time are carried.

| Event | Corresponding op (CRYPTO_SPEC §6.2) |
|---|---|
| `chain.genesis` ★ | `genesis`. **target_user_id carries the creator (= actor.user_id)** (so the start of the creator's membership interval can be fetched via Q1's index) |
| `chain.member_added` ★ | `add_member` (target_user_id, role, **scopeKind, scopeEnvironmentIds** — payload. 2026-09-14 ES) |
| `chain.member_removed` ★ | `remove_member` (target_user_id) |
| `chain.role_changed` ★ | `change_role` (target_user_id, newRole, **scopeKind, scopeEnvironmentIds** — payload. ★ because **demotion / shrink is a detection trigger in §4.1**) |
| `chain.environment_created` | `create_environment` (environment_id. dek_commitment is copied into the payload — CRYPTO_SPEC §6.2. 2026-08-03) |
| `chain.epoch_rotated` ★ | `rotate_epoch` (environment_id, new epoch, reason. dek_commitment is copied into the payload — 2026-08-03) |
| `chain.server_granted` ★ | `grant_server`. **target_key_fingerprint carries the granted server key FP**; the scope (target environment set) is copied into the payload |
| `chain.server_revoked` ★ | `revoke_server`. **target_key_fingerprint carries the revoked server key FP** |
| `chain.checkpointed` | `checkpoint` (CRYPTO_SPEC §6.2. 2026-08-18). The payload copies the notarized digests (per-environment epoch / manifest_version / manifest_sig_hash / values_digest and audit_head_hash). **The audit seq and row count are not copied even into the payload** (same reason as §7's non-disclosure of counts — the chain payload itself is designed not to contain seq. CRYPTO_SPEC §6.2) |
| **`chain.approval_policy_changed`** | `set_approval_policy` (payload = { ops, requiredApprovals }. 2026-09-14 PF1) |
| **`chain.proposed`** | `propose` (payload = { innerOp, expiresAtMs }. The inner payload is not copied — the chain is the source of truth) |
| **`chain.approved`** ★ | `approve` (payload = { proposalChainSeq, completed: boolean }) |
| **`chain.proposal_withdrawn`** | `withdraw` (payload = { proposalChainSeq }) |
| **`chain.device_added`** | `add_device` (target_user_id = actor, payload = { deviceKeyFingerprint, roleCap, scopeKind, scopeEnvironmentIds }. 2026-09-19 DK) |
| **`chain.device_revoked`** ★ | `revoke_device` (target_user_id = the target, payload = { deviceKeyFingerprints }. ★ because **it is a detection trigger in §4.1**. 2026-09-19 DK) |

- **Four-eyes applied rows (2026-09-14 PF1)**: an `approve` entry that reached
  quorum (`completed = true`) writes, in addition to `chain.approved`, **the
  inner op's mirror row** (`chain.member_removed` etc. — the matching row of
  the table) **at the same chain_seq**, with payload carrying `{
  viaProposalSeq }`. The actor is the proposer (the inner op's actor). This
  discipline exists so that §4.1's input structures — membership intervals
  (Q1), grant intervals (Q6) — do not change. `maruhi audit verify`'s full
  bijection check becomes "1 entry ↔ 1 mirror row, except a completed approve
  adds + the inner op's applied row, 1 row" (a missing or extra applied row,
  or a `viaProposalSeq` mismatch, is a verification failure)
- **Device addition / revocation (2026-09-19 DK)**: 1 row per entry (bijection
  unchanged). `chain.device_added` is not a detection trigger, but Q1 reads it
  as the start point of §4.1's device window
- **Backfill (2026-08-02 session 07 ruling)**: mirror recording starts from
  entries accepted after the audit-log implementation is introduced. No DO
  holds a chain accepted before the introduction (unreleased), so v1 does not
  implement backfill of existing chains. If it becomes needed for a future
  schema migration etc., it is designed as a reconstruction process based on
  §1-5 (the mirror is reconstructible from the chain)

### 3.5 Server access via grant_server ★ (2026-08-12 revision — adapting to workload leases)

A record of the server actually exercising a disclosed DEK. The actor is
`{ type: "server", key_fingerprint }` (only `server.lease_denied` is an
exception — below).

| Event | Main attributes | Notes |
|---|---|---|
| `server.dek_unwrapped` | environment_id, epoch | The server decrypted a wrapped DEK (accompanying a lease issuance) |
| `server.lease_issued` ★ | environment_id, payload = { grant_chain_seq, claims_digest, epochs } | Issuance of a workload lease (AUTH_SPEC §14). **1 row per environment** (a lease distributes per environment; there is no per-variable selection). External identifiers (repository name etc.) are not written — the matched policy is held by the chain (the grant payload), cross-checked via grant_chain_seq + claims_digest (don't grow §1-2's forbidden information on the lease path either) |
| `server.lease_denied` | payload = { reason, claims_digest? } | **Only rejections after the OIDC signature verification passed** are recorded, under a global fixed-window cap (100 rows per hour; excess not recorded) — the same discipline as `auth.login_failed` (§3.1). The actor is `{ type: "system" }` (an external workload with no maruhi-side identity, and not a server-key exercise either). reason includes the first-come-binding violation `token-replayed` (AUTH_SPEC §14-1 — 2026-08-15 ruling) — because this row's claims_digest is identical to the legitimate workload's issuance row, the owner can cross-check **which workload's token was stolen** |
| `server.value_decrypted` ★ | variable_id, environment_id, epoch, version | **Reserved (does not occur in the v1 lease path)**: in a lease the server does not decrypt values (CRYPTO_SPEC §9.1). Enabled if a push-type sync add-on is introduced (future — requires a ruling on the libsodium exception). 1 row per variable |

Rotation-needed detection on `revoke_server` uses §4.1's revoke_server variant
(interval = the grant interval, candidates = within the grant scope, actual
reads = `server.lease_issued` [includes all in-environment active variables at
issuance time in rank (a) — a consequence of per-environment distribution] +
`server.value_decrypted` [reserved]).

## 4. Query requirements derived backward from rotation-needed detection

### 4.1 Algorithm (implementing CRYPTO_SPEC §7)

On acceptance of `remove_member(M)`, inside the same project DO:

1. **Restore the membership intervals**: from the chain mirror, find every
   interval from M's `chain.member_added` (or `chain.genesis` with
   target_user_id = M) to `chain.member_removed` (a union of multiple
   intervals if re-added)
2. **Candidate set (the set that was viewable)**: **per-environment access
   windows (2026-09-14 ES — old: in v1 every member received every
   environment's every epoch's DEK, so "all (variable × environment) whose
   existence period overlaps the membership interval")**: for each membership
   interval of M, environment E's access window = "the seq range within the
   interval during which E was in M's scope" (restored from the scope in
   `chain.member_added` / `chain.role_changed` payloads — `all` means the
   whole membership interval, `listed` means while included. The window opens
   and closes at scope change points). Candidates = "all (variable ×
   environment) whose existence interval overlaps an access window". Judged by
   overlap with the existence interval `var.created` to `var.deleted` (to now
   if not deleted). **Deleted variables are included too** (deleting a
   variable does not revoke the upstream credential). It has the same
   structure as the revoke_server variant's "per-environment disclosure
   window" (below), and the implementation shares a single window derivation
3. **Rank the basis**: split the candidate set into 2 levels — (a)
   **definitely fetched**: those with M's `var.read` inside the membership
   interval (including via API token; matched by actor.user_id), (b) **was
   fetchable**: all other candidates. The UI / CLI highlights (a)
4. **Persist the result**: append as `rotation.recommended` events; the UI /
   CLI shows them as "rotation needed" flags
5. **Flag resolution**: resolved by a `var.version_pushed` to the target
   (variable × environment) (= upstream rotated and a new value stored.
   **Excluding pushes bearing the re-encryption marker — §3.3**: mandatory
   rotation's re-encryption is a re-push of the same plaintext, not an
   upstream revocation; without the exclusion the mandatory sweep running
   right after step 4 would auto-resolve every flag — 2026-08-15 session 25
   owner ruling) or by `rotation.dismissed`. Resolution is judged in event
   seq order (only resolution events at seq **after** the recommended count).
   Resolution state is derived from the event sequence (the flag itself is not
   kept in a mutable store)

**`revoke_server` variant**: same skeleton with these substitutions — step 1's
interval is the target server-key FP's `chain.server_granted` to
`chain.server_revoked` (per interval if re-granted). Step 2's candidates are
limited to variables of the environments contained in each grant's scope (a
subset of target environments. CRYPTO_SPEC §6.2). The scope is treated as a
**per-environment disclosure window**: because chain consensus rules accept a
widening re-grant to the same key FP (only narrowing is rejected), an
environment added later by widening has its window from "the seq of the grant
that first included that environment" to revocation (fixing to the initial
scope would leak the widened part out of detection; moving the interval start
up would produce false positives on variables deleted before the widening —
2026-08-15 review finding). Step 3's (a) uses `server.lease_issued` instead of
`var.read` (matched by actor_key_fingerprint = the server key FP. Includes all
in-environment active variables at issuance time in (a) — per-environment
distribution) and `server.value_decrypted` (reserved — §3.5). Steps 4–5 are
the same.

**`change_role` variant (2026-09-14 ES)**: demotion (to below member) and
scope shrink are detected with the same skeleton as `remove_member` — step 1's
interval is the window closed at that `change_role`'s seq (demotion = closes
the windows of all environments in the target scope; shrink = closes the
windows of the shrunk environments), step 2's candidates are limited to the
closed windows' environments, steps 3–5 are the same. `rotation.recommended`'s
`trigger = change_role`. **Demotion does not cause a confidentiality
revocation** (the target keeps receiving new DEKs as a reader — CRYPTO_SPEC
§7), but the values of the closed window are made a detection target as the
fact "someone who knows the upstream credential lost the permission"
(dismissal is an admin's judgment — §7). Application via four-eyes (PF1)
starts from the seq of the completed `approve` entry (`triggerChainSeq`)

**`revoke_device` variant (2026-09-19 DK)**: same skeleton with these
substitutions — step 1's interval is the **intersection** of each revoked
device's **validity interval** (`chain.device_added` [or, for the first key,
`add_member` / `genesis` — the start of the membership interval] to
`chain.device_revoked`), the target's per-environment access windows (step 2),
and the device's scope (the `chain.device_added` payload). Step 3's (a) is
matched by **actor.user_id**, same as the remove variant, with only the
interval narrowed by the above (device validity interval ∩ access window ∩
device scope) (**`var.read` is a signature-less read and carries no
`actor_key_fingerprint`** — outside §3.3's "operations accompanied by a client
signature" type, and the premise of §5.2's partial index. K1 review [2026-09-20
pullfrog] corrected the drafting-time "match by actor key FP, more precise
than remove" — design record dk-design.md §6 K1-12. Device-level precision is
given by the interval narrowing; reads by the same person's other devices may
enter (a) [the over-report direction = safe side]. The option of pulling (a)
toward the device by cross-checking `actor_api_token_id` against the device
registry's `tokenId` [AUTH_SPEC §13-11 — advisory] is not taken — it would
require a ruling making an advisory an input to the basis rank — settled by
the 2026-09-20 owner ruling [design record §6 K1-12 / owner ruling]. If
adopted in the future, it is revised as a reversal of approved item 8). Steps
4–5 are the same. `rotation.recommended`'s `trigger = revoke_device`, and the
payload carries the target user_id and the revoked FP set. The target stays a
member, so the membership interval is not closed (detection is on the "window
cut at the trigger seq", same as the demotion variant). Revoking a device with
empty scope (a vote-only device) yields empty candidates and writes no row

~~If environment-scoped role (CRYPTO_SPEC open item #11) is introduced, step
2's "all environments" narrows to "the environments M had access to". Because
the chain mirror copies role / scope, this extension works by a query change
alone (no schema change needed).~~ **Resolved 2026-09-14 (the per-environment
access windows above)**. Because the chain mirror copies scope (§3.4), it
works by a query change alone (no schema change needed — unchanged)

### 4.2 Query requirements the schema must satisfy

| # | Query | Required index |
|---|---|---|
| Q1 | user_id → membership intervals and per-environment access windows (columns of chain.genesis / member_added / role_changed / member_removed; the scope in member_added / role_changed payloads are the window's open/close points — §4.1 step 2. 2026-09-15 K3 correction: role_changed added to the enumeration), and device windows (columns of chain.device_added / device_revoked — the payload's FP and cap are the device window's open/close points. §4.1's `revoke_device` variant. 2026-09-19 DK. `chain.device_added`'s target is the actor themself) | (target_user_id, seq) (unchanged) |
| Q2 | Existence intervals of (variable × environment) (columns of var.created / deleted) | (variable_id, environment_id, seq) |
| Q3 | user_id × period → distinct set of read (variable × environment) | (actor_user_id, seq) + event kind. **The aggregate form of `var.read` (§3.3 — 2026-09-02) obtains the (variable × environment) set by expanding the payload's `variables` enumeration** (unioned with the old form's column values. The index works on the per-actor rows, and the row count drops to 1/variable-count under aggregation) |
| Q4 | (variable × environment) × period → list of principals who viewed / changed it (reverse lookup. For incident response) | Same index as Q2. **Because the aggregate `var.read` has no variable ID column**, environment-level rows (variable_id IS NULL, event = var.read) are narrowed to a seq range by the **value-existence interval (the first `var.version_pushed` to the last `var.deleted` in that environment)** before the payload's `variables` is inspected (a with-values pull returns all of the environment's active variables, so nearly every aggregate row in the interval contains the variable, and inspection is bounded by "page limit × payload length" — outside the interval not a single row is inspected. The lower bound is the value's first appearance, not `var.created`, because a declared variable that never held a value never appears in a pull — in that case the inspection itself is skipped). **Variable IDs are client-issued and the server's uniqueness unit is (environment, variable)**, so the interval is taken per environment and bounded by their union (don't miss the same ID deleted in environment A but alive in B; with an environment filter, only that environment's interval). §7's `variable_id` filter has the same shape (unioned with old-form column match) |
| Q5 | Currently effective rotation.recommended − resolution events | event kind + (variable_id, environment_id, seq) |
| Q6 | server key FP → grant intervals and scope (columns of chain.server_granted / revoked), plus in-period server.lease_issued (matched by actor_key_fingerprint = server key FP. The main input of §4.1 variant's (a) — 2026-08-12) + server.value_decrypted (reserved — §3.5) | (target_key_fingerprint, seq) + (actor_key_fingerprint, seq) |

All of these **complete inside a single project DO** (no cross-DO joins). §5's
placement choice prioritizes preserving this property above all else.

## 5. Storage and schema

### 5.1 Project events (§3.3–3.5): append-only inside the project DO (base policy)

- Storage is the project DO's SQLite. Co-locating with the chain (same DO) and
  the data itself lets §4's queries complete without cross-store joins, and
  lets a chain append and its mirror append be written in the same transaction
  (DO serialization makes seq monotonic and gapless)
- Tables (Drizzle schema at implementation time. Isolated inside the
  repository service per ADR-0006):

```sql
audit_events (
  seq         INTEGER PRIMARY KEY,  -- monotonically increasing via DO serialization. No gaps
  row_id      TEXT,                 -- wire row identifier (16-byte random hex. §7 — independent of seq. UNIQUE index)
  server_ts   INTEGER NOT NULL,     -- server acceptance time (unix ms)
  client_ts   INTEGER,              -- chain mirror only: the entry's client time
  event       TEXT NOT NULL,        -- §3 event name
  actor_type  TEXT NOT NULL,        -- 'user' | 'server' | 'system'
  actor_user_id          TEXT,
  actor_key_fingerprint  TEXT,
  actor_api_token_id     TEXT,
  target_user_id  TEXT,             -- target of membership operations
  target_key_fingerprint TEXT,      -- target server key FP of grant_server / revoke_server
  environment_id  TEXT,
  variable_id     TEXT,
  epoch           INTEGER,
  version         INTEGER,
  chain_seq       INTEGER,          -- chain mirror only
  payload         TEXT              -- JSON. Supplementary data like name snapshots. Contains none of §1-2/1-3's forbidden information
);
CREATE INDEX ae_var    ON audit_events (variable_id, environment_id, seq);
CREATE INDEX ae_actor  ON audit_events (actor_user_id, seq);
CREATE INDEX ae_target ON audit_events (target_user_id, seq);
CREATE INDEX ae_target_fp ON audit_events (target_key_fingerprint, seq);
CREATE INDEX ae_actor_fp  ON audit_events (actor_key_fingerprint, seq);
CREATE INDEX ae_event  ON audit_events (event, seq);
```

- What this section defines is the indexes' **set and column order**; an
  index's predicate (partial indexing — e.g. limiting the index of
  `target_user_id` / `target_key_fingerprint` / `actor_key_fingerprint`, which
  are always NULL on `var.read`, to `WHERE <column> IS NOT NULL`) is
  implementation discretion (2026-09-02 — audit-log growth density measure ①.
  The DDL above is the original form)

- Frequent attributes are promoted to columns (for indexes); everything else
  is payload JSON. Columns are NULL-allowed, and per-event-kind required
  attributes are enforced at the app layer (Effect Schema)
- **Audit-head cumulative hash (2026-08-18 session 27 drafting — resolving
  open item #2. The input of CRYPTO_SPEC §6.2 `checkpoint`)**: the project DO
  maintains a cumulative hash on each audit-row append — `h_n =
  lower_hex(SHA-256(LP("maruhi/v1/audit-head", h_{n-1}, seq, row_digest)))`
  (`h_0` = the empty string. LP is CRYPTO_SPEC §2.1). `row_digest` is the
  SHA-256 of the row's columns LP-encoded in fixed order (seq, row_id,
  server_ts, client_ts, event, actor_type, actor_user_id,
  actor_key_fingerprint, actor_api_token_id, target_user_id,
  target_key_fingerprint, environment_id, variable_id, epoch, version,
  chain_seq, payload — numbers decimalized to strings, payload is the stored
  TEXT's byte string as-is). **The LP field of a NULL-allowed column is a
  tagged byte string: NULL = 1 byte `0x00`, non-NULL = `0x01` + the value's
  byte string** (NULL and the empty string must not share a preimage —
  2026-08-18 pullfrog review response. LP's length prefix fixes the
  tag-inclusive boundary, so there is no ambiguity). **No JSON normalization
  is done** (the stored byte string is the truth — structurally avoiding
  divergence of comparisons via normalization differences). **`h_{n-1}` and
  `row_digest` are both placed on the LP field as lowercase hex strings** (a
  uniform representation consistent with `h_0` = empty string — pinned by
  `test-vectors/audit-head.json`. Stated 2026-08-28 session 35). The server
  keeps the cumulative hash of any accepted point verifiable (the form is an
  implementation detail such as a column co-located on the rows) and uses it
  for checkpoint acceptance verification (CRYPTO_SPEC §6.4 — the declared hash
  must exist in the computed column) and for admin cross-checks (§6). The
  append and the cumulative-hash update are in the same transaction — **or the
  cumulative-hash column may be kept as a deterministically derived value from
  the rows appended in the same transaction and materialized lazily**
  (2026-08-28 session 35 addendum): in that case, every path that reads the
  audit head (AUTH_SPEC §16-2 fetch, checkpoint acceptance verification) must
  extend the column to the latest row before reading, and mid-way failure must
  leave a prefix-contiguous column so the next extension resumes (the rows are
  the source of truth, the column is a derived cache, and no reader observes
  an incomplete column — observationally equivalent to the same-transaction
  form. An allowance so that in environments where SHA-256 is asynchronous the
  hash computation does not enter the append hot path [bulk recording of
  var.read etc.]. The ruling's course is in docs/notes/session-35.md).
  **Lazy-materialization extension may be bounded per call (2026-08-28 session
  38 addendum — resolving a PR #99 review handoff)**: a call that hits the cap
  = the column did not reach MAX(seq) rejects that read / acceptance with a
  retryable typed response (AUTH_SPEC §16-2's `AuditHeadNotReady`) and **must
  not perform checkpoint acceptance verification (CRYPTO_SPEC §6.4's
  existence / position checks) or an audit-head response on a stale column**
  (fail-closed — checks and responses happen only on a call where the column
  reached MAX(seq)). Extension progress is persisted across calls, and every
  call including a failure response must advance and converge. The
  introduction migration recomputes the cumulative hash from existing rows
  (all rows survive, append-only) to initialize (in lazy-materialize form the
  first read doubles as this initialization) — tampering done before
  initialization is out of detection scope (the checkpoint's guarantee covers
  "post-hoc tampering after the notarization point" — §6 — and initialization
  only creates its starting point). **The D1 side (§5.2's user / org events)
  is out of scope**: a checkpoint lives on the project chain, and there is no
  place to put rows that belong to no project (D1-side tamper resistance stays
  on §6's conventional model)
- **`row_id` (2026-08-16 session 26 owner ruling — C1)**: a 16-byte random
  value used as the wire row identifier and paging cursor (independent of the
  `seq` numbering). Because `seq` is a gapless shared numbering, distributing
  ordinals as-is would let a viewer below admin infer "the exact count and
  time window of hidden rows (class 2)" from the seq gaps of visible rows
  (contradicting §7's non-disclosure of counts). A random identifier carries
  no ordinal distance and structurally cuts this inference. The D1-side tables
  (§5.2) carry the same column (their `seq` is a deployment-wide
  autoincrement, so ordinal distribution would infer activity volume across
  tenants). Existing rows are backfilled by the introduction migration. On the
  D1 side a deploy gap (after migration application, while old code is running
  / on rollback) can write `row_id`-less rows, so a read that observes a NULL
  `row_id` may idempotently re-apply the same backfill statement (deferred
  backfill at read time) — this is numbering a synthetic identifier and does
  not touch audit-content columns (compatible with §1-4's append-only). After
  all deploys stabilize, a follow-up migration of NULL re-backfill + NOT NULL
  constraint removes this deferral (handoff)

### 5.2 Placement of org / user events (§3.1–3.2): option comparison

They cannot go in a project DO (they belong to no project, and a user spans
multiple projects). Candidates:

| Option | Content | Advantages | Disadvantages |
|---|---|---|---|
| **A: dedicated tables in D1** | `user_audit_events` / `org_audit_events` (structure same as 5.1, seq is autoincrement) | users / sessions / api_tokens / memberships already live in D1, so referential consistency and cross queries ("all auth events of this user") are natural. No new DO class, minimal v1 implementation. Write frequency is low, no lock-contention concern | No DO serialization guarantee so seq's gaplessness is weaker (D1 autoincrement suffices in practice). Breaks the "all logs live in DOs" uniformity |
| B: new user DO + org DO | 1 DO per principal, same structure as 5.1 | All logs in the same pattern. Strong separation when hosted. Easy per-user export later | +2 DO classes in v1. Auth flows (D1 transactions) and log appends end up in different stores and lose atomicity. Cross-cutting admin queries (suspicious-login monitoring etc.) become fan-outs |
| C: new org DO only; user events also go in the personal org they belong to | Unifies on the DO pattern with +1 class | — | A user can belong to multiple orgs, so "which org to write" is artificial. The placement of org-unrelated events (linking, recovery, etc.) gets distorted |

**Proposal: adopt option A (D1) for v1.** Reasons: (1) §4's core queries all
complete inside a project DO, and org / auth events do not participate in
detection = no benefit from DO co-location. (2) Placing auth events in the
same D1 as their recorded objects (sessions / tokens) lets them be appended in
the same transaction as the issuance / revocation processing. (3) append-only
is guarded in any store by "code discipline + an append-only service
boundary"; making it a DO does not strengthen it automatically. Migrating to
option B later is mechanically possible because the event structure is
isomorphic (re-evaluate when hosted-version compliance requirements emerge).

**Implementation (2026-08-10 session 21)**: per option A, `user_audit_events`
(§3.1) / `org_audit_events` (§3.2) were implemented in D1. Columns follow
§5.1's design (frequent attributes promoted to columns + payload JSON;
auth_method is in the payload per §2), without the DO-only columns that never
appear in D1-side events (chain / variable coordinates / key FP / client_ts),
and with `org_id` / `project_id` promoted to columns for org cross queries. No
FK to users (an audit row outlives the row it records; referential integrity
must not block an append). Same-transaction appending (reason (2)) is realized
by each repository bundling its insert statement into its own D1 batch; only
events not accompanied by a main-data write (`auth.login_failed` and CLI
login's `auth.login_succeeded` [device flow before the 2026-08-31 §4
revision]) are standalone appends. Only events with a corresponding operation
API are recorded (org rename / delete / member-management APIs are
unimplemented, so those events start recording when the APIs are introduced).
The read API is not built per §6–§7 (Phase 2).

### 5.3 Retention and volume

- v1 retains indefinitely (no delete API). DO SQLite allows up to 10 GB / DO;
  the dominant `var.read` lowers its density [how row count grows] via the
  aggregate form (§3.3 — 2026-09-02), and total volume is absorbed by AUTH_SPEC
  §12-8's DO storage total guard. An aggregate row's payload is variable count
  × tens of bytes (~80 KB at the 1,000-variable-per-environment cap — inside
  the 2 MB row size cap. row_digest's [§5.1] SHA-256 input is also this length
  and does not enter the append hot path [lazy materialization]). No cap,
  retention period, or deletion is placed on audit rows (ruling CZ's rejected
  option — docs/notes/session-47.md)
- On project deletion the whole DO disappears with chain and data (v1 has no
  requirement to keep only the audit log. Re-examine for the hosted version =
  open item #3)

## 6. Tamper resistance and access control

- The audit log is **server-managed data; unlike the chain it has no
  cryptographic tamper-proofness** (the server = the self-host operator has
  rewrite capability). Accepted under v1's threat model and mitigated by:
  - the project DO's seq being monotonic and gapless (a gap = the trace of a
    deletion)
  - the chain-mirror part being reconstructible and verifiable against the
    chain (signed)
  - **Checkpointing the audit head onto the chain (2026-08-18 — resolving open
    item #2. CRYPTO_SPEC §6.2 `checkpoint` / §5.1's cumulative hash)**: a
    client with **effective permission admin** notarizes the server-declared
    cumulative hash onto the chain when issuing a checkpoint (checkpoint's own
    issuance authority is member or above, but audit-head notarization follows
    the declaration fetch's effective permission admin-only — AUTH_SPEC §16-2.
    Any other issuance has no notarization = the empty string)
    - **The advance of the notarized prefix depends on admin clients' issuance
      frequency (an explicit residual — 2026-08-18 review round 5)**: a
      member's issuance notarizes only the data layer and does not advance the
      audit prefix. CRYPTO_SPEC §6.3's issuance trigger (iii) splits the admin
      client's baseline to "the latest checkpoint with a notarization" to tie
      this advance to admin syncs, but in a project where no admin issues for
      a long period, post-hoc tampering of audit rows after the last
      notarization cannot be detected by cross-checking (like falsehood at
      record time, a residual inside this section's threat model)
    - **The semantics is "unverified-at-issuance notarization"**: the issuer
      can view all rows, but fetching all rows per checkpoint and recomputing
      the cumulative hash is heavy. So at notarization the server-declared
      value is pinned, and full verification is split off to a later explicit
      admin cross-check. The fact that the server claimed "the cumulative hash
      at this point was this" is signed and fixed on the chain, so tampering
      with or deleting a row in the notarized prefix afterward contradicts the
      admin's recomputation (non-repudiable)
    - **The admin cross-check inspects "position" in addition to "presence"
      (2026-08-18 pullfrog review response — blocking stale replays)**: while
      recomputing the cumulative-hash column, for each checkpoint that
      notarized an audit head (audit_head_hash non-empty), check (a) the
      notarized head appears in the column, (b) its appearance position is
      non-retreating across notarizing checkpoints, (c) the appearance
      position is at or beyond the immediately preceding checkpoint's (with or
      without notarization — every checkpoint acceptance writes a mirror row)
      own mirror row (`chain.checkpointed` — identified by chain_seq). On the
      first checkpoint with no predecessor, (c) is not imposed (vacuously
      true. Same predicate and same base case as the acceptance check —
      CRYPTO_SPEC §6.4)
    - Presence alone would let a malicious server keep returning a real old
      cumulative hash h_k and pass every checkpoint while remaining able to
      tamper with rows beyond row k. With (c), the protected prefix advances
      monotonically. Because the server-side acceptance also checks the same
      position lower bound, an honest server satisfies (b)(c) structurally.
      Therefore a (b)(c) violation at cross-check is not benign contention but
      evidence of "a server not enforcing the acceptance policy" = a state
      enabling stale replay (reported separately from a presence violation =
      evidence of the row tampering itself)
    - Because a checkpoint append itself writes a mirror row, this check adds
      no seq to the chain or wire (compatible with C1 ruling's non-disclosure
      of counts) and completes on the admin side, which can read all rows.
      **Falsehood at record time (writing or not writing a fake row in the
      first place) remains a non-guarantee**
  - **Head declarations (CRYPTO_SPEC §6.6) are not eventized (2026-08-18)**:
    they are high-frequency low-information events updated on every sync (the
    same shape as var.read's bloat problem), do not contribute to
    rotation-needed detection (§4), and eventizing them would create a new
    permanent behavioral record of "who synced when" — contrary to this spec's
    privacy minimization (§1-2 / this section's visibility-class principle).
    The current state of declarations (latest 1 row per member) is held by the
    data plane (AUTH_SPEC §16-1); server acceptance times are not distributed
- **Viewing permission (2026-08-12 revision — replacing the old v1 interim
  plan. Resolves open item #1)**: events are split into 2 visibility classes.
  The line's principle is "**is it surveillance information on a person's
  action, or the operation of the disclosure mechanism**":
  - **Class 1 (chain role reader or above = all members)**: facts already
    distributed and verified by client sync, and the operation of the
    disclosure mechanism — all of `chain.*`, **any row carrying `chain_seq`**,
    `env.*`, `var.created` / `var.renamed` / `var.schema_reissued` /
    `var.deleted` / `var.version_pushed`, `server.*`, `rotation.recommended` /
    `rotation.dismissed`. Narrowing the chain mirror to admin would be only
    security theater since all members already verify and fetch the same facts
    via chain sync. The additional `chain_seq` condition (2026-08-25 deepsec
    S1) exists so the visibility predicate does not hide tamper evidence: the
    append boundary rejects `chain_seq` on non-`chain.*` as a defect, and the
    only thing an honest writer can set this column on is `chainMirrorEvent` =
    `chain.*` mirrors, so no legitimate class-2 row is disclosed and only a
    forged provenance claim naming an event one step outside the namespace
    reaches all members' verification. `server.*` is the disclosure
    mechanism's record, not a person's, and every member (readers included)
    has a legitimate interest in knowing the exercise of disclosure on their
    own secrets (the audit side of CRYPTO_SPEC §9's always-explicit
    obligation)
  - **Class 2 (chain role admin or above)**: human-actor action events —
    `var.read`, `dek.registered` / `dek.deleted`, `invite.*` (stored in D1 —
    §3.2 — but visibility is the same level), and cross search of rows whose
    actor is someone else. Colleagues' read patterns are privacy information
    and are bound to governance authority
  - **A row whose actor is the viewer is always visible to them regardless of
    class**. User events (§3.1) are self-only; org events (§3.2) are org admin
    or above (as before)
  - **The derived view of rotation-needed flags** (§4.1's "currently effective
    recommended − resolved") is class 1 — detection's purpose is prompting
    upstream credential rotation and would not work admin-only
  - **Environment scope does not change visibility class (2026-09-14 ES —
    design record ruling I)**: class-1 data events (`var.created` /
    `var.renamed` / `var.schema_reissued` / `var.deleted` /
    `var.version_pushed`, `env.*`) are visible to all members including those
    of out-of-scope environments (plaintext meta is visible to everyone —
    CRYPTO_SPEC §6.3). `chain.*` (including scope changes and four-eyes
    proposals / approvals / policy) is class 1. `var.read` stays class 2. No
    environment axis enters the visibility predicate (keeps `audit verify` /
    reconcile / the rotation-needed-flag view scope-independent)
  - **Device keys do not change visibility class (2026-09-19 DK)**:
    `chain.device_added` / `chain.device_revoked` are class 1 (`chain.*`). The
    device registry (AUTH_SPEC §13-11) is not an audit target (same discipline
    as the token list). The rotation-needed-flag view is class 1 including the
    `revoke_device` variant

## 7. API boundary

- Reading audit events is exposed via HttpApi (domain types only. No Drizzle
  types escape = ADR-0006). An append API is **not exposed** (events are
  generated by each operation's server-side processing. No API by which a
  client can write arbitrary events)
- **Read API shape (2026-08-12 drafting — Phase 2)**: the project DO side has
  seq-cursor paging (limit ≤ 200) + filters (event kind / **event-namespace
  prefix** (added 2026-08-24. below) / **presence of chain_seq** (added
  2026-08-25. below) / actor_user_id / target_user_id / variable_id /
  environment_id). §6's visibility classes are enforced at the authorization
  stage; class-2 rows and filters **behave as if they do not exist** to those
  below admin (not leaked even via counts or paging). Rotation-needed flags
  are a separate derived-view endpoint (the server runs §4.1's step-5
  derivation and returns the currently effective set). User-side and org-side
  (D1) use the same cursor-paging shape (self / org admin). **Exception:
  invite.* reads (stored in D1 — §3.2) do not belong to the org-admin axis**:
  they are provided as a project_id-scoped D1 query as part of the project
  audit path, and the permission axis is **chain role admin or above** of that
  project (same as §6 class 2) — being an org admin gives no viewing right to
  invite.*, and a chain role admin can view them without being an org admin
  (2026-08-12 review incorporation — storage and permission axis are decided
  independently). Consumed by the CLI's `maruhi audit` and the Web audit UI
  (Phase 2 C1 / W2)
- **Opaque cursors / row identifiers and admin-only disclosure of `seq`
  (2026-08-16 session 26 owner ruling — C1. Resolves a pullfrog review
  finding)**: the ordering of the "seq cursor paging" above stays the stored
  `seq` (descending = newest first), but **the wire row identifier and cursor
  use `row_id` (§5.1's random)** — handing the ordinals of a gapless numbering
  to those below admin would let them deterministically infer class-2 counts
  and time windows from the seq gaps of visible rows, contradicting this
  section's "not even via counts". Server-side resolution of a cursor (`before`
  = row_id) is done **with the viewer's visibility predicate applied**, and an
  invisible or unknown row_id behaves identically as an "empty page" (don't
  make cursor probing an existence oracle. row_id is a 128-bit random, so
  guessing itself is impossible). The `seq` field is carried **only on
  project-DO responses visible to admin (chain role admin × token scope
  admin)**: §6's "a gap = the trace of a deletion" detection is meaningful
  only to a viewer who sees all rows (to those below admin a gap is
  indistinguishable from class-2 hiding), so it is stored there. **The D1
  paths (invite.* / user events) return `seq` to no one** (§5.2's
  autoincrement is a deployment-wide shared numbering; ordinals would leak
  activity volume across tenants and users). For the same reason, **the
  rotation-needed-flag derived view (§4.1 step 5) also carries no audit seq**
  (ordering by recommendedAtMs suffices — revision from the B2 implementation)
- **Dismissal operation endpoint (2026-08-15 session 25 owner ruling — Wave 2
  B2)**: `rotation.dismissed` is not an exception to the append API but a
  **dedicated operation endpoint** (`POST
  /projects/:projectId/rotation/dismissals` — enumerate one or more target
  (variable × environment), all-or-nothing). The event is generated by
  server-side processing (this section's principle holds), and permission +
  target validation follow §3.3's recording rules (admin or above × admin
  scope; no effective flag → 404). The rotation-needed-flag derived view
  (above) doubles as the discovery path for this endpoint's dismissal targets.
  The CLI is `maruhi rotation list` / `maruhi rotation dismiss` (the flag view
  and dismissal — implemented early in Wave 2 B2. Raw events stay with
  `maruhi audit` in C1). Display-name resolution is done by the client on
  verified meta statements (including tombstone statements of deleted
  variables — AUTH_SPEC §12-7); the view response carries only identifiers
- **event-namespace prefix filter (2026-08-24 deepsec R1 response)**: in
  addition to the exact-match `event` filter, the vocabulary includes
  `event_prefix` (prefix match). This exists so `maruhi audit verify`'s mirror
  bijection check (§3.4) can fetch **all rows of the `chain.` namespace** —
  fetching known mirror event names one by one via exact match would never
  fetch a forged row claiming an out-of-set `chain.*` name, and verification
  would end "OK" (a coverage hole in the forgery direction). Prefix match is
  implemented as `substr(event, 1, ?) = ?`, not SQL LIKE — no wildcard
  semantics. Visibility class (§6), cursor, and non-disclosure of counts are
  handled identically to other filters. The client treats event names among
  fetched `chain.*` rows that are absent from the known mirror mapping as
  **verification failure** (a row claiming an unknown op = evidence of
  forgery). This property depends on §6's class-1 judgment **covering the
  namespace by prefix**: an implementation allowing only mapped names would
  drop forged rows at the server-side visibility predicate, and no row would
  reach a below-admin verify (verify does not require admin, so a reader's
  run would end "OK"). The class-1 judgment and this filter share the same
  prefix comparison
- **chain_seq-presence filter (2026-08-25 deepsec S1 response)**: the
  vocabulary includes `chain_seq_present=true`, returning only non-NULL rows.
  `maruhi audit verify` inspects the union by row_id of the `event_prefix=chain.`
  set and this filter's set. With only the former, a row claiming `chain_seq`
  one step outside the namespace — `member.add` / `chainx.grant` — would never
  be fetched: it would look like a bare coordinate in listings, and verify
  would end "OK". Legitimate mirror rows land in both sets and are
  deduplicated; if the contents of the same row_id differ between the two
  queries, the server response is self-contradictory and the run aborts. §6's
  visibility predicate also treats `chain_seq IS NOT NULL` as class 1, not
  hiding tamper evidence from non-admin verify. The client treats a
  non-`chain.*` row carrying `chain_seq` as an explicit distrust label +
  consistency violation
- Exception: if a future CLI / client needs to report "an event observable
  only client-side" (e.g. a rejection by agent-environment detection), design
  it as a dedicated narrow reporting endpoint and revise this spec

## 8. Open items

1. ~~Details of the permission model for the audit-log viewing UI~~
   **Resolved (2026-08-12 — §6's visibility classes. Settled by the merge of
   this revision PR)**
2. ~~Checkpointing the audit head onto the chain~~ **Resolved (2026-08-18
   drafting — settled by the merge of this revision PR)**: integrated into
   CRYPTO_SPEC §6.2 `checkpoint` op (§5.1's cumulative hash + §6's
   "unverified-at-issuance notarization" semantics. Resolved together with the
   old CRYPTO_SPEC open item #4). Implementation in a follow-up PR of Phase 2
   Wave 3 (design comparison in docs/notes/session-27.md)
3. Audit-log preservation after project deletion (when the hosted version's
   compliance requirements emerge: e.g. evacuating a pre-deletion snapshot to
   the org side)
4. ~~`var.read`'s aggregation policy (after dogfooding measurements. §3.3 /
   §5.3)~~ **Resolved (2026-09-02 owner decision — brought forward without
   waiting for measurements. §3.3's aggregate form = 1 row per environment per
   with-values bulk pull, payload enumerates the returned variables. Settled
   by the merge of an implementation PR containing this revision)**
5. Export (SIEM integration etc.). Separate from the telemetry prohibition
   (CLAUDE.md), but designed as explicit-operation-only and pull-type only
