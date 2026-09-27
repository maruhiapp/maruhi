# VH design record — value history and rollback (2026-09-27 design session)

**Position**: the ROADMAP H series "no-revision group" head = **VH: value
history display and rollback** (order VH → PF5 → PF4 → PF6 — 2026-09-14 owner
ruling). This record carries the overall picture, the option enumeration and
rulings for the two points the ROADMAP entry left to a design session, the new
read surfaces, and the implementation split.

**Approval (2026-09-27)**: the owner delegated both open points ("review
whether a strictly-better or structurally-better option exists, lay the
options out, and pick the one you recommend") and ruled that backward
compatibility is to be ignored entirely (there are zero users). The rulings
below (V1–V5) are the designer's picks under that delegation.

**Premises (not relitigated)**: CRYPTO_SPEC §4.1 (value signature, prev
chaining, epoch monotonicity along the version chain), AUTH_SPEC §12-5
(acceptance is current-epoch only; the version CAS), AUDIT_SPEC §4.1
(rotation-needed detection; resolution state is derived from the event
sequence, never kept in a mutable store), ADR-0014 decision 3 (counter human
error with mechanisms), AUDIT_SPEC §7 ruling C1 (no audit seq on the wire).

---

## 1. Overall picture

### 1-1. Problem

"I accidentally overwrote the prod key" has no mechanical answer today. Every
version of every value is already kept by the server (`variable_versions`, up
to 1,000 per variable — AUTH_SPEC §12-8) and chained by signature (§4.1), but
nothing reads a past version back: the only read path is the bulk pull of the
latest versions (§12-7). The user's only recourse is to find the old value
somewhere else and `maruhi push` it again — which also silently looks like
"a fresh value" to rotation-needed detection.

### 1-2. Mechanism sketch

```
maruhi var history API_KEY          (metadata only — no value, no DEK, no var.read)
  v7  epoch 2  2026-09-27 …  alice  fp 1a2b…  current
  v6  epoch 2  2026-09-26 …  bob    fp 3c4d…  re-encryption of v5
  v5  epoch 1  …                                    ⚠ 1 rotation flag while current
  …

maruhi var rollback API_KEY --to 4
  1. verified pull of the environment (latest = v7, all-epoch DEKs)
  2. fetch v4…v7 with values, verify every signature + the prev chain
     v4 → v5 → v6 → v7 ending at the verified latest (§4.1 / §6.3)
  3. decrypt v4 with its epoch's DEK; refuse if it equals the current value
  4. confirm (interactive) / --force (non-interactive)
  5. re-encrypt under the current epoch → push v8 with sameValueAs = 4
```

History stays append-only: a rollback is a new version (v8), never a rewind.
Crypto, the value signature, and the server's acceptance rules are unchanged.

## 2. Ruling V1 — how the audit trail records "this version restores an older value"

The ROADMAP draft: add a rollback-marker payload to `var.version_pushed`, in
the same format as the re-encryption marker, excluded from §4.1 step 5's
resolution derivation under the same discipline.

**Options**

| # | Shape | Verdict |
|---|---|---|
| 1-A | A second marker beside the existing boolean: `{ reencryption: true }` stays, rollback adds `{ rollback: { toVersion: k } }`; both excluded from resolution | Works, but two markers encode one fact ("this version's plaintext is an older version's plaintext") and the re-exposure question (V2) still needs extra machinery |
| 1-B | A new event kind `var.rolled_back` instead of a `var.version_pushed` payload | Rejected: every consumer of `var.version_pushed` (Q2/Q4 value-existence intervals, resolution, the §7 filter, Web / CLI audit display) would have to learn a second kind for what is still one value push. Breaks the "1 operation 1 row, principal event" discipline the other data events follow |
| 1-C | Put the lineage into the signed bytes (`value_signed_bytes` gains a field) | Rejected: a CRYPTO_SPEC §4.1 revision with test-vector regeneration and crypto human review, for no detection gain — the consumer of the marker is the server-side derivation, and a malicious server can forge any derived flag anyway (the advisory nature is inherent under E2EE — §12-5). A client that ever needs a verified "same value" fact can decrypt both versions and compare |
| 1-D | **One lineage field replaces both markers**: the push carries `sameValueAs: k` ("this version's plaintext equals version k's"). Re-encryption = `k` is the immediately preceding version; rollback = any older `k`. The audit payload is `{ sameValueAs: k }` | **Adopted** |
| 1-E | No marker; let the server infer | Impossible under E2EE (the server never sees plaintext) |

**Why 1-D is strictly better than 1-A**: it is the general form of which the
existing re-encryption marker is a special case (`k = version − 1`), so the
number of concepts goes down while the expressible facts go up. The kind is
derivable without redundancy (`sameValueAs = version − 1` ⇔ re-encryption;
`sameValueAs < version − 1` ⇔ rollback — a rollback to the current version is
refused as a no-op, so it never produces `version − 1`), which rules out the
inconsistent states 1-A allows (e.g. both markers on one push). And it is what
makes V2's structural answer possible. The zero-users ruling lets the boolean
`reencryption` field be removed outright (no dual acceptance).

**Acceptance rule**: `sameValueAs` is an optional positive integer; when
present it must be `< version` (it names an existing earlier version of the
same variable — versions are contiguous from 1, so after the version CAS this
range check is exact). A violation is `422 payload-mismatch`. The server
cannot verify the claim (E2EE) and doesn't try; like the old marker it has no
effect on acceptance or the signature. **False declarations stay confined to
the advisory flag state** and the dangerous direction is unchanged from today:
a writer who omits the field while restoring an old value (or who hand-copies
an old value through `maruhi push`) produces a push that looks fresh — which
was always possible and is unpreventable under E2EE. A false positive (claiming
an old value when it is fresh) only keeps flags open (the safe side).

## 3. Ruling V2 — re-exposure: what a rollback does to rotation-needed flags

The open question: when the restored value is one a departed principal could
have read, is that "re-exposure" a new flag? Does it re-fire a flag that was
resolved or dismissed?

**Options**

| # | Shape | Verdict |
|---|---|---|
| 2-A | Never re-fire; the rollback marker is merely excluded from resolution. Only a CLI warning before the push | Rejected: a resolved flag stays resolved while the live value is again one the departed principal knows — detection silently loses exactly the case VH creates |
| 2-B | The server appends new `rotation.recommended` rows at rollback acceptance (a new trigger kind `rollback`), recomputing who could read version k | Rejected: re-runs §4.1 steps 1–3 for every historical subject on a data-plane write, adds a trigger kind whose "subject" is not a chain op, and duplicates flags that already exist for the same (subject × pair) — the UI would show two flags for one exposure |
| 2-C | **Lineage derivation**: a flag is effective iff it has not been dismissed and the **live value was first encrypted under a key the flag's subject held**. Rollback to such a value re-opens the resolved flag automatically; rollback among values first encrypted after the mandated rotation changes nothing. Dismissal is sticky (and covers only the flags effective when it was recorded) | **Adopted** |
| 2-D | As 2-C but dismissal is also re-opened | Rejected: dismissal is a human risk-acceptance on the pair (admin × admin scope — §3.3); the risk it accepted ("that subject knows this variable's value") is the same class a pre-flag restore brings back. Overriding it mechanically would turn every rollback into flag noise and teach admins to ignore flags |
| 2-E | Refuse a rollback whose target predates a flag | Rejected: rollback is the incident-recovery tool; refusing it pushes the user to hand-copy the old value through `maruhi push`, which loses the marker entirely (strictly worse for detection) |

**The derivation (replaces AUDIT_SPEC §4.1 step 5's push rule — as corrected
by the §9 re-check round, findings R-5 / R-6)**. Every `rotation.recommended`
row R carries an **exposure bound** in its epoch column: the environment's
epoch at the end of the subject's last window on it (R-8) — the subject held
the DEKs of every epoch up to it and of none after it. Over the pair's `var.version_pushed` rows in seq order, each
version gets a **plaintext origin epoch** — the epoch its value was first
encrypted under:

```
originEpoch(v) = epoch(v)                          if the push carries no sameValueAs
originEpoch(v) = originEpoch(sameValueAs(v))       otherwise (an unknown target → 0, the safe side)
```

R is **effective** iff (i) no `rotation.dismissed` of the pair was recorded
while R was effective, and (ii) either the pair has no pushed version yet, or
`originEpoch(live) ≤ bound(R)` where live is the pair's latest pushed
version. (ii) is "the value in use now was first encrypted under a key the
flag's subject held" — the flag's own premise, stated in the only terms that
are exact under E2EE: which key a ciphertext is readable with.

**Why 2-C holds**:

- It generalizes today's rule for every sequence the CLI produces (removal /
  revocation / narrowing → mandated rotation → pushes): a fresh push after the
  rotation resolves, re-encryption inherits the origin so it neither resolves
  nor un-resolves. It is **stricter** in one case the old rule got wrong (a
  fresh push between the trigger and the mandated rotation — R-6)
- It answers the open question **without a new event, a new trigger kind, or
  a new persisted row kind** — "resolution state is derived from the event
  sequence" (§4.1) is preserved, and re-exposure falls out of the same fold
  (the bound is one more column on the existing row)
- It is **per subject**: M1 removed at epoch 1, a fresh value at epoch 2, M2
  removed at epoch 2: restoring the epoch-2 value re-opens M2's flag only (M1
  never held epoch 2's key) — 2-B would need to recompute this, 2-A can't
  express it
- A later fresh push resolves the re-opened flag again with no special case

**Display of a re-opened flag**: the flag wire gains
`reopenedByVersion?: number` — present when the flag had been resolved and is
effective again because version N restored a value within its bound (N is the
push that re-opened it; a re-encryption of that restored value keeps N). The
CLI's `rotation list` and the Web Rotation screen say "re-opened by the
rollback in vN" so a flag that reappears is never unexplained.

**The pre-push warning** (the ROADMAP's "warn before pushing if the target
predates the flag"): each history row carries **`flagsIfCurrent`** = the
number of non-dismissed flags on the pair that would be effective while that
version's value is the live one (= flags with `originEpoch(v) ≤ bound(R)`).
For the live version it equals the pair's effective flag count; for a
rollback target it is exactly the number of flags the rollback leaves (or
makes) effective. `var history` shows it per row and `var rollback` puts it
in the confirmation. It is derived server-side, where the lineage and the flag
rows live. (The first draft of this record compared seqs and called the
ROADMAP's epoch comparison an approximation; the re-check round showed the
opposite — R-6. The epoch comparison, applied to the *origin* epoch, is the
exact one.)

## 4. Ruling V3 — read surfaces

Two new endpoints on the existing `…/variables/:variableId/versions` resource
(the push is its POST):

1. **`GET …/variables/:variableId/versions` — the history (metadata only)**.
   Returns every stored version ascending: `version, epoch, writerUserId,
   writerKeyFingerprintHex, pushedAtMs, sameValueAs?, flagsIfCurrent`. No
   ciphertext, no DEK ⇒ **no `var.read`** (the §3.3 recording condition —
   don't record as read what was not read). Authorization = the metadata-only
   pull's (reader, scope-agnostic: plaintext metadata is visible to all
   members; every field is already on class-1 audit rows or the class-1 flag
   view). A declared variable returns an empty list; a deleted or unknown one
   is `404 variable-not-found`. Bounded by the 1,000-versions cap, so it is not
   paginated. **The response is server-declared** (a value signature can't be
   verified without its ciphertext); the CLI labels it so, and rollback never
   trusts it — it verifies the target itself (V4)
2. **`GET …/variables/:variableId/versions/values?fromVersion=k` — the value
   range**. Returns the distributed payloads (ciphertext + signature block +
   writer — the §12-7 shape) of versions k, k + 1, … ascending, at most 100
   versions and at most 1 MiB of ciphertext per page (always at least one
   version — a page of 64 KiB values would otherwise reach ~12.8 MiB as hex;
   re-check round, below). The CLI pages until it reaches the verified latest. Authorization = the
   with-values pull's (reader × environment ∈ scope; a session principal is
   refused like the value pull; the stateful-GET CSRF rule applies because it
   records audit). DEKs are not bundled — the caller already holds the
   all-epoch wraps from the verified pull it needs anyway
3. **`var.read` for the value range**: one row per request, same aggregate
   shape, listing every returned version (they are all distributed
   ciphertexts, and the reader holds their DEKs). The enumeration order
   generalizes from "ascending variableId, no duplicates" to "ascending
   (variableId, version), no duplicate pair" — a bulk pull still has one entry
   per variable, so its bytes are unchanged. Rotation-needed detection's rank
   (a) matches by variableId and is unaffected by repeats

Why not derive history from the audit API (`var.version_pushed` rows are
already class 1): it would make the CLI paginate the generic audit surface and
re-implement the lineage fold client-side, and `flagsIfCurrent` needs seqs the
wire must not carry. The dedicated endpoint keeps the derivation in the one
server implementation that already owns it.

## 5. Ruling V4 — the CLI

**`maruhi var history <name> [--json]`** — resolves the name through the
verified metadata-only pull (keyless — `openMetadataEnvironment`), then fetches
the history. Shows version, epoch, pushed-at (UTC), writer (user id + short
FP), a note (`current` / `re-encryption of vK` / `rollback to vK`), and the
`flagsIfCurrent` warning. No value is shown or decrypted, so the agent gate
does not apply (the permissive side, like `member list` / `schema export`).

**`maruhi var rollback <name> --to <version> [--force]`**

1. Open the environment with keys (`openEnvironment`), resolve and verify the
   latest value through the existing verified pull (the same path `maruhi push`
   uses)
2. Refuse: declared (no value yet), `--to` ≥ current version, `--to` < 1
3. Fetch the value range from `--to` to the latest, verify **every** version's
   signature (§6.3) and the prev chain with epoch monotonicity
   (`verifyDistributedValue` with its `predecessor` input), and require the
   chain to end byte-exactly at the verified latest (same version and
   signed-bytes hash). This is what makes a server-forged "old version" (e.g.
   signed by a removed member's key with a head inside their interval) fail —
   an old version is only trusted as an ancestor of the verified latest
4. Decrypt the target with its epoch's DEK (a missing wrap gets the existing
   `missingWrapReason` guidance); decrypt the latest too and refuse when the
   plaintexts are equal (a no-op rollback would only burn a version)
5. Confirm: interactive = a y/N prompt naming the from/to versions and the
   `flagsIfCurrent` warning; non-interactive requires `--force` (fail-closed,
   the `var rm` shape). A rollback is not a ceremony and never displays a
   value, so an agent with `--force` may run it (same posture as `var rm`)
6. Push through `pushVariable` with the restored plaintext and
   `sameValueAs = --to`, pinned to the resolved variableId **and to the
   confirmed latest** (its version and signed-bytes hash — §9 R-1): if a
   concurrent delete / rename / push makes the (re-)resolution land anywhere
   but a normal push directly on top of the version the user confirmed,
   refuse instead of creating a variable or overwriting a change. The value lives only in
   memory (`Redacted`) — nothing touches disk
7. Report the new version; when `flagsIfCurrent > 0`, a note pointing at
   `maruhi rotation list` (the flags are now effective / re-opened)

**The rotation sweep** (`env rotate`'s re-encryption) sends
`sameValueAs = latest.version` instead of `reencryption: true`.

## 6. What does not change

- CRYPTO_SPEC: nothing. The rollback push is an ordinary §4.1-signed push at
  the current epoch; epoch monotonicity along the version chain holds by
  construction (re-encrypting an old-epoch plaintext under the current DEK);
  test vectors are untouched
- Acceptance rules other than the `sameValueAs` range check; the version cap
  (a rollback consumes a version like any push)
- The Web holds no keys (ADR-0018): it only renders the audit marker and
  `reopenedByVersion`; no history screen is added in VH

## 7. Residuals (explicit)

- `var history` is server-declared metadata. A malicious server can lie about
  it (hide versions, invent writers). The mitigation is scoped: rollback
  verifies its target chain independently, and the audit log's own
  verification (`maruhi audit verify`) covers the `var.version_pushed` rows
- The lineage is a writer declaration (V1). Omitting it (or `maruhi push` of a
  hand-copied old value) under-reports re-exposure — unchanged from today
- The exposure bound is per environment epoch, so it inherits the epoch
  model's own granularity: a subject that held epoch E's key is treated as
  able to read every value first encrypted under E (whether or not it ever
  fetched that ciphertext) — the over-report direction, same as §4.1's
  "readable" rank
- Rollback cannot restore a deleted variable (deletion destroys every
  version's ciphertext — §12-5; deletion stays terminal)

## 8. Spec reflection and implementation split

Spec (same PR, reflected before the code): AUTH_SPEC §12-5 (the re-encryption
marker paragraph becomes the lineage field), §12-7 (the two read surfaces);
AUDIT_SPEC §3.3 (marker, `var.read` enumeration order), §4.1 step 5 (the
lineage derivation), §7 (`reopenedByVersion`); ROADMAP (VH entry).

Implementation: api-schema (push field, two GETs, flag field) → server
(acceptance check, audit payload, the lineage fold, the two programs) → CLI
(`var history`, `var rollback`, rotation-sweep marker, `rotation list`
display) → Web (audit marker + re-opened flag rendering) → public docs (a
`/docs/value-history` page).

## 9. Re-check round (2026-09-27 — owner-requested re-verification before the PR)

The owner asked for the rulings to be re-verified before the PR. Each ruling
was re-attacked (a self review plus an independent adversarial review). V1,
V3 and V4 stand as ruled; V2's skeleton (a derived lineage fold, no new event)
stands, but its comparison and its dismissal scope were corrected (R-5 /
R-6). The round's findings and fixes:

- **R-1 (V4 — concurrency)**: a push by another member between the rollback's
  verification and its push made `pushVariable`'s conflict retry land the
  restored value on top of the newer version — a silent overwrite of a change
  the user never saw. A rollback is a response to the state the user
  confirmed, so the push now carries the confirmed `fromVersion` and its
  signed-bytes hash, and any (re-)resolution to a different latest refuses
  before signing ("changed while the rollback was being prepared"). Pinned by
  a CLI test. (`maruhi push` keeps last-writer-wins — a plain write carries no
  "from" state)
- **R-2 (V3 — page size)**: 100 versions × the 64 KiB value cap could make one
  value-range page ~12.8 MiB of hex. A page now also stops at 1 MiB of
  ciphertext (always at least one version); AUTH_SPEC §12-7 updated
- **R-3 (V2 — safe side)**: `flagsIfCurrent` for a version without a push
  row defaulted to 0 (the under-report direction) while the fold treats an
  unknown origin as the oldest. Both now fall to origin 0 (every non-dismissed
  flag counts). Unreachable on an honest server (every accepted version writes
  its row in the same synchronous block) — a consistency fix
- **R-4 (V3 — consumers of the `var.read` enumeration)**: the enumeration may
  now repeat a variableId (one entry per version). The Web audit list keyed
  list items by variableId (duplicate React keys) — now keyed by
  (variableId, version). The CLI and Web summaries counted entries as
  variables — now "N versions of M variables" for a range read. Rotation-needed
  detection (rank (a) matches by variableId) and `audit reconcile` (structural
  JSON equality) were unaffected
- Checked and unchanged: the rotation sweep's retry path (a 409 rescans and
  pairs the new latest with its own decrypted plaintext, so
  `sameValueAs = latest.version` stays true); the new endpoints are
  authenticated, so the per-IP rate-limit table of SELF_HOSTING.md (the
  unauthenticated surface) needs no row
- **R-5 (V2 — dismissal scope; independent review)**: a dismissal marked
  every flag of the pair, including ones resolved at the time. Before VH that
  was harmless (a resolved flag never came back); with re-opening it hid a
  re-exposure nobody accepted — M1's flag resolved by a fresh value, M2's
  flag dismissed by an admin who saw only M2's, then a rollback to M1-era
  value: nothing reported (the under-report direction). A dismissal now covers
  exactly the flags effective when it was recorded (the flags the dismissing
  admin saw — the same set the dismissal endpoint's 404 rule is about).
  Pinned by a server test
- **R-6 (V2 — the comparison; independent review)**: the first draft compared
  audit seqs ("pushed before the flag") and claimed that was exact. It is not:
  a value pushed after the trigger but before the mandated rotation is
  encrypted under a DEK the subject still holds. For `revoke_device` the
  device's token may still be valid (and a reader who revokes their own device
  cannot rotate at all — CRYPTO_SPEC §7), for `revoke_server` the server key
  holder has every ciphertext, and for `remove_member` it is readable under a
  colluding server. The comparison is now **origin epoch ≤ the flag's
  exposure bound** (the recommended row's epoch column — R-8 fixes how the
  bound is taken). This also tightens the pre-VH rule (a fresh
  push before the rotation no longer resolves — the safe direction; the CLI's
  flows rotate first, so ordinary sequences are unchanged). The `rotation list`
  guidance and the docs page say to push the new value after the rotation
- **R-7 (spec — independent review)**: AUTH_SPEC §12-3's table gained the two
  new rows (the history refuses session principals — not on §5's allowlist)

**Second independent round (on the corrected V2)**:

- **R-8 (V2 — the bound)**: the first correction stamped the environment's
  *current* epoch on every flag. A removal also flags windows closed long
  before (an old shrink); for those, the current epoch overstated what the
  subject held, and since no rotation is mandated for an environment outside
  the subject's current scope, the flag could never clear the documented way
  (it had cleared under the seq rule — a regression in the over-report
  direction). The bound is now the epoch at the end of the subject's last
  window on the environment, derived inside detection from the chain mirror's
  epoch rows (`environmentEpochEvents` — no chain-state plumbing, which also
  retires the reviewer's latent concern about the composite pair path). And a
  flag whose bound is already below the live value's origin starts resolved
  (the fold previously assumed every new flag starts effective). Pinned by a
  scope test: shrink → rotate → fresh push → removal leaves the old
  environment's removal flag resolved
- **R-9 (V1/V2 — guidance-induced under-report)**: after R-6, the natural
  reaction to a still-open flag — push "the new value" again after the
  rotation — re-pushed the same plaintext without a lineage declaration, which
  looked fresh and cleared the flag although its old-epoch ciphertext was
  readable. `maruhi push` now compares the value with the verified latest (in
  memory, when it holds that DEK) and declares `sameValueAs` = the latest when
  they are identical. Pinned by a CLI test. (A re-push of an *older* value by
  hand stays the V1 residual)
- **R-10 (nits)**: the demotion carve-out is stated (a demoted reader keeps
  receiving DEKs by design; the flag there means "replaced after the
  demotion"); a recommended row's epoch is displayed as the *exposure* epoch
  (CLI `exposureEpoch=`, Web "exposure epoch"); a recommended row without an
  epoch (only rows written before this revision — none exist outside
  development, zero users) is unbounded and clears only by dismissal
