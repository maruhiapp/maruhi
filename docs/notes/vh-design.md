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
| 2-C | **Lineage derivation**: a flag is effective iff it has not been dismissed and the **live value's plaintext origin predates the flag**. Rollback to a pre-flag value re-opens the resolved flag automatically; rollback among post-flag values changes nothing. Dismissal is sticky | **Adopted** |
| 2-D | As 2-C but dismissal is also re-opened | Rejected: dismissal is a human risk-acceptance on the pair (admin × admin scope — §3.3); the risk it accepted ("that subject knows this variable's value") is the same class a pre-flag restore brings back. Overriding it mechanically would turn every rollback into flag noise and teach admins to ignore flags |
| 2-E | Refuse a rollback whose target predates a flag | Rejected: rollback is the incident-recovery tool; refusing it pushes the user to hand-copy the old value through `maruhi push`, which loses the marker entirely (strictly worse for detection) |

**The derivation (replaces AUDIT_SPEC §4.1 step 5's push rule)**. Over the
pair's `var.version_pushed` rows in seq order, each version gets an **origin
seq** — the seq of the push that first introduced its plaintext:

```
origin(v) = seq(push of v)              if the push carries no sameValueAs
origin(v) = origin(sameValueAs(v))      otherwise (an unknown target → 0, the safe side)
```

A `rotation.recommended` row R on the pair is **effective** iff (i) no
`rotation.dismissed` for the pair has seq > seq(R), and (ii) either the pair
has no pushed version yet, or `origin(live) < seq(R)` where live is the pair's
latest pushed version. (ii) is exactly "the value in use now is one the flag's
subject could have read" — the flag's own premise.

**Why 2-C is strictly better**:

- It is an **exact generalization** of today's rule: with only fresh pushes and
  re-encryption pushes, (ii) reduces to "no fresh push after R" — the current
  behaviour, bit for bit (a fresh push after R gives origin > seq(R);
  re-encryption inherits the origin, so it neither resolves nor un-resolves).
  Existing tests keep their meaning
- It answers the open question **without a new event, a new trigger kind, or
  a new persisted row** — "resolution state is derived from the event sequence"
  (§4.1) is preserved, and re-exposure falls out of the same fold
- It is **per subject**: with flags from two departures at seq 100 (M1) and 200
  (M2), restoring a value first pushed at seq 150 re-opens M2's flag only (M1
  left before that value existed) — 2-B would need to recompute this, 2-A can't
  express it
- A later fresh push resolves the re-opened flag again with no special case

**Display of a re-opened flag**: the flag wire gains
`reopenedByVersion?: number` — present when the flag had been resolved after
R and is effective again because version N restored a pre-flag value (N is the
push that re-opened it; a re-encryption of that restored value keeps N). The
CLI's `rotation list` and the Web Rotation screen say "re-opened by the
rollback in vN" so a flag that reappears is never unexplained.

**The pre-push warning** (the ROADMAP's "warn before pushing if the target
predates the flag"): the client cannot compare seqs (C1 forbids them on the
wire), so the server derives it. Each history row carries
**`flagsIfCurrent`** = the number of non-dismissed flags on the pair that would
be effective while that version's value is the live one (= flags with
`origin(v) < seq(R)`). For the live version it equals the pair's effective
flag count; for a rollback target it is exactly the number of flags the
rollback leaves (or makes) effective. `var history` shows it per row and
`var rollback` puts it in the confirmation. This is seq-exact where the
ROADMAP's epoch comparison was only an approximation (a fresh value pushed
after a removal but before the rotation sweep shares the old epoch).

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
   writer — the §12-7 shape) of versions k … min(k + 99, latest), ascending.
   The CLI pages until it reaches the verified latest. Authorization = the
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
   `sameValueAs = --to`, pinned to the resolved variableId: if a concurrent
   delete / rename makes the retry resolve anything but a normal push to that
   variable, refuse instead of creating a variable. The value lives only in
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
