# Session 16 notes (implementing the local floor — implementation PR-4 of the session-12 spec)

- Date: 2026-08-04
- Target: the CLI implementation of the approved CRYPTO_SPEC §6.3 "local floor" (SHOULD,
  normative) (implementation PR-4 of session-12 §9 — persistent detection of rollback,
  omission, and forward injection [values only] + the UX for reporting fork evidence)
- Premise ruling: session-12 §10-4 (introducing the CLI local floor = as the SHOULD says.
  Includes the policy change to session-11 §2-3's "the CLI never caches the chain") was
  finalized by the PR #27 merge
- Scope: the CLI only. wire / server / the crypto package are unchanged (no new cryptography =
  no test vectors added). Value signatures and meta verification (PR-2 / PR-3) are unchanged
- **PR #33 was merged on 2026-08-04** (squash merge `74ce574`. The §2 rulings are
  owner-approved. §6's ROADMAP sync and the three §6.3 spec-sync items were reflected in the
  post-merge session 16.5)

## 1. What was done

1. **The floor store** (`apps/cli/src/floor.ts`): the non-secret persistence layer. Writes only
   the non-secret digests enumerated in §6.3 to `<config dir>/floor/<projectId>.json` — the
   chain head (hash + seq) / each variable's latest version · **that version's epoch** ·
   metaVersion · the signed-bytes hashes of value and meta (deleted keeps only the tombstone's
   metaVersion + hash) / per environment "the chain-derived current epoch at the last
   successful pull (verification included)" (rule (c)'s reference `pullEpoch`). **No plaintext
   values, key material, variable names, or environment names are written** (all keys are IDs —
   the diskless invariant). Atomic update via temp + rename, strict decoding (a schema mismatch
   treats the whole file as corrupt — no partial reads), fail-open reads (missing = first sync /
   corrupt = distinguished and returned)
2. **Wiring the floor check** (`floor-check.ts` + values / pull / push / cli):
   - The chain floor (the chain part of rule (a)): after the sync check of `openProject` /
     `project verify`, reject shortening (headSeq regression) and hash mismatch at the floor's
     seq position (immediate evidence of a fork — via the prev_hash chain, matching at the
     floor seq means all entries below the floor match). After passing, advance the verified
     head into the floor (`commitHead` — rule (c)'s reference is not moved)
   - The environment floor (rules (a)(b)(c)): checked after `pullVerifiedEnvironment`'s §6.3
     verification succeeds — omission (a variable or tombstone in the floor is absent from the
     response) / regression of version, metaVersion, or epoch / differing signed bytes at the
     same version or metaVersion / unauthorized un-deletion / rule (c) (a version newer than
     the floor's whose epoch is below the `pullEpoch` reference). On passing, the new
     environment floor (variable floor + the reference's advance = this round's chain-derived
     current epoch) is committed **atomically in a single file write** (§6.3's update-order
     norm)
   - push: after acceptance, advance the variable floor with one's own write (the self-computed
     signed-bytes hash — the server echo is not used) (`commitPush` — `pullEpoch` unchanged).
     The resolving pull and the 409 re-fetch pull inside push also get the floor check and
     floor commit (`FloorHandle` carries the reference within the process)
   - A floor-check failure is **rejection + non-zero exit** for pull / push / run alike (the
     strong side of §6.3's "reject, warn" — everything compared is verified-signed data, so a
     mismatch is non-repudiable evidence with no false-positive concern)
3. **The fork-evidence reporting UX** (`floor-evidence.ts`): the rejection message bundles the
   coordinates (project / environment / variable — all IDs), the floor side's and the
   distributed side's signed-bytes hashes, the distributed side's declared head, and the kind —
   as multi-line text presentable to a third party (§14.2-5's non-repudiable evidence). No
   plaintext values, key material, or names are included (a name itself may be the contested
   object)
4. Tests (§7) and this memo

## 2. Ruling details (multiple candidates compared → adopted. Options not taken and why)

### 2-1. Location = `<config dir>/floor/<projectId>.json` (same family as config)

- **Adopted**: a `floor/` subdirectory under the same resolution rules as config.json
  (`MARUHI_CONFIG_DIR` → `XDG_CONFIG_HOME/maruhi` → `~/.config/maruhi`), one file per project.
  projectId = genesis hash is globally unique, so the server origin is not part of the key
  (task-specified). The hex-64 form is enforced before using it as a filename (prevents
  untrusted strings entering the path)
- Options not taken:
  - **XDG_STATE_HOME** (`~/.local/state/maruhi`): semantically it is "state", but XDG's state
    is aimed at logs and history — "things you can do without". The floor is security-detection
    material and is better preserved alongside config, which gets backed up and synced. Tests
    and advanced-user overrides also stay on the single `MARUHI_CONFIG_DIR`
  - **OS keychain**: the floor is non-secret (hashes and sequence numbers only) and needs no
    keychain protection. It has capacity/availability constraints, and on headless Linux
    Bun.secrets' no-response blocking has been measured (live.ts). It falls under "non-secret
    configuration" of the three categories the CLI may persist
  - **A single file for all projects**: the atomic-update granularity becomes coarse, and the
    write-collision radius for concurrent CLIs (operating on different projects) widens

### 2-2. Format = JSON + schema version (`v: 1`) + strict decoding

- **Adopted**: one JSON file, same family as config.ts. Decoding is strict per field (positive
  integer, hex 64), and **any breakage treats the whole file as corrupt** — a half-valid floor
  blurs the distinction between "checked" and "not checked"
- Options not taken: a line-oriented append log (appends are atomic, but it does not meet the
  "rule-(c) reference and variable floor in one transaction" norm, and needs compaction),
  SQLite / KV libraries (a new dependency — keep the supply chain small, same as the frontend)

### 2-3. Atomicity and concurrency = read-merge-write with temp + rename (no lock · **monotonic merge**)

- **Adopted**: merge into the latest file just before writing, then temp + rename. The merge
  rule is **monotonic** (revised from the original "the pull commit replaces the environment
  floor" after review ②'s major finding): the chain head takes the side with the larger seq /
  `pullEpoch` takes max / environment meta takes the side with the larger metaVersion / the
  variable floor monotonically merges the value side (version) and the meta side (metaVersion)
  independently / deleted is terminal and is not overwritten by active / variable keys are
  unioned (keys of a legitimate floor never disappear — deletion also persists as a tombstone
  record)
- The original full-replacement merge let a floor on disk **regress** when a stale commit
  landed later inside the read-merge-write window, and a malicious server controlling landing
  order via response delays could keep "rolling back detection material that a concurrent
  process had established" alive (it creates no wrongful rejections, but leaves a window of
  wrongful **acceptance**). Monotonic merge closes this — both inputs are floor records that
  passed §6.3 verification, so per-field max composition is sound
- No file locking: under monotonic merge a concurrent CLI has nothing to lose (every commit
  only moves the floor in the stronger direction), and flock would import the separate
  complications of platform differences and release-on-stall
- `commitPush` does **not** create an environment record when the environment floor is absent
  (e.g. concurrent corruption): rule (c)'s reference (pullEpoch) can only be settled by a pull,
  and fabricating it here would violate the norm "chain sync alone does not advance the
  reference" (only the head advance is reflected)

### 2-4. The fail-open line

- Reads: a missing file (first sync) and corruption both continue as "no floor" + a
  distinguished message (first sync = "note: … first sync" / corrupt = "warning: … corrupt.
  Continuing with no floor"). An attacker who can erase local state is outside the floor to
  begin with (it reduces to §14.3-3's non-guarantee), so going fail-closed here adds no
  guarantee
- **missing is ENOENT only** (revised after review ②'s major finding): treating transient read
  failures like EACCES / EIO as "first sync" would (a) make the load side emit the wrong
  "first sync" guidance, and (b) make the write path's read-merge-write rebuild from empty and
  **erase the entire floor without warning** (invisibly disabling the detection mechanism — a
  counterexample to this section's own principle). Read failures other than ENOENT abort as
  errors
- **A corrupt floor is quarantined before rebuilding**: a corrupt file is renamed to
  `<path>.corrupt-<timestamp>` before the next commit (the floor file is half of the evidence,
  and the corruption shape itself is forensic material — reviews ①③'s point)
- **Write failures are not fail-open** (abort with an error): an unwritable floor disables the
  detection mechanism, and silently continuing would give a false sense of "the floor exists".
  Same treatment as a config-file write failure. Only a floor-write failure after push
  acceptance is prefixed with "the push was accepted, but …" so it is not mistaken for the
  push itself failing

### 2-5. deleted is terminal — the floor demands exact match

- A variable whose floor recorded deleted rejects an active distribution as an unauthorized
  un-deletion, and a tombstone must **exactly match** the floor in metaVersion and hash
  (advancing is rejected too). Rationale: deletion is terminal and no legitimate follow-up
  statement exists (§4.2's "no re-activation after deleted" + session-15 §2-2's "if the
  predecessor is deleted, reject every successor"). A latest-only pull cannot check the
  predecessor, but a floor that knows deleted can enforce the same semantics at distribution
  time
- Conversely, a tombstone advancing metaVersion on a variable whose floor is active is
  accepted as a legitimate deletion and the floor advances to deleted

### 2-6. Rule (c) also applies to new variables absent from the floor (version-0 equivalent)

- In an environment where a floor exists, a distribution of a variable absent from the floor
  is also rejected when it carries an epoch below the `pullEpoch` reference. The argument: a
  variable that existed at the previous pull is on the floor via the bulk pull. So a variable
  absent from the floor was created after the previous pull, and a legitimate creation (the
  server accepts the current epoch only — §12-5) has an epoch ≥ the reference's. A "new" below
  the reference is the shape of a backdated creation under an old-epoch key
- The two edges of wrongful rejection follow §6.3's norm: the reference is the value of the
  last successful pull (chain sync alone does not advance it), and **at or above** the
  reference is accepted (the legitimate old-epoch latest value right after rotation, before
  re-encryption completes — §12-7). The reference's advance commits atomically with the
  variable floor after verification succeeds

### 2-7. The chain-head floor also advances on successful syncs (suspected shortening → bounded re-sync)

- `commitHead` runs after openProject / project verify's sync check + the chain-floor check
  pass (independent of whether a pull succeeded). §6.3's stored item is "the last **verified**
  chain head", and unlike rule (c)'s reference it has no wrongful-rejection edges (an honest
  server's head is monotonic, and the head-floor check requires only extendability)
- **A floor head ahead of one's own view (headSeq regression) is not immediate evidence**
  (revised after review ②'s major finding): the order is chain fetch (sync) → floor load, so
  if a sibling process commits a newer head into the floor in that gap, "own view < floor
  head" holds even when everyone is honest (the seq comparison depends on local fetch order,
  not on a contradiction between two signed artifacts). Resolution is attempted with a
  **bounded re-sync (once)**, the same shape as §6.3-2b, and if it is still short afterward it
  is rejected as shortening evidence. A hash mismatch at the floor's seq position stays an
  immediate rejection — it is a contradiction between two verified artifacts (hard evidence)

### 2-9. Rule (c)'s reference is derived from "the view before the response was fetched" (preventing over-advance on the re-sync path)

- **Revised after review ②'s major finding**: on the bounded re-sync path for future heads,
  re-verification runs against a chain fetched **after** the pull response was generated (T₂
  vs T₁). The original implementation also derived the reference's advanced value from the T₂
  view, so a rotate landing between T₁ and T₂ advanced the reference beyond "the epoch the
  response could have known" (over-advancement), after which rule (c) would keep wrongly
  rejecting the legitimate old-epoch latest value of "after rotation, before re-encryption
  completes" (§12-7) (a lockout until re-encryption completes + a false equivocation
  accusation). This was a missed application of §6.3's "chain sync alone does not advance the
  reference" norm to the re-sync path
- The fix: `enforceFloor` separates the verification view (commitView) from the
  reference-derivation view (baselineView = **the view verified before the response was
  fetched**). As long as the reference ≤ the epoch at response-generation time, the epoch of
  any legitimate push accepted afterward is always ≥ the reference, so no wrongful rejection
  occurs (the non-re-sync path has always satisfied this property). In the rare race where the
  reference-derivation view lacks the environment (the environment was created between the
  response and the re-sync), the floor commit is skipped (established on the next pull —
  choosing one round late over over-advancement)

### 2-8. Evidence output format = multi-line text on stderr (with signature and attribution)

- A kind label + coordinates (IDs only) + the floor side's record + the distributed side
  (signed-bytes hash, declared head, **the signature value and attribution** = the writer /
  author user_id and key FP — added after review ①'s finding) + preservation guidance. Options
  not taken: JSON output (the current CLI has no `--json` precedent, and a machine-readable
  format should be designed together with the CLI's overall output design — handoff),
  auto-saving an evidence file (non-secret or not, the decision to add "a file the CLI writes"
  should be made carefully. The floor file itself already holds half the evidence)
- Not fully self-contained (no bundled signed-subject preimage): for values, the nonce /
  ciphertext hex can be huge. For meta, the preimage includes the name, colliding with the
  "no names in evidence" decision. Preimage preservation/export is designed together with
  machine-readable output (handoff)

## 3. An honest record of the guarantee range (what this PR closes / does not close)

**Closes** (for a returning client = one holding a floor): chain shortening / forks at the
floor's seq position / omission of variables and tombstones / regression of version,
metaVersion, and epoch / differing signed bytes at the same version or metaVersion
(equivocation evidence-preservation) / unauthorized un-deletion and tombstone substitution /
rule (c) = old-epoch injection into a forward version (the value part of §14.3-5's forward
direction).

**Does not close (3 residuals)**:

1. **Forward injection of meta statements (the most important)**: meta carries no epoch anchor
   (§4.2), so a fake statement claiming the real latest's next metaVersion (a valid attributed
   signature) is **not detected even with the floor** (§14.3-5). **The meta floor is
   rollback-detection only**. This implementation places no check or wording that could be
   mistaken for "detected", and includes a test that explicitly pins the non-detection
   (floor-detection.test.ts's "forward injection of meta is not detected even by the floor").
   Closure is the responsibility of Phase 2's environment manifest / checkpoint (undecided
   #12) and head gossip
2. **First-sync clients**: distributing an "internally consistent old view" to a client with
   no floor (§14.3-3). An attacker who can erase the floor file reduces to the same class
   (fail-open — §2-4)
3. **The rotate window and residual (iii)**: the window from remove / demotion until the
   all-environment rotate completes (short under §7's operational obligation but not a
   mechanism guarantee), and a returning client whose epoch floor for that environment is
   older than the attacker's membership interval (§14.3-5 (iii) — rule (c)'s reference is
   at-or-below the attack coordinate's epoch, so it does not fire)

Notes (written up in review ③):

- **Unauthorized un-deletion of an environment is outside the floor's detection**: a deleted
  environment's statement distribution is rejected earlier than the floor
  (`verifyEnvironmentStatement` — distributing a deleted environment on pull is always
  rejected), so the floor has no path to learn an environment's deleted state, and §6.3's
  stored enumeration has no environment-deletion entry either (the detection material is the
  deleted statement on the environment-list side — session-15 §2-4)
- **Floor "poisoning" via meta forward injection**: once a fake tombstone (a forward
  metaVersion) is accepted into the floor as a "legitimate deletion", every subsequent genuine
  active distribution keeps being rejected as "unauthorized un-deletion". The rejection itself
  is correct (a fake tombstone and a genuine active are two contradictory valid signatures =
  true equivocation evidence, which cannot occur under an honest server), but the user's
  recovery path is quarantining/deleting the floor file (= degrading to a first sync). Writing
  this up in operational documentation goes into the pre-publication documentation work
  (handoff)

## 4. Impact on existing code

- `VerifiedPulledValue` gains the declared-head 4 fields (value and meta) (evidence material).
  `verifyAll` now also returns the verified digests of environment statements and tombstones
- Updated the expected messages of push's 3 409-retry tests: the floor that the first pull
  committed now detects the same attack (rollback, omission, epoch regression) at the re-fetch
  pull **before the winner check**. `winnerValueRegression` / `winnerMetaRegression` are not
  removed — kept as a defensive layer (for when the floor is unavailable + cross-checking
  against the 409-declared currentVersion and the adjacent prev check — checks the floor does
  not have)
- session-15 §8's handoff "the path where `reresolveTarget` discards a verified floor without
  comparison" is effectively closed — every pull including re-resolution pulls goes through
  the floor, so a post-re-resolution rollback distribution is detected by the in-process floor
  (FloorHandle)

## 5. Where we got stuck and environment findings

- **Deterministic chain extension in tests**: `buildChain` uses a fixed timestamp + Ed25519
  (deterministic signatures), so two chains sharing the same steps prefix are byte-identical
  on the shared prefix. `chain1` (epoch 1) and `chain2` (+rotate) built separately still form
  an exact extension, so the floor's "rotate across sessions" fixture could be written
  straightforwardly (conversely, a fork `chainB` of the same genesis is made just by changing
  the create DEK)
- **The fallow complexity gate**: a single evidence-formatting switch (11 cases) lands on the
  audit at cyclomatic 13. Resolved by splitting into chain-family / variable-family switches.
  `fallow audit` compares against the merge-base with the branch's upstream, so on an already-
  pushed branch it only sees the local uncommitted portion — pass `--base main` explicitly to
  get the same judgment as CI
- **Distinguishability of warning wording**: if the corrupt warning's body says "treating as
  first sync", tests can no longer mechanically distinguish it from the first-sync message.
  The corrupt side was unified to "continuing with no floor"
- The floor's effect on existing tests is only that a "first sync" notice line appears on
  stderr (existing `toContain`-based assertions are unharmed). No test calls runCli twice, so
  the floor never fires there

## 6. Handoffs

- **ROADMAP sync**: the spec sync that records PR-4 (this PR) completion in Phase 1's CLI /
  authenticity items happens after merge (the same practice as session 15.5) (→ reflected in
  session 16.5)
- **Spec sync into §6.3 (three points where the implementation is stricter than the spec —
  review ③)**: (i) rule (c)'s "a variable absent from the floor = version-0 equivalent"
  application (§2-6), (ii) the floor for environment meta statements (§6.3's enumeration
  covers only variables' meta_version), (iii) storing meta signed-bytes hashes (needed for
  rule (b)'s meta application). All strengthen detection, but take the shape of the
  implementation rejecting distributions the spec accepts, so a proposal is made to a human to
  append them to §6.3 in a post-merge spec-sync PR (or to state explicitly "the implementation
  may be stricter than the spec") (→ reflected in session 16.5 as a normative addition to
  §6.3. The explicit "the implementation may be stricter" was not taken — the enumeration side
  was aligned with the implementation to avoid detection-rule divergence across
  implementations)
- **Operational documentation of recovery from floor poisoning** (§3 note): the procedure of
  quarantining the floor file → degrading to a first sync, and an explanation of which
  guarantees are lost. In the pre-publication documentation
- **Machine-readable evidence output**: currently only multi-line stderr text. A
  machine-readable form like `--json` and evidence export are considered together with the
  CLI's overall output design (§2-8)
- **Floor concurrency exclusion**: lock-free read-merge-write (§2-3). If lost updates are
  observed under heavy concurrent-CLI operation, consider introducing flock (does not affect
  detection correctness — the floor only thins)
- **A floor summary in `project verify`**: currently it is just the chain-floor check + head
  advancement. Displaying the floor's contents (per-environment reference, variable count) is
  a UX-improvement candidate
- **Closing meta forward injection** stays with Phase 2 (environment manifest / checkpoint =
  CRYPTO_SPEC undecided #12, head gossip). This PR does not change the situation
- session-11 §5's remainders (the public-settings endpoint / extracting shared test support /
  the pull metadata-only mode) and the chain-append command family + remove_member's
  all-environment rotate (including session-12 §10-7's compoundization review) remain valid
  and unstarted

## 7. Test results

- CLI: **186 tests green** (existing 128 + 27 floor-store unit + 31 floor-detection wiring).
  Covers session-12 §8-5's floor items: omission (variables · tombstones · the 3 paths of
  pull / run / push) / rollback (version / metaVersion / environment metaVersion / epoch /
  chain length) / both edges of rule (c) (accepting the legitimate old-epoch new version right
  after rotate + rejecting an old-epoch forward version after the reference advanced +
  applying it to a new variable absent from the floor) / evidence-preservation of differing
  signed bytes at the same version · metaVersion (value, variable meta, environment meta.
  Including output verification of both hashes) / the two-way fork distinction (mismatch at or
  below the floor seq = immediate evidence, beyond the floor = bounded re-sync → accept on
  extension, evidence if unresolved) + bounded re-sync of the floor-head-ahead race / fail-open
  for missing and corrupt + the distinguished warnings / quarantining a corrupt floor /
  fail-closed on non-ENOENT read errors / a rejected pull not advancing the floor (update
  order) / floor advancement after push acceptance / monotonic merge (no floor regression ·
  deleted terminal · union) / unauthorized un-deletion (3 metaVersion cases) / establishing an
  environment floor from a commitHead-only floor / pinning the non-detection of meta forward
  injection (both variable and environment) / `constructor` / `prototype` keys treated as
  legitimate IDs / syncing the handle's cache with the commit return's merged floor
- `bun run check` (fmt / lint / typecheck / importlint / fallow audit / doctor / test) green —
  867 tests total. `fallow audit --base main` (CI-equivalent) also reports no issues. The
  4-runtime tests are out of scope because the crypto package is unchanged

## 8. Review → fix loops (in-PR. Parallel review by 3 viewpoints → fixes)

After implementation completed, an independent parallel 3-viewpoint review (①
security/crypto ② correctness/concurrency ③ spec-conformance/test coverage) was run. No
blockers. 4 majors (① and ② partially reporting the same finding) were fixed in code, cheap
minors were handled at the same time, and the rest was settled by record or handoff.

### Findings that were fixed

- **[major / ①②] non-monotonic floor merge (TOCTOU)**: `applyPull`'s full replacement of the
  environment floor + `applyPush`'s insufficient guard meant that inside the read-merge-write
  window a stale commit landing later would regress the floor on disk, and a malicious server
  controlling landing order via response delays could keep detection material rolled back. →
  Revised to monotonic merge (§2-3. pullEpoch = max · per-field monotonicity of the variable
  floor · deleted terminal · union). Pinned by unit tests
- **[major / ②] over-advancement of rule (c)'s reference on the future-head re-sync path**:
  deriving the reference from the post-re-sync view let a rotate between response generation
  and re-sync over-advance the reference, so the legitimate old-epoch latest value would keep
  being wrongly rejected until re-encryption completes (with a false equivocation
  accusation). → `enforceFloor` was split into baselineView (the pre-response-fetch view) /
  commitView (the verification view) (§2-9). The test expectations were also corrected toward
  the norm
- **[major / ②] false firing of the chain floor's "shortening" under concurrent CLIs**: in the
  gap between sync → floor load, a sibling process advancing the floor head produced a false
  "shortening" accusation even when everyone was honest. → Added a bounded re-sync (once) of
  the same shape as §6.3-2b (§2-7). Both resolving the race and rejecting a true shortening
  are pinned by tests
- **[major / ②] misclassifying read errors as missing**: every readFile exception was treated
  as "first sync", so EACCES / EIO etc. could erase the entire floor without warning (the load
  side's wrong "first sync" guidance; the write side rebuilding from empty). → missing =
  ENOENT only (§2-4). Fail-closed on EISDIR is pinned by a test
- **[minor / ①③] merge protection for the deleted terminal**: bundled with the first major's
  fix (deleted is not overwritten by active)
- **[minor / ①] evidence self-containedness**: added the distributed side's signature value
  and attribution (user_id + key FP) to the evidence output (§2-8). The preimage is not
  bundled (the reasons are also in §2-8)
- **[minor / ①②③] quarantining a corrupt floor**: renamed to `.corrupt-<ts>` before
  rebuilding (§2-4). Pinned by a test
- **[minor / ③] test gaps**: added equivocation of environment meta / non-detection of
  environment-meta forward injection / the 3 metaVersion cases of unauthorized un-deletion /
  a floor with only commitHead → a subsequent pull

### Findings settled by record (no code change)

- [minor / ③] the 3 points where the implementation is stricter than the spec → §6 handoff
- [minor / ③ nit] an e2e test of the "push was accepted, but …" prefix on post-push-acceptance
  floor-write failure: injecting a partial write failure into the real file store would be
  needed, so it was kept at unit level (write is fail-closed). The path is one mapError stage
- [info / ①②] the floor-commit point = §6.3 verification succeeding (wrap verification /
  decryption failures do not roll it back) — the interpretation is now written in
  `enforceFloor`'s JSDoc
- [info / ①] floor poisoning via meta forward injection and the recovery path → §3 note + §6
  handoff
- [info / ③] environment unauthorized un-deletion is outside the floor's scope → §3 note
- [nit / ①②] `.tmp` crash leftovers and schema forward compatibility (an old CLI treats v2 as
  corrupt → quarantines and rebuilds) — no real harm at present; record only

### Re-review (loop 2)

The fix diff was sent back to the 3 viewpoints for re-review. ② and ③ converged; ① detected
**1 new [major]** in the part bundled with the loop-1 fix (the `__proto__`-family key
defense):

- **[major / ①] the mistake of treating `constructor` / `prototype` as dangerous keys**: of the
  key-rejection set added in loop 1's decode (`__proto__` / `constructor` / `prototype`), the
  latter two **match §12-1's legitimate ID format**
  (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`). Pulling a variableId `constructor` even once makes the
  floor treat itself as corrupt, and the permanent loop of "corrupt warning + quarantine +
  rebuild → re-ingested on the next pull" disables floor detection (triggerable with member
  authority). Furthermore, a bare bracket reference (`record[variableId]`) resolves a
  `constructor` absent from the record to Object.prototype's inherited property (a function),
  inviting mis-checks and floor self-destruction. → (1) decode's key validation changed to
  "a key not matching §12-1's format = corrupt" (`__proto__` is excluded structurally — its
  leading `_` fails the format. `constructor` / `prototype` are accepted), (2) all dynamic-key
  reads of floor records were unified to `floorRecordGet` (an own-property read) (floor.ts's
  merge, floor-check.ts's rule (c), cli.ts's handle initialization). Acceptance and rejection
  in decode plus e2e of floor establishment + rollback detection under variableId
  `constructor` are pinned by tests
- **[minor / ②] the chain floor's bounded re-sync lacked an extension check**: doing the
  suspected-shortening re-sync with a bare `syncProject` would miss the evidence when the
  first view itself was forked (shortening + fork combined). → Changed to `resyncExtended`
  (with the extension check). An honest stale view is always a prefix of the re-synced view,
  so there is no false firing

### Re-review (loop 3)

The loop-2 fixes (correcting the key validation, own-property reads, the extension check) were
re-confirmed with ①, and convergence was confirmed. Every fix is either a correction of the
acceptance range (removing wrongful rejection of legitimate IDs) or a strengthening of checks;
the floor's detection rules and update order are unchanged. All quality gates re-run green.
Converged with zero blocking / new major findings.

### Automated-review handling after the PR went public (Cursor Bugbot — 2026-08-04)

Bugbot flagged 2 High Severity findings (same root): `FloorHandle`'s in-process cache is
updated after a commit with the **pre-send snapshot** (pull's environment floor / push's single
variable) and disagrees with the **merged floor** the store wrote to disk via read-merge-write
— subsequent checks in the same command (push's retry loop etc.) miss the detection material a
concurrent CLI established on disk (unioned variables, a deleted terminal, newer version /
pullEpoch).

- Of the findings, "rule (c) can fire wrongly" does not hold (the memory side's pullEpoch only
  ever errs to the lower = permissive side), but "missing a sibling process's detection
  material" is real (a detection-loss window — not a wrongful rejection)
- The fix: `commitPull` / `commitPush` were changed to **return the merged environment floor
  written to disk**, and the handle's cache adopts it (only in the rare shape where commitPush
  has no environment record does the in-process knowledge advance as before). Since the
  on-disk floor is written only with §6.3-verified records by this CLI, adopting the merged
  result is sound as a check basis (an attacker who can write local state is outside the floor
  — same line as fail-open)
- The store's return value (union / null) and the handle's cache sync are pinned by tests. The
  pre-commit window (the snapshot at openProject time) remains, but that is the knowledge at
  floor-load time itself and reduces to §2-3's one-generation residual
