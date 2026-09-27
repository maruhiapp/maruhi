# Session 46: S0 — the ruling record of the value-free schema (full) design + spec revisions

Date: 2026-08-30. Purpose: settle S0's major rulings (drafting the value-free-schema spec — a spec-and-docs-only PR; implementation is S1 onward) through "multiple options → upward-compatibility exploration → 3 rounds of comparison → autonomous choice", and record the rejected options with reasons. The round-1 material is docs/notes/value-free-schema.md (§1 the owner's already-decided items, §2–§5 the 8-round exploration, §6 open questions 1–12). The ruling symbols continue session-45's (…CQ) numbering, starting at **CR**.

Premises (not moved — owner ruling 2026-08-30): the full (name / type / description / required) implementation / MCP delivery deferred / `.env.schema` file is not made authoritative / H0 (hosted design + ADR-0014 revision) comes right after S0 — formalizing the order and the ROADMAP reorganization are H0's job. The starting point is the exploration memo §4's recommendation (the extension route = automatic inheritance via manifest coverage, including the correction from finding F).

Deliverable mapping: CRYPTO_SPEC 0.8-draft (§4.2 layout v2 / §4.3 coverage confirmation / §6.2–§6.3 / §11 / §14), AUTH_SPEC 0.16-draft (§12-2 / §12-5 / §12-7 / §12-8 / §12-10 / §12-11), AUDIT_SPEC §3.3, docs/notes/value-free-schema-design.md (the CLI and auxiliary surface + the implementation split S1 onward), a minimal wording update to ROADMAP Phase 3 ①②.

---

## 1. Ruling CR: the form of §4.2 layout evolution — the extension route + a statement-type-local layout version (issue (a), memo §6-1/10, finding F)

**Adopted**: the exploration memo §4's recommended **extension route** (adding the schema fields to `var_meta_signed_bytes`). The form of layout evolution is:

1. **A new domain-separation string `maruhi/v1/var-meta-sig-v2`** defines the second layout (v1 has 10 fields, v2 has 13 — `var_type` / `required` / `description` are inserted right after `status`). The domain string's version is local to the statement type; the suite (`maruhi/v1`) stays as-is
2. **The verifier's layout selection is driven by the wire's `layoutVersion`** (omitted = 1). layoutVersion is outside the signed material (a transport field), but verification cannot be broken — it is the same shape as CRYPTO_SPEC §1 principle 6's known residual "verification-mode selection": a false claim degenerates into recomputing signed_bytes under the other layout = a signature mismatch. All it buys is error-message quality (an honest failure mode)
3. **The old verifier's failure mode = decode-stage rejection**: a v2-capable client checks layoutVersion's supported range **before** signature verification, and refuses an excess with a typed error "unsupported layout (client update required)" (distinguished from an invalid signature = suspected tampering). The wire type of layoutVersion is an integer with no fixed upper bound, so that future bumps to v3+ always surface on old clients via this path
4. **The v1 layout stays valid** (existing statements need no migration — no mass migration). Statements that use neither schema fields nor declared may still be issued as v1 after v2 lands. They move to v2 at a natural reissue opportunity (a rename, a schema set)
5. **The activation gate for schema writes** is the per-project server setting `schemaPolicy` (default disabled — AUTH_SPEC §12-11; integral with ruling CV). The activation order is server → all members' CLI → enabling (the SELF_HOSTING "Updates" addition belongs to the implementation PR side — S2/S3)

**Rejected options**:

- **Bumping the whole suite to `maruhi/v2`**: §2's suite identifies the algorithm bundle (AES-GCM/HPKE/Ed25519), and v2 is reserved for a PQ hybrid KEM (§2, undecided #5). Spending it on a layout change (algorithms unchanged) would (i) make v2's meaning a compound of "PQ" and "schema fields", muddying the crypto-agility axis, and (ii) suggest every structure sharing the suite — values, DEK wraps, the chain — is versioned in lockstep (they are not). AUTH_SPEC §12-2's reservation "do not pre-empt v2" is about the algorithm version, and a statement-type-local layout version does not conflict with it — this distinction itself is codified by this ruling
- **Adding fields under the same domain string (variable-length LP)**: LP uniqueness (§2.1) is preserved, but an old verifier recomputes under the v1 layout and sees **a signature mismatch — the worst possible error message, indistinguishable from server tampering** (finding F-1). Moreover, "10-field v1" and "13-field v2" sharing one domain string makes the verifier's layout selection an implicit field-count branch, and principle 6's "information that selects the verification path" is made explicit nowhere
- **Re-reversing to the juxtaposed route (an independent schema statement type)**: a manifest entry is `LP(variable_id, status, meta_version, meta_sig_hash)`, binding only the variable statement's hash. A juxtaposed type falls outside the coverage, and including it would require changing `env_manifest_signed_bytes` (exploration memo §4 — brings back the signature-format change we wanted to avoid). A variant that puts the schema only on the wire while keeping signed material at v1 was verified and fails (meta_sig_hash does not cover the schema — tamperable, finding F-3)
- **Mass migration of existing statements (reissuing all)**: making migration a prerequisite means every variable × every environment gets a metaVersion+1 reissue plus a manifest reissue — the S2 deploy becomes a simultaneous ceremony across all projects. Coexistence with v1 staying valid removes the migration pressure itself (pre-publication, and existing statements' verification is unchanged)

**Applying upward-compatibility exploration** (folded into §8): an alternative that replaces the layout-selection rule with "branch on an unknown status value" (a statement carrying declared could split on status) was rejected because it cannot explain a v2 statement that has schema fields and is active (status is an incomplete branching input).

## 2. Ruling CS: the `declared` state and the activation compound — a first-class expression of "no value yet" (subordinate to issues (a)/(b) but recorded separately)

**Adopted**: add a third value to `status`: **`"declared"` (declared, no value set; v2 layout only)**.

- As the **sole exception** to the existing "a variable with no value does not exist" (AUTH_SPEC §12-5), add a compound accepted with no value: "a status-declared, schema-fields statement (metaVersion 1) + a manifest"
- **Activation (declared → active) is a compound with the first value push** (an EncryptedPayload version 1 + a status-active statement at metaVersion+1 + a manifest). Because the meta state changes, it involves a manifest reissue — the invariant "a value push never touches the manifest" (CRYPTO_SPEC §4.3) is unchanged (this is an activation, not a normal push)
- **Transitions are one-directional**: declared → active and declared → deleted are allowed. **active → declared is forbidden** (do not create an expression that rewinds the existence of a value — the only way to remove a value stays deletion). The existing ban on returning from deleted also applies to declared
- At the same time, a previously implicit structural anchor is promoted to a verification rule: **a variable holding a verified status-active statement whose value is absent from a valued distribution is rejected as missing (G6)** (CRYPTO_SPEC §6.3). Since declared legitimizes "no value", missing-value detection would loosen unless "legitimate value-free = declared only" is made explicit
- declared does not appear in the checkpoint's values_digest (active only — §6.2; the value does not exist). The manifest-side entry already enumerates status, so `"declared"` rides the coverage naturally as a new string value

**Rejected options**:

- **Representing "required declaration = a variable that does not exist yet" via environment meta / a separate table**: the declaration would leave the statement/manifest coverage, and the presence guarantee (ruling CU) would lose its "does not depend on a server claim" property. A shrunken re-creation of the juxtaposed route
- **Representing value-free as "an empty ciphertext version 0"**: the exception would propagate to every one of the AAD coordinates (version ≥ 1), "a variable with no value does not exist", and values_digest's semantics. Carrying "something that is not a value" in the value type also violates EncryptedPayload's boundary discipline (CLAUDE.md)
- **Allowing declared on the v1 layout too**: changing v1's status set would present an out-of-enum value to existing v1 verifiers (which decode status ∈ {active, deleted}) — honest in that it fails at decode, but it breaks the migration core "v1 is immutable and existing verification does not break" (ruling CR-4). Declaring is part of the schema feature and consistently v2-only

## 3. Ruling CT: the type system's scope and required's semantics (issue (b), memo §6-2/3)

**Adopted**:

- **`var_type` is the closed set `"" | "string" | "number" | "boolean" | "url"`** (`""` = unspecified). No validation DSL, regexes, or length constraints are introduced. **Enum is deferred** (too close to a value — it would open on the type side the same hole as real values leaking into description (finding D). A user cannot intuit that an enum value rides the meta = plaintext, server-visible surface). **No default values** (it steps half a pace into "value" territory and muddies the zero-knowledge line — per memo §6-3's recommendation)
- **required is "the environment's contract"**: a declaration that this environment should hold this variable's value. Since statements are per (environment, variable), per-environment required-ness is given by the structure itself (required in prod, optional in dev is naturally expressed by per-environment separate statements). What the code requires (things that must ride along with a branch) is not the schema's job — that surface is `maruhi schema lint` (S5 — finding G), which cross-checks the code itself as the source of truth
- **On v2 statements required is mandatory-explicit** (`"true" | "false"` — empty string not allowed). Do not disperse the omitted-default interpretation across client implementations (fail-closed; LP requires every field anyway, so it is natural as signed material)
- required's satisfaction test = "status is active" (decidable from verified statements alone — ruling CU). `maruhi run` / `ci run` fail-fast is hard on presence (required and declared → a hard error before running) and starts type checks as warnings (design doc §1-4)

**Rejected options**:

- **Including enum in the initial set**: see above. A future addition can be done as a closed-set Literal extension (acceptance side) + layout v3 (signature side) rather than a field addition to v2, so deferring costs nothing unrecoverable
- **Omitted required = an implicit default of true**: "forgot to write it = the strongest claim" is fail-closed in direction, but it makes a value on the signed bytes depend on a generation-side default interpretation — a poor fit with principle 6 (semantics live inside the signed bytes). Mandatory-explicit is simplest
- **Making required a cross-project contract on variable names**: variables are independent sets per environment (CRYPTO_SPEC §4), and a name-based cross-cutting contract bypasses the name ↔ ID correspondence-authenticity design (§4.2's point). The cross-cutting view is `maruhi env diff`'s display (S4)'s job

## 4. Ruling CU: the spec wording for splitting guarantees — presence hard / type soft (issue (c), memo §6-7, finding B)

**Adopted**: codified as norms in CRYPTO_SPEC §14.

- **Addition to §14.2 (guarantees)**: verifiability of required satisfaction (presence) — the schema fields and the declared state ride signed statements and enter manifest coverage (completeness, epoch freshness, checkpoint binding), so "are all required variables active" is decidable from the verified statement set alone, **without depending on a server claim**, by any verifier (including clients that cannot decrypt values). The server's room to falsely claim "a value exists" is sandwiched by the active value-distribution requirement (§6.3 — ruling CS), and its room to falsely claim "no value" by missing detection (manifest + checkpoints)
- **Addition to §14.3 (non-guarantees)**: agreement between a declared type and the value (type/format) is not guaranteed — under E2EE the server cannot verify in principle, and verification is only the client's advisory check at push time / run time. A subspecies of G9 (correctness of plaintext)
- **Display discipline**: a UI / CLI displays a type as a "declaration" and must not display "verified" in any context other than the party that ran the check (the client that performed that push / run). required satisfaction may be displayed as "verified from signed statements" (that one is hard)

**Rejected options**:

- **Making type server-verifiable too (type commitments, range proofs, etc.)**: introducing a ZK-proof system collides head-on with the no-primitive-invention ban (CLAUDE.md). Not worth raising the crypto spec's complexity class a notch for a 4-type closed set
- **Not writing the split into the spec, leaving it in the design doc**: the overclaim ban is a norm binding all display and documentation surfaces; since §14 is the sole source of truth on "what is not proven", a non-guarantee not listed there is one a future implementation or document will step on

## 5. Ruling CV: the schema-locked acceptance policy's form — a 3-tier project setting, not on the chain (issue (d), memo §6-9, finding E)

**Adopted**: unify the activation gate (ruling CR-5) and schema-locked (finding E) into **a single project setting `schemaPolicy` (disabled | enabled | locked; default disabled)** (AUTH_SPEC §12-11).

- `disabled` (default): rejects v2 statements (schema fields, declared) at acceptance with 422 — the activation gate protecting old verifiers. v1 acceptance is unchanged
- `enabled`: accepts v2. Schema fields are optional
- `locked`: enabled + **requires variable creation (metaVersion 1) to carry layoutVersion 2 and a non-empty varType** (422 `schema-required`) — write-time blocking of "creating a variable with no declaration" (typo shadow variables)
- **The declaration lives neither in a chain op nor in environment meta, but in a server project setting** (mutation requires admin scope × chain role admin or above, with the audit event `project.schema_policy_changed` — AUDIT_SPEC §3.3). Basis: this is a **write-acceptance policy (hygiene under an honest server)**, and since a malicious server can always ignore its own acceptance policy, putting it on the chain gains not one bit of adversarial guarantee (same character as §12-8's acceptance policies). The chain is "a ledger of key authenticity and authorization, not a ledger of mutable metadata" (CRYPTO_SPEC §6.2) — lease_policy rides the chain because it is authorization for key disclosure (the server is the verify-ee, not the verifier), a different character
- Distribution side: bundled as an advisory field in the environment list and pull responses (for client UX — not an input to verification rules)
- **Reversibility**: enabled → disabled only stops new v2 writes; existing v2 statements' storage, distribution, and verification are unchanged (verification does not consult the policy). locked → enabled likewise (consistent with the exploration memo's 8th-order removability walk)

**Rejected options**:

- **Making it a chain op (`set_schema_policy`)**: as above, adversarial guarantee does not increase, and a settings toggle would consume chain-entry budget (§6.4). Moreover, making it a consensus rule would be a breaking change via "unknown op = invalid chain" requiring simultaneous updates of all implementations, breaking S2's independent stoppability (a requirement of the implementation split)
- **Burning it into an environment-meta statement**: signatures and coverage are gained, but (i) every policy change requires environment-meta metaVersion+1 × all environments + a manifest reissue, and (ii) as an acceptance gate it is a value the server reads, not a value a verifier reads — there is nothing to sign for (signing covers "who declared what"; what is needed here is only auditing, which AUDIT_SPEC carries)
- **A per-environment setting**: no requirement for finer-than-project control exists right now, and per-environment differences (loose dev, locked prod) are largely absorbed by required's per-environment nature (ruling CT). Future refinement can be added backward-compatibly as an enabled/locked per-environment override (not pre-empted)
- **Default-enabled instead of opt-in**: in a project where un-updated CLIs remain, one upgraded member's write breaks everyone's verification (finding F-2). Default-disabled + explicit enabling mechanically enforces SELF_HOSTING's update order (server → all CLIs → enable)

## 6. Ruling CW: making the adversarial surface a requirement — description's length cap, neutralization, and entropy warning (issue (e), memo §6-8, findings C and D)

**Adopted**:

- **A 1024-character length cap (server acceptance policy — AUTH_SPEC §12-8) + rejection of control characters (including newlines), pinning it to a single line**. The cap suppresses DoS and simultaneously "suppresses the injection surface of data reaching agents" (finding C). Rejecting control characters simplifies the display-neutralization perimeter (most ANSI escapes and newline disguises are dropped at acceptance)
- **Display neutralization is an independent client obligation**: `maruhi schema` and other displays must always go through `escapeText` (apps/cli/src/display.ts — the ruling-CK precedent). Server acceptance checks do not bind a malicious server's distribution (even a verified statement can have a malicious signer — signed ≠ benign), so neutralization must not be skipped on the grounds that acceptance checks exist
- **The "data, not instructions" framing**: agent-facing output (the non-TTY output of `maruhi schema`, future MCP) carries a header note framing description as data (design doc §2)
- **The entropy warning is a write-time client check** (`schema set` / `schema import` — S3/S4): if a high-entropy substring (a secret-looking value) is detected in name or description, warn; in an interactive environment require confirmation; in a non-interactive environment refuse without an explicit flag (fail-closed). Thresholds and detectors are implementation details (S3); the spec pins only the requirement. A small precursor of ADR-0014 ⑤ (leak detection)
- **No server-side entropy check**: description is plaintext and server-visible, but a form where the server judges "secret-looking-ness" and rejects buys little against the confusion of false positives (422s on legitimate descriptions), and the value has already reached the server the moment it was written (the accident has already happened) — too late as a defensive position. The correct defensive position is the client at input time (before the accident)

**Rejected options**: Markdown support for description (widens the display-side attack surface — plain text only) / mandatory NFC normalization (description is not an identifier and is never used for matching — unlike name, byte-exact binding suffices) / making the cap a consensus rule (an acceptance policy suffices — leaves room for self-host adjustment, on the stated condition that raising it keeps neutralization and framing in place).

## 7. Ruling CX: the S0 specification scope of the auxiliary surface and the line to S1+ (issue (f), memo §6-4/6/11/12)

**Adopted** (details in docs/notes/value-free-schema-design.md):

| Surface | Treatment in S0 | Implementation stage |
|---|---|---|
| `maruhi schema` (display), `schema set` | Specified in the design doc (the agent-gate is explicitly on the **allowing** side — memo §6-5) | S3 |
| `maruhi run` / `ci run` fail-fast | Semantics specified (presence hard / type warning — rulings CT/CU) | S3 |
| Bootstrap (`schema import` — finding A) | The ceremony's form pinned in the design doc (an independent command; built-in to init is guidance only) | S4 |
| `maruhi env diff`'s schema awareness | Direction only | S4 |
| Derived snapshots (export + verify-snapshot — memo §3-2) | **Format = a JSON Schema subset (finding H) fixed as the first candidate**. The detailed mapping lands in S5 | S5 |
| `maruhi schema lint` (finding G) | Positioning only (best-effort, benign drift detection) | S5 |
| MCP delivery | Out of scope (owner-decided — after measuring demand) | — |

The line-drawing principle: **the semantics of signing, acceptance, and verification (surfaces that produce migration if changed later) are pinned in S0, while UX shapes (command form, output format, detector thresholds) have their direction pinned in the design doc and are settled in the implementation stage**. The exact mapping of the derived snapshot's JSON Schema subset (required's environment axis, the url type's representation) produces no migration cost when deferred to S5 because the snapshot is a generated artifact that is neither signed nor accepted (the store is the source of truth).

**Rejected options**: fully specifying verify-snapshot in S0 (a snapshot is a pure function of the verified store; deferring the format's details does not propagate to the signature surface — no benefit to early pinning) / specifying `schema lint` (code-scanning heuristics do not fit spec granularity — the same domain as BG tripwires: implementation documents).

## 8. Upward-compatibility exploration (post-drafting — changed the generation rules and ran to convergence)

A re-application of the exploration memo's 8 rounds (comparison → loser-trait inversion → mechanism synthesis → lifecycle → adversary → dual → skew → consumer inversion → cap/unify/remove) plus additional rounds under 3 new rules.

### Round 1: checking whether adopted rulings break earlier rulings' premises (the session-44 §13 pattern)

- **Consistency with §12-10 (1)'s strict-acceptance enumeration**: declared creation and activation are variants of "value push and meta operations (§12-5)" and fall under already-enumerated classes. A schema-policy PUT carries no signed structure — an exempt class; updating the enumeration takes only a clarification in §12-5. **No finding (consistent)**
- **§12-10 (3) the definition of mutation success**: declared creation and schema reissue are meta operations → effect is confirmed via a metadata-only pull (the existing rule applies as-is). Activation is a compound including a value push — the value-push exemption (pull pollutes var.read) intersects the statement-side confirmation duty. **Resolved**: activation's effect is confirmed via the statement + manifest (metadata-only pull — records no var.read), while the value side uses CAS + floor self-recording (the existing value-push discipline) — the split holds as-is. No spec addition needed (§12-10's existing text defines it per kind, and activation is a composition of both kinds)
- **Consistency with the §6.3 floor rules**: a declared variable has no version — the floor's variable record (version, epoch, meta_version, ...) advances only on the meta side; the value floor stays empty until activation. Rule (c)'s "a variable not on the floor counts as version 0" applies naturally to the first pull after activation. **No finding (the lattice stays monotonic)**
- **AUDIT_SPEC Q2 (the existence interval = var.created to var.deleted)**: recording declared creation as var.created puts an interval in which no value exists into the candidate set of "the set that was browsable" — but a rotation-needed flag on a variable with not even one value version is vacuous (there is no readable value) and does not mislead detection. The inverse option of making activation var.created would break the existing semantics "interval start = metaVersion 1". **Adopted: var.created = acceptance of metaVersion 1 (including declared); activation's value is var.version_pushed (version 1)**. A note was added to AUDIT_SPEC §3.3

### Round 2: failure / partial-application walk (new rule — "enumerate the worlds where each compound stops midway")

- Both declared creation and activation are single-request compounds (one decode, atomic acceptance — §12-10 (1)'s compound atomicity), so intermediate states like "a declaration exists but required is unknown" or "a value exists but status is still declared" are structurally impossible. **No finding**
- Contention between a schemaPolicy downgrade (enabled → disabled) and an in-flight v2 write: judged by the policy at acceptance time (normal serialization). After a downgrade, existing v2 verification and distribution are unchanged (ruling CV's reversibility), so no downgrade can break verification. **No finding** — **〔Added later: this judgment was incomplete. It missed the path where a downgrade freezes deletion/activation of existing v2 variables (because continuation statements must also be v2), which the PR #112 pullfrog review caught — resolved in §10〕**
- **Finding (small; resolved)**: a v1 variable creation racing a switch to locked could be accepted in a CAS gap — but the acceptance check reads the policy inside the project DO's serialization, so there is no contention window. The spec now explicitly says "judged by the policy at acceptance time" (§12-11)

### Round 2.5: enumeration consistency of the acceptance / authorization surface (new rule — "does the new operation appear without gaps in the existing enumerations" — run after the draft text was settled)

- **Finding (adopted)**: explicitly listed "declared creation, the activation compound, and schema settings" in the write row of §12-3's authorization table (the previous enumeration listed only create / push / rename / delete — leaving no room for the new compounds to fall through the table's interpretation). §12-10 (1)'s strict-target enumeration also now states the compounds' inclusion. §12-1's "authenticity of the active / deleted states" follows the 3-value update. §12-8's "variable count / environment (active)" now states how declared is counted (the §12-5 statement alone would not reach a reader of the table). All are enumeration refinements, not semantic changes

### Round 3: adversarial walk of the display / consumption surface (new rule — "enumerate every consumption point that reads the schema and check the injection surface")

- Enumerated consumption points: `maruhi schema` (TTY / non-TTY), `maruhi run`'s fail-fast error message (**it names the variable and the type — never the description**: description in an error message becomes an injection surface via logs — pinned in design doc §2), the web dashboard (future — a client render outside the RSC static shell + React's auto-escaping + CSP), the derived snapshot (S5 — JSON encoding doubles as neutralization, but the artifact header requires a "generated, data" framing), schema lint's cross-check report (S5 — variable names only). **Finding (adopted)**: added to the design doc's requirements that fail-fast errors and lint reports do not include description
- The injection surface of the name itself: name is already constrained by the existing acceptance rules (§12-1's character set is the env-var-name form) so no control characters enter. **No finding**

### Round 4: re-applying the exploration memo's 8-round rules (excerpt — deltas only)

- Re-applying the adversary walk: "a malicious member sets required=true on every variable to stop CI" — writes require member or above (same level as the existing rename), same class and same attribution (signature, audit) as rename-based sabotage (swapping names). Not a new threat class. **No finding**
- Re-applying the dual inversion (read ↔ write): schema-locked (write-time)'s read-time dual = run's fail-fast (ruling CT). Both directions are specified. **No finding**
- Re-applying the removability walk: the v2 layout itself cannot be removed (as long as signed statements exist, the verifier side must keep it) — but that is a property common to every signature format, and downgrading to schemaPolicy disabled puts the write side fully to sleep. **No finding (accepted)**

### Round 5: exhaustive check of the distribution channels (new rule — "enumerate every channel declared / the schema fields should flow through")

- Valued pull (§12-7), metadata-only pull (§12-7), the lease response (§14-2 — already bundles "the latest meta statements + the manifest", so declared flows naturally; `ci run`'s presence check has its material), the environment list (statement transport — §12-2). **No finding** (the existing discipline "a response returning names carries verifiable statements" covers it as-is)
- layoutVersion's wire type: making the distribution decode Literal(1, 2) would make v3 fail as a Schema error rather than "unsupported layout" — the spec already states "an integer with no fixed upper bound + a post-decode supported-range check" (§12-2). Pinning the implementation is an S3 test requirement. **No finding (the spec side is covered)**

### Convergence assessment

The new findings are round 1's AUDIT_SPEC note (adopted), round 2.5's 4 enumeration refinements (adopted), and round 3's "no description in error messages" (adopted) — all requirement additions or enumeration refinements needing no change to rulings CR–CX. Rounds 4 (re-applying prior rules) and 5 (all distribution channels) found zero. **Judged converged**.

## 9. Handoffs (to S1+ / H0)

- At the head of S1, commit the test vectors (CRYPTO_SPEC §11's 0.8-draft entry) before implementation (CLAUDE.md — crypto is vectors-first)
- The SELF_HOSTING "Updates" addition of the migration order (server → all members' CLI → enable) belongs to the S2/S3 implementation PRs
- Finding F′ (the O(N) round trips of a bulk import) is measured in S4 before deciding whether compound acceptance is needed (not pre-empted)
- H0 (hosted design + ADR-0014 revision) is right after this PR merges. Formalizing the S-series order and the ROADMAP Wave reorganization are H0's job
- enum, per-environment schemaPolicy, and MCP delivery are deferred until demand is measured (each deferred in a form that can be added backward-compatibly)

## 10. PR #112 review handling (a ruling supplement on pullfrog findings — 2026-08-30)

pullfrog detected 2 holes in the rules for "what happens to a variable after it becomes v2". Both are legitimate findings and were closed on the spec side before S1–S2 implementation (the signing / acceptance surface — the class that produces migration if changed later).

1. **Narrowing the activation gate's scope to "new v2 adoptions" (a refinement of ruling CV)**: the original "disabled = reject everything at layoutVersion 2" interacted with the schema-field / layout preservation rule (deleting a v2 variable is always v2) such that after an enabled → disabled downgrade, deleting existing v2 variables or activating declared variables became impossible — ruling CV's reversibility ("a downgrade only stops new writes") did not hold (§8 round 2's failure walk only looked at compound atomicity and missed this composition). Resolution: disabled rejects **only metaVersion-1 v2 creations and v2 reissues onto v1 variables**, and continuation statements of a variable whose latest is v2 (deletion, activation, rename, schema reissue) are accepted regardless of policy — the gate's purpose (preventing new v2s an un-updated client cannot read from appearing) is already unachievable for variables with distributed v2s, and stopping continuations adds no protection. **Rejected alternative**: codifying "downgrade = freeze existing v2s" and accepting it — a state where a declared variable can be neither deleted nor activated is an operational dead end and contradicts the spirit of removability (exploration memo 8th order)
2. **Adding per-variable layout monotonicity (supplementing rulings CR / CT)**: originally the schema-field / layout preservation rule was limited to deletion statements, so renaming a v2 variable under a v1 layout silently dropped the schema fields — a required = true declaration disappearing with no explicit operation broke the premise of the presence guarantee (§14.2-8), and locked could be bypassed by "create as v2 → drop to v1 via rename". Resolution: **a continuation statement of a variable whose latest is v2 must be layoutVersion 2** (acceptance is 422 `layout-regression`; client verification checks within the prev-known range — CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5). The schema-field values may be explicitly changed in a later v2 statement (a legitimate operation to lower required). The §11 negative list gained "a v1 continuation on a v2 variable (layout regression — rename form)"

Lesson (into the next exploration rules): the failure walk must enumerate not just "a compound stopping midway" but "**the cross product of configuration transitions × every lifecycle operation**", and the consumption-side walk must enumerate "**every statement kind** where a new rule intersects an old rule (the preservation rule)".

Round 2 (re-review of 527e895 — all resolved by making rules unambiguous; no structural spec change):

3. **Unifying when the schema-locked check applies (clarifying ruling CV)**: locked's check was limited to creation time (metaVersion 1), but the monotonicity addition codified "schema-field values may change in later v2 statements", leaving ambiguous whether it was "a one-time check at creation" or "a standing invariant". Ruling: **the one-time check at creation is correct** — what locked blocks is "the silent creation of shadow variables via typos", which the creation-time check completes. A later lowering via an explicit schema reissue (returning varType to `""`) is an explicit operation leaving signature and audit, handled the same as lowering required. Activating a declared variable created without varType in the enabled period is not a creation and does not apply retroactively. **Rejected alternative**: making it a standing invariant (requiring non-empty varType on every later v2) — forbids the legitimate "withdrawing a type annotation" and lets a switch to locked block activation of a declared variable created in the enabled period (the same freeze as §10-1), while adding nothing against the threat it blocks (typo creation)
4. **Settling `schema set`'s merge rule (design doc §1-2)**: partial update vs full replacement was unspecified, and since v2 requires required to be explicit, running `--description` alone could read as a full replacement where type and required silently fall away. Ruling: **partial update** (unspecified fields carry over the latest statement's values; returning to empty requires an explicit flag) — do not let the CLI reproduce the "silent disappearance" that monotonicity closed off.

Round 3 (re-review of 205405f):

5. **Settling the default on `schema set`'s creation path (design doc §1-2)**: partial update's basis is "the latest statement", and the creation path (no such variable = declared, metaVersion 1) has nothing to inherit from — since v2 requires required to be explicit, running a fresh `--description` alone left required's value undetermined by the spec. Ruling: **`required = true` is the creation default** (a declaration's purpose is establishing the environment's contract — ruling CT — and a false default would make the declaration contribute nothing to fail-fast, silently spinning. It also matches fail-closed's failure direction — an excessive required surfaces as a visible error before run executes and can be explicitly lowered with `--optional`). An unspecified `--type` means `varType = ""`. Consistency with CT's "no implicit defaults": that rejection concerned generation rules for the signed bytes (dispersing the omitted interpretation across implementations); a form where the CLI picks a default and **always puts an explicit value on the wire and prints the chosen value in its output** does not conflict with it. Under `locked`, an unspecified `--type` is a typed error at a local pre-check before signing (no waiting for a server-422 round trip — the acceptance authority stays the server's). **Rejected alternative**: `required = false` as the default — disables the declaration's main use (the presence contract) by default, and the surprise "I declared it but run sails through" is discovered later than "declaring made it required" (the former is silent, the latter visible immediately).
