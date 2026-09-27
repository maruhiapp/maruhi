# Exploration memo on the value-free schema (full) — seed for the S series

Date: 2026-08-30. Position: **an exploration memo (not a ruling)**. Rulings
happen in the S series (value-free schema's spec revision → implementation)
design PRs, in the "multiple options → strictly-better search → 3-round
comparison → autonomous choice" format. This memo records the initial
candidates and the opened questions. Provenance: ADR-0014 (what we steal
from Varlock is only the agent-isolation idea) / ROADMAP Phase 3 ① (name /
type / description / required only; no `.env.schema` file as the source of
truth).

## 1. Owner-settled items (dialogue of 2026-08-30)

- **Implement the full version (name / type / description / required)**.
  Don't stop at v0 (name only)
- **MCP distribution is deferred** (for a coding agent with a shell, the
  `maruhi schema` CLI + one guidance line in AGENTS.md delivers most of the
  value. Add it as a thin wrapper once demand is measured)
- **No file (`.env.schema`) as the source of truth** (keeping ROADMAP's
  default — the file-leaning option is not taken)
- Recommended positioning (formalized in H0): run alongside the H series
  (hosted) and **land before the hosted beta opens** — a change touching
  the wire / signature formats is overwhelmingly cheaper before external
  tenants exist

## 2. File vs signed store evaluation (summary)

| Consideration | File (Varlock-style) | Signed store |
|---|---|---|
| Coupling with code | ◎ Rides branches / PRs | △ Only the environment's current form |
| Visibility | ◎ Visible even to non-adopters | △ Assumes members + CLI |
| Implementation cost | ◎ Almost zero | △ Spec revision + migration |
| Sync with reality | ✕ Always drifts (.env.example rot) | ◎ Structurally can't diverge |
| Authenticity / ACL | ✕ Unsigned; repository write permission = a different authority system. The only unauthenticated surface agents read (an injection surface via descriptions) | ◎ Signed + audited |
| **Completeness** (found in §4) | ◎ Self-evident in 1 file | **Unprovable** by statements alone → flips to ◎ under manifest coverage |

The file's "branch coupling" is simultaneously a deploy-time source of lies
(the instant it merges to main, "the schema says required but the prod store
has no value"). The file speaks **the code's requirements**; the store
speaks **the environment's contract** — and what we want to verify is the
latter.

## 3. Three options that overturn the losing points (first search)

1. **Redefine as "the environment's contract" + existing mechanisms**:
   branch-ahead declarations are received by dev/preview environments (cheap
   with client-side numbering). Schema revision history is already carried
   by metaVersion's hash chain (more auditable than git history)
2. **CI-verified derived snapshot** (the main answer for visibility): allow
   placing `maruhi schema export`'s output (marked generated) in the
   repository, with CI's `maruhi schema verify-snapshot` making divergence
   from the signed store fail-loud — the same shape as the BW/BG sweeps'
   "hand-written copies forbidden, machine-checked copies allowed". Truth
   stays the store; take only the visibility to GitHub browsers /
   un-onboarded agents and PR diff review. Residual = the window until the
   next CI rejects a tampered snapshot (same class as any file in the
   repository. For an agent with maruhi, `maruhi schema` is guided as the
   truth)
3. ~~Cost compression = side-by-side (independent statement kind)~~
   **withdrawn on §4's discovery** (below)

## 4. Second search's discovery: manifest coverage (the leading candidate)

Generation rule = "look for composition blind spots with existing invariant
mechanisms".

- **The hidden 4th losing point "completeness"**: per-variable signed
  statements prove only individual authenticity, not "the server isn't
  hiding a required variable" (= the core of the fail-fast promise). This is
  exactly the problem the **environment manifest (CRYPTO_SPEC §4.3 —
  implemented in M1–M4)** closed (G6 absence / injection detection, epoch
  freshness, checkpoint binding, equivocation as evidence). If the schema
  enters manifest coverage, it becomes a guarantee **a file fundamentally
  cannot express**: "a signed, complete, freshness-carrying schema"
- **The side-by-side option's self-contradiction**: a manifest's entry is
  `LP(variable_id, status, meta_version, meta_sig_hash)` — **it binds the
  hash of the variable meta statement**. Therefore:
  - **The extension route** (add type / description / required to the §4.2
    variable meta statement) = **automatically inherits** manifest coverage
    (completeness, freshness, rollback detection). The manifest layer is
    unchanged
  - **The side-by-side route** (an independent schema statement) = outside
    coverage. To include it you'd have to change
    `env_manifest_signed_bytes`, bringing back the signature-format change
    we wanted to avoid — the "cheap" disappears (same shape as session-44
    §13's "a ruling rewriting its own premise" blind spot)
  - **The recommendation is the extension route**. Cost concentrates on
    designing §4.2's layout evolution (**correction — sixth search, finding
    F**: "automatic inheritance = free" applies **only to new verifiers**.
    The old verifiers' breakage form and an activation gate are the true
    price — §5 sixth)
- **Distribution composition**: once inside manifest coverage, it flows
  through every existing verified channel with no added implementation —
  metadata-only pull (§12-7 — humans / agents, doesn't soil the audit),
  the manifest bundled in the lease response (§14-2 — CI), `maruhi run`'s
  verification path (the natural implementation point of fail-fast
  verification)
- **Bonus (UX)**: the pushing client holds the plaintext, so a
  **client-side type-inference bootstrap** (`maruhi schema infer` — proposes
  type candidates locally and only statement-izes approved ones) rides while
  preserving zero-knowledge

## 5. Searches 3–8 (2026-08-30 — 6 additional rounds with changed generation rules)

### Third: lifecycle-observer walk (birth → consumption → evolution → violation)

- **Finding A (birth = dissolving the adoption killer): the bootstrap
  ingests `.env.example`**. Making someone hand-type types / descriptions
  for an existing project's 50 variables is adoption's biggest barrier, but
  the moment maruhi is introduced is **exactly the moment `.env` /
  `.env.example` still exist**. `maruhi init` / import proposes schema
  candidates from the file's names, comments, and value shapes (values are
  observed client-side only — zero-knowledge preserved), then approve →
  sign → delete the source file, as one ceremony. "`.env.example`'s last
  job is to become a signed schema" — the deletion story connects in one
  line with the derived snapshot (§3-2 = the successor)
- **Finding B (splitting the guarantee): presence is strict, type/format is
  lenient**. Because of E2EE, the server **fundamentally cannot verify**
  that a value matches its declared type (type/format verification is an
  advisory guarantee done client-side). Meanwhile **required fulfillment =
  ciphertext existence** can be judged by the server without seeing contents
  (a strict guarantee). The spec states this split explicitly and doesn't
  overclaim type verification as "verified" (the display-discipline
  culture). Byproduct: "required but no value set" can be displayed
  read-only on the Web dashboard (server-computable — synergy with hosted)

### Fourth: adversary walk (seeing the schema itself as attack surface)

- **Finding C (description is the first data maruhi intentionally hands to
  an LLM)**: signed ≠ benign (a compromised member / malicious insider can
  sign). Description text written on the premise that an agent reads it is
  a prompt-injection surface, so **neutralization (escapeText — ruling CK's
  precedent) + a length cap + "data, not instructions" framing** in
  `maruhi schema` / the future MCP's output become spec requirements
- **Finding D (secrets sneaking into schema fields)**: meta is plaintext and
  server-visible. The accident of writing a real value into description /
  enum opens a **user-shaped hole** in the zero-knowledge promise. A
  client-side entropy warning at `schema set` time (a mini-advance of
  ADR-0014 ⑤'s leak detection) + a documentation warning. enum is "close to
  a value", so treat its adoption itself carefully

### Fifth: dual inversion (verification at read → verification at write)

- **Finding E (schema-locked acceptance policy)**: under the extension route
  (§4) the schema is part of the variable statement, so a per-project opt-in
  **1-line server acceptance policy** — "**a new variable's statement must
  carry the schema fields**" — can cut off "creation of undeclared
  variables" (a typo silently creating a shadow variable — an accident no
  dotenv-family tool has ever closed) **at write time**. Meta is plaintext,
  so server enforcement doesn't contradict E2EE. **A strictly-better
  capability the store option has and Varlock — with no store —
  fundamentally cannot**
- Incidental: schema consideration in `maruhi env diff` (parity comparison
  on the required axis)

### Sixth: version-skew walk (new vs old "verifiers" — 2026-08-30 addendum)

- **Finding F (a premise correction to §4's adoption recommendation)**:
  `var_meta_signed_bytes` is a fixed-enumeration LP (the domain string
  `maruhi/v1/var-meta-sig` enumerates 10 fields — CRYPTO_SPEC §4.2), and
  **an old CLI can't verify** a statement written after the field addition
  (recompute under the v1 layout → signature mismatch). Unlike M1
  (**adding** a new statement kind — old CLIs just don't fetch it), this is
  **the first change that breaks old verifiers of an existing statement
  kind**. Consequences:
  1. Keeping suite pinned to the `"maruhi/v1"` Literal while changing only
     the signature layout would surface to old CLIs as "invalid signature" =
     the **worst mis-message**, indistinguishable from server tampering. The
     honest breakage form is bumping the domain string / suite version so it
     **breaks at the decode stage** — this intersects §12-2's deferred
     "don't preempt up to v2" suite-bump judgment (a ruling target of S0)
  2. **Schema writes need an explicit activation gate** (per project /
     environment) — preventing the shape where one upgraded member's write
     breaks every un-upgraded member's verification. SELF_HOSTING's update
     order (server → all members' CLIs → activation) is the **inter-peer
     skew version** of the M1 precedent
  3. No re-reversal to the side-by-side route (verified: carrying the
     schema only on the wire while keeping signed-target v1 leaves the
     schema uncovered by meta_sig_hash and tamperable — no free lunch
     exists). The recommendation stays the extension route, now understood
     as priced at "an activation gate + designing the breakage form"
- **Finding F′ (minor)**: bulk backfill (finding A) is a per-variable meta
  op × manifest re-issuance (CAS-serialized) = O(N) round-trips. Probably
  tolerable, but measure in S1 and judge whether composite acceptance is
  needed (don't preempt)

### Seventh: mechanizing the file's last remaining advantage (inverting the consumer)

- **Finding G**: the file's residual advantage "the code-side requirements
  declaration" (§2's △) can be closed without a third artifact — **because
  the code itself is the code-side truth**. `maruhi schema lint` statically
  scans source env references (`process.env.X` etc.) and matches them
  against the store-side schema in CI ("the code reads FOO but the schema
  has no declaration / and the reverse"). Dynamic access can't be caught —
  best-effort, same footing as the BG tripwire's "well-intentioned drift
  detection". The comparison table's "coupling with code △" moves to
  effectively ◎ with the machine check
- **Finding H (medium)**: don't hand-roll the derived snapshot (§3-2)'s
  format — make **JSON Schema (a subset)** the first candidate — editors,
  agents, and docs generation consume it free, consistent with the "don't
  invent formats" discipline

### Eighth: applying 3 more rules — checklist-level only (convergence)

- Caps / economics walk: strict-acceptance caps on schema fields (applying
  §12-8 / §12-10's existing disciplines) — no new invariant
- Truth-unification walk: consistency with the AGENTS.md guidance line / CLI
  help — trivial
- Removability walk: extension fields optional, schema-locked opt-in,
  snapshot deletable — fully reversible, no issue

### Convergence assessment (final)

Across 8 rounds (comparison → losing-point reversal → mechanism composition
→ lifecycle → adversary → dual → skew → consumer inversion →
caps/unification/removal), the gradient of findings fell monotonically:
"premise correction of an adopted recommendation (F) → 1 check surface (G) →
format selection (H) → checklist". New-invariant-level findings are judged
exhausted; from here on it's S0's 3-round comparison territory (once
concrete options stand).

## 6. Open questions for the S series' design PR

1. **The shape of §4.2's layout evolution**: adding fields to the signed
   target requires bumping the domain-separation string, a dual-path
   verifier side (migration window), and a test-vector revision. How
   existing statements are treated (migrate via natural re-issuance on next
   edit / bulk migration) is ruled here. **Landing before the beta opens**
   minimizes migration cost
2. **The semantics of required**: pin it to "the environment's contract"
   (this environment should hold this variable), or allow per-environment
   required. The judgment point and wording of `maruhi run` / `ci run`'s
   fail-fast verification
3. **The type system's scope**: keep to a small set like
   string/number/boolean/url/enum (don't invent a verification DSL).
   **Recommended: no default values** (half a step into "value" territory —
   muddies the zero-knowledge boundary)
4. **Adoption and shape of the derived snapshot (§3-2)**: export format, CI
   check placement, how to state "the truth is the store"
5. `maruhi schema`'s position on the agent-gate (it's a value-free read, so
   on the **allowed** side in agent environments — the spec writes that
   it's explicitly passed, not denied)
6. **The bootstrap (finding A)'s shape**: whether `.env` / `.env.example`
   ingestion is built into init or a standalone command. Value observation
   is client-side only (zero-knowledge preserved) + the ceremony of
   deleting the source file after ingestion
7. **Spec wording for the guarantee split (finding B)**: write presence
   (server-judgeable, strict) and type/format (client advisory) separately,
   and don't overclaim type verification as "verified". Whether `maruhi
   run`'s fail-fast makes presence strict and starts types at warnings
8. **The adversarial surface (findings C, D)**: description length cap,
   display neutralization (escapeText — ruling CK's precedent), whether an
   entropy warning is needed and where it goes
9. **The schema-locked acceptance policy (finding E)**: the per-project
   opt-in's shape, default value, and where the declaration lives (a chain
   op or environment meta)
10. **The old verifiers' breakage form and the activation gate (finding
    F)**: the shape of the domain-string / suite version bump (its relation
    to §12-2's "don't preempt up to v2" deferral), where the schema-write
    activation gate lives, and SELF_HOSTING's update order (server → all
    members' CLIs → activation). Measuring the backfill's O(N) round-trips
    (F′)
11. **Adoption and scope of `maruhi schema lint` (finding G)**: static
    scanning of source env references ↔ matching against the store
    (best-effort — same footing as BG's well-intentioned drift detection).
    Whether it's spec'd in S0 or later in the S series
12. **The snapshot format (finding H)**: JSON Schema subset as first
    candidate (don't invent formats). The mapping for expressing required's
    environment axis
