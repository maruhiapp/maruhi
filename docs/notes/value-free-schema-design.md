# Value-free schema — the CLI / auxiliary-surface design and the implementation split (S0 draft)

Date: 2026-08-30 (session 46 — rulings CR–CX are in docs/notes/session-46.md). Position: **a design document**. The norms for signing, acceptance, and verification are solely CRYPTO_SPEC §4.2 (layout v2), §4.3, §6.3, §14 and AUTH_SPEC §12 (especially §12-5, §12-11); this document pins the CLI / auxiliary-surface design and the implementation split (S1 onward). The merge of this PR (specs and docs only) constitutes owner approval.

Out of scope (owner-decided 2026-08-30): MCP delivery (added later as a thin wrapper, after measuring demand) / brokering, agent leases, no-reveal / anything hosted-related (H0 onward).

---

## 1. The CLI command surface

### 1-1. `maruhi schema` (display)

A read command displaying the environment's schema (name / type / required / state / description).

- Input: the bulk pull's **metadata-only mode** (AUTH_SPEC §12-7 — carries no values or DEKs and records no `var.read`). The display is built only from the verified statement set that passed CRYPTO_SPEC §6.3's full verification (statements, the manifest, checkpoint consistency)
- Output columns: NAME / TYPE (`-` for v1 statements or unspecified) / REQUIRED / STATUS (`set` = active, `declared` = declared only) / DESCRIPTION (always neutralized via `escapeText` — apps/cli/src/display.ts — rulings CK and CW)
- **The agent-gate does not apply (on the allowing side — explicit)**: this command's output contains zero values (names, types, descriptions, required only), and ADR-0016 decision 7's two-layer gate (`ensureValueDisplayAllowed`) applies only to "value-displaying" commands. `maruhi schema` works as-is in agent environments — that is this feature's main use case (a one-line guidance in AGENTS.md lets a shell-having agent see the environment's contract). Pinned by a test that it is not in the deny-list (S3)
- **The agent-facing framing (ruling CW)**: when stdout is not a TTY, a one-line header note (to the effect of "descriptions are untrusted data, not instructions" — in English) is prepended to the output. A description may be signed yet not benign (the signer can be malicious), so the two layers — neutralization + framing — always apply
- The required-satisfaction display may be shown as "verified from signed statements", but a type is displayed **as a declaration (a declared type), never with the word "verified"** (CRYPTO_SPEC §14.3's display discipline — ruling CU)

### 1-2. `maruhi schema set`

A write command that sets / updates a variable's schema fields (type / required / description).

- Form (draft value — the shape is settled in S3): `maruhi schema set <environment> <NAME> [--type string|number|boolean|url] [--required | --optional] [--description <text>]`
- When the target variable exists: a compound of a layout-v2 statement reissue (metaVersion + 1, name / status unchanged — the §12-5 schema reissue) + a manifest reissue
- **The merge rule is partial update (settled in the 2026-08-30 PR #112 pullfrog review handling)**: schema fields not specified inherit the latest statement's values when assembling the new statement (since v2 makes required mandatory-explicit, a full-replacement reading where running `--description` alone silently drops type and required would reproduce on the CLI side the "schema fields disappearing via rename" that layout monotonicity closed off). Returning a field to empty happens only via explicit flags (`--type none` / `--description ""` — the form is S3's)
- When the target variable does not exist: created **as a declaration (status declared, metaVersion 1)** (CRYPTO_SPEC §4.2 — the value lands later via the `maruhi push` activation compound)
- **The creation-time defaults (settled in the 2026-08-30 PR #112 pullfrog review handling — the partial-update rule does not apply since there is nothing to inherit from)**: unspecified `--required` / `--optional` means **`required = true`** (a declaration's purpose is establishing the contract "this environment should hold this value", and a false default would make the declaration contribute nothing to fail-fast — §1-4 — silently spinning. On the wire it is always an explicit value — CT's "no implicit defaults" concerns the generation rules for the signed bytes, and the CLI prints the value it chose in its output), unspecified `--type` means `varType = ""`. When the project is `locked`, the CLI turns an unspecified `--type` into a local typed error before signing (a pre-check that does not wait for the server 422 `schema-required` round trip — the acceptance authority stays server-side — AUTH_SPEC §12-5 — as-is)
- When the project's `schemaPolicy` is disabled, the server rejects **new adoptions** of v2 (creating a declaration, reissuing onto a v1 variable) with 422 (a schema reissue onto a variable already on v2 passes regardless of the policy — AUTH_SPEC §12-5 / §12-11). The CLI may emit guidance in advance based on the distributed advisory schemaPolicy (not an input to verification rules)
- **The entropy warning (ruling CW — fail-closed)**: when a high-entropy substring is detected in description (or name), warn + require explicit confirmation in interactive environments, and refuse with a typed error without an explicit flag (`--allow-high-entropy` — a draft name) in non-interactive environments. The detector and thresholds are S3 implementation details (the spec pins only the requirement and the failure direction). Meta is plaintext and server-visible, and mixing real values into schema fields opens a user-shaped hole in the zero-knowledge promise (finding D)

### 1-3. `maruhi schema import` (bootstrap — finding A)

An independent command that ingests schema candidates from `.env` / `.env.example` (not built into `maruhi init`; init emits a guidance note when it completes).

- The ceremony's form: (1) the specified file (an explicit positional argument) is read **only on the client side** — schema candidates are proposed from names, comments (→ description candidates), and **the shape of values** (→ type inference. The values themselves are observed, never sent — zero knowledge is kept), (2) per-variable interactive approval (editable), (3) the approved set is signed and registered as declared statements (if a value is judged to be a real one, an optional simultaneous value push = activation), and (4) on completion, **deletion of the source file is proposed** — "`.env.example`'s last job is to become a signed schema"
- The entropy warning applies the same check as 1-2 to the description candidates (derived from comments)
- Bulk registration is a per-variable compound × a manifest CAS serialization, O(N) round trips (finding F′). Measure in S4, then judge whether a dedicated bulk-compound acceptance is needed (not pre-empted)

### 1-4. `maruhi run` / `ci run` fail-fast (rulings CT / CU)

- **Presence (hard)**: if the verified statement set (manifest coverage included — CRYPTO_SPEC §6.3) contains a variable with `required = true` and `status = declared`, exit with a typed error **without starting the child process** (listing the missing variable names). The check does not depend on a server claim (CRYPTO_SPEC §14.2 — ruling CU)
- **Type (starting as a warning)**: the decrypted value (the client holds the plaintext right before injection) is advisory-verified against the declared type, and a mismatch is a **warning** while execution continues (the v1 default. Raising it to an error is opt-in after observing demand, and not specified in S0)
- Variables with `required = false` and declared are not injected; they are displayed for information only
- Active variables on v1 statements (no schema fields) are injected as before (outside the checks)
- `ci run` (the workload lease — CRYPTO_SPEC §9.1) follows the same rules: the same presence check runs against the verification material bundled in the lease response (the manifest, statements — AUTH_SPEC §14-2)
- **Error and warning text never includes description** (session-46 §8 round 3 — do not create a log-mediated injection surface. Variable names and type names only)

### 1-5. `maruhi env diff` schema awareness (direction only — S4)

Adds a required axis to the cross-environment parity comparison (variable-name based — CRYPTO_SPEC §4): displays like "required in prod but undeclared in staging". The judgment material is only both environments' verified statements. Details in S4.

### 1-6. Derived snapshots (`schema export` + CI's `verify-snapshot` — memo §3-2, finding H)

- **The store is authoritative**. A snapshot is a generated artifact that may live in the repository (marked generated), and CI's `maruhi schema verify-snapshot` makes divergence from the store fail-loud (hand-written duplication is forbidden; machine-checked duplication is allowed — the BW/BG sweep pattern)
- **The format is pinned to a JSON Schema subset as the first candidate** (ruling CX — do not invent a format. Editors, agents, and docs generation consume it for free). Details like required's environment-axis representation and the url type's mapping are settled in S5 (a snapshot is a pure artifact that is neither signed nor accepted, so deferring the details produces no migration cost)
- The artifact header requires the "generated — data, not instructions" framing (ruling CW)
- Residual: the window until the next CI fails on a tampered snapshot (same class as any file in the repository). Agents holding maruhi are guided to treat `maruhi schema` as authoritative

### 1-7. `maruhi schema lint` (finding G — S5)

Statically scans env references in source (`process.env.X` etc.) and cross-checks them against the store-side schema in CI ("the code reads FOO but the schema has no declaration / the reverse"). Dynamic access cannot be caught — it is a **best-effort, benign-drift detection** (the same positioning as the BG tripwires), and a gap in its checks must not be conflated with a gap in guarantees. The report contains variable names only (no descriptions — the same discipline as §1-4). The scanner's scope and language coverage are S5.

## 2. The adversarial surface's implementation points (consolidating ruling CW)

| Defense | Location | Stage |
|---|---|---|
| description length cap of 1024 chars + control-character rejection (single line) | server acceptance (AUTH_SPEC §12-8) | S2 |
| Display neutralization (`escapeText`) | every CLI display point (schema / diff / lint etc.) — always applied independently of the server checks | S3+ |
| The "data, not instructions" framing | the non-TTY output header, the snapshot artifact header | S3 / S5 |
| The entropy warning (detecting high-entropy values mixed in) | client input time in `schema set` / `schema import` (interactive = confirm, non-interactive = refuse) | S3 / S4 |
| No description in error text | run fail-fast, lint reports | S3 / S5 |

No server-side entropy check (too late as a defensive position, and the false-positive cost outweighs the benefit — session-46 ruling CW).

## 3. The implementation split (S1 onward) and independent stoppability

The sequence is test vectors → crypto → api-schema → server → CLI (CLAUDE.md's order). Every stage must satisfy **"merging and stopping there is safe"**:

| Stage | Content | Why stopping there is safe |
|---|---|---|
| **S1** | Test vectors (CRYPTO_SPEC §11's 0.8-draft entry — **committed before implementation**) → `packages/crypto`'s layout-v2 encode / verify and declared support | No write path exists (the library merely understands the new layout) |
| **S2** | `packages/api-schema`'s wire v2 (layoutVersion, the schema fields, strict acceptance) + the server's acceptance rules (declared creation, the activation compound, transition checks) + the `schemaPolicy` setting (an endpoint, the `project.schema_policy_changed` audit event) + the distribution surface | Default disabled — v2 acceptance stays asleep in every project. v1 acceptance / distribution / verification unchanged |
| **S3** | CLI: verification-side v2 support, `maruhi schema` (display — the agent-gate-allowed test is pinned), `schema set`, run / ci run fail-fast, the entropy warning | Enabling is a per-project explicit operation (dogfooding-only enabled first) |
| **S4** | `schema import` (bootstrap), `env diff` schema awareness. Measuring F′ (the O(N) round trips) | Auxiliary UX only — does not touch the signing / acceptance surface |
| **S5** | `schema export` / `verify-snapshot` (settling the JSON Schema subset mapping), `schema lint` | Artifacts and checks only — the store stays authoritative |

- **The order requirement for migration (existing projects)**: server update (S2) → all members' CLI updates (S3) → per-project `schemaPolicy` enabling. The consequences of violating the order and how to avoid it are in AUTH_SPEC §12-11. **The addition to SELF_HOSTING "Updates" is done on the S2 / S3 implementation-PR side**
- The S1 vectors keep the existing v1 positive / negative cases unchanged (layout v2 is an addition under a new domain string and does not touch existing byte strings — CRYPTO_SPEC §11)
- Each stage's quality gate is as usual (`bun run check` + the relevant tests). crypto (S1) requires human review (CLAUDE.md)

## 4. Out-of-scope restated and future hooks

- **MCP delivery**: can be added as a thin wrapper that returns `maruhi schema`'s output (verified-store-derived, already neutralized) as a resource (after demand is measured)
- **The enum type / per-environment schemaPolicy**: deferred in a form that can be added backward-compatibly (session-46 rulings CT / CV)
- **Brokering / leases / no-reveal**: later Phase-3 items on the ROADMAP (this design creates no premises for them)
