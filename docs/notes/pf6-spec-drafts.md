# PF6 spec revision drafts — layout v3 of the variable meta statement (expiring values, R9) (drafted 2026-10-02 — **awaiting owner approval**)

**Position**: the deliverable of PF6 R9 (ROADMAP "minimal upstream rotation" — `expires_at` equivalent in the schema field, "CRYPTO_SPEC §4.2 revision, test vectors first, human review"). The overall design, the ruling record (R9 — the interval form, the third layout rather than an in-place change of v2), the exhaustion loop, and the implementation live in docs/notes/pf6-design.md. This file is the **as-drafted revision text** for the two canonical documents (CRYPTO_SPEC / AUTH_SPEC). **Nothing in the canonical texts is edited by the PF6 PR**: per CLAUDE.md the order is "revise the spec → human approval → implement", and the owner was asleep when PF6 was designed and implemented under the "proceed" delegation. The test vectors (`metadata-signature.json` — appended, no existing byte changed) and the implementation (`packages/crypto`, the server, the CLI) are in the same PR so the owner reviews the vectors, the text, and the code together; **if the owner declines the revision, the R9 commit is dropped and R1–R3 stand on their own** (they touch no spec).

Each draft is shown as a "substitution" or an "addition". Parts of the existing text that do not change are not quoted. Version numbers: CRYPTO_SPEC 0.12 → **0.13-draft**, AUTH_SPEC 0.25 → **0.26-draft**. AUDIT_SPEC is untouched (no new event; the max age is a schema field, and `rotation list`'s expiring section is a client-side derivation from the verified statement and the history's server-declared push time).

---

## A. CRYPTO_SPEC revision proposals

### A-1. Addition at the end of §4.2 (after the "Layout v2" block)

> **Layout v3 of the variable meta statement — the `max_age_days` field (drafted 2026-10-02 PF6 R9 — "expiring values". Rulings in docs/notes/pf6-design.md §9)**
>
> Adds one schema field to the value-free schema: **the number of days after a value's push within which it should be replaced** (a rotation interval — the form every surveyed product uses: Infisical's reminder interval, AWS Secrets Manager's `AutomaticallyAfterDays`, Vault's `rotation_period`). A fixed expiry date was rejected (pf6-design.md ruling R9-A): it would have to be re-issued as a new signed statement on every rotation, while an interval is a stable declaration whose due date is derived from the live version's push time — a value pushed by `maruhi var rotate`, `maruhi push`, or a rollback resets the clock without touching the statement.
>
> ```
> var_meta_signed_bytes_v3 = LP("maruhi/v1/var-meta-sig-v3",
>                               project_id, environment_id, variable_id,
>                               name, status, var_type, required, description, max_age_days,
>                               meta_version, prev_meta_sig_hash_hex,
>                               author_user_id, chain_head_hash_hex, chain_head_seq)
> ```
>
> - **The encoding is §2.1 (same convention as v2)**. The domain-separation string is `maruhi/v1/var-meta-sig-v3` — the layout version stays statement-kind-local, the suite stays `maruhi/v1`. Mutual interpretation of v2 and v3 fails structurally as a signature mismatch (§1 principle 6 — vector `layout-confusion-v3-as-v2`)
> - **The field**: `max_age_days` ∈ `""` | a decimal integer `1`…`3650` **without leading zeros** (one value = one byte string — signature uniqueness; vectors `v3-max-age-leading-zero` / `v3-max-age-out-of-range`). `""` = no declaration. **Explicit and mandatory in v3** (the same fail-closed reasoning as v2's `required` — vector `v3-missing-max-age`); a v2 statement must not carry it (vector `v2-with-max-age`). The upper bound (ten years) is a consensus rule pinned by vectors: a longer interval is "no interval"
> - **Semantics**: advisory, like `var_type` (§14.3-7). The signature proves the author declared the interval, never that a value was replaced in time. The due date is derived by the client as the live version's **server-declared** push time (AUTH_SPEC §12-7's history) plus the interval; a declared variable with no value has no age. Nothing on the server depends on it (no server-side detection, no event — AUDIT_SPEC unchanged)
> - **Layout monotonicity, generalized**: a successor statement's layout is **never lower than its predecessor's** (`layout-regression` — v1 after v2 as before, and now v2 after v3; vector `layout-regression-v3-to-v2`). Raising the layout is the legitimate direction: a schema reissue moves a v2 variable to v3 (vector `var-v3-upgrade-from-v2`), and a continuation of a v2 variable (activation, deletion) may stay v2 — the schema fields byte-exact (§12-5's conventions)
> - **Deletion keeps `max_age_days`** verbatim like the other schema fields (vector `var-v3-delete-keeps-max-age`). `declared` is allowed in v3 as in v2 (vector `var-v3-create-no-max-age`)
> - **The write enablement gate (AUTH_SPEC §12-11)** treats v3 like v2: a new adoption (a v1 → v3 reissue, a metaVersion-1 v3 creation) needs the policy enabled; a continuation of an already-v2/v3 variable passes regardless. `schema-locked` requires layout ≥ 2 and a non-empty `var_type` at creation (unchanged in substance)
> - **The verifier's layout selection** is unchanged: the supported range is now {1, 2, 3}; an excess (v4+) is the typed "unsupported layout (client update required)" error before signature verification (ruling CR). Existing v1 / v2 statements and vectors do not change by one byte (extend by appending — §11)
> - **The author's required role is the same as v2** (member or above). The environment meta statement stays v1

### A-2. Addition to §11 (test vectors — one item appended to the revision list)

> - Vectors added in 0.13-draft (PF6 R9) (**committed in the implementation PR; the spec text awaits owner approval — docs/notes/pf6-spec-drafts.md**): the **additive extension** of `metadata-signature.json` (§4.2 layout v3). Positives = `var-v3-create-expiring` (max_age_days = 90) / `var-v3-create-no-max-age` (declared, `""`) / `var-v3-upgrade-from-v2` (a v2 → v3 reissue) / `var-v3-delete-keeps-max-age`. Negatives = `layout-confusion-v3-as-v2` (signature family), `tampered-max-age-days` (signature family), `layout-regression-v3-to-v2` (rule family — the generalized monotonicity), `v2-with-max-age` / `v3-missing-max-age` / `v3-max-age-leading-zero` / `v3-max-age-out-of-range` (structural family — InvalidInput). `var_v3_signed_fields_order` and the `layout_v3` note are added to the file; no existing vector changes by one byte

### A-3. Substitution in the Status line

> … **0.13-draft (2026-10-02 — PF6 R9: §4.2 layout v3 `max_age_days`; awaiting owner approval)** …

---

## B. AUTH_SPEC revision proposals

### B-1. Substitution in §12-2 (the `VariableMetaStatement` wire form — the layout v2 comment block)

> ```
>   // layout v2 / v3 (CRYPTO_SPEC §4.2 — 2026-08-30 / 2026-10-02. On a v1 statement all fields below are absent):
>   layoutVersion,               // 2 or 3 (omitted = 1. The verifier checks the supported range before signature verification — an excess is a typed "unsupported layout" error)
>   varType,                     // "" | "string" | "number" | "boolean" | "url" ("" = unspecified)
>   required,                    // boolean (must be present explicitly in v2 / v3)
>   description,                 // a free string (cap / charset acceptance checks are §12-8. Display is always neutralized by the client — same section)
>   maxAgeDays,                  // layout v3 only: an integer 1..3650, or null = no declaration. Present iff layoutVersion is 3 (§12-5 — the layout ↔ field coupling is an acceptance check, 422 payload-mismatch; the two layouts share one wire shape)
> ```

### B-2. Addition to §12-2's "wire rules of layout v2" bullet

> A v3 statement carries `layoutVersion` = 3, the v2 schema fields, and `maxAgeDays` (null = none); the LP-signed target is the field sequence of the v3 domain string (CRYPTO_SPEC §4.2 layout v3). On distribution, a v3 stored row expands `maxAgeDays` alongside the v2 fields; a v2 row never carries it (no new field is added to a v1 or v2 distribution). The client refuses a distribution whose `maxAgeDays` presence disagrees with its `layoutVersion` as an inconsistent response (the all-or-nothing rule extended)

### B-3. Addition to §12-5's "Acceptance of layout v2 / declared / activation" block

> - **Layout v3 (2026-10-02 PF6 R9 — CRYPTO_SPEC §4.2 layout v3)**: accepted under the v2 rules with three additions. (1) **The layout ↔ field coupling**: a statement declaring layoutVersion 3 without `maxAgeDays`, or layoutVersion 2 with it, is refused with 422 `payload-mismatch` (field `maxAgeDays`) **before** signature verification (the signing API cannot produce either shape; the check keeps the honest wording instead of a crypto-layer InvalidInput). (2) **Layout monotonicity, generalized**: a successor whose layout is lower than the stored predecessor's (v2 after v3, as v1 after v2) is 422 `layout-regression`; a v2 → v3 reissue is accepted like any schema reissue. (3) **The delete statement's just-before match** covers `maxAgeDays` (a deletion altering it is 422 `payload-mismatch`, field `maxAgeDays`). The enablement gate (§12-11) and `schema-locked` treat v3 as v2 (a new adoption = predecessor layout 1 → 2 or 3; locked = layout ≥ 2 and a non-empty varType at creation). Storage: the project DO's `variable_meta_statements` gains `max_age_days TEXT` (migration step 2 — NULL on v1 / v2 rows; the signed string on v3 rows)

### B-4. Addition to §12-8's limits table

> | Schema max age (variable — layout v3) | 1 to 3650 days (a consensus rule pinned by CRYPTO_SPEC §4.2's vectors; the Schema rejects other values with 400) |

### B-5. Substitution in the Status line

> … **0.26-draft (2026-10-02 — PF6 R9: §12-2 / §12-5 / §12-8 layout v3; awaiting owner approval)** …

---

## C. What is deliberately not revised

- **AUDIT_SPEC**: no new event. The expiring section of `maruhi rotation list` derives from the verified statement (the interval) and `var.version_pushed`'s server-declared time already distributed by the history endpoint (§12-7). A server-side `rotation.due` event was considered and rejected (pf6-design.md ruling R9-C): the server would be asserting a conclusion the client can draw from verified material plus one server-declared timestamp, and an advisory reminder does not justify an append-only row
- **The value write signature (§4.1)**: a per-version `expires_at` (the fact "this credential expires on X", known when a connector issues a token with a TTL) was considered as a complement and deferred (pf6-design.md §12 residuals): it changes every value vector for a field only connector-issued credentials can fill honestly
