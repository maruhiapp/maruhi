# PF6 design record — minimal upstream rotation (2026-10-02 design and implementation session)

**Position**: the ROADMAP H series "no-revision group", last item =
**PF6: minimal upstream rotation (R1 runbooks + R2 `maruhi var rotate <var>`
+ R3 a checklist right after `member remove` + R9 expiring values)** (order
VH → PF5 → PF4 → PF6 — 2026-09-14 owner ruling). The option enumeration is
docs/notes/integration-options.md §4 (R1–R9; recommendation R1 + R2 + R3 +
R9, R7 as the docs' position, R4 when demand appears, R5 / R6 never). This
record carries the overall picture, the competitor survey the rulings were
checked against, the rulings (R1–R9 below are *rulings*, numbered after the
ROADMAP items they realize), the exhaustion loops, the residuals, the
implementation, and the one item flagged for the owner (§13 — the R9 spec
revision awaits approval).

**Approval (2026-10-02)**: the owner delegated every open point ("for each
point needing a ruling, loop until no strictly-better or structurally-better
option remains, lay the options out, and pick the one you recommend"),
asked for parity with or superiority over competitors, ruled backward
compatibility out of scope (zero users), and went to sleep ("proceed with
the implementation"). The rulings below are the designer's picks under that
delegation. **One item is flagged for the owner's explicit approval** (§13:
R9 is a CRYPTO_SPEC §4.2 revision — the text is drafted in
docs/notes/pf6-spec-drafts.md, the vectors and the implementation are in
the PR, and the canonical texts are untouched).

**Premises (not relitigated)**: integration-options.md §4's problem
definition (rotation = ① trigger → ② create at the issuer → ③ write to
maruhi signed → ④ reach consumers → ⑤ disable the old credential; ① is
done, ③ hits "only humans sign"); the ROADMAP's constraints (**no
server-driven rotation, no long-term signing key in CI**; the connector
frame + three issuer families; dual-credential grace → `--finalize`; the
admin credential fetched into memory as a maruhi variable); AUDIT_SPEC §4.1
(the flag set, its resolution lineage — VH ruling V2); the `maruhi sync` /
`maruhi proxy run` conventions (a non-secret repository config, strict
parsing, output scrubbing, fixed vendor hosts); pf4-design.md ruling P8 (a
connector is a client of a third party's protocol — CRYPTO_SPEC §12's
scope note, class (b)); ADR-0014 decision 3 ("human error is guarded by
mechanisms, not education" — the reason R3 exists); ADR-0016 decision 7
(the agent gate's archetypes).

---

## 1. Overall picture

### 1-1. Problem

Encryption cannot un-read a value. After `member remove` (or a device
revocation, a scope narrowing, a server-key revocation) the environment's
key is rotated, but every value the person could already read is still
valid at its issuer. The product feature "rotation-needed detection" lists
those values; nothing closes the loop. Competitors close it with
**server-driven** rotation (Infisical, Doppler, Phase: the server holds the
issuer's admin credential and a scheduler) — the shape the ROADMAP rules
out, because it hands the server a signing key and the issuer's keys.
maruhi's answer keeps the E2EE property: a member's CLI creates the new
credential, signs the push, and the server sees ciphertext and a timestamp.

### 1-2. Mechanism sketch

```
maruhi member remove u_bob
  │ … remove_member on the chain, the §7 sweep …
  ▼
Rotation checklist: 3 variables the party that lost access could read (…):
  [read]     prod DATABASE_URL:      `maruhi var rotate DATABASE_URL --env prod` (postgres connector in maruhi.rotate.json)
  [readable] prod STRIPE_SECRET_KEY: rotate at the issuer, then `maruhi push STRIPE_SECRET_KEY --env prod` (runbooks: …/docs/rotation)
  [readable] prod OLD_WEBHOOK:       deleted — rotate at the issuer, then `maruhi rotation dismiss v-2a9c --env prod`

maruhi var rotate DATABASE_URL --env prod           (maruhi.rotate.json: connector postgres, roles [app_a, app_b], inputs.adminUrl → ops/ADMIN_DATABASE_URL)
  │ verified pull of prod → decrypt DATABASE_URL (postgres://app_a:…) ; verified pull of ops → decrypt ADMIN_DATABASE_URL
  │ connector: ALTER ROLE "app_b" WITH PASSWORD '<32 random alnum>' on the admin connection ; SELECT 1 with the new URL
  │ pushVariable(new URL as app_b) → version 8  (an ordinary signed push: a fresh value after the §7 rotation resolves the flag — AUDIT_SPEC §4.1-5)
  ▼ "role app_a keeps its previous password until you finalize" — deploy — then:
maruhi var rotate DATABASE_URL --env prod --finalize
  │ version 7 read back as a verified ancestor of version 8 (the rollback's evidence rule) → the previous role app_a
  │ confirm (y/N or --yes) → ALTER ROLE "app_a" WITH PASSWORD '<random nobody holds>'
  ▼
maruhi schema set STRIPE_SECRET_KEY --max-age 90   (layout v3 — R9) → `maruhi rotation list` shows "Expiring values" when due
```

Nothing on the server changes for R1–R3: no endpoint, no acceptance rule,
no audit event beyond the push's own `var.version_pushed` and the pull's
`var.read`. R9 is the one spec item (§9 / §13).

### 1-3. Competitor survey (checked before ruling — facts from vendor docs and source, 2026-10-02)

| Product | Rotation shape | What maruhi takes / rejects |
|---|---|---|
| Infisical Secret Rotation v2 | Server-driven; **dual-phase** (Active → Inactive → Revoked: the previous credential lives one full interval); DB = two pre-created users alternated, AWS IAM = delete the oldest key then create; "App Connections" hold the issuer credential; manual rotate; `secretReminderRepeatDays` (≤365, relative) as a reminder | Takes: two-user alternation, "reclaim the stale key" for IAM, the reminder-as-interval form. Rejects: the server holding the issuer credential and a scheduler |
| Doppler | Server-driven; two secret instances switched halfway through the interval (half-interval grace); a **managing user** per rotated secret; AWS through a customer-deployed Lambda; "Rotate now"; per-secret reminders with recipients | Takes: the managing-user notion (= the admin input), manual rotate as the primary verb. Rejects: the half-interval timer (no timer exists here) |
| Pulumi ESC rotated secrets | Rotate on demand (`pulumi env rotate`) or cron; **two-secret strategy** with `state.current / previous`; `aws-iam` seeds state when the user already has two keys | Takes: the current/previous model — but **derived from the version history instead of a state file** (R5) |
| HashiCorp Vault | DB static roles rotate in place (no dual user; `rotation_period`, manual `rotate-role`); AWS static roles keep up to two keys and **rotate the oldest** | Takes: "the next rotation reclaims the oldest" for IAM; in-place as an explicit lower-grade option (R3) |
| AWS Secrets Manager | Lambda 4-step with `AWSCURRENT / AWSPENDING / AWSPREVIOUS`; single-user vs **alternating users** (`user_clone`); `AutomaticallyAfterDays` 1–1000 | Takes: alternating users as the Postgres shape; `testSecret` as the post-change connection probe |
| Phase | Mint → Expose → Expire (a revocation delay) → Revoke, server-driven | Takes: the explicit "revocation delay" idea in its human-driven form (`--finalize` is the delay) |
| Akeyless / Keeper / 1Password | Akeyless "grace rotation" keeps two AWS keys and rotates only the older; Keeper runs post-rotation scripts; 1Password has no rotation but an item expiry alert | Takes: the "older key only" rule. Deferred: post-rotation hooks (sync-on-push covers the common case) |
| MySQL 8 | `ALTER USER … RETAIN CURRENT PASSWORD` / `DISCARD OLD PASSWORD` — a true single-account dual password | Takes: the in-place MySQL shape **with** a grace period (R3) |
| Cloudflare API tokens | `PUT …/tokens/{id}/value` rolls in place and invalidates the old value at once; `POST …/tokens` creates a second token; account-owned tokens survive member removal | Takes: create-new-then-delete-old (the only overlap-capable shape); account-owned tokens as an option. Rejects: rolling |

The common denominator every product converged on — **two credentials
valid at once, the old one retired later** — is R2's dual-credential grace
period. Where maruhi differs structurally: no server, no scheduler, no
state file, and the admin credential never leaves the member's machine.

## 2. Ruling R1 — where the rotation configuration lives

| # | Shape | Verdict |
|---|---|---|
| 1-A | **A repository config `maruhi.rotate.json`** (strict parser, `version`, `project`, `variables: { NAME: rule }`, inputs as `{ environment?, name }` pointers to maruhi variables — the `maruhi.sync.json` / `maruhi.proxy.json` discipline) | **Adopted** |
| 1-B | Command-line flags only (`--connector postgres --admin ops/ADMIN_URL`) | Rejected: `--finalize` days later must repeat the same parameters; the checklist (R3) could not name a command; nothing reviewable in a PR |
| 1-C | A signed schema field naming the connector and inputs (a §4.2 revision) | Rejected for v1: the only thing a signature would protect is *which variable the admin credential is read from*, and the member can decrypt that variable anyway; the issuer **host** is fixed by the connector, not the config, so a tampered config cannot redirect a credential. Recorded as the follow-up that would make R3's "has an upstream" verifiable without a checkout |
| 1-D | A maruhi variable holding the config (the `sync-receipt:<target>` precedent) | Rejected: a receipt is *state* the CLI writes; a config is reviewed and versioned with the code. Also, config-in-a-value would make `member remove` depend on decrypting an environment to print a checklist |
| 1-E | Inferring the connector from `var_type` (`url` → database) | Rejected: `url` does not say which database, nor where the admin credential is; a closed `var_type` set is a ruling (session-46 CT) not to extend for this |

**Why 1-A is strictly better**: the same place the team already keeps the
sync and proxy configs, the same project check, the same "no secrets in the
file" line (`inputs` are names), and the checklist can print the exact
command from it. Inputs in **another environment** (`{ "environment":
"ops", "name": … }`) are the structural answer to "a member who may rotate
`prod` should not read the issuer's admin credential": keep it in an
environment only owners are scoped into (ES).

## 3. Ruling R2 — the connector set and each one's grace mechanism

| Connector | Rotate | Finalize | Grace |
|---|---|---|---|
| `aws-iam-access-key` | `CreateAccessKey` (IAM allows two per user — a leftover **inactive** key is deleted first; two **active** keys refuse: never delete a live key) | `UpdateAccessKey … Inactive` on the previous key (reversible at the issuer; the next rotation deletes an inactive key) | yes |
| `cloudflare-api-token` | `/verify` with the current token → its id → `GET` its definition → `POST` a second token with the same name, policies, condition, validity | `DELETE` the previous token | yes |
| `postgres` (two roles) | `ALTER ROLE <other> WITH PASSWORD` on the admin connection; the URL moves to the other role | `ALTER ROLE <previous> WITH PASSWORD <random nobody holds>` | yes |
| `postgres` (one role) | `ALTER ROLE <self> WITH PASSWORD` | nothing (the old password died at the change) | **no** — the command asks for confirmation (`--yes` in scripts) |
| `mysql` (one account) | `ALTER USER … IDENTIFIED BY … RETAIN CURRENT PASSWORD` | `ALTER USER … DISCARD OLD PASSWORD` | yes (MySQL 8.0.14+) |
| `mysql` (two accounts) | as Postgres | as Postgres | yes |

Options weighed per issuer:

- **AWS**: (a) delete the oldest key when two exist (Infisical / Vault) /
  (b) **reclaim only an inactive one, refuse two active** / (c) `--replace`
  flag. (b) adopted: deleting an active key is an outage nobody confirmed;
  the refusal names `--finalize`. Self-rotation (no admin inputs) is
  allowed: an IAM user with `iam:*AccessKey*` on itself rotates with its
  own key, and `GetAccessKeyLastUsed` names the user so the config needs no
  `user` (optional override). STS session tokens ride as `sessionToken`.
  SigV4 is implemented over WebCrypto (`sigv4.ts`, pinned to the AWS
  documentation's worked example: canonical hash, signing key, signature)
  — no SDK, toward `iam.amazonaws.com` only.
- **Cloudflare**: (a) roll in place (`PUT …/value`) / (b) **create-new +
  delete-old** / (c) both behind a flag. (b): rolling has no grace. Token
  names need not be unique at Cloudflare; the replacement keeps the name.
  Account-owned tokens (`accountId`) are supported because they survive the
  very event (member removal) that triggers the rotation.
- **Postgres**: (a) in place only / (b) two roles only / (c) **both, the
  two-role form documented as the one with a grace period**. (c): a
  development database should not need two roles; production should.
- **MySQL**: the dual password is the one in-place shape with a grace
  period, so it is the default; two accounts stay available for symmetry.
- **The database client**: (a) a wire-protocol client written here (as the
  proxy's HTTP was) / (b) `pg` + `mysql2` dependencies / (c) **Bun's
  built-in SQL client behind a `SqlRunner` service** (production = `Bun.SQL`
  in live.ts, tests = a recorder). (c): zero dependencies, both drivers,
  and the service seam keeps vitest on Node. SCRAM / TLS are the driver's
  (`sslmode=require` is documented).
- **Passwords**: 32 alphanumerics from `crypto.getRandomValues` with
  rejection sampling (URL-safe, quote-safe). Identifiers from the config
  and the URL are restricted to `[A-Za-z0-9_.@-]` and quoted; a name outside
  the set is refused rather than escaped.
- **The connection probe** (AWS SM's `testSecret`): `SELECT 1` with the new
  URL after the change; a failure is a **warning**, not a refusal (the
  password is already set at the server — hiding that would be worse).

**Not built** (the ROADMAP's "connectors are a treadmill"): GitHub tokens
(a GitHub App is the answer — PF4), Stripe (its dashboard has a native
roll-with-delay), OAuth client secrets, SendGrid / Twilio, SSH keys,
certificates — all runbooks on the docs page.

## 4. Ruling R3 — the admin credential and self-rotation

| # | Shape | Verdict |
|---|---|---|
| 3-A | **Inputs are maruhi variables (this or another environment the member can decrypt); with no inputs the credential rotates itself** | **Adopted** |
| 3-B | Inputs required always | Rejected: an IAM user managing its own keys, a Cloudflare token with `API Tokens Write`, a role changing its own password are the simplest real setups; forcing a second credential doubles what must be rotated |
| 3-C | A "managing user" stored on the server (Doppler) | Rejected: the server never holds an issuer credential |
| 3-D | Prompting for the admin credential interactively | Rejected: it would be typed into a terminal (history, shoulder) and would make the checklist's one-command promise false |

The trade-off of self-rotation is stated in the docs: whoever holds the
credential can also rotate it. The scope check for another environment is
the client's own (`requireEnvironmentInScope` — "do not wait for the
server's 403"), and the inputs are unwrapped once, in memory, to be sent
to the issuer's fixed host.

## 5. Ruling R4 — what the rotation pushes and how it reports

- The new value is pushed through `pushVariable` as an **ordinary new
  version** (no `sameValueAs`): a fresh plaintext after the §7 rotation
  resolves the rotation flag by the lineage rule (AUDIT_SPEC §4.1-5); a
  rotation performed before the mandated rotation does not, and the docs
  say so. No new audit event, no rotation marker (a marker would let a
  push *claim* a rotation the server cannot verify).
- An AWS rule pushes **two** variables (the key id companion, then the
  secret). A reader between the two pushes gets a mismatched pair for one
  round trip; the alternative — one JSON variable — breaks every consumer
  that expects two environment variables. A push failure after the issuer
  accepted the rotation reports exactly what exists at the issuer (the key
  id) and that only this process holds the secret.
- The report carries issuer-side identifiers (key ids, roles, token ids),
  version numbers, and the finalize command; never a value, a password, or
  a URL with credentials (driver messages are scrubbed of URLs).
- `maruhi.sync.json`'s `onPush` targets are synced after the push (step ④
  "reach consumers" — the same path as `maruhi push`).

## 6. Ruling R5 — `--finalize` and where the rotation state lives

| # | Shape | Verdict |
|---|---|---|
| 5-A | **No state: `--finalize` reads the previous version from the version history as a verified ancestor of the latest (the rollback's evidence rule — `verifiedAncestorValues`), and the connector derives "the previous credential" from it** (the AWS key id companion's previous version, the Cloudflare token's `/verify` id, the Postgres role in the previous URL; MySQL needs only the account) | **Adopted** |
| 5-B | `state.current / previous` in the config (Pulumi ESC) | Rejected: credential ids in a reviewed file, churn on every rotation, and a second source of truth beside the history |
| 5-C | A rotation ledger in a maruhi variable | Rejected: a value written by the CLI that the member must not edit — the receipt precedent exists, but the history already *is* that ledger |
| 5-D | Finalize inside the same command after a timer | Rejected: no daemon; the deploy is the member's, not a clock's |

`--previous <version>` names another version when someone pushed in
between. Finalizing confirms (y/N or `--yes`); an in-place rotation (no
grace) confirms the same way before the issuer is touched. Idempotency:
an already-inactive key, an already-invalid token, or two versions holding
the same credential report "already" / "nothing" without an issuer call
that could fail.

## 7. Ruling R6 — the agent gate

`var rotate` is **not** on the ceremony deny list: like `push` and `var
rollback --force`, it displays nothing and an agent cannot learn a value
from it; the irreversible steps (finalize, an in-place rotation) take the
same fail-closed confirmation as `var rm` (`--yes`, or a terminal). The
option "deny under agents outright" was weighed and rejected: a leaver
checklist that an operator's agent cannot work through is worse than one it
can, and the damage an agent could do (rotate a credential early) is the
damage `push` already allows.

## 8. Ruling R7 — the leaver checklist (R3 of the ROADMAP)

| # | Shape | Verdict |
|---|---|---|
| 7-A | **After `member remove` / `change-role` (narrowing) / `server revoke`, list the flags addressed to the party — confirmed fetches first — each with its next step: the exact `var rotate` command when `maruhi.rotate.json` covers the variable, the by-hand route with the runbooks otherwise, dismissal for a deleted variable. `maruhi rotation list` carries the same next step per row** | **Adopted** |
| 7-B | An interactive loop ("rotate DATABASE_URL now? [y/N]") | Rejected: it would run the issuer calls inside the removal command (one failure then blocks the removal's exit), and it cannot run under an agent or in CI; the printed commands are the loop |
| 7-C | `maruhi var rotate --flagged` (rotate every flagged variable in one go) | Deferred: each connector call can fail independently and needs its own confirmation when in place; the per-row command is the honest shape until demand shows otherwise |
| 7-D | A count only (the previous behaviour) | Rejected: ADR-0014 decision 3 asks for the mechanism, not a number |

The flag set is the server's derived view (AUDIT_SPEC §7's discipline); the
names and the deleted state come from the verified statements on the
member's machine; the config is consulted only from the working directory's
default path (a broken file is a note, never a failure — the checklist is
guidance). `maruhi device revoke` spans projects without a project
context, so its page points at `rotation list` per project (residual).

## 9. Ruling R9 — expiring values (the one spec item)

### 9-A. The field: an interval, not a date

| # | Shape | Verdict |
|---|---|---|
| A-1 | **`max_age_days` on the schema statement — an interval; the due date = the live version's push time + the interval** | **Adopted** |
| A-2 | A fixed `expires_at` on the schema statement (the ROADMAP's literal wording) | Rejected: every rotation would need a second signed statement to move the date, and a by-hand `maruhi push` would leave a stale date behind; the interval resets with any push |
| A-3 | A per-version `expires_at` in the value write signature (§4.1) | Deferred (residual): the honest fact for connector-issued credentials with a TTL, but it changes every value vector for a field only connectors can fill |
| A-4 | Both A-1 and A-3 | Deferred with A-3 |

Every surveyed reminder is an interval (Infisical ≤365 days, AWS SM 1–1000,
Vault `rotation_period`, Akeyless 1–365). The bound here is 3650 (ten
years); a longer interval is "no interval".

### 9-B. Where the field lives

| # | Shape | Verdict |
|---|---|---|
| B-1 | **Layout v3 of the variable meta statement (a new domain string; v1 / v2 vectors untouched; monotonicity generalized to "never lower")** | **Adopted** |
| B-2 | Change layout v2's signed bytes in place (zero users — the §6.2 precedent) | Rejected: it regenerates every v2 vector **and** the manifest / checkpoint-digest vectors that reference a v2 hash; B-1 appends |
| B-3 | A server-side column outside the signature (set through a new endpoint) | Rejected: the schema is the thing agents and snapshots read as verified; one unsigned column in a signed structure is the "schema-locked bypass" shape §4.2's monotonicity exists to prevent |
| B-4 | `maruhi.rotate.json` (`maxAgeDays` per variable) | Rejected: not shared with members without the checkout, not in the agent-visible schema, not exported with the snapshot |
| B-5 | A convention in `description` | Rejected: a hack |

### 9-C. Where "due" is computed

| # | Shape | Verdict |
|---|---|---|
| C-1 | **Client-side in `rotation list`: the verified statement's interval + the history's server-declared push time (one metadata pull per environment, one history call per declared variable)** | **Adopted** |
| C-2 | A server-side `rotation.due` event / flag | Rejected: an append-only row for an advisory reminder, asserting what the client derives from verified material plus one timestamp the server already declares |
| C-3 | A new field on the metadata pull (`latestPushedAtMs`) to save the history calls | Deferred: an AUTH_SPEC §12-7 change for a per-variable call that is bounded by the number of declared intervals |

The window: past due, or due within 14 days ("due soon"). The section is
printed only when non-empty, after the flags (or after "No rotation flags").

### 9-D. The CLI surface

`maruhi schema set <name> --max-age <days|none>`; the `MAX AGE` column of
`maruhi schema`; `maruhi schema export` writes `x-maruhi-maxAgeDays` (a
JSON Schema extension keyword — unknown keywords are ignored by
validators); `maruhi mcp` returns `maxAgeDays`; `maruhi var rotate` names
the next due date when the variable declares an interval. A new
declaration or a schema reissue signs **v3**; an activation or a deletion
keeps the predecessor's layout (byte-exact fields — §12-5); `schema import`
declares no interval.

## 10. Exhaustion loop (owner-requested — a self-review; pf5-design.md §15's caveat applies)

| Ruling | Round 2 — new candidates | Round 3 | Outcome |
|---|---|---|---|
| R1 config | 1-F: one `maruhi.integrations.json` merging sync / proxy / rotate | Rejected: the three have different trust levels (proxy rules need per-machine acceptance; rotate rules name admin credentials) and different lifecycles | 1-A stands |
| R2 connectors | 2-F: a generic "HTTP recipe" connector (declarative create / revoke requests) so users add issuers without code | Rejected for v1: a recipe that can read any response and write any request is the proxy's "rules are repository-trusted" problem with a credential attached; the three connectors are code reviewed here | R2 stands; recorded |
| R2 AWS | 2-G: validate the new key with `sts:GetCallerIdentity` before pushing (Infisical) | Rejected for v1: a second signed service and an eventual-consistency race (new keys take seconds) that would report false failures; the docs say "a few seconds" | recorded |
| R3 admin | 3-E: inputs from a `maruhi agent` session's memory | Rejected: the session holds the member's keys, not issuer credentials; nothing to gain over a variable | 3-A stands |
| R4 push | 4-F: a `rotation: true` marker on the push for the audit | Rejected: the server cannot verify a rotation happened; a marker that can be claimed is worse than none | R4 stands |
| R5 finalize | 5-E: an issuer-side query instead of the history (list keys / tokens, invalidate everything but the current) | Rejected: "everything but the current" invalidates credentials maruhi never created (a human-made key); the history names exactly the one maruhi stored | 5-A stands |
| R7 checklist | 7-E: open the checklist in the dashboard | Deferred: the dashboard shows the flags; the command per row is the CLI's | 7-A stands |
| R9 field | A-5: both an interval and a hard cap (`max_age_days` + `expires_by`) | Rejected: two fields for one reminder; A-3 covers the hard case later | A-1 stands |
| R9 layout | B-6: put `max_age_days` into the manifest instead | Rejected: the manifest binds statement hashes; it is not a per-variable field carrier | B-1 stands |

### 10-1. Round 4 (owner-requested after the review round — scheduling, the connector set, due notification)

| Topic | Candidates | Verdict |
|---|---|---|
| Scheduled rotation | S-A sealed proposals (ROADMAP's recorded form: a CI process with an OIDC lease mints the credential at the issuer, HPKE-seals it to the members' keys, a human countersigns — CRYPTO_SPEC §5 addendum first) / S-B **scheduled nagging**: `maruhi rotation list --fail-on-due` (a non-zero exit when a value is past its max age) run by a CI cron, which opens an issue or fails a build — no spec, no key, no sending by maruhi / S-C server cron (rejected: the server would hold a signing key and the issuer credential) / S-D a long-lived signing key in CI (rejected by ROADMAP) / S-E a nudge at the point of use: `maruhi run` / `pull` prints a note when a pulled value is past its max age (client-side, zero spec) / S-F a leased CI job pushing the new value itself (collapses into S-A: without a signing key there is no signed version) | **S-A stays the future form** (ROADMAP line "Periodic automation comes later as sealed proposals"; integration-options.md §7 ③). **S-B and S-E are recommended as small follow-ups** before S-A: they give "a schedule" to teams with a CI cron and a reminder to everyone else, at no spec cost. Not in this PR (scope) |
| The connector set | C-A a generic HTTP recipe (rejected 2-F: maruhi interpreting arbitrary credential-bearing requests from a repository-trusted file) / C-B a signed recipe carrier (resolves C-A's trust problem; the 1-C follow-up — larger) / C-C more code-reviewed connectors, one PR each, ranked by dual-credential fit: Azure AD app client secrets (native two secrets — `addPassword` / `removePassword`), GCP service-account keys (two keys at once; federation stays the first answer), Twilio auth tokens (secondary token → promote), SendGrid / Datadog / OpenAI project API keys (create-then-delete), MongoDB Atlas database users / C-D **an `exec` connector**: the rule names a script; maruhi runs it with the admin inputs and the current credential in the child's environment (the `maruhi run` / sync `exec` driver pattern — plaintext by memory injection only), reads the new credential from stdout, and runs a finalize script the same way with the previous one. The trust model equals running any repository script on the member's machine; maruhi interprets nothing | **C-D is the structural answer to "the connector treadmill"** and was not on the table in R2 (a new candidate from this round): it makes the set unbounded without code here, keeps "no server, no scheduler", and is strictly better than C-A on trust (the user's own code, not an interpreter inside maruhi). Recommended as the next rotation PR; C-C per demand after it. The ROADMAP records only the three built connectors — whether more are planned is the owner's to state |
| Due notification | N-1 `rotation list` on demand (done) / N-2 S-B's CI cron (the team's own channel: an issue, Slack via CI) / N-3 S-E's point-of-use note / N-4 a server-side reminder (the server can read `max_age_days` and the push time without decrypting, so an email or webhook "X is due" is feasible on hosted) — the SY6 change-notification doorbell is the recorded shared part for any server-side send; it was demoted to demand-driven (2026-09-05) / N-5 the dashboard showing due values (the web already renders the schema; a badge is a small change) | **Not needed for v1**: N-1 + N-2 + N-3 cover every team that runs a CI cron or uses the values; N-4 only matters for parity with Infisical / Doppler's e-mail reminders for teams that do neither, and rides SY6 when demand appears (no new sending path of its own — the "say nothing" principle is about the client; a user-configured destination is SY6's shape). N-5 is a cheap follow-up for the dashboard |

## 11. Residuals (explicit)

- **Self-rotation's trust**: a rule with no inputs lets whoever holds the
  credential rotate it; the docs name the trade-off. The structural answer
  (an admin credential in an owners-only environment) is a configuration,
  not a default
- **No connection probe for AWS / Cloudflare**: IAM keys propagate in
  seconds and a probe would race them; a Cloudflare token's `/verify` is
  used only to learn ids
- **A finalize's target is never the server's to pick** (security review,
  round 2): the previous value is a lineage-verified ancestor of the
  verified latest, the default "latest − 1" comes from the verified pull
  (not the history endpoint), and the AWS key to deactivate is decided
  against the issuer — a listed key other than the current one, only when
  a lineage-verified earlier version of the key id variable held its id
  **and** it authenticates with the previous version's secret
  (`sts:GetCallerIdentity`, which needs no permission). The history
  endpoint's versions and push times are display data only (vh-design.md)
- **The two-variable AWS push is not atomic** (one round trip of mismatch).
  A push that fails after the issuer accepted the change leaves the new
  credential held only by the exiting process: the failure names the
  connector's recovery step and the rollback of a companion already stored
  (review round 1). Narrowing the window by pre-flighting the push's
  preconditions (scope, floor, CAS head) before the issuer call is the
  follow-up; pushing the primary first would not shrink it for a pair
- **Driver limits**: PostgreSQL / MySQL through Bun's client — SCRAM, TLS
  and `sslmode` are the driver's; no live database runs in CI (the runner
  is recorded in tests; the live path is a Bun probe left for a
  dogfooding session)
- **`maruhi device revoke`** prints no checklist (no project context); the
  docs point at `rotation list` per project
- **The rotation config is repository-trusted** (as P5 of PF4): a signed
  carrier (1-C) is the follow-up that would change that
- **Expiring values are advisory**: the push time is server-declared;
  a per-version signed `expires_at` (9-A A-3) is the follow-up
- **Scheduled rotation (R4 of the memo — sealed proposals)** remains
  demand-driven; nothing here precludes it (a proposal would carry a
  connector's output). The cheap intermediates are §10-1's S-B
  (`rotation list --fail-on-due` under a CI cron) and S-E (a note at the
  point of use)
- **The connector set stays at four**: §10-1's C-D (`exec` connector) is
  the recommended next step, then one code-reviewed connector per demand

## 12. What does not change

- CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC for R1–R3: nothing. **R9 drafts** a
  §4.2 / §11 (CRYPTO_SPEC) and §12-2 / §12-5 / §12-8 (AUTH_SPEC) revision in
  docs/notes/pf6-spec-drafts.md — the canonical texts are untouched until
  the owner approves (§13)
- The server for R1–R3: nothing. For R9: the layout-v3 acceptance (the
  layout ↔ field coupling, the generalized monotonicity, the delete
  just-before match), one DO migration step (`max_age_days TEXT`), the
  support range {1, 2, 3}
- The value-display gate (ADR-0016 decision 7): unchanged
- `maruhi push`, `pull`, `run`: unchanged (an activation keeps its layout)

## 13. Item flagged for the owner — the R9 spec revision

**Resolved 2026-10-02**: the owner approved the R9 spec revision in the PF6 session; the drafts in pf6-spec-drafts.md were applied to CRYPTO_SPEC (0.13-draft) and AUTH_SPEC (0.26-draft) in the implementation PR. The owner also ruled that scheduled rotation (§10-1 S-A with S-B / S-E first) and the connector additions (§10-1 C-D, then C-C) are done **before the release** — ROADMAP PF7 / PF8.

R9 is a CRYPTO_SPEC §4.2 revision (test vectors first, human review — the
ROADMAP's own words). Under the delegation the designer **drafted** the
revision text (pf6-spec-drafts.md), **appended** the vectors
(`metadata-signature.json`: 4 positives, 7 negatives; no existing byte
changed; `generate_reference.py` regenerates the file byte-exact), and
**implemented** it end to end so the owner reviews text, vectors, and code
together. The canonical texts are not edited. The R9 work is its own
commit: if the owner wants the spec round first, that commit is dropped
and R1–R3 stand (they touch no spec and no server). The designer's
recommendation is to approve: the field is one LP position, the layout
mechanism is the one §4.2 already has, and every rule (coupling,
monotonicity, deletion retention) is pinned by a vector.

## 14. Implementation

- `apps/cli/src/sigv4.ts` — SigV4 over WebCrypto (pinned to the AWS
  documentation example)
- `apps/cli/src/rotate-config.ts` — `maruhi.rotate.json` (strict parser,
  per-connector rules, input pointers, the AWS companion's uniqueness,
  `ruleFor` by variable or companion)
- `apps/cli/src/rotate-connector.ts` — the frame (`planRotation` /
  `rotateCredential` / `finalizeCredential` / `describeFinalize`), the four
  connectors, the `SqlRunner` service, password generation
- `apps/cli/src/var-rotate.ts` — the command body (verified pulls, inputs
  from another environment, confirmation, the push, `--finalize` through
  `verifiedAncestorValues`), the `RotateSeams` test reference, the reports
- `apps/cli/src/var-history.ts` — `verifiedAncestorValues` (the rollback's
  ancestor verification, shared)
- `apps/cli/src/rotation.ts` — `reportRotationChecklist` (replacing the
  flag count), `rotationAction`, the `next:` row of `rotation list`, the
  expiring section (R9)
- `apps/cli/src/effect-cli.ts` — `maruhi var rotate`, the checklist calls
  after remove / change-role / server revoke, `schema set --max-age`
- `apps/cli/src/live.ts` — `Bun.SQL` behind `SqlRunner`; `context.ts` —
  the service in `CliServices`
- R9: `packages/crypto` (`meta-sign.ts` layout v3, `meta-verify.ts`
  generalized monotonicity), `packages/api-schema/src/data.ts`
  (`maxAgeDays`), the server (`verify-meta.ts` `ensureLayoutShape`,
  `data-store.ts` the column, `do-schema.ts` step 2, `data-plane.ts`,
  `data-http.ts`, `programs-variable.ts`), the CLI (`floor-check.ts`,
  `values.ts`, `schema-statement.ts` `layoutVersion: 2 | 3`, `schema.ts`,
  `push.ts`, `var-rm.ts`, `schema-import.ts`, `schema-snapshot.ts`,
  `mcp.ts`), the vectors (`generate_reference.py`, `metadata-signature.json`,
  the harness and inventory)
- Tests: `sigv4`, `rotate-config` (+ `rotationAction`), `rotate-connector`
  (fake issuers, a recording SQL runner), `var-rotate` (through `runCli`
  against the in-memory value environment: Postgres across two
  environments, finalize with and without `--yes`, in-place confirmation,
  the AWS pair, refusals before any issuer call), the checklist in
  `member-remove`, the `next:` rows and the expiring section in `rotation`,
  `schema` (`--max-age`, the column, v4 as the unsupported layout),
  `mcp` / `schema-import` expectations, the server's layout-v3 cases
  (`data-schema-v2-transitions`), the crypto vector suite (2585 checks),
  the help golden, the unwrap inventory (`var-rotate.ts`: 7 sites)
- Public docs: `/docs/rotation` (new), `/docs/ai-agents` (`maxAgeDays`),
  the docs index, README; ROADMAP PF6 done
