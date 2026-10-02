# PF7 / PF8 design record — scheduled rotation and the `exec` connector (2026-10-02 design and implementation session)

**Position**: the ROADMAP H series PF index, the two items added by the
2026-10-02 owner ruling "before the release": **PF7: scheduled rotation**
(PF7a = the cheap intermediates `rotation list --fail-on-due` and the
point-of-use note; PF7b = sealed proposals, a CRYPTO_SPEC §5 addendum) and
**PF8: rotation connectors beyond the first four** (first the `exec`
connector, then code-reviewed connectors by demand). The candidates were
enumerated in docs/notes/pf6-design.md §10-1 (S-A … S-F, C-A … C-D, N-1 …
N-5); this record carries the rulings that turned them into code, the
exhaustion loops run on each, the competitor check, the residuals, and the
implementation. PF7b has its own sections (§6 onward) because it is the
one spec item.

**Approval (2026-10-02)**: the owner delegated every open point ("for each
point needing a ruling, loop until no strictly-better or structurally-better
option remains, lay the options out, and pick the one you recommend"),
allowed the designer to decide spec revisions, asked for parity with or
superiority over competitors, ruled backward compatibility out of scope
(zero users), asked for an independent agent review of each item, and went
to sleep. The rulings below are the designer's picks under that delegation.

**Premises (not relitigated)**: the ROADMAP's constraints (**no
server-driven rotation, no long-term signing key in CI** — R5 / R6 of
integration-options.md §4 are never taken); pf6-design.md's rulings R1–R9
(the repository config, the connector frame, the dual-credential grace
period, the history as the rotation state, the agent gate, layout v3);
pf4-design.md ruling P8 and CRYPTO_SPEC §12's scope note (a connector is a
client of a third party's protocol — class (b) — and a script is the
member's own code); the `maruhi run` / `maruhi sync` conventions (memory
injection only, a non-secret repository config, strict parsing, output
scrubbing); the "say nothing" principle (maruhi sends nothing to anyone the
user did not name).

---

## 1. Overall picture

### 1-1. Problem

PF6 made rotation a one-command act and gave values an expiry, but both
still wait for a member to remember. Competitors close that loop with a
scheduler on their server (Infisical, Doppler, Phase, AWS Secrets Manager —
pf6-design.md §1-3), the shape the ROADMAP rules out because it hands the
server a signing key and the issuer's credentials. maruhi's answer keeps
"only humans sign" and splits the problem in three: **a reminder the team's
own CI cron can act on** (PF7a S-B), **a reminder at the point of use**
(PF7a S-E), and — for the issuers the four connectors do not cover — **a
script the team already trusts** (PF8). The automated minting of a new
credential without a member present (PF7b) is the one part that needs a
spec addendum, because the server must store something a machine produced
and a human must countersign it.

### 1-2. Mechanism sketch

```
CI cron (weekly)
  maruhi rotation list --fail-on-due --due-within 14 --fail-on-flags
    │ flags (server-derived view) + verified statements + history push times
    │ prints the full checklist (next step per row), then:
    ▼ exit 3 "Rotation due: 1 value due within 14 days (STRIPE_SECRET_KEY)"  → the team's CI fails the job

maruhi run -- node server.js                      (any pull)
    │ … verified pull, decrypt in memory …
    │ for each variable whose statement declares max_age_days: one history call (concurrent)
    ▼ Note: 1 value past the max age its schema declares: STRIPE_SECRET_KEY (max age 90d, pushed 2026-06-20, expired 14 days ago) — …

maruhi var rotate STRIPE_SECRET_KEY --env prod    (maruhi.rotate.json: connector exec, rotate ./scripts/rotate-stripe.sh, finalize ./scripts/finalize-stripe.sh)
    │ verified pull → decrypt STRIPE_SECRET_KEY and the admin input in memory
    │ spawn ./scripts/rotate-stripe.sh  with  STRIPE_SECRET_KEY=<current>  STRIPE_ADMIN_KEY=<input>  MH_ROTATE_{VARIABLE,ENVIRONMENT,PHASE,CURRENT}
    │ stdout = the new credential (one trailing newline dropped) ; stderr kept only on failure, scrubbed
    │ pushVariable(stdout) → version 8  (an ordinary signed push — the writer is the member)
    ▼ "the previous credential stays valid until you finalize (./scripts/finalize-stripe.sh runs with it)"
maruhi var rotate STRIPE_SECRET_KEY --env prod --finalize
    │ version 7 read back as a verified ancestor → MH_ROTATE_PREVIOUS=<previous>, STRIPE_SECRET_KEY=<current>
    ▼ spawn ./scripts/finalize-stripe.sh
```

Nothing on the server changes for PF7a and PF8: no endpoint, no acceptance
rule, no audit event, no spec text, no wire field.

### 1-3. Competitor check (facts from vendor docs, 2026-10-02 — pf6-design.md §1-3 extended)

| Product | Scheduling | Custom issuers | What maruhi takes / rejects |
|---|---|---|---|
| AWS Secrets Manager | `AutomaticallyAfterDays` on the server; a Lambda per secret | **A custom rotation Lambda** with the four-step contract (create / set / test / finish) | Takes: the "your function does the issuer half" split, as a script on the member's machine (PF8). Rejects: the server-side scheduler |
| Doppler | A per-secret rotation interval on the server; AWS through **a customer-deployed Lambda**; per-secret reminders with recipients | The Lambda is the extension point | Takes: the customer-owned code as the extension point. Rejects: Doppler holding the managing credential and the timer |
| Infisical | Server-side rotation intervals; `secretReminderRepeatDays` with e-mail | No custom rotation function (connectors only) | Takes: reminders. Rejects: e-mail from the server (SY6 territory — "say nothing") |
| HashiCorp Vault | `rotation_period` / `rotation_schedule` on static roles | Plugins (compiled) | Takes: a schedule as the team's own cron. Rejects: a plugin ABI |
| Pulumi ESC | `pulumi env rotate` on demand or by a cron **the user runs** | Rotator providers (built-in only) | Takes: "the cron is yours" |
| Keeper (PAM) | Scheduled on the gateway | **Post-rotation scripts** (PowerShell / bash with the new credential in the environment) | Takes: the environment-injection contract for scripts |
| 1Password | No rotation; an expiry alert on items; the Secrets Automation CLI exits non-zero on failure | — | Takes: the exit-code shape for CI |

The common denominator for custom issuers is **"your own function, with the
credential handed to it, returning the new one"**; the common denominator for
scheduling is a server-side timer, which maruhi replaces with the team's CI
cron plus an exit code. Where maruhi differs structurally: the function runs
inside the member's trust boundary (no server-held issuer credential), and
the push it feeds is signed by the member.

## 2. PF7a — the cheap intermediates (S-B and S-E)

### 2-1. Ruling A — the CI-cron shape of `rotation list`

| # | Shape | Verdict |
|---|---|---|
| A-1 | **`--fail-on-due` (past the max age → exit 3) + `--due-within <days>` (also values coming due within the window) + `--fail-on-flags` (any active rotation flag → exit 3); the listing is printed in full first** | **Adopted** |
| A-2 | `--fail-on-due` alone, exit 1 | Rejected: exit 1 is "the check could not run" (a network or verification failure); a cron must tell "due" from "outage" to route them differently. Exit 2 is usage. **3** is the first free code and is now reserved for "something is due" |
| A-3 | A separate `maruhi rotation check` command | Rejected: the listing *is* the checklist; a second command would print the same rows and drift. The switches turn the existing output into a verdict without a second surface |
| A-4 | A window baked into `--fail-on-due` (fail when due within 14 days, the listing's horizon) | Rejected: a cron that fails two weeks early with no way to say "only past due" is noise; the window is the operator's parameter (`--due-within`, default 0). The listing still shows the 14-day horizon for context |
| A-5 | Fail on flags only through `--fail-on-due` (one switch for everything) | Rejected: a flag is a different fact (a departed party could read the value — a leaver obligation) with a different owner than an aging value; a team may want one check and not the other. Two switches, combinable |
| A-6 | A JSON output for the cron to parse | Deferred: the exit code plus the printed checklist is what a cron acts on; a `--json` listing is a small follow-up when a consumer needs it |

**Why A-1 is strictly better**: the cron's two questions ("is anything
due?" and "could the check run?") get two distinct answers, the operator
chooses the lead time, and the job's log is the checklist itself (the exact
`maruhi var rotate` command per row — pf6-design.md R7). No new endpoint,
no sending by maruhi: the notification is whatever the CI does with a
failed scheduled job (the "say nothing" principle holds).

### 2-2. Ruling B — the point-of-use note

| # | Shape | Verdict |
|---|---|---|
| B-1 | **After `maruhi run` / `maruhi pull` verified and decrypted the environment, one `Note:` line names the values past their max age; the push time comes from the history endpoint, one call per variable that declares an interval, run concurrently** | **Adopted** |
| B-2 | Add `pushedAtMs` to the bulk-pull wire (AUTH_SPEC §12-7) and to the lease response, so no extra call is needed | Rejected for now (pf6-design.md R9-C deferred the same field): it changes two wire shapes and the lease path for an advisory reminder, and every pull mock in the test suite (174 sites) would carry it. The history calls are bounded by the number of declared intervals — a handful — and run concurrently, so a `run` pays one round-trip time whatever the count. Recorded as the follow-up that would also give `ci run` the note |
| B-3 | Note values *due soon* as well as past due | Rejected: a `run` is the wrong place for a 14-day lookahead (it would print on every run for two weeks); the listing has the horizon, the `run` note has the fact |
| B-4 | Warn (stderr `Warning:`) instead of note | Rejected: a warning in `run` reads as "something about this run is degraded"; nothing about the run is. A note is information |
| B-5 | Also on `ci run` | Not possible without B-2: a workload holds no token and the lease carries no push time; documented |

**Why B-1 is strictly better**: zero spec, zero wire, zero server; the note
appears exactly where the aging value is used; and the cost is proportional
to the number of declared intervals, which the team controls.

## 3. PF8 — the `exec` connector

### 3-1. Ruling C — what the script receives

| # | Shape | Verdict |
|---|---|---|
| C-1 | **The credential under the rule's own variable name and as `MH_ROTATE_CURRENT`, the companions and the admin inputs under their configured names, plus `MH_ROTATE_VARIABLE` / `_ENVIRONMENT` / `_PHASE` (and `MH_ROTATE_PREVIOUS` on finalize) — all in the child's environment by memory injection; stdin closed** | **Adopted** |
| C-2 | Everything on stdin as JSON (the sync exec driver's shape) | Rejected: the sync driver keeps values off the environment because the *vendor CLI* is a third-party program whose argv and env are visible to it; here the script is the team's own code and its environment is the natural interface of every shell / Python / Node script. A JSON stdin forces a parser into the simplest script |
| C-3 | A single `MARUHI_ROTATE_*` namespace for everything | Rejected: `buildChildEnvironment` structurally strips `MARUHI_*` from every child (so a nested `maruhi` never sees the parent's token); the control variables must live outside it. `MH_ROTATE_*` is distinctive, outside the stripped namespace, and read by nothing in maruhi |
| C-4 | Only the variable name (no `MH_ROTATE_CURRENT`) | Rejected: a script that serves several rules would need `${!MH_ROTATE_VARIABLE}` (bash only). Both names cost nothing |
| C-5 | Pass the admin inputs as files | Rejected: the diskless invariant (plaintext never on disk) |

Names are validated at config time with the same rules as `maruhi run`'s
injection (a POSIX identifier, not an execution-control name such as `PATH`
/ `LD_PRELOAD`, not the `MH_ROTATE_` prefix, not the rule's own name); values
are refused when they are not UTF-8 text without NUL (an environment
variable cannot carry them), naming the variable and never the value.

### 3-2. Ruling D — what the script answers

| # | Shape | Verdict |
|---|---|---|
| D-1 | **stdout = the new credential (one trailing newline dropped, nothing else touched) by default; `"output": "json"` opts into `{ value, companions?, facts? }` for issuers whose credential has an id to store next to it** | **Adopted** |
| D-2 | JSON always | Rejected: the simplest real script is `curl … \| jq -r .secret`; forcing JSON means forcing the quoting of a secret into a shell string |
| D-3 | Raw value always, companions through a second script or a file | Rejected: companions are the AWS pair's shape (a key id next to the secret, pushed together) and belong in the same answer |
| D-4 | A specific exit code for "nothing to do" / "already rotated" | Rejected: the contract has one success (a credential was produced) and one failure; a script that finds nothing to do exits non-zero with a sentence, which is what the member reads |

The script's `facts` and its stderr are the only text the script controls
that reaches the terminal, and both are scrubbed of every secret this run
knows (the current credential, its companions, the inputs, the previous
credential, and the new value) with the sync driver's scrubber before being
shown; stderr is shown only on failure, as its tail.

### 3-3. Ruling E — grace period and finalize

| # | Shape | Verdict |
|---|---|---|
| E-1 | **A `finalize` script present = the dual-credential grace period (the rotate script creates the second credential, finalize retires the previous one, receiving it as `MH_ROTATE_PREVIOUS`); absent = no grace period: the rotate script is expected to retire the old credential itself, and the rotation asks for confirmation (`--yes` in scripts)** | **Adopted** |
| E-2 | A `"grace": true/false` field | Rejected: it would be a claim about the script that nothing checks; the presence of a finalize script *is* the fact |
| E-3 | Finalize optional with no consequence | Rejected: a rule without a way to retire the old credential later must say so at rotation time, exactly as the in-place PostgreSQL shape does (pf6-design.md R2) |

The previous credential comes from the version history as a verified
ancestor (pf6-design.md R5 — no state file), so a finalize script never
receives a value the server could have substituted.

### 3-4. Ruling F — where and how the script runs

| # | Shape | Verdict |
|---|---|---|
| F-1 | **argv arrays (no shell), run from the config's directory (`cwd` relative to it), through the same ProcessRunner boundary as `maruhi run` / `sync` (production: Bun.spawn; tests: a recorder)** | **Adopted** |
| F-2 | A shell string (`sh -c`) | Rejected: quoting a credential into a shell line is the failure the environment contract avoids; and `cmd`-vs-`sh` portability |
| F-3 | cwd = the process's working directory | Rejected: `--rotate-config ../ops/maruhi.rotate.json` would resolve scripts against the wrong tree; scripts travel with the config |
| F-4 | An absolute `cwd` | Rejected: it would not travel with the repository |
| F-5 | A timeout | Deferred: a script that hangs is visible (the member is at the terminal, or the CI job times out); a configurable timeout is a small follow-up |

### 3-5. Ruling G — the trust model (why no new review surface)

The ROADMAP's objection to a generic HTTP recipe (pf6-design.md 2-F / C-A)
was that maruhi would interpret arbitrary credential-bearing requests from a
repository-trusted file. The `exec` connector interprets nothing: the script
is the team's code, run with the member's own credentials, exactly like any
script in the repository the member runs by hand. What maruhi adds is the
maruhi half (verified pull, decryption in memory, the signed push, the sync,
the grace period, the history as state) and the hygiene (no disk, scrubbed
output, validated names). A compromised script can rotate a credential badly
— the same damage `maruhi push` already allows (pf6-design.md R6) — and
cannot sign as the member on its own (no key leaves maruhi). Nothing needs a
per-machine acceptance like `maruhi.proxy.json` (pf4-design.md §21 R-8):
that gate exists because the proxy config changes what an *agent* receives
under `maruhi run`; a rotation is a member's explicit act with a
confirmation on every irreversible step.

## 4. Exhaustion loop (owner-requested — a self-review)

| Ruling | Round 2 — new candidates | Verdict |
|---|---|---|
| A (cron) | A-7: `--fail-on-due` also when a declared interval cannot be evaluated (a history read failed) | Rejected: it would turn an outage into "due"; the failure is said as a note and the row is absent, which keeps exit 1 / 3 honest. A-8: a `--quiet` to print only the verdict | Deferred (the log *is* the checklist) |
| B (note) | B-6: cache the push times in the floor log to skip the history calls | Rejected: the push time is server-declared and advisory; caching it would make the floor carry a non-verified fact |
| C (script env) | C-6: pass companions as `MH_ROTATE_COMPANION_<NAME>` instead of their own names | Rejected: the companion's env name is what the script author chose in the rule; a derived name adds a mapping to remember |
| D (answer) | D-5: accept the new value on a file descriptor 3 instead of stdout, leaving stdout free for commentary | Rejected: fd 3 is not portable to every host and every language's convenience APIs; "stdout is the answer, stderr is commentary" is the Unix contract |
| E (grace) | E-4: let finalize run automatically after a configured delay | Rejected: no daemon (pf6-design.md 5-D); the deploy is the member's, not a clock's |
| G (trust) | G-2: require the script to be committed and clean in git before running | Rejected: a check that proves nothing (the committed script can be anything) and breaks local iteration; the repository's review process is the review |

Round 3: a generic "webhook" connector (POST the current credential to a
URL and read the new one back) was weighed and rejected as C-A in a new
coat — the URL would receive the credential, and the script can do the same
`curl` with the team's own review. Enumeration closed.

## 5. Residuals (explicit)

- **`ci run` has no point-of-use note** (no push times in a lease — B-5);
  the CI-cron shape (A-1) is the CI answer
- **A script's secrets are scrubbed by exact match**: a script that prints a
  transformed credential (base64, split) can leak it on failure; the docs
  say stderr is the script's responsibility
- **No script timeout** (F-5)
- **The exec rule is repository-trusted** like every rotation rule
  (pf6-design.md 1-C / §11); a signed carrier is the recorded follow-up
- **The companion pair push is not atomic** (pf6-design.md §11) — the exec
  connector inherits it

## 6. PF7b — sealed proposals (the spec item)

### 6-1. Problem and shape

PF7a gives a schedule to a team with a CI cron, but the rotation itself
still needs a member at a keyboard. The ROADMAP's recorded form closes
that gap without a server-side scheduler or a long-term signing key in
CI: a CI job holding only a workload lease (§9.1) mints the new
credential at the issuer through the rotation connectors, seals it to the
members' public keys, and stores the proposal; a member countersigns.

```
cron → maruhi ci rotate STRIPE_SECRET_KEY --env prod  (the job: OIDC lease, no signing key)
   │ lease prod (+ the env of an admin input) → decrypt current + inputs in memory
   │ planRotation: refuse an immediate rule (no grace period = a proposal could strand the service)
   │ rotateCredential (exec / aws / cloudflare / postgres / mysql) → new values + facts
   │ W(E) from the verified chain: devices of member-or-above whose scope ∋ prod
   │ one HPKE Seal per (device × value): info = LP(sealed-value, project, env, proposal_id, variable_id, base_version, recipient_user_id)
   ▼ POST /projects/:p/environments/prod/rotation-proposals { oidcToken, ephemeralPubHex, proposal }  (the lease's token and key)
server: the lease's authorization (grant × policy × scope → uniform 404; first-come binding → 401) → window → §14-5 checks → store rows + rotation.proposed (actor system)
member → maruhi rotation accept <id>
   │ GET /rotation/proposals (own wraps only) → verified pull → base_version == current? → Open with the device enc key
   │ confirm (facts, the minting workload's claims digest + grant seq) → pushVariable (an ordinary §4.1 push)
   ▼ POST /rotation/proposals/<id>/resolution { accepted, versions }  → rows deleted, rotation.proposal_accepted
```

### 6-2. Rulings (each after an exhaustion loop)

| # | Ruling | Candidates | Why |
|---|---|---|---|
| H | **Who seals, who stores**: the job seals to member device keys; the server stores ciphertexts it cannot open | H-1 the server seals (it would hold the plaintext — rejected); H-2 **the job seals, the server stores** (adopted); H-3 the job pushes an unsigned version a member re-signs later (an unsigned version in the §4.1 history — rejected); H-4 a signing key in CI (rejected by the ROADMAP) | H-2 is the only shape where nobody but a member device ever holds the plaintext, and the version history stays "signed pushes only" |
| I | **The recipient set W(E)** = every device whose effective permission (person ∩ device) has role ≥ member and a scope that includes E | I-1 R(E) (all wrap recipients incl. readers and the server key — the server key would decrypt the proposal; readers cannot push — rejected); I-2 **W(E)** (adopted); I-3 owners only (narrows who can act for no gain — rejected); I-4 a named acceptor (brittle: the device may be away — rejected) | Minimal disclosure: the value is disclosed before acceptance only to those who could have pushed it. The server refuses a set that is not exactly W(E) (the §6.3 ghost-member ban applied to proposals) |
| J | **What the info binds**: project, environment, proposal id, variable id, **base version**, recipient user id | J-1 the §5 shape with an epoch (a value is not epoch-bound; without a proposal id a sealed value could be re-filed — rejected); J-2 project / env / proposal / variable / recipient; J-3 also the recipient device fingerprint (the keys differ already — the §8 guardian-share precedent — rejected); J-4 **J-2 plus the base version** (adopted in a second loop: without it a server could re-label a stale proposal as minted against the current version and a member would push the job's old credential on top of a newer push; with it the member's Open fails) | The same primitive as §5 / §9.1, a new domain string, no new primitive. Facts and the minter's identity are server-managed metadata (shown with that caveat — §6-5) |
| K | **The mint's credential** = the lease's OIDC token and ephemeral key, through the lease's authorization and first-come binding | K-1 an API token in CI (a long-lived credential — rejected); K-2 **the lease's credential** (adopted — one token, one key, already bound); K-3 a fresh token per mint (works, creates a second binding for nothing) | Nothing new to provision or steal; a copy of the token in other hands is refused before anything is stored |
| L | **Acceptance** = the member pushes (an ordinary signed version), then resolves naming the versions; the server verifies they exist and are newer than the base | L-1 the server applies the version on resolution (no signature — rejected); L-2 **push then resolve** (adopted); L-3 a composite "push + resolve" request (atomic, but a new acceptance surface; a pending proposal left behind by a failed resolve is harmless and the CLI says what to do — deferred) | The proposal never becomes a version; a member's push is what it always was |
| M | **Visibility**: list = member or above, environments in scope, **own wraps only**; readers 403; session principals refused (no Web screen); resolve = member or above × environment ∈ scope | M-1 every wrap to everyone (leaks the recipient set, useless — rejected); M-2 **own wraps** (adopted) | A wrap to someone else's key is worthless to the caller |
| N | **Caps**: 32 pending per project, 8 variables per proposal, 16 facts of 256 characters, expiry ≤ 30 days, 60 mints per hour per project (its own window kind) | the four-eyes proposal's caps as the precedent; a per-mint window separate from issuance so a retry loop cannot drain the lease window | Judged after authorization (existence concealment) |
| O | **Immediate rules are refused in CI** (a rule with no grace period) | O-1 allow with `--yes` (a proposal may be rejected or expire while the service runs on a credential the job already invalidated — rejected); O-2 **refuse before the issuer is touched** (adopted) | The dual-credential discipline of pf6-design.md §2 holds in CI by construction |
| P | **Lifetime of rows**: resolution and expiry delete the rows; the audit log keeps the outcome (`rotation.proposed` actor system with the claims digest and grant seq; `rotation.proposal_accepted` / `_rejected` actor member, class 1) | P-1 keep resolved rows (storage for nothing — rejected) | The audit rows are the history |

### 6-3. Competitor check

| Product | Scheduled rotation | Where the new secret lives before it is "accepted" | maruhi's position |
|---|---|---|---|
| Doppler / Infisical / Phase | A server-side timer; the server holds the managing credential and writes the new value itself | In the server, plaintext-readable by it | The server never holds a plaintext or a signing key; the timer is the team's CI; a human countersigns |
| AWS Secrets Manager | A rotation Lambda per secret, scheduled by the service | In the service | The connector runs in the team's job; the result is encrypted to member devices only |
| HashiCorp Vault | `rotation_period` on static roles | In Vault | Vault cannot be E2EE; maruhi can because the job seals and the member signs |
| 1Password / Keeper | No automated rotation (1Password); gateway-scheduled with post-rotation scripts (Keeper) | Keeper's gateway | Takes Keeper's "script with the credential in the environment" shape (PF8) and adds the sealed hand-off |

No competitor has "a machine mints, a human countersigns, the server stores only ciphertext": it is the shape E2EE forces, and it keeps the ROADMAP's two negatives (no server-driven rotation, no long-term signing key in CI).

### 6-4. Exhaustion loop (self-review)

| Ruling | Later candidates | Verdict |
|---|---|---|
| H | H-5: the job seals to a project-wide "proposal key" held by every member | Rejected: one key for everyone is a key to revoke on every departure; device keys already carry the per-device revocation |
| I | I-5: include the server key so `ci run` could consume a proposal before acceptance | Rejected: the server would decrypt the proposal; the whole point is that it cannot |
| J | J-5: also seal the facts (an envelope `{value, facts}`) so the server cannot re-label them | Deferred: the facts are display-only; a wrong fact cannot make the member push a different value (the value is under the seal). Recorded as a follow-up if dogfooding shows a need |
| L | L-4: let the resolution carry the pushed values' signed-bytes hashes so the server can match them | Rejected: the server already verifies the named version exists and is newer than the base; the hash adds a check the member's own push already covers |
| K | K-4: a dedicated OIDC audience for mints | Rejected: the policy already names the workload; a second audience doubles the policy for no new boundary |
| O | O-3: refuse `exec` rules without a finalize script even locally | Rejected: locally the member is present and confirms; in CI nobody is |
| I | I-6 (review round): judge the device's effective role, not the person's chain role | Adopted: a reader-capped device of a member could open the value but never push it (the server judges pushes on the effective permission) — the spec's rationale "only those who could have pushed" is now literal on both sides |
| L | L-5 (review round): recognize an earlier accept's own push (same bytes as the opened value, current version > base) and resolve without pushing | Adopted: a push that succeeded while the resolution failed no longer ends in a `rotation.proposal_rejected` row for a value that is live; the re-run of `accept` decrypts the current value, compares, and only resolves. The variable order is stored (`position`) so the companions-first push order survives random variable ids |
| N | N-2 (review round): the §12-8 ciphertext meter counts pending proposals' sealed values; a mint that would pass the cap is refused as `storage-limit` | Adopted: without it a project could park ciphertext outside the cap in proposals |
| M | M-3 (review round): an out-of-scope member's resolution folds into the same 404 as unknown / resolved / expired | Adopted: the environment is known only from the stored row, so scope cannot be judged before existence; the fold keeps "pending" indistinguishable from "gone" for a member outside the environment |

Round 3: a "proposal to create a variable" (declared → active) was weighed and
rejected — a creation needs a statement the member signs, and the job
cannot know the name/schema policy; the existing `declare` + `accept`
cannot express it without a new composite. Enumeration closed.

### 6-5. Residuals (explicit)

- **Facts, the connector name, the minter's claims digest and grant seq
  are server-managed metadata**, like audit rows: a malicious server can
  alter them; it cannot alter the value, the variable, or the replaced
  version (under the seal) and cannot read the value. The CLI shows the
  minter with that caveat and the audit row is the cross-check
- **The pair push is not atomic** (pf6-design.md §11) — accept inherits it;
  a failed second push leaves the proposal pending with the stored
  versions named in the message, and the re-run of `accept` recognizes
  the stored value (ruling L-5) and pushes only the rest. A value the
  proposal pushed and that a later push then replaced is a "moved"
  proposal: rejecting it records the outcome, and the credential the job
  created is named for retirement although it was live for a while
- **A proposal cannot create a variable** (declared variables are not
  accepted targets)
- **One proposal per job run** (a job rotating several rules runs the
  command once per rule)
- **No automatic finalize**: the member finalizes after the deploy, as
  locally
- **Spec text**: CRYPTO_SPEC §5.3 and §11 are applied in this change. The
  AUTH_SPEC additions (§14-5 — the mint endpoint, its acceptance checks,
  the two member endpoints and their rows in §12-3 and §12-8) and the
  AUDIT_SPEC §3.3 rows for the three events were drafted in this session,
  refused by the editing tool at first, and **applied later in the same
  session** (after the PF2 review round) from the implementation

### 6-6. Implementation (PF7b)

- `packages/crypto/src/internal.package/sealed-value.ts` — `SealedValueContext`,
  `buildSealedValueInfo`, `sealProposedValue`, `openProposedValue`,
  `isProposalId`, `MAX_SEALED_VALUE_BYTES`; vectors `test-vectors/sealed-value.json`
  (`tools/generate-sealed-value.mjs`, the `verify_reference.mjs` section,
  `test/checks/sealed-value.ts`, the inventory, README convention 29)
- `packages/api-schema` — `lease.propose` (strict), `rotation.proposals`,
  `rotation.resolveProposal` (strict), the schemas and the two errors
  (`RotationProposalRejected` 422 with its reason vocabulary,
  `RotationProposalNotFound` 404); `lease.propose` classified unauthenticated
- `apps/server` — migration step 3 (`rotation_proposals`,
  `rotation_proposal_variables`, `rotation_proposal_wraps`),
  `programs-lease.ts`'s `authorizeWorkload` (the shared front stage),
  `programs-proposal.ts` (mint / list / resolve, W(E)), the DO RPCs, the
  handlers, the store's proposal queries and write ops, the `proposed`
  window kind, the three class-1 events, the policy constants
- `apps/cli` — `ci-rotate.ts` (`maruhi ci rotate`), `rotation-proposals.ts`
  (`rotation proposals / accept / reject`), the pending line in
  `rotation list`, `leaseEnvironmentsWithCredential`, the lease material's
  `verified` view, the error mapping
- Tests: `packages/crypto` (vectors + roundtrip + invalid contexts),
  `apps/server/test/rotation-proposals.test.ts` (mint / list / accept,
  W(E) refusals, the §14-5 reasons, the window, the lease's 404 and 401,
  resolution, expiry, a scoped member), `apps/cli/test/ci-rotate.test.ts`
  and `rotation-proposals.test.ts`
- Docs: `/docs/rotation` ("Rotation from CI: sealed proposals"),
  `/docs/github-actions` ("Rotate a credential from CI"), README, the index

## 6-7. Review round (independent agents, 2026-10-02)

Two read-only review agents went over PF7a / PF8 and PF7b after the
implementation. Everything they found was applied in the same change:

- PF8 config: the exec rule's own variable name goes through the same
  environment-name line as its inputs (an `LD_PRELOAD` or `MH_ROTATE_*`
  variable cannot be an exec rule); a companion under the rule's own name
  is refused; collisions between the rule name, inputs and companions
  are judged case-insensitively; `cwd` may not climb out of the config's
  directory
- PF8 connector: a produced value (stdout or a JSON field) must be UTF-8
  text without NUL before it is stored; the script's own words (an unknown
  JSON key, an undeclared companion name) never reach an error message;
  the finalize script's stdout as facts is documented
- PF7a: a history that could not be read fails `--fail-on-due` with exit
  1 (an unknown age is not a passed check); `describeDue` rounds the way
  the `--due-within` window counts; the docs' cron example installs the
  CLI with `setup-maruhi` and names the server and project
- PF7b: rulings I-6, L-5, N-2, M-3 (§6-4) — the device's effective role in
  W(E), the already-stored detection on a re-run of `accept`, the stored
  variable order, the proposal bytes in the §12-8 meter, the out-of-scope
  resolution's 404; the harness pins the sixth info negative
  (`info-base-version-mismatch`); the spec's §5.3 wording (value cap
  reference, six negatives, push order) and the github-actions note on
  in-place PostgreSQL rules; tests for every pinned claim the reviews
  listed as missing (pending-limit, duplicate-variable, past expiry,
  device-axis W(E), the mint window's 429 with its denied row, the
  two-variable order on both sides, the push-ok / resolve-failed path,
  `--expires-in 30`). Not pinned by a test: `storage-limit` (a 1 GiB
  fixture) and `rotation list` as a reader (the branch is three lines)

## 7. What does not change (PF7a / PF8 — PF7b's changes are §6)

- CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC: nothing (PF7b: CRYPTO_SPEC §5.3)
- The server: nothing (no endpoint, no acceptance rule, no audit event —
  PF7b adds its own, §6-6)
- The value-display gate (ADR-0016 decision 7): unchanged — the exec
  connector displays nothing; `--fail-on-due` reads metadata only
- `maruhi push`, `pull`, `run`'s outcomes: unchanged (the note never
  changes an exit code)

## 8. Implementation (PF7a / PF8)

- `apps/cli/src/max-age.ts` — the due computation shared by `rotation list`
  and the point-of-use note (`dueRowsFor`, `formatPastDueNote`,
  `notePastDueValues`), concurrent history reads
- `apps/cli/src/rotation.ts` — `RotationListOptions` (`failOnDue`,
  `dueWithinDays`, `failOnFlags`), `ROTATION_DUE_EXIT_CODE = 3`, the
  verdict after the full listing
- `apps/cli/src/pull.ts` / `lease-client.ts` — `DecryptedVariable.maxAgeDays`
- `apps/cli/src/effect-cli.ts` — the three `rotation list` flags, the note
  in `pullForRun` (run / brokered run) and `pull`
- `apps/cli/src/rotate-config.ts` — the `exec` rule (argv, finalize, cwd,
  output, companions, free-form inputs), name validation shared with
  `maruhi run` (`isDeniedEnvName` / `SAFE_ENV_NAME` exported from run.ts),
  `companionVariablesOf` generalizing the AWS companion, `parseRotateConfig`
  takes the config's directory
- `apps/cli/src/rotate-connector.ts` — the exec connector (environment
  assembly, the stdout contract, the JSON answer, scrubbed stderr / facts,
  finalize), `RotationSite`, `RotateDeps.exec`
- `apps/cli/src/run.ts` / `live.ts` — `ProcessRunnerShape.captureScript`
  (`CaptureInput` / `CaptureOutcome`; Bun.spawn with stdin closed, stdout as
  bytes)
- Tests: `max-age` through `rotation.test.ts` (`--fail-on-due`,
  `--due-within`, `--fail-on-flags`, the usage error) and
  `pull-run.test.ts` (the note on run / pull, no note when fresh, a failed
  history said), `rotate-config.test.ts` (every exec shape and refusal),
  `rotate-connector.test.ts` (the env contract, the stdout / JSON answers,
  finalize, scrubbing, failures), `var-rotate.test.ts` (end to end through
  `runCli` with a recorded script: rotate, finalize, a failing script, the
  no-finalize confirmation), the help golden
- Public docs: `/docs/rotation` (the `exec` connector, the point-of-use
  note, "Checks on a schedule"), the docs index, README

## 9. Exhaustion loop, round 2 and later (owner-directed, 2026-10-02)

After the review round the owner asked whether every ruling had been looped
until no candidate remained; the honest answer was no (one enumeration plus
one self-review, several rulings closed implicitly), and the owner directed
additional rounds over **every** ruling until each closes. Each round sends
independent adversarial agents over the rulings that still take candidates;
the designer judges under the delegation; adopted candidates are
implemented in the same change; a ruling is **CLOSED** at the round whose
agents found nothing strictly or structurally better.

### 9-1. Round 2 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| A (cron) | A-9: `--fail-on-pending` — exit 3 while a sealed proposal awaits a member (the check that closes the PF7b loop; `--due-within` counts the ones expiring in the window) | **Adopted**. A proposal nobody answers is the one rotation state the listing could see and the cron could not act on. It needs a member's token (readers are not recipients): a reader's token or a failed list is "cannot judge" (exit 1), the same rule as an unreadable history |
| B (note) | B-7: a bound on the history calls so a slow server cannot stall `run` | **Adopted** — 10 s per history read (`Effect.timeout`); the timeout is a failed read and is said as a note, the run proceeds. B-8: a `--no-note` switch — deferred (one line on stderr; a case for it has not appeared) |
| C (script env) | C-7: pass the previous credential's companions to finalize as `MH_ROTATE_PREVIOUS_<companion>` | **Adopted**. The pairing is positional (a rotation pushes the pair together), so the companion's value directly before the current one is passed only when the primary's previous version is also the one directly before; otherwise nothing is claimed. Scrubbed like every other value |
| D (answer) | D-6: cap the script's stdout (1 MiB) and stop the script past it | **Adopted** — a credential is small; an unbounded read is a memory hole a script can open by accident (`cat` of the wrong file). D-7: the value's shape (bytes, lines) as the first fact | **Adopted** — a member accepting a proposal sees a script that printed chatter instead of a value before pushing it; the ciphertext length tells the server the same, so nothing new leaks |
| E / F / G | nothing new | **CLOSED (round 2)** |
| H (who seals) | H-6: seal to a per-project rotating "acceptor key" distributed through DEK wraps; H-7: seal to the environment DEK | Rejected: H-6 is a second key to revoke on departure (ruling H's reason); H-7 lets every reader and the server-wrap path open the value (ruling I's reason). **CLOSED (round 2)** |
| I / J / M | nothing new | **CLOSED (round 2)** |
| K (credential) | K-5: present a token minted after the connector, under the lease's ephemeral key | **Adopted** — a connector can outlive a short-lived token (propagation waits at the issuer); §14-1's binding makes the key, not the token, the continuity, so a fresh token binds to the same key. The lease's token stays the fallback when the runner's issuance endpoint does not answer again. (K-3 was rejected in §6-2 as "a second binding for nothing"; K-5 is the same mechanism with a reason) |
| L (acceptance) | L-6: a server-side "accept" that applies a member-signed envelope; L-7: a resolution deadline | Rejected: L-6 is ruling L-1 again; L-7 is the expiry. **CLOSED (round 2)** |
| N (caps) | N-3: per-workload mint caps | Rejected: the per-project window already bounds it and the workload has no stable identity below the claims digest. **CLOSED (round 2)** |
| O (immediate rules) | O-4: a pre-flight — the mint's checks that do not depend on the sealed content, asked before the issuer is touched; O-5: a dry-run flag | **O-4 adopted** — `POST …/rotation-proposals/preflight` under the lease's credential, storing nothing and consuming no window; a refusal strands nothing. New reason `variable-pending` (one pending proposal per variable — two jobs cannot race a member into two pushes), checked by the mint as well. O-5 deferred (the pre-flight is the dry run of what matters) |
| P (lifetime) | P-2: an audit row for an expiry; P-3: a notification | **P-2 adopted** — `rotation.proposal_expired` (actor system) when the sweep drops the row, so `rotation.proposed` is never without a closing row. P-3 deferred (maruhi sends nothing; `--fail-on-pending` is the cron's notification) |

Rulings A, B, C, D, K, O and P received candidates in this round and stay
open for round 3.
