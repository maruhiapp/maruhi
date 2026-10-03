# PF2 — Mirror: a read replica in your own Cloudflare account (design record)

Date: 2026-10-02. Owner-delegated session (every open point ruled after an
exhaustion loop; competitor parity; zero users, no compatibility kept).
ROADMAP item PF2 ("the answer to read-side availability. Spec revision
[server-key uniqueness §6.2 / re-grant rules §6.3] + a replication path +
the client's 'primary → mirror' fallback order. Writes wait for the
primary's recovery"). The earlier framing is integration-options.md
supplement 17 ("what a mirror avoids is the read side — `run` / `ci run` /
deploy-time re-apply; the write side waits; to issue CI leases from a
mirror, `grant_server` to the mirror's server key").

PF3 (docs/notes/pf3-design.md) is the foundation: the paged export is the
replication primitive, and the import job is the mirror's bootstrap.

## 1. The problem in one paragraph

Every deploy-time read (`maruhi run`, `ci run`, `ci sync`) depends on one
deployment being up. A mirror is a second deployment (the team's own
account) that holds a verified replica of the project and answers those
reads when the first does not, including CI leases under its own server
key. Nothing about the trust model changes: a mirror is "another server",
and the client verifies what it serves exactly as it verifies the primary
(the chain, the floor, the anchors, the gossip). What the design has to
settle is who may write to a mirror (nobody), how the replica gets there
(the export, pushed by a member), how the client decides to use it, and
how a mirror becomes the primary when the primary is gone for good.

## 2. Rulings (each after an exhaustion loop)

| # | Ruling | Candidates | Why |
|---|---|---|---|
| A | **A mirror is a marked project on an ordinary deployment**: the project DO carries a `mirror_state` row (the source origin, the sync position, the last head) in a table outside the snapshot set; the deployment itself is unchanged and may host primaries of its own | A-1 a "mirror mode" worker (every project read-only — a team's own deployment also hosts its own projects; rejected); A-2 a D1 flag (the DO is the point of determination — AUTH_SPEC §11-3; rejected); A-3 **a DO-held mark** (adopted) | One deployment, one code path; the mark lives next to the data it governs |
| B | **The DO refuses every write on a mirror** (chain appends and composites, variable and statement writes, wrap registration and deletion, the schema policy, dismissals, proposal resolutions, head attestations) with `Forbidden` reason `mirror-read-only` — guarded at the DO's write entry points after the caller's membership (checked in the DO: the worker checks only the token's scope, so a non-member keeps the uniform 404) and before the role floor (the mark is readable by every member, so nothing a reader could not learn leaks). The workload mint refuses with `RotationProposalRejected` reason `mirror-read-only` after the lease authorization (the lease vocabulary has no 403: the workload is not a member, and existence concealment comes first). Reads and leases are served | B-1 refuse in the worker (a second place to forget — rejected); B-2 **the DO's write entry points** (adopted); B-3 allow attestations (they would be erased by the next sync and mislead gossip — rejected) | A client that mistakes the mirror for the primary learns it at once; the lease path is a read (the server unwraps only its own wraps) |
| C | **Bootstrap = the PF3 import, then the mark**: the mirror's operator imports the owner's export (identities included, so members can log in on the mirror), and the owner marks the project with `PUT /projects/:id/mirror { sourceOrigin }`. Unmarking (`DELETE`) **promotes** the mirror to a primary — the failover | C-1 a sync that creates the project (nobody could log in to run it — rejected); C-2 **import + mark** (adopted); C-3 an automatic promotion when the primary is silent (a split brain by design — rejected) | The first copy needs the operator anyway (D1 identities); the promotion is an owner's decision |
| D | **Replication = the export's pages uploaded to the mirror**: `PUT /projects/:id/mirror/pages { sequence, lines }` (admin × admin scope on the mirror's current chain). Pages are staged in the DO (one staging table per snapshot table; `sequence` 0 restarts the staging; a gap is refused); the page carrying the trailer commits: counts against the trailer, the schema version, **the staged chain extends the live chain** (every live (seq, hash) present at the same seq; the head not behind), the audit seq not behind, then one transaction swaps every snapshot table **except the server-local ones** (lease windows and bindings, attestation windows — the mirror's own first-come state must survive a sync) | D-1 the mirror pulls from the primary with a stored owner token (a long-lived admin credential in a second deployment's secrets — rejected); D-2 the primary pushes to mirrors (the hosted operator holding tenants' mirror credentials — rejected); D-3 re-import into an empty DO (a mirror is never empty — rejected); D-4 **a member-driven page upload** (adopted) | The same bytes the owner can already take out; the extension rule makes a mirror monotonic (a stale old primary can never be synced over a newer one) |
| E | **The client fallback is explicit and read-only**: `maruhi config set mirror <url>` or `--mirror <url>` on `run`, `pull`, `ci run`, `ci sync`; the primary is tried first; on a transport failure or a gateway error (no response, 502 / 503 / 504, Cloudflare 52x) the whole read is retried against the mirror with the mirror's own credential (the keychain token of that origin; in CI a second OIDC token for the mirror's audience unless `--audience` was given), announced on stderr; every verification duty runs unchanged, and a mirror behind the floor is refused like any server. Writes never fall back | E-1 fall back on any error (a 403 or a 404 from the primary would be retried against a replica that cannot answer differently — rejected); E-2 a silent fallback (the member must know which server answered — rejected); E-3 **transport failures only, announced** (adopted); E-4 the mirror first (reads would silently lag — rejected) | Availability for deploys, nothing else moves |
| F | **CI leases from a mirror need a grant to the mirror's server key**: `maruhi server grant --key-from <mirror url>` reads the mirror's `/auth/config`, runs the same fingerprint ceremony, appends the grant **on the primary** and registers the wraps there; the next sync replicates both. A project may hold several valid grants (one per server key); CRYPTO_SPEC's uniqueness rule is against member keys only | F-1 grant on the mirror (the mirror refuses writes — rejected); F-2 one grant shared by two keys (a key is a recipient; two keys are two recipients — rejected) | The chain already keys grants by fingerprint; the spec text is clarified, not changed |
| G | **No audit row for a replication, and the mirror's own rows survive one**: the mirror's audit log is the source's replica followed by the rows the mirror itself appends while serving reads and leases (`var.read`, `server.*`); a commit re-appends those rows after the replica's (their `seq` moves, the wire row id does not — AUDIT_SPEC §7 C1), and the audit non-regression check compares the replica against the last replicated position, not the live log. Sync history lives in `mirror_state` and is read through `GET /projects/:id/mirror` (reader or above) | G-1 append `project.mirror_synced` on the mirror (erased by the next sync and a divergent audit head — rejected); G-2 record it on the primary (the primary does not learn of a sync — rejected); G-3 discard the mirror's own rows at each sync (the first draft — rejected during implementation: a read served by the mirror would leave no durable record, and a regression check against the live log would refuse every replica after the first read); G-4 **keep them, re-appended** (adopted) | The audit log has one source for the project's history; what the mirror itself did is kept, not erased |
| H | **Who runs the sync**: `maruhi mirror sync --mirror <url>` (a member with the primary's owner session for the export and the mirror's admin session for the upload; `MARUHI_TOKEN` for the primary and `MARUHI_MIRROR_TOKEN` for the mirror when run from a cron) and `maruhi mirror status --mirror <url>` (the two heads side by side) | H-1 a server-side timer (rejected — D-1 / D-2); H-2 **a command a cron can run** (adopted) | The team's cron is the timer, as for rotation |
| I | **No new crypto**: a mirror serves what the primary stored; its chain is verified by the mirror server **before the commit** (the staged chain in full, with the verifier the DO runs on load — a replica the mirror could not load never replaces the live one) and by every client on read | — | CLAUDE.md |

## 3. Competitor check

| Product | Read availability when the service is down | maruhi's position |
|---|---|---|
| Doppler / Infisical (cloud) | None without their own caching proxies; a self-hosted Infisical replica needs the server's encryption keys | A mirror is a second server that never sees a plaintext; no keys move |
| HashiCorp Vault | Performance replication (Enterprise) — server-to-server with its own credentials | Member-driven replication over the owner's export; no server credential crosses deployments |
| AWS Secrets Manager | Multi-region replication inside AWS | Same shape, in the team's own account, verified by clients |
| 1Password | Local cache in the app | The CLI keeps no cache (diskless); the mirror is the cache, server-side and verified |

No competitor gives an end-to-end-encrypted project a read replica that
the client verifies independently and that can be promoted to the primary
by its owner alone.

## 4. Exhaustion loop (self-review)

| Ruling | Later candidate | Verdict |
|---|---|---|
| B | B-4: allow the mirror to accept pushes and forward them to the primary later | Rejected: a chain append is serialized by the source of truth (CRYPTO_SPEC §6.4); a queued write is a second chain |
| D | D-5: incremental sync (only rows after a watermark) | Deferred: the export already pages; a project that fits the storage guard syncs in minutes; incremental sync needs per-table watermarks that the restore reader does not have. The page protocol does not preclude it |
| D | D-6: keep the mirror's own head attestations across a sync | Rejected: attestations are the primary's gossip; a mirror serving its own set would show members a different gossip view |
| E | E-5: a client-side cache of the last verified read as a third fallback | Rejected: the CLI is diskless by rule; a cache of ciphertext plus the floor is exactly what a mirror is |
| E | E-6: a list of mirrors in order | Deferred: one mirror covers the stated need; a list is an additive config change |
| G | G-3: discard the mirror's own audit rows at each sync (the first draft) | Rejected during implementation (ruling G): pulls and leases on the mirror append rows, so the live log is always ahead of the replica's; a regression check against it would block every sync, and dropping the rows would leave the mirror's reads unrecorded |
| F | F-3: the mirror's lease policy copied from the primary grant | Rejected: the grant is per key and the owner chooses the policy for each; a mirror used only as a fallback for `run` needs no lease policy at all |

## 5. Residuals (explicit)

- **Lag**: a mirror is as fresh as its last sync; a client that already
  verified a newer head refuses it (the floor). The fallback announces the
  mirror's head so the member can judge
- **Credentials on the mirror**: members must log in there once
  (`maruhi login --server <mirror>`); a CI job's OIDC policy must be granted
  on the mirror's key for leases to work there
- **Promotion is manual**, and the old primary, if it returns, is a stale
  server: its owner marks it as a mirror of the new primary or exports it
  away. The extension rule keeps it from being synced over the newer chain
- **Replay state**: the mirror keeps its own lease windows and bindings
  across syncs (ruling D); a token first used on the primary can be used on
  the mirror under another key within its validity — the same per-project
  residue CRYPTO_SPEC §9.1 already states for cross-project policies, now
  cross-deployment. The lease policy can name an audience per deployment
- **The bootstrap window**: audit rows the mirror appends between the
  import and the mark are kept — the mark starts the audit position at 0
  (ruling C revision, round 5), so the first replication re-appends every
  row the replica does not carry after the replica's rows (their seq
  moves, the wire row id does not)
- **The commit is one transaction** (the swap of every snapshot table plus
  the re-append): a project near the storage guard doubles its footprint
  transiently (staging + live) and commits in one DO transaction. The
  guard bounds the staging like any growth; a project that fits the guard
  commits in seconds. Incremental replication (D-5) is the follow-up if
  this ever binds
- **The device key on a fallback read**: the keychain stores the device key
  per server origin; a mirror read loads the server origin's key (the key
  is the person's). A member who never logged in to the server on that
  machine has no key for it there either, so nothing is lost
- **Spec text**: CRYPTO_SPEC §9.2 (mirrors) and AUTH_SPEC §11-7 (the mark,
  the refusal, the pages endpoint, the acceptance rules, the fallback)
  drafted in this session; see §7 for whether they landed

## 6. Implementation (PF2)

- `apps/server/src/do-schema.ts` — step 4: `mirror_state` (outside the
  snapshot set — `PROJECT_DO_LOCAL_TABLES`; the test reset wipes it and
  drops leftover `*_mirror` staging tables)
- `apps/server/src/do-mirror.ts` — the mark, the page stager (one
  transaction per page with the position update; the restore reader's
  checks reused — `parseLine` / `acceptHeader` / `acceptColumns` are now
  exported from do-snapshot.ts) and the commit (counts, chain extension,
  audit non-regression against the last replicated position, the swap that
  keeps `lease_windows` / `lease_bindings` / `attestation_windows`, the
  re-append of the mirror's own audit rows)
- `apps/server/src/programs-mirror.ts` (status / mark / unmark / page —
  the storage guard before the page; a commit discards the derived caches
  and extends the audit-head column to the end), `handlers-mirror.ts`, the
  DO RPCs and the `#runWrite` guard in `chain-do.ts` (`Forbidden`
  `mirror-read-only`), `DataStore.isMirrorSync` for the mint's refusal in
  `programs-proposal.ts` (`RotationProposalRejected` `mirror-read-only`)
- `packages/api-schema/src/mirror-api.ts` (`status`, `mark`, `unmark`,
  `pages`; the pages payload strict), `errors/mirror.ts`
  (`MirrorSyncRejected` 422, `MirrorState` 409), the `mirror-read-only`
  Forbidden and proposal reasons; data-plane kinds `mirror-read-only` /
  `mirror-state` / `mirror-sync-rejected`
- CLI: `maruhi mirror sync | status | mark | promote` (`mirror.ts`),
  `config set mirror`, `--mirror` on `run` / `pull` / `ci run` / `ci sync`
  with the fallback (`withMirrorFallback` in context.ts, the CI variant in
  effect-cli.ts; `CliError.unreachable` set by failure.ts for a transport
  failure or a gateway 502 / 503 / 504 / 52x), the mirror's own credential
  (`resolveSession(origin, "mirror")` — the keychain token of the mirror
  origin or `MARUHI_MIRROR_TOKEN`; the fallback read submits no head
  attestation), `maruhi server grant --key-from <url>` (`keySource` in
  server-grant.ts)
- Docs: SELF_HOSTING.md "Running a mirror", the site's self-hosting page,
  README, ROADMAP PF2; CRYPTO_SPEC §9.2 and AUTH_SPEC §11-7 (§7)
- Tests: `apps/server/test/mirror.test.ts` (the mark and the refusals, a
  forward replication with the kept windows and the re-appended rows, the
  refusal matrix, a lease served and the mint refused on a mirror, the
  promotion), `apps/cli/test/mirror.test.ts` (sync / status / mark /
  promote, the restart, MARUHI_MIRROR_TOKEN, the pull / run / ci run
  fallbacks and their non-fallback cases, `--key-from`), the policy /
  schema / strict pins

### 6-1. Independent review round (2026-10-02)

An independent agent reviewed the implementation after the first commit.
Findings and what changed:

| # | Finding | Fix |
|---|---|---|
| 1 (high) | The write guard ran before any membership check (the worker checks only the token's scope), so a non-member's write on a marked project answered 403 `mirror-read-only` instead of the uniform 404 — an existence and "is a mirror" oracle | `#runWrite` now runs `requireMemberState(caller, "reader")` → the mirror guard → the program; ruling B, AUTH_SPEC §11-7 and the DO comment say so; a test pins the stranger's 404 on a marked project |
| 2 (high) | The device key is stored per server origin; the fallback read opened the mirror origin and found no key — every real fallback died after announcing the retry (the tests seeded both origins) | The retry carries the server origin (`mirrorOf`); the key is loaded from it; the CLI tests keep the key under the server origin only |
| 3 (high) | A replica whose chain rows carried the live hashes but garbage `entry_json` committed; every later load was a defect and no API path recovered (an admin-only, unrecoverable brick) | The commit is split: the trailer page runs the synchronous checks and parks the trailer; the program parses and verifies the staged chain in full (`chain-invalid`) before the swap transaction |
| 4 (medium) | The `MARUHI_TOKEN` path folded a transport failure into "authentication failed", so a cron's `run` never fell back | The env-token path keeps the `unreachable` flag; a test runs `MARUHI_TOKEN` + `MARUHI_MIRROR_TOKEN` against a dead server |
| 5 (low) | A staged row the live schema refuses (a duplicate key, NULL) surfaced as a defect | The swap's SQL errors are `malformed`; `seq` must be an integer; tested |
| 6 (low) | The fallback `pull` still attempted writes on the mirror (wrap fills, the device registration), refused and folded into confusing warnings | Both are skipped on a mirror read; the `run` test asserts no non-GET request reaches the mirror |
| 7 (low) | `mirror status` needed the server (synced it first) — unusable exactly when the server is down | The server view is optional: a server that does not answer leaves the mirror's head alone on the report, announced |
| 8–10 (low) | Comments and spec that contradicted the code; test gaps (kept tables, a second replication, the byte bound, `--audience` on the CI retry); unused exports | All applied: the kept tables and the second replication are asserted, the byte bound and `chain-invalid` / `malformed` shapes are tested, the exports trimmed |

Verified as correct by the review (kept as is): no SQL identifier
injection (table names from the known set, column lists from the live
table), page and commit atomicity, the sequence protocol, the re-append
arithmetic and the derived audit-head column, the kept tables, the
mint's refusal after authorization, the session allowlist and strict
classification, no plaintext or key material in pages or reports.

## 7. Spec text status

Applied in this session: CRYPTO_SPEC §9.2 (mirrors — one grant per server key, the extension rule, no writes, the client's unchanged duties, promotion, the non-guarantees) and AUTH_SPEC §11-7 (the mark, the read-only guard and the mint's vocabulary, the pages endpoint and its acceptance rules, the authorization order, the client fallback and credentials, what a replication does not carry). AUDIT_SPEC is unchanged (no new event; the re-append keeps §7 C1's wire row id).

## 8. Exhaustion loop, round 2 and later (owner-directed, 2026-10-02)

After the review round the owner asked whether every ruling had been looped
until no candidate remained; the answer was no (one enumeration plus one
self-review, several rulings closed implicitly), and the owner directed
additional rounds over **every** ruling until each closes. Each round sends
independent adversarial agents over the rulings still taking candidates;
the designer judges under the delegation; adopted candidates are
implemented in the same change; a ruling is **CLOSED** at the round whose
agents found nothing strictly or structurally better.

### 8-1. Round 2 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| A (the mark) | nothing new | **CLOSED (round 2)** |
| B (read-only) | guard the project-delete API | **CLOSED (round 2)** — no such API exists; nothing to guard |
| C (bootstrap / promotion) | C-5: a split-brain guard on `promote` (probe the source; refuse while it answers unless `--force`); C-4: promote while the source's chain is ahead (needs the PF3 G-2 identity claim) | **C-5 adopted** — any HTTP answer counts as alive (even a 500: the server process is up), only no answer within 10 s as gone; the refusal names the two honest paths (mark the source as a mirror of the new primary, or take it down). C-4 deferred |
| D (replication) | D-7: merge the source's `lease_bindings` at commit (never replacing the mirror's); D-11: order chain_entries first; D-17: two syncers overlapping; D-18: a sync token below admin | **D-7 adopted** (`INSERT OR IGNORE` from the staging — a token bound on the source cannot bind to another key on the mirror); D-11 rejected (the premise is wrong: chain_entries is last by the restore invariant, which the mirror's staging relies on); D-17 deferred, recorded as a residual (two overlapping syncers refuse each other's pages as `sequence-mismatch`; the later one restarts); D-18 deferred (owner) |
| E (fallback) | E-7: a per-request bound on the client; E-14: read the mirror's mark before a fallback read (promoted → "set config server"; another source → refuse); E-15: a 500 is fallback-eligible; E-17: `config set mirror` warns when no session for the mirror is stored; E-16: fall back on a 401 | **E-7 adopted** (30 s per request, a timeout is a transport failure — a server that accepts the connection and never answers held a read forever and the fallback never fired); **E-14 adopted** (with the mirror's own credential, before the read; the CI lease path has no member credential and is documented as unchecked); **E-15 adopted** (a crashed handler is not an answer about the read); **E-17 adopted** as the mitigation of the structural problem (a login is not possible once the server is the reason the mirror is needed — the structural fix, one session for both deployments, needs the PF3 G-2 identity claim; deferred); E-16 rejected (a 401 is an answer about the credential) |
| F (CI leases) | F-6: say what to do with a compromised former primary's key | **Adopted** (the promotion message and the guide: revoke the key, rotate the environments it could open — the promotion itself retires nothing) |
| G (audit) | G-5: the audit seq in the status is admin-and-above only (AUDIT_SPEC §7 C1 — `seq` is never distributed below admin); G-6: report the re-appended own rows | **G-5 adopted** (`head.auditMaxSeq`, `head.attestationMark` and `lastSync` are shown to admins and owners; every member sees the mark, the source and the chain head — what the fallback check needs); **G-6 adopted** (`ownAuditRows` in the commit's answer and the sync report) |
| H (who syncs) | H-3: a no-change short-circuit (the source's status against the last replication); H-4: a replicate-only token permission; H-6: a server-side sync | **H-3 adopted** — the three marks (chain head, audit seq, attestation mark — the last is stored in `mirror_state` by schema step 6, since an attestation appends no audit row) compared against the source's `GET /projects/:id/mirror`; equal = nothing uploaded, so a cron costs one read. H-4 deferred (owner); H-6 rejected (rulings D-1 / D-2) |
| I (no crypto) | nothing new | **CLOSED (round 2)** |

Rulings C, D, E, F, G and H received adopted candidates in this round and
stay open for round 3.

### 8-2. Round 3 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-6: read the source's mark before the probe (a source already demoted as the refusal instructs still answered `/auth/config` and was refused again — the honest path needed `--force`); C-7: the planned failover ordered so no write is lost (freeze the source, one last sync, promote); C-8: `mirror mark` refuses a project whose head is not an entry of the source's chain (a bricked mirror reachable by a legitimate command sequence) | **C-6 adopted** (`frozen` / `writable` / `gone`; the probe decides only without a session or on any answer but the mark). **C-7 adopted as the documented order and the refusal's text** (the one-command flag is deferred — the three commands are the mechanism). **C-8 adopted** (`--force`; warn-and-mark when the source cannot be read). The probe's "alive" (any HTTP answer) being wider than the fallback's "down" is recorded in §11-7 as the safe side |
| D (replication) | D-19: expired bindings are filtered on the merge and purged at the commit (a fallback-only mirror never issues a lease, so nothing else collected the table) | **Adopted** |
| E (fallback) | E-18: the "promoted" refusal told the member to point `config set server` at the copy on the mirror's own say-so (a mirror operator answering `mirror: false` during an outage would steer writes to a copy under their control); E-19 (a gap in E-7): the request bound covered the headers only — a stalled body held a read forever | **E-18 adopted** (confirm with an owner). **E-19 adopted** — a second, wider bound on the whole answer (3 min; `transformResponse`), the same transport failure |
| F (keys) | F-7: the promotion names the concrete follow-ups from the verified chain — every other granted server key with the environments its grant covers, and whether this deployment's own key is granted | **Adopted**. **CLOSED (round 3)** |
| G (audit) | nothing new | **CLOSED (round 3)** — a residual recorded: a former primary re-marked as a mirror takes its live audit seq as the bootstrap, so the rows it appended after its last sync and before it went down count as replica rows and are replaced by the first replication ("export it away" covers it) |
| H (sync) | H-7: compare the source's mutation counter (PF3's, kept by the schema) instead of the attestation mark — it covers every write by construction, attestations included; H-8: also require the mirror to still hold the recorded head, and print the head in the "current" line | **H-7 adopted** — the export's head carries the counter, the trailer page records it (`sourceMutationSeq`, schema step 8), the status shows it to admins; the attestation mark stays recorded but is no longer compared. **H-8 adopted**. The comment that disagreed with the code (a source that does not answer fails the sync) is fixed |

Rulings C, D, E and H received adopted candidates in this round and stay
open for round 4; F and G are closed.

### 8-3. Round 4 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-9 (a bug in C-6): `sourceState` answered "frozen" for a source marked as a mirror of **any** deployment — a mirror of an older primary that had failed over elsewhere was promoted without a probe (two writable copies by honest commands); C-10 (structural): re-point a marked project at another source without the writable window of `promote --force` + `mark`; C-11: say at mark time when the project's audit seq is ahead of the source's (the first sync's bare `audit-regression` otherwise) | **C-9 adopted** — the source's `sourceOrigin` is compared with this deployment; a mirror of another deployment is "moved" and the refusal names the re-point (`--force` promotes anyway). **C-10 adopted** — a mark naming another source re-points in place (staging dropped, positions kept, the local mutation counter forgotten; the same source is still `already-mirror`); §11-7 revised. **C-11 adopted** — a warning from the two statuses (admin+; nothing to say below) |
| D (replication) | D-20: drop and re-create the mutation triggers around the commit's bulk copy (per-row trigger cost on large projects) | **Declined** — a cost optimization only (no behavior changes; DDL inside the commit transaction adds risk for no correctness gain). **CLOSED (round 4)** — the merge filter, the purge, the `INSERT OR IGNORE`, and the trailer counts were checked and hold |
| E (fallback) | nothing new (the body bound's synthetic request reaches only the failure's description; the fallback closure ends before the child runs; the mark read with the mirror's credential moves neither writes nor a stale read) | **CLOSED (round 4)** |
| H (sync) | H-9 (the implementation did not deliver H-3's claim): the verified view was built — a full chain download — before the no-change check, so a "current" tick was not "one status read"; H-10: the pages were uploaded under the 30 s header bound, which includes sending a 4 MiB body — below ~1.2 Mbit/s every full page was "did not answer" | **H-9 adopted** — the two sessions open first, the no-change check runs, and the chain is fetched and verified only on the replicating path (the test pins a "current" tick to the two status reads). **H-10 adopted** — the mirror's session of a sync takes the body bound (3 min) on its headers |

Rulings C and H received adopted candidates in this round and stay open
for round 5; D and E are closed.

### 8-4. Round 5 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-12 (structural): the audit position kept across a re-point is a seq compared across two different logs — a sibling mirror re-pointed at a promoted sibling whose log is shorter was refused `audit-regression` indefinitely, and when it finally committed the rows only it held were deleted by the swap; C-12b: the same for the fresh mark (bootstrap the position at 0 — removes the first-sync regression of a former primary and the round-3 G residual); C-11 was a bug (it compared the live audit seq, not the replicated position — a false warning on a re-point after reads); C-13 (structural): deployment identity was the origin string — a source marked under its workers.dev hostname and promoted under its custom domain was "moved", and the suggested re-point marked the deployment as a mirror of itself (every server check passes); C-14: the probe path refused a frozen source with "holds this project writable — mark it", an instruction that fails (`already-mirror`) when the owner simply has no session for the source on this machine | **C-12 and C-12b adopted** — the mark and the re-point start the audit position at 0; the first replica is accepted whatever its audit seq, and the row-id rule re-appends exactly the rows the new source does not carry (strictly more availability and strictly more history; the G residual disappears). **C-11 retired** (nothing left to warn about). **C-13 adopted** — the promotion's "frozen" and the mark's self-check compare deployments by server key fingerprint from the public `/auth/config` (the origin string when either publishes none); the sync's own self-check stays by string so a "current" tick remains two status reads. **C-14 adopted** — the probe path's refusal says the mark could not be read from this machine and names the login. Recorded, no candidate: two writable copies remain reachable by a transient outage (the §5 residual) and by sibling mirrors after a take-down — the chain carries no deployment origins (a CRYPTO_SPEC change, out of scope); the guide prefers the freeze over the take-down |
| H (sync) | H-11: the "current" path consulted no floor — a source rebuilt from a backup taken at the last synced head reported "current" while a pull on the same machine would have refused it; H-13: the verified view was built once — a restart after a mid-export chain write uploaded the new state without the floor check and reported "ahead of the verified view" falsely; H-12 (cost): the 3-min header bound on the whole mirror session made the sync's first status read wait 3 min on a mirror that never answers | **H-11 adopted** — a source whose reported head is behind the local floor's is never "current"; the replicating path decides with its evidence. **H-13 adopted** — the view is rebuilt before every restart. **H-12 adopted** — the pages go through a client of their own under the body bound; the mirror session keeps the 30 s bound |

Rulings C and H received adopted candidates in this round and stay open
for round 6; D and E are closed.

### 8-5. Round 6 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-15 (a fail-open in C-13): the promotion took "frozen" from a fingerprint match of the source's recorded origin with this deployment — the fingerprint is self-reported, and deployments cloned from one secrets set (one `SERVER_ENC_KEY_IKM`) share it, so a sibling mirror was promoted beside a promoted sibling without a probe; the mark's self-check named "the server itself" with no way out for shared-key siblings; the fallback's own check compares strings, so the guide's "recognized by its fingerprint" was false for the only path members hit. Record bug: §11-7 and §5 still said the bootstrap window's rows are replaced (with the position at 0 they are kept) | **C-15 adopted** — "frozen" is by origin string only (the name the freeze used); a fingerprint match only names the way out (promote under that name, or fix the shared key); the mark's refusal names the shared-IKM cause; the fingerprints are fetched concurrently and only on the refusing branch. **The record corrected** (the window is kept). The guide's bootstrap step asks for a distinct IKM per deployment |
| H (sync) | H-14 (an escape of H-11's rationale): a floor below the source's reported head could not be checked from the two statuses — a machine whose floor sits on another fork reported "current" while a pull there would refuse the server; H-15 (a silent misconfiguration): nothing checked that the server the sync exports from is the mirror's recorded source — a cron left at a former primary after a failover replicated the frozen copy into a mirror of another source (an equal-head replica commits) | **H-14 adopted** — with a floor below the source's head, "current" waits for the view (its floor check proves the floor's entry is on the source's chain); the steady state stays two reads. **H-15 adopted** — refused before any export, `--force` overrides |

Rulings C and H received adopted candidates in this round and stay open
for round 7; D and E are closed.

### 8-6. Round 7 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-16: the "frozen" path promoted without checking that the planned order's last sync happened — a frozen source holding chain entries the mirror lacks was promoted, and those entries became unreachable forever (the test pinned exactly that as a pass). Record bug: the guide's bootstrap step still said the CLI tells deployments apart by the key | **C-16 adopted** — the source's status already carries its head: a frozen source whose chain head is not the mirror's is refused with the sync to run (`--force` promotes without its last writes); the audit seq is not compared (a frozen source still appends read rows). **The guide corrected** |
| H (sync) | H-16 (a bug in H-14's delivery): the sync's view never advanced the local floor (only the gossip reconciliation does), so on any machine whose floor sat below the source's head the H-14 branch — a full chain download — was taken on every tick, forever; the H-9 cost claim held only for a machine with no floor | **Adopted** — the sync's view is `project verify`'s keyless prologue (floor check, invite anchor, head gossip), which advances the floor once every check passes; the view is taken once per machine, never in steady state, and a gossip contradiction now aborts the sync instead of replicating a contradicted view |

Rulings C and H received adopted candidates in this round and stay open
for round 8; D, E, F and G are closed.

### 8-7. Round 8 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-17 (a bug in C-8's delivery of C-7): the mark accepted only a project equal to or behind the source, so the planned failover's freeze (the primary ahead of the mirror — the normal case) was refused without `--force`, and on a machine whose floor sat at the primary's head the floored view of the mirror failed and the mark proceeded on the "could not be read" path instead; C-18 (structural): a frozen source behind the mirror (restored from an older backup, then frozen) was refused with a sync that cannot succeed (`chain-not-extension`), leaving only `--force`, which skips every guard; C-19 (informational, F-7 precedent): the promotion did not say what stays on the frozen source | **C-17 adopted** — both views are plain verified chains; a prefix in either direction passes (ahead: a note names the last sync to run), only a fork is refused. **C-18 adopted** — a frozen head behind the mirror's is checked against the mirror's own chain: an entry of it promotes, anything else is refused as a fork (no sync suggested). **C-19 adopted** — the promotion counts the source's audit rows past the mirror's last replication and names `project export` on the source. Record note (corrected again in round 9): a "current" tick is two status reads — the server's own mark and its marks are one answer — plus `/auth/me` per session on the token path |
| H (sync) | H-17 (structural): the star rule the spec states was enforced by nothing — a mirror marked with another mirror as its source synced once and was refused `audit-not-extension` forever after that source's next sync; H-18 (structural): a replica on another chain than the verified view was reported and exited 0, so a cron never noticed | **H-17 adopted** (with PF3's J-20 — one implementation): the server's own mark is read before any export; a server that is a mirror of another origin, or a frozen former primary that already synced back, is refused with the honest path, the planned failover's last sync passes, `--force` overrides. The page head's `mirrorOf` variant is subsumed (the status read is one request and names `lastSync` too). **H-18 adopted** — the two fork notes fail the sync after the commit; "behind" and "ahead" stay notes |

Rulings C and H received adopted candidates in this round and stay open
for round 9; D, E, F and G are closed.

### 8-8. Round 9 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-20 (structural): the mark read the source's chain but never its mark, so its success line or note named a sync that `mirror sync` refuses (a source that is a mirror of a third origin — the star, enforced one command too late) or that cannot run (a writable source behind this project — no page is taken by a writable deployment); C-21 (precision): the left-behind count subtracted positions of two logs on the C-18 branch and after a re-point, and said nothing with no replication recorded; C-22 (informational): `--force` skipped the source read, so a forced promotion named nothing of what it abandoned | **C-20 adopted** — the source's mark is read in the session the chain check opens; a mirror of a third origin is refused naming the primary to mark against, a writable source behind this project is refused saying which way round the mark goes; the note stays for a source frozen for this project. **C-21 adopted** — counted only when the frozen head is the mirror's and a replication is recorded (one log's positions; H-19 makes the record the current source's), else "cannot be counted from here". **C-22 adopted** — `--force` reads the source and warns with the refusal it overrides |
| H (sync) | H-19 (structural, a false refusal): the re-point kept `last_synced_at`, so a sibling re-pointed at this mirror carried a replication record from its old source and the round-8 "already synced back" refusal fired on the honest consolidation path; the branch's hazard does not reach the pair at all (the mirror's rows travel verbatim, its own rows are carried by row id — the renumbering hurts a third mirror only, which the first refusal covers); H-20 (evidence gap): "behind" was never a race (the view precedes the export — a shorter export is a rollback) and "ahead" hid a server that serves one chain and exports another; H-21 (text): the cost claim | **H-19 adopted** — the re-point clears the replication record on the server, and the client's second refusal is dropped (a server frozen for this mirror is a source whatever it replicated before). **H-20 adopted** — behind the view taken before the export fails as a rollback; past it the view is taken again (its floor check proves the extension) and the replica must be on it, else the server exported entries it no longer serves; off either chain is the fork exit. **H-21 adopted** (two status reads) |

Rulings C and H received adopted candidates in this round and stay open
for round 10; D, E, F and G are closed.

### 8-9. Round 10 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-23 (precision bug in C-18): a frozen source at the mirror's height on another chain fell through to "run `mirror sync` first", the dead-end C-18 removed for the behind case; C-24 (parity with C-22): the mark's `--force` skipped the guard and named nothing; C-25 (precision): one `Effect.all` under one catch discarded a chain already read when the mark's read failed, and said both could not be read; C-26 (precision bug in C-21): a frozen source that synced back from this mirror holds the mirror's log followed by its own rows, so the mirror's record over-counted by every own row the mirror carried into it; C-27 (text): the forced warning ended with "pass --force"; C-28 (informational): a mark equal to or behind a source frozen for it left two frozen copies silently | **All adopted** — the same height with another hash is the fork refusal (no chain fetch); `ensureMarkable` runs in warn mode under `--force`; the chain and the mark are read on their own and each check runs when its read succeeded; the source's own replication record counts when present; the escape clause is stripped on the forced path; the undo note names the promotion. Record precision: the round-9 note fires for a project ahead of the frozen source only |
| H (sync) | H-22 (text contradiction): the sync's report called a replica past the second view "a write landed on the server after this sync" one line before the verdict called it a rollback — and the clause was wrong for `mirror status` too (a write on the server lengthens the view, never the mirror's head); H-23 (reporting gap): when the view taken after the commit fails, the sync exited 1 with the prologue's generic message and never said that the mirror now holds a replica from a server that failed verification right after exporting it | **H-22 adopted** — the "ahead" note names the promotion, a rollback at the server or a recorded source that is not this server. **H-23 adopted** — the second view's failure names the committed head, the cause and the no-promotion advice |

Rulings C and H received adopted candidates in this round and stay open
for round 11; D, E, F and G are closed.

### 8-10. Round 11 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-29 (record/code gap, structural): the forced mark's warning kept the refusal's escape clause, and the regex that stripped it on the promotion could not be reused (origins carry dots); C-30 (delivery gap of C-25/C-28): the undo note was lost when the chain's read failed although it depends on the mark alone, and the ahead note presumed a frozen source when the mark's read failed; C-31 (dead-end, the C-13/C-15 parity): the star refusal's instruction was a self-mark when the third origin is this deployment under another hostname | **All adopted** — refusals carry `{ body, escape }` and the callers compose them (the regex is gone); the undo note stands on the mark alone, the ahead note hedges when the mark is unread; the star refusal fetches the two fingerprints only when refusing and names the mark under the freeze's name |
| H (sync) | H-24 (precision bug in H-23): every failure of the view taken after the commit was reported as "the server failed verification" — a server that stopped answering, or refused the session, condemned the replica and told the owner not to promote; H-25 (text): the sync's report listed `mirror status`'s "ahead" causes, impossible on the sync path; H-26 (text): the fourth "changed" failed with the export's own message naming `project export`; H-27 (asymmetry): `mirror status` exited 0 on fork evidence the sync fails on | **All adopted** — the second view's failure branches on the error's `unreachable` / `evidence` flags (kept on the mapped error; the chain floor violation now carries `evidence` like the value pull's); a sync-specific "ahead" note; a sync-specific exhaustion message; `mirror status` fails with evidence on a fork note |

Rulings C and H received adopted candidates in this round and stay open
for round 12; D, E, F and G are closed.

### 8-11. Round 12 — candidates and verdicts

| Ruling | Candidate | Verdict |
|---|---|---|
| C (promotion) | C-32 (the C-27/C-29 class): three promotion refusal bodies end in a remedy the forced promotion has just made impossible (a sync into a promoted copy, a login to read the mark), and the forced path printed it verbatim — while the real loss of a forced promotion past a frozen source behind, the chain entries it holds past the mirror, was named nowhere. Cost observation adopted alongside: the mark's two source reads ran in sequence (a source that does not answer cost two bounds) | **C-32 adopted** — a refusal carries an optional `forced` consequence the forced path prints instead of the body (the entries that become unreachable with the export that keeps them; two writable copies until the source is marked or taken down). The mark's reads run concurrently |
| H (sync) | H-28 (delivery gap of H-24): the record claimed evidence coverage for the floor and the gossip, but the gossip contradiction, the invite-anchor failure and the floor's same-coordinate conflict were plain errors, so the second view's failure told the owner to re-run on them; H-29 (text): the sync's "ahead" note named a forced replication from a non-recorded source as a cause, impossible on the sync path (the replica and the view are of the same server); H-30 (precision): the status's fork evidence named "do not promote the mirror" for a promoted copy that diverged (two writable copies) and for a mirror of another source (judged against the wrong server); H-31 (tests only): the second view's session-refused branch was unpinned | **All adopted** — the three failures carry the evidence flag (the rotate/push cleanup then fails on them instead of warning, by its own contract); the phantom cause is gone from the note and the spec; the status's failure is attributed to its state and prints the resolved server origin; the 401 re-read is pinned |

Rulings C and H received adopted candidates in this round and stay open
for round 13; D, E, F and G are closed.
