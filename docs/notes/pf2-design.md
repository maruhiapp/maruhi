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
  import and the mark count as replica rows (the mark takes the live
  positions as the bootstrap) and are replaced by the first replication.
  Marking right after the import keeps the window empty
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
