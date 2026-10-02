# PF3 — Project export / self-host migration (design record)

Date: 2026-10-02. Owner-delegated session (the owner asked for every open
point to be ruled after an exhaustion loop, for competitor parity, and
for no compatibility to be kept — zero users). ROADMAP item PF3 ("export /
self-host migration — the path carrying chains, values, and manifests with
their history from hosted to one's own deploy. Structurally portable;
only the transport is missing. Touches the acceptance surface, so it gets
its own design session"). The earlier framing is hosted-design.md §10
(three design questions: the transport, the non-portable server-key
wraps, the portability of the audit history).

## 1. The problem in one paragraph

A project is already portable by construction: its id is the genesis
hash, its membership is a self-verifying signed chain, its values are
ciphertexts whose AAD binds the project id, and its audit log lives in
the same Durable Object. What is missing is (a) a way for an owner to
take the whole project out of a deployment, (b) a way for the operator of
another deployment to put it in, and (c) **identity continuity**: the
chain names its actors by the source deployment's internal user ids
(ULIDs — AUTH_SPEC §2), and a destination that minted fresh ULIDs at
first login would never match them (AUTH_SPEC §11-1 accepts an append
only when the authenticated principal's id equals `entry.actor.user_id`).

## 2. Rulings (each after an exhaustion loop)

| # | Ruling | Candidates | Why |
|---|---|---|---|
| A | **The export is the evacuation format itself** (the gzip NDJSON of hosted-ops §2-D: header / table / row / trailer), produced by paging the DO's tables over the authenticated API | A-1 a new JSON "project bundle" (a second serialization of the same tables, a second restore path — rejected); A-2 **the evacuation format** (adopted — the restore path, its verification [row counts, schema version, chain-last promotion], and the drill procedure already exist and are tested); A-3 `cf` reading the DO from outside (no such path exists) | One format, one reader. An export file is a snapshot with a different origin; the operator verifies it the same way (the trailer) |
| B | **Transport = a paged JSON endpoint** `GET /projects/:id/export?cursor=` returning the NDJSON lines of one page plus an opaque cursor; the client concatenates and gzips | B-1 a streamed response holding the DO's permit for the whole download (a slow client would hold the project's write lock — rejected); B-2 the DO writes to R2 and the worker streams the object (needs R2 on the source, i.e. not on a plain self-host, and copies the project a second time — rejected as the only path; the hosted backup already exists for operators); B-3 **pages under the permit, one synchronous read per call** (adopted); B-4 an in-memory snapshot in one response (a Worker's memory is bounded; projects are not — rejected) | No permit across awaits; memory bounded by the page; the client controls the pace. Each page is read under the permit, so a page is internally consistent |
| C | **Consistency across pages = watermarks in the cursor**: the first page records the chain head, the audit seq, and the attestation mark; every later page re-reads them and refuses with 409 `ExportChanged` when any moved; the client restarts (bounded) | C-1 ignore changes (a chain with a newer head than its own audit log — rejected); C-2 a server-side export lock (a lock a client can hold against a project — rejected); C-3 **refuse-and-restart** (adopted) | The three marks cover every write that matters to verification (chain appends, data writes [every data write appends an audit row], attestations); rate-limit window rows can drift between pages, and that is harmless (they are counted as exported, so the restore's row-count check still passes) |
| D | **The cursor is stateless and unsigned**: base64url JSON of the table index, the last rowid, the per-table counts so far, and the watermarks | D-1 server-side export sessions (state to expire and a surface to fill — rejected); D-2 a signed cursor (what would a forged cursor buy? a wrong trailer on the forger's own export, which the restore's verification refuses — rejected as unneeded); D-3 **plain opaque** (adopted) | The owner is exporting their own data; the restore side verifies |
| E | **Who may export**: chain role **owner** × token scope **admin**; session principals are not allowed (no screen); readers / members / admins get 403; non-members the uniform 404 | E-1 admin or above (the export carries the class-2 audit rows and every DEK wrap of every member — the strongest read the project has; owner is the role that may also revoke the server key — rejected); E-2 **owner** (adopted) | The export is the whole project |
| F | **Audit**: `project.exported` (actor = the owner, class 2, payload = the chain head seq and hash at export) appended on the first page, **before** the watermarks are read, so the exported audit log records its own export; one window of 20 first-pages per project per hour under the lease-window mechanism (`kind = "exported"`) | F-1 no audit row (an owner copying every ciphertext and the whole audit log must leave a trace for the other members — rejected); F-2 **class 2** (adopted — like `var.read`, it is an access record) | An export is the largest read; the log says who took it and what state it had |
| G | **Identity continuity = pre-bound identities**: a second owner-only endpoint `GET /projects/:id/export/identities` lists the current members' provider identities (`provider`, `provider_user_id`, `provider_login`) keyed by their chain user id; the import creates `users` rows **with the source ids** and the matching `linked_identities` rows, so the first login of each member on the destination resolves to the id the chain already names | G-1 re-key the chain to new ids (a new chain = a new project id, and the value AADs bind the old one — rejected); G-2 a key-proof identity claim at first login (a member proves possession of the chain-bound signing key and the server binds the login to that id — the right successor for a provider-less future; needs an AUTH_SPEC addendum and a new acceptance surface — deferred, recorded as the follow-up); G-3 **pre-binding from the export** (adopted); G-4 the destination operator maps ids by hand (error-prone, and nothing checks it — rejected) | The chain is the source of truth of who is a member; the destination only needs its login lookup (`(provider, provider_user_id)` — AUTH_SPEC §2) to land on the chain's ids. No chain or value bytes change |
| H | **Import = the restore path** (operator-only, non-HTTP: the restore worker's job file gains `identitiesKey`; after the DO restore the worker provisions D1) | H-1 an HTTP import endpoint used by a logged-in owner (circular: the importer's destination id is not the chain's id until the import has run — rejected); H-2 an unauthenticated import endpoint gated by a deployment secret (a new operator-secret HTTP surface — rejected; hosted-ops §2-E already rules the operator path is R2 + a job); H-3 **the restore job** (adopted — "only an operator with write access to the bucket can place a job" holds for imports too) | No new acceptance surface on the HTTP API; the destination operator is the one who must consent to the import anyway |
| I | **D1 provisioning on import** (one atomic batch): for each identity a `users` row (source id), its `linked_identities` row, a personal org and owner membership (the same shape first login creates — AUTH_SPEC §9-1); the `projects` row under the exporter's personal org; one `project_members` projection row per member. Conflicts refuse the whole import: a provider identity already linked to a different destination id (`identity-conflict` — the person logged in before the import), a source id already taken by someone else (`user-id-taken`), the project row already present (`project-exists`), the exporter missing from the identities (`exporter-missing`) | I-1 provision users only (the first login would then create a personal org and the init-style project row lookups would fail — rejected); I-2 skip the org and attach the project to a job-named org (a second knob for nothing — rejected); I-3 **mirror first-login provisioning** (adopted) | After the import the destination looks as if every member had logged in once and the owner had created the project there |
| J | **What is not carried**, stated and documented: sessions and API tokens (log in again), the server-key grant and its wraps (the destination has a different server key — revoke the old fingerprint, grant the new one, and rotate the epochs the old server could open), recovery wraps and guardian shares (D1 — set up again), pending invitations and device-add requests, the advisory device registry (self-heals on the next login), ops state | J-1 carry the recovery ledger too (it is bound to the source deployment's wrap windows and keys — rejected for this change; a follow-up if demanded) | The DO is the project; D1 is the deployment |
| K | **No new crypto**: nothing is sealed, signed, or hashed by this change; the file is the DO's content | K-1 encrypt the export file to the owner's key (it is ciphertext already; a second layer would need a spec addition for no new property — rejected, same ruling as hosted-ops §2-D) | CLAUDE.md: no crypto outside CRYPTO_SPEC |

## 3. Competitor check

| Product | Export | Migration to self-host | maruhi's position |
|---|---|---|---|
| Doppler | `doppler secrets download` = plaintext | None (no self-host) | The export never contains a plaintext; the audit history travels |
| Infisical | Plaintext secret export; self-host migration = a database dump plus the server's encryption keys | Operator copies the DB and the keys | Same operator-driven shape, but no server key is ever needed: the members' device keys are the only keys |
| HashiCorp Vault | Raft snapshots (opaque, operator-only) | Snapshot restore | The same shape as the restore path; maruhi adds the owner-side export over the API so a tenant can leave without the operator |
| Bitwarden | Encrypted JSON export bound to the account key | Self-host import of the encrypted export only for the same account | The identity binding is explicit (pre-bound ids), not implicit in a key |
| 1Password | 1PUX plaintext | None | — |

No competitor lets a tenant take an end-to-end-encrypted project with its
signed history to their own server and keep every member's identity; it
is the shape that makes ADR-0003's FSL ("you can leave") a mechanism.

## 4. Exhaustion loop (self-review)

| Ruling | Later candidate | Verdict |
|---|---|---|
| B | B-5: the CLI could write the file in the evacuation format but the server could send rows as typed JSON (not pre-rendered lines) | Rejected: a second encoder on the client that must stay byte-compatible with the restore reader; the server already renders lines for the backup |
| C | C-4: include a per-table row-count check against live counts on every page | Rejected: the watermarks already imply unchanged counts for the tables that matter; `COUNT(*)` per page on large tables costs more than it tells |
| G | G-5: export every historical actor's identity, not only current members | Rejected: former members have no business logging in as their old id; their ids stay as chain history and nobody can claim them on the destination (a stranger's first login mints a fresh id) |
| H | H-4: let `maruhi project import` do the R2 uploads with Cloudflare credentials | Rejected: maruhi holds no Cloudflare credentials by design; `cf r2 objects put` is one command and the docs give it |
| I | I-4: provision the `devices` registry from the chain's device keys | Rejected: the registry is advisory and self-heals on login (AUTH_SPEC §13-11); provisioning it would be a second source of the chain's device set |
| J | J-2: port the server-key wraps by re-wrapping on the destination | Rejected: the destination server would have to open DEKs it must never see; the re-grant is a member operation by construction (CRYPTO_SPEC §6.3) |

## 5. Residuals (explicit)

- **Trust in the file at the destination**: the operator imports what they
  chose to import; the chain is verified by the destination server on
  first read and by every client, so a tampered file can only produce a
  project nobody can verify. A file from a hostile source could carry
  identities that pre-bind a provider id to a chain user id — the import
  confirms every listed id against the restored chain (a current member;
  the exporter an owner — review round), refuses any identity that
  collides with an existing destination account, and the operator sees
  the identities file in clear before placing the job. What remains is a
  source owner binding a wrong provider id to one of *their own* members'
  ids; the destination operator imports only from owners they trust
  (SELF_HOSTING says so). The structural successor is ruling G-2
- **A forged cursor** (review round): a cursor built by hand with the
  current marks at table 0 yields a header-less copy of the same state
  with no new `project.exported` row and no window use. The data is the
  one an audited export of that state already carries, so this is
  accepted rather than closed with server-side export sessions; it is
  recorded here instead of being called "unneeded" (ruling D)
- **Privacy of the identities file**: it names the members' provider
  ids and logins to the owner. They are the team's own identities, and
  the owner invited them; the file is not an append-only structure
  (CLAUDE.md's prohibition is about the chain and the audit log)
- **The floor on clients**: a client that verified a head newer than the
  export's head refuses the destination (CRYPTO_SPEC §6.3 rule (a)) — the
  right behaviour; export after the last write, before the switch
- **Exports as a disclosure channel**: an owner could always pull every
  value and read the audit log; the export changes the volume, not the
  class, and leaves the `project.exported` row
- **Spec text**: the AUTH_SPEC §11-6 section (the two owner endpoints, the
  acceptance order, the import's D1 rules) and the AUDIT_SPEC §3.3 row for
  `project.exported` were drafted in this session; see §7 for whether
  they landed
- **Follow-up (recorded)**: the key-proof identity claim (ruling G-2) as
  the provider-independent successor; porting the recovery ledger

## 6. Implementation (PF3)

- `apps/server/src/do-snapshot.ts` — `exportSnapshotPage` (the paged
  reader sharing the line encoders with `writeSnapshot`), `ExportCursor`
  encode / decode
- `apps/server/src/programs-export.ts` — the owner check, the window, the
  audit row, the page; the members-of-project read for the identities
- `apps/server/src/chain-do.ts` — RPCs `exportPage`, `exportMembers`
- `packages/api-schema/src/export-api.ts`, `errors/export.ts` — the group
  `export` (`page`, `identities`), `ExportChangedError` (409)
- `apps/server/src/handlers-export.ts` — the worker side (owner × admin
  scope; the identities join with D1 `linked_identities`)
- `apps/server/src/db.package/import.ts` — `provisionImportedProject`
  (the D1 batch of ruling I); `IdentityRepo.identitiesOf`
- `apps/server/src/restore-worker.ts` — `identitiesKey` on the job, the D1
  provisioning after a successful DO restore, the result's `identities`
- `apps/server/cloudflare.config.ts` — the restore mode's `DB` binding
- `apps/cli/src/project-export.ts` — `maruhi project export --out <file>`
  (pages, retries on `ExportChanged`, writes the gzip file and the
  `<file>.identities.json` sidecar, prints the trailer and the next steps,
  cross-checks the trailer's chain head against the verified view)
- Docs: `docs/SELF_HOSTING.md` "Migrating a project", the site's
  self-hosting page, README; ROADMAP PF3
- Tests: `apps/server/test/export.test.ts` (pages → a file the restore
  path accepts; owner-only; the 409 on a change; the identities), the
  restore worker's import (D1 rows, conflicts, the pre-bound login),
  `apps/cli/test/project-export.test.ts`

## 6-1. Review round (independent agent, 2026-10-02)

Applied in the same change: the page's byte bound is checked after every
row (a chunk of 500 ciphertext rows could pass the bound by tens of MiB);
the CLI removes the partial file on every failure, not only on a 409, and
removes the data file when the companion cannot be fetched; the import's
D1 lookups are chunked under the bound-parameter cap; the companion is
confirmed against the restored chain (member / owner) before the batch;
cursor positions are validated as integers; a same-height different-hash
trailer is reported as fork evidence; D1 failures are `db-error`, a
repeated id in the file `identities-malformed`; SELF_HOSTING names the
destination's preconditions (the `hosted` mode's bucket and D1, the
`restore` mode's matching D1 id), the shape of the retry result, and the
real recovery commands. Tests added for the multi-page export (row and
byte bounds, counts against the live tables), the audit row's position,
an admin's 403, an unlinked member, the import refusals, the audit row's
class, a data-only write between pages, and the CLI's failure cleanup.

## 7. Spec text status

Applied in the implementation change: AUTH_SPEC §11-6 (the two owner
endpoints, consistency, acceptance policy, audit, the import's D1 rules,
identity continuity, what is not carried) and the AUDIT_SPEC §3.3 row for
`project.exported` (class 2). CRYPTO_SPEC is untouched (ruling K).

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
| A (format) | A-4: a typed JSON bundle; A-5: a signed manifest over the file; A-7: a second serialization for mirrors | A-4 / A-7 rejected (ruling A's reason: one format, one reader). A-5 **deferred**: the restore's verification and the owner's verified head already refuse a wrong file; a signature would need a CRYPTO_SPEC addition for a property the chain carries |
| B (transport) | B-6: a resumable download of a server-side object | Deferred (B-2's reason — R2 on the source is not a given on a self-host; the pages are the transport) |
| C (consistency) | C-5: bound the exported audit log at the first page's seq instead of refusing when it moves; C-9: a deployment-local **mutation counter** as the mark for every write (so a read that appends an audit row does not restart the export); C-7: a server-side export lock | **C-9 + C-5 adopted** — a `mutation_state` row (step 5 of the DO schema; never exported, replicated or restored) bumped by every write entry point, the workload mint and a replica commit; the marks are the chain head, the attestation mark and the counter, and `auditMaxSeq` becomes the bound of the exported `audit_events` / `audit_head_hashes` rows (the trailer's head is the head at the bound, materialized on the first page). Before this, every pull by any member during an export restarted it. C-7 rejected again (ruling C-2's reason) |
| D (cursor) | D-5: bind the cursor to the export's own `project.exported` row (its seq travels; a continuation is served only to the owner the row names, while the row says what the cursor says) | **Adopted** — another owner continuing a cursor would take pages without a row of their own and outside their window; a cursor naming a row that is not an export's, or a different head, is `ExportChanged` |
| E (who) | E-7: an admin-scoped token below owner for automation; E-5: a one-time export token; E-3 / E-6: wider roles | E-7 / E-5 deferred (owner's call — the export is the whole project); E-3 / E-6 rejected (ruling E's reason) |
| F (audit) | F-3: `project.restored` on the destination; F-4: a row per page; F-5: record the page count | F-3 **deferred, recommended** (the destination's log begins with the import; a row that says so is the natural first entry — needs a restore-time audit append the import path does not have yet); F-4 rejected (one export, one row); F-5 recorded (the trailer carries the counts) |
| G (identity) | G-8: a key-proof claim at first login (G-2 again); G-11: carry the users' e-mail; G-7 / G-10: provider-independent ids now | G-8 deferred (the recorded follow-up); G-11 deferred low (e-mail is not identity here — AUTH_SPEC); G-7 / G-10 rejected (ruling G-1's reason) |
| H (import) | H-6: ask everything that can refuse **before the DO is touched** (verify the snapshot's chain, confirm the companion against it, classify D1 read-only), and make a `drill` job with a companion a rehearsal; H-9: a newer export over an imported project; H-10 / H-11: an HTTP import | **H-6 adopted** — `import-check.ts`: a refused import (`import-refused`, `snapshot-chain-invalid`) leaves the destination as it was; a drill reports `rehearsed` with the counts. **H-9 adopted as documentation**: the second restore is refused by construction (`not-empty`); the path is mark the imported project as a mirror of the source → sync → promote. H-10 / H-11 rejected (ruling H-1 / H-2's reasons) |
| I (D1) | I-5: a re-run on the exporter's own project row provisions only the missing members; I-11: provision the recovery ledger | **I-5 adopted** — a projects row under the exporting owner's personal org is kept and the members missing since are provisioned (`project: kept`); a row of anyone else's stays `project-exists`. I-11 deferred (ruling J's reason) |
| J (not carried) | J-9: after the switch, mark the **source** as a mirror of the destination so it turns read-only instead of drifting; J-5: carry pending invitations; J-3: carry the device registry; J-6: carry sessions | **J-9 adopted** (documentation and the export command's next steps); J-5 deferred; J-3 deferred low (self-heals); J-6 rejected (a session is a credential of the source) |
| K (no crypto) | K-3: an HMAC over the cursor; K-2: encrypt the file | K-3 deferred (ruling D-2's reason — the restore verifies); K-2 rejected (ruling K-1's reason) |

Rulings C, D, H, I and J received adopted candidates in this round and
stay open for round 3. Rulings A, B, E, F, G and K received only rejected
or deferred candidates — nothing strictly or structurally better — and are
**CLOSED (round 2)**.
