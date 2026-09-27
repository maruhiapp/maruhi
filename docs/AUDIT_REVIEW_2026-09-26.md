# maruhi external audit review — cross-check ledger (2026-09-26)

- Subject: a parallel audit report by an external AI covering 9 areas (security /
  performance / accessibility / maintainability / scalability / architecture /
  documentation / testing / automation). Target revision = main
  `7365781`–`12e2b9a`. The report had 60 raw findings; excluding 5 duplicates, 55
  (High 6 / Medium 20 / Low 29)
- Method: every finding was checked one by one against the current code
  (`12e2b9a`) and judged "true / partially true / wrong". Of the true ones, those
  needing neither spec/ADR revision nor an owner decision were fixed in PR #203
- This file's role: **a ledger so unfixed findings are not forgotten**. When a
  finding is started or resolved, update the "Status" column (same operation as
  SECURITY_REVIEW_2026-08-14.md)

## Status legend

| Status | Meaning |
|---|---|
| **Fixed (PR #203)** | Fixed in this cross-check |
| **Needs spec revision** | True, but the current behavior is defined by a spec (CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC). Order: revision proposal → owner approval → implementation |
| **Needs human review** | True, but touches `packages/crypto` (CLAUDE.md: human review required) |
| **Owner decision** | True, but requires a decision on operational policy, public contract, dependency additions, etc. |
| **Deferred** | True, but the change's impact is large relative to the effect (fine to start if the judgment changes) |
| **Wrong** | The claim does not hold after cross-checking (reason noted) |

## Overall assessment

- As the report says, no problems were found with the E2EE boundary, agreement
  with the crypto spec, module boundaries, or CI permission design
- Of the 6 High findings, 2 (CLI fingerprint-ledger loss, the getting-started
  procedure) are fixed. The remaining 4 share **the same root** (a design that
  replays the entire membership chain on every pass), and all are governed by the
  current behavior defined in CRYPTO_SPEC §6.4 / AUTH_SPEC §11-5 / §14-2 — the
  right move is to handle them together as a spec revision
- While fixing, one problem the audit missed was found (note on P-3)

---

## Security

| ID | Severity | Status | Summary |
|---|---|---|---|
| S-1 | Low | **Fixed (PR #203 `195b8e0`)** | Snapshot restore embedded the backup's column names into SQL without verifying them → now requires an exact match, including order, against the live table's column names, and only the live table's column names are used in the SQL |
| S-2 | Low | Owner decision | IP rate limiting fails open when the binding is missing or an exception is thrown. SELF_HOSTING.md has already published the contract that "removing the ratelimits binding restores the old unlimited behavior", so going fail-closed is a contract change. Note the report's "the 300/hr per project is also lost" is wrong (the DO-side fixed window is unaffected; only the per-IP layer is lost) |

## Performance / Scalability

The performance and scalability findings share roots, so they are combined into
one table (the report's Sc1 = P-1, Sc2 = P-2, Sc4 = P-4, Sc5 ⊃ P-3).

| ID | Severity | Status | Summary |
|---|---|---|---|
| P-1 | High | Needs spec revision + needs human review | On every append and DO cold start, the whole chain is verified sequentially with Ed25519, and during that time the DO's single permit serializes all operations. Incremental verification is a revision of CRYPTO_SPEC §6.4 (full-chain re-verification on append). Memoizing CryptoKey within a pass needs no spec change but is a `packages/crypto` change. The full re-scan in `proposalIndexOf` has the same root |
| P-2 | High | Needs spec revision | `GET /projects` issues up to 100 DO RPCs of `memberRoleFor` per candidate, and a cold DO pays full verification. AUTH_SPEC §11-5 allows "≤ 100 DO checks", and `project_members` holding no role column is ruling BI; putting roles in D1 would violate §6.4's "two sources of truth are forbidden" |
| P-3 | Medium | Partially fixed (PR #203 `467db6d`) / the rest needs spec revision | Rotation-needed detection scans the entire audit history. **Fixed**: `variableReadsBy` was narrowed to the window's envelope (open interval). While fixing, it was discovered that the existing query had been reading **all users'** var.read via the `ae_event` index (an audit oversight) → pinned to a range scan of `ae_actor` with `+event`, and the query plan is pinned by a test. **Remaining**: `variableLifecycles` cannot be bounded below (creations before the window are still candidates); materializing flag state is a revision of AUDIT_SPEC §4.1 step 5 "resolved state is derived from the event column". **Report error**: `rotationFlagEvents` does not run on the write path (only GET flags and dismiss). The suggested "seq ≥ triggerSeq" is the wrong direction (§4.1's window **ends** at the trigger) |
| P-4 | Medium | Needs spec revision | Every CLI project command fetches and re-verifies the whole chain (sync.ts's "v1 has no local cache or delta verification" is intentional design). Delta sync requires adding an AUTH_SPEC §11 endpoint and revising CRYPTO_SPEC §6.3's client verification semantics |
| P-5 | Medium | Deferred | CLI value verification / decryption awaits serially per variable (up to 1,000 variables × 2 operations). Parallelizing needs no spec change. Fine to start as long as the current semantics of reporting the first failure in input order are preserved |
| P-6 | Medium | Deferred | The CLI eagerly imports all command modules at startup (~0.6 s on `--version`). Lazy import is a mid-size refactor because `COMMAND_SPECS` is needed for parsing |
| P-7 | Medium | **Fixed (PR #203 `f996b8e`)** | `deleteStaleMemberWraps` scanned all of `dek_wraps` → added a recipient index `dw_recipient` to the DO migration. **Caution**: the DO schema version goes up by 1, so an R2 snapshot taken before the deploy can only be restored by code of the same version (as assumed in hosted-ops.md §2-E) |
| P-8 | Low | Wrong | useMemo-izing the web `deriveReportedView`. The parent `OverviewTab` only re-renders when a new value arrives, and hidden tabs are unmounted, so recomputation on the same snapshot does not actually occur |
| Sc-3 | High | Needs spec revision | pull / lease / chain fetch assemble the entire set into one response (up to 1,000 variables × 64 KiB; lease also bundles the whole chain). Governed by AUTH_SPEC §14-2 (response = whole chain + all active variables) and §12-7. A "too large" typed error and its threshold are also a spec change |
| Sc-5 | High | Needs spec revision | Rotation-needed detection runs synchronously inside the commit task, and there is no cap on recommended output rows (one `rotation.recommended` line per candidate). An output cap / deferred emission is a revision of AUDIT_SPEC §4.1 step 4 (persisting recommendations as events). Narrowing the scan range was partially done under P-3 |
| Sc-6 | Medium | Needs spec revision | The storage guard's exception paths (audit rows for pull / lease, deletion tombstones, checkpoint) keep writing past the 9 GB rejection threshold, approaching the 10 GB SQLite limit. The exception paths are enumerated in AUTH_SPEC §12-8. **Report error**: "warnings should be wired to ops-alerts" is already implemented (`storage_warn_projects` / `storage_reject_projects`) — the stale comment was corrected in PR #203 `a7b6dfc` |
| Sc-7 | Medium | Needs spec revision | Lease issuance materializes a DO even for an unknown project ID (the same phenomenon as SECURITY_REVIEW_2026-08-14 A-4). A D1 existence check is a small change, but AUTH_SPEC §14-3's judgment order, the description of mitigations, and the handling of a false 404 in §11-3's partial state (DO initialized, D1 row not yet created) need consideration |
| Sc-8 | Low | Needs spec revision | The non-admin audit visibility predicate (an OR condition) can scan most of the table under `ORDER BY seq DESC LIMIT`. Adding a visibility column revises AUDIT_SPEC §5.1's schema, and a scan budget + continuation cursor revises §7's paging semantics |
| Sc-9 | Low | **Fixed (PR #203 `128184c`)** | A standalone checkpoint re-enumerated every covered environment's snapshot each time via DELETE + re-INSERT → the enumeration replacement is now skipped when the values digest is unchanged (the `environment_checkpoints` row is still always updated). **Report error**: the scale is at most ~100k rows, not ~1M (deleted environments are out of scope) |

## Accessibility

| ID | Severity | Status | Summary |
|---|---|---|---|
| A-1 | Medium | **Fixed (PR #203 `42dc6b9`)** | `document.title` was the fixed "maruhi" on every SPA screen |
| A-2 | Medium | Deferred | Focus does not move to the h1 after SPA navigation (the report's "stays on a detached node" is inaccurate; in fact the browser's default focus reset sends it to body). It must be focused after `navigation.transition.finished`, and distinguishing from first load is needed, so it is handled on its own |
| A-3 | Medium | **Fixed (PR #203 `df824de`)** | Load more unmounted the whole button while loading, dropping focus to body |
| A-4 | Medium | **Fixed (PR #203 `cfa1dfb`)** | Re-fetching after a revocation made the list vanish and lose focus, with no success notification |
| A-5 | Low | **Fixed (PR #203 `e68b75b`)** | The sign-in, loading, and failure screens had no main landmark |
| A-6 | Low | **Fixed (PR #203 `03b8b02`)** | Every row's Revoke button had the same spoken name |
| A-7 | Low | **Fixed (PR #203 `f10aeec`)** | The Variable names toggle had no `aria-expanded` / `aria-controls` |
| A-8 | Low | Deferred | On the LP's even steps the visual order and DOM order are reversed. Each step's body is self-contained, so the impact is minor. The report's "make all the figures aria-hidden" is unacceptable because it would hide step 3's entity list |
| A-9 | Low | **Fixed (PR #203 `d4c38fa`)** | The two terminal examples on the LP handled labels inconsistently |

## Maintainability

| ID | Severity | Status | Summary |
|---|---|---|---|
| M-1 | High | **Fixed (PR #203 `2085907`)** | `known-fingerprints.ts` folded non-ENOENT read failures (EACCES / EISDIR / EIO) into "none", so `record` overwrote the ledger with an empty one, losing verified fingerprints, and `lookup` silenced the change warning → only ENOENT is "none". With a regression test |
| M-2 | Medium | Needs human review | §6.2's voting/quorum logic is triple-implemented across crypto / CLI (`approval-rules.ts`) / web (`chain-view.ts`). Consolidating requires exporting it from `packages/crypto`. The alternative — "verify the 3 implementations on the same inputs with shared golden vectors" — is also a design decision (the same story as A-F1) |
| M-3 | Medium | Deferred | `isRecord` is duplicated in 11 files with 2 meanings (whether it accepts arrays), and `parseJsonRecord` is used in only 3 places. Unifying inside the CLI is possible, but the crypto and web copies cross package and review boundaries |
| M-4 | Medium | Deferred | `makeRootCommand` is a single ~1,500-line function (`effect-cli.ts` is 5,037 lines). A large behavior-free refactor with high collision risk against parallel work |
| M-5 | Medium | Deferred (partly wrong) | `data-http.ts`'s `toMetaStatementInput` declares the §12-2 statement shape three times in handwritten types. **Report error**: "a different statement silently gets verified" is wrong — a dropped field changes the signed statement, and client-side verification fails closed |
| M-6 | Low | Needs human review | crypto's byte-length constants (`DEK_BYTES` etc.) are redeclared in several files (`FINGERPRINT_BYTES` is in 3 files, not the report's 2) |
| M-7 | Low | **Fixed (PR #203 `dcdb9ca`)** (partly wrong) | Duplicated assembly of the manifest issuance material → consolidated into `manifestIssueBaseOf`. **Report error**: the duplication is not CLI↔server (the two ends of the wire) but inside the CLI, `push.ts` ↔ `apps/cli/src/schema.ts`. `apps/server/src/schema.ts` does not exist |
| M-8 | Low | Deferred | `repos.ts` (2,017 lines) hosts 9 repository factories |
| M-9 | Low | **Fixed (PR #203 `637dcae`)** | Duplicated short-write retry loop in `floor-log.ts` → consolidated into `appendAll` |

## Architecture

| ID | Severity | Status | Summary |
|---|---|---|---|
| F-1a | Medium | **Fixed (PR #203 `8e1e9a9`)** | The web `audit-read.ts` accepted non-integer epoch/version elements, disagreeing with core's `auditReadVariablesOf` (which drops them) → aligned to core and added a test comparing directly against core |
| F-1b | Medium | Owner decision | The web `chain-view.ts` (~910 lines) re-implements the chain fold by hand, with no mechanism checking it against the canonical fold. Checking requires adding `@maruhi/crypto` / `@maruhi/core` to the web devDependencies and preparing a signed fixture chain — this touches ADR-0018's scope (handle together with M-2) |
| F-2 | Low | **Fixed (PR #203 `5fdd73d`)** | There was no mechanical check stopping imports from RSC (the server graph) into dashboard helper modules |

## Documentation

| ID | Severity | Status | Summary |
|---|---|---|---|
| D-1 | High | **Fixed (PR #203 `2350f82` / `b2de09d`)** | getting-started step 5 could not be run as written (the required positional argument of `env create`, default project/env unset) → reordered so it runs, and added a check to `cli-vocabulary.test.ts` that docs' ```sh blocks carry USAGE's required positional arguments |
| D-2 | Low | **Fixed (PR #203 `2350f82` / `78a573c`)** | docs and web described the dashboard as "read-only" (it actually has a revocation mutation — ADR-0018 revision 2) |
| D-3 | Low | **Fixed (PR #203 `2350f82`)** | 2 comments pointing at the deleted `args.ts` |
| D-4 | Low | **Fixed (PR #203 `2350f82`)** | AUDIT_SPEC.md was missing from the spec list in README and the docs index |
| D-5 | Medium | **Fixed (PR #203 `2350f82`)** | CONTRIBUTING.md lacked structure, local-run, and test-scope descriptions (e2e is not included in the root `bun run test`) |
| D-6 | Low | Owner decision | No English HTTP API reference. A product decision on whether the HTTP API is a public surface or internal (ADR-0017's boundary) |
| D-7 | Low | Owner decision (partly wrong) | No integrated incident-response runbook for self-hosters. **Report error**: the client_secret rotation procedure already exists in SELF_HOSTING.md |

## Testing

| ID | Severity | Status | Summary |
|---|---|---|---|
| T-1 | Medium | **Fixed (PR #203 `83b6055` / `b06e044`)** | `maruhi token list / revoke` had no tests, and `device revoke --revoke-token` only exercised the 403 path |
| T-2 | Low | Deferred | The server tests use `isolate: false` with shared state and do not enforce order independence (the file count is 63, not the report's 56). `sequence.shuffle` (per file) could enforce it, but first confirm a shuffled run passes |
| T-3 | Low | Owner decision | No test drives the real CLI against a real server (harness design needed) |
| T-4 | Low | Owner decision | No coverage measurement (requires adding a `@vitest/coverage-*` dependency; the workerd pool needs istanbul) |

## Automation / CI

| ID | Severity | Status | Summary |
|---|---|---|---|
| C-1 | Medium | Owner decision | The DCO Signed-off-by is not enforced automatically (DCO App or a custom workflow) |
| C-2 | Medium | Owner decision | No deploy automation for hosted. The `deploy` script applies D1 migrations before deploying (a destructive migration can break a running worker), there is no staging, and there is no rollback procedure for worker code |
| C-3 | Medium | Owner decision | Release binaries have no build-provenance attestation (npm has provenance. install.sh already notes checksums are unsigned — SECURITY_REVIEW_2026-08-14 I-1) |
| C-4 | Low | **Fixed (PR #203 `a7b6dfc`)** | ci.yml had no concurrency → on PRs, stale runs are now cancelled; main pushes and release.yml's workflow_call are in separate per-run groups (the report's proposal had a flaw where a release dry-run and a main push would cancel each other — applied with that corrected) |
| C-5 | Low | Partially fixed (PR #203 `a7b6dfc`) / the rest is an owner decision | ops-backup.yml: added concurrency to prevent overlap. Post-upload verification of R2 and detecting "the latest backup is stale" are operational policy |
| C-6 | Low | Owner decision | pullfrog.yml has no `timeout-minutes` and passes 10 provider keys (only the owner knows which values and which providers they are for) |
| C-7 | Low | Owner decision | No Dependabot and no scheduled CI run (tension with the "updates happen as deliberate standalone PRs" policy) |
| C-8 | Low | Owner decision | No CODEOWNERS and no PR template, so "crypto changes require human review" is not mechanically enforced (needs assignee handles) |
| C-9 | Low | **Fixed (PR #203 `a7b6dfc`)** | The Playwright cache key depended only on the apps/web pin → if the apps/web and apps/site pins diverge, stop at the resolve step (the actual danger was that the install step only gets the web version, not the cache key) |
| C-10 | Low | Deferred | No caching of `bun install` (efficiency only) |

---

## Proposed work units for the unfixed findings

1. **Spec revision for chain economics** (P-1 / P-2 / P-4 / Sc-3 / Sc-5 / Sc-7 /
   Sc-8): the report's recommended order = ① incremental verification on append
   against a cached VerifiedChainView → ② materializing member→role → ③ delta
   sync (afterSeq) + cursor-paginated pull → ④ materializing bounded
   rotation-flag state on append. In every case: revision proposal for
   CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC → owner approval → test vectors first
2. **crypto cleanup** (P-1's CryptoKey memoization / M-2 / M-6 / F-1b): assumes
   human review. M-2 and F-1b can be handled together via "a golden vector that
   checks the 3 implementations on the same inputs"
3. **Operational policy** (S-2 / C-1–C-3 / C-5 remainder / C-6–C-8 / T-3 / T-4 /
   D-6 / D-7): small individual PRs after owner decisions
4. **Deferred items** (P-5 / P-6 / A-2 / A-8 / M-3–M-5 / M-8 / T-2 / C-10): no
   spec change needed. Fine to pick up as standalone PRs when time is free
