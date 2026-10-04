// Handlers for the membership-log API (CRYPTO_SPEC §6.4 + AUTH_SPEC §11).
//
// Authorization flow (§11):
//   1. AuthMiddleware resolves the principal (anonymous 401 / CSRF 403)
//   2. Append-style calls check actor match (§11-1) and token scope (the
//      scope half of the §9-2 min)
//   3. Membership (chain-derived) is judged on the DO side; non-members map
//      to 404 (§11-2)
//   4. Per-op chain-role authorization has verifyChain (§6.2) as its source
//      of truth

import {
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  CompositeRequiredError,
  ForbiddenError,
  maruhiApi,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
} from "@maruhi/api-schema";
import type { AuthenticatedPrincipal } from "@maruhi/core";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import type { ChainEntry, ChainOperation, Role } from "@maruhi/crypto";
import { canonicalChainEntryBytes, computeChainEntryHash } from "@maruhi/crypto";
import { Effect } from "effect";
import type { HttpApiEndpoint } from "effect/http-api";
import { HttpApiBuilder } from "effect/http-api";

import {
  ensureActorMatches,
  ensureTokenScopeForInit,
  ensureTokenScopeForProject,
  requiredPermissionForEntry,
  scopedProjectIdsFor,
  tokenScopeAllowsForProject,
} from "../authz.ts";
import { callProjectData, noContent, unwrapDataOutcome } from "../data/data-http.ts";
import type { DataOutcome } from "../data/data-plane.ts";
import { InviteRepo, OrgRepo, ProjectRepo } from "../db.package/index.ts";
import type { AppendOutcome, InitOutcome, SnapshotOutcome } from "../do/chain-do.ts";
import {
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ENTRY_CANONICAL_BYTES,
  PROJECT_LIST_PAGE_SIZE,
} from "../policy.ts";
import { projectQuotaExceeded } from "../quotas.ts";
import { projectStub, rpcCall, WorkerEnv } from "../worker-env.ts";

// Mapping of outcomes at the RPC boundary onto the api-schema typed errors /
// success responses. A chain-RPC rejection arrives as a DataRejection
// (data-plane.ts), and the same unwrapDataOutcome (data-http.ts) as the data
// plane picks and maps it against the set derived from the endpoint's
// contract declaration (no double-tracking of chain-error mappings).
// "project-id-mismatch" cannot happen as long as the worker passes the ID it
// computed itself (if it ever did it would be an implementation bug, so it is
// dropped as a defect)

/**
 * The §11-3 idempotent repair: when the DO is initialized but the projects
 * row is missing, insert the row and return success as long as the requester
 * is the genesis actor themselves. Anything else is 409.
 *
 * The genesisActorUserId check is defense in depth that is in practice
 * unreachable (the actor-match check runs first, and projectId = genesis
 * hash routing means already-initialized is returned only on a resubmission
 * of the same genesis = the actor always matches).
 */
const repairOrConflict = (
  projectId: string,
  orgId: string,
  principal: AuthenticatedPrincipal,
  outcome: Extract<InitOutcome, { kind: "already-initialized" }>,
) =>
  Effect.gen(function* () {
    const projects = yield* ProjectRepo;
    const exists = yield* projects.exists(projectId);
    if (exists || outcome.genesisActorUserId !== principal.userId) {
      return yield* Effect.fail(new ProjectAlreadyInitializedError({ projectId }));
    }
    yield* projects.insertIfAbsent(
      projectId,
      orgId,
      principal.userId,
      Date.now(),
      auditActorOf(principal),
    );
    return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
  });

const mapInitOutcome = <Endpoint extends HttpApiEndpoint.Top>(
  endpoint: Endpoint,
  projectId: string,
  orgId: string,
  principal: AuthenticatedPrincipal,
  outcome: InitOutcome,
) => {
  switch (outcome.kind) {
    case "initialized":
      return Effect.gen(function* () {
        const projects = yield* ProjectRepo;
        // org.project_created (AUDIT_SPEC §3.2) and the genesis actor's
        // membership projection row (§11-5) are recorded by insertIfAbsent
        // in the same batch
        yield* projects.insertIfAbsent(
          projectId,
          orgId,
          principal.userId,
          Date.now(),
          auditActorOf(principal),
        );
        return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
      });
    case "already-initialized":
      return repairOrConflict(projectId, orgId, principal, outcome);
    case "fresh-not-admitted":
      // AUTH_SPEC §11-3: the org's active-project count limit. The DO wrote
      // nothing (it only declined a fresh initialization). The repair path
      // passes on the already-initialized side regardless of the limit
      return Effect.fail(new ProjectLimitError({ limit: MAX_ACTIVE_PROJECTS_PER_ORG }));
    case "project-id-mismatch":
      return Effect.die(new Error("project id mismatch between worker and DO"));
    case "rejected": {
      const rejected: DataOutcome<never> = { kind: "rejected", rejection: outcome.rejection };
      // The type argument is spelled out: T inference from
      // DataOutcome<never> (always rejected) falls to unknown on
      // union-versus-union
      return unwrapDataOutcome<never, Endpoint>(rejected, projectId, endpoint);
    }
  }
};

/**
 * The worker-side pre-check before handing to the DO: skip hashing and the
 * DO transfer for oversized entries, and land encoder exceptions as 422, not
 * 5xx (the DO is the authority of the acceptance decision). On success,
 * return the project ID = genesis entry hash (§6.4).
 */
const precheckAndComputeProjectId = (entry: ChainEntry) =>
  Effect.gen(function* () {
    const canonicalBytes = yield* Effect.try({
      try: () => canonicalChainEntryBytes(entry).length,
      catch: () => new ChainEntryInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
    });
    if (canonicalBytes > MAX_ENTRY_CANONICAL_BYTES) {
      return yield* Effect.fail(
        new ChainEntryTooLargeError({ limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
      );
    }
    return yield* Effect.tryPromise({
      try: () => computeChainEntryHash(entry),
      catch: () => new ChainEntryInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
    });
  });

export const membershipLive = HttpApiBuilder.group(maruhiApi, "membership", (handlers) =>
  handlers
    .handle("init", ({ payload, endpoint }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // The size pre-check runs first (an oversized entry is dropped with
        // 413 before any semantic judgment — resource protection outranks
        // acceptance semantics)
        const projectId = yield* precheckAndComputeProjectId(payload.entry);
        // §11-1: init's genesis actor = the authenticated principal
        yield* ensureActorMatches(principal, payload.entry);
        yield* ensureTokenScopeForInit(principal, projectId);
        // §11-3: creation permission = member-or-above of the target org (a
        // membership row suffices)
        const orgs = yield* OrgRepo;
        const orgRole = yield* orgs.roleOf(payload.orgId, principal.userId);
        if (orgRole === null) {
          return yield* Effect.fail(new ForbiddenError({ reason: "org-membership-required" }));
        }
        // §11-3 project-count / org limit: the check runs after the org
        // permission check (do not leak whether the limit is reached to a
        // principal outside the org) and before the DO init. The decision
        // input is the indexed D1 count (best-effort — not atomic with DO
        // acceptance: a slight excess under concurrent inits is accepted;
        // the comparison-and-rejection option of §11-3). Even at the limit
        // the DO is asked with admitFresh = false — the DO judges
        // "already initialized?" inside its own serialization and declines
        // only fresh initialization (fresh-not-admitted), so the repair path
        // (already-initialized → repairOrConflict) passes regardless of the
        // limit
        const projects = yield* ProjectRepo;
        const admitFresh = !projectQuotaExceeded(yield* projects.countInOrg(payload.orgId));
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<InitOutcome>(() =>
          projectStub(env, projectId).init(projectId, payload.entry, { admitFresh }),
        );
        return yield* mapInitOutcome(endpoint, projectId, payload.orgId, principal, outcome);
      }),
    )
    .handle("list", ({ query }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // The token-principal scope intersection happens at the **candidate
        // index stage** (out-of-scope = absent — the same information content
        // as the "out-of-scope = 404" of §11-2 elsewhere). If it were only a
        // later-stage filter, the nextAfter computed from the candidate
        // page's tail could carry an out-of-scope project_id (ID =
        // capability) and leak it. A session principal or a `*` scope is
        // unrestricted (it already passed the §5 permission enumeration —
        // the same discipline as ensureTokenScopeForProject)
        const scopeFilter = scopedProjectIdsFor(principal);
        if (scopeFilter !== null && scopeFilter.length === 0) {
          return { projects: [] };
        }
        const projects = yield* ProjectRepo;
        // §11-5: the D1 projection is only a candidate index (not used for
        // authorization). Pages are candidate-order, ascending project_id
        // (fixed before the DO-confirmation filter — if ordered after
        // confirmation, the cursor would stall on a ghost tail)
        const candidates = yield* projects.listMemberProjectIds(
          principal.userId,
          query.after ?? null,
          PROJECT_LIST_PAGE_SIZE,
          scopeFilter,
        );
        const lastCandidate = candidates[candidates.length - 1];
        const nextAfter = candidates.length === PROJECT_LIST_PAGE_SIZE ? lastCandidate : undefined;
        // Defense in depth: the candidates are already SQL-intersected, but
        // apply the same predicate to the response rows too (even if the
        // intersection implementations disagree, an out-of-scope row never
        // gets promoted into the response)
        const visible = candidates.filter((projectId) =>
          tokenScopeAllowsForProject(principal, projectId, "read"),
        );
        const env = yield* WorkerEnv;
        // Read-time confirmation: confirm membership with each candidate's
        // DO and return only passing rows, together with the chain-derived
        // role at acceptance time (the chain is the response's source of
        // truth). Concurrency is capped (one listing must not instantiate a
        // page-limit's worth of DOs at once)
        const rows = yield* Effect.forEach(
          visible,
          (projectId) =>
            Effect.gen(function* () {
              // A defect of the confirmation RPC (DO unreachable, stored
              // chain corrupted, etc.) is isolated per candidate: on the
              // discovery endpoint, one project's failure must not turn the
              // rest of the enumeration into a 500.
              // The row is only omitted from the response — it is **kept**
              // (a ghost is deleted only on the DO's explicit non-member
              // answer — it can reappear once the fault recovers).
              // The contract-violation detection line (the die on an
              // unexpected rejection kind below) stays loud outside this
              // isolation, as before. The isolation does not swallow
              // silently (CLAUDE.md — the same discipline as the fail-open
              // warning in worker-env.ts): a corrupt chain's die is
              // deterministic and this omission could be permanent —
              // leave only a static message + the error class name in the
              // Workers log (no request-derived strings such as the project
              // ID or the user ID)
              const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
                projectStub(env, projectId).memberRoleFor(principal.userId),
              ).pipe(
                Effect.catchDefect((defect) => {
                  console.warn(
                    "project list: a membership confirmation failed; omitting that project from the page (its projection row is retained)",
                    defect instanceof Error ? defect.name : "unknown",
                  );
                  return Effect.succeed(null);
                }),
              );
              if (outcome === null) {
                return null;
              }
              if (outcome.kind === "ok") {
                return { projectId, role: outcome.value };
              }
              const kind = outcome.rejection.kind;
              if (kind !== "not-member" && kind !== "not-initialized") {
                // memberRoleFor's rejection vocabulary is just the 2 kinds
                // above (the reader floor is met by every member) —
                // anything else is an invariant violation
                return yield* Effect.die(
                  new Error(`memberRoleFor returned an unexpected rejection: ${kind}`),
                );
              }
              // A stale ghost row (a failed delete after remove_member, a
              // §11-3 partial state): exclude it from the response and
              // delete the row to converge onto the chain truth. A D1 fault
              // on the delete is swallowed-and-forward (the next listing
              // converges again)
              yield* projects
                .deleteMember(projectId, principal.userId)
                .pipe(Effect.catchDefect(() => Effect.void));
              return null;
            }),
          { concurrency: 10 },
        );
        const memberships = rows.filter(
          (row): row is { readonly projectId: string; readonly role: Role } => row !== null,
        );
        return nextAfter === undefined
          ? { projects: memberships }
          : { projects: memberships, nextAfter };
      }),
    )
    .handle("get", ({ params, endpoint }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<SnapshotOutcome>(() =>
          projectStub(env, params.projectId).snapshotFor(principal.userId),
        );
        // §11-2: do not distinguish uninitialized from non-member
        // (existence concealment. The folding is rejectionErrors —
        // derivation from the contract declaration is unwrapDataOutcome)
        const snapshot = yield* unwrapDataOutcome(outcome, params.projectId, endpoint);
        // §11-5 (4): a successful get = the DO confirmed a chain-derived
        // member — lazy insert into the membership projection (self-repair
        // of a D1 fault at add_member time + unattended backfill of
        // pre-projection projects). An idempotent derived-cache write; a D1
        // fault is not propagated into the success response (the same
        // discipline as the §15-2 completed cross-check. The consequence is
        // only a listing omission, which the next get repairs)
        const projects = yield* ProjectRepo;
        yield* projects
          .upsertMember(params.projectId, principal.userId, Date.now())
          .pipe(Effect.catchDefect(() => Effect.void));
        return {
          projectId: params.projectId,
          entries: snapshot.entries,
          headSeq: snapshot.headSeq,
          headHashHex: snapshot.headHashHex,
          // Current members' latest head attestations (AUTH_SPEC §16-1).
          // The stored row's acceptance time does not appear here
          // (StoredHeadAttestation never had it — §16-1)
          attestations: snapshot.attestations,
        };
      }),
    )
    .handle("attest", ({ params, payload, endpoint }) =>
      // Submission of a head attestation (AUTH_SPEC §16-1). The token scope
      // is read (an attestation accompanies read sync — at the level where a
      // sync client holding a read token can join the gossip in the
      // reader-always-present authorization model). attester = the calling
      // principal is structural (the wire has no attester field; the DO uses
      // the calling principal as the attester_user_id being signed — the
      // §12-5 rule)
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.putHeadAttestation(actor.userId, payload),
      }).pipe(Effect.as(noContent)),
    )
    .handle("append", ({ params, payload, endpoint }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // AUTH_SPEC §6 / §12-4: create_environment / rotate_epoch go only
        // through the composite endpoint (atomic acceptance together with
        // their collateral data). Bypassing via the generic append would
        // create the intermediate state "an epoch exists but no wraps", so
        // it is refused with a typed error (the DO side has the same guard,
        // arriving as a composite-required rejection — defense in layers).
        // A standalone (periodic) checkpoint is accepted by this endpoint
        // (§16-2 — the DO-side standaloneCheckpointProgram does content
        // cross-check + atomic snapshot saving)
        if (payload.entry.op === "create_environment" || payload.entry.op === "rotate_epoch") {
          return yield* Effect.fail(new CompositeRequiredError({ op: payload.entry.op }));
        }
        // The four-eyes 4 ops (CRYPTO_SPEC §6.2 PF1) have been accepted via
        // the generic append since K5 (AUTH_SPEC §11-1). The device-key 2 ops
        // (2026-09-19 DK) are accepted since K3 — the acceptance side effects
        // (mirror, revocation rotation-needed detection, attestation-row
        // deletion) run inside the DO's acceptance task, and the device-count
        // acceptance policy (§12-8) is returned by the DO's appendProgram as
        // DeviceLimit. The four-eyes acceptance policy (pending bound,
        // expires_at_ms upper bound — §12-8) and the growth guard are also
        // judged by the DO (appendProgram) and arrive as ProposalLimit /
        // DataLimitExceeded
        // §11-1: an appended entry's actor = the authenticated principal
        // (acceptance policy)
        yield* ensureActorMatches(principal, payload.entry);
        yield* ensureTokenScopeForProject(
          principal,
          params.projectId,
          requiredPermissionForEntry(payload.entry),
        );
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<AppendOutcome>(() =>
          projectStub(env, params.projectId).append(
            payload.parentHeadHashHex,
            payload.entry,
            principal.userId,
          ),
        );
        const head = yield* unwrapDataOutcome(outcome, params.projectId, endpoint);
        // The accepted effect = the directly appended op, or the inner op a
        // completed approve applied (four-eyes — CRYPTO_SPEC §6.4 "identical
        // to accepting the inner op directly". The DO returns it as
        // appliedProposal — design record es-design.md §11 K5-H). An
        // incomplete approve / propose / withdraw / set_approval_policy has
        // no D1 post-processing
        const applied: ChainOperation = head.appliedProposal?.inner ?? payload.entry;
        // AUTH_SPEC §15-2: when an add_member is accepted, cross-check the
        // accepted invite whose target = invitee into completed (it updates
        // a derived state; the chain is the source of truth. §15-4: the
        // evidence is chain.member_added — no separate audit event is
        // written). The DO acceptance and the D1 update are separate
        // transactions and the chain is already final at this point — if a
        // D1 fault of the cross-check propagated into the response, "the
        // successful append would look like a 500 and a retry with the same
        // parent head would become a ChainHeadConflict", so here — and only
        // here — the defect is swallowed and we move on (an explicit
        // exception to the ban on silently swallowing: the failure's
        // consequence is only a missing derived state — "the invite stays
        // listed as accepted" — which is visible, repairable, and an admin
        // can clean it up with a revocation — fail toward the omission side)
        if (applied.op === "add_member") {
          const target = applied.payload;
          const invites = yield* InviteRepo;
          yield* invites
            .completeAccepted({
              projectId: params.projectId,
              inviteeUserId: target.targetUserId,
              inviteeEncPubHex: target.encPubHex,
              inviteeSigPubHex: target.sigPubHex,
            })
            .pipe(Effect.catchDefect(() => Effect.void));
          // §11-5 (2): insert a row into the membership projection (a
          // candidate index for discovery — not used for authorization).
          // The same defect-exception reasoning: the failure's consequence
          // is only a listing omission, which the subject's next chain fetch
          // (lazy insert) self-repairs
          const projects = yield* ProjectRepo;
          yield* projects
            .upsertMember(params.projectId, target.targetUserId, Date.now())
            .pipe(Effect.catchDefect(() => Effect.void));
        }
        if (applied.op === "remove_member") {
          // §11-5 (3): delete the projection row (candidate-set hygiene).
          // The listing's correctness does not depend on this delete
          // succeeding — the read-time DO confirmation excludes + deletes a
          // stale row from the response (session-42 ruling BI-c), so this
          // defect is also swallowed-and-forward
          const projects = yield* ProjectRepo;
          yield* projects
            .deleteMember(params.projectId, applied.payload.targetUserId)
            .pipe(Effect.catchDefect(() => Effect.void));
        }
        return {
          projectId: params.projectId,
          headSeq: head.headSeq,
          headHashHex: head.headHashHex,
        };
      }),
    ),
);
