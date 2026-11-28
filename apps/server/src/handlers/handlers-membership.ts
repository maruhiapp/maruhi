import {
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  CompositeRequiredError,
  ForbiddenError,
  maruhiApi,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
} from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, OrgId, ProjectId } from "@maruhi/core";
import { auditActorOf, cryptoPromise, decodeProjectId, RequestAuth } from "@maruhi/core";
import type { ChainEntry, ChainOperation, Role } from "@maruhi/crypto";
import { canonicalChainEntryBytes, computeChainEntryHash } from "@maruhi/crypto";
import { Clock, Effect } from "effect";
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
import type { DataOutcome } from "../data.package/index.ts";
import { callProjectData, noContent, unwrapDataOutcome } from "../data.package/index.ts";
import { InviteRepo, OrgRepo, ProjectRepo } from "../db.package/index.ts";
import {
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ENTRY_CANONICAL_BYTES,
  PROJECT_LIST_PAGE_SIZE,
} from "../policy.ts";
import type { AppendOutcome, InitOutcome, SnapshotOutcome } from "../programs/programs-chain.ts";
import { projectQuotaExceeded } from "../quotas.ts";
import { projectStub, rpcCall, WorkerEnv } from "../worker-env.ts";

const repairOrConflict = Effect.fn("handlers-membership.repairOrConflict")(function* (
  projectId: ProjectId,
  orgId: OrgId,
  principal: AuthenticatedPrincipal,
  outcome: Extract<InitOutcome, { kind: "already-initialized" }>,
) {
  const projects = yield* ProjectRepo;
  const exists = yield* projects.exists(projectId);
  if (exists || outcome.genesisActorUserId !== principal.userId) {
    return yield* Effect.fail(new ProjectAlreadyInitializedError({ projectId }));
  }
  yield* projects.insertIfAbsent(
    projectId,
    orgId,
    principal.userId,
    yield* Clock.currentTimeMillis,
    auditActorOf(principal),
  );
  return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
});

const mapInitOutcome = <Endpoint extends HttpApiEndpoint.Top>(
  endpoint: Endpoint,
  projectId: ProjectId,
  orgId: OrgId,
  principal: AuthenticatedPrincipal,
  outcome: InitOutcome,
) => {
  switch (outcome.kind) {
    case "initialized":
      return Effect.gen(function* () {
        const projects = yield* ProjectRepo;
        yield* projects.insertIfAbsent(
          projectId,
          orgId,
          principal.userId,
          yield* Clock.currentTimeMillis,
          auditActorOf(principal),
        );
        return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
      });
    case "already-initialized":
      return repairOrConflict(projectId, orgId, principal, outcome);
    case "fresh-not-admitted":
      return Effect.fail(new ProjectLimitError({ limit: MAX_ACTIVE_PROJECTS_PER_ORG }));
    case "project-id-mismatch":
      return Effect.die(new Error("project id mismatch between worker and DO"));
    case "rejected": {
      const rejected: DataOutcome<never> = { kind: "rejected", rejection: outcome.rejection };
      return unwrapDataOutcome<never, Endpoint>(rejected, projectId, endpoint);
    }
  }
};

const precheckAndComputeProjectId = Effect.fn("handlers-membership.precheckAndComputeProjectId")(
  function* (entry: ChainEntry) {
    const canonicalBytes = yield* Effect.try({
      try: () => canonicalChainEntryBytes(entry).length,
      catch: () => new ChainEntryInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
    });
    if (canonicalBytes > MAX_ENTRY_CANONICAL_BYTES) {
      return yield* Effect.fail(
        new ChainEntryTooLargeError({ limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
      );
    }
    return yield* cryptoPromise("computeChainEntryHash", () => computeChainEntryHash(entry)).pipe(
      Effect.mapError(
        () => new ChainEntryInvalidError({ seq: entry.seq, reason: "invalid-payload" }),
      ),
      Effect.map(decodeProjectId),
    );
  },
);

export const membershipLive = HttpApiBuilder.group(maruhiApi, "membership", (handlers) =>
  handlers
    .handle(
      "init",
      Effect.fn("handlers-membership.init")(function* ({ payload, endpoint }) {
        const principal = yield* (yield* RequestAuth).principal;
        const projectId = yield* precheckAndComputeProjectId(payload.entry);
        yield* ensureActorMatches(principal, payload.entry);
        yield* ensureTokenScopeForInit(principal, projectId);
        const orgs = yield* OrgRepo;
        const orgRole = yield* orgs.roleOf(payload.orgId, principal.userId);
        if (orgRole === null) {
          return yield* Effect.fail(new ForbiddenError({ reason: "org-membership-required" }));
        }
        const projects = yield* ProjectRepo;
        const admitFresh = !projectQuotaExceeded(yield* projects.countInOrg(payload.orgId));
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<InitOutcome>(() =>
          projectStub(env, projectId).init(projectId, payload.entry, { admitFresh }),
        ).pipe(Effect.orDie);
        return yield* mapInitOutcome(endpoint, projectId, payload.orgId, principal, outcome);
      }),
    )
    .handle(
      "list",
      Effect.fn("handlers-membership.list")(function* ({ query }) {
        const principal = yield* (yield* RequestAuth).principal;
        const scopeFilter = scopedProjectIdsFor(principal);
        if (scopeFilter !== null && scopeFilter.length === 0) {
          return { projects: [] };
        }
        const projects = yield* ProjectRepo;
        const candidates = yield* projects.listMemberProjectIds(
          principal.userId,
          query.after ?? null,
          PROJECT_LIST_PAGE_SIZE,
          scopeFilter,
        );
        const lastCandidate = candidates[candidates.length - 1];
        const nextAfter = candidates.length === PROJECT_LIST_PAGE_SIZE ? lastCandidate : undefined;
        const visible = candidates.filter((projectId) =>
          tokenScopeAllowsForProject(principal, projectId, "read"),
        );
        const env = yield* WorkerEnv;
        const rows = yield* Effect.forEach(
          visible,
          (projectId) =>
            Effect.gen(function* () {
              const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
                projectStub(env, projectId).memberRoleFor(principal.userId),
              ).pipe(
                Effect.catchTag("RpcCallError", (error) =>
                  Effect.as(
                    Effect.logWarning(
                      "project list: a membership confirmation failed; omitting that project from the page (its projection row is retained)",
                      error.errorName,
                    ),
                    null,
                  ),
                ),
              );
              if (outcome === null) {
                return null;
              }
              if (outcome.kind === "ok") {
                return { projectId, role: outcome.value };
              }
              const kind = outcome.rejection.kind;
              if (kind !== "not-member" && kind !== "not-initialized") {
                return yield* Effect.die(
                  new Error(`memberRoleFor returned an unexpected rejection: ${kind}`),
                );
              }
              yield* projects
                .deleteMember(projectId, principal.userId)
                .pipe(Effect.catchDefect(() => Effect.void));
              return null;
            }),
          { concurrency: 10 },
        );
        const memberships = rows.filter(
          (row): row is { readonly projectId: ProjectId; readonly role: Role } => row !== null,
        );
        return nextAfter === undefined
          ? { projects: memberships }
          : { projects: memberships, nextAfter };
      }),
    )
    .handle(
      "get",
      Effect.fn("handlers-membership.get")(function* ({ params, endpoint }) {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<SnapshotOutcome>(() =>
          projectStub(env, params.projectId).snapshotFor(principal.userId),
        ).pipe(Effect.orDie);
        const snapshot = yield* unwrapDataOutcome(outcome, params.projectId, endpoint);
        const projects = yield* ProjectRepo;
        yield* projects
          .upsertMember(params.projectId, principal.userId, yield* Clock.currentTimeMillis)
          .pipe(Effect.catchDefect(() => Effect.void));
        return {
          projectId: params.projectId,
          entries: snapshot.entries,
          headSeq: snapshot.headSeq,
          headHashHex: snapshot.headHashHex,
          attestations: snapshot.attestations,
        };
      }),
    )
    .handle("attest", ({ params, payload, endpoint }) =>
      callProjectData<void>()({
        endpoint,
        projectId: params.projectId,
        permission: "read",
        invoke: (stub, actor) => stub.putHeadAttestation(actor.userId, payload),
      }).pipe(Effect.as(noContent)),
    )
    .handle(
      "append",
      Effect.fn("handlers-membership.append")(function* ({ params, payload, endpoint }) {
        const principal = yield* (yield* RequestAuth).principal;
        if (
          payload.entry.op === "create_environment" ||
          payload.entry.op === "rotate_epoch" ||
          payload.entry.op === "delete_environment"
        ) {
          return yield* Effect.fail(new CompositeRequiredError({ op: payload.entry.op }));
        }
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
        ).pipe(Effect.orDie);
        const head = yield* unwrapDataOutcome(outcome, params.projectId, endpoint);
        const applied: ChainOperation = head.appliedProposal?.inner ?? payload.entry;
        if (applied.op === "add_member") {
          const target = applied.payload;
          const invites = yield* InviteRepo;
          yield* invites
            .completeAccepted({
              projectId: params.projectId,
              inviteeUserId: target.targetUserId,
              inviteeEncPubHex: target.encPubHex,
              inviteeSigPubHex: target.sigPubHex,
              role: target.role,
              scopeKind: target.scopeKind,
              scopeEnvironmentIds: target.scopeEnvironmentIds,
            })
            .pipe(Effect.catchDefect(() => Effect.void));
          const projects = yield* ProjectRepo;
          yield* projects
            .upsertMember(params.projectId, target.targetUserId, yield* Clock.currentTimeMillis)
            .pipe(Effect.catchDefect(() => Effect.void));
        }
        if (applied.op === "remove_member") {
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
