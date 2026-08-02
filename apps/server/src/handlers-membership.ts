// メンバーシップログ API のハンドラ(CRYPTO_SPEC §6.4 + AUTH_SPEC §11)。
//
// 認可の流れ(§11):
//   1. AuthMiddleware が主体を解決(匿名 401 / CSRF 403)
//   2. 追記系は actor 一致(§11-1)とトークンスコープ(§9-2 の min のスコープ半分)
//   3. メンバーシップ(チェーン導出)は DO 側で判定し、非メンバーは 404 に写す(§11-2)
//   4. op ごとのチェーン role 認可は verifyChain(§6.2)が真実源

import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  ForbiddenError,
  maruhiApi,
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { RequestAuth } from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { canonicalChainEntryBytes, computeChainEntryHash } from "@maruhi/crypto";
import { Effect } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  ensureActorMatches,
  ensureTokenScopeForInit,
  ensureTokenScopeForProject,
  requiredPermissionForOp,
} from "./authz.ts";
import type { AppendOutcome, InitOutcome, SnapshotOutcome } from "./chain-do.ts";
import { OrgRepo, ProjectRepo } from "./db.package/index.ts";
import { MAX_ENTRY_CANONICAL_BYTES } from "./policy.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

// RPC 境界の outcome → api-schema の型付きエラー / 成功レスポンスへの写像。
// "project-id-mismatch" は worker が自分で計算した ID を渡す限り起こらない
// (起きたら実装バグなので defect として落とす)

type PolicyRejection = Extract<
  AppendOutcome,
  { kind: "chain-invalid" | "entry-too-large" | "capacity-exceeded" }
>;

/** init / append に共通する受理拒否(検証失敗・サイズ / 累積上限)の写像。 */
function policyFailure(
  outcome: Extract<PolicyRejection, { kind: "chain-invalid" | "entry-too-large" }>,
): ChainEntryInvalidError | ChainEntryTooLargeError;
function policyFailure(
  outcome: PolicyRejection,
): ChainEntryInvalidError | ChainEntryTooLargeError | ChainCapacityExceededError;
function policyFailure(outcome: PolicyRejection) {
  switch (outcome.kind) {
    case "chain-invalid":
      return new ChainEntryInvalidError({ seq: outcome.seq, reason: outcome.reason });
    case "entry-too-large":
      return new ChainEntryTooLargeError({ limitBytes: outcome.limitBytes });
    case "capacity-exceeded":
      return new ChainCapacityExceededError({
        maxEntries: outcome.maxEntries,
        maxTotalBytes: outcome.maxTotalBytes,
      });
  }
}

/**
 * §11-3 の冪等修復: DO は初期化済みだが projects 行が欠けている場合、要求者が
 * genesis actor 本人であれば行を挿入して成功として返す。それ以外は 409。
 */
const repairOrConflict = (
  projectId: string,
  orgId: string,
  principalUserId: string,
  outcome: Extract<InitOutcome, { kind: "already-initialized" }>,
) =>
  Effect.gen(function* () {
    const projects = yield* ProjectRepo;
    const exists = yield* projects.exists(projectId);
    if (exists || outcome.genesisActorUserId !== principalUserId) {
      return yield* Effect.fail(new ProjectAlreadyInitializedError({ projectId }));
    }
    yield* projects.insertIfAbsent(projectId, orgId, Date.now());
    return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
  });

const mapInitOutcome = (
  projectId: string,
  orgId: string,
  principalUserId: string,
  outcome: InitOutcome,
) => {
  switch (outcome.kind) {
    case "initialized":
      return Effect.gen(function* () {
        const projects = yield* ProjectRepo;
        yield* projects.insertIfAbsent(projectId, orgId, Date.now());
        return { projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex };
      });
    case "already-initialized":
      return repairOrConflict(projectId, orgId, principalUserId, outcome);
    case "project-id-mismatch":
      return Effect.die(new Error("project id mismatch between worker and DO"));
    default:
      return Effect.fail(policyFailure(outcome));
  }
};

function appendRejection(projectId: string, outcome: Exclude<AppendOutcome, { kind: "appended" }>) {
  // §11-2: 未初期化と非メンバーを区別しない(存在秘匿)
  if (outcome.kind === "not-initialized" || outcome.kind === "not-member") {
    return new ProjectNotFoundError({ projectId });
  }
  if (outcome.kind === "head-conflict") {
    return new ChainHeadConflictError({
      currentHeadSeq: outcome.currentHeadSeq,
      currentHeadHashHex: outcome.currentHeadHashHex,
    });
  }
  return policyFailure(outcome);
}

const mapAppendOutcome = (projectId: string, outcome: AppendOutcome) =>
  outcome.kind === "appended"
    ? Effect.succeed({ projectId, headSeq: outcome.headSeq, headHashHex: outcome.headHashHex })
    : Effect.fail(appendRejection(projectId, outcome));

/**
 * DO へ渡す前の worker 側先行検査: サイズ超過エントリのハッシュ計算・DO 転送を
 * 避け、エンコーダの例外は 5xx でなく 422 に落とす(受理判定の権威は DO)。
 * 通過したら プロジェクト ID = genesis エントリハッシュ(§6.4)を返す。
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
    .handle("init", ({ payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // サイズの先行検査を最初に行う(巨大エントリはどの意味論的判定よりも先に
        // 413 で落とす — 資源保護は受理意味論に優先する)
        const projectId = yield* precheckAndComputeProjectId(payload.entry);
        // §11-1: init の genesis actor = 認証主体
        yield* ensureActorMatches(principal, payload.entry);
        yield* ensureTokenScopeForInit(principal, projectId);
        // §11-3: 作成権限 = 対象 org の member 以上(membership 行があればよい)
        const orgs = yield* OrgRepo;
        const orgRole = yield* orgs.roleOf(payload.orgId, principal.userId);
        if (orgRole === null) {
          return yield* Effect.fail(new ForbiddenError({ reason: "org-membership-required" }));
        }
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<InitOutcome>(() =>
          projectStub(env, projectId).init(projectId, payload.entry),
        );
        return yield* mapInitOutcome(projectId, payload.orgId, principal.userId, outcome);
      }),
    )
    .handle("get", ({ params }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        yield* ensureTokenScopeForProject(principal, params.projectId, "read");
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<SnapshotOutcome>(() =>
          projectStub(env, params.projectId).snapshotFor(principal.userId),
        );
        if (outcome.kind !== "snapshot") {
          // §11-2: 未初期化と非メンバーを区別しない(存在秘匿)
          return yield* Effect.fail(new ProjectNotFoundError({ projectId: params.projectId }));
        }
        return {
          projectId: params.projectId,
          entries: outcome.entries,
          headSeq: outcome.headSeq,
          headHashHex: outcome.headHashHex,
        };
      }),
    )
    .handle("append", ({ params, payload }) =>
      Effect.gen(function* () {
        const principal = yield* (yield* RequestAuth).principal;
        // §11-1: 追記エントリの actor = 認証主体(受理ポリシー)
        yield* ensureActorMatches(principal, payload.entry);
        yield* ensureTokenScopeForProject(
          principal,
          params.projectId,
          requiredPermissionForOp(payload.entry.op),
        );
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<AppendOutcome>(() =>
          projectStub(env, params.projectId).append(
            payload.parentHeadHashHex,
            payload.entry,
            principal.userId,
          ),
        );
        return yield* mapAppendOutcome(params.projectId, outcome);
      }),
    ),
);
