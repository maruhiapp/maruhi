// メンバーシップログ API のハンドラ(CRYPTO_SPEC §6.4 + AUTH_SPEC §11)。
//
// 認可の流れ(§11):
//   1. AuthMiddleware が主体を解決(匿名 401 / CSRF 403)
//   2. 追記系は actor 一致(§11-1)とトークンスコープ(§9-2 の min のスコープ半分)
//   3. メンバーシップ(チェーン導出)は DO 側で判定し、非メンバーは 404 に写す(§11-2)
//   4. op ごとのチェーン role 認可は verifyChain(§6.2)が真実源

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
import type { ChainEntry, Role } from "@maruhi/crypto";
import { canonicalChainEntryBytes, computeChainEntryHash } from "@maruhi/crypto";
import { Effect } from "effect";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import {
  ensureActorMatches,
  ensureTokenScopeForInit,
  ensureTokenScopeForProject,
  requiredPermissionForEntry,
  scopedProjectIdsFor,
  tokenScopeAllowsForProject,
} from "./authz.ts";
import type { AppendOutcome, InitOutcome, SnapshotOutcome } from "./chain-do.ts";
import { callProjectData, noContent, unwrapDataOutcome } from "./data-http.ts";
import type { DataOutcome } from "./data-plane.ts";
import { InviteRepo, OrgRepo, ProjectRepo } from "./db.package/index.ts";
import {
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ENTRY_CANONICAL_BYTES,
  PROJECT_LIST_PAGE_SIZE,
} from "./policy.ts";
import { projectQuotaExceeded } from "./quotas.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

// RPC 境界の outcome → api-schema の型付きエラー / 成功レスポンスへの写像。
// チェーン RPC の拒否は DataRejection(data-plane.ts)で届き、データプレーンと
// 同じ unwrapDataOutcome(data-http.ts)がエンドポイントの契約宣言から導出した
// 集合で選別・写像する(チェーン系エラーの写像を二重管理しない)。
// "project-id-mismatch" は worker が自分で計算した ID を渡す限り起こらない
// (起きたら実装バグなので defect として落とす)

/**
 * §11-3 の冪等修復: DO は初期化済みだが projects 行が欠けている場合、要求者が
 * genesis actor 本人であれば行を挿入して成功として返す。それ以外は 409。
 *
 * genesisActorUserId の照合は実際には到達しない深層防御である(actor 一致検査が
 * 先行し、projectId = genesis ハッシュのルーティングにより already-initialized が
 * 返るのは同一 genesis の再提出時のみ = actor は常に一致する)。
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
        // org.project_created(AUDIT_SPEC §3.2)と genesis actor の membership
        // 投影行(§11-5)は insertIfAbsent が同一 batch で記録
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
      // AUTH_SPEC §11-3: org のアクティブプロジェクト数上限。DO は何も書いて
      // いない(新規初期化を断っただけ)。修復経路は already-initialized 側で
      // 上限に依らず通っている
      return Effect.fail(new ProjectLimitError({ limit: MAX_ACTIVE_PROJECTS_PER_ORG }));
    case "project-id-mismatch":
      return Effect.die(new Error("project id mismatch between worker and DO"));
    case "rejected": {
      const rejected: DataOutcome<never> = { kind: "rejected", rejection: outcome.rejection };
      // 型引数は明示する: DataOutcome<never>(常に rejected)からの T 推論は
      // union 対 union で unknown に落ちるため
      return unwrapDataOutcome<never, Endpoint>(rejected, projectId, endpoint);
    }
  }
};

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
    .handle("init", ({ payload, endpoint }) =>
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
        // §11-3 プロジェクト数 / org 上限(H2): 判定は org 権限確認の後(org 外の
        // 主体に上限到達の有無を返さない)・DO init の前。判定材料は D1 の
        // 索引付き count(best-effort — DO 受理と原子化しない: 並行 init の僅かな
        // 超過は受容。§11-3 の比較と棄却案)。上限到達時も DO には admitFresh =
        // false で問い合わせる — DO が「初期化済みか」を自分の直列化の中で
        // 判定し、新規初期化だけを断る(fresh-not-admitted)ため、修復経路
        // (already-initialized → repairOrConflict)は上限に依らず通る
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
        // トークン主体のスコープ交差は**候補索引の段**で行う(スコープ外 =
        // 不出現 — 他所の「スコープ外 = 404」§11-2 と同じ情報量)。後段の
        // 絞り込みだけに置くと、候補ページ末尾から出る nextAfter にスコープ外の
        // project_id(ID = capability)が載って漏れる(Cursor Security Agent
        // 指摘 — PR #106)。セッション主体・`*` スコープは制限なし(§5 の許可
        // 列挙を通過済み — ensureTokenScopeForProject と同じ規律)
        const scopeFilter = scopedProjectIdsFor(principal);
        if (scopeFilter !== null && scopeFilter.length === 0) {
          return { projects: [] };
        }
        const projects = yield* ProjectRepo;
        // §11-5: D1 投影は候補索引にすぎない(認可に使わない)。ページは
        // 候補基準・project_id 昇順(DO 確認の絞り込みより前に確定する —
        // 確認後基準にすると ghost の尾部でカーソルが進まない)
        const candidates = yield* projects.listMemberProjectIds(
          principal.userId,
          query.after ?? null,
          PROJECT_LIST_PAGE_SIZE,
          scopeFilter,
        );
        const lastCandidate = candidates[candidates.length - 1];
        const nextAfter = candidates.length === PROJECT_LIST_PAGE_SIZE ? lastCandidate : undefined;
        // 深層防御: 候補は SQL 交差済みだが、応答行にも同じ述語を適用する
        // (交差の実装が食い違ってもスコープ外が応答に昇格しない)
        const visible = candidates.filter((projectId) =>
          tokenScopeAllowsForProject(principal, projectId, "read"),
        );
        const env = yield* WorkerEnv;
        // 読取時確認: 各候補の DO へ membership を確認し、通過した行だけを
        // 受理時点のチェーン導出 role とともに返す(応答の真実源はチェーン)。
        // 並行度は絞る(1 一覧がページ上限ぶんの DO を同時に実体化しない)
        const rows = yield* Effect.forEach(
          visible,
          (projectId) =>
            Effect.gen(function* () {
              // 確認 RPC の defect(DO 到達不能・保存チェーンの破損等)は候補
              // 単位で隔離する: 発見エンドポイントで 1 プロジェクトの障害が
              // 残り全部の列挙を 500 にしない(pullfrog 指摘 — PR #106)。
              // 当該行は応答から省くだけで**保持**する(ghost 削除は DO の
              // 明確な非メンバー回答のみ — 障害の回復後に再出現できる)。
              // 契約違反の検出線(下の想定外 rejection kind の die)はこの
              // 隔離の外側で従来どおり loud に保つ。隔離は無言では飲まない
              // (CLAUDE.md — worker-env.ts の fail-open 警告と同じ規律):
              // 破損チェーンの die は決定的で、この省略は恒久になりうる —
              // Workers ログへ静的メッセージ + エラー種別名だけ残す
              // (プロジェクト ID・ユーザー ID 等のリクエスト由来文字列は
              // 書かない)
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
                // memberRoleFor の拒否語彙は上の 2 種のみ(下限 reader = 全
                // メンバーが満たす)— それ以外は不変条件違反
                return yield* Effect.die(
                  new Error(`memberRoleFor returned an unexpected rejection: ${kind}`),
                );
              }
              // stale ghost 行(remove_member 後の削除失敗・§11-3 の部分状態):
              // 応答から除外し、行を削除してチェーン truth へ収束させる。削除の
              // D1 障害は握って前進(次回一覧が再収束する)
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
        // §11-2: 未初期化と非メンバーを区別しない(存在秘匿。畳み込みは
        // rejectionErrors — 契約宣言からの導出は unwrapDataOutcome)
        const snapshot = yield* unwrapDataOutcome(outcome, params.projectId, endpoint);
        // §11-5 (4): 取得成功 = DO がチェーン導出メンバーと確認済み — membership
        // 投影の lazy 挿入(add_member 時の D1 障害の自己修復 + 投影導入前
        // プロジェクトの無人バックフィル)。冪等な導出キャッシュ書き込みであり、
        // D1 障害を成功応答へ伝播させない(§15-2 の completed 突合と同じ規律。
        // 帰結は一覧の表示欠落のみで、次回取得が再修復する)
        const projects = yield* ProjectRepo;
        yield* projects
          .upsertMember(params.projectId, principal.userId, Date.now())
          .pipe(Effect.catchDefect(() => Effect.void));
        return {
          projectId: params.projectId,
          entries: snapshot.entries,
          headSeq: snapshot.headSeq,
          headHashHex: snapshot.headHashHex,
          // 現メンバーの最新ヘッド申告(AUTH_SPEC §16-1)。保存行の受理時刻は
          // ここに現れない(StoredHeadAttestation が最初から持たない — §16-1)
          attestations: snapshot.attestations,
        };
      }),
    )
    .handle("attest", ({ params, payload, endpoint }) =>
      // ヘッド申告の提出(AUTH_SPEC §16-1 — 2026-08-28 PR-M4)。トークン
      // スコープは read(申告は読み取り同期の付随 — reader 常在の認可モデルで
      // read トークンの同期クライアントがゴシップに参加できる水準)。attester =
      // 呼び出し主体は構造的(ワイヤに attester フィールドがなく、DO が署名
      // 対象の attester_user_id に呼び出し主体を用いる — §12-5 の規則)
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
        // AUTH_SPEC §6 / §12-4(2026-08-03): create_environment / rotate_epoch は
        // 複合エンドポイント(付随データとの原子受理)経由のみ。汎用追記での
        // 迂回は「エポックはあるがラップがない」中間状態を作るため型付きで拒否
        // (DO 側にも同じガードがあり composite-required 拒否として届く — 多層防御)。
        // standalone(周期)checkpoint は本エンドポイントが受理する(§16-2 —
        // 2026-08-28 PR-M2。DO 側の standaloneCheckpointProgram が内容突合 +
        // スナップショット原子保存を行う)
        if (payload.entry.op === "create_environment" || payload.entry.op === "rotate_epoch") {
          return yield* Effect.fail(new CompositeRequiredError({ op: payload.entry.op }));
        }
        // §11-1: 追記エントリの actor = 認証主体(受理ポリシー)
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
        // AUTH_SPEC §15-2: add_member 受理時、target = invitee の accepted 招待を
        // completed へ突合する(導出状態の更新であり真実源はチェーン。§15-4:
        // 証跡は chain.member_added — 独立の監査イベントは書かない)。DO 受理と
        // D1 更新は別トランザクションであり、この時点でチェーンは確定済み —
        // 突合の D1 障害を応答へ伝播させると「成功した追記が 500 に見え、同じ
        // 親ヘッドでの再試行が ChainHeadConflict になる」ため、ここに限り defect
        // を握って前進する(無言の握り潰しの禁止に対する明示例外: 失敗の帰結は
        // 「招待が accepted のまま一覧に残る」という可視・可修復な導出状態の
        // 欠落のみで、管理者が失効で掃除できる — 欠落側に倒す)
        if (payload.entry.op === "add_member") {
          const target = payload.entry.payload;
          const invites = yield* InviteRepo;
          yield* invites
            .completeAccepted({
              projectId: params.projectId,
              inviteeUserId: target.targetUserId,
              inviteeEncPubHex: target.encPubHex,
              inviteeSigPubHex: target.sigPubHex,
            })
            .pipe(Effect.catchDefect(() => Effect.void));
          // §11-5 (2): membership 投影への行挿入(発見用の候補索引 — 認可には
          // 使わない)。同じ defect 例外の論法: 失敗の帰結は一覧の表示欠落のみで、
          // 対象者の次回チェーン取得(lazy 挿入)が自己修復する
          const projects = yield* ProjectRepo;
          yield* projects
            .upsertMember(params.projectId, target.targetUserId, Date.now())
            .pipe(Effect.catchDefect(() => Effect.void));
        }
        if (payload.entry.op === "remove_member") {
          // §11-5 (3): 投影行の削除(候補集合の衛生)。一覧の正しさはこの削除の
          // 成否に依存しない — 読取時の DO 確認が stale 行を応答から排除 + 削除
          // する(session-42 裁定 BI-c)ため、ここも defect を握って前進する
          const projects = yield* ProjectRepo;
          yield* projects
            .deleteMember(params.projectId, payload.entry.payload.targetUserId)
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
