// `maruhi ci sync <target>`: CI ジョブからの同期(integration-options.md §3
// 補足 7 P3「デプロイ時再適用」/ 補足 16 G1「CI は http」)。
//
// 資格の経路は `ci run` と同じワークロードリース(ci-lease.ts — OIDC → DEK →
// 復号)で、maruhi トークン・キーチェーン・セッション・config ファイルに依存
// しない。読むのはリポジトリにコミットされた同期設定(`maruhi.sync.json` —
// アンカーファイルと同じ非機密の設定)だけ。
//
// **レシートは書かない**(型で示す — この経路は sync-receipt.ts を import せず、
// 署名鍵〔master 鍵〕を受け取らない): CI は CRYPTO_SPEC §4.1 の書き込み署名に
// 使う鍵を持たない。したがって CI の同期は「選択した変数の全件再適用」(冪等な
// upsert)であり、削除の情報源(レシート)が無いので**何も削除しない**。
// 削除は手元の `maruhi sync apply`(レシートあり)で行う — docs に明記。
//
// リースは環境単位なので、http ドライバのトークンが同期元と別の環境にあれば
// 2 環境をリースする(1 本の OIDC トークン・1 つの一時鍵で — ci-lease.ts)。
// grant のリースポリシーはその両方の環境を許していなければならない。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { type CiLeaseInput, leaseEnvironments } from "./ci-lease.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { VerifiedLeaseMaterial } from "./lease-client.ts";
import type { ProcessRunner } from "./run.ts";
import type { SyncTarget } from "./sync-config.ts";
import { DEFAULT_HTTP_RETRY, type HttpRetryPolicy, type IntegrationToken } from "./sync-http.ts";
import {
  computePlan,
  failDriver,
  integrationTokenOf,
  prepareWork,
  requireProductionConsent,
  reviewPlan,
  runDriver,
  sourceVariablesOf,
  writesOf,
} from "./sync-plan.ts";

/** `maruhi ci sync` の入力(フラグ + リポジトリ設定のターゲット)。 */
export interface CiSyncInput extends CiLeaseInput {
  readonly target: SyncTarget;
  /** production ターゲットへの apply の明示(手元の apply と同じ語)。 */
  readonly yes: boolean;
  readonly httpRetry?: HttpRetryPolicy;
}

/** リースした環境の材料を引く(無いのは実装の不整合)。 */
function materialOf(
  materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  environmentId: string,
): Effect.Effect<VerifiedLeaseMaterial, CliError> {
  const material = materials.get(environmentId as EnvironmentId);
  return material === undefined
    ? Effect.fail(cliError("The lease returned no material (internal inconsistency)"))
    : Effect.succeed(material);
}

/**
 * `maruhi ci sync <target>`: lease the target's source environment (and the
 * token environment for the http driver), then write every selected variable
 * to the target through its driver. No receipt is read or written: the CI
 * job holds no signing key, so it re-applies everything and deletes nothing.
 */
export function ciSyncOp(
  input: CiSyncInput,
): Effect.Effect<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { target } = input;
    const tokenEnvironment =
      target.driver.kind === "http" && target.driver.token.environment !== target.environment
        ? target.driver.token.environment
        : null;
    const materials = yield* leaseEnvironments({
      ...input,
      environmentIds: [
        target.environment as EnvironmentId,
        ...(tokenEnvironment === null ? [] : [tokenEnvironment as EnvironmentId]),
      ],
    });
    const source = yield* materialOf(materials, target.environment);
    const plan = yield* computePlan({
      target,
      source: sourceVariablesOf(source.variables),
      declared: source.declared,
      // レシート無し: 選択した全変数が add(全件再適用)、削除は生まれない
      receipt: null,
    });
    yield* reviewPlan(target, plan, { kind: "none-in-ci" });
    const work = yield* prepareWork(target, plan, writesOf(source.variables));
    if (work.writes.length === 0) {
      yield* io.log("Nothing to apply: the target selects no variable with a value");
      return;
    }
    yield* requireProductionConsent(target, input.yes, "maruhi ci sync");
    let token: IntegrationToken | null = null;
    if (target.driver.kind === "http") {
      const holder = yield* materialOf(materials, target.driver.token.environment);
      token = yield* integrationTokenOf(target.driver.token, holder.variables);
    }
    const result = yield* runDriver({
      target,
      work,
      token,
      httpRetry: input.httpRetry ?? DEFAULT_HTTP_RETRY,
    });
    if (result.failure !== null) {
      return yield* failDriver({
        target,
        work,
        result,
        receiptsEnvironment: null,
        next: "re-run the job (every selected variable is written again)",
      });
    }
    yield* io.log(
      `Applied to target ${displayText(target.name)}: ${countNoun(result.written.length, "variable")} written (no receipt is kept in CI, and nothing is deleted)`,
    );
  });
}
