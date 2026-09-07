// `maruhi ci run -- <cmd>`: CI ジョブ内のワークロードリース実行
// (CRYPTO_SPEC §9.1 / AUTH_SPEC §14。設計判断は docs/notes/session-25.md)。
//
// リースの取得と検証は ci-lease.ts(`maruhi ci sync` と共有)。このモジュールは
// その材料を `run` と同一の経路へ渡すだけ: 復号値は Redacted のまま runOp
// (buildInjectionEnv → ProcessRunner)へ渡り、子プロセスの環境変数への
// メモリ注入のみで消費される(ディスクレス不変条件)。これは値の「表示」では
// なく「注入」なので agent-gate(値表示ゲート)の対象外である(run と同じ
// サンクションされた消費経路 — ADR-0016 決定 7)。要求サービス型
// (CliIo | ProcessRunner | HttpClient)が config・トークン・キーチェーンへの
// 依存の不在を示す。

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { type CiLeaseInput, leaseEnvironments } from "./ci-lease.ts";
import { logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { CliIo } from "./io.ts";
import { enforceDeclaredPresence, ProcessRunner, runOp, typeAdvisoryWarnings } from "./run.ts";

/** `maruhi ci run` の入力(すべて明示フラグ由来 — session-25 §2)。 */
export interface CiRunInput extends CiLeaseInput {
  readonly environmentId: EnvironmentId;
  readonly command: readonly string[];
}

/**
 * Runs one command with the environment's variables leased through OIDC
 * (CRYPTO_SPEC §9.1 / AUTH_SPEC §14), then injects the decrypted values
 * into the child process environment (memory only).
 */
export function ciRunOp(
  input: CiRunInput,
): Effect.Effect<number, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const materials = yield* leaseEnvironments({
      ...input,
      environmentIds: [input.environmentId],
    });
    const material = materials.get(input.environmentId);
    if (material === undefined) {
      return yield* Effect.fail(
        cliError("The lease returned no material (internal inconsistency)"),
      );
    }
    // presence fail-fast(設計文書 §1-4 — run と同一規則): リース応答に同梱
    // された検証材料(ステートメント + マニフェスト — §14-2)に対して判定する。
    // required = true の declared があれば子プロセスは起動しない
    yield* enforceDeclaredPresence(material.declared);
    // type は advisory(§14.3-7)— 不一致は警告のみで実行続行
    yield* logWarnings(typeAdvisoryWarnings(material.variables));
    return yield* runOp({ command: input.command, variables: material.variables });
  });
}
