// 値の表示可否の判定(ADR-0016 決定 7 — 一次境界を TTY に置く fail-closed の 2 層)。
//
// **旧実装の弱点**: `gunshi/agent` は「既知のエージェントの環境変数リスト」に
// 一致したら拒否する **deny-list** だった。境界の定義が上流のリストに依存し、
// リストに載っていない新しいエージェント・自作ハーネス・CI・ログ収集経路は
// **素通りする**(fail-open)。環境変数の標準化は未確定
// (`AGENT` と `AI_AGENT` が併存、各社独自変数が乱立)なので、
// 「リストが常に正しい」という前提そのものが持たない。
//
// **再設計**: 値を見てよいのは**人間が対話端末で実行したとき**だけ、という
// 要件そのものを判定にする(allow-list = fail-closed):
//
//   1. 一次境界: stdin と stdout の両方が TTY か(`Stdio` サービス)。
//      エージェント・CI・パイプ・リダイレクトはすべて既定で拒否になる。
//      未知のエージェントも同じ理由で拒否される(知らなくても止まる)
//   2. 二次層: 既知エージェントの環境変数(名前が分かると診断が親切になり、
//      PTY を割り当てて実行するエージェントも捕まえられる)
//
// 判定材料はどちらも Effect のサービス経由で差し替えられる(`process.stdout` を
// 直に読まない)。実体の検出は live.ts が std-env で行い、テストは
// `Stdio.layerTest` と {@link AgentProfileRef} の差し替えで両方を偽装する。
//
// 拒否メッセージで `maruhi run -- <cmd>` を勧めない: run は「値を使う」ための
// 注入経路であって「値を見る」ための経路ではなく、`run -- printenv` のような
// 使い方は結局平文をエージェントの標準出力(トランスクリプト)へ流す =
// 拒否した境界の迂回になる。エージェントに迂回レシピを渡さない。
//
// なお、失敗は maruhi 共通の {@link CliError}(実行の失敗 = exit 1)で表す。
// 終了コードはエラー型が `Runtime.errorExitCode` で持つ(errors.ts)ので、
// ランナー側に写像表は要らない(ADR-0016 決定 4)。

import { Context, Effect, Stdio } from "effect";

import { cliError, type CliError } from "./errors.ts";

/** AI コーディングエージェントの検出結果(検出そのものは注入する)。 */
export interface AgentProfile {
  readonly isAgent: boolean;
  readonly name?: string | undefined;
}

/**
 * 検出結果のサービス。実装(std-env / 自前表)を差し替えられるように
 * ここでは値だけを受け取る — 二次層であって境界ではない。
 */
export class AgentProfileRef extends Context.Reference<AgentProfile>("cli/AgentProfile", {
  defaultValue: (): AgentProfile => ({ isAgent: false }),
}) {}

/** 既知エージェントを検出したときの拒否文(名前は診断のためだけに出す)。 */
function agentRejection(name: string | undefined): CliError {
  const detected = name === undefined ? "" : `: ${name}`;
  return cliError(
    `Refused to display values because an AI agent environment was detected${detected}. If you need to inspect a value, run this yourself on an interactive terminal`,
  );
}

/**
 * Fails unless value display is allowed: a human at an interactive terminal,
 * not an AI coding agent.
 *
 * 呼び出し側は 2 か所ある(多層防御): pull の入口(復号より前 — 本線)と
 * `showValues`(復号後の防衛線 — display.ts)。
 */
export const ensureValueDisplayAllowed: Effect.Effect<void, CliError, Stdio.Stdio> = Effect.gen(
  function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      return yield* Effect.fail(agentRejection(agent.name));
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      // パイプ・リダイレクト・CI・未知のエージェントはここで止まる。
      // 「知っているものを止める」ではなく「人間の端末だけ通す」
      return yield* Effect.fail(
        cliError(
          "Displaying values is only allowed on an interactive terminal (pipes, redirects, CI, and AI agents are refused). Run this as a human on an interactive terminal",
        ),
      );
    }
  },
);
