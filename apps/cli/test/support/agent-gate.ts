// 値の表示可否の判定(エージェント検出の再設計)。
//
// **現状の弱点**: `gunshi/agent` は「既知のエージェントの環境変数リスト」に
// 一致したら拒否する **deny-list** である。境界の定義が上流のリストに依存し、
// リストに載っていない新しいエージェント・自作ハーネス・CI・ログ収集経路は
// **素通りする**(fail-open)。実測でも、この環境の Claude Code は
// `CLAUDECODE` と `AI_AGENT` を両方立てていたが、これはあくまで「たまたま
// 知られている実装」であって、境界の保証ではない。
//
// **再設計**: 一次境界を「人間の対話端末か」に置き換える(allow-list =
// fail-closed)。値を見てよいのは**人間が対話端末で実行したとき**だけ、
// という要件そのものを判定にする:
//
//   1. 一次境界: stdin と stdout の両方が TTY か(`Stdio` サービス)。
//      エージェント・CI・パイプ・リダイレクトはすべて既定で拒否になる。
//      未知のエージェントも同じ理由で拒否される(知らなくても止まる)
//   2. 二次層: 既知エージェントの環境変数(名前が分かると診断が親切になる。
//      PTY を割り当てて実行するエージェントを捕まえる層でもある)
//
// 判定材料はどちらも Effect のサービス経由で差し替えられる(`process.stdout`
// を直に読まない)。テストは Stdio.layerTest と AgentProfileRef で両方を偽装する。

import { Context, Data, Effect, Runtime, Stdio } from "effect";

/** AI コーディングエージェントの検出結果(検出そのものは注入する)。 */
export interface AgentProfile {
  readonly isAgent: boolean;
  readonly name?: string | undefined;
}

/**
 * 検出結果のサービス。実装(std-env / @vercel/detect-agent / 自前表)を
 * 差し替えられるようにここでは値だけを受け取る — 二次層であって境界ではない。
 */
export class AgentProfileRef extends Context.Reference<AgentProfile>("cli/AgentProfile", {
  defaultValue: (): AgentProfile => ({ isAgent: false }),
}) {}

/**
 * 値の表示を拒む理由。実行の失敗(exit 1)であって書き方の誤り(2)ではない
 * ことを、**エラー型自身が持つ**(`Runtime.errorExitCode`)。ランナー側に
 * 写像表を書かないための Effect の機構。
 */
export class ValueDisplayRefused extends Data.TaggedError("ValueDisplayRefused")<{
  readonly message: string;
}> {
  override readonly [Runtime.errorExitCode] = 1;
}

/**
 * Fails unless value display is allowed: a human at an interactive terminal,
 * not an AI coding agent.
 *
 * 拒否メッセージで `maruhi run -- <cmd>` を勧めない(エージェントに迂回
 * レシピを渡さない — src/agent.ts と同じ規律)。
 */
export const valueDisplayRejection: Effect.Effect<void, ValueDisplayRefused, Stdio.Stdio> =
  Effect.gen(function* () {
    const agent = yield* AgentProfileRef;
    if (agent.isAgent) {
      const name = agent.name === undefined ? "" : `: ${agent.name}`;
      return yield* new ValueDisplayRefused({
        message: `AI エージェント環境を検出したため、値の表示を拒否しました${name}。値を確認する必要がある場合は、人間が対話端末で実行してください`,
      });
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      // パイプ・リダイレクト・CI・未知のエージェントはここで止まる。
      // 「知っているものを止める」ではなく「人間の端末だけ通す」
      return yield* new ValueDisplayRefused({
        message:
          "値の表示は対話端末でのみ許可されます(パイプ・リダイレクト・CI・AI エージェントでは拒否されます)。人間が対話端末で実行してください",
      });
    }
  });
