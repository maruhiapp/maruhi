// AI エージェント環境での値表示系コマンドの拒否(CLAUDE.md ディスクレス
// 不変条件)。検出は gunshi/agent(getAgentProfile)。
//
// 線引き(タスク裁定): 値を端末に表示する操作(pull --show)は拒否、
// `maruhi run`(子プロセスへのメモリ注入)は許可する。
//
// 重要(レビュー対応): 拒否メッセージで `maruhi run -- <cmd>` を勧めない。
// run は「値を使う」ための注入経路であって「値を見る」ための経路ではなく、
// `run -- printenv` のような使い方は結局平文をエージェントの標準出力
// (トランスクリプト)へ流す = 拒否した境界の迂回になる。エージェントに
// 迂回レシピを渡さないため、値を見たい場合は人間の対話端末で実行する旨を出す。

import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { AgentProfile } from "./io.ts";

/**
 * Fails when the process runs under an AI coding agent: value display is the
 * one operation the diskless invariants reserve for humans. The message does
 * not advertise `maruhi run` — that would hand the agent a way to echo the
 * value into its transcript, defeating the very boundary being enforced.
 */
export function ensureValueDisplayAllowed(profile: AgentProfile): Effect.Effect<void, CliError> {
  if (profile.isAgent) {
    const name = profile.name === undefined ? "" : `: ${profile.name}`;
    return Effect.fail(
      cliError(
        `AI エージェント環境を検出したため、値の表示を拒否しました${name}。値を確認する必要がある場合は、人間が対話端末で実行してください`,
      ),
    );
  }
  return Effect.void;
}
